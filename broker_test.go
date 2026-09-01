package main

// Tests for the Broker API upstream.
//
// The RPC-level tests run the fake broker over a plain unix socket rather than
// mTLS. What is worth pinning here is what spiffefs puts on the wire and how it
// behaves when the wire breaks; the mTLS setup lives entirely in
// newBrokerSource and is go-spiffe's code doing the work, so wrapping it in a
// test would mostly assert that go-spiffe still exists.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	broker "github.com/spiffe/go-spiffe/v2/exp/proto/spiffe/broker"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T, cn string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA %s: %v", cn, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA %s: %v", cn, err)
	}
	return &testCA{cert: cert, key: key}
}

// issue mints a leaf for id and returns its DER and a PKCS#8 encoding of its
// key, which is the shape the Broker API delivers.
func (c *testCA) issue(t *testing.T, id string) (certDER []byte, keyPKCS8 []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	uri, err := url.Parse(id)
	if err != nil {
		t.Fatalf("parse %s: %v", id, err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		URIs:         []*url.URL{uri},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err = x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatalf("issue %s: %v", id, err)
	}
	keyPKCS8, err = x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return certDER, keyPKCS8
}

// The response translation is where the two APIs actually differ, so pin the
// whole shape of it: the chain arrives as one concatenated DER blob rather than
// a repeated field, and bundles arrive as DER rather than PEM.
func TestBrokerPayloadTranslatesResponse(t *testing.T) {
	ca := newTestCA(t, "example.org")
	other := newTestCA(t, "other.org")

	leaf0, key0 := ca.issue(t, "spiffe://example.org/test2/main")
	leaf1, key1 := ca.issue(t, "spiffe://example.org/test2/other")

	resp := &broker.SubscribeToX509SVIDResponse{
		Svids: []*broker.X509SVID{
			{
				SpiffeId: "spiffe://example.org/test2/main",
				// Leaf first, then an intermediate: one blob, not a list.
				X509Svid:    append(append([]byte{}, leaf0...), ca.cert.Raw...),
				X509SvidKey: key0,
				Bundle:      ca.cert.Raw,
				Hint:        "main",
			},
			{
				SpiffeId:    "spiffe://example.org/test2/other",
				X509Svid:    leaf1,
				X509SvidKey: key1,
				Bundle:      ca.cert.Raw,
			},
		},
		FederatedBundles: map[string][]byte{
			"spiffe://other.org": other.cert.Raw,
		},
	}

	payload := brokerPayload(resp)

	if len(payload.Registry) != 2 {
		t.Fatalf("registry has %d entries, want 2", len(payload.Registry))
	}

	// Index 0 keeps the private key first, then leaf, then intermediate --
	// the exact bytes a workload reads out of the credential bundle file.
	want, err := buildCredentialBundle(key0, [][]byte{leaf0, ca.cert.Raw})
	if err != nil {
		t.Fatalf("buildCredentialBundle: %v", err)
	}
	got := payload.Registry["0"]
	if got == nil {
		t.Fatal("no entry at index 0")
	}
	if string(got.CredentialBundle) != string(want) {
		t.Errorf("credential bundle at index 0 does not match the expected PEM layout")
	}
	if got.Hint != "main" {
		t.Errorf("hint = %q, want %q", got.Hint, "main")
	}
	if got.TrustDomain != "example.org" {
		t.Errorf("trust domain = %q, want %q", got.TrustDomain, "example.org")
	}

	// The fingerprint has to be a plain digest of the served bytes, so a
	// reader can check it with sha256sum and nothing else.
	sum := sha256.Sum256(got.CredentialBundle)
	if wantFP := "sha256:" + hex.EncodeToString(sum[:]); got.Fingerprint != wantFP {
		t.Errorf("fingerprint = %q, want %q", got.Fingerprint, wantFP)
	}

	if second := payload.Registry["1"]; second == nil {
		t.Error("no entry at index 1")
	} else if second.Hint != "" {
		t.Errorf("index 1 hint = %q, want empty", second.Hint)
	}

	// Own trust domain from the SVID, federated one from the map, both keyed
	// by bare trust domain rather than by SPIFFE ID.
	if len(payload.Bundles) != 2 {
		t.Fatalf("bundles has %d entries (%v), want 2", len(payload.Bundles), payload.Bundles)
	}
	assertPEMHas(t, payload.Bundles["example.org"], ca.cert.Raw)
	assertPEMHas(t, payload.Bundles["other.org"], other.cert.Raw)
}

func assertPEMHas(t *testing.T, pemBytes []byte, wantDER []byte) {
	t.Helper()
	if len(pemBytes) == 0 {
		t.Fatal("bundle is empty")
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("bundle is not PEM")
	}
	if block.Type != "CERTIFICATE" {
		t.Fatalf("PEM block type = %q, want CERTIFICATE", block.Type)
	}
	if string(block.Bytes) != string(wantDER) {
		t.Error("bundle does not carry the expected certificate")
	}
}

// One unusable SVID must not cost a workload the rest of its identities. The
// index is left alone rather than renumbered, so the file names the other SVIDs
// are served under do not shift because a neighbour failed to parse.
func TestBrokerPayloadDropsMalformedSVID(t *testing.T) {
	ca := newTestCA(t, "example.org")
	leaf, key := ca.issue(t, "spiffe://example.org/test1")

	payload := brokerPayload(&broker.SubscribeToX509SVIDResponse{
		Svids: []*broker.X509SVID{
			{SpiffeId: "spiffe://example.org/broken", X509Svid: []byte("not der"), X509SvidKey: key, Bundle: ca.cert.Raw},
			{SpiffeId: "spiffe://example.org/test1", X509Svid: leaf, X509SvidKey: key, Bundle: ca.cert.Raw},
		},
	})

	if _, bad := payload.Registry["0"]; bad {
		t.Error("the malformed SVID was served anyway")
	}
	if _, good := payload.Registry["1"]; !good {
		t.Error("the usable SVID was dropped along with the malformed one")
	}
	if len(payload.Registry) != 1 {
		t.Errorf("registry has %d entries, want 1", len(payload.Registry))
	}
}

// A missing key or chain is not a usable identity, and serving half of one
// would look like success to a reader.
func TestBrokerPayloadRejectsIncompleteSVID(t *testing.T) {
	ca := newTestCA(t, "example.org")
	leaf, _ := ca.issue(t, "spiffe://example.org/test1")

	payload := brokerPayload(&broker.SubscribeToX509SVIDResponse{
		Svids: []*broker.X509SVID{
			{SpiffeId: "spiffe://example.org/test1", X509Svid: leaf, Bundle: ca.cert.Raw},
		},
	})

	if len(payload.Registry) != 0 {
		t.Errorf("registry has %d entries, want 0", len(payload.Registry))
	}
}

func TestBrokerTarget(t *testing.T) {
	cases := map[string]string{
		"unix:///run/broker.sock": "unix:///run/broker.sock",
		"tcp://10.0.0.1:8443":     "dns:///10.0.0.1:8443",
		"tcp://agent.local:8443":  "dns:///agent.local:8443",
	}
	for in, want := range cases {
		if got := brokerTarget(in); got != want {
			t.Errorf("brokerTarget(%q) = %q, want %q", in, got, want)
		}
	}
}

// fakeBroker records what the client sent and serves whatever the test queued.
type fakeBroker struct {
	broker.UnimplementedAPIServer

	mu       sync.Mutex
	calls    int
	lastMD   metadata.MD
	lastRef  *broker.WorkloadReference
	failOnce bool

	resp *broker.SubscribeToX509SVIDResponse
}

func (f *fakeBroker) SubscribeToX509SVID(req *broker.SubscribeToX509SVIDRequest, stream grpc.ServerStreamingServer[broker.SubscribeToX509SVIDResponse]) error {
	md, _ := metadata.FromIncomingContext(stream.Context())

	f.mu.Lock()
	f.calls++
	call := f.calls
	f.lastMD = md
	f.lastRef = req.Reference
	fail := f.failOnce
	resp := f.resp
	f.mu.Unlock()

	if fail && call == 1 {
		return status.Error(codes.Unavailable, "upstream having a moment")
	}
	if err := stream.Send(resp); err != nil {
		return err
	}
	<-stream.Context().Done()
	return stream.Context().Err()
}

func (f *fakeBroker) snapshot() (int, metadata.MD, *broker.WorkloadReference) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls, f.lastMD, f.lastRef
}

func startFakeBroker(t *testing.T, fake *fakeBroker) *brokerSource {
	t.Helper()

	// A short path: the sun_path limit is 108 bytes, and t.TempDir() under a
	// long test name has run into it before.
	dir, err := os.MkdirTemp("", "bkr")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sockPath := filepath.Join(dir, "b.sock")

	lis, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv := grpc.NewServer()
	broker.RegisterAPIServer(srv, fake)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("unix://"+sockPath, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	return &brokerSource{client: broker.NewAPIClient(conn)}
}

// Both of these are refusal conditions on a real agent: without the metadata
// header every call is answered InvalidArgument, and the reference is the only
// thing that says which workload is being asked about.
func TestBrokerSubscribeSendsMetadataAndPIDReference(t *testing.T) {
	ca := newTestCA(t, "example.org")
	leaf, key := ca.issue(t, "spiffe://example.org/test1")

	fake := &fakeBroker{resp: &broker.SubscribeToX509SVIDResponse{
		Svids: []*broker.X509SVID{{
			SpiffeId: "spiffe://example.org/test1", X509Svid: leaf, X509SvidKey: key, Bundle: ca.cert.Raw,
		}},
	}}
	bs := startFakeBroker(t, fake)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	updates := make(chan SVIDUpdatePayload, 1)
	go bs.subscribe(ctx, 4242, updates)

	select {
	case payload := <-updates:
		if len(payload.Registry) != 1 {
			t.Errorf("registry has %d entries, want 1", len(payload.Registry))
		}
	case <-ctx.Done():
		t.Fatal("no payload delivered")
	}

	_, md, ref := fake.snapshot()
	if got := md.Get("broker.spiffe.io"); len(got) != 1 || got[0] != "true" {
		t.Errorf("broker.spiffe.io metadata = %v, want [true]", got)
	}

	if ref == nil || ref.Reference == nil {
		t.Fatal("no workload reference sent")
	}
	const wantType = "type.googleapis.com/spiffe.broker.WorkloadPIDReference"
	if ref.Reference.TypeUrl != wantType {
		t.Fatalf("reference type = %q, want %q", ref.Reference.TypeUrl, wantType)
	}
	var pidRef broker.WorkloadPIDReference
	if err := proto.Unmarshal(ref.Reference.Value, &pidRef); err != nil {
		t.Fatalf("unmarshal reference: %v", err)
	}
	if pidRef.Pid != 4242 {
		t.Errorf("referenced pid = %d, want 4242", pidRef.Pid)
	}
}

// A caller's state is built once and never revisited, so a stream that fails
// before any identity arrives has to be retried here or that caller never gets
// credentials at all.
func TestBrokerSubscribeRetriesAfterStreamError(t *testing.T) {
	ca := newTestCA(t, "example.org")
	leaf, key := ca.issue(t, "spiffe://example.org/test1")

	fake := &fakeBroker{failOnce: true, resp: &broker.SubscribeToX509SVIDResponse{
		Svids: []*broker.X509SVID{{
			SpiffeId: "spiffe://example.org/test1", X509Svid: leaf, X509SvidKey: key, Bundle: ca.cert.Raw,
		}},
	}}
	bs := startFakeBroker(t, fake)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	updates := make(chan SVIDUpdatePayload, 1)
	go bs.subscribe(ctx, 4242, updates)

	select {
	case payload := <-updates:
		if len(payload.Registry) != 1 {
			t.Errorf("registry has %d entries, want 1", len(payload.Registry))
		}
	case <-ctx.Done():
		t.Fatal("gave up after the first stream error instead of retrying")
	}

	if calls, _, _ := fake.snapshot(); calls < 2 {
		t.Errorf("server saw %d subscribe calls, want at least 2", calls)
	}
}
