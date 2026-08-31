package main

// The verifier decides whether a soak run passes, so the way it classifies what
// it sees is worth pinning directly. In particular it must never be wrong in the
// direction of passing: a workload served another workload's material has to
// fail, and fail immediately rather than being retried away.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T, td string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	uri, err := url.Parse("spiffe://" + td)
	if err != nil {
		t.Fatalf("parse trust domain %s: %v", td, err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: td},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA %s: %v", td, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA %s: %v", td, err)
	}
	return &testCA{cert: cert, key: key}
}

// credentialPEM renders what spiffefs serves: the private key, then the chain.
func (c *testCA) credentialPEM(t *testing.T, id string) []byte {
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
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatalf("issue %s: %v", id, err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	out := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})...)
}

func (c *testCA) bundlePEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw})
}

// mount builds a directory that looks like what spiffefs serves one caller.
type mount struct {
	dir   string
	hints []hintEntry
	t     *testing.T
}

func newMount(t *testing.T) *mount {
	return &mount{dir: t.TempDir(), t: t}
}

func (m *mount) write(name string, content []byte) {
	m.t.Helper()
	if err := os.WriteFile(filepath.Join(m.dir, name), content, 0o644); err != nil {
		m.t.Fatalf("write %s: %v", name, err)
	}
}

func (m *mount) addCredential(idx int, hint string, content []byte) {
	m.t.Helper()
	name := credentialBundleFileName(idx)
	m.write(name, content)
	m.hints = append(m.hints, hintEntry{Hint: hint, ID: idx, Fingerprint: fingerprint(content)})
}

func (m *mount) addTrustBundle(td string, content []byte) {
	m.t.Helper()
	m.write(trustBundleFileName(td), content)
}

// finish writes hints.json. Nothing reads the mount until this is called, since
// hints.json is always served.
func (m *mount) finish() string {
	m.t.Helper()
	doc := struct {
		Hints []hintEntry `json:"hints"`
	}{Hints: m.hints}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		m.t.Fatalf("marshal hints: %v", err)
	}
	m.write(hintsFileName, append(raw, '\n'))
	return m.dir
}

func expect(domains []string, svids ...[2]string) expectation {
	var exp expectation
	exp.TrustDomains = domains
	for _, s := range svids {
		exp.SVIDs = append(exp.SVIDs, struct {
			Hint     string `json:"hint"`
			SPIFFEID string `json:"spiffe_id"`
		}{Hint: s[0], SPIFFEID: s[1]})
	}
	return exp
}

func TestCheckAcceptsASingleUnhintedSVID(t *testing.T) {
	ca := newTestCA(t, "example.org")
	m := newMount(t)
	m.addCredential(0, "", ca.credentialPEM(t, "spiffe://example.org/soak/one"))
	m.addTrustBundle("example.org", ca.bundlePEM())

	exp := expect([]string{"example.org"}, [2]string{"", "spiffe://example.org/soak/one"})
	if err := check(m.finish(), exp); err != nil {
		t.Fatalf("check: %v", err)
	}
}

// Two entries on one selector, told apart by hint, with a federated bundle
// alongside. Index 0 deliberately carries the "other" hint: indexes follow the
// order the upstream returned the entries in, which is not the order they were
// created in, so nothing may assume the two line up.
func TestCheckAcceptsHintedSVIDsInAnyOrder(t *testing.T) {
	ca := newTestCA(t, "example.org")
	fed := newTestCA(t, "other.org")

	m := newMount(t)
	m.addCredential(0, "other", ca.credentialPEM(t, "spiffe://example.org/soak/two/other"))
	m.addCredential(1, "main", ca.credentialPEM(t, "spiffe://example.org/soak/two/main"))
	m.addTrustBundle("example.org", ca.bundlePEM())
	m.addTrustBundle("other.org", fed.bundlePEM())

	exp := expect([]string{"example.org", "other.org"},
		[2]string{"main", "spiffe://example.org/soak/two/main"},
		[2]string{"other", "spiffe://example.org/soak/two/other"},
	)
	if err := check(m.finish(), exp); err != nil {
		t.Fatalf("check: %v", err)
	}
}

// The point of the whole soak: another workload's identity showing up in this
// workload's directory has to fail, and has to fail fatally so the retry loop
// cannot wait it away.
func TestCheckRejectsAForeignSVID(t *testing.T) {
	ca := newTestCA(t, "example.org")
	m := newMount(t)
	m.addCredential(0, "", ca.credentialPEM(t, "spiffe://example.org/soak/mine"))
	m.addCredential(1, "stolen", ca.credentialPEM(t, "spiffe://example.org/soak/somebody-else"))
	m.addTrustBundle("example.org", ca.bundlePEM())

	exp := expect([]string{"example.org"}, [2]string{"", "spiffe://example.org/soak/mine"})
	err := check(m.finish(), exp)
	if err == nil {
		t.Fatal("accepted another workload's SVID")
	}
	if !isFatal(err) {
		t.Errorf("foreign SVID reported as retryable: %v", err)
	}
}

// A workload whose entry does not federate must not be shown the federated
// bundle. This is the leak that the old process-wide bundle map made possible.
func TestCheckRejectsAnUnfederatedTrustBundle(t *testing.T) {
	ca := newTestCA(t, "example.org")
	fed := newTestCA(t, "other.org")

	m := newMount(t)
	m.addCredential(0, "", ca.credentialPEM(t, "spiffe://example.org/soak/one"))
	m.addTrustBundle("example.org", ca.bundlePEM())
	m.addTrustBundle("other.org", fed.bundlePEM())

	exp := expect([]string{"example.org"}, [2]string{"", "spiffe://example.org/soak/one"})
	err := check(m.finish(), exp)
	if err == nil {
		t.Fatal("accepted a trust bundle the entry does not federate with")
	}
	if !isFatal(err) {
		t.Errorf("unfederated trust bundle reported as retryable: %v", err)
	}
}

// A bundle filed under the wrong trust domain would have a workload trusting the
// wrong authority while the file name says otherwise.
func TestCheckRejectsAMislabelledTrustBundle(t *testing.T) {
	ca := newTestCA(t, "example.org")
	fed := newTestCA(t, "other.org")

	m := newMount(t)
	m.addCredential(0, "", ca.credentialPEM(t, "spiffe://example.org/soak/one"))
	m.addTrustBundle("example.org", ca.bundlePEM())
	m.addTrustBundle("other.org", ca.bundlePEM()) // example.org's CA under other.org's name
	_ = fed

	exp := expect([]string{"example.org", "other.org"}, [2]string{"", "spiffe://example.org/soak/one"})
	err := check(m.finish(), exp)
	if err == nil {
		t.Fatal("accepted example.org's CA filed as other.org")
	}
	if !isFatal(err) {
		t.Errorf("mislabelled trust bundle reported as retryable: %v", err)
	}
}

func TestCheckRejectsAnUnexpectedFile(t *testing.T) {
	ca := newTestCA(t, "example.org")
	m := newMount(t)
	m.addCredential(0, "", ca.credentialPEM(t, "spiffe://example.org/soak/one"))
	m.addTrustBundle("example.org", ca.bundlePEM())
	m.write("surprise.txt", []byte("hello"))

	exp := expect([]string{"example.org"}, [2]string{"", "spiffe://example.org/soak/one"})
	err := check(m.finish(), exp)
	if err == nil {
		t.Fatal("accepted an unexpected file")
	}
	if !isFatal(err) {
		t.Errorf("unexpected file reported as retryable: %v", err)
	}
}

// A key paired with somebody else's certificate is well formed enough to read
// but useless, and is never a transient state.
func TestCheckRejectsAMismatchedKeyPair(t *testing.T) {
	ca := newTestCA(t, "example.org")
	mine := ca.credentialPEM(t, "spiffe://example.org/soak/one")
	theirs := ca.credentialPEM(t, "spiffe://example.org/soak/one")

	// Our key, their certificate.
	keyBlock, _ := pem.Decode(mine)
	_, certPEM := pem.Decode(theirs)

	m := newMount(t)
	m.addCredential(0, "", append(pem.EncodeToMemory(keyBlock), certPEM...))
	m.addTrustBundle("example.org", ca.bundlePEM())

	exp := expect([]string{"example.org"}, [2]string{"", "spiffe://example.org/soak/one"})
	err := check(m.finish(), exp)
	if err == nil {
		t.Fatal("accepted a key that does not match its certificate")
	}
	if !isFatal(err) {
		t.Errorf("mismatched key pair reported as retryable: %v", err)
	}
}

// Our own SVID under the wrong hint is still a real defect: the hint is how a
// workload picks which identity to use.
func TestCheckRejectsASwappedHint(t *testing.T) {
	ca := newTestCA(t, "example.org")
	m := newMount(t)
	m.addCredential(0, "main", ca.credentialPEM(t, "spiffe://example.org/soak/two/other"))
	m.addCredential(1, "other", ca.credentialPEM(t, "spiffe://example.org/soak/two/main"))
	m.addTrustBundle("example.org", ca.bundlePEM())

	exp := expect([]string{"example.org"},
		[2]string{"main", "spiffe://example.org/soak/two/main"},
		[2]string{"other", "spiffe://example.org/soak/two/other"},
	)
	err := check(m.finish(), exp)
	if err == nil {
		t.Fatal("accepted hints pointing at the wrong identities")
	}
	if !isFatal(err) {
		t.Errorf("swapped hint reported as retryable: %v", err)
	}
}

// Everything below is the system still converging. These must stay retryable,
// or the soak would fail every workload that reads before its entry propagates.
func TestCheckTreatsAnIncompleteViewAsRetryable(t *testing.T) {
	ca := newTestCA(t, "example.org")
	fed := newTestCA(t, "other.org")

	t.Run("second SVID has not arrived", func(t *testing.T) {
		m := newMount(t)
		m.addCredential(0, "main", ca.credentialPEM(t, "spiffe://example.org/soak/two/main"))
		m.addTrustBundle("example.org", ca.bundlePEM())

		exp := expect([]string{"example.org"},
			[2]string{"main", "spiffe://example.org/soak/two/main"},
			[2]string{"other", "spiffe://example.org/soak/two/other"},
		)
		assertRetryable(t, check(m.finish(), exp))
	})

	t.Run("federated bundle has not arrived", func(t *testing.T) {
		m := newMount(t)
		m.addCredential(0, "", ca.credentialPEM(t, "spiffe://example.org/soak/one"))
		m.addTrustBundle("example.org", ca.bundlePEM())

		exp := expect([]string{"example.org", "other.org"}, [2]string{"", "spiffe://example.org/soak/one"})
		assertRetryable(t, check(m.finish(), exp))
	})

	t.Run("nothing has arrived", func(t *testing.T) {
		m := newMount(t)
		exp := expect([]string{"example.org"}, [2]string{"", "spiffe://example.org/soak/one"})
		assertRetryable(t, check(m.finish(), exp))
	})

	// A rotation between reading hints.json and reading the bundle looks exactly
	// like this, so it has to be re-read rather than failed.
	t.Run("fingerprint is stale", func(t *testing.T) {
		m := newMount(t)
		m.addCredential(0, "", ca.credentialPEM(t, "spiffe://example.org/soak/one"))
		m.hints[0].Fingerprint = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
		m.addTrustBundle("example.org", ca.bundlePEM())

		exp := expect([]string{"example.org"}, [2]string{"", "spiffe://example.org/soak/one"})
		assertRetryable(t, check(m.finish(), exp))
	})

	_ = fed
}

func assertRetryable(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("accepted an incomplete view as converged")
	}
	if isFatal(err) {
		t.Errorf("a still-converging view was reported as fatal: %v", err)
	}
}

// verify has to give up on a fatal finding immediately rather than sitting on it
// until the deadline, and has to keep retrying an incomplete one.
func TestVerifyStopsOnFatalAndWaitsOnRetryable(t *testing.T) {
	ca := newTestCA(t, "example.org")

	m := newMount(t)
	m.addCredential(0, "", ca.credentialPEM(t, "spiffe://example.org/soak/somebody-else"))
	m.addTrustBundle("example.org", ca.bundlePEM())
	dir := m.finish()

	exp := expect([]string{"example.org"}, [2]string{"", "spiffe://example.org/soak/mine"})

	start := time.Now()
	err := verify(dir, exp, time.Now().Add(30*time.Second))
	if err == nil {
		t.Fatal("verify accepted a foreign SVID")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("verify sat on a fatal finding for %s instead of failing at once", elapsed)
	}

	empty := newMount(t).finish()
	start = time.Now()
	if err := verify(empty, exp, time.Now().Add(2*time.Second)); err == nil {
		t.Fatal("verify accepted an empty mount")
	}
	if elapsed := time.Since(start); elapsed < time.Second {
		t.Errorf("verify gave up on an incomplete view after only %s", elapsed)
	}
}
