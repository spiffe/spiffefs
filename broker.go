package main

// SPIFFE Broker API support. This is the default upstream.
//
// Unlike the delegated API, the Broker API is mutually authenticated and
// entry-scoped: spiffefs presents its own X509-SVID, names the caller with a
// WorkloadPIDReference, and the agent attests that reference itself. Trust
// bundles come back inline on the same stream, so there is no process-wide
// bundle state here at all.

import (
	"context"
	"crypto/x509"
	"fmt"
	"log"
	"strings"
	"time"

	broker "github.com/spiffe/go-spiffe/v2/exp/proto/spiffe/broker"
	"github.com/spiffe/go-spiffe/v2/logger"
	"github.com/spiffe/go-spiffe/v2/spiffegrpc/grpccredentials"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	// The floor a stock gRPC server permits. grpc-go applies
	// EnforcementPolicy{MinTime: 5m} whenever the server sets none, and
	// maxPingStrikes is 2, so the third too-frequent ping earns a GOAWAY
	// ENHANCE_YOUR_CALM "too_many_pings" and the connection dies -- the very
	// failure keepalive is meant to detect. The strike counter resets only
	// when the server writes application data, and an SVID subscription is
	// quiet by design, so strikes accumulate rather than being forgiven.
	// SPIRE's broker endpoint sets no keepalive options, so it inherits that
	// default; lower this only once SPIRE lets the enforcement policy be
	// configured.
	brokerKeepaliveTime    = 5 * time.Minute
	brokerKeepaliveTimeout = 20 * time.Second
)

// brokerSource serves callers from a SPIFFE Broker API endpoint.
type brokerSource struct {
	client broker.APIClient
	// Deliberately never closed: it keeps rotating our SVID so the mTLS
	// client certificate stays fresh for the life of the process.
	source *workloadapi.X509Source
}

var _ identitySource = (*brokerSource)(nil)

// newBrokerSource blocks until spiffefs has its own identity and a client for
// the broker endpoint. There is nothing to serve before then: without an SVID
// there is no mTLS, and without mTLS every call is refused.
func newBrokerSource(workloadAddr, brokerAddr string) *brokerSource {
	var source *workloadapi.X509Source
	for {
		var err error
		log.Printf("[Broker-Client] Obtaining our own identity from %s", workloadAddr)
		// NewX509Source blocks until an SVID is actually issued, silently
		// retrying every failure (missing socket, no identity issued, ...)
		// internally. Bound each attempt and hand go-spiffe a real logger so
		// an agent that will not issue us an identity shows up in the logs
		// instead of hanging silently forever. The timeout only bounds
		// initialization; the source's rotation watch runs on its own
		// background context.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		source, err = workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(
			workloadapi.WithAddr(workloadAddr),
			workloadapi.WithLogger(logger.Std),
		))
		cancel()
		if err == nil {
			break
		}
		log.Printf("[Broker-Client] Failed to obtain identity from %s: %v. Retrying...", workloadAddr, err)
		time.Sleep(5 * time.Second)
	}

	// Logged rather than fatal: the source only returns here once it has an
	// SVID, so a failure now is a surprise worth seeing, not a reason to
	// refuse to serve.
	if svid, err := source.GetX509SVID(); err != nil {
		log.Printf("[Broker-Client] Could not read back our own SVID: %v", err)
	} else {
		log.Printf("[Broker-Client] Our identity: %s", svid.ID)
	}

	// The server's SPIFFE ID is not pinned. The broker endpoint presents the
	// agent's own SVID, whose ID is not predictable from configuration, so
	// there is nothing to compare against; the certificate is still verified
	// against our trust bundle.
	creds := grpccredentials.MTLSClientCredentials(source, source, tlsconfig.AuthorizeAny())

	conn, err := grpc.NewClient(brokerTarget(brokerAddr),
		grpc.WithTransportCredentials(creds),
		// Keepalive exists to catch a wedged connection (silent drop, black
		// holed TCP), where Recv would otherwise block forever and the
		// caller would keep waiting on credentials that will never arrive.
		// Everything else -- process death, socket close, RST, RPC errors --
		// already surfaces as a stream error. PermitWithoutStream is false so
		// we do not ping while every subscription is in its retry sleep.
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                brokerKeepaliveTime,
			Timeout:             brokerKeepaliveTimeout,
			PermitWithoutStream: false,
		}),
	)
	if err != nil {
		log.Fatalf("[Broker-Client] Failed to create broker client for %s: %v", brokerAddr, err)
	}

	log.Printf("[Broker-Client] Broker client ready against %s", brokerAddr)
	return &brokerSource{client: broker.NewAPIClient(conn), source: source}
}

// brokerTarget rewrites a tcp:// address for grpc.NewClient, which does not
// understand that scheme. unix:// targets pass through natively.
func brokerTarget(addr string) string {
	if rest, ok := strings.CutPrefix(addr, "tcp://"); ok {
		return "dns:///" + rest
	}
	return addr
}

// brokerMD adds the metadata the Broker API requires on every call as an SSRF
// mitigation. Without it the server answers InvalidArgument.
func brokerMD(ctx context.Context) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "broker.spiffe.io", "true")
}

func pidWorkloadReference(pid uint32) (*broker.WorkloadReference, error) {
	ref, err := anypb.New(&broker.WorkloadPIDReference{Pid: int32(pid)})
	if err != nil {
		return nil, err
	}
	return &broker.WorkloadReference{Reference: ref}, nil
}

// subscribe keeps a caller's identities up to date until the caller exits. It
// retries rather than giving up on the first failure: a workload that reads
// before its registration entry has propagated is answered with no identities,
// and without retrying that caller would be left with no credentials for as
// long as it lives. Its state is created once and reused, so nothing else
// would go back for it.
func (bs *brokerSource) subscribe(ctx context.Context, pid uint32, updates chan<- SVIDUpdatePayload) {
	defer close(updates)

	const retryDelay = 2 * time.Second

	ref, err := pidWorkloadReference(pid)
	if err != nil {
		// Only a programming error can get here: the reference message is
		// ours and always marshals.
		log.Printf("[Broker-Client] Failed building workload reference for PID %d: %v", pid, err)
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if !bs.subscribeOnce(ctx, pid, ref, updates) {
			return
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(retryDelay):
		}
	}
}

// subscribeOnce runs one attempt. It reports whether another is worth making;
// only the caller going away ends the loop.
func (bs *brokerSource) subscribeOnce(ctx context.Context, pid uint32, ref *broker.WorkloadReference, updates chan<- SVIDUpdatePayload) bool {
	stream, err := bs.client.SubscribeToX509SVID(brokerMD(ctx), &broker.SubscribeToX509SVIDRequest{Reference: ref})
	if err != nil {
		log.Printf("[Broker-Client] Failed subscribing to SVID stream for PID %d: %v. Retrying...", pid, err)
		return true
	}

	log.Printf("[Broker-Client] Active identity watch established for PID %d", pid)

	for {
		resp, err := stream.Recv()
		if err != nil {
			if ctx.Err() != nil {
				// The caller exited and its context was cancelled; stop.
				return false
			}
			log.Printf("[Broker-Client] Identity stream closed/interrupted for PID %d: %v. Retrying...", pid, err)
			return true
		}

		select {
		case <-ctx.Done():
			return false
		case updates <- brokerPayload(resp):
		}
	}
}

// brokerPayload translates one response into the snapshot the FS serves. A
// single malformed SVID is dropped with a log line rather than discarding the
// whole response: the other identities in it are still usable.
func brokerPayload(resp *broker.SubscribeToX509SVIDResponse) SVIDUpdatePayload {
	registry := make(map[string]*SVIDFileSystemState)
	bundles := make(map[string][]byte)

	for idx, svid := range resp.Svids {
		// x509_svid is one blob of concatenated DER, leaf first -- not a
		// repeated field like the delegated API's cert chain.
		certs, err := x509.ParseCertificates(svid.X509Svid)
		if err != nil {
			log.Printf("[Broker-Client] Failed parsing certificate chain for index %d: %v", idx, err)
			continue
		}
		chain := make([][]byte, 0, len(certs))
		for _, cert := range certs {
			chain = append(chain, cert.Raw)
		}

		bundle, err := buildCredentialBundle(svid.X509SvidKey, chain)
		if err != nil {
			log.Printf("[Broker-Client] Failed serializing PEM elements for index %d: %v", idx, err)
			continue
		}

		td := cleanTrustDomain(svid.SpiffeId)
		if td == "" && len(certs) > 0 && len(certs[0].URIs) > 0 {
			td = cleanTrustDomain(certs[0].URIs[0].Host)
		}

		registry[fmt.Sprintf("%d", idx)] = &SVIDFileSystemState{
			CredentialBundle: bundle,
			Hint:             svid.Hint,
			Fingerprint:      bundleFingerprint(bundle),
			TrustDomain:      td,
		}

		// The bundle rides along with the SVID it belongs to, so the
		// caller's own trust domain needs no separate lookup.
		if td != "" && len(svid.Bundle) > 0 {
			if pemBundle, err := derBundleToPEM(svid.Bundle); err != nil {
				log.Printf("[Broker-Client] Failed parsing DER bundle for %s: %v", td, err)
			} else {
				bundles[td] = pemBundle
			}
		}
	}

	for id, der := range resp.FederatedBundles {
		td := cleanTrustDomain(id)
		if td == "" {
			continue
		}
		pemBundle, err := derBundleToPEM(der)
		if err != nil {
			log.Printf("[Broker-Client] Failed parsing DER federated bundle for %s: %v", id, err)
			continue
		}
		bundles[td] = pemBundle
	}

	return SVIDUpdatePayload{Registry: registry, Bundles: bundles}
}
