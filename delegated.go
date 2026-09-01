package main

// Delegated Identity API support.
//
// DEPRECATED. This is the original upstream for spiffefs, kept behind
// -mode=delegated while the Broker API takes over. Everything specific to it
// lives in this file so that removing it is deleting this file, the one switch
// case in main that names it, and the spire-api-sdk dependency. Nothing
// outside this file knows the delegated API exists.

import (
	"context"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"sort"
	"sync"
	"time"

	delegatedidentityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/delegatedidentity/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// delegatedSource serves callers from SPIRE's Delegated Identity API over the
// agent's private admin socket.
//
// The API splits what the filesystem needs across two streams that move
// independently: a per-caller SVID stream, and one process-wide trust bundle
// stream. The FS wants a single per-caller snapshot, so this type owns both
// halves and joins them, rather than exposing a global bundle map the rest of
// the program would have to know about.
type delegatedSource struct {
	socketPath string

	// bundleMutex guards both fields below. bundleChan is closed and
	// replaced on every bundle update, which is how live per-caller pumps
	// learn that their snapshot needs re-emitting.
	bundleMutex sync.RWMutex
	bundles     map[string][]byte
	bundleChan  chan struct{}
}

// delegatedSVIDUpdate is the SVID stream's half of a caller's snapshot, before
// it is joined with the trust bundles.
type delegatedSVIDUpdate struct {
	registry  map[string]*SVIDFileSystemState
	federated []string
}

var _ identitySource = (*delegatedSource)(nil)

// newDelegatedSource starts the global bundle watcher and gives it a moment to
// prime. Priming is best effort: the watcher backs off and retries on its own,
// and mounting without bundles is better than not mounting, so a timeout here
// is logged rather than fatal.
func newDelegatedSource(socketPath string) *delegatedSource {
	ds := &delegatedSource{
		socketPath: socketPath,
		bundles:    make(map[string][]byte),
		bundleChan: make(chan struct{}),
	}

	ready := make(chan struct{})
	go ds.watchGlobalX509Bundles(context.Background(), ready)

	select {
	case <-ready:
		log.Printf("[Bundle-Watcher] Initial trust bundles primed successfully")
	case <-time.After(3 * time.Second):
		log.Printf("[Bundle-Watcher] Timeout waiting for trust bundles; continuing anyway")
	}

	return ds
}

func (ds *delegatedSource) currentBundleChan() chan struct{} {
	ds.bundleMutex.RLock()
	defer ds.bundleMutex.RUnlock()
	return ds.bundleChan
}

func (ds *delegatedSource) subscribe(ctx context.Context, pid uint32, updates chan<- SVIDUpdatePayload) {
	raw := make(chan delegatedSVIDUpdate, 2)
	go ds.pumpSVIDs(ctx, pid, raw)
	ds.join(ctx, raw, updates)
}

// join fans the two streams into one. It re-emits the caller's snapshot
// whenever either its SVIDs or the global bundles move, so a bundle that
// arrives long after a caller started still reaches it.
func (ds *delegatedSource) join(ctx context.Context, raw <-chan delegatedSVIDUpdate, updates chan<- SVIDUpdatePayload) {
	defer close(updates)

	var last *delegatedSVIDUpdate
	for {
		// Sampled before the select, so an update landing while we are
		// blocked below closes the channel we are actually waiting on.
		bundlesMoved := ds.currentBundleChan()

		select {
		case <-ctx.Done():
			return
		case update, ok := <-raw:
			if !ok {
				return
			}
			last = &update
		case <-bundlesMoved:
			// Bundles without a registry is not a snapshot worth
			// sending: the caller would be shown trust bundles while
			// its own identities still look absent.
			if last == nil {
				continue
			}
		}

		select {
		case <-ctx.Done():
			return
		case updates <- ds.snapshot(*last):
		}
	}
}

// snapshot pairs a caller's SVIDs with the bundles it should trust: the trust
// domains of its own SVIDs plus everything it federates with, minus any domain
// no bundle has arrived for.
func (ds *delegatedSource) snapshot(update delegatedSVIDUpdate) SVIDUpdatePayload {
	seen := make(map[string]bool)
	for _, svid := range update.registry {
		if svid.TrustDomain != "" {
			seen[svid.TrustDomain] = true
		}
	}
	for _, td := range update.federated {
		if td != "" {
			seen[td] = true
		}
	}

	bundles := make(map[string][]byte, len(seen))
	ds.bundleMutex.RLock()
	for td := range seen {
		if bundle, ok := ds.bundles[td]; ok {
			bundles[td] = bundle
		}
	}
	ds.bundleMutex.RUnlock()

	return SVIDUpdatePayload{Registry: update.registry, Bundles: bundles}
}

// pumpSVIDs keeps a caller's identities coming until the caller exits. It
// retries rather than giving up on the first failure: a workload that reads
// before its registration entry has propagated is answered with "no identity
// issued", and without retrying that caller would be left with no credentials
// for as long as it lives. Its state is created once and reused, so nothing
// else would go back for it.
func (ds *delegatedSource) pumpSVIDs(ctx context.Context, pid uint32, out chan<- delegatedSVIDUpdate) {
	defer close(out)

	const retryDelay = 2 * time.Second

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if !ds.subscribeToSVIDs(ctx, pid, out) {
			return
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(retryDelay):
		}
	}
}

// subscribeToSVIDs runs one attempt. It reports whether another is worth
// making; only the caller going away ends the loop.
func (ds *delegatedSource) subscribeToSVIDs(ctx context.Context, pid uint32, out chan<- delegatedSVIDUpdate) bool {
	conn, err := ds.dial(ctx)
	if err != nil {
		log.Printf("[SPIRE-Client] Failed connecting to SPIRE socket %s: %v. Retrying...", ds.socketPath, err)
		return true
	}
	defer conn.Close()

	client := delegatedidentityv1.NewDelegatedIdentityClient(conn)

	req := &delegatedidentityv1.SubscribeToX509SVIDsRequest{
		Pid: int32(pid),
	}

	stream, err := client.SubscribeToX509SVIDs(ctx, req)
	if err != nil {
		log.Printf("[SPIRE-Client] Failed subscribing to SVID watch stream for PID %d: %v. Retrying...", pid, err)
		return true
	}

	log.Printf("[SPIRE-Client] Active identity watch established for PID %d", pid)

	for {
		resp, err := stream.Recv()
		if err != nil {
			if ctx.Err() != nil {
				// The caller exited and its context was cancelled; stop.
				return false
			}
			log.Printf("[SPIRE-Client] Identity stream closed/interrupted for PID %d: %v. Retrying...", pid, err)
			return true
		}

		newMap := make(map[string]*SVIDFileSystemState)

		for idx, svidWithKey := range resp.X509Svids {
			if svidWithKey.X509Svid == nil {
				continue
			}

			bundle, err := buildCredentialBundle(svidWithKey.X509SvidKey, svidWithKey.X509Svid.CertChain)
			if err != nil {
				log.Printf("[SPIRE-Client] Failed serializing PEM elements for index %d: %v", idx, err)
				continue
			}

			var td string
			if svidWithKey.X509Svid.Id != nil {
				td = cleanTrustDomain(svidWithKey.X509Svid.Id.TrustDomain)
			} else if len(svidWithKey.X509Svid.CertChain) > 0 {
				leaf, err := x509.ParseCertificate(svidWithKey.X509Svid.CertChain[0])
				if err == nil && len(leaf.URIs) > 0 {
					td = cleanTrustDomain(leaf.URIs[0].Host)
				}
			}

			indexKey := fmt.Sprintf("%d", idx)
			newMap[indexKey] = &SVIDFileSystemState{
				CredentialBundle: bundle,
				Hint:             svidWithKey.X509Svid.Hint,
				Fingerprint:      bundleFingerprint(bundle),
				TrustDomain:      td,
			}
		}

		var cleanFederated []string
		for _, ftd := range resp.FederatesWith {
			cleanFederated = append(cleanFederated, cleanTrustDomain(ftd))
		}

		select {
		case <-ctx.Done():
			return false
		case out <- delegatedSVIDUpdate{registry: newMap, federated: cleanFederated}:
		}
	}
}

// watchGlobalX509Bundles keeps the process-wide bundle map current. The stream
// is process-wide rather than per-caller, which is exactly why subscribe has to
// fan its updates back out to every live caller.
func (ds *delegatedSource) watchGlobalX509Bundles(ctx context.Context, ready chan<- struct{}) {
	var signaled bool

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn, err := ds.dial(ctx)
		if err != nil {
			log.Printf("[Bundle-Watcher] Connection failed: %v. Retrying...", err)
			time.Sleep(5 * time.Second)
			continue
		}

		client := delegatedidentityv1.NewDelegatedIdentityClient(conn)
		stream, err := client.SubscribeToX509Bundles(ctx, &delegatedidentityv1.SubscribeToX509BundlesRequest{})
		if err != nil {
			log.Printf("[Bundle-Watcher] Stream subscription failed: %v. Retrying...", err)
			conn.Close()
			time.Sleep(5 * time.Second)
			continue
		}

		log.Printf("[Bundle-Watcher] Global trust bundle streaming subscription active")

		for {
			resp, err := stream.Recv()
			if err != nil {
				log.Printf("[Bundle-Watcher] Stream interrupted: %v", err)
				break
			}

			localMap := make(map[string][]byte)
			var parsedDomains []string

			for td, derCerts := range resp.CaCertificates {
				normTD := cleanTrustDomain(td)
				pemBundle, err := derBundleToPEM(derCerts)
				if err != nil {
					log.Printf("[Bundle-Watcher] Failed parsing DER bundle for %s: %v", td, err)
					continue
				}
				localMap[normTD] = pemBundle
				parsedDomains = append(parsedDomains, normTD)
			}
			sort.Strings(parsedDomains)

			ds.publishBundles(localMap)

			log.Printf("[Bundle-Watcher] Synced global trust bundles into memory for domains: %v", parsedDomains)

			if !signaled {
				close(ready)
				signaled = true
			}
		}
		conn.Close()
		time.Sleep(2 * time.Second)
	}
}

// publishBundles swaps in a new bundle map and wakes every live caller pump.
// Both happen under the same lock the pumps read with, so a pump that wakes is
// guaranteed to see the map that woke it.
func (ds *delegatedSource) publishBundles(bundles map[string][]byte) {
	ds.bundleMutex.Lock()
	defer ds.bundleMutex.Unlock()

	ds.bundles = bundles
	close(ds.bundleChan)
	ds.bundleChan = make(chan struct{})
}

func (ds *delegatedSource) dial(ctx context.Context) (*grpc.ClientConn, error) {
	return grpc.DialContext(ctx, fmt.Sprintf("unix://%s", ds.socketPath),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return net.DialTimeout("unix", ds.socketPath, 2*time.Second)
		}),
	)
}
