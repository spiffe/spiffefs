package main

// Tests for the deprecated Delegated Identity API upstream. They exist to cover
// the one part of it that is not just the original code moved: the delegated
// API delivers a caller's SVIDs and the trust bundles on two streams that move
// independently, so this source has to fan bundle updates back out to every
// live caller. Deleting this file goes with deleting delegated.go.

import (
	"context"
	"testing"
	"time"
)

func newTestDelegatedSource() *delegatedSource {
	return &delegatedSource{
		bundles:    make(map[string][]byte),
		bundleChan: make(chan struct{}),
	}
}

func recvPayload(t *testing.T, updates <-chan SVIDUpdatePayload) SVIDUpdatePayload {
	t.Helper()
	select {
	case payload, ok := <-updates:
		if !ok {
			t.Fatal("updates closed before a payload arrived")
		}
		return payload
	case <-time.After(5 * time.Second):
		t.Fatal("no payload arrived")
		return SVIDUpdatePayload{}
	}
}

func assertNoPayload(t *testing.T, updates <-chan SVIDUpdatePayload) {
	t.Helper()
	select {
	case payload := <-updates:
		t.Fatalf("unexpected payload: %+v", payload)
	case <-time.After(200 * time.Millisecond):
	}
}

// Bundles arriving before the caller's SVIDs do are not a snapshot worth
// sending: the caller would be shown trust bundles while its own identities
// still look absent, which reads as "attested, but entitled to nothing".
func TestDelegatedJoinWaitsForFirstSVIDUpdate(t *testing.T) {
	ds := newTestDelegatedSource()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	raw := make(chan delegatedSVIDUpdate, 1)
	updates := make(chan SVIDUpdatePayload, 4)
	go ds.join(ctx, raw, updates)

	ds.publishBundles(map[string][]byte{"example.org": []byte("bundle")})
	assertNoPayload(t, updates)

	raw <- delegatedSVIDUpdate{
		registry:  map[string]*SVIDFileSystemState{"0": {TrustDomain: "example.org"}},
		federated: nil,
	}

	payload := recvPayload(t, updates)
	if string(payload.Bundles["example.org"]) != "bundle" {
		t.Errorf("bundles = %v, want example.org", payload.Bundles)
	}
}

// The bundle stream is process-wide and can deliver long after a caller
// started. Without the re-emit, a workload that read early would sit with no
// trust bundle for as long as it lives, because nothing else comes back for it.
func TestDelegatedJoinReEmitsOnBundleChange(t *testing.T) {
	ds := newTestDelegatedSource()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	raw := make(chan delegatedSVIDUpdate, 1)
	updates := make(chan SVIDUpdatePayload, 4)
	go ds.join(ctx, raw, updates)

	raw <- delegatedSVIDUpdate{
		registry:  map[string]*SVIDFileSystemState{"0": {TrustDomain: "example.org"}},
		federated: []string{"other.org"},
	}

	first := recvPayload(t, updates)
	if len(first.Bundles) != 0 {
		t.Errorf("first payload carried %d bundles, want none yet", len(first.Bundles))
	}
	if len(first.Registry) != 1 {
		t.Errorf("first payload carried %d SVIDs, want 1", len(first.Registry))
	}

	ds.publishBundles(map[string][]byte{
		"example.org": []byte("local"),
		"other.org":   []byte("federated"),
		"unrelated":   []byte("not ours"),
	})

	second := recvPayload(t, updates)
	if string(second.Bundles["example.org"]) != "local" {
		t.Errorf("missing own trust domain bundle: %v", second.Bundles)
	}
	if string(second.Bundles["other.org"]) != "federated" {
		t.Errorf("missing federated bundle: %v", second.Bundles)
	}
	// A caller is only ever told about trust domains its own entry entitles
	// it to, never everything the agent happens to hold.
	if _, leaked := second.Bundles["unrelated"]; leaked {
		t.Error("served a trust domain the caller is not entitled to")
	}
}

// A trust domain with no bundle yet must not appear at all. An empty bundle
// file is worse than a missing one: a reader takes it for a valid, empty CA set.
func TestDelegatedSnapshotSkipsDomainsWithNoBundle(t *testing.T) {
	ds := newTestDelegatedSource()
	ds.publishBundles(map[string][]byte{"example.org": []byte("local")})

	payload := ds.snapshot(delegatedSVIDUpdate{
		registry:  map[string]*SVIDFileSystemState{"0": {TrustDomain: "example.org"}},
		federated: []string{"other.org", ""},
	})

	if len(payload.Bundles) != 1 {
		t.Fatalf("bundles = %v, want only example.org", payload.Bundles)
	}
	if _, ok := payload.Bundles["example.org"]; !ok {
		t.Error("missing example.org")
	}
}

// The caller exiting has to end the fan-out, or its goroutine outlives it.
func TestDelegatedJoinStopsWhenSVIDStreamEnds(t *testing.T) {
	ds := newTestDelegatedSource()
	raw := make(chan delegatedSVIDUpdate)
	updates := make(chan SVIDUpdatePayload, 1)
	go ds.join(context.Background(), raw, updates)

	close(raw)

	select {
	case _, ok := <-updates:
		if ok {
			t.Error("got a payload after the SVID stream ended")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("updates was never closed")
	}
}
