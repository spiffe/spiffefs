package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestCredentialBundleFileName(t *testing.T) {
	cases := map[int]string{
		0:  "credential-bundle.private-key.x509.pem",
		1:  "1.credential-bundle.private-key.x509.pem",
		2:  "2.credential-bundle.private-key.x509.pem",
		10: "10.credential-bundle.private-key.x509.pem",
	}

	for idx, want := range cases {
		if got := credentialBundleFileName(idx); got != want {
			t.Errorf("credentialBundleFileName(%d) = %q, want %q", idx, got, want)
		}
	}
}

func TestParseCredentialBundleFileNameRoundTrip(t *testing.T) {
	for _, idx := range []int{0, 1, 2, 10, 4096} {
		name := credentialBundleFileName(idx)
		got, ok := parseCredentialBundleFileName(name)
		if !ok {
			t.Errorf("parseCredentialBundleFileName(%q) rejected a name we emit", name)
			continue
		}
		if got != idx {
			t.Errorf("parseCredentialBundleFileName(%q) = %d, want %d", name, got, idx)
		}
	}
}

func TestParseCredentialBundleFileNameRejects(t *testing.T) {
	rejects := []string{
		"0.credential-bundle.private-key.x509.pem",  // index 0 only uses the bare name
		"01.credential-bundle.private-key.x509.pem", // leading zero
		"+1.credential-bundle.private-key.x509.pem",
		"-1.credential-bundle.private-key.x509.pem",
		"foo.credential-bundle.private-key.x509.pem",
		".credential-bundle.private-key.x509.pem",
		"1..credential-bundle.private-key.x509.pem",
		"credential-bundle.pem",   // the old name
		"1/credential-bundle.pem", // the old path shape
		"credential-bundle.private-key.x509.pem.bak",
		"hints.json",
		"",
	}

	for _, name := range rejects {
		if idx, ok := parseCredentialBundleFileName(name); ok {
			t.Errorf("parseCredentialBundleFileName(%q) accepted, returning %d", name, idx)
		}
	}
}

func TestTrustBundleFileName(t *testing.T) {
	if got, want := trustBundleFileName("example.org"), "example.org.spiffe-trust-bundle.x509.pem"; got != want {
		t.Errorf("trustBundleFileName = %q, want %q", got, want)
	}

	for _, td := range []string{"example.org", "other.org", "a.b.c.example"} {
		got, ok := parseTrustBundleFileName(trustBundleFileName(td))
		if !ok || got != td {
			t.Errorf("round trip of %q gave (%q, %v)", td, got, ok)
		}
	}
}

func TestParseTrustBundleFileNameRejects(t *testing.T) {
	rejects := []string{
		".spiffe-trust-bundle.x509.pem",       // no trust domain
		"example.org.spiffe-trust-bundle.pem", // the old suffix
		"example.org.spiffe-trust-bundle.x509.pem.bak",
		"credential-bundle.private-key.x509.pem",
		"",
	}

	for _, name := range rejects {
		if td, ok := parseTrustBundleFileName(name); ok {
			t.Errorf("parseTrustBundleFileName(%q) accepted, returning %q", name, td)
		}
	}
}

func TestCertFingerprint(t *testing.T) {
	der := []byte("not a real certificate, but the digest does not care")
	got := certFingerprint(der)

	if !strings.HasPrefix(got, "sha256:") {
		t.Fatalf("fingerprint %q is missing the sha256: prefix", got)
	}

	digest := strings.TrimPrefix(got, "sha256:")
	pairs := strings.Split(digest, ":")
	if len(pairs) != sha256.Size {
		t.Fatalf("fingerprint %q has %d byte pairs, want %d", got, len(pairs), sha256.Size)
	}

	if digest != strings.ToUpper(digest) {
		t.Errorf("fingerprint %q is not uppercase", got)
	}

	sum := sha256.Sum256(der)
	if want := strings.ToUpper(hex.EncodeToString(sum[:])); strings.ReplaceAll(digest, ":", "") != want {
		t.Errorf("fingerprint digest = %q, want %q", digest, want)
	}
}

func decodeHints(t *testing.T, registry map[string]*SVIDFileSystemState) (hintsDoc, []byte) {
	t.Helper()

	raw, err := buildHintsJSON(registry)
	if err != nil {
		t.Fatalf("buildHintsJSON: %v", err)
	}
	if !strings.HasSuffix(string(raw), "\n") {
		t.Errorf("hints document does not end in a newline: %q", raw)
	}

	var doc hintsDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("hints document is not valid JSON: %v (%q)", err, raw)
	}
	return doc, raw
}

func TestBuildHintsJSONEmpty(t *testing.T) {
	_, raw := decodeHints(t, map[string]*SVIDFileSystemState{})

	if strings.Contains(string(raw), "null") {
		t.Errorf("empty registry must render an empty array, got %q", raw)
	}
	if !strings.Contains(string(raw), `"hints": []`) {
		t.Errorf("empty registry rendered as %q, want an empty hints array", raw)
	}
}

func TestBuildHintsJSONOrdersNumerically(t *testing.T) {
	registry := map[string]*SVIDFileSystemState{
		"10": {Hint: "ten", Fingerprint: "sha256:AA"},
		"2":  {Hint: "two", Fingerprint: "sha256:BB"},
		"0":  {Hint: "zero", Fingerprint: "sha256:CC"},
	}

	doc, _ := decodeHints(t, registry)

	wantIDs := []int{0, 2, 10}
	if len(doc.Hints) != len(wantIDs) {
		t.Fatalf("got %d entries, want %d", len(doc.Hints), len(wantIDs))
	}
	for i, want := range wantIDs {
		if doc.Hints[i].ID != want {
			t.Errorf("entry %d has id %d, want %d (lexical rather than numeric sort?)", i, doc.Hints[i].ID, want)
		}
	}

	if doc.Hints[0].Hint != "zero" || doc.Hints[0].Fingerprint != "sha256:CC" {
		t.Errorf("entry 0 = %+v, want the registry's \"0\" entry", doc.Hints[0])
	}
}

func TestBuildHintsJSONIncludesHintlessSVIDs(t *testing.T) {
	registry := map[string]*SVIDFileSystemState{
		"0": {Hint: "", Fingerprint: "sha256:AA"},
	}

	doc, raw := decodeHints(t, registry)

	if len(doc.Hints) != 1 {
		t.Fatalf("got %d entries, want 1: a hintless SVID still gets an entry", len(doc.Hints))
	}
	if doc.Hints[0].Hint != "" {
		t.Errorf("hint = %q, want empty", doc.Hints[0].Hint)
	}
	if !strings.Contains(string(raw), `"hint": ""`) {
		t.Errorf("hintless entry should serialize an empty hint, got %q", raw)
	}
}

func TestBuildHintsJSONPreservesSparseIndices(t *testing.T) {
	registry := map[string]*SVIDFileSystemState{
		"0": {Hint: "main", Fingerprint: "sha256:AA"},
		"2": {Hint: "other", Fingerprint: "sha256:BB"},
	}

	doc, _ := decodeHints(t, registry)

	if len(doc.Hints) != 2 {
		t.Fatalf("got %d entries, want 2", len(doc.Hints))
	}
	if doc.Hints[0].ID != 0 || doc.Hints[1].ID != 2 {
		t.Errorf("ids = %d, %d; want 0, 2 preserved from the source indices", doc.Hints[0].ID, doc.Hints[1].ID)
	}

	if name := credentialBundleFileName(doc.Hints[1].ID); name != "2.credential-bundle.private-key.x509.pem" {
		t.Errorf("sparse id 2 maps to %q", name)
	}
}
