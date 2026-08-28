package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const (
	credentialBundleName = "credential-bundle.private-key.x509.pem"
	trustBundleSuffix    = ".spiffe-trust-bundle.x509.pem"
	hintsFileName        = "hints.json"
)

type hintEntry struct {
	Hint        string `json:"hint"`
	ID          int    `json:"id"`
	Fingerprint string `json:"fingerprint"`
}

type hintsDoc struct {
	Hints []hintEntry `json:"hints"`
}

// credentialBundleFileName returns the on-disk name for the SVID at idx. The
// first SVID is delivered under the bare name; the rest carry their index.
func credentialBundleFileName(idx int) string {
	if idx == 0 {
		return credentialBundleName
	}
	return fmt.Sprintf("%d.%s", idx, credentialBundleName)
}

// parseCredentialBundleFileName is the exact inverse of
// credentialBundleFileName. It only accepts names this filesystem would emit,
// so "0.credential-bundle.private-key.x509.pem" and "01.<name>" are rejected.
func parseCredentialBundleFileName(name string) (int, bool) {
	if name == credentialBundleName {
		return 0, true
	}

	prefix, ok := strings.CutSuffix(name, "."+credentialBundleName)
	if !ok || prefix == "" {
		return 0, false
	}

	idx, err := strconv.Atoi(prefix)
	if err != nil || idx < 1 || credentialBundleFileName(idx) != name {
		return 0, false
	}
	return idx, true
}

func trustBundleFileName(td string) string {
	return td + trustBundleSuffix
}

func parseTrustBundleFileName(name string) (string, bool) {
	td, ok := strings.CutSuffix(name, trustBundleSuffix)
	if !ok || td == "" {
		return "", false
	}
	return td, true
}

// certFingerprint renders the SHA-256 of a DER certificate the way
// `openssl x509 -noout -fingerprint -sha256` does, prefixed with the algorithm
// so other digests can be introduced later.
func certFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	encoded := strings.ToUpper(hex.EncodeToString(sum[:]))

	var sb strings.Builder
	sb.WriteString("sha256:")
	for i := 0; i < len(encoded); i += 2 {
		if i > 0 {
			sb.WriteByte(':')
		}
		sb.WriteString(encoded[i : i+2])
	}
	return sb.String()
}

// buildHintsJSON renders the hints document for a PID's SVID registry. Every
// SVID gets an entry, hinted or not, ordered by ascending index.
func buildHintsJSON(registry map[string]*SVIDFileSystemState) ([]byte, error) {
	doc := hintsDoc{Hints: make([]hintEntry, 0, len(registry))}

	for key, svid := range registry {
		idx, err := strconv.Atoi(key)
		if err != nil {
			continue
		}
		doc.Hints = append(doc.Hints, hintEntry{
			Hint:        svid.Hint,
			ID:          idx,
			Fingerprint: svid.Fingerprint,
		})
	}

	sort.Slice(doc.Hints, func(i, j int) bool {
		return doc.Hints[i].ID < doc.Hints[j].ID
	})

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}
