package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
)

type SVIDFileSystemState struct {
	CredentialBundle []byte
	Hint             string
	Fingerprint      string
	TrustDomain      string
}

// SVIDUpdatePayload is one complete snapshot of what a single caller is
// entitled to: every SVID issued to it, and every trust bundle it should
// trust. Both halves are replaced wholesale on each update rather than
// merged, so a revoked identity or a dropped federation disappears instead of
// lingering.
//
// Bundles is scoped to the caller, not to the process. The Broker API delivers
// it that way; the delegated source synthesizes it from its process-wide
// bundle stream. Keeping the FS on the per-caller shape means it never has to
// know which upstream answered.
type SVIDUpdatePayload struct {
	Registry map[string]*SVIDFileSystemState
	Bundles  map[string][]byte
}

// identitySource supplies callers' credentials. There is one implementation
// per upstream API; main picks one at startup and nothing downstream of that
// choice asks which it got.
type identitySource interface {
	// subscribe keeps pid's credentials up to date on updates until ctx is
	// cancelled, closing updates before it returns. It is expected to retry
	// internally: a caller that reads before its registration entry has
	// propagated must not be left with no credentials for as long as it
	// lives, and nothing else will come back for it.
	subscribe(ctx context.Context, pid uint32, updates chan<- SVIDUpdatePayload)
}

// cleanTrustDomain reduces a SPIFFE ID, or a bare trust domain, to just the
// trust domain name. The FS names bundle files after it.
func cleanTrustDomain(td string) string {
	td = strings.TrimPrefix(td, "spiffe://")
	return strings.Split(td, "/")[0]
}

// derBundleToPEM re-encodes a trust bundle. Both upstream APIs hand bundles
// over as concatenated ASN.1 DER; the FS serves PEM, because that is what the
// consumers of these files expect to point a CA path at.
func derBundleToPEM(der []byte) ([]byte, error) {
	certs, err := x509.ParseCertificates(der)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	for _, cert := range certs {
		if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// buildCredentialBundle renders the single file a workload reads to get a
// usable identity: its private key first, then its certificate chain, leaf
// first.
func buildCredentialBundle(privKeyDER []byte, certChainDER [][]byte) ([]byte, error) {
	if len(privKeyDER) == 0 || len(certChainDER) == 0 {
		return nil, fmt.Errorf("malformed SVID payload blocks from SPIRE")
	}

	var buf bytes.Buffer

	privBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privKeyDER,
	}
	if err := pem.Encode(&buf, privBlock); err != nil {
		return nil, err
	}

	for _, certDER := range certChainDER {
		certBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certDER,
		}
		if err := pem.Encode(&buf, certBlock); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}
