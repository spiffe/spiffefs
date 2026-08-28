package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	delegatedidentityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/delegatedidentity/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type SVIDFileSystemState struct {
	CredentialBundle []byte
	Hint             string
	Fingerprint      string
	TrustDomain      string
}

type SVIDUpdatePayload struct {
	Registry  map[string]*SVIDFileSystemState
	Federated []string
}

func cleanTrustDomain(td string) string {
	td = strings.TrimPrefix(td, "spiffe://")
	return strings.Split(td, "/")[0]
}

func fetchSpireSVIDsForPID(ctx context.Context, socketPath string, pid uint32, updateChan chan<- SVIDUpdatePayload) {
	defer close(updateChan)

	conn, err := grpc.DialContext(ctx, fmt.Sprintf("unix://%s", socketPath),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return net.DialTimeout("unix", socketPath, 2*time.Second)
		}),
	)
	if err != nil {
		log.Printf("[SPIRE-Client] Failed connecting to SPIRE socket %s: %v", socketPath, err)
		return
	}
	defer conn.Close()

	client := delegatedidentityv1.NewDelegatedIdentityClient(conn)

	req := &delegatedidentityv1.SubscribeToX509SVIDsRequest{
		Pid: int32(pid),
	}

	stream, err := client.SubscribeToX509SVIDs(ctx, req)
	if err != nil {
		log.Printf("[SPIRE-Client] Failed subscribing to SVID watch stream for PID %d: %v", pid, err)
		return
	}

	log.Printf("[SPIRE-Client] Active identity watch established for PID %d", pid)

	for {
		resp, err := stream.Recv()
		if err != nil {
			log.Printf("[SPIRE-Client] Identity stream closed/interrupted for PID %d: %v", pid, err)
			return
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
				Fingerprint:      certFingerprint(svidWithKey.X509Svid.CertChain[0]),
				TrustDomain:      td,
			}
		}

		var cleanFederated []string
		for _, ftd := range resp.FederatesWith {
			cleanFederated = append(cleanFederated, cleanTrustDomain(ftd))
		}

		payload := SVIDUpdatePayload{
			Registry:  newMap,
			Federated: cleanFederated,
		}

		select {
		case <-ctx.Done():
			return
		case updateChan <- payload:
		}
	}
}

func watchGlobalX509Bundles(ctx context.Context, socketPath string, ready chan<- struct{}) {
	var signaled bool

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn, err := grpc.DialContext(ctx, fmt.Sprintf("unix://%s", socketPath),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
				return net.DialTimeout("unix", socketPath, 2*time.Second)
			}),
		)
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
				var buf bytes.Buffer

				certs, err := x509.ParseCertificates(derCerts)
				if err != nil {
					log.Printf("[Bundle-Watcher] Failed parsing DER bundle for %s: %v", td, err)
					continue
				}
				for _, cert := range certs {
					pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
				}
				localMap[normTD] = buf.Bytes()
				parsedDomains = append(parsedDomains, normTD)
			}

			bundleMutex.Lock()
			globalBundles = localMap
			bundleMutex.Unlock()

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
