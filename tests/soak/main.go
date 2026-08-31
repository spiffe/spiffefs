// Command spiffefs-soak-client is the workload half of the soak test. It runs
// inside a randomly named transient systemd unit, alongside many others, and
// asserts that spiffefs served it its own identities and nothing else.
//
// The layout constants below are deliberately a second, independent copy of the
// filesystem's naming rules rather than an import. A soak run should fail when
// the served layout stops matching what a consumer was told to expect, which is
// exactly what sharing the constants would hide.
package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	credentialBundleName = "credential-bundle.private-key.x509.pem"
	trustBundleSuffix    = ".spiffe-trust-bundle.x509.pem"
	hintsFileName        = "hints.json"
)

func credentialBundleFileName(idx int) string {
	if idx == 0 {
		return credentialBundleName
	}
	return fmt.Sprintf("%d.%s", idx, credentialBundleName)
}

func trustBundleFileName(td string) string {
	return td + trustBundleSuffix
}

// expectation is the complete truth about what this workload's registration
// entries entitle it to. The driver writes it out when it creates the entries.
type expectation struct {
	SVIDs []struct {
		Hint     string `json:"hint"`
		SPIFFEID string `json:"spiffe_id"`
	} `json:"svids"`
	TrustDomains []string `json:"trust_domains"`
}

func (e expectation) ids() map[string]string {
	out := make(map[string]string, len(e.SVIDs))
	for _, s := range e.SVIDs {
		out[s.SPIFFEID] = s.Hint
	}
	return out
}

func (e expectation) trustDomains() map[string]bool {
	out := make(map[string]bool, len(e.TrustDomains))
	for _, td := range e.TrustDomains {
		out[td] = true
	}
	return out
}

// A fatal error is one no amount of waiting can fix, because it says a workload
// was served something that is not its own. Everything else is the system still
// converging -- an entry that has not propagated yet, a file that has not
// appeared -- and is retried until the deadline.
type fatalError struct{ err error }

func (f fatalError) Error() string { return f.err.Error() }
func (f fatalError) Unwrap() error { return f.err }

func fatalf(format string, a ...any) error {
	return fatalError{fmt.Errorf(format, a...)}
}

func isFatal(err error) bool {
	var f fatalError
	return errors.As(err, &f)
}

func main() {
	name := flag.String("name", "soak", "This workload's name, for log messages")
	mount := flag.String("mount", "/tmp/mnt", "spiffefs mount point")
	expectFile := flag.String("expect-file", "", "Path to the JSON expectation for this workload")
	maxWait := flag.Duration("max-wait", 3*time.Second, "Upper bound on the random pause before reading")
	deadline := flag.Duration("deadline", 60*time.Second, "How long to wait for this workload's entries to propagate")
	flag.Parse()

	if *expectFile == "" {
		fail(*name, fmt.Errorf("-expect-file is required"))
	}

	raw, err := os.ReadFile(*expectFile)
	if err != nil {
		fail(*name, fmt.Errorf("reading expectation: %w", err))
	}
	var exp expectation
	if err := json.Unmarshal(raw, &exp); err != nil {
		fail(*name, fmt.Errorf("parsing expectation: %w", err))
	}

	// Land at an unpredictable point relative to the other workloads and to our
	// own entries propagating.
	pause := time.Duration(rand.Int63n(int64(*maxWait) + 1))
	fmt.Printf("soak %s: pausing %s before reading\n", *name, pause)
	time.Sleep(pause)

	run, where := pickReader()
	fmt.Printf("soak %s: reading from %s\n", *name, where)

	err = run(func() error {
		return verify(*mount, exp, time.Now().Add(*deadline))
	})
	if err != nil {
		fail(*name, err)
	}
	fmt.Printf("soak %s: ok\n", *name)
}

func fail(name string, err error) {
	fmt.Fprintf(os.Stderr, "soak %s: FAIL: %v\n", name, err)
	os.Exit(1)
}

// pickReader chooses, at random, whether this run's reads happen on the process
// group leader or on some other thread. The distinction matters: fuse reports
// the calling *thread* id, and spiffefs has to map it back to the process
// before it can look up who is asking.
func pickReader() (func(func() error) error, string) {
	if rand.Intn(2) == 0 {
		return func(f func() error) error {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			return f()
		}, fmt.Sprintf("the group leader (tid %d)", unix.Gettid())
	}

	// The first locked goroutine can land on the main thread, since the main
	// goroutine is parked waiting for it. It stays locked either way, so a
	// retry is guaranteed a different thread.
	for attempt := 0; attempt < 4; attempt++ {
		run, tid := lockedThreadRunner()
		if tid != os.Getpid() {
			return run, fmt.Sprintf("a worker thread (tid %d, pid %d)", tid, os.Getpid())
		}
	}

	// Thread scheduling is not ours to assert on. Say so and read anyway.
	return func(f func() error) error { return f() }, "the group leader (no worker thread came free)"
}

// lockedThreadRunner starts a goroutine pinned to one OS thread and returns a
// function that runs closures on it, plus that thread's id.
func lockedThreadRunner() (func(func() error) error, int) {
	type request struct {
		f    func() error
		done chan error
	}

	requests := make(chan request)
	tids := make(chan int, 1)

	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		tids <- unix.Gettid()
		for r := range requests {
			r.done <- r.f()
		}
	}()

	return func(f func() error) error {
		done := make(chan error, 1)
		requests <- request{f: f, done: done}
		return <-done
	}, <-tids
}

// verify retries until the workload's view matches its entries, or until the
// deadline. A fatal error ends it immediately: waiting cannot un-serve another
// workload's credentials.
func verify(mount string, exp expectation, deadline time.Time) error {
	var last error
	for {
		err := check(mount, exp)
		if err == nil {
			return nil
		}
		if isFatal(err) {
			return err
		}
		last = err

		if time.Now().After(deadline) {
			return fmt.Errorf("did not converge before the deadline: %w", last)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func check(mount string, exp expectation) error {
	entries, err := os.ReadDir(mount)
	if err != nil {
		return fmt.Errorf("listing %s: %w", mount, err)
	}

	wantIDs := exp.ids()
	wantTDs := exp.trustDomains()

	var served []string
	for _, entry := range entries {
		served = append(served, entry.Name())
	}
	sort.Strings(served)

	// Anything served that our own entries do not account for came from
	// somewhere else. That is the whole point of this test, so it is checked
	// first and unconditionally, before any convergence reasoning.
	bundles := make(map[string]*credential)
	for _, name := range served {
		switch {
		case name == hintsFileName:

		case strings.HasSuffix(name, trustBundleSuffix):
			td := strings.TrimSuffix(name, trustBundleSuffix)
			if !wantTDs[td] {
				return fatalf("served a trust bundle for %q; our entries cover only %v", td, exp.TrustDomains)
			}

		case name == credentialBundleName || strings.HasSuffix(name, "."+credentialBundleName):
			cred, err := loadCredential(filepath.Join(mount, name))
			switch {
			case errors.Is(err, fs.ErrNotExist):
				// It went away between the listing and the read, which is
				// what an identity being withdrawn looks like.
				return fmt.Errorf("reading %s: %w", name, err)
			case err != nil:
				// Anything else -- unparseable PEM, a key that does not
				// match its certificate -- is not something waiting fixes.
				return fatalf("%s is not a usable credential: %v", name, err)
			}
			if _, ours := wantIDs[cred.spiffeID]; !ours {
				return fatalf("served %s for %q, which is not one of ours (%v)", name, cred.spiffeID, sortedKeys(wantIDs))
			}
			bundles[name] = cred

		default:
			return fatalf("served unexpected file %q", name)
		}
	}

	// Everything present belongs to us. Now wait for everything of ours to be
	// present.
	for td := range wantTDs {
		if _, err := os.Stat(filepath.Join(mount, trustBundleFileName(td))); err != nil {
			return fmt.Errorf("trust bundle for %s not served yet", td)
		}
	}

	hints, err := loadHints(filepath.Join(mount, hintsFileName))
	if err != nil {
		return fmt.Errorf("reading %s: %w", hintsFileName, err)
	}
	if len(hints) != len(exp.SVIDs) {
		return fmt.Errorf("hints.json lists %d SVIDs, want %d", len(hints), len(exp.SVIDs))
	}

	// Indexes are assigned in the order the upstream returned the entries, which
	// is not the order they were created in, so every mapping is checked by
	// hint rather than by position.
	for _, want := range exp.SVIDs {
		hint, ok := hints[want.Hint]
		if !ok {
			return fmt.Errorf("hints.json has no entry for hint %q", want.Hint)
		}

		fileName := credentialBundleFileName(hint.ID)
		cred, ok := bundles[fileName]
		if !ok {
			return fmt.Errorf("hint %q points at %s, which was not served", want.Hint, fileName)
		}
		if cred.spiffeID != want.SPIFFEID {
			return fatalf("hint %q resolves to %s holding %q, want %q", want.Hint, fileName, cred.spiffeID, want.SPIFFEID)
		}

		// The advertised fingerprint has to be a plain digest of the bytes a
		// reader gets, so a rotation between reading hints.json and reading the
		// bundle is detectable without parsing any PEM. A mismatch is retried
		// because that is precisely what a rotation looks like.
		if got := fingerprint(cred.raw); got != hint.Fingerprint {
			return fmt.Errorf("hint %q advertises fingerprint %s, but %s hashes to %s", want.Hint, hint.Fingerprint, fileName, got)
		}
	}

	// A credential served under a name no hint points at would be an extra
	// identity smuggled in alongside ours.
	if len(bundles) != len(hints) {
		return fmt.Errorf("served %d credential bundles but hints.json lists %d", len(bundles), len(hints))
	}

	return checkTrustBundles(mount, exp, bundles)
}

func checkTrustBundles(mount string, exp expectation, bundles map[string]*credential) error {
	roots := x509.NewCertPool()

	for _, td := range exp.TrustDomains {
		raw, err := os.ReadFile(filepath.Join(mount, trustBundleFileName(td)))
		if err != nil {
			return fmt.Errorf("reading trust bundle for %s: %w", td, err)
		}
		certs, err := parseCertsPEM(raw)
		if err != nil {
			return fmt.Errorf("parsing trust bundle for %s: %w", td, err)
		}
		if len(certs) == 0 {
			return fmt.Errorf("trust bundle for %s is empty", td)
		}

		// The bundle filed under a trust domain has to actually be that trust
		// domain's, or the name is a lie and a workload would trust the wrong
		// authority.
		var matched bool
		for _, cert := range certs {
			for _, uri := range cert.URIs {
				if uri.Scheme == "spiffe" && uri.Host == td {
					matched = true
				}
			}
			roots.AddCert(cert)
		}
		if !matched {
			return fatalf("trust bundle for %s carries no certificate identifying that trust domain", td)
		}
	}

	for name, cred := range bundles {
		intermediates := x509.NewCertPool()
		for _, cert := range cred.chain[1:] {
			intermediates.AddCert(cert)
		}
		if _, err := cred.chain[0].Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}); err != nil {
			return fmt.Errorf("%s does not chain to the served trust bundles: %w", name, err)
		}
	}

	return nil
}

type credential struct {
	raw      []byte
	chain    []*x509.Certificate
	spiffeID string
}

// loadCredential also proves the key and the leaf belong together. A file that
// pairs one workload's key with another's certificate would otherwise read as
// perfectly well formed.
func loadCredential(path string) (*credential, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	pair, err := tls.X509KeyPair(raw, raw)
	if err != nil {
		return nil, fmt.Errorf("key and certificate do not form a pair: %w", err)
	}

	chain := make([]*x509.Certificate, 0, len(pair.Certificate))
	for _, der := range pair.Certificate {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		chain = append(chain, cert)
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("no certificates")
	}
	if len(chain[0].URIs) == 0 {
		return nil, fmt.Errorf("leaf certificate carries no SPIFFE ID")
	}

	return &credential{raw: raw, chain: chain, spiffeID: chain[0].URIs[0].String()}, nil
}

type hintEntry struct {
	Hint        string `json:"hint"`
	ID          int    `json:"id"`
	Fingerprint string `json:"fingerprint"`
}

// loadHints returns the document keyed by hint. A repeated hint is an error:
// the hint is what a workload uses to pick an identity, so two answers to the
// same question is not a thing a reader can act on.
func loadHints(path string) (map[string]hintEntry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var doc struct {
		Hints []hintEntry `json:"hints"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}

	out := make(map[string]hintEntry, len(doc.Hints))
	for _, h := range doc.Hints {
		if _, dup := out[h.Hint]; dup {
			return nil, fmt.Errorf("hint %q listed more than once", h.Hint)
		}
		out[h.Hint] = h
	}
	return out, nil
}

func fingerprint(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func parseCertsPEM(raw []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for len(raw) > 0 {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			return nil, fmt.Errorf("trailing data is not PEM")
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
