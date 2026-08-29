package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hanwen/go-fuse/v2/fs"
	"golang.org/x/sys/unix"
)

// Readers reach for different syscalls depending on where their output goes,
// and which they pick changes between busybox versions, coreutils versions and
// kernels. Asserting through those tools tests them as much as it tests us, so
// exercise the syscalls directly against a real mount instead.
//
// The contract is that a read path may fail loudly, but must never report
// success while handing back less than the whole file. A short read that looks
// like a clean end of file is how a workload silently ends up with no
// credentials.

type readPath struct {
	name string
	read func(path string, want int) ([]byte, error)
}

func readPaths() []readPath {
	return []readPath{
		{"read", func(path string, _ int) ([]byte, error) {
			f, err := os.Open(path)
			if err != nil {
				return nil, err
			}
			defer f.Close()
			return io.ReadAll(f)
		}},
		{"pread", func(path string, want int) ([]byte, error) {
			f, err := os.Open(path)
			if err != nil {
				return nil, err
			}
			defer f.Close()
			buf := make([]byte, want)
			n, err := f.ReadAt(buf, 0)
			if err != nil && err != io.EOF {
				return nil, err
			}
			return buf[:n], nil
		}},
		{"sendfile-to-file", func(path string, want int) ([]byte, error) {
			return sendfileTo(path, want, false)
		}},
		{"sendfile-to-pipe", func(path string, want int) ([]byte, error) {
			return sendfileTo(path, want, true)
		}},
		{"splice-to-pipe", func(path string, want int) ([]byte, error) {
			f, err := os.Open(path)
			if err != nil {
				return nil, err
			}
			defer f.Close()

			var p [2]int
			if err := unix.Pipe2(p[:], 0); err != nil {
				return nil, err
			}
			defer unix.Close(p[0])

			n, err := unix.Splice(int(f.Fd()), nil, p[1], nil, want+1, 0)
			unix.Close(p[1])
			if err != nil {
				return nil, err
			}
			return drainPipe(p[0], int(n))
		}},
	}
}

func sendfileTo(path string, want int, toPipe bool) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if !toPipe {
		out, err := os.CreateTemp("", "sendfile")
		if err != nil {
			return nil, err
		}
		defer os.Remove(out.Name())
		defer out.Close()

		if _, err := unix.Sendfile(int(out.Fd()), int(f.Fd()), nil, want+1); err != nil {
			return nil, err
		}
		return os.ReadFile(out.Name())
	}

	var p [2]int
	if err := unix.Pipe2(p[:], 0); err != nil {
		return nil, err
	}
	defer unix.Close(p[0])

	n, err := unix.Sendfile(p[1], int(f.Fd()), nil, want+1)
	unix.Close(p[1])
	if err != nil {
		return nil, err
	}
	return drainPipe(p[0], n)
}

func drainPipe(fd int, n int) ([]byte, error) {
	if n <= 0 {
		return nil, nil
	}
	buf := make([]byte, n)
	read := 0
	for read < n {
		got, err := unix.Read(fd, buf[read:])
		if err != nil {
			return nil, err
		}
		if got == 0 {
			break
		}
		read += got
	}
	return buf[:read], nil
}

// seedReadPathState installs state for this process directly, so the test needs
// no SPIRE agent. verifyOrCreatePidState hands back an entry that is already
// present and whose pidfd is alive, so nothing tries to reach the agent.
func seedReadPathState(t *testing.T) map[string][]byte {
	t.Helper()

	pid := uint32(os.Getpid())
	pidFd, err := unix.PidfdOpen(int(pid), 0)
	if err != nil {
		t.Skipf("pidfd_open is unavailable: %v", err)
	}
	t.Cleanup(func() { unix.Close(pidFd) })

	// Big enough that a splice has to move more than a token amount, small
	// enough to sit inside a pipe buffer without a concurrent reader.
	bundle := []byte(strings.Repeat("-----BEGIN PRIVATE KEY-----\nnot a real key\n-----END PRIVATE KEY-----\n", 100))
	trust := []byte(strings.Repeat("-----BEGIN CERTIFICATE-----\nnot a real cert\n-----END CERTIFICATE-----\n", 100))

	registry := map[string]*SVIDFileSystemState{
		"0": {
			CredentialBundle: bundle,
			Hint:             "main",
			Fingerprint:      bundleFingerprint(bundle),
			TrustDomain:      "example.org",
		},
	}

	stateMutex.Lock()
	pidRegistry[pid] = &PidState{
		Pid:          pid,
		PidFd:        pidFd,
		CancelFunc:   func() {},
		SvidRegistry: registry,
	}
	stateMutex.Unlock()
	t.Cleanup(func() {
		stateMutex.Lock()
		delete(pidRegistry, pid)
		stateMutex.Unlock()
	})

	bundleMutex.Lock()
	globalBundles = map[string][]byte{"example.org": trust}
	bundleMutex.Unlock()

	hints, err := buildHintsJSON(registry)
	if err != nil {
		t.Fatalf("buildHintsJSON: %v", err)
	}

	return map[string][]byte{
		credentialBundleName:               bundle,
		trustBundleFileName("example.org"): trust,
		hintsFileName:                      hints,
	}
}

func TestReadPathsDeliverWholeFile(t *testing.T) {
	want := seedReadPathState(t)

	dir := t.TempDir()
	server, err := fs.Mount(dir, &MainRoot{}, mountOptions())
	if err != nil {
		t.Skipf("cannot mount fuse, needs /dev/fuse and privileges: %v", err)
	}
	t.Cleanup(func() {
		if err := server.Unmount(); err != nil {
			_ = unix.Unmount(dir, unix.MNT_DETACH)
		}
	})

	for name, content := range want {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name)

			if fi, err := os.Stat(path); err != nil {
				t.Fatalf("stat: %v", err)
			} else if fi.Size() != int64(len(content)) {
				// The size reported at lookup is what a splicing reader trusts;
				// if it is wrong, sendfile hands back nothing and calls it EOF.
				t.Fatalf("stat reports %d bytes, file holds %d", fi.Size(), len(content))
			}

			for _, rp := range readPaths() {
				t.Run(rp.name, func(t *testing.T) {
					got, err := rp.read(path, len(content))
					if err != nil {
						t.Logf("%s failed: %v (acceptable, callers fall back)", rp.name, err)
						return
					}
					if !bytes.Equal(got, content) {
						t.Fatalf("%s reported success with %d of %d bytes", rp.name, len(got), len(content))
					}
				})
			}
		})
	}
}
