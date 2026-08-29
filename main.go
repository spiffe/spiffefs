package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/unix"
)

type PidState struct {
	Pid                   uint32
	PidFd                 int
	CancelFunc            context.CancelFunc
	SvidRegistry          map[string]*SVIDFileSystemState
	FederatedTrustDomains []string
}

var (
	stateMutex    sync.RWMutex
	pidRegistry   = make(map[uint32]*PidState)
	spireSocket   = "/var/run/spire/agent/sockets/main/private/admin.sock"

	bundleMutex   sync.RWMutex
	globalBundles = make(map[string][]byte)
)

func isPidFdAlive(fd int) bool {
	pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	n, err := unix.Poll(pfd, 0)
	if err != nil && err != unix.EINTR {
		return false
	}
	return n == 0
}

func verifyOrCreatePidState(callerPid uint32) (*PidState, bool) {
	if callerPid == 0 {
		return nil, false
	}

	stateMutex.Lock()

	if state, exists := pidRegistry[callerPid]; exists {
		if isPidFdAlive(state.PidFd) {
			stateMutex.Unlock()
			return state, true
		}

		log.Printf("[System-Reaper] Inline eviction of dead process state for PID %d", callerPid)
		state.CancelFunc()
		delete(pidRegistry, callerPid)
	}

	fd, err := unix.PidfdOpen(int(callerPid), 0)
	if err != nil {
		stateMutex.Unlock()
		return nil, false
	}

	ctx, cancel := context.WithCancel(context.Background())
	updateChan := make(chan SVIDUpdatePayload, 2)
	readyChan := make(chan struct{})

	state := &PidState{
		Pid:                   callerPid,
		PidFd:                 fd,
		CancelFunc:            cancel,
		SvidRegistry:          make(map[string]*SVIDFileSystemState),
		FederatedTrustDomains: []string{},
	}
	pidRegistry[callerPid] = state

	go func(p uint32, pidFd int, c context.CancelFunc) {
		defer unix.Close(pidFd)
		defer c()

		pfd := []unix.PollFd{{Fd: int32(pidFd), Events: unix.POLLIN}}
		for {
			n, err := unix.Poll(pfd, -1)
			if err == unix.EINTR {
				continue
			}
			if err != nil || n > 0 {
				stateMutex.Lock()
				if current, exists := pidRegistry[p]; exists && current.PidFd == pidFd {
					log.Printf("[System-Reaper] Process %d terminated. Evicting state.", p)
					delete(pidRegistry, p)
				}
				stateMutex.Unlock()
				return
			}
		}
	}(callerPid, fd, cancel)

	go fetchSpireSVIDsForPID(ctx, spireSocket, callerPid, updateChan)

	var once sync.Once
	go func(p uint32, s *PidState) {
		for payload := range updateChan {
			stateMutex.Lock()
			if current, exists := pidRegistry[p]; exists && current == s {
				s.SvidRegistry = payload.Registry
				s.FederatedTrustDomains = payload.Federated
				log.Printf("[Registry-Update] Refreshed %d SVIDs and %d federated domains for PID %d", len(payload.Registry), len(payload.Federated), p)
			}
			stateMutex.Unlock()

			once.Do(func() { close(readyChan) })
		}
	}(callerPid, state)

	stateMutex.Unlock()

	select {
	case <-readyChan:
	case <-time.After(2 * time.Second):
		log.Printf("[System] Timeout waiting for initial SVID fetch for PID %d", callerPid)
	}

	stateMutex.RLock()
	defer stateMutex.RUnlock()

	if current, exists := pidRegistry[callerPid]; exists && current == state {
		return current, true
	}
	return nil, false
}

type MainRoot struct {
	fs.Inode
}

var _ fs.NodeLookuper = (*MainRoot)(nil)
var _ fs.NodeReaddirer = (*MainRoot)(nil)

// bundleTargetDomains returns the trust domains this PID should be handed a
// bundle for: its own SVIDs' domains plus everything it federates with, minus
// any domain we have not actually received a bundle for. Deduped and sorted so
// readdir output is stable.
func bundleTargetDomains(pid uint32) ([]string, syscall.Errno) {
	stateMutex.RLock()
	state, exists := pidRegistry[pid]
	if !exists {
		stateMutex.RUnlock()
		return nil, syscall.ENOENT
	}

	seen := make(map[string]bool)
	for _, svid := range state.SvidRegistry {
		if svid.TrustDomain != "" {
			seen[svid.TrustDomain] = true
		}
	}
	for _, td := range state.FederatedTrustDomains {
		if td != "" {
			seen[td] = true
		}
	}
	stateMutex.RUnlock()

	var domains []string
	bundleMutex.RLock()
	for td := range seen {
		if _, ok := globalBundles[td]; ok {
			domains = append(domains, td)
		}
	}
	bundleMutex.RUnlock()

	sort.Strings(domains)
	return domains, 0
}

func (r *MainRoot) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	caller, ok := fuse.FromContext(ctx)
	if !ok { return nil, syscall.EIO }

	state, alive := verifyOrCreatePidState(caller.Pid)
	if !alive { return nil, syscall.EACCES }

	fileAttr := fs.StableAttr{Mode: syscall.S_IFREG | 0644}

	out.EntryValid = 0
	out.AttrValid = 0

	if name == hintsFileName {
		content, errno := hintsContentForPid(ctx)
		if errno != 0 { return nil, errno }
		setLookupAttr(out, len(content))
		return r.NewPersistentInode(ctx, &HintsFile{}, fileAttr), 0
	}

	if idx, ok := parseCredentialBundleFileName(name); ok {
		indexName := fmt.Sprintf("%d", idx)

		stateMutex.RLock()
		svid, found := state.SvidRegistry[indexName]
		var size int
		if found {
			size = len(svid.CredentialBundle)
		}
		stateMutex.RUnlock()

		if found {
			setLookupAttr(out, size)
			return r.NewPersistentInode(ctx, &BundleFile{indexName: indexName}, fileAttr), 0
		}
		return nil, syscall.ENOENT
	}

	if targetDomain, ok := parseTrustBundleFileName(name); ok {
		domains, err := bundleTargetDomains(caller.Pid)
		if err != 0 { return nil, err }

		for _, td := range domains {
			if td == targetDomain {
				bundleMutex.RLock()
				size := len(globalBundles[td])
				bundleMutex.RUnlock()

				setLookupAttr(out, size)
				return r.NewPersistentInode(ctx, &TrustBundleFile{trustDomain: td}, fileAttr), 0
			}
		}
	}

	return nil, syscall.ENOENT
}

// setLookupAttr reports the file's size in the lookup reply. Without it the
// kernel takes i_size to be 0, and a reader that splices rather than reads --
// sendfile(2), which is what busybox cat does when its output is a pipe -- gets
// nothing back and reports a clean EOF. The read path is unaffected because it
// issues its own getattr first. Nothing is cached here: attrValid stays zero, so
// the kernel still asks again next time.
func setLookupAttr(out *fuse.EntryOut, size int) {
	out.Attr.Mode = syscall.S_IFREG | 0644
	out.Attr.Size = uint64(size)
}

func (r *MainRoot) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	caller, ok := fuse.FromContext(ctx)
	if !ok { return nil, syscall.EIO }

	state, alive := verifyOrCreatePidState(caller.Pid)
	if !alive { return nil, syscall.EACCES }

	entries := []fuse.DirEntry{
		{Name: hintsFileName, Mode: syscall.S_IFREG},
	}

	stateMutex.RLock()
	for key := range state.SvidRegistry {
		idx, err := strconv.Atoi(key)
		if err != nil {
			continue
		}
		entries = append(entries, fuse.DirEntry{
			Name: credentialBundleFileName(idx),
			Mode: syscall.S_IFREG,
		})
	}
	stateMutex.RUnlock()

	domains, err := bundleTargetDomains(caller.Pid)
	if err == 0 {
		for _, td := range domains {
			entries = append(entries, fuse.DirEntry{
				Name: trustBundleFileName(td),
				Mode: syscall.S_IFREG,
			})
		}
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return fs.NewListDirStream(entries), 0
}

type snapshotHandle struct {
	content []byte
}

// Every caller gets its own credentials from the same path, so the kernel must
// never answer a read from a page cache shared between them. Nothing is cached
// today anyway, because a fresh inode is minted on each lookup, but that is a
// side effect rather than a promise: say it outright so the guarantee survives
// any later change to how inodes are handed out.
//
// This replaced FOPEN_NONSEEKABLE, which was only ever working around a missing
// size in the lookup reply. With the size reported, that flag bought nothing and
// cost pread and sendfile-to-a-file, which had to fail and let callers fall back
// rather than simply working.
const openFlags = fuse.FOPEN_DIRECT_IO

type TrustBundleFile struct {
	fs.Inode
	trustDomain string
}
var _ fs.NodeOpener = (*TrustBundleFile)(nil)
var _ fs.NodeReader = (*TrustBundleFile)(nil)
var _ fs.NodeGetattrer = (*TrustBundleFile)(nil)

func (t *TrustBundleFile) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	bundleMutex.RLock()
	content, exists := globalBundles[t.trustDomain]
	bundleMutex.RUnlock()
	if !exists { return nil, 0, syscall.EIO }

	snapshot := make([]byte, len(content))
	copy(snapshot, content)
	return &snapshotHandle{content: snapshot}, openFlags, 0
}

func (t *TrustBundleFile) Read(ctx context.Context, fh fs.FileHandle, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	return readHelper(fh.(*snapshotHandle).content, dest, off)
}

func (t *TrustBundleFile) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	if fh != nil {
		if sh, ok := fh.(*snapshotHandle); ok {
			out.Mode = syscall.S_IFREG | 0644
			out.Size = uint64(len(sh.content))
			return 0
		}
	}
	bundleMutex.RLock()
	content, exists := globalBundles[t.trustDomain]
	bundleMutex.RUnlock()
	if !exists { return syscall.EIO }
	out.Mode = syscall.S_IFREG | 0644
	out.Size = uint64(len(content))
	return 0
}

type BundleFile struct { fs.Inode; indexName string }
var _ fs.NodeOpener = (*BundleFile)(nil)
var _ fs.NodeReader = (*BundleFile)(nil)
var _ fs.NodeGetattrer = (*BundleFile)(nil)

func (b *BundleFile) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	caller, ok := fuse.FromContext(ctx)
	if !ok { return nil, 0, syscall.EACCES }
	if _, alive := verifyOrCreatePidState(caller.Pid); !alive { return nil, 0, syscall.EACCES }

	stateMutex.RLock()
	state, exists := pidRegistry[caller.Pid]
	if !exists {
		stateMutex.RUnlock()
		return nil, 0, syscall.EIO
	}
	svid, found := state.SvidRegistry[b.indexName]
	stateMutex.RUnlock()
	if !found { return nil, 0, syscall.EIO }

	snapshot := make([]byte, len(svid.CredentialBundle))
	copy(snapshot, svid.CredentialBundle)
	return &snapshotHandle{content: snapshot}, openFlags, 0
}

func (b *BundleFile) Read(ctx context.Context, fh fs.FileHandle, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	return readHelper(fh.(*snapshotHandle).content, dest, off)
}

func (b *BundleFile) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	if fh != nil {
		if sh, ok := fh.(*snapshotHandle); ok {
			out.Mode = syscall.S_IFREG | 0644
			out.Size = uint64(len(sh.content))
			return 0
		}
	}
	caller, ok := fuse.FromContext(ctx)
	if !ok { return syscall.EACCES }

	state, alive := verifyOrCreatePidState(caller.Pid)
	if !alive { return syscall.EACCES }

	stateMutex.RLock()
	svid, found := state.SvidRegistry[b.indexName]
	stateMutex.RUnlock()
	if !found { return syscall.EIO }
	out.Mode = syscall.S_IFREG | 0644
	out.Size = uint64(len(svid.CredentialBundle))
	return 0
}

type HintsFile struct { fs.Inode }
var _ fs.NodeOpener = (*HintsFile)(nil)
var _ fs.NodeReader = (*HintsFile)(nil)
var _ fs.NodeGetattrer = (*HintsFile)(nil)

// hintsContentForPid renders the hints document for the calling process. An
// empty registry is not an error; it renders as an empty hints array.
func hintsContentForPid(ctx context.Context) ([]byte, syscall.Errno) {
	caller, ok := fuse.FromContext(ctx)
	if !ok { return nil, syscall.EACCES }

	state, alive := verifyOrCreatePidState(caller.Pid)
	if !alive { return nil, syscall.EACCES }

	stateMutex.RLock()
	content, err := buildHintsJSON(state.SvidRegistry)
	stateMutex.RUnlock()
	if err != nil {
		log.Printf("[Hints] Failed rendering hints for PID %d: %v", caller.Pid, err)
		return nil, syscall.EIO
	}
	return content, 0
}

func (h *HintsFile) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	content, errno := hintsContentForPid(ctx)
	if errno != 0 { return nil, 0, errno }
	return &snapshotHandle{content: content}, openFlags, 0
}

func (h *HintsFile) Read(ctx context.Context, fh fs.FileHandle, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	return readHelper(fh.(*snapshotHandle).content, dest, off)
}

func (h *HintsFile) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	if fh != nil {
		if sh, ok := fh.(*snapshotHandle); ok {
			out.Mode = syscall.S_IFREG | 0644
			out.Size = uint64(len(sh.content))
			return 0
		}
	}
	content, errno := hintsContentForPid(ctx)
	if errno != 0 { return errno }
	out.Mode = syscall.S_IFREG | 0644
	out.Size = uint64(len(content))
	return 0
}

func readHelper(content []byte, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	if off >= int64(len(content)) {
		return fuse.ReadResultData(nil), 0
	}
	end := off + int64(len(dest))
	if end > int64(len(content)) {
		end = int64(len(content))
	}
	return fuse.ReadResultData(content[off:end]), 0
}

// isFuseMount reports whether path is the mount point of a fuse filesystem.
// Anything else at that path is not ours to unmount: under a container runtime
// it is the bind mount the filesystem is served through, and detaching that
// severs the mount propagation the mount depends on.
func isFuseMount(path string) bool {
	f, err := os.Open("/proc/self/mounts")
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		if fields[1] == path && strings.HasPrefix(fields[2], "fuse") {
			return true
		}
	}
	return false
}

// mountOptions is shared with the tests so they exercise the same settings the
// binary runs with. Nothing is cached: the filesystem serves different content
// to different callers, so a kernel cache shared across them could hand one
// workload another's credentials.
func mountOptions() *fs.Options {
	zeroDuration := time.Duration(0)
	return &fs.Options{
		EntryTimeout: &zeroDuration,
		AttrTimeout:  &zeroDuration,
		MountOptions: fuse.MountOptions{
			AllowOther:  true,
			DirectMount: true,
		},
	}
}

func main() {
	forceUnmount := flag.Bool("umount", false, "Take ownership of the mount point: clear a stale fuse mount at startup, and unmount on SIGINT or SIGTERM. Without this a mount outliving the process is left disconnected, so reads fail loudly instead of falling through to whatever is underneath.")
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		log.Fatal("Usage: spiffefs [-umount] <mountpoint>")
	}
	mountPoint := args[0]

	if *forceUnmount {
		if !isFuseMount(mountPoint) {
			log.Printf("[FUSE-Engine] Nothing to clean up at %s: it is not a fuse mount", mountPoint)
		} else {
			log.Printf("[FUSE-Engine] Attempting lazy unmount cleanup on: %s", mountPoint)
			err := unix.Unmount(mountPoint, unix.MNT_DETACH)
			if err != nil {
				log.Printf("[FUSE-Engine] Cleanup unmount notice: %v", err)
			} else {
				log.Printf("[FUSE-Engine] Successfully detached previous stale mount at %s", mountPoint)
				time.Sleep(1 * time.Second)
			}
		}
	}

	if envSocket := os.Getenv("SPIFFE_ENDPOINT_SOCKET"); envSocket != "" {
		spireSocket = envSocket
	}
	log.Printf("[FUSE-Engine] Transparent mapping active against socket: %s", spireSocket)

	readyChan := make(chan struct{})
	go watchGlobalX509Bundles(context.Background(), spireSocket, readyChan)

	select {
	case <-readyChan:
		log.Printf("[FUSE-Engine] Initial trust bundles primed successfully")
	case <-time.After(3 * time.Second):
		log.Printf("[FUSE-Engine] Timeout waiting for trust bundles; mounting anyway")
	}

	root := &MainRoot{}

	server, err := fs.Mount(mountPoint, root, mountOptions())
	if err != nil {
		log.Fatalf("Mount initialization failed: %v", err)
	}

	log.Printf("SPIRE Transparent-Path FUSE Driver running at: %s", mountPoint)

	// Only unmount on the way out when asked to. A mount that outlives the
	// process is dead rather than merely idle, and every read of it fails with
	// ENOTCONN. That is usually what you want: it is louder, and safer, than
	// reverting the path to whatever sits under the mount point. Under a
	// container runtime it is not, because the runtime cannot bind a dead mount
	// and so the replacement instance never starts.
	if *forceUnmount {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			sig := <-sigChan
			log.Printf("[FUSE-Engine] Received %s, unmounting %s", sig, mountPoint)
			if err := server.Unmount(); err != nil {
				// Unmount refuses while the filesystem is in use, so detach it
				// instead. Leaving it behind is worse than tearing it out from
				// under a reader.
				log.Printf("[FUSE-Engine] Unmount failed: %v. Detaching instead.", err)
				if err := unix.Unmount(mountPoint, unix.MNT_DETACH); err != nil {
					log.Printf("[FUSE-Engine] Detach also failed: %v", err)
				}
			}
		}()
	}

	server.Wait()
}
