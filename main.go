package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
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
var _ fs.NodeOnAdder = (*MainRoot)(nil)

func (r *MainRoot) OnAdd(ctx context.Context) {
	stableAttr := fs.StableAttr{Mode: syscall.S_IFDIR | 0755}
	x509Inode := r.NewPersistentInode(ctx, &X509Dir{}, stableAttr)
	r.AddChild("x509", x509Inode, false)
}

type X509Dir struct {
	fs.Inode
}
var _ fs.NodeLookuper = (*X509Dir)(nil)
var _ fs.NodeReaddirer = (*X509Dir)(nil)

func (xd *X509Dir) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	caller, ok := fuse.FromContext(ctx)
	if !ok { return nil, syscall.EIO }

	state, alive := verifyOrCreatePidState(caller.Pid)
	if !alive { return nil, syscall.EACCES }

	stateMutex.RLock()
	_, exists := state.SvidRegistry[name]
	stateMutex.RUnlock()

	if !exists {
		return nil, syscall.ENOENT
	}

	stableAttr := fs.StableAttr{Mode: syscall.S_IFDIR | 0755}
	childNode := xd.NewPersistentInode(ctx, &IndexDir{indexName: name}, stableAttr)

	out.EntryValid = 0
	out.AttrValid = 0
	return childNode, 0
}

func (xd *X509Dir) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	caller, ok := fuse.FromContext(ctx)
	if !ok { return nil, syscall.EIO }

	state, alive := verifyOrCreatePidState(caller.Pid)
	if !alive { return nil, syscall.EACCES }

	stateMutex.RLock()
	var entries []fuse.DirEntry
	for k := range state.SvidRegistry {
		entries = append(entries, fuse.DirEntry{
			Name: k,
			Mode: syscall.S_IFDIR,
		})
	}
	stateMutex.RUnlock()
	return fs.NewListDirStream(entries), 0
}

type IndexDir struct {
	fs.Inode
	indexName string
}
var _ fs.NodeLookuper = (*IndexDir)(nil)
var _ fs.NodeReaddirer = (*IndexDir)(nil)

func (id *IndexDir) getBundleTargetDomains(pid uint32) ([]string, syscall.Errno) {
	stateMutex.RLock()
	state, exists := pidRegistry[pid]
	if !exists {
		stateMutex.RUnlock()
		return nil, syscall.ENOENT
	}
	svid, found := state.SvidRegistry[id.indexName]
	var domains []string
	if found && svid.TrustDomain != "" {
		domains = append(domains, svid.TrustDomain)
	}
	if found {
		domains = append(domains, state.FederatedTrustDomains...)
	}
	stateMutex.RUnlock()
	return domains, 0
}

func (id *IndexDir) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	caller, ok := fuse.FromContext(ctx)
	if !ok { return nil, syscall.EIO }

	state, alive := verifyOrCreatePidState(caller.Pid)
	if !alive { return nil, syscall.EACCES }

	stateMutex.RLock()
	svid, found := state.SvidRegistry[id.indexName]
	stateMutex.RUnlock()

	if !found { return nil, syscall.ENOENT }

	stableAttr := fs.StableAttr{Mode: syscall.S_IFREG | 0644}

	if name == "credential-bundle.pem" {
		return id.NewPersistentInode(ctx, &BundleFile{indexName: id.indexName}, stableAttr), 0
	}
	if name == "hint" && svid.HasHint {
		return id.NewPersistentInode(ctx, &HintFile{indexName: id.indexName}, stableAttr), 0
	}

	if strings.HasSuffix(name, ".spiffe-trust-bundle.pem") {
		targetDomain := strings.TrimSuffix(name, ".spiffe-trust-bundle.pem")
		domains, err := id.getBundleTargetDomains(caller.Pid)
		if err != 0 { return nil, err }

		for _, td := range domains {
			if td == targetDomain {
				bundleMutex.RLock()
				_, bundleExists := globalBundles[td]
				bundleMutex.RUnlock()

				if bundleExists {
					return id.NewPersistentInode(ctx, &TrustBundleFile{trustDomain: td}, stableAttr), 0
				}
			}
		}
	}

	return nil, syscall.ENOENT
}

func (id *IndexDir) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	caller, ok := fuse.FromContext(ctx)
	if !ok { return nil, syscall.EIO }

	state, alive := verifyOrCreatePidState(caller.Pid)
	if !alive { return nil, syscall.EACCES }

	stateMutex.RLock()
	svid, found := state.SvidRegistry[id.indexName]
	stateMutex.RUnlock()

	if !found { return nil, syscall.ENOENT }

	entries := []fuse.DirEntry{
		{Name: "credential-bundle.pem", Mode: syscall.S_IFREG},
	}
	if svid.HasHint {
		entries = append(entries, fuse.DirEntry{Name: "hint", Mode: syscall.S_IFREG})
	}

	domains, err := id.getBundleTargetDomains(caller.Pid)
	if err == 0 {
		bundleMutex.RLock()
		seen := make(map[string]bool)
		for _, td := range domains {
			if _, exists := globalBundles[td]; exists && !seen[td] {
				seen[td] = true
				entries = append(entries, fuse.DirEntry{
					Name: fmt.Sprintf("%s.spiffe-trust-bundle.pem", td),
					Mode: syscall.S_IFREG,
				})
			}
		}
		bundleMutex.RUnlock()
	}

	return fs.NewListDirStream(entries), 0
}

type snapshotHandle struct {
	content []byte
}

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
	return &snapshotHandle{content: snapshot}, fuse.FOPEN_NONSEEKABLE, 0
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
	return &snapshotHandle{content: snapshot}, fuse.FOPEN_NONSEEKABLE, 0
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

type HintFile struct { fs.Inode; indexName string }
var _ fs.NodeOpener = (*HintFile)(nil)
var _ fs.NodeReader = (*HintFile)(nil)
var _ fs.NodeGetattrer = (*HintFile)(nil)

func (h *HintFile) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	caller, ok := fuse.FromContext(ctx)
	if !ok { return nil, 0, syscall.EACCES }
	if _, alive := verifyOrCreatePidState(caller.Pid); !alive { return nil, 0, syscall.EACCES }

	stateMutex.RLock()
	state, exists := pidRegistry[caller.Pid]
	if !exists {
		stateMutex.RUnlock()
		return nil, 0, syscall.EIO
	}
	svid, found := state.SvidRegistry[h.indexName]
	stateMutex.RUnlock()
	if !found || !svid.HasHint { return nil, 0, syscall.EIO }

	content := []byte(svid.Hint + "\n")
	snapshot := make([]byte, len(content))
	copy(snapshot, content)
	return &snapshotHandle{content: snapshot}, fuse.FOPEN_NONSEEKABLE, 0
}

func (h *HintFile) Read(ctx context.Context, fh fs.FileHandle, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	return readHelper(fh.(*snapshotHandle).content, dest, off)
}

func (h *HintFile) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
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
	svid, found := state.SvidRegistry[h.indexName]
	stateMutex.RUnlock()
	if !found || !svid.HasHint { return syscall.EIO }
	out.Mode = syscall.S_IFREG | 0644
	out.Size = uint64(len(svid.Hint) + 1)
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

func main() {
	forceUnmount := flag.Bool("umount", false, "Forcefully unmount the target directory if it is already mounted or stuck")
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		log.Fatal("Usage: spiffefs [-umount] <mountpoint>")
	}
	mountPoint := args[0]

	if *forceUnmount {
		log.Printf("[FUSE-Engine] Attempting lazy unmount cleanup on: %s", mountPoint)
		err := unix.Unmount(mountPoint, unix.MNT_DETACH)
		if err != nil {
			log.Printf("[FUSE-Engine] Cleanup unmount notice (can be ignored if not previously mounted): %v", err)
		} else {
			log.Printf("[FUSE-Engine] Successfully detached previous stale mount at %s", mountPoint)
			time.Sleep(1 * time.Second)
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
	zeroDuration := time.Duration(0)

	opts := &fs.Options{
		EntryTimeout: &zeroDuration,
		AttrTimeout:  &zeroDuration,
		MountOptions: fuse.MountOptions{
			AllowOther: true,
			DirectMount: true,
		},
	}

	server, err := fs.Mount(mountPoint, root, opts)
	if err != nil {
		log.Fatalf("Mount initialization failed: %v", err)
	}

	log.Printf("SPIRE Transparent-Path FUSE Driver running at: %s", mountPoint)
	server.Wait()
}
