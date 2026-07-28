package adaptive

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"net/netip"
	"strings"
	"sync"
)

const maxProcessExitIdentityEntries = 65536

type exitIdentityGroupState struct {
	identities map[NodeID][16]byte
	changes    uint64
}

var processExitIdentities struct {
	once   sync.Once
	key    [32]byte
	err    error
	access sync.Mutex
	groups map[string]*exitIdentityGroupState
}

// ExitIdentityStore is process-local by design. It survives configuration
// reloads, but the baseline disappears when the sing-box process exits. Raw
// addresses and even their keyed fingerprints are never exposed by its API.
type ExitIdentityStore struct {
	groupID string
}

func NewExitIdentityStore(groupID string) (*ExitIdentityStore, error) {
	groupID = strings.TrimSpace(groupID)
	if groupID == "" {
		return nil, errors.New("adaptive exit identity group is empty")
	}
	processExitIdentities.once.Do(func() {
		_, processExitIdentities.err = rand.Read(processExitIdentities.key[:])
		processExitIdentities.groups = make(map[string]*exitIdentityGroupState)
	})
	if processExitIdentities.err != nil {
		return nil, errors.New("adaptive exit identity key initialization failed")
	}
	return &ExitIdentityStore{groupID: groupID}, nil
}

func tokenizeExitIdentity(value []byte) ([16]byte, bool) {
	address, err := netip.ParseAddr(strings.TrimSpace(string(value)))
	if err != nil || !address.IsValid() || address.IsUnspecified() || address.IsLoopback() || address.IsPrivate() || address.IsMulticast() {
		return [16]byte{}, false
	}
	canonical := address.Unmap().String()
	digest := hmac.New(sha256.New, processExitIdentities.key[:])
	_, _ = digest.Write([]byte(canonical))
	sum := digest.Sum(nil)
	var token [16]byte
	copy(token[:], sum[:len(token)])
	return token, true
}

func (s *ExitIdentityStore) Observe(handle NodeHandle, token [16]byte) (changed bool, accepted bool) {
	if s == nil || s.groupID == "" || handle.NodeID == (NodeID{}) || token == ([16]byte{}) {
		return false, false
	}
	processExitIdentities.access.Lock()
	defer processExitIdentities.access.Unlock()
	group := processExitIdentities.groups[s.groupID]
	if group == nil {
		group = &exitIdentityGroupState{identities: make(map[NodeID][16]byte)}
		processExitIdentities.groups[s.groupID] = group
	}
	previous, loaded := group.identities[handle.NodeID]
	if !loaded {
		entries := 0
		for _, state := range processExitIdentities.groups {
			entries += len(state.identities)
		}
		if entries >= maxProcessExitIdentityEntries {
			return false, false
		}
		group.identities[handle.NodeID] = token
		return false, true
	}
	if hmac.Equal(previous[:], token[:]) {
		return false, true
	}
	group.identities[handle.NodeID] = token
	group.changes++
	return true, true
}

func (s *ExitIdentityStore) Stats() (baselines, changes uint64) {
	if s == nil {
		return 0, 0
	}
	processExitIdentities.access.Lock()
	defer processExitIdentities.access.Unlock()
	group := processExitIdentities.groups[s.groupID]
	if group == nil {
		return 0, 0
	}
	return uint64(len(group.identities)), group.changes
}
