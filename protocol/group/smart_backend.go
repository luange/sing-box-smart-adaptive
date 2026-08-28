package group

import (
	"hash/fnv"
	"time"
)

// smartPolicyBackend is the small portability boundary between the Smart
// host (provider discovery, EndpointProfile and dialing) and the policy
// kernel.  A backend must own its selection state; the host must not run a
// second confirmation/cooldown state machine for the same decision.
type smartPolicyBackend interface {
	Choose(key string, candidates []smartPolicyCandidate, profile smartTrafficProfile, now time.Time) smartPolicyDecision
	Observe(key string, id uint64, success bool, elapsed time.Duration, now time.Time)
	Reset()
	Close()
}

type smartPolicyCandidate struct {
	ID          uint64
	Reliability float64
	ConnectMS   float64
	FirstByteMS float64
	JitterMS    float64
	Throughput  float64
	Samples     float64
	Weight      float64
	State       uint8
	Eligible    bool
}

type smartPolicyDecision struct {
	SelectedID uint64
	Score      float64
	Switched   bool
	Reason     uint8
}

// betterSmartPolicyCandidate merges duplicate subscription lines that resolve
// to one endpoint. Prefer a usable line over an open one, then retain the
// strongest evidence so one stale provider copy cannot poison the shared
// endpoint profile.
func betterSmartPolicyCandidate(left, right smartPolicyCandidate) bool {
	leftOpen, rightOpen := left.State == smartPolicyState("open"), right.State == smartPolicyState("open")
	if leftOpen != rightOpen {
		return !leftOpen
	}
	if left.Reliability != right.Reliability {
		return left.Reliability > right.Reliability
	}
	if left.Samples != right.Samples {
		return left.Samples > right.Samples
	}
	if left.ConnectMS != right.ConnectMS {
		return left.ConnectMS > 0 && (right.ConnectMS <= 0 || left.ConnectMS < right.ConnectMS)
	}
	if left.FirstByteMS != right.FirstByteMS {
		return left.FirstByteMS > 0 && (right.FirstByteMS <= 0 || left.FirstByteMS < right.FirstByteMS)
	}
	return left.Throughput > right.Throughput
}

// smartPolicyID is derived from the canonical Endpoint identity, not the
// provider display tag.  Numeric suffixes added to duplicate subscription
// lines therefore share one policy profile and cannot cause oscillation.
func smartPolicyID(identity string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte("sing-box/smart-policy/v1\x00"))
	_, _ = h.Write([]byte(identity))
	id := h.Sum64()
	if id == 0 {
		return 1
	}
	return id
}

func smartPolicyState(state string) uint8 {
	switch state {
	case "healthy":
		return 1
	case "warming":
		return 2
	case "suspect", "half_open":
		return 3
	case "open":
		return 4
	default:
		return 0
	}
}
