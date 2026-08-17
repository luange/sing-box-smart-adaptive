package adapter

import (
	"context"
	"net"
	"net/netip"
	"time"

	N "github.com/sagernet/sing/common/network"
)

// SpliceCapableConn is an optional extension for eBPF sockmap splice.
type SpliceCapableConn interface {
	// SpliceReady returns underlying TCP after framing is done; nil = not ready.
	SpliceReady() *net.TCPConn
}

// ConnectionSplicer is registered by eBPF inbound when outbound_offload.splice is on.
type ConnectionSplicer interface {
	TrySpliceTCP(
		ctx context.Context,
		inboundType string,
		dialer N.Dialer,
		local net.Conn,
		remote net.Conn,
		metadata InboundContext,
		onClose N.CloseHandlerFunc,
	) bool
}

// VerdictLearner is registered by eBPF inbound when outbound_offload.verdict.mode != off.
type VerdictLearner interface {
	MaybeLearnTCP(ctx context.Context, dialer N.Dialer, metadata InboundContext, remote netip.AddrPort)
	MaybeLearnUDP(ctx context.Context, dialer N.Dialer, metadata InboundContext, remote netip.AddrPort)
}

// DirectOffload is registered by eBPF inbound whenever the TC bypass surface is up.
// Route calls it after selecting a DIRECT/ebpf leaf so destination IPs are promoted
// into kernel bypass without waiting for dial-time learn.
type DirectOffload interface {
	NoteRoutedDirect(metadata InboundContext, outbound Outbound)
}

// SmartCandidateStatus is a snapshot of one smart leaf candidate.
type SmartCandidateStatus struct {
	Tag           string  `json:"tag"`
	State         string  `json:"state"`
	Score         float64 `json:"score"`
	Weight        float64 `json:"weight,omitempty"`
	WeightRule    string  `json:"weight_rule,omitempty"`
	WeightExact   bool    `json:"weight_rule_exact,omitempty"`
	Reliability   float64 `json:"reliability"`
	ConnectMS     float64 `json:"connect_ms,omitempty"`
	FirstByteMS   float64 `json:"first_byte_ms,omitempty"`
	ThroughputBPS float64 `json:"throughput_bps,omitempty"`
	Samples       float64 `json:"samples"`
	Reason        string  `json:"reason,omitempty"`
}

// SmartGroupStatus is exported for clash/API status surfaces.
type SmartGroupStatus struct {
	Selected                  string                 `json:"selected,omitempty"`
	Pinned                    string                 `json:"pinned,omitempty"`
	Network                   string                 `json:"network,omitempty"`
	Site                      string                 `json:"site,omitempty"`
	Reason                    string                 `json:"reason,omitempty"`
	UpdatedAt                 time.Time              `json:"updated_at,omitempty"`
	CandidateCount            int                    `json:"candidate_count"`
	CandidateDetailsCount     int                    `json:"candidate_details_count"`
	CandidateDetailsTruncated bool                   `json:"candidate_details_truncated"`
	StateCounts               map[string]int         `json:"state_counts"`
	TemporaryOverride         string                 `json:"temporary_override,omitempty"`
	OverrideExpiresAt         *time.Time             `json:"override_expires_at,omitempty"`
	OverrideRemainingSeconds  int64                  `json:"override_remaining_seconds,omitempty"`
	OverrideReason            string                 `json:"override_reason,omitempty"`
	SwitchesTotal             uint64                 `json:"switches_total,omitempty"`
	SwitchesForceAll          uint64                 `json:"switches_force_all,omitempty"`
	SwitchesSelective         uint64                 `json:"switches_selective,omitempty"`
	ConnectionsInterrupted    uint64                 `json:"connections_interrupted,omitempty"`
	ConnectionsKept           uint64                 `json:"connections_kept,omitempty"`
	Candidates                []SmartCandidateStatus `json:"candidates"`
}

// SmartGroup is implemented by protocol/group smart outbound.
type SmartGroup interface {
	URLTestGroup
	SmartStatus() SmartGroupStatus
	SelectOutbound(tag string) bool
	ClearSelection()
	SelectTemporaryOutbound(tag string, ttl time.Duration, reason string) bool
	ClearTemporarySelection()
}


// PreMatchDisabledOutbound keeps transparent flows on the L4 outbound path.
// Groups use it when resolving to a leaf would bypass retry or observation.
type PreMatchDisabledOutbound interface {
	DisablePreMatch()
}


// SelectorGroup is implemented by selector outbound (stable Selected leaf).
type SelectorGroup interface {
	Selected() Outbound
}
