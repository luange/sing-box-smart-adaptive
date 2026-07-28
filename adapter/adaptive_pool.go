package adapter

import (
	"context"
	"errors"
	"time"
)

var (
	ErrAdaptiveCapabilityUnavailable = errors.New("adaptive capability probe is unavailable")
	ErrAdaptiveCapabilityBusy        = errors.New("adaptive capability probe is already running")
)

type AdaptiveCandidateStatus struct {
	NodeID                string    `json:"node_id"`
	EndpointID            string    `json:"endpoint_id,omitempty"`
	EndpointConflictCount int       `json:"endpoint_conflict_count,omitempty"`
	NodeSlot              uint64    `json:"node_slot"`
	NodeVersion           uint64    `json:"node_version"`
	Tag                   string    `json:"tag"`
	Aliases               []string  `json:"aliases,omitempty"`
	IdentityStable        bool      `json:"identity_stable"`
	State                 string    `json:"state"`
	Health                string    `json:"health"`
	Breaker               string    `json:"breaker"`
	LastProbeAt           time.Time `json:"last_probe_at,omitempty"`
	LastProbeDelay        uint16    `json:"last_probe_delay,omitempty"`
	ThroughputBPS         float64   `json:"throughput_bps,omitempty"`
	ThroughputSamples     uint64    `json:"throughput_samples,omitempty"`
	Successes             uint64    `json:"successes,omitempty"`
	Failures              uint64    `json:"failures,omitempty"`
	EvidenceWeight        float64   `json:"evidence_weight,omitempty"`
	OpenUntil             time.Time `json:"open_until,omitempty"`
	Reason                string    `json:"reason,omitempty"`
}

type AdaptiveSwitchAudit struct {
	ServiceID     string    `json:"service_id"`
	OldNodeID     string    `json:"old_node_id,omitempty"`
	OldTag        string    `json:"old_tag,omitempty"`
	NewNodeID     string    `json:"new_node_id,omitempty"`
	NewTag        string    `json:"new_tag,omitempty"`
	Reason        string    `json:"reason"`
	Failure       string    `json:"failure,omitempty"`
	FailureSource string    `json:"failure_source,omitempty"`
	OccurredAt    time.Time `json:"occurred_at"`
}

type AdaptiveServiceLease struct {
	ServiceID string    `json:"service_id"`
	Mode      string    `json:"mode"`
	NodeID    string    `json:"node_id"`
	Tag       string    `json:"tag,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type AdaptivePoolStatus struct {
	Shadow                          bool                      `json:"shadow"`
	Generation                      uint64                    `json:"generation"`
	CandidateCount                  int                       `json:"candidate_count"`
	AliasCount                      int                       `json:"alias_count"`
	DuplicatesSuppressed            int                       `json:"duplicates_suppressed"`
	EndpointConflictCount           int                       `json:"endpoint_conflict_count"`
	StableIdentityCount             int                       `json:"stable_identity_count"`
	ProbeQueueDepth                 int                       `json:"probe_queue_depth"`
	ProbeOwnerEpoch                 uint64                    `json:"probe_owner_epoch"`
	ProbeOwnerGeneration            uint64                    `json:"probe_owner_generation"`
	ProbeAcceptedTotal              uint64                    `json:"probe_accepted_total"`
	ProbeCoalescedTotal             uint64                    `json:"probe_coalesced_total"`
	ProbeDeferredTotal              uint64                    `json:"probe_deferred_total"`
	ProbeRejectedTotal              uint64                    `json:"probe_rejected_total"`
	ProbeCompletedTotal             uint64                    `json:"probe_completed_total"`
	ProbeSchedulerStalledTotal      uint64                    `json:"probe_scheduler_stalled_total"`
	CapabilityEnabled               bool                      `json:"capability_enabled"`
	CapabilityRunning               bool                      `json:"capability_running"`
	CapabilityCyclesStarted         uint64                    `json:"capability_cycles_started"`
	CapabilityCyclesCompleted       uint64                    `json:"capability_cycles_completed"`
	CapabilityInitFailures          uint64                    `json:"capability_init_failures"`
	CapabilityRefreshFailures       uint64                    `json:"capability_refresh_failures"`
	CapabilityViewFailures          uint64                    `json:"capability_view_failures"`
	CapabilitySuiteFailures         uint64                    `json:"capability_suite_failures"`
	CapabilityLastFailureStage      string                    `json:"capability_last_failure_stage,omitempty"`
	CapabilityTargetGeneration      uint64                    `json:"capability_target_generation"`
	ExitIdentityBaselines           uint64                    `json:"exit_identity_baselines"`
	ExitIdentityChangesTotal        uint64                    `json:"exit_identity_changes_total"`
	ExitIdentitySaturatedNodes      uint64                    `json:"exit_identity_saturated_nodes"`
	StateEntries                    int                       `json:"state_entries"`
	StateEvictions                  uint64                    `json:"state_evictions"`
	StatePersistenceFailures        uint64                    `json:"state_persistence_failures"`
	MissedObservations              uint64                    `json:"missed_observations"`
	ObservationStaleTotal           uint64                    `json:"observation_stale_total"`
	ObservationDuplicateTotal       uint64                    `json:"observation_duplicate_total"`
	ObservationBackpressureTotal    uint64                    `json:"observation_backpressure_total"`
	ObservationReducerFailureTotal  uint64                    `json:"observation_reducer_failure_total"`
	ObservationIdentityFailureTotal uint64                    `json:"observation_identity_failure_total"`
	ObservationPanicTotal           uint64                    `json:"observation_panic_total"`
	ObservationPermitBusyTotal      uint64                    `json:"observation_permit_busy_total"`
	BusinessTLSFailuresTotal        uint64                    `json:"business_tls_failures_total"`
	TransportFailuresTotal          uint64                    `json:"transport_failures_total"`
	SelectionSwitchesTotal          uint64                    `json:"selection_switches_total"`
	Mode                            string                    `json:"mode"`
	Pinned                          string                    `json:"pinned,omitempty"`
	ActiveLeases                    int                       `json:"active_leases"`
	LeaseEvictions                  uint64                    `json:"lease_evictions"`
	BulkSequence                    uint64                    `json:"bulk_sequence"`
	ControlRevision                 uint64                    `json:"control_revision"`
	ServiceOverrideCount            int                       `json:"service_override_count"`
	ActiveBindingCount              int                       `json:"active_binding_count"`
	RetiredBindingCount             uint64                    `json:"retired_binding_count"`
	DeltaAppliedTotal               uint64                    `json:"delta_applied_total"`
	DeltaFallbackTotal              uint64                    `json:"delta_fallback_total"`
	UpdatedAt                       time.Time                 `json:"updated_at,omitempty"`
	Candidates                      []AdaptiveCandidateStatus `json:"candidates"`
	RecentSwitches                  []AdaptiveSwitchAudit     `json:"recent_switches,omitempty"`
	ServiceLeases                   []AdaptiveServiceLease    `json:"service_leases,omitempty"`
}

type AdaptivePoolGroup interface {
	URLTestGroup
	AdaptiveStatus() AdaptivePoolStatus
	TriggerAdaptiveProbe(context.Context) error
	TriggerAdaptiveCapabilityProbe(context.Context) error
	SelectAdaptiveOutbound(string) bool
	ClearAdaptiveSelection()
}

type AdaptivePoolRevisioned interface {
	SelectAdaptiveOutboundAt(string, uint64) bool
	ClearAdaptiveSelectionAt(uint64) bool
	AdaptiveSelectionRevision() uint64
}

type AdaptiveServiceOverride struct {
	ServiceID string    `json:"service_id"`
	Mode      string    `json:"mode"`
	ExpiresAt time.Time `json:"expires_at"`
}

type AdaptivePoolServiceControl interface {
	SetAdaptiveServiceOverride(serviceID, mode string, ttl time.Duration, expectedRevision uint64) error
	ClearAdaptiveServiceOverride(serviceID string, expectedRevision uint64) error
	AdaptiveServiceOverrides() []AdaptiveServiceOverride
}
