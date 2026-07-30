package option

import "github.com/sagernet/sing/common/json/badoption"

type AdaptivePoolOutboundOptions struct {
	GroupCommonOption
	Shadow        bool                             `json:"shadow,omitempty"`
	Probe         AdaptivePoolProbeOptions         `json:"probe,omitempty"`
	Capability    AdaptivePoolCapabilityOptions    `json:"capability,omitempty"`
	Qualification AdaptivePoolQualificationOptions `json:"qualification,omitempty"`
	State         AdaptivePoolStateOptions         `json:"state,omitempty"`
	Policy        AdaptivePoolPolicyOptions        `json:"policy,omitempty"`
}

type AdaptivePoolCapabilityOptions struct {
	Enabled             bool               `json:"enabled,omitempty"`
	BuiltinYouTubeTLS   bool               `json:"builtin_youtube_tls,omitempty"`
	BuiltinExitIdentity bool               `json:"builtin_exit_identity,omitempty"`
	ManifestURL         string             `json:"manifest_url,omitempty"`
	TrustedKeys         map[string]string  `json:"trusted_keys,omitempty"`
	RefreshInterval     badoption.Duration `json:"refresh_interval,omitempty"`
	Timeout             badoption.Duration `json:"timeout,omitempty"`
	Quorum              int                `json:"quorum,omitempty"`
	CommonModeMinNodes  int                `json:"common_mode_min_nodes,omitempty"`
}

// AdaptivePoolQualificationOptions configures control-plane service
// qualification. Data-plane connections only consume reduced eligibility
// evidence and never execute qualification probes.
type AdaptivePoolQualificationOptions struct {
	Enabled            bool               `json:"enabled,omitempty"`
	RefreshInterval    badoption.Duration `json:"refresh_interval,omitempty"`
	Timeout            badoption.Duration `json:"timeout,omitempty"`
	Quorum             int                `json:"quorum,omitempty"`
	CommonModeMinNodes int                `json:"common_mode_min_nodes,omitempty"`
}

type AdaptivePoolPolicyOptions struct {
	Default          string             `json:"default,omitempty"`
	StrictLeaseTTL   badoption.Duration `json:"strict_lease_ttl,omitempty"`
	AdaptiveLeaseTTL badoption.Duration `json:"adaptive_lease_ttl,omitempty"`
	MaxLeases        int                `json:"max_leases,omitempty"`
	MaxAttempts      int                `json:"max_attempts,omitempty"`
	AttemptTimeout   badoption.Duration `json:"attempt_timeout,omitempty"`
	HedgeDelay       badoption.Duration `json:"hedge_delay,omitempty"`
	ManualFailure    string             `json:"manual_failure,omitempty"`
	AIIPv6Policy     string             `json:"ai_ipv6_policy,omitempty"`
}

type AdaptivePoolProbeOptions struct {
	URL              string             `json:"url,omitempty"`
	CoverageInterval badoption.Duration `json:"coverage_interval,omitempty"`
	Timeout          badoption.Duration `json:"timeout,omitempty"`
	Concurrency      int                `json:"concurrency,omitempty"`
	QueueSize        int                `json:"queue_size,omitempty"`
}

type AdaptivePoolStateOptions struct {
	Path       string             `json:"path,omitempty"`
	Retention  badoption.Duration `json:"retention,omitempty"`
	MaxEntries int                `json:"max_entries,omitempty"`
}
