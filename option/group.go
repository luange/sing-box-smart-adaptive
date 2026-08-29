package option

import "github.com/sagernet/sing/common/json/badoption"

type SelectorOutboundOptions struct {
	GroupCommonOption
	Default                   string `json:"default,omitempty" reference:"outbound"`
	InterruptExistConnections bool   `json:"interrupt_exist_connections,omitempty"`
}

type URLTestOutboundOptions struct {
	GroupCommonOption
	URL                       string                 `json:"url,omitempty"`
	Interval                  badoption.Duration     `json:"interval,omitempty"`
	Tolerance                 uint16                 `json:"tolerance,omitempty"`
	IdleTimeout               badoption.Duration     `json:"idle_timeout,omitempty"`
	InterruptExistConnections bool                   `json:"interrupt_exist_connections,omitempty"`
	Fallback                  URLTestFallbackOptions `json:"fallback,omitempty"`
}

type GroupCommonOption struct {
	Outbounds       []string                   `json:"outbounds" reference:"outbound"`
	Providers       []string                   `json:"providers" reference:"provider"`
	Exclude         *badoption.Regexp          `json:"exclude,omitempty"`
	Include         *badoption.Regexp          `json:"include,omitempty"`
	ExcludeNodes    badoption.Listable[string] `json:"exclude_nodes,omitempty"`
	NodeWeights     []NodeWeightOptions        `json:"node_weights,omitempty"`
	UseAllProviders bool                       `json:"use_all_providers,omitempty"`
}

type NodeWeightOptions struct {
	Match  string  `json:"match"`
	Weight float64 `json:"weight"`
}

type URLTestFallbackOptions struct {
	Enabled  bool               `json:"enabled,omitempty"`
	MaxDelay badoption.Duration `json:"max_delay,omitempty"`
}

type LoadBalanceOutboundOptions struct {
	GroupCommonOption
	URL                       string             `json:"url,omitempty"`
	Interval                  badoption.Duration `json:"interval,omitempty"`
	IdleTimeout               badoption.Duration `json:"idle_timeout,omitempty"`
	TTL                       badoption.Duration `json:"ttl,omitempty"`
	InterruptExistConnections bool               `json:"interrupt_exist_connections,omitempty"`
	Strategy                  string             `json:"strategy,omitempty"`
}

type SmartOutboundOptions struct {
	GroupCommonOption
	URL               string             `json:"url,omitempty"`
	ProbeInterval     badoption.Duration `json:"probe_interval,omitempty"`
	ProbeCycleTimeout badoption.Duration `json:"probe_cycle_timeout,omitempty"`
	ProbeTimeout      badoption.Duration `json:"probe_timeout,omitempty"`
	ProbeConcurrency  int                `json:"probe_concurrency,omitempty"`
	MaxAttempts       int                `json:"max_attempts,omitempty"`
	AttemptTimeout    badoption.Duration `json:"attempt_timeout,omitempty"`
	// EstablishedStallTimeout bounds passive first-response observation after
	// a successful dial and first write. Smart does not generate traffic.
	EstablishedStallTimeout badoption.Duration `json:"established_stall_timeout,omitempty"`
	SiteStickiness          badoption.Duration `json:"site_stickiness,omitempty"`
	SwitchConfirm           badoption.Duration `json:"switch_confirm,omitempty"`
	SwitchConfirmSamples    int                `json:"switch_confirm_samples,omitempty"`
	SwitchCooldown          badoption.Duration `json:"switch_cooldown,omitempty"`
	SwitchMargin            *float64           `json:"switch_margin,omitempty"`
	// SwitchMinImprovement is the minimum absolute p95 latency gain required
	// for a performance-driven switch. Omit/zero uses the 100ms default; hard
	// failures still fail over immediately.
	SwitchMinImprovement badoption.Duration `json:"switch_min_improvement,omitempty"`
	Exploration          *float64           `json:"exploration,omitempty"`
	MinSamples           int                `json:"min_samples,omitempty"`
	// PassiveThroughputFloorBPS is a lower bound for real-traffic throughput
	// observations in bulk profiles. It never performs a probe or fetches a
	// resource; after PassiveThroughputSamples low observations the candidate
	// is temporarily bypassed so the next real connection can try another line.
	PassiveThroughputFloorBPS uint64                      `json:"passive_throughput_floor_bps,omitempty"`
	PassiveThroughputSamples  int                         `json:"passive_throughput_samples,omitempty"`
	BreakerFailures           int                         `json:"breaker_failures,omitempty"`
	BreakerCooldown           badoption.Duration          `json:"breaker_cooldown,omitempty"`
	HalfLife                  badoption.Duration          `json:"half_life,omitempty"`
	HistoryPath               string                      `json:"history_path,omitempty"`
	HistoryRetention          badoption.Duration          `json:"history_retention,omitempty"`
	MaxHistoryEntries         int                         `json:"max_history_entries,omitempty"`
	InterruptConnections      bool                        `json:"interrupt_exist_connections,omitempty"`
	InterruptPolicy           SmartInterruptPolicyOptions `json:"interrupt_policy,omitempty"`
}

type SmartInterruptPolicyOptions struct {
	Mode              string             `json:"mode,omitempty"`
	IdleThreshold     badoption.Duration `json:"idle_threshold,omitempty"`
	LongConnectionAge badoption.Duration `json:"long_connection_age,omitempty"`
	GracePeriod       badoption.Duration `json:"grace_period,omitempty"`
}
