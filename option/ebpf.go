package option

import (
	"net/netip"

	"github.com/sagernet/sing/common/json/badoption"
)

type EBPFInboundOptions struct {
	ListenOptions
	CgroupPath string `json:"cgroup_path,omitempty"`
	// CaptureLocal controls cgroup interception for processes running on this host.
	// It defaults to true. Router deployments using only shared_network can set it
	// to false to keep management traffic out of the proxy data path.
	CaptureLocal *bool       `json:"capture_local,omitempty"`
	Network      NetworkList `json:"network,omitempty"`
	DNSMode      string      `json:"dns_mode,omitempty" enum:"hijack,off"`
	// DNSKernelDirect (module M-dns-kernel-direct): selected DNS server CIDRs keep
	// the kernel path when dns_mode=hijack. All other :53 still hijacked.
	// Default off. Independent of dns_prefill. See docs/ebpf-feature-modules-20260805.md.
	DNSKernelDirect EBPFDNSKernelDirectOptions       `json:"dns_kernel_direct,omitempty"`
	RedirectAddress badoption.Listable[netip.Prefix] `json:"redirect_address,omitempty" examples:"127.128.0.0/9,fd53:696e:672d:626f::/64"`
	BypassRuleSet   badoption.Listable[string]       `json:"bypass_rule_set,omitempty" reference:"rule_set"`
	IncludeUID      badoption.Listable[uint32]       `json:"include_uid,omitempty"`
	IncludeUIDRange badoption.Listable[string]       `json:"include_uid_range,omitempty"`
	ExcludeUID      badoption.Listable[uint32]       `json:"exclude_uid,omitempty"`
	ExcludeUIDRange badoption.Listable[string]       `json:"exclude_uid_range,omitempty"`
	SharedNetwork   EBPFSharedNetworkOptions         `json:"shared_network,omitempty"`
	// OutboundOffload hangs post-route eBPF acceleration under the ebpf inbound.
	// Not a routable outbound type. Defaults all-off.
	// Contract: docs/ebpf-in-out-framework-master-20260803.md §7 / plan §6.
	OutboundOffload EBPFOutboundOffloadOptions `json:"outbound_offload,omitempty"`
	// Zero selects conservative defaults: 512 data sessions and 128 DNS sessions.
	UDPSessionCapacity uint32 `json:"udp_session_capacity,omitempty"`
	DNSSessionCapacity uint32 `json:"dns_session_capacity,omitempty"`
}

// EBPFDNSKernelDirectOptions splits the DNS path under dns_mode=hijack:
//
//   - server_cidr :53 → kernel forward (no userspace hijack)
//   - all other :53 → still hijacked (smart/fakeip/rules stay userspace)
//
// Authority for domain routing remains userspace. This only excepts DNS
// *server* addresses, not answers. Defaults off.
type EBPFDNSKernelDirectOptions struct {
	Enabled    bool                             `json:"enabled,omitempty"`
	ServerCIDR badoption.Listable[netip.Prefix] `json:"server_cidr,omitempty" examples:"223.5.5.5/32,119.29.29.29/32"`
}

type EBPFSharedNetworkOptions struct {
	Enabled          bool                       `json:"enabled,omitempty"`
	IncludeInterface badoption.Listable[string] `json:"include_interface,omitempty"`
	// DataPlane selects how packets from shared interfaces reach the transparent
	// listener. "token" is the compatibility implementation. "socket_assign"
	// preserves the original tuple and uses TC socket assignment plus policy routing.
	DataPlane string `json:"data_plane,omitempty" enum:"token,socket_assign"`
	// RoutingMark and RoutingTable are used only by socket_assign. Zero selects
	// process-owned defaults.
	RoutingMark  uint32 `json:"routing_mark,omitempty"`
	RoutingTable uint32 `json:"routing_table,omitempty"`
	// TCPriority is the clsact filter priority (lower runs earlier). 0 means default (1),
	// which is chosen to run before Android tethering offload (prio 2/3).
	// Set higher (e.g. 10) if you need other TC filters at prio 1 to run first.
	TCPriority uint16 `json:"tc_priority,omitempty"`
	// DropUDP443 drops QUIC (UDP/443) inside the TC program before divert, matching classic
	// tproxy nft bypass ("udp dport 443 drop") so clients fall back to TCP. Default true when omitted.
	// Set to false to allow UDP/443 through shared_network (experimental).
	DropUDP443 *bool `json:"drop_udp_443,omitempty"`
	// FlowVerdict enables the dae-style exact-flow direct fast path. After a
	// userspace route proves a flow is DIRECT, subsequent packets bypass the
	// transparent listener in TC until the TTL or policy generation expires.
	// It is valid only with data_plane=socket_assign because token mode cannot
	// safely preserve the original route semantics for direct forwarding.
	FlowVerdict bool `json:"flow_verdict,omitempty"`
}

// EBPFOutboundOffloadOptions is the inbound-attached outbound offload block.
// Field names are locked by the master framework contract.
type EBPFOutboundOffloadOptions struct {
	Splice  EBPFSpliceOptions  `json:"splice,omitempty"`
	Verdict EBPFVerdictOptions `json:"verdict,omitempty"`
	// DNSPrefill (module M-dns-prefill): weak IP→TC promote after userspace
	// A/AAAA. Stable leaf DIRECT/ebpf only; skip fakeip/private/groups.
	// Default off. Independent of dns_kernel_direct. See docs/ebpf-feature-modules-20260805.md.
	DNSPrefill EBPFDNSPrefillOptions `json:"dns_prefill,omitempty"`
}

// EBPFDNSPrefillOptions configures weak DNS answer → TC bypass promote.
type EBPFDNSPrefillOptions struct {
	Enabled bool `json:"enabled,omitempty"`
	// TTL for promoted /32 entries. 0 → 60s (intentionally shorter than verdict learn).
	TTL badoption.Duration `json:"ttl,omitempty"`
}

type EBPFSpliceOptions struct {
	Enabled     bool               `json:"enabled,omitempty"`
	MaxPairs    uint32             `json:"max_pairs,omitempty"`                           // 0 → 8192
	Accounting  *bool              `json:"accounting,omitempty"`                          // default true
	HalfClose   string             `json:"half_close,omitempty" enum:"close,passthrough"` // default close
	IdleTimeout badoption.Duration `json:"idle_timeout,omitempty"`                        // 0 → 2×UDPTimeout
	// AllowOutboundTypes is an explicit whitelist of outbound types eligible for
	// splice (framework B-5 / E4). Empty → default ["direct","ebpf","socks","http"]
	// (official dial already post-handshake bare TCP). Do not add AEAD/TLS proxy
	// types unless you intentionally accept risk; opaque gate blocks under-TLS peel.
	AllowOutboundTypes []string `json:"allow_outbound_types,omitempty"`
}

type EBPFVerdictOptions struct {
	Mode           string             `json:"mode,omitempty" enum:"off,learn"` // default off; "dns" removed (never implemented)
	TTL            badoption.Duration `json:"ttl,omitempty"`                   // 0 → 5m
	MaxEntries     uint32             `json:"max_entries,omitempty"`           // 0 → 8192
	AllowWithSniff bool               `json:"allow_with_sniff,omitempty"`      // default false
	// PromoteBypass installs learned DIRECT IPs as /32 into TC bypass LPM (dae-style high hit-rate).
	// nil → true when mode=learn. Set false to keep port-level userspace only (connect4 verdict).
	PromoteBypass *bool `json:"promote_bypass,omitempty"`
}

// EBPFOutboundOptions is a routable outbound with type "ebpf".
//
// It dials like a bare direct (DialerOptions only; no proxy protocol) so it is
// eligible for inbound outbound_offload splice/verdict when an eBPF inbound is
// present. Without eBPF inbound offload it still works as plain direct.
//
// Preferred production path remains outbound_offload under type:ebpf inbound;
// this outbound exists so route rules can write `outbound: <ebpf-tag>` explicitly.
type EBPFOutboundOptions struct {
	DialerOptions
}
