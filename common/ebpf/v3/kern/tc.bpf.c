// Copyright 2026 sing-box smart-adaptive contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Single v3 TC object: ingress decision engine + minimal egress.
// Maps are process-owned; do not pin across ABI versions.

#define SEC(name) __attribute__((section(name), used))

#include "parser.h"
#include "policy_maps.h"

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <stdbool.h>

#ifndef SB_V3_SOURCE_HASH
#define SB_V3_SOURCE_HASH "untracked"
#endif

const char sb_v3_source_hash[] SEC(".sb.source") = SB_V3_SOURCE_HASH;

static void *(*map_lookup)(void *, const void *) = (void *)BPF_FUNC_map_lookup_elem;
static long (*map_update)(void *, const void *, const void *, __u64) = (void *)BPF_FUNC_map_update_elem;
static long (*map_delete)(void *, const void *) = (void *)BPF_FUNC_map_delete_elem;
static long (*assign_socket)(struct __sk_buff *, void *, __u64) = (void *)BPF_FUNC_sk_assign;
static long (*release_socket)(void *) = (void *)BPF_FUNC_sk_release;
static struct bpf_sock *(*lookup_tcp)(void *, struct bpf_sock_tuple *, __u32, __u64, __u64) =
	(void *)BPF_FUNC_skc_lookup_tcp;
static __u64 (*monotonic_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;

static __attribute__((always_inline)) void count_stat(__u32 key) {
	__u64 *value = map_lookup(&v3_stats, &key);
	if (value)
		__sync_fetch_and_add(value, 1);
}

static __attribute__((always_inline)) void count_bytes(__u32 key, __u32 len) {
	__u64 *value = map_lookup(&v3_stats, &key);
	if (value)
		__sync_fetch_and_add(value, len);
}

static __attribute__((always_inline)) bool policy_port_match(const struct sb_v3_policy_value *policy,
							     const struct sb_v3_packet *packet) {
	if (policy->match_protocol != 0 && policy->match_protocol != packet->protocol)
		return false;
	if (policy->match_dport_min == 0 && policy->match_dport_max == 0)
		return true;
	return packet->dport >= policy->match_dport_min && packet->dport <= policy->match_dport_max;
}

static __attribute__((always_inline)) const struct sb_v3_policy_value *lookup_static_policy(
	const struct sb_v3_control *control, const struct sb_v3_packet *packet) {
	if (!(control->flags & SB_V3_FLAG_STATIC_POLICY))
		return 0;
	if (packet->family == SB_V3_AF_INET) {
		struct sb_v3_lpm4_key key = {.prefixlen = 32U};
		__builtin_memcpy(key.addr, packet->daddr, 4);
		const struct sb_v3_policy_value *policy =
			control->active_bank == 0 ? map_lookup(&v3_policy4_bank0, &key)
						 : map_lookup(&v3_policy4_bank1, &key);
		if (!policy || policy->generation != control->policy_generation)
			return 0;
		if (!policy_port_match(policy, packet))
			return 0;
		return policy;
	}
	if (packet->family == SB_V3_AF_INET6) {
		struct sb_v3_lpm6_key key = {.prefixlen = 128U};
		__builtin_memcpy(key.addr, packet->daddr, 16);
		const struct sb_v3_policy_value *policy =
			control->active_bank == 0 ? map_lookup(&v3_policy6_bank0, &key)
						 : map_lookup(&v3_policy6_bank1, &key);
		if (!policy || policy->generation != control->policy_generation)
			return 0;
		if (!policy_port_match(policy, packet))
			return 0;
		return policy;
	}
	return 0;
}

static __attribute__((always_inline)) bool host_address(const struct sb_v3_packet *packet) {
	if (packet->family == SB_V3_AF_INET) {
		struct sb_v3_lpm4_key key = {.prefixlen = 32U};
		__builtin_memcpy(key.addr, packet->daddr, 4);
		return map_lookup(&v3_host4, &key) != 0;
	}
	if (packet->family == SB_V3_AF_INET6) {
		struct sb_v3_lpm6_key key = {.prefixlen = 128U};
		__builtin_memcpy(key.addr, packet->daddr, 16);
		return map_lookup(&v3_host6, &key) != 0;
	}
	return false;
}

static __attribute__((always_inline)) bool security_bypass(const struct sb_v3_packet *packet, int parse_rc) {
	if (parse_rc == 1)
		return true;
	if (packet->protocol == IPPROTO_ICMP || packet->protocol == IPPROTO_ICMPV6)
		return true;
	if (packet->protocol == IPPROTO_UDP && sb_v3_is_dhcp_ports(packet->sport, packet->dport))
		return true;
	if (packet->family == SB_V3_AF_INET) {
		if (sb_v3_ipv4_is_multicast(packet->daddr) || sb_v3_ipv4_is_broadcast_like(packet->daddr))
			return true;
	} else if (packet->family == SB_V3_AF_INET6) {
		if (sb_v3_ipv6_is_multicast(packet->daddr))
			return true;
	}
	if (host_address(packet))
		return true;
	return false;
}

static __attribute__((always_inline)) const struct sb_v3_flow_value *lookup_flow(
	const struct sb_v3_control *control, const struct sb_v3_packet *packet) {
	if (!(control->flags & SB_V3_FLAG_EXACT_FLOW))
		return 0;
	/* Userspace publishes both directions with direction=0 and swapped
	 * 5-tuples so TC can key solely on the on-wire addresses/ports. */
	struct sb_v3_flow_key key = {};
	key.family = packet->family;
	key.protocol = packet->protocol;
	key.direction = 0;
	key.sport = packet->sport;
	key.dport = packet->dport;
	__builtin_memcpy(key.saddr, packet->saddr, 16);
	__builtin_memcpy(key.daddr, packet->daddr, 16);
	struct sb_v3_flow_value *value = map_lookup(&v3_flow_verdict, &key);
	if (!value)
		return 0;
	if (value->generation != control->policy_generation) {
		count_stat(SB_V3_STAT_GENERATION_MISS_PROXY);
		return 0;
	}
	if (value->expires_ns <= monotonic_ns())
		return 0;
	return value;
}

static __attribute__((always_inline)) bool dns_hint_allows_direct(const struct sb_v3_control *control,
								  const struct sb_v3_packet *packet,
								  __u32 *reason_out) {
	if (!(control->flags & SB_V3_FLAG_DNS_HINT) && !(control->flags & SB_V3_FLAG_FAKEIP))
		return false;
	struct sb_v3_dns_ip_key key = {};
	key.family = packet->family;
	__builtin_memcpy(key.addr, packet->daddr, 16);
	struct sb_v3_dns_ip_value *hint = map_lookup(&v3_dns_ip_hint, &key);
	if (!hint)
		return false;
	if (hint->generation != control->policy_generation)
		return false;
	if (hint->expires_ns <= monotonic_ns())
		return false;
	if (hint->proxy_refs != 0) {
		count_stat(SB_V3_STAT_DNS_HINT_CONFLICT);
		return false;
	}
	if (hint->direct_refs == 0 || hint->evidence == SB_V3_DNS_EVIDENCE_WEAK)
		return false;
	if (hint->evidence == SB_V3_DNS_EVIDENCE_FAKEIP) {
		if (!(control->flags & SB_V3_FLAG_FAKEIP))
			return false;
		*reason_out = SB_V3_STAT_FAKEIP_DIRECT;
		return true;
	}
	if (hint->evidence == SB_V3_DNS_EVIDENCE_STRONG) {
		if (!(control->flags & SB_V3_FLAG_DNS_HINT))
			return false;
		*reason_out = SB_V3_STAT_DNS_HINT_DIRECT;
		return true;
	}
	return false;
}

static __attribute__((always_inline)) int listener_key_for(const struct sb_v3_packet *packet) {
	if (packet->family == SB_V3_AF_INET && packet->protocol == IPPROTO_TCP)
		return SB_V3_LISTENER_TCP4;
	if (packet->family == SB_V3_AF_INET && packet->protocol == IPPROTO_UDP)
		return SB_V3_LISTENER_UDP4;
	if (packet->family == SB_V3_AF_INET6 && packet->protocol == IPPROTO_TCP)
		return SB_V3_LISTENER_TCP6;
	if (packet->family == SB_V3_AF_INET6 && packet->protocol == IPPROTO_UDP)
		return SB_V3_LISTENER_UDP6;
	return -1;
}

static __attribute__((always_inline)) int remember_redirect(const struct sb_v3_packet *packet,
							    __u32 ifindex) {
	struct sb_v3_redirect_key key = {};
	key.family = packet->family;
	key.protocol = packet->protocol;
	key.client_port = packet->sport;
	key.dest_port = packet->dport;
	__builtin_memcpy(key.client_addr, packet->saddr, 16);
	__builtin_memcpy(key.dest_addr, packet->daddr, 16);
	if (map_lookup(&v3_redirect, &key))
		return 0;
	struct sb_v3_redirect_value value = {};
	value.family = packet->family;
	value.protocol = packet->protocol;
	value.dest_port = packet->dport;
	value.ifindex = ifindex;
	__builtin_memcpy(value.dest_addr, packet->daddr, 16);
	__builtin_memcpy(value.source_mac, packet->smac, 6);
	return map_update(&v3_redirect, &key, &value, BPF_ANY);
}

static __attribute__((always_inline)) void forget_redirect(const struct sb_v3_packet *packet) {
	struct sb_v3_redirect_key key = {};
	key.family = packet->family;
	key.protocol = packet->protocol;
	key.client_port = packet->sport;
	key.dest_port = packet->dport;
	__builtin_memcpy(key.client_addr, packet->saddr, 16);
	__builtin_memcpy(key.dest_addr, packet->daddr, 16);
	map_delete(&v3_redirect, &key);
}

static __attribute__((always_inline)) int assign_established(struct __sk_buff *skb,
							     const struct sb_v3_packet *packet) {
	if (packet->protocol != IPPROTO_TCP)
		return 0;
	struct bpf_sock_tuple tuple = {};
	__u32 tuple_size;
	if (packet->family == SB_V3_AF_INET) {
		__builtin_memcpy(&tuple.ipv4.saddr, packet->saddr, 4);
		__builtin_memcpy(&tuple.ipv4.daddr, packet->daddr, 4);
		tuple.ipv4.sport = __builtin_bswap16(packet->sport);
		tuple.ipv4.dport = __builtin_bswap16(packet->dport);
		tuple_size = sizeof(tuple.ipv4);
	} else {
		__builtin_memcpy(tuple.ipv6.saddr, packet->saddr, 16);
		__builtin_memcpy(tuple.ipv6.daddr, packet->daddr, 16);
		tuple.ipv6.sport = __builtin_bswap16(packet->sport);
		tuple.ipv6.dport = __builtin_bswap16(packet->dport);
		tuple_size = sizeof(tuple.ipv6);
	}
	struct bpf_sock *socket = lookup_tcp(skb, &tuple, tuple_size, BPF_F_CURRENT_NETNS, 0);
	if (!socket)
		return 0;
	if (socket->state == BPF_TCP_LISTEN) {
		release_socket(socket);
		return 0;
	}
	long result = assign_socket(skb, socket, 0);
	release_socket(socket);
	return result == 0 ? 1 : -1;
}

/* Mark policy (match working v2 TC on Alpine):
 * - Never clear skb->mark (writing mark=0 after data/ctx use trips
 *   "dereference of modified ctx ptr ... disallowed").
 * - Only set mark after a successful sk_assign, like shared_network_v2.bpf.c.
 */
static __attribute__((always_inline)) int handoff_proxy(struct __sk_buff *skb,
							const struct sb_v3_control *control,
							const struct sb_v3_packet *packet,
							__u32 reason,
							__u32 ifindex,
							__u32 pkt_len) {
	count_stat(reason);
	count_stat(SB_V3_STAT_PACKETS_PROXY);
	count_bytes(SB_V3_STAT_BYTES_PROXY, pkt_len);

	if (!(control->flags & SB_V3_FLAG_SOCKET_ASSIGN))
		return TC_ACT_OK;

	if (remember_redirect(packet, ifindex) != 0)
		count_stat(SB_V3_STAT_MAP_CAPACITY_REJECT);

	int lkey = listener_key_for(packet);
	if (lkey < 0) {
		count_stat(SB_V3_STAT_SOCKET_ASSIGN_FAILURE);
		return TC_ACT_OK;
	}
	__u32 key = (__u32)lkey;
	struct bpf_sock *listener = map_lookup(&v3_listener_sockets, &key);
	if (!listener) {
		count_stat(SB_V3_STAT_SOCKET_ASSIGN_FAILURE);
		forget_redirect(packet);
		return TC_ACT_OK;
	}
	long result = assign_socket(skb, listener, 0);
	/* SOCKMAP lookup leaves a ref; always release (v2 pattern). */
	release_socket(listener);
	if (result != 0) {
		count_stat(SB_V3_STAT_SOCKET_ASSIGN_FAILURE);
		forget_redirect(packet);
		return TC_ACT_OK;
	}
	skb->mark = control->routing_mark;
	count_stat(SB_V3_STAT_SOCKET_ASSIGN_SUCCESS);
	return TC_ACT_OK;
}

static __attribute__((always_inline)) int action_direct(struct __sk_buff *skb, __u32 reason) {
	/* DIRECT: leave mark alone; Linux L3 forwards without PBR mark. */
	(void)skb;
	count_stat(reason);
	count_stat(SB_V3_STAT_PACKETS_DIRECT);
	return TC_ACT_OK;
}

static __attribute__((always_inline)) int action_block(struct __sk_buff *skb) {
	(void)skb;
	count_stat(SB_V3_STAT_BLOCKED);
	return TC_ACT_SHOT;
}

SEC("classifier/ingress")
int sb_v3_ingress(struct __sk_buff *skb) {
	__u32 zero = 0;
	struct sb_v3_control *control = map_lookup(&v3_control, &zero);
	if (!control || !control->enabled || control->abi_version != SB_V3_ABI_VERSION)
		return TC_ACT_OK;

	/* Capture scalar metadata once from the original ctx before any pkt walk.
	 * Never stash a derived ctx pointer for later load (Alpine verifier). */
	__u32 ifindex = skb->ingress_ifindex;
	if (ifindex == 0)
		ifindex = skb->ifindex;
	__u32 pkt_len = skb->len;
	__u32 routing_mark = control->routing_mark;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct sb_v3_packet packet = {};
	int parse_rc = sb_v3_parse(data, data_end, &packet);
	packet.ifindex = ifindex;

	if (parse_rc < 0) {
		count_stat(SB_V3_STAT_PARSE_FAIL_PROXY);
		/* Incomplete headers → NEED_USERSPACE (fail toward control plane). */
		return TC_ACT_OK;
	}

	/* DNS interception must precede host-address bypass.  PBR deployments send
	 * DNS to an address owned by this host (for example 10.20.30.1:53).  If
	 * host_address() runs first, those packets are passed to the local stack
	 * even though no userspace DNS socket is bound to port 53, so queries time
	 * out and never reach the configured DNS hijack path.  Only fully parsed
	 * TCP/UDP packets are eligible; DHCP, fragments and malformed packets keep
	 * their existing safety behavior. */
	if (parse_rc == 0 && (control->flags & SB_V3_FLAG_DNS_HIJACK) != 0 &&
	    (packet.protocol == IPPROTO_TCP || packet.protocol == IPPROTO_UDP) && packet.dport == 53)
		return handoff_proxy(skb, control, &packet, SB_V3_STAT_DNS_HIJACK_PROXY, ifindex, pkt_len);

	if (security_bypass(&packet, parse_rc)) {
		count_stat(SB_V3_STAT_SECURITY_BYPASS);
		return TC_ACT_OK;
	}

	/* IP fragments lack a reliable L4 5-tuple; never static/flow DIRECT them. */
	if (packet.fragmented) {
		count_stat(SB_V3_STAT_PARSE_FAIL_PROXY);
		return handoff_proxy(skb, control, &packet, SB_V3_STAT_PARSE_FAIL_PROXY, ifindex, pkt_len);
	}

	if (packet.family == SB_V3_AF_INET && !(control->flags & SB_V3_FLAG_IPV4))
		return TC_ACT_OK;
	if (packet.family == SB_V3_AF_INET6 && !(control->flags & SB_V3_FLAG_IPV6))
		return TC_ACT_OK;
	if (packet.protocol == IPPROTO_TCP && !(control->flags & SB_V3_FLAG_TCP))
		return TC_ACT_OK;
	if (packet.protocol == IPPROTO_UDP && !(control->flags & SB_V3_FLAG_UDP))
		return TC_ACT_OK;
	if (packet.protocol != IPPROTO_TCP && packet.protocol != IPPROTO_UDP)
		return TC_ACT_OK;

	if ((control->flags & SB_V3_FLAG_DROP_UDP_443) != 0 && packet.protocol == IPPROTO_UDP &&
	    packet.dport == 443)
		return action_block(skb);

	const struct sb_v3_policy_value *static_policy = lookup_static_policy(control, &packet);
	if (static_policy) {
		if (static_policy->verdict == SB_V3_DIRECT)
			return action_direct(skb, SB_V3_STAT_STATIC_DIRECT);
		if (static_policy->verdict == SB_V3_BLOCK)
			return action_block(skb);
		if (static_policy->verdict == SB_V3_PROXY)
			return handoff_proxy(skb, control, &packet, SB_V3_STAT_STATIC_PROXY, ifindex, pkt_len);
		if (static_policy->verdict == SB_V3_MUST_CONTROL)
			return handoff_proxy(skb, control, &packet, SB_V3_STAT_MUST_CONTROL, ifindex, pkt_len);
	}

	const struct sb_v3_flow_value *flow = lookup_flow(control, &packet);
	if (flow) {
		if (flow->verdict == SB_V3_DIRECT)
			return action_direct(skb, SB_V3_STAT_FLOW_DIRECT);
		if (flow->verdict == SB_V3_BLOCK)
			return action_block(skb);
		if (flow->verdict == SB_V3_PROXY)
			return handoff_proxy(skb, control, &packet, SB_V3_STAT_FLOW_PROXY, ifindex, pkt_len);
		if (flow->verdict == SB_V3_MUST_CONTROL)
			return handoff_proxy(skb, control, &packet, SB_V3_STAT_MUST_CONTROL, ifindex, pkt_len);
	}

	__u32 dns_reason = 0;
	if (dns_hint_allows_direct(control, &packet, &dns_reason))
		return action_direct(skb, dns_reason);

	if (assign_established(skb, &packet) > 0) {
		skb->mark = routing_mark;
		count_stat(SB_V3_STAT_ESTABLISHED_BYPASS);
		return TC_ACT_OK;
	}

	return handoff_proxy(skb, control, &packet, SB_V3_STAT_MAP_MISS_PROXY, ifindex, pkt_len);
}

SEC("classifier/egress")
int sb_v3_egress(struct __sk_buff *skb) {
	__u32 zero = 0;
	struct sb_v3_control *control = map_lookup(&v3_control, &zero);
	if (!control || !control->enabled)
		return TC_ACT_OK;
	(void)skb;
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
