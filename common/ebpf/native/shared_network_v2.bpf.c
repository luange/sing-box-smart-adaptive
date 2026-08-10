// Copyright 2026 sing-box data-plane v2 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "dataplane_v2_parser.h"
#include "shared_network.h"

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <stdbool.h>

#define SEC(name) __attribute__((section(name), used))

struct bpf_map_def {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
};

struct sb_dp2_lpm4 { __u32 prefixlen; __u8 addr[4]; };
struct sb_dp2_lpm6 { __u32 prefixlen; __u8 addr[16]; };

#define EXTERNAL_MAP(name, map_type, key_type, value_type, count, flags_value) \
    struct bpf_map_def SEC("maps") name = { \
        .type = map_type, .key_size = sizeof(key_type), \
        .value_size = sizeof(value_type), .max_entries = count, \
        .map_flags = flags_value, \
    }

EXTERNAL_MAP(shared_control, BPF_MAP_TYPE_HASH, __u32, struct sb_shared_control, 1U, 0U);
EXTERNAL_MAP(shared_redirect, BPF_MAP_TYPE_LRU_HASH, struct sb_shared_redirect_key,
             struct sb_shared_original_dst, SB_SHARED_NETWORK_MAP_ENTRIES, 0U);
EXTERNAL_MAP(shared_flow_direct, BPF_MAP_TYPE_HASH, struct sb_shared_flow_key,
             struct sb_shared_flow_value, SB_SHARED_NETWORK_MAP_ENTRIES, BPF_F_NO_PREALLOC);
EXTERNAL_MAP(shared_listener_sockets, BPF_MAP_TYPE_SOCKMAP, __u32, __u64,
             SB_SHARED_LISTENER_COUNT, 0U);
EXTERNAL_MAP(shared_stats, BPF_MAP_TYPE_ARRAY, __u32, __u64, SB_SHARED_STAT_COUNT, 0U);
EXTERNAL_MAP(shared_host_ipv4, BPF_MAP_TYPE_LPM_TRIE, struct sb_dp2_lpm4, __u8,
             SB_SHARED_NETWORK_MAP_ENTRIES, BPF_F_NO_PREALLOC);
EXTERNAL_MAP(shared_host_ipv6, BPF_MAP_TYPE_LPM_TRIE, struct sb_dp2_lpm6, __u8,
             SB_SHARED_NETWORK_MAP_ENTRIES, BPF_F_NO_PREALLOC);
EXTERNAL_MAP(shared_bypass_ipv4, BPF_MAP_TYPE_LPM_TRIE, struct sb_dp2_lpm4, __u8,
             SB_SHARED_NETWORK_MAP_ENTRIES, BPF_F_NO_PREALLOC);
EXTERNAL_MAP(shared_bypass_ipv6, BPF_MAP_TYPE_LPM_TRIE, struct sb_dp2_lpm6, __u8,
             SB_SHARED_NETWORK_MAP_ENTRIES, BPF_F_NO_PREALLOC);
EXTERNAL_MAP(shared_dns_direct_ipv4, BPF_MAP_TYPE_LPM_TRIE, struct sb_dp2_lpm4, __u8,
             SB_SHARED_NETWORK_MAP_ENTRIES, BPF_F_NO_PREALLOC);
EXTERNAL_MAP(shared_dns_direct_ipv6, BPF_MAP_TYPE_LPM_TRIE, struct sb_dp2_lpm6, __u8,
             SB_SHARED_NETWORK_MAP_ENTRIES, BPF_F_NO_PREALLOC);

static void *(*map_lookup)(void *, const void *) = (void *)BPF_FUNC_map_lookup_elem;
static long (*map_update)(void *, const void *, const void *, __u64) = (void *)BPF_FUNC_map_update_elem;
static long (*assign_socket)(struct __sk_buff *, void *, __u64) = (void *)BPF_FUNC_sk_assign;
static long (*release_socket)(void *) = (void *)BPF_FUNC_sk_release;
static __u64 (*monotonic_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;

static __attribute__((always_inline)) void count_stat(__u32 key) {
    __u64 *value = map_lookup(&shared_stats, &key);
    if (value) __sync_fetch_and_add(value, 1);
}

static __attribute__((always_inline)) bool lpm4_has(void *map, const __u8 address[16]) {
    struct sb_dp2_lpm4 key = {.prefixlen = 32U};
    __builtin_memcpy(key.addr, address, 4);
    return map_lookup(map, &key) != 0;
}

static __attribute__((always_inline)) bool lpm6_has(void *map, const __u8 address[16]) {
    struct sb_dp2_lpm6 key = {.prefixlen = 128U};
    __builtin_memcpy(key.addr, address, 16);
    return map_lookup(map, &key) != 0;
}

static __attribute__((always_inline)) bool destination_bypass(const struct sb_dp2_packet *packet) {
    if (packet->family == SB_DP2_AF_INET) {
        if (lpm4_has(&shared_host_ipv4, packet->destination) ||
            lpm4_has(&shared_bypass_ipv4, packet->destination)) return true;
        return packet->destination_port == 53 &&
               lpm4_has(&shared_dns_direct_ipv4, packet->destination);
    }
    if (lpm6_has(&shared_host_ipv6, packet->destination) ||
        lpm6_has(&shared_bypass_ipv6, packet->destination)) return true;
    return packet->destination_port == 53 &&
           lpm6_has(&shared_dns_direct_ipv6, packet->destination);
}

static __attribute__((always_inline)) bool learned_direct(const struct sb_dp2_packet *packet,
                                                           const struct sb_shared_control *control) {
    if (!(control->flags & SB_SHARED_FLAG_FLOW_DIRECT)) return false;
    struct sb_shared_flow_key key = {};
    key.family = packet->family;
    key.protocol = packet->protocol;
    key.client_port = packet->source_port;
    key.original_port = packet->destination_port;
    __builtin_memcpy(key.client_addr, packet->source, 16);
    __builtin_memcpy(key.original_addr, packet->destination, 16);
    struct sb_shared_flow_value *value = map_lookup(&shared_flow_direct, &key);
    return value && value->generation == control->flow_generation && value->expires_ns > monotonic_ns();
}

static __attribute__((always_inline)) int remember_original(struct __sk_buff *skb,
                                                             const struct sb_dp2_packet *packet) {
    struct sb_shared_redirect_key key = {};
    key.family = packet->family;
    key.protocol = packet->protocol;
    key.redirect_port = packet->destination_port;
    key.client_port = packet->source_port;
    __builtin_memcpy(key.redirect_addr, packet->destination, 16);
    __builtin_memcpy(key.client_addr, packet->source, 16);

    struct sb_shared_original_dst value = {};
    value.family = packet->family;
    value.protocol = packet->protocol;
    value.port = packet->destination_port;
    value.socket_cookie = skb->ifindex;
    __builtin_memcpy(value.addr, packet->destination, 16);
    return map_update(&shared_redirect, &key, &value, BPF_ANY);
}

SEC("classifier/ingress")
int sb_share_v2_in(struct __sk_buff *skb) {
    __u32 zero = 0;
    struct sb_shared_control *control = map_lookup(&shared_control, &zero);
    if (!control || !control->enabled || !(control->flags & SB_SHARED_FLAG_SOCKET_ASSIGN))
        return TC_ACT_OK;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct sb_dp2_packet packet = {};
    if (sb_dp2_parse(data, data_end, &packet) != 0 || packet.fragmented) {
        count_stat(SB_SHARED_STAT_INGRESS_BYPASS);
        return TC_ACT_OK;
    }
    if (packet.protocol != IPPROTO_TCP && packet.protocol != IPPROTO_UDP)
        return TC_ACT_OK;
    if ((packet.protocol == IPPROTO_TCP && !(control->flags & SB_SHARED_FLAG_TCP)) ||
        (packet.protocol == IPPROTO_UDP && !(control->flags & SB_SHARED_FLAG_UDP)))
        return TC_ACT_OK;
    if (destination_bypass(&packet) || learned_direct(&packet, control)) {
        count_stat(SB_SHARED_STAT_INGRESS_BYPASS);
        return TC_ACT_OK;
    }
    if (packet.protocol == IPPROTO_UDP && packet.destination_port == 443 &&
        (control->flags & SB_SHARED_FLAG_DROP_UDP_443)) {
        count_stat(SB_SHARED_STAT_INGRESS_DROPS);
        return TC_ACT_SHOT;
    }
    if (remember_original(skb, &packet) != 0) {
        count_stat(SB_SHARED_STAT_FLOW_UPDATE_FAILURES);
        return TC_ACT_SHOT;
    }

    __u32 listener = packet.family == SB_DP2_AF_INET ?
        (packet.protocol == IPPROTO_TCP ? SB_SHARED_LISTENER_TCP4 : SB_SHARED_LISTENER_UDP4) :
        (packet.protocol == IPPROTO_TCP ? SB_SHARED_LISTENER_TCP6 : SB_SHARED_LISTENER_UDP6);
    void *socket = map_lookup(&shared_listener_sockets, &listener);
    if (!socket) {
        count_stat(SB_SHARED_STAT_SOCKET_ASSIGN_FAILURES);
        return TC_ACT_SHOT;
    }
    long result = assign_socket(skb, socket, 0);
    release_socket(socket);
    if (result != 0) {
        count_stat(SB_SHARED_STAT_SOCKET_ASSIGN_FAILURES);
        return TC_ACT_SHOT;
    }
    skb->mark = control->routing_mark;
    count_stat(SB_SHARED_STAT_SOCKET_ASSIGNMENTS);
    count_stat(SB_SHARED_STAT_INGRESS_REDIRECTS);
    return TC_ACT_OK;
}

SEC("classifier/egress")
int sb_share_v2_out(struct __sk_buff *skb) {
    (void)skb;
    return TC_ACT_OK;
}

char sb_dp2_license[] SEC("license") = "GPL";
