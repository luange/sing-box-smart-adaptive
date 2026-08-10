// Copyright 2026 sing-box data-plane v2 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef SING_BOX_DATAPLANE_V2_H
#define SING_BOX_DATAPLANE_V2_H

#include <linux/types.h>

#define SB_DP2_MAX_QUEUES 64U
#define SB_DP2_STAT_COUNT 12U

enum sb_dp2_action {
    SB_DP2_ACTION_FALLBACK = 0,
    SB_DP2_ACTION_DIRECT = 1,
    SB_DP2_ACTION_PROXY_TCP = 2,
    SB_DP2_ACTION_PROXY_UDP = 3,
    SB_DP2_ACTION_DROP = 4,
};

enum sb_dp2_stat {
    SB_DP2_STAT_XDP_PASS = 0,
    SB_DP2_STAT_XDP_REDIRECT,
    SB_DP2_STAT_XDP_NO_QUEUE,
    SB_DP2_STAT_XDP_DROP,
    SB_DP2_STAT_TC_PASS,
    SB_DP2_STAT_TC_ASSIGN,
    SB_DP2_STAT_TC_ASSIGN_FAIL,
    SB_DP2_STAT_PARSE_FALLBACK,
    SB_DP2_STAT_IPV4,
    SB_DP2_STAT_IPV6,
    SB_DP2_STAT_TCP,
    SB_DP2_STAT_UDP,
};

struct sb_dp2_control {
    __u32 enabled;
    __u32 generation;
    __u32 flags;
    __u32 reserved;
};

struct sb_dp2_packet {
    __u8 family;
    __u8 protocol;
    __u8 fragmented;
    __u8 vlan_depth;
    __u16 source_port;
    __u16 destination_port;
    __u8 source[16];
    __u8 destination[16];
};

_Static_assert(sizeof(struct sb_dp2_control) == 16U, "dp2 control ABI");
_Static_assert(sizeof(struct sb_dp2_packet) == 40U, "dp2 packet ABI");

#endif
