// Copyright 2026 sing-box smart-adaptive contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Linux-only AF_XDP object/control lifecycle.  The packet-forwarding loop is
// intentionally outside this loader: a queue is only enabled after its XSK
// has been bound and userspace owns the RX/TX rings.  Any failure leaves TC
// as the live path.

#include "singbox_ebpf.h"

#include "../v3/kern/abi.h"

#include <errno.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef BPF_F_NO_PREALLOC
#define BPF_F_NO_PREALLOC 1U
#endif

#ifndef __NR_bpf
#if defined(__aarch64__)
#define __NR_bpf 280
#elif defined(__arm__)
#define __NR_bpf 386
#elif defined(__i386__)
#define __NR_bpf 357
#elif defined(__x86_64__)
#define __NR_bpf 321
#endif
#endif

static long xdp_bpf_sys(enum bpf_cmd cmd, union bpf_attr *attr) {
	return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

static int xdp_close_fd(int *fd) {
	if (fd == NULL || *fd < 0)
		return 0;
	int value = *fd;
	*fd = -1;
	return close(value);
}

static void xdp_init(struct sb_ebpf_xdp_runtime *runtime) {
	memset(runtime, 0, sizeof(*runtime));
	runtime->control_map_fd = -1;
	runtime->xsk_map_fd = -1;
	runtime->program_fd = -1;
	runtime->link_fd = -1;
}

static int xdp_map_update(int map_fd, const void *key, const void *value) {
	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.map_fd = (uint32_t)map_fd;
	attr.key = (uint64_t)(uintptr_t)key;
	attr.value = (uint64_t)(uintptr_t)value;
	attr.flags = BPF_ANY;
	return (int)xdp_bpf_sys(BPF_MAP_UPDATE_ELEM, &attr);
}

static int xdp_map_delete(int map_fd, const void *key) {
	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.map_fd = (uint32_t)map_fd;
	attr.key = (uint64_t)(uintptr_t)key;
	return (int)xdp_bpf_sys(BPF_MAP_DELETE_ELEM, &attr);
}

static int xdp_link_create(uint32_t ifindex, int program_fd) {
	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.link_create.prog_fd = (uint32_t)program_fd;
	attr.link_create.target_ifindex = ifindex;
	attr.link_create.attach_type = BPF_XDP;
	return (int)xdp_bpf_sys(BPF_LINK_CREATE, &attr);
}

int sb_ebpf_xdp_prepare(
	const uint8_t *object,
	size_t object_size,
	const struct sb_ebpf_v3_runtime *v3,
	uint32_t max_queues,
	struct sb_ebpf_xdp_runtime *runtime) {
	if (object == NULL || object_size == 0U || v3 == NULL || runtime == NULL ||
	    v3->control_map_fd < 0 || max_queues == 0U) {
		errno = EINVAL;
		return -1;
	}
	if (max_queues > SB_XDP_MAX_QUEUES)
		max_queues = SB_XDP_MAX_QUEUES;
	xdp_init(runtime);
	runtime->queue_count = max_queues;
	runtime->control_map_fd = sb_ebpf_create_map(
		BPF_MAP_TYPE_ARRAY, sizeof(uint32_t), sizeof(struct sb_xdp_control), 1U, 0U);
	runtime->xsk_map_fd = sb_ebpf_create_map(
		BPF_MAP_TYPE_XSKMAP, sizeof(uint32_t), sizeof(uint32_t), max_queues, 0U);
	if (runtime->control_map_fd < 0 || runtime->xsk_map_fd < 0)
		goto fail;

	struct sb_ebpf_object_map_entry entries[20];
	struct sb_ebpf_object_map_table maps;
	size_t n = 0U;
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_control", v3->control_map_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_policy4_bank0", v3->policy4_bank0_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_policy4_bank1", v3->policy4_bank1_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_policy6_bank0", v3->policy6_bank0_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_policy6_bank1", v3->policy6_bank1_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_host4", v3->host4_map_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_host6", v3->host6_map_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_flow_verdict", v3->flow_map_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_dns_ip_hint", v3->dns_hint_map_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_source_mac", v3->source_mac_map_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_redirect", v3->redirect_map_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_listener_sockets", v3->listener_map_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_socket_identity", v3->socket_identity_map_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_stats", v3->stats_map_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_xdp_control", runtime->control_map_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_xsk_map", runtime->xsk_map_fd};
	maps.entries = entries;
	maps.count = n;
	runtime->program_fd = sb_ebpf_object_load_section(
		object, object_size, "xdp", "sb_v3_xdp_ingress", BPF_PROG_TYPE_XDP,
		(enum bpf_attach_type)0, &maps);
	if (runtime->program_fd < 0)
		goto fail;
	/* Disabled until attach and every selected queue has a bound XSK. */
	uint32_t zero = 0U;
	struct sb_xdp_control control = {};
	control.abi_version = SB_XDP_ABI_VERSION;
	control.queue_count = max_queues;
	if (xdp_map_update(runtime->control_map_fd, &zero, &control) != 0)
		goto fail;
	return 0;

fail: {
		int saved_errno = errno;
		(void)sb_ebpf_xdp_close(runtime);
		errno = saved_errno;
		return -1;
	}
}

int sb_ebpf_xdp_attach(struct sb_ebpf_xdp_runtime *runtime, uint32_t ifindex) {
	if (runtime == NULL || runtime->program_fd < 0 || ifindex == 0U) {
		errno = EINVAL;
		return -1;
	}
	if (runtime->link_fd >= 0) {
		if (runtime->ifindex == ifindex)
			return 0;
		errno = EBUSY;
		return -1;
	}
	int link = xdp_link_create(ifindex, runtime->program_fd);
	if (link < 0)
		return -1;
	runtime->link_fd = link;
	runtime->ifindex = ifindex;
	return 0;
}

int sb_ebpf_xdp_detach(struct sb_ebpf_xdp_runtime *runtime) {
	if (runtime == NULL)
		return 0;
	int result = xdp_close_fd(&runtime->link_fd);
	runtime->ifindex = 0U;
	/* A detached program must never leave redirect enabled. */
	(void)sb_ebpf_xdp_set_control(runtime, false, 0U, 0U, 0U, 0U, false, 0U);
	return result;
}

int sb_ebpf_xdp_set_control(
	struct sb_ebpf_xdp_runtime *runtime,
	bool enabled,
	uint32_t policy_generation,
	uint32_t active_bank,
	uint32_t queue_count,
	uint32_t max_frame_size,
	bool allow_multibuffer,
	uint64_t attached_since_ns) {
	if (runtime == NULL || runtime->control_map_fd < 0 || queue_count > runtime->queue_count) {
		errno = EINVAL;
		return -1;
	}
	uint32_t zero = 0U;
	struct sb_xdp_control control = {};
	control.abi_version = SB_XDP_ABI_VERSION;
	control.flags = enabled ? SB_XDP_CTRL_ENABLED : 0U;
	if (allow_multibuffer)
		control.flags |= SB_XDP_CTRL_ALLOW_MULTIBUFFER;
	control.policy_generation = policy_generation;
	control.active_bank = active_bank & 1U;
	control.queue_count = queue_count;
	control.max_frame_size = max_frame_size;
	control.attached_since_ns = attached_since_ns;
	return xdp_map_update(runtime->control_map_fd, &zero, &control);
}

int sb_ebpf_xdp_set_xsk(struct sb_ebpf_xdp_runtime *runtime, uint32_t queue, int xsk_fd) {
	if (runtime == NULL || runtime->xsk_map_fd < 0 || queue >= runtime->queue_count || xsk_fd < 0) {
		errno = EINVAL;
		return -1;
	}
	return xdp_map_update(runtime->xsk_map_fd, &queue, &xsk_fd);
}

int sb_ebpf_xdp_clear_xsk(struct sb_ebpf_xdp_runtime *runtime, uint32_t queue) {
	if (runtime == NULL || runtime->xsk_map_fd < 0 || queue >= runtime->queue_count) {
		errno = EINVAL;
		return -1;
	}
	return xdp_map_delete(runtime->xsk_map_fd, &queue);
}

int sb_ebpf_xdp_close(struct sb_ebpf_xdp_runtime *runtime) {
	if (runtime == NULL)
		return 0;
	int result = 0;
	if (sb_ebpf_xdp_detach(runtime) != 0)
		result = -1;
	if (xdp_close_fd(&runtime->program_fd) != 0 && result == 0)
		result = -1;
	if (xdp_close_fd(&runtime->xsk_map_fd) != 0 && result == 0)
		result = -1;
	if (xdp_close_fd(&runtime->control_map_fd) != 0 && result == 0)
		result = -1;
	runtime->queue_count = 0U;
	return result;
}
