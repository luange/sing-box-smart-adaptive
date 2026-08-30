//! Capability matrix for AF_XDP admission. Inputs are already-observed bits;
//! this module does not call netlink, ioctl, or bind.

const model = @import("model.zig");

pub const feat_basic: u64 = 1 << 0;
pub const feat_redirect: u64 = 1 << 1;
pub const feat_ndo_xmit: u64 = 1 << 2;
pub const feat_xsk_zerocopy: u64 = 1 << 3;
pub const feat_hw_offload: u64 = 1 << 4;
pub const feat_rx_sg: u64 = 1 << 5;
pub const feat_ndo_xmit_sg: u64 = 1 << 6;

pub const BindResult = enum(u8) {
    none = 0,
    zerocopy_ok = 1,
    copy_ok = 2,
    failed = 3,
};

pub const Outcome = enum(u8) {
    attach_zerocopy = 1,
    attach_copy = 2,
    fallback_tc = 3,
};

pub const FallbackReason = enum(u8) {
    none = 0,
    missing_redirect = 1,
    missing_zerocopy = 2,
    single_queue = 3,
    bind_failed = 4,
    copy_disallowed = 5,
    features_absent_skip = 6,
};

pub const Sample = struct {
    features: u64 = 0,
    features_present: bool = true,
    rx_queues: u32 = 0,
    bind: BindResult = .none,
    allow_copy_mode: bool = false,
};

pub const Result = struct {
    outcome: Outcome,
    reason: FallbackReason,
    need_multibuffer_pass: bool = false,
    fatal: bool = false,
};

fn fallback(reason: FallbackReason, multibuffer: bool) Result {
    return .{
        .outcome = .fallback_tc,
        .reason = reason,
        .need_multibuffer_pass = multibuffer,
        .fatal = false,
    };
}

pub fn evaluate(sample: Sample) Result {
    const multibuffer = sample.features_present and (sample.features & feat_rx_sg) != 0;

    if (sample.rx_queues < 2) {
        return fallback(.single_queue, multibuffer);
    }

    if (sample.features_present) {
        if (sample.features & feat_redirect == 0) {
            return fallback(.missing_redirect, multibuffer);
        }
        if (sample.features & feat_xsk_zerocopy == 0) {
            return fallback(.missing_zerocopy, multibuffer);
        }
    }

    return switch (sample.bind) {
        .zerocopy_ok => .{
            .outcome = .attach_zerocopy,
            .reason = if (sample.features_present) .none else .features_absent_skip,
            .need_multibuffer_pass = multibuffer,
            .fatal = false,
        },
        .copy_ok => if (sample.allow_copy_mode) .{
            .outcome = .attach_copy,
            .reason = .none,
            .need_multibuffer_pass = multibuffer,
            .fatal = false,
        } else fallback(.copy_disallowed, multibuffer),
        .failed, .none => fallback(.bind_failed, multibuffer),
    };
}

const std = @import("std");

const capable: u64 = feat_basic | feat_redirect | feat_xsk_zerocopy;

test "missing redirect falls back" {
    const r = evaluate(.{ .features = feat_basic | feat_xsk_zerocopy, .rx_queues = 4, .bind = .zerocopy_ok });
    try std.testing.expectEqual(Outcome.fallback_tc, r.outcome);
    try std.testing.expectEqual(FallbackReason.missing_redirect, r.reason);
    try std.testing.expect(!r.fatal);
}

test "missing zerocopy falls back" {
    const r = evaluate(.{ .features = feat_basic | feat_redirect, .rx_queues = 4, .bind = .zerocopy_ok });
    try std.testing.expectEqual(Outcome.fallback_tc, r.outcome);
    try std.testing.expectEqual(FallbackReason.missing_zerocopy, r.reason);
}

test "single queue falls back" {
    const r = evaluate(.{ .features = capable, .rx_queues = 1, .bind = .zerocopy_ok });
    try std.testing.expectEqual(Outcome.fallback_tc, r.outcome);
    try std.testing.expectEqual(FallbackReason.single_queue, r.reason);
}

test "bind failed falls back" {
    const r = evaluate(.{ .features = capable, .rx_queues = 4, .bind = .failed });
    try std.testing.expectEqual(Outcome.fallback_tc, r.outcome);
    try std.testing.expectEqual(FallbackReason.bind_failed, r.reason);
}

test "copy bind without allow_copy_mode falls back" {
    const r = evaluate(.{ .features = capable, .rx_queues = 4, .bind = .copy_ok, .allow_copy_mode = false });
    try std.testing.expectEqual(Outcome.fallback_tc, r.outcome);
    try std.testing.expectEqual(FallbackReason.copy_disallowed, r.reason);
}

test "copy bind with allow_copy_mode attaches copy" {
    const r = evaluate(.{ .features = capable, .rx_queues = 4, .bind = .copy_ok, .allow_copy_mode = true });
    try std.testing.expectEqual(Outcome.attach_copy, r.outcome);
    try std.testing.expect(!r.fatal);
}

test "rx_sg records multibuffer pass" {
    const r = evaluate(.{
        .features = capable | feat_rx_sg,
        .rx_queues = 4,
        .bind = .zerocopy_ok,
    });
    try std.testing.expectEqual(Outcome.attach_zerocopy, r.outcome);
    try std.testing.expect(r.need_multibuffer_pass);
}

test "absent feature bitmap skips tier 0" {
    const r = evaluate(.{
        .features = 0,
        .features_present = false,
        .rx_queues = 4,
        .bind = .zerocopy_ok,
    });
    try std.testing.expectEqual(Outcome.attach_zerocopy, r.outcome);
    try std.testing.expectEqual(FallbackReason.features_absent_skip, r.reason);
    try std.testing.expect(!r.fatal);
}

test "no probe result is fatal" {
    const samples = [_]Sample{
        .{},
        .{ .features = capable, .rx_queues = 0, .bind = .failed },
        .{ .features = capable, .rx_queues = 8, .bind = .zerocopy_ok },
    };
    for (samples) |sample| {
        try std.testing.expect(!evaluate(sample).fatal);
    }
}

test "probe sample has no driver or kind fields" {
    const sample = Sample{ .features = capable, .rx_queues = 2, .bind = .zerocopy_ok };
    const r = evaluate(sample);
    try std.testing.expectEqual(Outcome.attach_zerocopy, r.outcome);
    _ = model.abi_version;
}
