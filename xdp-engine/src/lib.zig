//! Next-gen XDP policy core. Host-neutral: no netlink, UMEM, or Go FFI yet.

const std = @import("std");
const model = @import("model.zig");
const classify = @import("classify.zig");
const probe = @import("probe.zig");
const lifecycle = @import("lifecycle.zig");

pub const abi_version = model.abi_version;
pub const Verdict = model.Verdict;
pub const XdpAction = model.XdpAction;
pub const classifyPacket = classify.classify;
pub const evaluateProbe = probe.evaluate;
pub const Session = lifecycle.Session;

pub fn version() u32 {
    return abi_version;
}

comptime {
    _ = model;
    _ = classify;
    _ = probe;
    _ = lifecycle;
}

test "abi version is stable" {
    try std.testing.expectEqual(@as(u32, 1), version());
}

test "proxy traffic cannot ride an attached session" {
    var session = Session{};
    session.beginProbe();
    const sample = probe.Sample{
        .features = probe.feat_basic | probe.feat_redirect | probe.feat_xsk_zerocopy,
        .rx_queues = 4,
        .bind = .zerocopy_ok,
    };
    session.applyProbe(sample, probe.evaluate(sample));
    try std.testing.expect(session.attached());

    const decision = classify.classify(.{
        .generation = 1,
        .xdp_attached = session.attached(),
        .packet = .{ .dport = 443 },
        .static_hit = .{ .verdict = .proxy, .generation = 1 },
    });
    try std.testing.expectEqual(model.XdpAction.pass, decision.action);
    try std.testing.expectEqual(model.Verdict.proxy, decision.verdict);
}
