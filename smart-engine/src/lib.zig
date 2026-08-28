const std = @import("std");
const model = @import("model.zig");
const metrics = @import("metrics.zig");
const policy = @import("policy.zig");
const scoring = @import("scoring.zig");
const adaptive = @import("adaptive.zig");

const max_candidates = 8192;

pub const Candidate = model.Candidate;
pub const Config = model.Config;
pub const Decision = model.Decision;

const Engine = struct {
    config: Config,
    observations: metrics.Store = .{},
    state: policy.State = .{},

    fn init(config: Config) Engine {
        var normalized = config;
        if (!(normalized.exploration >= 0) or normalized.exploration != normalized.exploration) normalized.exploration = 0;
        if (!(normalized.switch_margin >= 0) or normalized.switch_margin != normalized.switch_margin) normalized.switch_margin = 0;
        if (normalized.switch_margin > 0.95) normalized.switch_margin = 0.95;
        if (normalized.switch_confirm_samples == 0) normalized.switch_confirm_samples = 1;
        return .{ .config = normalized };
    }

    fn reset(self: *Engine) void {
        self.observations.reset();
        self.state.reset();
    }

    fn observe(self: *Engine, id: u64, success: bool, elapsed_ms: f64, now_ms: u64) void {
        self.observations.observe(id, success, elapsed_ms, now_ms);
    }
};

export fn smart_engine_create(config: Config) ?*Engine {
    const engine = std.heap.page_allocator.create(Engine) catch return null;
    engine.* = Engine.init(config);
    return engine;
}

export fn smart_engine_abi_version() u32 {
    return 1;
}

export fn smart_engine_destroy(engine: ?*Engine) void {
    if (engine) |value| {
        value.reset();
        std.heap.page_allocator.destroy(value);
    }
}

export fn smart_engine_observe(engine: ?*Engine, id: u64, success: u8, elapsed_ms: f64, now_ms: u64) void {
    if (engine) |value| value.observe(id, success != 0, elapsed_ms, now_ms);
}

export fn smart_engine_choose(engine: ?*Engine, candidates: ?[*]const Candidate, count: usize, now_ms: u64) Decision {
    if (engine) |value| {
        if (count > max_candidates) return .{ .selected_id = 0, .score = 100.0, .switched = 0, .reason = 3 };
        if (candidates) |pointer| return policy.choose(&value.state, value.config, &value.observations, pointer[0..count], now_ms);
    }
    return .{ .selected_id = 0, .score = 100.0, .switched = 0, .reason = 3 };
}

export fn smart_engine_choose_profile(engine: ?*Engine, candidates: ?[*]const Candidate, count: usize, now_ms: u64, profile: u8) Decision {
    if (engine) |value| {
        if (count > max_candidates) return .{ .selected_id = 0, .score = 100.0, .switched = 0, .reason = 3 };
        if (candidates) |pointer| {
            const selected_profile: scoring.TrafficProfile = switch (profile) {
                1 => .bulk,
                2 => .udp,
                else => .interactive,
            };
            return policy.chooseProfile(&value.state, value.config, &value.observations, pointer[0..count], now_ms, selected_profile);
        }
    }
    return .{ .selected_id = 0, .score = 100.0, .switched = 0, .reason = 3 };
}

export fn smart_engine_reset(engine: ?*Engine) void {
    if (engine) |value| value.reset();
}

const AdaptiveEngine = struct {
    config: adaptive.Config,
    state: adaptive.State = .{},
};

export fn adaptive_engine_abi_version() u32 {
    return 3;
}

export fn adaptive_engine_create(config: adaptive.Config) ?*AdaptiveEngine {
    const engine = std.heap.page_allocator.create(AdaptiveEngine) catch return null;
    var normalized = config;
    if (!(normalized.switch_margin >= 0) or normalized.switch_margin != normalized.switch_margin) normalized.switch_margin = 0.15;
    if (normalized.switch_margin > 0.95) normalized.switch_margin = 0.95;
    if (normalized.switch_confirm_samples == 0) normalized.switch_confirm_samples = 1;
    engine.* = .{ .config = normalized };
    return engine;
}

export fn adaptive_engine_configure(engine: ?*AdaptiveEngine, config: adaptive.Config) void {
    if (engine) |value| {
        var normalized = config;
        if (!(normalized.switch_margin >= 0) or normalized.switch_margin != normalized.switch_margin) normalized.switch_margin = 0.15;
        if (normalized.switch_margin > 0.95) normalized.switch_margin = 0.95;
        if (normalized.switch_confirm_samples == 0) normalized.switch_confirm_samples = 1;
        value.config = normalized;
    }
}

export fn adaptive_engine_destroy(engine: ?*AdaptiveEngine) void {
    if (engine) |value| std.heap.page_allocator.destroy(value);
}

export fn adaptive_engine_choose(engine: ?*AdaptiveEngine, candidates: ?[*]const adaptive.Candidate, count: usize, now_ms: u64) adaptive.Decision {
    if (engine) |value| {
        if (candidates) |pointer| {
            if (count <= adaptive.max_candidates) return adaptive.choose(&value.state, value.config, pointer[0..count], now_ms);
        }
    }
    return .{ .selected_id = 0, .switched = 0, .reason = 5, .score = 0 };
}

export fn adaptive_engine_set_bulk_sequence(engine: ?*AdaptiveEngine, sequence: u64) void {
    if (engine) |value| value.state.bulk_sequence = sequence;
}

export fn adaptive_engine_remember(engine: ?*AdaptiveEngine, id: u64, now_ms: u64, cooldown_ms: u64) void {
    if (engine) |value| {
        value.state.sticky_id = id;
        value.state.sticky_until = if (cooldown_ms > 0) now_ms +| cooldown_ms else 0;
        value.state.selected_id = id;
        value.state.challenge_id = 0;
        value.state.challenge_count = 0;
        value.state.challenge_since = 0;
    }
}

export fn adaptive_engine_forget(engine: ?*AdaptiveEngine) void {
    if (engine) |value| {
        value.state.sticky_id = 0;
        value.state.sticky_until = 0;
        value.state.selected_id = 0;
        value.state.challenge_id = 0;
        value.state.challenge_count = 0;
        value.state.challenge_since = 0;
    }
}

export fn adaptive_engine_reset(engine: ?*AdaptiveEngine) void {
    if (engine) |value| value.state.reset();
}

test "retains incumbent until confirmation" {
    var engine = Engine.init(.{ .exploration = 0, .switch_margin = 0.05, .switch_confirm_samples = 2, .switch_confirm_ms = 1000, .switch_cooldown_ms = 2000 });
    const candidates = [_]Candidate{
        .{ .id = 1, .reliability = 0.9, .connect_ms = 20, .first_byte_ms = 20, .jitter_ms = 1, .throughput_bps = 0, .samples = 4, .weight = 1, .state = 1, .eligible = 1 },
        .{ .id = 2, .reliability = 0.99, .connect_ms = 5, .first_byte_ms = 5, .jitter_ms = 1, .throughput_bps = 0, .samples = 4, .weight = 1, .state = 1, .eligible = 1 },
    };
    try std.testing.expectEqual(@as(u64, 1), policy.choose(&engine.state, engine.config, &engine.observations, candidates[0..1], 0).selected_id);
    try std.testing.expectEqual(@as(u8, 0), policy.choose(&engine.state, engine.config, &engine.observations, &candidates, 1000).switched);
    try std.testing.expectEqual(@as(u8, 1), policy.choose(&engine.state, engine.config, &engine.observations, &candidates, 2000).switched);
}

test "hard-open incumbent fails over without confirmation" {
    var engine = Engine.init(.{ .exploration = 0, .switch_margin = 0.95, .switch_confirm_samples = 3, .switch_confirm_ms = 60000, .switch_cooldown_ms = 2000 });
    const incumbent = Candidate{ .id = 1, .reliability = 0.99, .connect_ms = 5, .first_byte_ms = 5, .jitter_ms = 1, .throughput_bps = 0, .samples = 10, .weight = 1, .state = 1, .eligible = 1 };
    const fallback = Candidate{ .id = 2, .reliability = 0.30, .connect_ms = 500, .first_byte_ms = 500, .jitter_ms = 10, .throughput_bps = 0, .samples = 1, .weight = 1, .state = 1, .eligible = 1 };
    const initial = [_]Candidate{incumbent};
    _ = policy.chooseProfile(&engine.state, engine.config, &engine.observations, initial[0..], 0, .bulk);
    const opened = [_]Candidate{ .{ .id = 1, .reliability = 0.99, .connect_ms = 5, .first_byte_ms = 5, .jitter_ms = 1, .throughput_bps = 0, .samples = 10, .weight = 1, .state = 4, .eligible = 1 }, fallback };
    const decision = policy.chooseProfile(&engine.state, engine.config, &engine.observations, opened[0..], 1, .bulk);
    try std.testing.expectEqual(@as(u64, 2), decision.selected_id);
    try std.testing.expectEqual(@as(u8, 1), decision.switched);
}

test "stale incumbent is replaced immediately after catalog refresh" {
    var engine = Engine.init(.{ .exploration = 0, .switch_margin = 0.15, .switch_confirm_samples = 3, .switch_confirm_ms = 60000, .switch_cooldown_ms = 120000 });
    const old = [_]Candidate{.{ .id = 11, .reliability = 0.99, .connect_ms = 10, .first_byte_ms = 10, .jitter_ms = 1, .throughput_bps = 0, .samples = 4, .weight = 1, .state = 1, .eligible = 1 }};
    _ = policy.chooseProfile(&engine.state, engine.config, &engine.observations, old[0..], 0, .interactive);
    const refreshed = [_]Candidate{.{ .id = 22, .reliability = 0.80, .connect_ms = 100, .first_byte_ms = 100, .jitter_ms = 2, .throughput_bps = 0, .samples = 1, .weight = 1, .state = 1, .eligible = 1 }};
    const decision = policy.chooseProfile(&engine.state, engine.config, &engine.observations, refreshed[0..], 1, .interactive);
    try std.testing.expectEqual(@as(u64, 22), decision.selected_id);
    try std.testing.expectEqual(@as(u8, 1), decision.switched);
    try std.testing.expectEqual(@as(u64, 0), engine.state.challenge_id);
}

test "adaptive remember clears an in-flight challenge" {
    var engine = AdaptiveEngine{ .config = .{ .switch_margin = 0, .switch_cooldown_ms = 0, .switch_confirm_samples = 3, .switch_confirm_ms = 60000, .mode = 1, .manual_failure = 0 } };
    engine.state.challenge_id = 2;
    engine.state.challenge_count = 2;
    engine.state.challenge_since = 1;
    adaptive_engine_remember(&engine, 1, 2, 0);
    try std.testing.expectEqual(@as(u64, 0), engine.state.challenge_id);
    try std.testing.expectEqual(@as(u32, 0), engine.state.challenge_count);
    try std.testing.expectEqual(@as(u64, 0), engine.state.challenge_since);
}

test "bounded observations do not grow after reset" {
    var engine = Engine.init(.{ .exploration = 0, .switch_margin = 0, .switch_confirm_samples = 1, .switch_confirm_ms = 0, .switch_cooldown_ms = 0 });
    var id: u64 = 1;
    while (id <= metrics.max_entries + 1) : (id += 1) engine.observe(id, true, 1, id);
    try std.testing.expectEqual(metrics.max_entries, engine.observations.count);
    engine.reset();
    try std.testing.expectEqual(@as(usize, 0), engine.observations.count);
}

test "hashed observations evict the oldest entry and remain addressable" {
    var engine = Engine.init(.{ .exploration = 0, .switch_margin = 0, .switch_confirm_samples = 1, .switch_confirm_ms = 0, .switch_cooldown_ms = 0 });
    var id: u64 = 1;
    while (id <= metrics.max_entries) : (id += 1) engine.observe(id, true, 1, id);
    // The first entry is the oldest and must be replaced on the next insert.
    engine.observe(metrics.max_entries + 1, true, 2, metrics.max_entries + 1);
    try std.testing.expect(engine.observations.get(1) == null);
    try std.testing.expect(engine.observations.get(2048) != null);
    try std.testing.expect(engine.observations.get(metrics.max_entries + 1) != null);
    try std.testing.expectEqual(metrics.max_entries, engine.observations.count);

    // Cross the tombstone rebuild threshold and verify that reusing a metric
    // slot never leaves the evicted id pointing at the replacement entry.
    var churn: u64 = 0;
    while (churn < 2100) : (churn += 1) {
        engine.observe(metrics.max_entries + 2 + churn, true, 3, metrics.max_entries + 2 + churn);
    }
    try std.testing.expect(engine.observations.get(2) == null);
    try std.testing.expect(engine.observations.get(metrics.max_entries + 2101) != null);
}

test "observations fill missing candidate evidence" {
    var engine = Engine.init(.{ .exploration = 0, .switch_margin = 0, .switch_confirm_samples = 1, .switch_confirm_ms = 0, .switch_cooldown_ms = 0 });
    engine.observe(7, true, 10, 1);
    engine.observe(7, true, 12, 2);
    engine.observe(7, false, 0, 3);
    const candidates = [_]Candidate{.{
        .id = 7,
        .reliability = 0,
        .connect_ms = 0,
        .first_byte_ms = 0,
        .jitter_ms = 0,
        .throughput_bps = 0,
        .samples = 0,
        .weight = 1,
        .state = 1,
        .eligible = 1,
    }};
    const decision = policy.choose(&engine.state, engine.config, &engine.observations, &candidates, 4);
    try std.testing.expectEqual(@as(u64, 7), decision.selected_id);
}

test "profile scoring changes only the intended objective" {
    const config = Config{ .exploration = 0, .switch_margin = 0, .switch_confirm_samples = 1, .switch_confirm_ms = 0, .switch_cooldown_ms = 0 };
    const slow = Candidate{ .id = 1, .reliability = 0.98, .connect_ms = 5, .first_byte_ms = 5, .jitter_ms = 1, .throughput_bps = 1_000_000, .samples = 10, .weight = 1, .state = 1, .eligible = 1 };
    const fast = Candidate{ .id = 2, .reliability = 0.98, .connect_ms = 5, .first_byte_ms = 5, .jitter_ms = 1, .throughput_bps = 100_000_000, .samples = 10, .weight = 1, .state = 1, .eligible = 1 };
    try std.testing.expect(scoring.score(config, fast, 20, .bulk) < scoring.score(config, slow, 20, .bulk));
    try std.testing.expectEqual(scoring.score(config, fast, 20, .interactive), scoring.score(config, slow, 20, .interactive));
}
