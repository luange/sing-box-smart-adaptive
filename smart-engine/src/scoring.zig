const std = @import("std");
const model = @import("model.zig");

pub fn normalizedCost(value: f64, ceiling: f64) f64 {
    if (!(value > 0) or value != value) return 0.5;
    return std.math.clamp(std.math.log1p(value) / std.math.log1p(ceiling), 0.0, 1.0);
}

pub const TrafficProfile = enum(u8) {
    interactive = 0,
    bulk = 1,
    udp = 2,
};

pub fn score(config: model.Config, candidate: model.Candidate, total_samples: f64, profile: TrafficProfile) f64 {
    const reliability = std.math.clamp(candidate.reliability, 0.0, 1.0);
    // The host supplies robust tail-latency values in these fields. Keeping
    // the ABI names stable lets older callers continue to work; callers that
    // only have an EWMA still get the same bounded fallback behavior.
    const connect_cost = normalizedCost(candidate.connect_ms, 5000.0);
    const first_byte_cost = normalizedCost(candidate.first_byte_ms, 10000.0);
    const jitter_cost = if (candidate.jitter_ms > 0)
        std.math.clamp(candidate.jitter_ms / 1000.0, 0.0, 1.0)
    else
        0.5;
    const throughput_ceiling: f64 = 64 * 1024 * 1024;
    const throughput_cost = if (candidate.throughput_bps > 0)
        1.0 - std.math.clamp(std.math.log1p(candidate.throughput_bps) / std.math.log1p(throughput_ceiling), 0.0, 1.0)
    else
        0.60;
    const exploration = if (candidate.samples > 0 and total_samples > 0)
        @max(config.exploration, 0.0) * @sqrt(@log(total_samples + 1.0) / candidate.samples)
    else
        @max(config.exploration, 0.0);
    const weight = if (candidate.weight > 0) candidate.weight else 1.0;
    var reliability_weight: f64 = 0.30;
    var connect_weight: f64 = 0.25;
    var first_byte_weight: f64 = 0.30;
    var throughput_weight: f64 = 0;
    var jitter_weight: f64 = 0.10;
    var confidence_weight: f64 = 0.05;
    switch (profile) {
        .bulk => {
            reliability_weight = 0.30;
            connect_weight = 0.15;
            first_byte_weight = 0.20;
            throughput_weight = 0.30;
            jitter_weight = 0.00;
        },
        .udp => {
            reliability_weight = 0.50;
            connect_weight = 0.25;
            first_byte_weight = 0;
            throughput_weight = 0;
            jitter_weight = 0.20;
        },
        .interactive => {},
    }
    const confidence_cost = if (candidate.samples < 3.0) @max(0.0, 1.0 - candidate.samples / 3.0) else 0.0;
    const base = reliability_weight * (1.0 - reliability) + connect_weight * connect_cost + first_byte_weight * first_byte_cost + throughput_weight * throughput_cost + jitter_weight * jitter_cost + confidence_weight * confidence_cost;
    return @max(0.0, base - exploration) / weight;
}
