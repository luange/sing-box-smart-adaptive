const model = @import("model.zig");
const scoring = @import("scoring.zig");
const metrics = @import("metrics.zig");

pub const State = struct {
    selected_id: u64 = 0,
    challenge_id: u64 = 0,
    challenge_count: u32 = 0,
    challenge_since: u64 = 0,
    cooldown_until: u64 = 0,
    sticky_until: u64 = 0,

    pub fn reset(self: *State) void {
        self.* = .{};
    }
};

pub fn choose(state: *State, config: model.Config, observations: *const metrics.Store, candidates: []const model.Candidate, now_ms: u64) model.Decision {
    return chooseProfile(state, config, observations, candidates, now_ms, .interactive);
}

pub fn chooseProfile(state: *State, config: model.Config, observations: *const metrics.Store, candidates: []const model.Candidate, now_ms: u64, profile: scoring.TrafficProfile) model.Decision {
    const switch_margin = if (config.switch_margin >= 0 and scoring.isFinite(config.switch_margin)) @min(config.switch_margin, 0.95) else 0.0;
    var decision = model.Decision{ .selected_id = 0, .score = 100.0, .switched = 0, .reason = @intFromEnum(model.DecisionReason.no_candidate) };
    var best: ?model.Candidate = null;
    var best_score: f64 = 100.0;
    var best_tier: u8 = 255;
    var total_samples: f64 = 0;
    for (candidates) |raw_candidate| {
        const candidate = observations.enrich(raw_candidate);
        if (candidate.id == 0 or candidate.eligible == 0 or candidate.state == 4) continue;
        const tier = healthTier(candidate.state);
        if (tier < best_tier) best_tier = tier;
    }
    if (best_tier == 255) return decision;
    for (candidates) |raw_candidate| {
        const candidate = observations.enrich(raw_candidate);
        if (candidate.id != 0 and candidate.eligible != 0 and candidate.state != 4 and healthTier(candidate.state) == best_tier) {
            if (candidate.samples > 0 and scoring.isFinite(candidate.samples)) {
                total_samples += candidate.samples;
            }
        }
    }
    for (candidates) |raw_candidate| {
        const candidate = observations.enrich(raw_candidate);
        if (candidate.id == 0 or candidate.eligible == 0 or candidate.state == 4 or healthTier(candidate.state) != best_tier) continue;
        const value = scoring.score(config, candidate, total_samples, profile);
        if (scoring.isFinite(value) and (best == null or value < best_score)) {
            best = candidate;
            best_score = value;
        }
    }
    var selected = best orelse return decision;
    var selected_score = best_score;
    // Balanced mode is deliberately implemented in the policy kernel rather
    // than in the sing-box host.  The host may be replaced by mihomo or
    // another core, while the health tier, score margin and confirmation FSM
    // remain identical.  A context seed is supplied when the engine is
    // created, so rendezvous selection is stable without retaining a string
    // key in the Zig state.
    var incumbent: ?model.Candidate = null;
    if (state.selected_id != 0) {
        for (candidates) |raw_candidate| {
            const candidate = observations.enrich(raw_candidate);
            if (candidate.id == state.selected_id) {
                incumbent = candidate;
                break;
            }
        }
    }
    if (config.selection_mode == 1) {
        const threshold = if (best_score > 0) best_score * (1.0 + switch_margin) else 0.05;
        var retained_incumbent = false;
        if (incumbent) |current| {
            const current_score = scoring.score(config, current, total_samples, profile);
            if (current.id != 0 and current.eligible != 0 and current.state != 4 and
                healthTier(current.state) == best_tier and scoring.isFinite(current_score) and current_score <= threshold)
            {
                retained_incumbent = true;
                selected = current;
                selected_score = current_score;
            }
        }
        if (!retained_incumbent) {
            var selected_hash: u64 = 0;
            var found = false;
            for (candidates) |raw_candidate| {
                const candidate = observations.enrich(raw_candidate);
                if (candidate.id == 0 or candidate.eligible == 0 or candidate.state == 4 or healthTier(candidate.state) != best_tier) continue;
                const value = scoring.score(config, candidate, total_samples, profile);
                if (!scoring.isFinite(value) or value > threshold) continue;
                const hash = rendezvousHash(config.affinity_seed, candidate.id);
                if (!found or hash > selected_hash) {
                    found = true;
                    selected_hash = hash;
                    selected = candidate;
                    selected_score = value;
                }
            }
        }
    }
    // The host calls set_selected only after a real dial succeeds. Hold a
    // healthy incumbent for the configured window so score noise cannot cause
    // rapid oscillation; a hard-open incumbent still fails over below.
    if (incumbent) |current| {
        if (config.site_stickiness_ms > 0 and now_ms < state.sticky_until and
            current.state != 4 and current.eligible != 0 and healthTier(current.state) == best_tier)
        {
            const current_score = scoring.score(config, current, total_samples, profile);
            if (scoring.isFinite(current_score)) {
                decision.selected_id = current.id;
                decision.score = current_score;
                decision.reason = @intFromEnum(model.DecisionReason.retained);
                return decision;
            }
        }
    }
    decision.selected_id = selected.id;
    decision.score = selected_score;
    // `selected_id` is the last candidate whose dial actually succeeded.  Do
    // not commit a cold-start guess here: the host may still fail the dial and
    // report the observation on the next call.  Committing before that
    // callback would turn an unconnected candidate into the apparent primary
    // and could keep retrying it during a transient failure.
    if (state.selected_id == 0 or state.selected_id == selected.id) {
        decision.reason = @intFromEnum(model.DecisionReason.best);
        return decision;
    }
    if (incumbent) |current| {
        // A hard-open incumbent is unavailable (for example after the host's
        // passive throughput floor trips). Do not wait for performance
        // confirmation or cooldown: the next real connection must fail over.
        if (current.state == 4) {
            state.cooldown_until = now_ms +| config.switch_cooldown_ms;
            state.challenge_id = 0;
            state.challenge_count = 0;
            state.challenge_since = 0;
            decision.switched = 1;
            decision.reason = @intFromEnum(model.DecisionReason.confirmed);
            return decision;
        }
        const current_score = scoring.score(config, current, total_samples, profile);
        const improvement = if (current_score > 0) (current_score - selected_score) / current_score else 0;
        if (improvement < switch_margin or
            !absoluteImprovement(selected, current, config.switch_min_improvement_ms) or
            now_ms < state.cooldown_until)
        {
            decision.selected_id = current.id;
            decision.score = current_score;
            decision.reason = @intFromEnum(model.DecisionReason.retained);
            return decision;
        }
    }
    // A provider refresh can remove or rename the incumbent while the engine
    // still carries its previous selected_id.  That is a catalog change, not
    // a performance challenge: retaining an ID which cannot be emitted would
    // make the host fall back on every refresh and could strand the engine in
    // a stale challenge state.  Adopt the best currently eligible candidate
    // immediately and clear all confirmation state.
    if (state.selected_id != 0 and incumbent == null) {
        state.cooldown_until = now_ms +| config.switch_cooldown_ms;
        state.challenge_id = 0;
        state.challenge_count = 0;
        state.challenge_since = 0;
        decision.switched = 1;
        decision.reason = @intFromEnum(model.DecisionReason.confirmed);
        return decision;
    }
    if (state.challenge_id != selected.id or state.challenge_since == 0) {
        state.challenge_id = selected.id;
        state.challenge_count = 1;
        state.challenge_since = now_ms;
        decision.selected_id = state.selected_id;
        decision.reason = @intFromEnum(model.DecisionReason.retained);
        return decision;
    }
    state.challenge_count +|= 1;
    if (state.challenge_count < config.switch_confirm_samples or now_ms -| state.challenge_since < config.switch_confirm_ms) {
        decision.selected_id = state.selected_id;
        decision.reason = @intFromEnum(model.DecisionReason.retained);
        return decision;
    }
    state.cooldown_until = now_ms +| config.switch_cooldown_ms;
    state.challenge_id = 0;
    state.challenge_count = 0;
    state.challenge_since = 0;
    decision.switched = 1;
    decision.reason = @intFromEnum(model.DecisionReason.confirmed);
    return decision;
}

fn absoluteImprovement(best: model.Candidate, current: model.Candidate, minimum_ms: u64) bool {
    if (minimum_ms == 0) return true;
    const best_latency = candidateLatencyMS(best);
    const current_latency = candidateLatencyMS(current);
    if (!(best_latency > 0) or !scoring.isFinite(best_latency) or
        !(current_latency > 0) or !scoring.isFinite(current_latency)) return false;
    return current_latency - best_latency >= @as(f64, @floatFromInt(minimum_ms));
}

fn candidateLatencyMS(candidate: model.Candidate) f64 {
    if (candidate.first_byte_ms > 0 and scoring.isFinite(candidate.first_byte_ms)) return candidate.first_byte_ms;
    if (candidate.connect_ms > 0 and scoring.isFinite(candidate.connect_ms)) return candidate.connect_ms;
    return 0;
}

// splitmix64 gives a stable, cheap rendezvous metric for the pair
// (context-seed, canonical endpoint id).  It intentionally has no process
// randomness: the same service context keeps the same line across reloads,
// while independent contexts spread across the near-tied healthy pool.
fn rendezvousHash(seed: u64, id: u64) u64 {
    var value = seed ^ (id +% 0x9e3779b97f4a7c15);
    value = (value ^ (value >> 30)) *% 0xbf58476d1ce4e5b9;
    value = (value ^ (value >> 27)) *% 0x94d049bb133111eb;
    return value ^ (value >> 31);
}

// Health is a hard ordering boundary. Latency and throughput may choose the
// primary inside the best available tier, but a suspect or half-open node must
// never displace a healthy incumbent merely because its current sample is
// faster. Open nodes are excluded before this function is called.
fn healthTier(state: u8) u8 {
    return switch (state) {
        1 => 0, // healthy
        2, 0 => 1, // warming/unknown
        3 => 2, // suspect
        5 => 3, // half-open: usable only for a bounded recovery trial
        4 => 4, // defensive: open is filtered above
        else => 2,
    };
}
