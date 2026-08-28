const model = @import("model.zig");
const scoring = @import("scoring.zig");
const metrics = @import("metrics.zig");

pub const State = struct {
    selected_id: u64 = 0,
    challenge_id: u64 = 0,
    challenge_count: u32 = 0,
    challenge_since: u64 = 0,
    cooldown_until: u64 = 0,

    pub fn reset(self: *State) void {
        self.* = .{};
    }

    pub fn stick(self: *State, id: u64, until_ms: u64) void {
        if (id == 0) return;
        self.selected_id = id;
        self.challenge_id = 0;
        self.challenge_count = 0;
        self.challenge_since = 0;
        self.cooldown_until = until_ms;
    }
};

pub fn choose(state: *State, config: model.Config, observations: *const metrics.Store, candidates: []const model.Candidate, now_ms: u64) model.Decision {
    return chooseProfile(state, config, observations, candidates, now_ms, .interactive);
}

pub fn chooseProfile(state: *State, config: model.Config, observations: *const metrics.Store, candidates: []const model.Candidate, now_ms: u64, profile: scoring.TrafficProfile) model.Decision {
    var decision = model.Decision{ .selected_id = 0, .score = 100.0, .switched = 0, .reason = @intFromEnum(model.DecisionReason.no_candidate) };
    var best: ?model.Candidate = null;
    var best_score: f64 = 100.0;
    var total_samples: f64 = 0;
    for (candidates) |raw_candidate| {
        const candidate = observations.enrich(raw_candidate);
        if (candidate.id != 0 and candidate.eligible != 0 and candidate.state != 4) total_samples += @max(candidate.samples, 0.0);
    }
    for (candidates) |raw_candidate| {
        const candidate = observations.enrich(raw_candidate);
        if (candidate.id == 0 or candidate.eligible == 0 or candidate.state == 4) continue;
        const value = scoring.score(config, candidate, total_samples, profile);
        if (best == null or value < best_score) {
            best = candidate;
            best_score = value;
        }
    }
    const selected = best orelse return decision;
    decision.selected_id = selected.id;
    decision.score = best_score;
    if (state.selected_id == 0 or state.selected_id == selected.id) {
        state.selected_id = selected.id;
        decision.reason = @intFromEnum(model.DecisionReason.best);
        return decision;
    }
    var incumbent: ?model.Candidate = null;
    for (candidates) |raw_candidate| {
        const candidate = observations.enrich(raw_candidate);
        if (candidate.id == state.selected_id) {
            incumbent = candidate;
            break;
        }
    }
    if (incumbent) |current| {
        // A hard-open incumbent is unavailable (for example after the host's
        // passive throughput floor trips). Do not wait for performance
        // confirmation or cooldown: the next real connection must fail over.
        // An ineligible incumbent is equivalent to a hard-open one. This can
        // happen during a provider refresh when the old endpoint disappears
        // from the current catalog; retaining it would return a stale ID and
        // force the host to fall back for the whole confirmation window.
        if (current.state == 4 or current.eligible == 0) {
            state.selected_id = selected.id;
            state.cooldown_until = now_ms +| config.switch_cooldown_ms;
            state.challenge_id = 0;
            state.challenge_count = 0;
            state.challenge_since = 0;
            decision.switched = 1;
            decision.reason = @intFromEnum(model.DecisionReason.confirmed);
            return decision;
        }
        const current_score = scoring.score(config, current, total_samples, profile);
        const improvement = if (current_score > 0) (current_score - best_score) / current_score else 0;
        if (improvement < config.switch_margin or now_ms < state.cooldown_until) {
            decision.selected_id = current.id;
            decision.score = current_score;
            decision.reason = @intFromEnum(model.DecisionReason.retained);
            return decision;
        }
    } else {
        // The previous selection is no longer present in this catalog. There
        // is no incumbent to protect, so adopt the best current candidate
        // immediately instead of emitting a stale selected_id while waiting
        // for confirmation samples that can never be observed.
        state.selected_id = selected.id;
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
    state.selected_id = selected.id;
    state.cooldown_until = now_ms +| config.switch_cooldown_ms;
    state.challenge_id = 0;
    state.challenge_count = 0;
    state.challenge_since = 0;
    decision.switched = 1;
    decision.reason = @intFromEnum(model.DecisionReason.confirmed);
    return decision;
}
