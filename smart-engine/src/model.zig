pub const Candidate = extern struct {
    id: u64,
    reliability: f64,
    connect_ms: f64,
    first_byte_ms: f64,
    jitter_ms: f64,
    throughput_bps: f64,
    samples: f64,
    weight: f64,
    state: u8,
    eligible: u8,
};

pub const Config = extern struct {
    exploration: f64,
    switch_margin: f64,
    switch_confirm_samples: u32,
    switch_confirm_ms: u64,
    switch_cooldown_ms: u64,
    affinity_seed: u64 = 0,
    selection_mode: u8 = 0,
    site_stickiness_ms: u64 = 0,
    switch_min_improvement_ms: u64 = 0,
};

pub const Decision = extern struct {
    selected_id: u64,
    score: f64,
    switched: u8,
    reason: u8,
};

pub const DecisionReason = enum(u8) {
    best = 0,
    retained = 1,
    confirmed = 2,
    no_candidate = 3,
};
