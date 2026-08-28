const std = @import("std");

pub const max_entries = 4096;

pub const Metrics = struct {
    id: u64 = 0,
    used: bool = false,
    successes: u64 = 0,
    failures: u64 = 0,
    connect_ms: f64 = 0,
    jitter_ms: f64 = 0,
    samples: u64 = 0,
    last_ms: f64 = 0,
    last_updated: u64 = 0,
};

pub const Store = struct {
    entries: [max_entries]Metrics = [_]Metrics{Metrics{}} ** max_entries,
    count: usize = 0,

    pub fn reset(self: *Store) void {
        self.entries = [_]Metrics{Metrics{}} ** max_entries;
        self.count = 0;
    }

    pub fn observe(self: *Store, id: u64, success: bool, elapsed_ms: f64, now_ms: u64) void {
        if (id == 0) return;
        var slot = self.find(id);
        if (slot == null) slot = self.allocate(id, now_ms);
        if (slot == null) return;
        var metric = &self.entries[slot.?];
        if (success) metric.successes +|= 1 else metric.failures +|= 1;
        if (elapsed_ms > 0 and elapsed_ms == elapsed_ms) {
            if (metric.samples == 0) {
                metric.connect_ms = elapsed_ms;
            } else {
                const delta = elapsed_ms - metric.connect_ms;
                metric.connect_ms += 0.2 * delta;
                metric.jitter_ms += 0.2 * (@abs(delta) - metric.jitter_ms);
            }
            metric.last_ms = elapsed_ms;
        }
        metric.samples +|= 1;
        metric.last_updated = now_ms;
    }

    pub fn get(self: *const Store, id: u64) ?Metrics {
        if (self.findConst(id)) |index| return self.entries[index];
        return null;
    }

    pub fn enrich(self: *const Store, candidate: anytype) @TypeOf(candidate) {
        const observed = self.get(candidate.id) orelse return candidate;
        var result = candidate;
        if (result.samples <= 0 and observed.samples > 0) {
            const total = observed.successes + observed.failures;
            result.samples = @floatFromInt(observed.samples);
            if (total > 0) result.reliability = @as(f64, @floatFromInt(observed.successes)) / @as(f64, @floatFromInt(total));
        }
        if (result.connect_ms <= 0 and observed.connect_ms > 0) result.connect_ms = observed.connect_ms;
        if (result.jitter_ms <= 0 and observed.jitter_ms > 0) result.jitter_ms = observed.jitter_ms;
        return result;
    }

    fn find(self: *Store, id: u64) ?usize {
        for (self.entries, 0..) |entry, index| {
            if (entry.used and entry.id == id) return index;
        }
        return null;
    }

    fn findConst(self: *const Store, id: u64) ?usize {
        for (self.entries, 0..) |entry, index| {
            if (entry.used and entry.id == id) return index;
        }
        return null;
    }

    fn allocate(self: *Store, id: u64, now_ms: u64) ?usize {
        if (self.count < max_entries) {
            for (&self.entries, 0..) |*entry, index| {
                if (!entry.used) {
                    entry.* = .{ .id = id, .used = true, .last_updated = now_ms };
                    self.count += 1;
                    return index;
                }
            }
        }
        var oldest: usize = 0;
        var oldest_time: u64 = std.math.maxInt(u64);
        var found = false;
        for (self.entries, 0..) |entry, index| {
            if (entry.used and entry.last_updated <= oldest_time) {
                oldest = index;
                oldest_time = entry.last_updated;
                found = true;
            }
        }
        if (!found) return null;
        self.entries[oldest] = .{ .id = id, .used = true, .last_updated = now_ms };
        return oldest;
    }
};
