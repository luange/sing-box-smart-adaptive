const std = @import("std");

pub const max_entries = 4096;
// Keep the metric payload bounded at max_entries while giving the lookup
// index enough headroom for expected O(1) probing.  The index stores 16-bit
// entry numbers, so it is much smaller than duplicating Metrics itself.
const index_capacity = 8192;
const index_mask = index_capacity - 1;
const empty_slot: u16 = std.math.maxInt(u16);
const tombstone_slot: u16 = empty_slot - 1;

fn initialFreeSlots() [max_entries]u16 {
    @setEvalBranchQuota(10000);
    var slots = [_]u16{0} ** max_entries;
    for (&slots, 0..) |*slot, index| slot.* = @intCast(max_entries - index - 1);
    return slots;
}

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
    slots: [index_capacity]u16 = [_]u16{empty_slot} ** index_capacity,
    free_slots: [max_entries]u16 = initialFreeSlots(),
    free_count: usize = max_entries,
    count: usize = 0,
    tombstones: usize = 0,

    pub fn reset(self: *Store) void {
        self.entries = [_]Metrics{Metrics{}} ** max_entries;
        self.slots = [_]u16{empty_slot} ** index_capacity;
        for (&self.free_slots, 0..) |*slot, index| slot.* = @intCast(max_entries - index - 1);
        self.free_count = max_entries;
        self.count = 0;
        self.tombstones = 0;
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
        var position = hash(id) & index_mask;
        var steps: usize = 0;
        while (steps < index_capacity) : (steps += 1) {
            const slot = self.slots[position];
            if (slot == empty_slot) return null;
            if (slot != tombstone_slot) {
                const index: usize = slot;
                if (self.entries[index].used and self.entries[index].id == id) return index;
            }
            position = (position + 1) & index_mask;
        }
        return null;
    }

    fn findConst(self: *const Store, id: u64) ?usize {
        var position = hash(id) & index_mask;
        var steps: usize = 0;
        while (steps < index_capacity) : (steps += 1) {
            const slot = self.slots[position];
            if (slot == empty_slot) return null;
            if (slot != tombstone_slot) {
                const index: usize = slot;
                if (self.entries[index].used and self.entries[index].id == id) return index;
            }
            position = (position + 1) & index_mask;
        }
        return null;
    }

    fn allocate(self: *Store, id: u64, now_ms: u64) ?usize {
        var index: usize = undefined;
        if (self.free_count > 0) {
            self.free_count -= 1;
            index = self.free_slots[self.free_count];
            self.count += 1;
        } else {
            var oldest: usize = 0;
            var oldest_time: u64 = std.math.maxInt(u64);
            var found = false;
            for (self.entries, 0..) |entry, candidate_index| {
                if (entry.used and entry.last_updated <= oldest_time) {
                    oldest = candidate_index;
                    oldest_time = entry.last_updated;
                    found = true;
                }
            }
            if (!found) return null;
            self.removeIndex(self.entries[oldest].id);
            index = oldest;
        }
        self.entries[index] = .{ .id = id, .used = true, .last_updated = now_ms };
        // Rebuild only after the replacement entry is written. Rebuilding
        // while the evicted entry is still marked used would briefly restore
        // the old id and leave a stale slot pointing at the reused entry.
        if (self.tombstones > index_capacity / 4) {
            self.rebuildIndex();
        } else {
            self.insertIndex(id, @intCast(index));
        }
        return index;
    }

    fn hash(id: u64) usize {
        var value = id;
        value ^= value >> 30;
        value *%= 0xbf58476d1ce4e5b9;
        value ^= value >> 27;
        value *%= 0x94d049bb133111eb;
        value ^= value >> 31;
        return @intCast(value);
    }

    fn insertIndex(self: *Store, id: u64, entry_index: u16) void {
        var position = hash(id) & index_mask;
        var first_tombstone: ?usize = null;
        while (true) {
            const slot = self.slots[position];
            if (slot == empty_slot) {
                const target = first_tombstone orelse position;
                if (first_tombstone != null) self.tombstones -= 1;
                self.slots[target] = entry_index;
                return;
            }
            if (slot == tombstone_slot and first_tombstone == null) first_tombstone = position;
            position = (position + 1) & index_mask;
        }
    }

    fn removeIndex(self: *Store, id: u64) void {
        var position = hash(id) & index_mask;
        var steps: usize = 0;
        while (steps < index_capacity) : (steps += 1) {
            const slot = self.slots[position];
            if (slot == empty_slot) return;
            if (slot != tombstone_slot) {
                const index: usize = slot;
                if (self.entries[index].used and self.entries[index].id == id) {
                    self.slots[position] = tombstone_slot;
                    self.tombstones += 1;
                    return;
                }
            }
            position = (position + 1) & index_mask;
        }
    }

    fn rebuildIndex(self: *Store) void {
        self.slots = [_]u16{empty_slot} ** index_capacity;
        self.tombstones = 0;
        for (self.entries, 0..) |entry, index| {
            if (entry.used) self.insertIndex(entry.id, @intCast(index));
        }
    }
};
