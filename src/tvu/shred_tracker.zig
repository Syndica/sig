const std = @import("std");
const sig = @import("../lib.zig");

const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const Atomic = std.atomic.Atomic;
const Ordering = std.atomic.Ordering;
const DefaultRwLock = std.Thread.RwLock.DefaultRwLock;
const Mutex = std.Thread.Mutex;

const AtomicBitArray = sig.sync.AtomicBitArray;
const ReferenceCounter = sig.sync.ReferenceCounter;
const Slot = sig.core.Slot;

pub const MAX_SHREDS_PER_SLOT: usize = sig.tvu.MAX_SHREDS_PER_SLOT;

/// Naively tracks which shreds have been received, so we can request missing shreds.
/// Has no awareness of forking.
/// Placeholder until more sophisticated Blockstore and RepairWeights implementation.
///
/// This struct is thread safe. Public methods can be called from anywhere at any time.
pub const BasicShredTracker = struct {
    allocator: Allocator,

    /// prevents multiple threads from executing a rotation simultaneously
    rotation_lock: Mutex = Mutex{},

    /// The starting slot when this is first created, when the shard_counter = 0
    /// never changes
    start_slot: Slot,

    /// The lowest slot currently tracked
    first_slot: Atomic(Slot),
    /// The highest slot currently tracked
    last_slot: Atomic(Slot),

    slots: [num_slots]Atomic(*MonitoredSlot),

    good_until: Atomic(Slot),
    max_slot_seen: Atomic(Slot),

    const num_slots: usize = 128;

    const Self = @This();

    pub fn init(allocator: Allocator, slot: Slot) !Self {
        var slots: [num_slots]Atomic(*MonitoredSlot) = undefined;
        for (&slots) |*s| s.* = .{ .value = try MonitoredSlot.init(allocator) };
        // TODO is this off by one?
        return .{
            .allocator = allocator,
            .start_slot = slot,
            .good_until = Atomic(Slot).init(slot),
            .max_slot_seen = Atomic(Slot).init(slot),
            .first_slot = Atomic(Slot).init(slot),
            .last_slot = Atomic(Slot).init(slot + num_slots - 1),
            .slots = slots,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.slots) |s| s.load(.Monotonic).release();
    }

    pub fn registerShred(
        self: *Self,
        slot: Slot,
        shred_index: u64,
    ) !void {
        try self.rotate();
        _ = self.max_slot_seen.fetchMax(slot, .Monotonic);
        const monitored_slot = try self.getSlot(slot);
        defer monitored_slot.release();
        try monitored_slot.record(shred_index);
    }

    // TODO make use of this
    pub fn setLastShred(self: *Self, slot: Slot, index: usize) !void {
        const monitored_slot = try self.getSlot(slot);
        defer monitored_slot.release();
        monitored_slot.setLastShred(index);
    }

    pub fn identifyMissing(self: *Self, allocator: Allocator) !MultiSlotReport {
        var found_bad = false;
        var slot_reports = ArrayList(SlotReport).init(allocator);
        const max_slot_seen = self.max_slot_seen.load(.Monotonic);
        for (self.good_until.load(.Monotonic)..max_slot_seen + 1) |slot| {
            const monitored_slot = try self.getSlot(slot);
            defer monitored_slot.release();
            const missing_shreds = try monitored_slot.identifyMissing(allocator);
            if (missing_shreds.items.len > 0) {
                found_bad = true;
                try slot_reports.append(.{ .slot = slot, .missing_shreds = missing_shreds });
            }
            if (!found_bad) {
                const old = self.good_until.fetchMax(slot, .Monotonic);
                if (old != slot) {
                    // TODO remove this
                    std.debug.print("finished slot: {}\n", .{old});
                }
            }
        }
        var last_one = ArrayList(Range).init(allocator);
        try last_one.append(.{ .start = 0, .end = null });
        try slot_reports.append(.{ .slot = max_slot_seen + 1, .missing_shreds = last_one });
        return .{ .reports = slot_reports };
    }

    fn getSlot(self: *Self, slot: Slot) error{ SlotUnderflow, SlotOverflow }!*MonitoredSlot {
        const slot_index = (slot - self.start_slot) % num_slots;
        if (slot > self.last_slot.load(.Acquire)) {
            return error.SlotOverflow;
        }
        const the_slot = self.slots[slot_index].load(.Acquire);
        if (slot < self.first_slot.load(.Monotonic)) {
            return error.SlotUnderflow;
        }
        return the_slot.acquire() catch {
            return error.SlotUnderflow;
        };
    }

    fn rotate(self: *Self) !void {
        if (!self.rotation_lock.tryLock()) return;
        defer self.rotation_lock.unlock();

        const good_until = self.good_until.load(.Monotonic);
        for (self.first_slot.load(.Monotonic)..self.last_slot.load(.Monotonic)) |slot_num| {
            var slot = &self.slots[slot_num % num_slots];
            if (good_until <= slot_num) { // TODO off by one?
                break;
            }
            _ = self.first_slot.fetchAdd(1, .Monotonic);
            const new_slot = try MonitoredSlot.init(self.allocator);
            slot.swap(new_slot, .Monotonic).release();
            _ = self.last_slot.fetchAdd(1, .Monotonic);
        }
    }
};

pub const MultiSlotReport = struct {
    reports: ArrayList(SlotReport),

    pub fn deinit(self: @This()) void {
        for (self.reports.items) |report| {
            report.missing_shreds.deinit();
        }
        self.reports.deinit();
    }
};

pub const SlotReport = struct {
    slot: Slot,
    missing_shreds: ArrayList(Range),
};

pub const Range = struct {
    start: usize,
    end: ?usize,
};

/// This is reference counted.
/// Do not use without calling acquire first.
/// Call release when done with a particular usage.
const MonitoredSlot = struct {
    allocator: Allocator,
    refcount: ReferenceCounter = .{},
    shreds: AtomicBitArray(MAX_SHREDS_PER_SLOT) = .{},
    max_seen: Atomic(usize) = Atomic(usize).init(0),
    last_shred: Atomic(usize) = Atomic(usize).init(unknown),

    const unknown = std.math.maxInt(usize);

    const Self = @This();

    pub fn init(allocator: Allocator) !*Self {
        var self = try allocator.create(Self);
        self.* = .{ .allocator = allocator };
        return self;
    }

    pub fn acquire(self: *Self) !*Self {
        if (self.refcount.acquire()) {
            return self;
        }
        return error.Destroyed;
    }

    pub fn release(self: *Self) void {
        if (self.refcount.release()) {
            self.allocator.destroy(self);
        }
    }

    // TODO: can all these be unordered?
    pub fn record(self: *Self, shred_index: usize) !void {
        try self.shreds.set(shred_index, .Monotonic);
        _ = self.max_seen.fetchMax(shred_index, .Monotonic);
    }

    // TODO make use of this
    pub fn setLastShred(self: *Self, value: usize) void {
        self.last_shred.store(value, .Monotonic);
    }

    pub fn identifyMissing(self: *Self, allocator: Allocator) !ArrayList(Range) {
        var missing_windows = ArrayList(Range).init(allocator);
        var gap_start: ?usize = null;
        const last_shred = self.last_shred.load(.Monotonic);
        const max_seen = self.max_seen.load(.Monotonic);
        for (0..max_seen + 2) |i| {
            if (self.shreds.get(i, .Monotonic) catch unreachable) {
                if (gap_start) |start| {
                    try missing_windows.append(.{ .start = start, .end = i });
                    gap_start = null;
                }
            } else if (gap_start == null) {
                gap_start = i;
            }
        }
        if (max_seen < last_shred) {
            const start = if (gap_start) |x| x else max_seen; // TODO is this redundant?
            const end = if (last_shred == unknown) null else last_shred;
            try missing_windows.append(.{ .start = start, .end = end });
        }
        return missing_windows;
    }
};

test "tvu.shred_tracker: trivial happy path" {
    const allocator = std.testing.allocator;

    var tracker = try BasicShredTracker.init(allocator, 13579);
    defer tracker.deinit();

    const output = try tracker.identifyMissing(allocator);
    defer output.deinit();

    try std.testing.expect(1 == output.reports.items.len);
    const report = output.reports.items[0];
    try std.testing.expect(13579 == report.slot);
    try std.testing.expect(1 == report.missing_shreds.items.len);
    try std.testing.expect(0 == report.missing_shreds.items[0].start);
    try std.testing.expect(null == report.missing_shreds.items[0].end);
}

test "tvu.shred_tracker: 1 registered shred is identified" {
    const allocator = std.testing.allocator;

    var tracker = try BasicShredTracker.init(allocator, 13579);
    defer tracker.deinit();
    try tracker.registerShred(13579, 123);

    const output = try tracker.identifyMissing(allocator);
    defer output.deinit();

    try std.testing.expect(1 == output.reports.items.len);
    const report = output.reports.items[0];
    try std.testing.expect(13579 == report.slot);
    try std.testing.expect(2 == report.missing_shreds.items.len);
    try std.testing.expect(0 == report.missing_shreds.items[0].start);
    try std.testing.expect(123 == report.missing_shreds.items[0].end);
    try std.testing.expect(124 == report.missing_shreds.items[1].start);
    try std.testing.expect(null == report.missing_shreds.items[1].end);
}
