const std = @import("std");
const sig = @import("../lib.zig");

const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const Mutex = std.Thread.Mutex;

const Slot = sig.core.Slot;
const Shred = sig.tvu.Shred;

const MAX_SHREDS_PER_SLOT: usize = sig.tvu.MAX_SHREDS_PER_SLOT;

pub const Range = struct {
    start: usize,
    end: ?usize,
};

pub const BasicShredTracker = struct {
    allocator: Allocator,
    logger: sig.trace.Logger,
    mux: Mutex = .{},
    /// The slot that this struct was initialized with at index 0
    start_slot: Slot,
    /// The oldest slot still being tracked, which hasn't yet been finished
    current_bottom_slot: Slot,
    /// The highest slot for which a shred has been received and processed successfully.
    max_slot_seen: Slot,
    /// ring buffer
    slots: [num_slots]MonitoredSlot = .{.{}} ** num_slots,

    const num_slots: usize = 1024;

    const Self = @This();

    pub fn init(
        allocator: Allocator,
        slot: Slot,
        logger: sig.trace.Logger,
    ) !*Self {
        const self = try allocator.create(Self);
        self.* = .{
            .allocator = allocator,
            .start_slot = slot,
            .current_bottom_slot = slot,
            .max_slot_seen = slot -| 1,
            .logger = logger,
        };
        return self;
    }

    pub fn deinit(self: *Self) void {
        self.allocator.destroy(self);
    }

    pub fn registerShred(
        self: *Self,
        slot: Slot,
        shred_index: u64,
    ) !void {
        self.mux.lock();
        defer self.mux.unlock();

        const monitored_slot = try self.getSlot(slot);
        const new = try monitored_slot.record(shred_index);
        if (new) self.logger.debugf("new slot: {}", .{slot});
        self.max_slot_seen = @max(self.max_slot_seen, slot);
    }

    pub fn setLastShred(self: *Self, slot: Slot, index: usize) !void {
        self.mux.lock();
        defer self.mux.unlock();

        const monitored_slot = try self.getSlot(slot);
        if (monitored_slot.last_shred) |old_last| {
            monitored_slot.last_shred = @min(old_last, index);
        } else {
            monitored_slot.last_shred = index;
        }
    }

    pub fn identifyMissing(self: *Self, slot_reports: *MultiSlotReport) !void {
        self.mux.lock();
        defer self.mux.unlock();

        var found_an_incomplete_slot = false;
        slot_reports.clearRetainingCapacity();
        const timestamp = std.time.milliTimestamp();
        const last_slot_to_check = @max(self.max_slot_seen, self.current_bottom_slot);
        for (self.current_bottom_slot..last_slot_to_check + 1) |slot| {
            const monitored_slot = try self.getSlot(slot);
            if (monitored_slot.first_received_timestamp_ms + 1000 > timestamp) {
                continue;
            }
            var slot_report = try slot_reports.addOne();
            slot_report.slot = slot;
            try monitored_slot.identifyMissing(&slot_report.missing_shreds);
            if (slot_report.missing_shreds.items.len > 0) {
                found_an_incomplete_slot = true;
            } else {
                slot_reports.drop(1);
            }
            if (!found_an_incomplete_slot) {
                self.logger.debugf("finished slot: {}", .{slot});
                self.current_bottom_slot = @max(self.current_bottom_slot, slot + 1);
                monitored_slot.* = .{};
            }
        }
    }

    fn getSlot(self: *Self, slot: Slot) error{ SlotUnderflow, SlotOverflow }!*MonitoredSlot {
        if (slot > self.current_bottom_slot + num_slots - 1) {
            return error.SlotOverflow;
        }
        if (slot < self.current_bottom_slot) {
            return error.SlotUnderflow;
        }
        const slot_index = (slot - self.start_slot) % num_slots;
        return &self.slots[slot_index];
    }
};

pub const MultiSlotReport = sig.utils.RecyclingList(
    SlotReport,
    SlotReport.initBlank,
    SlotReport.reset,
    SlotReport.deinit,
);

pub const SlotReport = struct {
    slot: Slot,
    missing_shreds: ArrayList(Range),

    fn initBlank(allocator: Allocator) SlotReport {
        return .{
            .slot = undefined,
            .missing_shreds = ArrayList(Range).init(allocator),
        };
    }

    fn deinit(self: SlotReport) void {
        self.missing_shreds.deinit();
    }

    fn reset(self: *SlotReport) void {
        self.missing_shreds.clearRetainingCapacity();
    }
};

const ShredSet = std.bit_set.ArrayBitSet(usize, MAX_SHREDS_PER_SLOT / 10);

const MonitoredSlot = struct {
    shreds: ShredSet = ShredSet.initEmpty(),
    max_seen: ?usize = null,
    last_shred: ?usize = null,
    first_received_timestamp_ms: i64 = 0,

    const Self = @This();

    pub fn record(self: *Self, shred_index: usize) !bool {
        self.shreds.set(shred_index);
        if (self.max_seen == null) {
            self.max_seen = shred_index;
            self.first_received_timestamp_ms = std.time.milliTimestamp();
            return true;
        }
        self.max_seen = @max(self.max_seen.?, shred_index);
        return false;
    }

    pub fn identifyMissing(self: *Self, missing_shreds: *ArrayList(Range)) !void {
        missing_shreds.clearRetainingCapacity();
        const highest_shred_to_check = self.last_shred orelse self.max_seen orelse 0;
        var gap_start: ?usize = null;
        for (0..highest_shred_to_check + 1) |i| {
            if (self.shreds.isSet(i)) {
                if (gap_start) |start| {
                    try missing_shreds.append(.{ .start = start, .end = i });
                    gap_start = null;
                }
            } else if (gap_start == null) {
                gap_start = i;
            }
        }
        if (self.last_shred == null or self.max_seen == null) {
            try missing_shreds.append(.{ .start = 0, .end = null });
        } else if (self.max_seen.? < self.last_shred.?) {
            try missing_shreds.append(.{ .start = self.max_seen.? + 1, .end = self.last_shred });
        }
    }
};

test "tvu.shred_tracker2: trivial happy path" {
    const allocator = std.testing.allocator;

    var msr = MultiSlotReport.init(allocator);
    defer msr.deinit();

    var tracker = try BasicShredTracker.init(allocator, 13579);
    defer tracker.deinit();

    try tracker.identifyMissing(&msr);

    try std.testing.expect(1 == msr.reports.items.len);
    const report = msr.reports.items[0];
    try std.testing.expect(13579 == report.slot);
    try std.testing.expect(1 == report.missing_shreds.items.len);
    try std.testing.expect(0 == report.missing_shreds.items[0].start);
    try std.testing.expect(null == report.missing_shreds.items[0].end);
}

test "tvu.shred_tracker2: 1 registered shred is identified" {
    const allocator = std.testing.allocator;

    var msr = MultiSlotReport.init(allocator);
    defer msr.deinit();

    var tracker = try BasicShredTracker.init(allocator, 13579);
    defer tracker.deinit();
    try tracker.registerShred(13579, 123);
    std.time.sleep(210 * std.time.ns_per_ms);

    try tracker.identifyMissing(&msr);

    try std.testing.expect(1 == msr.len);
    const report = msr.reports.items[0];
    try std.testing.expect(13579 == report.slot);
    try std.testing.expect(2 == report.missing_shreds.items.len);
    try std.testing.expect(0 == report.missing_shreds.items[0].start);
    try std.testing.expect(123 == report.missing_shreds.items[0].end);
    try std.testing.expect(124 == report.missing_shreds.items[1].start);
    try std.testing.expect(null == report.missing_shreds.items[1].end);
}
