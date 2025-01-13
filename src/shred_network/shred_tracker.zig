const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const Mutex = std.Thread.Mutex;

const Gauge = sig.prometheus.Gauge;
const Registry = sig.prometheus.Registry;
const Slot = sig.core.Slot;

const MAX_SHREDS_PER_SLOT: usize = sig.ledger.shred.MAX_SHREDS_PER_SLOT;

const MIN_SLOT_AGE_TO_REPORT_AS_MISSING: u64 = 600;

pub const Range = struct {
    start: usize,
    end: ?usize,
};

/// This is a temporary placeholder that will be replaced by a solution that
/// depends on the ledger and consensus. This struct optimistically discards
/// slots that another slot claims to be skipped, even if consensus has not yet
/// rooted that slot. This is necessary to keep up with turbine while consensus
/// is not yet implemented. A complete implementation in the future should
/// continue pursuing missing shreds unless a later slot is rooted.
pub const BasicShredTracker = struct {
    logger: sig.trace.ScopedLogger(@typeName(Self)),
    mux: Mutex = .{},
    /// The slot that this struct was initialized with at index 0
    start_slot: ?Slot,
    /// The oldest slot still being tracked, which hasn't yet been finished
    current_bottom_slot: Slot,
    /// The highest slot for which a shred has been received and processed successfully.
    max_slot_processed: Slot,
    /// The highest slot that has been seen at all.
    max_slot_seen: Slot,
    /// ring buffer
    slots: [num_slots]MonitoredSlot = .{.{}} ** num_slots,
    metrics: Metrics,

    const num_slots: usize = 1024;

    const Metrics = struct {
        finished_slots_through: *Gauge(u64),
        max_slot_processed: *Gauge(u64),

        pub const prefix = "shred_tracker";
    };

    const Self = @This();

    pub fn init(slot: Slot, logger: sig.trace.Logger, registry: *Registry(.{})) !Self {
        const metrics = try registry.initStruct(Metrics);
        metrics.finished_slots_through.set(slot);
        metrics.max_slot_processed.set(slot);
        return .{
            .start_slot = slot,
            .current_bottom_slot = slot,
            .max_slot_processed = slot,
            .max_slot_seen = slot,
            .logger = logger.withScope(@typeName(Self)),
            .metrics = try registry.initStruct(Metrics),
        };
    }

    pub fn registerDataShred(
        self: *Self,
        shred: *const sig.ledger.shred.DataShred,
    ) !void {
        const parent = try shred.parent();
        const is_last_in_slot = shred.custom.flags.isSet(.last_shred_in_slot);
        const slot = shred.common.slot;
        const index = shred.common.index;
        try self.registerShred(slot, index, parent, is_last_in_slot);
    }

    pub fn registerShred(
        self: *Self,
        slot: Slot,
        shred_index: u64,
        parent_slot: Slot,
        is_last_in_slot: bool,
    ) SlotOutOfBounds!void {
        self.mux.lock();
        defer self.mux.unlock();

        const monitored_slot = try self.observeSlot(slot);
        const new = monitored_slot.record(shred_index);
        if (new) self.logger.debug().logf("new slot: {}", .{slot});
        if (slot > self.max_slot_processed) {
            self.max_slot_processed = slot;
            self.metrics.max_slot_processed.set(slot);
        }

        if (monitored_slot.parent_slot != null and monitored_slot.parent_slot != parent_slot) {
            self.logger.warn().logf(
                "parent conflict for slot {}. prior parent is {?}. index {} specifies parent {}",
                .{ slot, monitored_slot.parent_slot, shred_index, parent_slot },
            );
        }
        monitored_slot.parent_slot = parent_slot;

        // set last shred
        if (is_last_in_slot) if (monitored_slot.last_shred) |old_last| {
            monitored_slot.last_shred = @min(old_last, shred_index);
        } else {
            monitored_slot.last_shred = shred_index;
        };

        // identify skipped slots
        if (parent_slot + 1 != slot) {
            for (parent_slot + 1..slot) |slot_to_skip| {
                const monitored_slot_to_skip = self.observeSlot(slot_to_skip) catch continue;
                if (!monitored_slot_to_skip.is_complete) {
                    monitored_slot_to_skip.is_complete = true;
                    self.logger.info().logf("skipping slot: {}", .{slot_to_skip});
                    if (slot_to_skip > self.max_slot_processed) {
                        self.max_slot_processed = slot_to_skip;
                        self.metrics.max_slot_processed.set(slot_to_skip);
                    }
                }
            }
        }
    }

    /// Writes the contents of the monitored slots as progress bars.
    /// Returns the number of slots printed.
    pub fn print(self: *Self, writer: anytype) !Slot {
        const start = self.current_bottom_slot;
        const end = @max(self.max_slot_seen + 1, self.current_bottom_slot);
        var found_incomplete = false;
        for (start..end) |slot| {
            const monitored_slot = self.getMonitoredSlot(slot) catch break;
            if (monitored_slot.is_complete and !found_incomplete) {
                // the tracker may have some completed slots at the beginning
                // that it hasn't cleared yet.
                continue;
            }
            found_incomplete = true;
            try writer.print("slot {} (parent {?}): ", .{ slot, monitored_slot.parent_slot });
            if (monitored_slot.last_shred orelse monitored_slot.max_seen) |last_shred| {
                for (0..last_shred + 1) |index| {
                    if (monitored_slot.shreds.isSet(index)) {
                        try writer.print("█", .{});
                    } else {
                        try writer.print("🭹", .{});
                    }
                }
                if (monitored_slot.last_shred == null) {
                    try writer.print(" ???\n", .{});
                } else {
                    try writer.print(" END\n", .{});
                }
            } else if (monitored_slot.is_complete) {
                try writer.print("SKIPPED\n", .{});
            } else {
                try writer.print("EMPTY\n", .{});
            }
        }
        return end - start;
    }

    /// returns whether it makes sense to send any repair requests
    pub fn identifyMissing(
        self: *Self,
        slot_reports: *MultiSlotReport,
    ) (Allocator.Error || SlotOutOfBounds)!bool {
        if (self.start_slot == null) return false;
        self.mux.lock();
        defer self.mux.unlock();

        var found_an_incomplete_slot = false;
        slot_reports.clearRetainingCapacity();
        const timestamp = std.time.milliTimestamp();
        const last_slot_to_check = @max(self.max_slot_processed, self.current_bottom_slot);
        for (self.current_bottom_slot..last_slot_to_check + 1) |slot| {
            const monitored_slot = try self.getMonitoredSlot(slot);
            if (monitored_slot.first_received_timestamp_ms +
                MIN_SLOT_AGE_TO_REPORT_AS_MISSING > timestamp) //fix
            {
                continue;
            }
            var slot_report = try slot_reports.addOne();
            slot_report.slot = slot;
            try monitored_slot.identifyMissing(&slot_report.missing_shreds);
            if (slot_report.missing_shreds.items.len > 0) {
                found_an_incomplete_slot = true;
            }
            if (!found_an_incomplete_slot) {
                (if (slot % 20 == 0) self.logger.info() else self.logger.debug())
                    .logf("received all shreds up to slot {}", .{slot});
                self.setBottom(slot);
            }
        }
        return true;
    }

    /// assumes lock is held
    fn setBottom(self: *Self, slot: usize) void {
        for (self.current_bottom_slot..slot) |slot_to_wipe| {
            const monitored_slot = self.getMonitoredSlot(slot_to_wipe) catch unreachable;
            monitored_slot.* = .{};
        }
        self.current_bottom_slot = @max(self.current_bottom_slot, slot);
        self.metrics.finished_slots_through.max(slot -| 1);
    }

    /// - Record that a slot has been observed.
    /// - Acquire the slot's status for mutation.
    fn observeSlot(self: *Self, slot: Slot) SlotOutOfBounds!*MonitoredSlot {
        self.max_slot_seen = @max(self.max_slot_seen, slot);
        return try self.getMonitoredSlot(slot);
    }

    fn getMonitoredSlot(self: *Self, slot: Slot) SlotOutOfBounds!*MonitoredSlot {
        if (slot > self.current_bottom_slot + num_slots - 1) {
            return error.SlotOverflow;
        }
        if (slot < self.current_bottom_slot) {
            return error.SlotUnderflow;
        }
        const slot_index = (slot - self.start_slot.?) % num_slots;
        return &self.slots[slot_index];
    }
};

pub const MultiSlotReport = sig.utils.collections.RecyclingList(
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

pub const SlotOutOfBounds = error{ SlotUnderflow, SlotOverflow };

const MonitoredSlot = struct {
    shreds: ShredSet = ShredSet.initEmpty(),
    max_seen: ?usize = null,
    last_shred: ?usize = null,
    first_received_timestamp_ms: i64 = 0,
    is_complete: bool = false,
    parent_slot: ?Slot = null,

    const Self = @This();

    /// returns whether this is the first shred received for the slot
    pub fn record(self: *Self, shred_index: usize) bool {
        if (self.is_complete) return false;
        self.shreds.set(shred_index);
        if (self.max_seen == null) {
            self.max_seen = shred_index;
            self.first_received_timestamp_ms = std.time.milliTimestamp();
            return true;
        }
        self.max_seen = @max(self.max_seen.?, shred_index);
        return false;
    }

    pub fn identifyMissing(self: *Self, missing_shreds: *ArrayList(Range)) Allocator.Error!void {
        missing_shreds.clearRetainingCapacity();
        if (self.is_complete) return;
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
        if (missing_shreds.items.len == 0) {
            self.is_complete = true;
        }
    }
};

test "trivial happy path" {
    const allocator = std.testing.allocator;

    var msr = MultiSlotReport.init(allocator);
    defer msr.deinit();

    var tracker = try BasicShredTracker.init(13579, .noop, sig.prometheus.globalRegistry());

    _ = try tracker.identifyMissing(&msr);

    try std.testing.expect(1 == msr.len);
    const report = msr.items()[0];
    try std.testing.expect(13579 == report.slot);
    try std.testing.expect(1 == report.missing_shreds.items.len);
    try std.testing.expect(0 == report.missing_shreds.items[0].start);
    try std.testing.expect(null == report.missing_shreds.items[0].end);
}

test "1 registered shred is identified" {
    const allocator = std.testing.allocator;

    var msr = MultiSlotReport.init(allocator);
    defer msr.deinit();

    var tracker = try BasicShredTracker.init(13579, .noop, sig.prometheus.globalRegistry());
    try tracker.registerShred(13579, 123, 13578, false);
    std.time.sleep(210 * std.time.ns_per_ms);

    _ = try tracker.identifyMissing(&msr);

    try std.testing.expect(1 == msr.len);
    const report = msr.items()[0];
    try std.testing.expect(13579 == report.slot);
    try std.testing.expect(2 == report.missing_shreds.items.len);
    try std.testing.expect(0 == report.missing_shreds.items[0].start);
    try std.testing.expect(123 == report.missing_shreds.items[0].end);
    try std.testing.expect(0 == report.missing_shreds.items[1].start);
    try std.testing.expect(null == report.missing_shreds.items[1].end);
}
