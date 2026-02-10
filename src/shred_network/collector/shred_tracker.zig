const std = @import("std");
const sig = @import("../../sig.zig");

const Allocator = std.mem.Allocator;
const ArrayList = std.array_list.Managed;
const Mutex = std.Thread.Mutex;

const Duration = sig.time.Duration;
const Gauge = sig.prometheus.Gauge;
const Instant = sig.time.Instant;
const Registry = sig.prometheus.Registry;
const Slot = sig.core.Slot;

const assert = std.debug.assert;

const Logger = sig.trace.Logger("shred_tracker");

const MAX_SHREDS_PER_SLOT: usize = sig.ledger.shred.MAX_SHREDS_PER_SLOT;
const MIN_SLOT_AGE_TO_REPORT_AS_MISSING: Duration = Duration.fromMillis(600);

pub const Range = struct {
    start: u32,
    end: ?u32,
};

/// This is a temporary placeholder that will be replaced by a solution that
/// depends on the ledger and consensus. This struct optimistically discards
/// slots that another slot claims to be skipped, even if consensus has not yet
/// rooted that slot. This is necessary to keep up with turbine while consensus
/// is not yet implemented. A complete implementation in the future should
/// continue pursuing missing shreds unless a later slot is rooted.
///
/// This struct is over 8 MB so you should probably allocate memory on the heap
/// for it and pass it by pointer.
pub const BasicShredTracker = struct {
    logger: Logger,
    skip_checking_arena: std.heap.ArenaAllocator,
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
    slots: [num_slots]MonitoredSlot = @splat(.{}),
    metrics: Metrics,
    /// Whether to log when finished_slots_through is updated
    log_finished_slots: bool,

    const num_slots: usize = 1024;

    const Metrics = struct {
        finished_slots_through: *Gauge(u64),
        max_slot_processed: *Gauge(u64),

        pub const prefix = "shred_tracker";
    };

    const Self = @This();

    pub fn init(
        self: *BasicShredTracker,
        allocator: Allocator,
        slot: Slot,
        logger: Logger,
        registry: *Registry(.{}),
        log_finished_slots: bool,
    ) !void {
        const metrics = try registry.initStruct(Metrics);
        metrics.finished_slots_through.set(slot);
        metrics.max_slot_processed.set(slot);
        self.* = .{
            .start_slot = slot,
            .skip_checking_arena = .init(allocator),
            .current_bottom_slot = slot,
            .max_slot_processed = slot,
            .max_slot_seen = slot,
            .logger = logger,
            .metrics = metrics,
            .log_finished_slots = log_finished_slots,
        };
    }

    pub fn deinit(self: *const BasicShredTracker) void {
        self.skip_checking_arena.deinit();
    }

    pub const RegisterDataShredError = SlotOutOfBounds ||
        error{ InvalidShredIndex, InvalidShredParent, InvalidParentSlotOffset };

    pub fn registerDataShred(
        self: *Self,
        shred: *const sig.ledger.shred.DataShred,
        timestamp: Instant,
    ) RegisterDataShredError!void {
        const parent = try shred.parent();
        const is_last_in_slot = shred.custom.flags.isSet(.last_shred_in_slot);
        const slot = shred.common.slot;
        const index = shred.common.index;
        try self.registerShred(slot, index, parent, is_last_in_slot, timestamp);
    }

    fn registerShred(
        self: *Self,
        slot: Slot,
        shred_index: u32,
        parent_slot: Slot,
        is_last_in_slot: bool,
        timestamp: Instant,
    ) (SlotOutOfBounds || error{ InvalidShredIndex, InvalidShredParent })!void {
        if (parent_slot >= slot) return error.InvalidShredParent;
        if (shred_index >= sig.ledger.shred.DataShred.constants.max_per_slot)
            return error.InvalidShredIndex;

        self.mux.lock();
        defer self.mux.unlock();

        const monitored_slot = try self.observeSlot(slot);

        const slot_is_complete = monitored_slot
            .record(self.logger, shred_index, is_last_in_slot, timestamp);

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

        var new_bottom = self.current_bottom_slot;

        // identify skipped slots
        if (parent_slot + 1 != slot) {
            for (parent_slot + 1..slot) |slot_to_skip| {
                const monitored_slot_to_skip = self.observeSlot(slot_to_skip) catch continue;
                monitored_slot_to_skip.is_skipped = true;
            }
        }

        if (slot_is_complete and slot == new_bottom) new_bottom += 1;

        if (self.current_bottom_slot != new_bottom) self.setBottom(new_bottom);
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
            try writer.print("slot {} (parent {any}): ", .{ slot, monitored_slot.parent_slot });
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
        now: Instant,
    ) (Allocator.Error || SlotOutOfBounds)!bool {
        if (self.start_slot == null) return false;
        self.mux.lock();
        defer self.mux.unlock();

        var found_an_incomplete_slot = false;
        slot_reports.clearRetainingCapacity();
        const last_slot_to_check = @max(self.max_slot_processed, self.current_bottom_slot);
        for (self.current_bottom_slot..last_slot_to_check + 1) |slot| {
            const monitored_slot = try self.getMonitoredSlot(slot);

            var this_slot_needs_more_shreds = !monitored_slot.is_complete;
            defer {
                if (this_slot_needs_more_shreds) found_an_incomplete_slot = true;
                if (!found_an_incomplete_slot) self.setBottom(slot + 1);
            }

            if (monitored_slot.is_complete or
                now.elapsedSince(monitored_slot.first_received_timestamp)
                    .lt(MIN_SLOT_AGE_TO_REPORT_AS_MISSING))
                continue;

            if (try self.slotShouldBeSkipped(monitored_slot, slot, last_slot_to_check, now)) {
                this_slot_needs_more_shreds = false;
                continue;
            }

            const slot_report = try slot_reports.addOne();
            slot_report.slot = slot;
            try monitored_slot.identifyMissing(&slot_report.missing_shreds);
            if (monitored_slot.is_complete) {
                assert(slot_report.missing_shreds.items.len == 0);
                slot_reports.drop(1);
            }
        }

        return true;
    }

    /// assumes lock is held
    ///
    /// skip the slot if:
    /// - marked as skipped by another slot
    /// - there are at least 32 more slots we've received after this one
    /// - 80% of those are complete or skipped
    /// - it has been at least 10 seconds since we received any shreds for this
    ///   slot
    ///
    /// the implication is that we'll stop repairing this slot because the
    /// cluster has selected a fork that doesn't include the slot, and we won't
    /// ever be able to repair it.
    ///
    /// This is only a temporary solution to make repair slightly more
    /// fork-aware and handle the uncertainty of skipped slots more robustly.
    /// - in the long term, we should only skip slots that our own consensus
    ///   tells us to skip, and no others.
    /// - in the short term, maybe this can be optimized somehow to avoid so
    ///   much looping.
    fn slotShouldBeSkipped(
        self: *Self,
        slot_in_question: *MonitoredSlot,
        this_slot: Slot,
        top_slot: Slot,
        now: Instant,
    ) Allocator.Error!bool {
        const total_slots_tracked = top_slot -| this_slot;
        if (!slot_in_question.is_skipped or total_slots_tracked < 32)
            return false;

        const allocator = self.skip_checking_arena.allocator();
        defer _ = self.skip_checking_arena.reset(.retain_capacity);

        var forks = ForkForest.empty;
        defer forks.deinit(allocator);
        for (this_slot + 1..top_slot + 1) |slot_to_check| {
            const ms_to_check = self.getMonitoredSlot(slot_to_check) catch unreachable;
            if (ms_to_check.parent_slot) |parent| {
                try forks.append(allocator, slot_to_check, parent);
            }
        }

        return forks.hasFork(this_slot, 32) and
            now.elapsedSince(slot_in_question.last_unique_received_timestamp).asSecs() > 10;
    }

    /// assumes lock is held
    fn setBottom(self: *Self, slot: usize) void {
        for (self.current_bottom_slot..slot) |slot_to_wipe| {
            const monitored_slot = self.getMonitoredSlot(slot_to_wipe) catch unreachable;
            monitored_slot.* = .{};
        }
        self.current_bottom_slot = @max(self.current_bottom_slot, slot);
        self.metrics.finished_slots_through.max(slot -| 1);
        if (self.log_finished_slots) {
            self.logger.info().logf("tracked to slot: {}", .{slot -| 1});
        }
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

/// Contains multiple trees, where each tree may contain many forks.
pub const ForkForest = struct {
    /// Every single node
    nodes: List(*Node),
    /// A subset of the nodes that have no known parent. Each of these is the
    /// root of a separate tree in the forest.
    roots: List(*Node),

    pub const empty = ForkForest{ .roots = .empty, .nodes = .empty };

    const Node = struct {
        slot: Slot,
        parent: Slot,
        next: List(*Node),

        fn hasFork(self: *const Node, disallowed_slot: Slot, minimum_length: usize) bool {
            if (self.parent == disallowed_slot or self.slot == disallowed_slot) return false;
            if (minimum_length == 0) return true;
            for (self.next.items) |next| {
                if (next.hasFork(disallowed_slot, minimum_length - 1)) {
                    return true;
                }
            }
            return false;
        }
    };

    const List = std.ArrayListUnmanaged;

    pub fn deinit(const_self: ForkForest, allocator: Allocator) void {
        var self = const_self;
        for (self.nodes.items) |item| allocator.destroy(item);
        self.nodes.deinit(allocator);
        self.roots.deinit(allocator);
    }

    pub fn append(self: *ForkForest, allocator: Allocator, slot: Slot, parent: Slot) !void {
        const node = try allocator.create(Node);
        node.* = .{ .slot = slot, .parent = parent, .next = .{} };
        try self.nodes.append(allocator, node);
        for (self.nodes.items) |maybe_parent| {
            if (maybe_parent.slot == parent) {
                try maybe_parent.next.append(allocator, node);
                return;
            }
        }
        try self.roots.append(allocator, node);
    }

    /// Returns whether at least one fork exists with the requested properties:
    /// - there are at least minimum_length slots
    /// - disallowed_slot is known to be excluded from the fork
    pub fn hasFork(self: *const ForkForest, disallowed_slot: Slot, minimum_length: usize) bool {
        for (self.roots.items) |tree| {
            if (tree.hasFork(disallowed_slot, minimum_length)) return true;
        }
        return false;
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

const ShredSet = std.bit_set.ArrayBitSet(usize, MAX_SHREDS_PER_SLOT);

const bit_set = struct {
    pub fn setAndWasSet(self: *ShredSet, index: usize) bool {
        assert(index < ShredSet.bit_length);
        const mask_bit = maskBit(index);
        const mask_index = maskIndex(index);
        defer self.masks[mask_index] |= mask_bit;
        return self.masks[mask_index] & mask_bit != 0;
    }

    fn maskBit(index: usize) ShredSet.MaskInt {
        return @as(ShredSet.MaskInt, 1) << @as(ShredSet.ShiftInt, @truncate(index));
    }

    fn maskIndex(index: usize) usize {
        return index >> @bitSizeOf(ShredSet.ShiftInt);
    }
};

pub const SlotOutOfBounds = error{ SlotUnderflow, SlotOverflow };

const MonitoredSlot = struct {
    shreds: ShredSet = ShredSet.initEmpty(),
    max_seen: ?u32 = null,
    last_shred: ?u32 = null,
    first_received_timestamp: Instant = .EPOCH_ZERO,
    last_unique_received_timestamp: Instant = .EPOCH_ZERO,
    is_complete: bool = false,
    /// this just means we've identified that another slot that claims to be
    /// skipping this one. it doesn't mean this slot is definitely being skipped.
    is_skipped: bool = false,
    parent_slot: ?Slot = null,
    unique_observed_count: u32 = 0,

    const Self = @This();

    /// returns if the slot is *definitely* complete (there may be false negatives)
    fn record(
        self: *Self,
        logger: Logger,
        shred_index: u32,
        is_last_in_slot: bool,
        timestamp: Instant,
    ) bool {
        if (self.is_complete) return false;
        if (!bit_set.setAndWasSet(&self.shreds, shred_index)) {
            self.last_unique_received_timestamp = timestamp;
            self.unique_observed_count += 1;
        }

        if (is_last_in_slot) {
            if (self.last_shred) |old_last| {
                self.last_shred = @max(old_last, shred_index);
                if (shred_index != old_last) {
                    logger.err().log(
                        "The last shred index changed after already being set. " ++
                            "A leader might have produced a duplicate/invalid block for a slot",
                    );
                }
            } else {
                self.last_shred = shred_index;
            }
        }

        if (self.max_seen) |max_seen| {
            self.max_seen = @max(max_seen, shred_index);
        } else {
            self.max_seen = shred_index;
            self.first_received_timestamp = timestamp;
        }
        const max_seen = self.max_seen.?; // was just set above if null

        if (self.last_shred) |last| {
            assert(last <= max_seen);

            if (self.unique_observed_count == last + 1) {
                self.is_complete = true;
                return true;
            }
        }

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
                    try missing_shreds.append(.{ .start = @intCast(start), .end = @intCast(i) });
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

test "MonitoredSlot.record" {
    var monitor = MonitoredSlot{};
    _ = monitor.record(.noop, 10, true, Instant.now()); // last index
    _ = monitor.record(.noop, 0, true, Instant.now()); // invalid/mismatching last index
}

test "trivial happy path" {
    const allocator = std.testing.allocator;

    var msr = MultiSlotReport.init(allocator);
    defer msr.deinit();

    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();

    const tracker = try allocator.create(BasicShredTracker);
    defer allocator.destroy(tracker);
    try tracker.init(allocator, 13579, .noop, &registry, false);
    defer tracker.deinit();

    _ = try tracker.identifyMissing(&msr, Instant.EPOCH_ZERO.plus(Duration.fromSecs(1)));

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

    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();

    const tracker = try allocator.create(BasicShredTracker);
    defer allocator.destroy(tracker);
    try tracker.init(allocator, 13579, .noop, &registry, false);
    defer tracker.deinit();

    try tracker.registerShred(13579, 123, 13578, false, .EPOCH_ZERO);

    _ = try tracker.identifyMissing(&msr, .EPOCH_ZERO);
    try std.testing.expectEqual(0, msr.len);

    _ = try tracker.identifyMissing(&msr, Instant.EPOCH_ZERO.plus(Duration.fromSecs(1)));
    try std.testing.expectEqual(1, msr.len);

    const report = msr.items()[0];
    try std.testing.expect(13579 == report.slot);
    try std.testing.expect(2 == report.missing_shreds.items.len);
    try std.testing.expect(0 == report.missing_shreds.items[0].start);
    try std.testing.expect(123 == report.missing_shreds.items[0].end);
    try std.testing.expect(0 == report.missing_shreds.items[1].start);
    try std.testing.expect(null == report.missing_shreds.items[1].end);
}

test "slots are only skipped after a competing fork has developed sufficiently" {
    const allocator = std.testing.allocator;

    var msr = MultiSlotReport.init(allocator);
    defer msr.deinit();

    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();

    const tracker = try allocator.create(BasicShredTracker);
    defer allocator.destroy(tracker);
    try tracker.init(allocator, 1, .noop, &registry, false);
    defer tracker.deinit();

    const start = Instant.EPOCH_ZERO;

    // complete slots 1 and 3, where 3 skips 2.
    try tracker.registerShred(1, 0, 0, true, start);
    try tracker.registerShred(3, 0, 1, true, start);
    _ = try tracker.identifyMissing(&msr, start.plus(.fromSecs(11)));
    try std.testing.expectEqual(2, msr.items()[0].slot);

    // add shreds for many slots that are all separate forks. it should have no
    // effect on 2 being identified as missing. 2 will be considered missing
    // until ONE fork has at least 32 slots ahead of 2.
    for (4..100) |slot| {
        try tracker.registerShred(slot, 0, 3, false, start);
        _ = try tracker.identifyMissing(&msr, start.plus(.fromSecs(11)));
        try std.testing.expectEqual(2, msr.items()[0].slot);
    }

    // add 30 slots in a single fork, one less than we need to skip slot 2
    for (100..130) |slot| {
        try tracker.registerShred(slot, 0, slot - 1, false, start);
        // trying after 11 seconds have passed: it should still report slot 2 as
        // missing because not enough slots have passed
        _ = try tracker.identifyMissing(&msr, start.plus(.fromSecs(11)));
        try std.testing.expectEqual(2, msr.items()[0].slot);
    }

    // add shred for slot 130: now enough slots have passed, but we're going back
    // in time to prove that 2 will still be reported as missing until enough
    // time has passed.
    try tracker.registerShred(130, 0, 129, false, start);
    _ = try tracker.identifyMissing(&msr, start.plus(.fromSecs(9)));
    try std.testing.expectEqual(2, msr.items()[0].slot);

    // now 32 slots AND 10 seconds have passed, so we should be good to skip slot 2
    _ = try tracker.identifyMissing(&msr, start.plus(.fromSecs(11)));
    try std.testing.expectEqual(4, msr.items()[0].slot);
}

test "slots are not skipped when the current fork is developed" {
    const allocator = std.testing.allocator;

    var msr = MultiSlotReport.init(allocator);
    defer msr.deinit();

    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();

    const tracker = try allocator.create(BasicShredTracker);
    defer allocator.destroy(tracker);
    try tracker.init(allocator, 1, .noop, &registry, false);
    defer tracker.deinit();

    const start = Instant.EPOCH_ZERO;

    // complete slots 1 and 3, where 3 skips 2.
    try tracker.registerShred(1, 0, 0, true, start);
    try tracker.registerShred(3, 0, 2, true, start);
    _ = try tracker.identifyMissing(&msr, start.plus(.fromSecs(11)));
    try std.testing.expectEqual(2, msr.items()[0].slot);

    // add shreds for 96 slots continue to branch off 2. 2 should always be
    // considered missing even though more than 32 slots have passed, because we
    // need slot 2 to process this fork.
    for (4..100) |slot| {
        try tracker.registerShred(slot, 0, 3, false, start);
        _ = try tracker.identifyMissing(&msr, start.plus(.fromSecs(11)));
        try std.testing.expectEqual(2, msr.items()[0].slot);
    }
}
