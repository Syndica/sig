const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;

const Epoch = sig.core.Epoch;
const EpochConstants = sig.core.EpochConstants;
const EpochSchedule = sig.core.EpochSchedule;
const Slot = sig.core.Slot;
const SlotConstants = sig.core.SlotConstants;
const SlotState = sig.core.SlotState;

/// Central registry that tracks high-level info about slots and how they fork.
///
/// This is a lean version of `BankForks` from agave, focused on storing the
/// minimal information about slots to serve its core focus, rather than the
/// kitchen-sink style approach of storing everything under the sun.
///
/// [BankForks](https://github.com/anza-xyz/agave/blob/161fc1965bdb4190aa2d7e36c7c745b4661b10ed/runtime/src/bank_forks.rs#L75)
///
/// This struct is *not* thread safe, and the lifetimes of the returned pointers
/// will end as soon as the items are removed.
pub const SlotTracker = struct {
    slots: std.AutoArrayHashMapUnmanaged(Slot, *Element),
    root: Slot,

    const Element = struct {
        constants: SlotConstants,
        state: SlotState,
    };

    const Reference = struct {
        constants: *const SlotConstants,
        state: *SlotState,
    };

    pub fn init(root_slot: Slot) SlotTracker {
        return .{
            .slots = .empty,
            .root = root_slot,
        };
    }

    pub fn deinit(self: SlotTracker, allocator: Allocator) void {
        var slots = self.slots;
        for (slots.values()) |v| allocator.destroy(v);
        slots.deinit(allocator);
    }

    pub fn put(
        self: *SlotTracker,
        allocator: Allocator,
        slot: Slot,
        constants: SlotConstants,
        state: SlotState,
    ) !void {
        try self.slots.ensureUnusedCapacity(allocator, 1);
        const elem = try allocator.create(Element);
        elem.* = .{ .constants = constants, .state = state };
        self.slots.putAssumeCapacity(slot, elem);
    }

    pub fn get(self: *const SlotTracker, slot: Slot) ?Reference {
        const elem = self.slots.get(slot) orelse return null;
        return .{
            .constants = &elem.constants,
            .state = &elem.state,
        };
    }

    pub fn contains(self: *const SlotTracker, slot: Slot) bool {
        return self.slots.contains(slot);
    }

    pub fn activeSlots(
        self: *const SlotTracker,
        allocator: Allocator,
    ) Allocator.Error![]const Slot {
        var list = try std.ArrayListUnmanaged(Slot).initCapacity(allocator, self.slots.count());
        for (self.slots.keys(), self.slots.values()) |slot, value| {
            if (!value.state.isFrozen()) {
                list.appendAssumeCapacity(slot);
            }
        }
        return try list.toOwnedSlice(allocator);
    }

    pub fn frozenSlots(
        self: *const SlotTracker,
        allocator: Allocator,
    ) Allocator.Error!std.AutoArrayHashMapUnmanaged(Slot, Reference) {
        var frozen_slots = std.AutoArrayHashMapUnmanaged(Slot, Reference).empty;
        try frozen_slots.ensureTotalCapacity(allocator, self.slots.count());
        for (self.slots.keys(), self.slots.values()) |slot, value| {
            if (value.state.isFrozen()) {
                frozen_slots.putAssumeCapacity(slot, .{
                    .constants = &value.constants,
                    .state = &value.state,
                });
            }
        }
        return frozen_slots;
    }

    pub fn parents(
        self: *const SlotTracker,
        allocator: Allocator,
        slot: Slot,
    ) Allocator.Error![]const Slot {
        var parents_list = std.ArrayListUnmanaged(Slot).empty;
        errdefer parents_list.deinit(allocator);

        // Parent list count cannot be more than the self.slots count.
        try parents_list.ensureTotalCapacity(allocator, self.slots.count());

        var current_slot = slot;
        while (self.slots.get(current_slot)) |current| {
            const parent_slot = current.constants.parent_slot;
            parents_list.appendAssumeCapacity(parent_slot);

            current_slot = parent_slot;
        }

        return try parents_list.toOwnedSlice(allocator);
    }

    /// Analogous to [prune_non_rooted](https://github.com/anza-xyz/agave/blob/441258229dfed75e45be8f99c77865f18886d4ba/runtime/src/bank_forks.rs#L591)
    //  TODO Revisit: Currently this removes all slots less than the rooted slot.
    // In Agave, only the slots not in the root path are removed.
    pub fn pruneNonRooted(self: *SlotTracker, allocator: Allocator) void {
        var slice = self.slots.entries.slice();
        var index: usize = 0;
        while (index < slice.len) {
            if (slice.items(.key)[index] < self.root) {
                allocator.destroy(slice.items(.value)[index]);
                self.slots.swapRemoveAt(index);
                slice = self.slots.entries.slice();
            } else {
                index += 1;
            }
        }
    }
};

pub const EpochTracker = struct {
    epochs: std.AutoArrayHashMapUnmanaged(Epoch, EpochConstants) = .{},
    schedule: EpochSchedule,

    pub fn deinit(self: EpochTracker, allocator: Allocator) void {
        var epochs = self.epochs;
        for (epochs.values()) |ec| ec.deinit(allocator);
        epochs.deinit(allocator);
    }

    pub fn getForSlot(self: *const EpochTracker, slot: Slot) ?EpochConstants {
        return self.epochs.get(self.schedule.getEpoch(slot));
    }

    /// lifetime ends as soon as the map is modified
    pub fn getPtrForSlot(self: *const EpochTracker, slot: Slot) ?*const EpochConstants {
        return self.epochs.getPtr(self.schedule.getEpoch(slot));
    }
};

test "SlotTracker.prune removes all slots less than root" {
    const allocator = std.testing.allocator;
    const root = 4;
    var tracker = SlotTracker.init(root);
    defer tracker.deinit(allocator);

    // Add slots 1, 2, 3, 4, 5
    for (1..6) |i| {
        try tracker.put(
            allocator,
            i,
            sig.core.SlotConstants{
                .parent_slot = i - 1,
                .parent_hash = sig.core.Hash.ZEROES,
                .block_height = 0,
                .collector_id = sig.core.Pubkey.ZEROES,
                .max_tick_height = 0,
                .fee_rate_governor = sig.core.genesis_config.FeeRateGovernor.DEFAULT,
                .epoch_reward_status = .inactive,
                .ancestors = .{},
                .feature_set = .empty,
            },
            sig.core.SlotState.GENESIS,
        );
    }

    // Prune slots less than root (4)
    tracker.pruneNonRooted(allocator);

    // Only slots 4 and 5 should remain
    try std.testing.expect(tracker.contains(4));
    try std.testing.expect(tracker.contains(5));
    try std.testing.expect(!tracker.contains(1));
    try std.testing.expect(!tracker.contains(2));
    try std.testing.expect(!tracker.contains(3));
}
