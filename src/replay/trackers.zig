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
        var list = std.ArrayListUnmanaged(Slot){};
        var iter = self.slots.iterator();
        while (iter.next()) |entry| {
            if (!entry.value_ptr.*.state.isFrozen()) {
                try list.append(allocator, entry.key_ptr.*);
            }
        }
        return try list.toOwnedSlice(allocator);
    }

    pub fn frozenSlots(
        self: *const SlotTracker,
        allocator: Allocator,
    ) Allocator.Error!std.AutoArrayHashMapUnmanaged(Slot, Reference) {
        var frozen_slots = std.AutoArrayHashMapUnmanaged(Slot, Reference).empty;
        var iter = self.slots.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.*.state.isFrozen()) {
                try frozen_slots.put(allocator, entry.key_ptr.*, .{
                    .constants = &entry.value_ptr.*.constants,
                    .state = &entry.value_ptr.*.state,
                });
            }
        }
        return frozen_slots;
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
