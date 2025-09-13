const std = @import("std");
const sig = @import("../sig.zig");

const HashMap = std.AutoArrayHashMapUnmanaged;

const RingBitSet = sig.utils.collections.RingBitSet;
const Slot = sig.core.Slot;

pub const Ancestors = struct {
    ancestors: RingBitSet(MAX_SLOT_RANGE),

    pub const EMPTY: Ancestors = .{ .ancestors = .empty };

    /// The maximum allowed distance from the highest to lowest contained slot.
    pub const MAX_SLOT_RANGE = 256;

    pub fn fromMap(map: *const HashMap(Slot, usize)) error{Underflow}!Ancestors {
        var set = RingBitSet(MAX_SLOT_RANGE).empty;
        for (map.keys()) |slot| try set.set(slot);
        return .{ .ancestors = set };
    }

    pub fn addSlot(self: *Ancestors, slot: Slot) error{Underflow}!void {
        try self.ancestors.set(slot);
    }

    pub fn removeSlot(self: *Ancestors, slot: Slot) void {
        self.ancestors.unset(slot);
    }

    pub fn containsSlot(self: *const Ancestors, slot: Slot) bool {
        return self.ancestors.isSet(slot);
    }

    pub fn count(self: *const Ancestors) usize {
        return self.ancestors.count();
    }

    pub const Iterator = RingBitSet(MAX_SLOT_RANGE).Iterator;

    pub fn iterator(self: *const Ancestors) Iterator {
        return self.ancestors.iterator();
    }
};
