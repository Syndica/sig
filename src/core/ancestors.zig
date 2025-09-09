const std = @import("std");
const sig = @import("../sig.zig");

const HashMap = std.AutoArrayHashMapUnmanaged;

const bincode = sig.bincode;

const RingBitSet = sig.utils.collections.RingBitSet;
const Slot = sig.core.Slot;

pub const Ancestors = struct {
    ancestors: RingBitSet(MAX_SLOT_RANGE),

    pub const EMPTY: Ancestors = .{ .ancestors = .empty };

    /// The maximum allowed distance from the highest to lowest contained slot.
    pub const MAX_SLOT_RANGE = 256;

    /// For some reason, agave serializes Ancestors as HashMap(slot, usize). But deserializing
    /// ignores the usize, and serializing just uses the value 0. So we need to serialize void
    /// as if it's 0, and deserialize 0 as if it's void.
    pub const @"!bincode-config:ancestors" = bincode.FieldConfig(RingBitSet(MAX_SLOT_RANGE)){
        .serializer = serialize,
        .deserializer = deserialize,
    };

    pub fn addSlot(self: *Ancestors, slot: Slot) error{Underflow}!void {
        try self.ancestors.set(slot);
    }

    pub fn removeSlot(self: *Ancestors, slot: Slot) void {
        self.ancestors.unset(slot);
    }

    pub fn containsSlot(self: *const Ancestors, slot: Slot) bool {
        return self.ancestors.isSet(slot);
    }

    pub const Iterator = RingBitSet(MAX_SLOT_RANGE).Iterator;

    pub fn iterator(self: *const Ancestors) Iterator {
        return self.ancestors.iterator();
    }

    fn deserialize(
        l: *bincode.LimitAllocator,
        reader: anytype,
        params: bincode.Params,
    ) anyerror!RingBitSet(MAX_SLOT_RANGE) {
        const deserialized = try bincode.readWithLimit(l, HashMap(Slot, usize), reader, params);
        defer bincode.free(l.allocator(), deserialized);
        var set = RingBitSet(MAX_SLOT_RANGE).empty;
        for (deserialized.keys()) |slot| {
            try set.set(slot);
        }
        return set;
    }

    fn serialize(writer: anytype, data: anytype, params: bincode.Params) anyerror!void {
        var map = HashMap(Slot, usize){};
        defer map.deinit(std.heap.c_allocator); // TODO: change this
        var iter = data.iterator();
        while (iter.next()) |slot| {
            try map.put(std.heap.c_allocator, slot, 0);
        }
        try bincode.write(writer, map, params);
    }
};
