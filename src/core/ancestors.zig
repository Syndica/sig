const std = @import("std");
const sig = @import("../sig.zig");

const HashMap = std.AutoArrayHashMapUnmanaged;

const bincode = sig.bincode;
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

/// A bit set that is allowed to progress forwards by setting bits out of bounds
/// and deleting old values, but not allowed to regress backwards.
pub fn RingBitSet(len: usize) type {
    return struct {
        /// underlying bit set
        inner: InnerSet,
        /// The lowest value represented
        bottom: usize,

        const InnerSet = std.bit_set.ArrayBitSet(usize, len);

        pub const empty = RingBitSet(len){
            .inner = .initEmpty(),
            .bottom = 0,
        };

        pub fn isSet(self: *const RingBitSet(len), index: usize) bool {
            if (index < self.bottom or index >= self.bottom + len) return false;
            return self.inner.isSet(index % len);
        }

        pub fn set(self: *RingBitSet(len), index: usize) error{Underflow}!void {
            if (index < self.bottom) return error.Underflow;
            if (index - self.bottom > len) {
                const wipe_start = self.bottom;
                self.bottom = 1 + index - len;
                const wipe_end = self.bottom;
                if (wipe_start % len > wipe_end % len) {
                    self.inner.setRangeValue(.{ .start = wipe_start % len, .end = len }, false);
                    self.inner.setRangeValue(.{ .start = 0, .end = wipe_end % len }, false);
                } else {
                    self.inner.setRangeValue(
                        .{ .start = wipe_start % len, .end = wipe_end % len },
                        false,
                    );
                }
            }
            self.inner.set(index % len);
        }

        pub fn unset(self: *RingBitSet(len), index: usize) void {
            if (index < self.bottom or index >= self.bottom + len) return;
            return self.inner.unset(index % len);
        }

        pub fn count(self: *const RingBitSet(len)) usize {
            return self.inner.count();
        }

        pub const Iterator = struct {
            inner: InnerSet.Iterator(.{}),
            bottom: usize,

            pub fn next(self: *Iterator) ?usize {
                if (self.inner.next()) |item| {
                    return if (item < self.bottom % len)
                        item + self.bottom - len
                    else
                        item + self.bottom;
                }
                return null;
            }
        };

        /// items are not sorted
        pub fn iterator(self: *const RingBitSet(len)) Iterator {
            return .{
                .inner = self.inner.iterator(.{}),
                .bottom = self.bottom,
            };
        }
    };
}
