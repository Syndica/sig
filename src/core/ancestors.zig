const std = @import("std");
const sig = @import("../sig.zig");

const HashMap = std.AutoArrayHashMapUnmanaged;

const bincode = sig.bincode;
const Slot = sig.core.Slot;

pub const Ancestors = struct {
    // agave uses a "RollingBitField" which seems to be just an optimisation for a set
    ancestors: HashMap(Slot, void) = .{},

    // For some reason, agave serializes Ancestors as HashMap(slot, usize). But deserializing
    // ignores the usize, and serializing just uses the value 0. So we need to serialize void
    // as if it's 0, and deserialize 0 as if it's void.
    pub const @"!bincode-config:ancestors" = bincode.hashmap.hashMapFieldConfig(
        HashMap(Slot, void),
        .{
            .key = .{},
            .value = .{ .serializer = voidSerialize, .deserializer = voidDeserialize },
        },
    );

    pub const EMPTY: Ancestors = .{ .ancestors = .empty };

    pub fn deinit(self: Ancestors, allocator: std.mem.Allocator) void {
        var ancestors = self.ancestors;
        ancestors.deinit(allocator);
    }

    pub fn initWithSlots(
        allocator: std.mem.Allocator,
        slots: []const Slot,
    ) std.mem.Allocator.Error!Ancestors {
        var new: Ancestors = .EMPTY;
        errdefer new.deinit(allocator);
        try new.ancestors.ensureTotalCapacity(allocator, slots.len);
        for (slots) |slot| new.addSlotAssumeCapacity(slot);
        return new;
    }

    pub fn addSlot(
        self: *Ancestors,
        allocator: std.mem.Allocator,
        slot: Slot,
    ) std.mem.Allocator.Error!void {
        try self.ancestors.ensureUnusedCapacity(allocator, 1);
        self.addSlotAssumeCapacity(slot);
    }

    pub fn addSlotAssumeCapacity(
        self: *Ancestors,
        slot: Slot,
    ) void {
        self.ancestors.putAssumeCapacity(slot, {});
    }

    pub fn containsSlot(self: *const Ancestors, slot: Slot) bool {
        return self.ancestors.contains(slot);
    }

    fn voidDeserialize(l: *bincode.LimitAllocator, reader: anytype, params: bincode.Params) !void {
        _ = try bincode.readWithLimit(l, usize, reader, params);
    }

    fn voidSerialize(writer: anytype, data: anytype, params: bincode.Params) !void {
        _ = data;
        try bincode.write(writer, @as(usize, 0), params);
    }

    pub fn clone(self: *const Ancestors, allocator: std.mem.Allocator) !Ancestors {
        return .{ .ancestors = try self.ancestors.clone(allocator) };
    }

    pub fn subsetInto(
        self: *const Ancestors,
        max_slot: Slot,
        allocator: std.mem.Allocator,
        subset_result: *Ancestors,
    ) std.mem.Allocator.Error!void {
        subset_result.ancestors.clearRetainingCapacity();
        try subset_result.ancestors.ensureTotalCapacity(allocator, self.ancestors.count());
        for (self.ancestors.keys()) |slot| {
            if (slot > max_slot) continue;
            subset_result.addSlotAssumeCapacity(slot);
        }
    }

    // TODO: The need for this function will go away when the Ancestors set is converted
    // into a bitset-based data structure. For now, we need to cleanup the ancestors and
    // ensure it is never longer than Unrooted.MAX_SLOTS. If it becomes longer than that,
    // when we iterate over the ancestors for performing unrooted get()s, we will wrap
    // around and start getting funky behaviour.
    pub fn cleanup(self: *Ancestors) void {
        if (self.ancestors.count() >= sig.accounts_db.Two.Unrooted.MAX_SLOTS) {
            self.ancestors.orderedRemoveAt(0);
        }
    }
};
