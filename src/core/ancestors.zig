const std = @import("std");
const sig = @import("../sig.zig");

const HashMap = std.AutoArrayHashMapUnmanaged;

const bincode = sig.bincode;
const Slot = sig.core.Slot;

pub const Ancestors = struct {
    // agave uses a "RollingBitField" which seems to be just an optimisation for a set
    ancestors: Map = .{},

    pub const Map = HashMap(Slot, void);

    pub fn containsSlot(self: *const Ancestors, slot: Slot) bool {
        return self.ancestors.contains(slot);
    }

    // For some reason, agave serializes Ancestors as HashMap(slot, usize). But deserializing
    // ignores the usize, and serializing just uses the value 0. So we need to serialize void
    // as if it's 0, and deserialize 0 as if it's void.
    pub const @"!bincode-config:ancestors" = bincode.hashmap.hashMapFieldConfig(
        Map,
        .{
            .key = .{},
            .value = .{ .serializer = voidSerialize, .deserializer = voidDeserialize },
        },
    );

    fn voidDeserialize(alloc: std.mem.Allocator, reader: anytype, params: bincode.Params) !void {
        _ = try bincode.read(alloc, usize, reader, params);
    }

    fn voidSerialize(writer: anytype, data: anytype, params: bincode.Params) !void {
        _ = data;
        try bincode.write(writer, @as(usize, 0), params);
    }

    pub fn clone(self: *const Ancestors, allocator: std.mem.Allocator) !Ancestors {
        return .{ .ancestors = try self.ancestors.clone(allocator) };
    }

    pub fn deinit(self: *Ancestors, allocator: std.mem.Allocator) void {
        self.ancestors.deinit(allocator);
    }
};
