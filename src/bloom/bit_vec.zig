const std = @import("std");
const bincode = @import("../bincode/bincode.zig");
const DynamicArrayBitSet = @import("bit_set.zig").DynamicArrayBitSet;

/// Provides compatibility with the Rust BitVec type.
pub fn BitVec(comptime T: type) type {
    return struct {
        bits: ?[]const T,
        len: u64,

        pub fn init(bitset: *const DynamicArrayBitSet(T)) BitVec(T) {
            if (bitset.capacity() > 0) {
                return .{
                    .bits = bitset.masks,
                    .len = bitset.capacity(),
                };
            }
            return .{
                .bits = null,
                .len = bitset.capacity(),
            };
        }

        pub fn toBitSet(
            self: *const BitVec(T),
            allocator: std.mem.Allocator,
        ) !DynamicArrayBitSet(T) {
            var bitset = try DynamicArrayBitSet(T).initEmpty(allocator, self.len);
            if (self.bits) |bits| {
                for (bits, 0..) |bit, i| {
                    bitset.masks[i] = bit;
                }
            }
            return bitset;
        }
    };
}

pub fn BitVecConfig(comptime T: type) bincode.FieldConfig(DynamicArrayBitSet(T)) {
    const S = struct {
        pub fn serialize(
            writer: anytype,
            data: DynamicArrayBitSet(T),
            params: bincode.Params,
        ) !void {
            const bitvec: BitVec(T) = .init(&data);
            try bincode.write(writer, bitvec, params);
        }

        pub fn deserialize(
            allocator: std.mem.Allocator,
            reader: anytype,
            params: bincode.Params,
        ) !DynamicArrayBitSet(T) {
            var bitvec = try bincode.read(allocator, BitVec(T), reader, params);
            defer bincode.free(allocator, bitvec);

            return try bitvec.toBitSet(allocator);
        }

        pub fn free(allocator: std.mem.Allocator, data: anytype) void {
            data.deinit(allocator);
        }
    };

    return .{
        .serializer = S.serialize,
        .deserializer = S.deserialize,
        .free = S.free,
    };
}

test "serializes/deserializes matches Rust's BitVec u64" {
    const allocator = std.testing.allocator;

    var bitset = try DynamicArrayBitSet(u64).initFull(allocator, 128);
    defer bitset.deinit(allocator);

    bitset.setValue(20, false);
    bitset.setValue(30, false);

    const original = BitVec(u64).init(&bitset);

    var buffer: [100]u8 = undefined;
    const out = try bincode.writeToSlice(
        &buffer,
        original,
        bincode.Params.standard,
    );

    const deserialied = try bincode.readFromSlice(
        allocator,
        BitVec(u64),
        out,
        bincode.Params.standard,
    );
    defer bincode.free(allocator, deserialied);

    try std.testing.expect(std.mem.eql(u64, original.bits.?, deserialied.bits.?));
    try std.testing.expectEqualSlices(
        u8,
        &.{
            1,   2,   0,   0,   0,   0,   0,   0,   0,   255, 255,
            239, 191, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 128, 0,   0,   0,   0,   0,   0,   0,
        },
        out,
    );
}

test "serializes/deserializes matches Rust's BitVec u8" {
    const allocator = std.testing.allocator;

    var bitset = try DynamicArrayBitSet(u8).initFull(allocator, 128);
    defer bitset.deinit(allocator);

    bitset.setValue(20, false);
    bitset.setValue(40, false);

    const original = BitVec(u8).init(&bitset);

    var buffer: [100]u8 = undefined;
    const out = try bincode.writeToSlice(
        &buffer,
        original,
        bincode.Params.standard,
    );

    const deserialied = try bincode.readFromSlice(
        allocator,
        BitVec(u8),
        out,
        bincode.Params.standard,
    );
    defer bincode.free(allocator, deserialied);

    try std.testing.expect(std.mem.eql(u8, original.bits.?, deserialied.bits.?));
    try std.testing.expectEqualSlices(
        u8,
        &.{
            1,   16,  0,   0,   0,   0,   0,   0,   0,   255, 255, 239, 255, 255,
            254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 128, 0,   0,
            0,   0,   0,   0,   0,
        },
        out,
    );
}
