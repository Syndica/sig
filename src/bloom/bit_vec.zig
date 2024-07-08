const std = @import("std");
const bincode = @import("../bincode/bincode.zig");
const testing = std.testing;

const DynamicArrayBitSet = @import("bit_set.zig").DynamicArrayBitSet;

/// We created this for compatibility with the Rust BitVec type
/// even though `DynamicArrayBitSet` functions the same but bincode
/// serializes/deserializes differently thus why we need this
/// intermediary type.
pub fn BitVec(comptime T: type) type {
    return struct {
        bits: ?[]T,
        len: u64,

        const Self = @This();

        pub fn initFromBitSet(bitset: *const DynamicArrayBitSet(T)) Self {
            if (bitset.capacity() > 0) {
                return Self{
                    .bits = bitset.masks,
                    .len = @as(u64, bitset.capacity()),
                };
            }
            return Self{
                .bits = null,
                .len = @as(u64, bitset.bit_length),
            };
        }

        pub fn toBitSet(self: *const Self, allocator: std.mem.Allocator) !DynamicArrayBitSet(T) {
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
        pub fn serialize(writer: anytype, data: anytype, params: bincode.Params) !void {
            var bitset: DynamicArrayBitSet(T) = data;
            const bitvec = BitVec(T).initFromBitSet(&bitset);
            try bincode.write(writer, bitvec, params);
        }

        pub fn deserialize(allocator: std.mem.Allocator, reader: anytype, params: bincode.Params) !DynamicArrayBitSet(T) {
            var bitvec = try bincode.read(allocator, BitVec(T), reader, params);
            defer bincode.free(allocator, bitvec);

            const dynamic_bitset = try bitvec.toBitSet(allocator);
            return dynamic_bitset;
        }

        pub fn free(allocator: std.mem.Allocator, data: anytype) void {
            data.deinit(allocator);
        }
    };

    return bincode.FieldConfig(DynamicArrayBitSet(T)){
        .serializer = S.serialize,
        .deserializer = S.deserialize,
        .free = S.free,
    };
}

test "bloom.bit_vec: serializes/deserializes matches Rust's BitVec u64" {
    var rust_bit_vec_serialized = [_]u8{
        1,   2,   0,   0,   0,   0,   0, 0, 0, 255, 255, 239, 191, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 128, 0, 0, 0, 0,   0,   0,   0,
    };
    var bitset = try DynamicArrayBitSet(u64).initFull(std.testing.allocator, 128);
    defer bitset.deinit(std.testing.allocator);

    bitset.setValue(20, false);
    bitset.setValue(30, false);

    var buf: [10000]u8 = undefined;

    const original = BitVec(u64).initFromBitSet(&bitset);
    var out = try bincode.writeToSlice(buf[0..], original, bincode.Params.standard);

    var deserialied = try bincode.readFromSlice(testing.allocator, BitVec(u64), out, bincode.Params.standard);
    defer bincode.free(testing.allocator, deserialied);

    try testing.expect(std.mem.eql(u64, original.bits.?[0..], deserialied.bits.?[0..]));
    try testing.expectEqualSlices(u8, rust_bit_vec_serialized[0..], out[0..]);
}

test "bloom.bit_vec: serializes/deserializes matches Rust's BitVec u8" {
    var rust_bit_vec_serialized = [_]u8{ 1, 16, 0, 0, 0, 0, 0, 0, 0, 255, 255, 239, 255, 255, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 128, 0, 0, 0, 0, 0, 0, 0 };
    var bitset = try DynamicArrayBitSet(u8).initFull(std.testing.allocator, 128);
    defer bitset.deinit(std.testing.allocator);

    bitset.setValue(20, false);
    bitset.setValue(40, false);

    var buf: [10000]u8 = undefined;

    const original = BitVec(u8).initFromBitSet(&bitset);
    var out = try bincode.writeToSlice(buf[0..], original, bincode.Params.standard);

    var deserialied = try bincode.readFromSlice(testing.allocator, BitVec(u8), out, bincode.Params.standard);
    defer bincode.free(testing.allocator, deserialied);

    try testing.expect(std.mem.eql(u8, original.bits.?[0..], deserialied.bits.?[0..]));
    try testing.expectEqualSlices(u8, rust_bit_vec_serialized[0..], out[0..]);
}
