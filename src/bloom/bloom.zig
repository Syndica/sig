const std = @import("std");
const ArrayList = std.ArrayList;
const DynamicBitSet = std.bit_set.DynamicBitSet;
const BitVec = @import("bitvec.zig").BitVec;
const ArrayListConfig = @import("../utils/arraylist.zig").ArrayListConfig;
const bincode = @import("bincode-zig");
const FnvHasher = @import("../crypto/fnv.zig").FnvHasher;
const testing = std.testing;

/// A bloom filter whose bitset is made up of u64 blocks
pub const Bloom = struct {
    keys: ArrayList(u64),
    bits: DynamicBitSet,
    num_bits_set: u64,

    pub const @"!bincode-config:keys" = ArrayListConfig(u64);
    pub const @"!bincode-config:bits" = bincode.FieldConfig{
        .serializer = bincode_serialize_bit_vec,
        .deserializer = bincode_deserialize_bit_vec,
    };

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .keys = ArrayList(u64).init(allocator),
            .bits = DynamicBitSet.initEmpty(allocator, 0) catch unreachable,
            .num_bits_set = 0,
        };
    }

    pub fn deinit(self: Self) void {
        self.bits.deinit();
        self.keys.deinit();
    }

    pub fn add(self: *Self, key: u64) void {
        for (self.keys.items) |k| {
            var i = self.pos(key, k);
            if (!self.bits.isSet(i)) {
                self.num_bits_set +|= 1;
                self.bits.set(i);
            }
        }
    }

    pub fn pos(self: *Self, key: u64, k: u64) u64 {
        return self.hash_at_index(key, k) % @bitSizeOf(u64);
    }

    pub fn hash_at_index(key: u64, hash_index: u64) u64 {
        var bytes = std.mem.asBytes(&key);
        var hasher = FnvHasher.initWithOffset(hash_index);
        hasher.update(bytes);
        return hasher.final();
    }

    // pub fn pos()

    // pub fn add(self: *Self) void {
    //      for (self.keys) |key| {
    //         let pos = self.pos(key, *k);
    //         if !self.bits.get(pos) {
    //             self.num_bits_set = self.num_bits_set.saturating_add(1);
    //             self.bits.set(pos, true);
    //         }
    //     }
    // }
};

fn bincode_serialize_bit_vec(writer: anytype, data: anytype, params: bincode.Params) !void {
    var bitset: DynamicBitSet = data;
    var bitvec = BitVec.initFromBitSet(bitset);
    try bincode.write(writer, bitvec, params);
    return;
}

fn bincode_deserialize_bit_vec(allocator: std.mem.Allocator, comptime T: type, reader: anytype, params: bincode.Params) !T {
    var bitvec = try bincode.read(allocator, BitVec, reader, params);
    return try bitvec.toBitSet(allocator);
}

// TODO: Finish test
test "bloom serializes/deserializes correctly" {
    var keys = ArrayList(u64).init(testing.allocator);
    _ = keys;
    var bloom = Bloom.init(testing.allocator);
    var buf: [10000]u8 = undefined;

    var out = try bincode.writeToSlice(buf[0..], bloom, bincode.Params.standard);

    std.log.debug("out: {any}", .{out});

    var deserialized = try bincode.readFromSlice(testing.allocator, Bloom, out, bincode.Params.standard);

    try testing.expect(bloom.num_bits_set == deserialized.num_bits_set);
}
