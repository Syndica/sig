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

    pub fn init(allocator: std.mem.Allocator, num_bits: u64, keys: ArrayList(u64)) Self {
        return Self{
            .keys = keys,
            .bits = DynamicBitSet.initEmpty(allocator, num_bits) catch unreachable,
            .num_bits_set = 0,
        };
    }

    pub fn deinit(self: Self) void {
        self.bits.deinit();
        self.keys.deinit();
    }

    pub fn add(self: *Self, key: []const u8) void {
        for (self.keys.items) |hash_index| {
            var i = self.pos(key, hash_index);
            if (!self.bits.isSet(i)) {
                self.num_bits_set +|= 1;
                self.bits.set(i);
            }
        }
    }

    pub fn pos(self: *Self, bytes: []const u8, hash_index: u64) u64 {
        return hash_at_index(bytes, hash_index) % @as(u64, self.bits.capacity());
    }

    pub fn hash_at_index(bytes: []const u8, hash_index: u64) u64 {
        var hasher = FnvHasher.initWithOffset(hash_index);
        hasher.update(bytes);
        return hasher.final();
    }
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

// // TODO: Finish test
// test "bloom serializes/deserializes correctly" {
//     var keys = ArrayList(u64).init(testing.allocator);
//     _ = keys;
//     var bloom = Bloom.init(testing.allocator);
//     var buf: [10000]u8 = undefined;

//     var out = try bincode.writeToSlice(buf[0..], bloom, bincode.Params.standard);


//     std.log.debug("out: {any}", .{out});

//     var deserialized = try bincode.readFromSlice(testing.allocator, Bloom, out, bincode.Params.standard);

//     try testing.expect(bloom.num_bits_set == deserialized.num_bits_set);
// }

// // TODO: fix 
// test "compare bloom to rust" {
//     var keys = ArrayList(u64).init(testing.allocator);
//     try keys.append(1);
//     try keys.append(2);
//     try keys.append(3);

//     var bloom = Bloom.init(testing.allocator, 100, keys);
//     var buf: [10000]u8 = undefined;

//     const v: [1]u8 = .{ 1 };
//     bloom.add(&v);

//     var bytes = try bincode.writeToSlice(buf[0..], bloom, bincode.Params.standard);

//     // let mut bloom = Bloom::new(100, vec![1, 2, 3]);
//     // bloom.add(&[1u8; 1]);
//     // println!("{:?}", bincode::serialize(&bloom).unwrap());
//     const rust_bytes = .{3, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 1, 0, 64, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0}; 

//     try testing.expectEqualSlices(u8, bytes[0..bytes.len], &rust_bytes);
// }