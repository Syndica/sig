const std = @import("std");
const ArrayList = std.ArrayList;
const DynamicBitSet = std.bit_set.DynamicBitSet;
const BitVec = @import("bitvec.zig").BitVec;
const ArrayListConfig = @import("../utils/arraylist.zig").ArrayListConfig;

const bincode = @import("../bincode/bincode.zig");
const BitVecConfig = @import("bitvec.zig").BitVecConfig;

const FnvHasher = @import("../crypto/fnv.zig").FnvHasher;
const testing = std.testing;

const RndGen = std.rand.DefaultPrng;

/// A bloom filter whose bitset is made up of u64 blocks
pub const Bloom = struct {
    keys: ArrayList(u64),
    bits: DynamicBitSet,
    num_bits_set: u64,

    pub const @"!bincode-config:keys" = ArrayListConfig(u64);
    pub const @"!bincode-config:bits" = BitVecConfig();

    const Self = @This();

    pub fn init(alloc: std.mem.Allocator, n_bits: u64, keys: ?ArrayList(u64)) Self {
        // note: we do this to match the rust deserialization
        // needs to be power of 2 < 64
        const bitset_bits = blk: {
            if (n_bits == 0) {
                break :blk 0;
            } else if (n_bits < 64) {
                break :blk 64;
            } else {
                // smallest power of 2 >= 64
                break :blk std.math.pow(u64, 2, std.math.log2(n_bits));
            }
        };
        // if (bitset_bits != n_bits) {
        //     std.debug.print("rounding n_bits from {d} to {d}...\n", .{ n_bits, bitset_bits });
        // }

        return Self{
            .keys = keys orelse ArrayList(u64).init(alloc),
            .bits = DynamicBitSet.initEmpty(alloc, bitset_bits) catch unreachable,
            .num_bits_set = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        self.bits.deinit();
        self.keys.deinit();
    }

    // used in tests
    pub fn addKey(self: *Self, key: u64) !void {
        try self.keys.append(key);
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

    pub fn contains(self: *const Self, key: []const u8) bool {
        for (self.keys.items) |hash_index| {
            var i = self.pos(key, hash_index);
            if (self.bits.isSet(i)) {
                continue;
            }
            return false;
        }
        return true;
    }

    pub fn pos(self: *const Self, bytes: []const u8, hash_index: u64) u64 {
        return hashAtIndex(bytes, hash_index) % @as(u64, self.bits.capacity());
    }

    pub fn hashAtIndex(bytes: []const u8, hash_index: u64) u64 {
        var hasher = FnvHasher.initWithOffset(hash_index);
        hasher.update(bytes);
        return hasher.final();
    }

    pub fn random(alloc: std.mem.Allocator, num_items: usize, false_rate: f64, max_bits: usize) error{OutOfMemory}!Self {
        const n_items_f: f64 = @floatFromInt(num_items);
        const m = Bloom.numBits(n_items_f, false_rate);
        const n_bits = @max(1, @min(@as(usize, @intFromFloat(m)), max_bits));
        const n_keys = Bloom.numKeys(@floatFromInt(n_bits), n_items_f);

        var seed = @as(u64, @intCast(std.time.milliTimestamp()));
        var rnd = RndGen.init(seed);

        var keys = try ArrayList(u64).initCapacity(alloc, n_keys);
        for (0..n_keys) |_| {
            const v = rnd.random().int(u64);
            keys.appendAssumeCapacity(v);
        }

        return Bloom.init(alloc, n_bits, keys);
    }

    fn numBits(num_items: f64, false_rate: f64) f64 {
        const n = num_items;
        const p = false_rate;
        const two: f64 = 2;

        // const d: f64 = -4.804530139182015e-01
        const d: f64 = @log(@as(f64, 1) / (std.math.pow(f64, two, @log(two))));
        return std.math.ceil((n * @log(p)) / d);
    }

    fn numKeys(n_bits: f64, num_items: f64) usize {
        const n = num_items;
        const m = n_bits;

        if (n == 0) {
            return 0;
        } else {
            return @intFromFloat(@max(@as(f64, 1), std.math.round((m / n) * @log(@as(f64, 2)))));
        }
    }
};

test "bloom.bloom: helper fcns match rust" {
    const n_bits = Bloom.numBits(100.2, 1e-5);
    try testing.expectEqual(@as(f64, 2402), n_bits);

    const n_keys = Bloom.numKeys(100.2, 10);
    try testing.expectEqual(@as(usize, 7), n_keys);

    var bloom = try Bloom.random(std.testing.allocator, 100, 0.1, 10000);
    defer bloom.deinit();
}

test "bloom.bloom: serializes/deserializes correctly" {
    var bloom = Bloom.init(testing.allocator, 0, null);

    var buf: [10000]u8 = undefined;
    var out = try bincode.writeToSlice(buf[0..], bloom, bincode.Params.standard);

    var deserialized: Bloom = try bincode.readFromSlice(testing.allocator, Bloom, out, bincode.Params.standard);
    defer bincode.free(testing.allocator, deserialized);

    // allocate some memory to make sure were cleaning up too
    try deserialized.addKey(10);
    try deserialized.bits.resize(100, true);

    try testing.expect(bloom.num_bits_set == deserialized.num_bits_set);
}

test "bloom.bloom: serializes/deserializes correctly with set bits" {
    var bloom = Bloom.init(testing.allocator, 128, null);
    try bloom.addKey(10);
    // required for memory leaks
    defer bloom.deinit();

    var buf: [10000]u8 = undefined;
    var out = try bincode.writeToSlice(buf[0..], bloom, bincode.Params.standard);

    var deserialized: Bloom = try bincode.readFromSlice(testing.allocator, Bloom, out, bincode.Params.standard);
    defer deserialized.deinit();

    try testing.expect(bloom.num_bits_set == deserialized.num_bits_set);
}

test "bloom.bloom: rust: serialized bytes equal rust (one key)" {
    // note: need to init with len 2^i
    var bloom = Bloom.init(testing.allocator, 128, null);
    defer bloom.deinit();
    try bloom.addKey(1);

    const v: [1]u8 = .{1};
    bloom.add(&v);

    var buf: [10000]u8 = undefined;
    var bytes = try bincode.writeToSlice(buf[0..], bloom, bincode.Params.standard);

    const rust_bytes = .{ 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0 };

    try testing.expectEqualSlices(u8, &rust_bytes, bytes[0..bytes.len]);
}

test "bloom.bloom: rust: serialized bytes equal rust (multiple keys)" {
    var bloom = Bloom.init(testing.allocator, 128, null);
    defer bloom.deinit();

    try bloom.addKey(1);
    try bloom.addKey(2);
    try bloom.addKey(3);

    var buf: [10000]u8 = undefined;

    const v: [2]u8 = .{ 1, 2 };
    bloom.add(&v);

    const x: [2]u8 = .{ 3, 4 };
    bloom.add(&x);

    var bytes = try bincode.writeToSlice(buf[0..], bloom, bincode.Params.standard);

    // let mut bloom = Bloom::new(128, vec![1, 2, 3]);
    // bloom.add(&[1, 2]);
    // bloom.add(&[3, 4]);
    // println!("{:?}", bincode::serialize(&bloom).unwrap());

    const rust_bytes = .{ 3, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 66, 16, 32, 0, 128, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0 };

    try testing.expectEqualSlices(u8, &rust_bytes, bytes[0..bytes.len]);
}
