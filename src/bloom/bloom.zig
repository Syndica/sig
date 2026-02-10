const std = @import("std");
const sig = @import("../sig.zig");

const testing = std.testing;
const bincode = sig.bincode;

const ArrayList = std.array_list.Managed;

const DynamicArrayBitSet = sig.bloom.bit_set.DynamicArrayBitSet;
const BitVecConfig = sig.bloom.bit_vec.BitVecConfig;
const FnvHasher = sig.crypto.FnvHasher;

/// A bloom filter whose bitset is made up of u64 blocks
pub const Bloom = struct {
    keys: ArrayList(u64),
    bits: DynamicArrayBitSet(u64),
    num_bits_set: u64,

    pub const @"!bincode-config:bits" = BitVecConfig(u64);

    pub fn init(alloc: std.mem.Allocator, n_bits: u64, keys: ?ArrayList(u64)) !Bloom {
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

        return .{
            .keys = keys orelse ArrayList(u64).init(alloc),
            .bits = try DynamicArrayBitSet(u64).initEmpty(alloc, bitset_bits),
            .num_bits_set = 0,
        };
    }

    pub fn deinit(self: *const Bloom) void {
        self.bits.deinit(self.keys.allocator);
        self.keys.deinit();
    }

    // used in tests
    pub fn addKey(self: *Bloom, key: u64) !void {
        try self.keys.append(key);
    }

    pub fn add(self: *Bloom, key: []const u8) void {
        for (self.keys.items) |hash_index| {
            const i = self.pos(key, hash_index);
            if (!self.bits.isSet(i)) {
                self.num_bits_set +|= 1;
                self.bits.set(i);
            }
        }
    }

    pub fn contains(self: *const Bloom, key: []const u8) bool {
        for (self.keys.items) |hash_index| {
            const i = self.pos(key, hash_index);
            if (self.bits.isSet(i)) {
                continue;
            }
            return false;
        }
        return true;
    }

    pub fn pos(self: *const Bloom, bytes: []const u8, hash_index: u64) u64 {
        return hashAtIndex(bytes, hash_index) % @as(u64, self.bits.capacity());
    }

    pub fn hashAtIndex(bytes: []const u8, hash_index: u64) u64 {
        return FnvHasher.hashWithOffset(bytes, hash_index);
    }

    pub fn initRandom(
        alloc: std.mem.Allocator,
        random: std.Random,
        num_items: usize,
        false_rate: f64,
        max_bits: usize,
    ) error{OutOfMemory}!Bloom {
        const n_items_f: f64 = @floatFromInt(num_items);
        const m = Bloom.numBits(n_items_f, false_rate);
        const n_bits = @max(1, @min(@as(usize, @intFromFloat(m)), max_bits));
        const n_keys = Bloom.numKeys(@floatFromInt(n_bits), n_items_f);

        var keys = try ArrayList(u64).initCapacity(alloc, n_keys);
        for (0..n_keys) |_| {
            const v = random.int(u64);
            keys.appendAssumeCapacity(v);
        }

        return init(alloc, n_bits, keys);
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

test "helper methods match rust" {
    const n_bits = Bloom.numBits(100.2, 1e-5);
    try testing.expectEqual(@as(f64, 2402), n_bits);

    const n_keys = Bloom.numKeys(100.2, 10);
    try testing.expectEqual(@as(usize, 7), n_keys);

    var prng = std.Random.Xoshiro256.init(123);
    var bloom = try Bloom.initRandom(std.testing.allocator, prng.random(), 100, 0.1, 10000);
    defer bloom.deinit();
}

test "serializes/deserializes correctly" {
    const bloom = try Bloom.init(testing.allocator, 0, null);

    var buf: [10000]u8 = undefined;
    const out = try bincode.writeToSlice(buf[0..], bloom, .{});

    var deserialized: Bloom = try bincode.readFromSlice(testing.allocator, Bloom, out, .{});
    defer bincode.free(testing.allocator, deserialized);

    // allocate some memory to make sure were cleaning up too
    try deserialized.addKey(10);
    try testing.expect(bloom.num_bits_set == deserialized.num_bits_set);
}

test "serializes/deserializes correctly with set bits" {
    var bloom = try Bloom.init(testing.allocator, 128, null);
    try bloom.addKey(10);
    // required for memory leaks
    defer bloom.deinit();

    var buf: [10000]u8 = undefined;
    const out = try bincode.writeToSlice(buf[0..], bloom, .{});

    var deserialized: Bloom = try bincode.readFromSlice(testing.allocator, Bloom, out, .{});
    defer deserialized.deinit();

    try testing.expect(bloom.num_bits_set == deserialized.num_bits_set);
}

test "serialized bytes equal rust (one key)" {
    // note: need to init with len 2^i
    var bloom = try Bloom.init(testing.allocator, 128, null);
    defer bloom.deinit();
    try bloom.addKey(1);

    const v: [1]u8 = .{1};
    bloom.add(&v);

    var buf: [10000]u8 = undefined;
    var bytes = try bincode.writeToSlice(buf[0..], bloom, bincode.Params.standard);

    const rust_bytes = .{
        1, 0, 0, 0,   0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 2, 0,
        0, 0, 0, 0,   0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
    };

    try testing.expectEqualSlices(u8, &rust_bytes, bytes[0..bytes.len]);
}

test "serialized bytes equal rust (multiple keys)" {
    var bloom = try Bloom.init(testing.allocator, 128, null);
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

    const rust_bytes = .{
        3,  0,  0, 0,   0, 0,  0, 0, 1, 0, 0, 0, 0, 0, 0,  0, 2, 0,
        0,  0,  0, 0,   0, 0,  3, 0, 0, 0, 0, 0, 0, 0, 1,  2, 0, 0,
        0,  0,  0, 0,   0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 66,
        16, 32, 0, 128, 0, 0,  0, 0, 0, 0, 0, 6, 0, 0, 0,  0, 0, 0,
        0,
    };

    try testing.expectEqualSlices(u8, &rust_bytes, bytes[0..bytes.len]);
}
