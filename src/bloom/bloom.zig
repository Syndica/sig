const std = @import("std");
const builtin = @import("builtin");
const sig = @import("../sig.zig");

const testing = std.testing;
const bincode = sig.bincode;

const DynamicArrayBitSet = sig.bloom.bit_set.DynamicArrayBitSet;
const BitVecConfig = sig.bloom.bit_vec.BitVecConfig;
const FnvHasher = sig.crypto.FnvHasher;

/// A bloom filter whose bitset is made up of u64 blocks
pub const Bloom = struct {
    keys: std.ArrayListUnmanaged(u64),
    bits: DynamicArrayBitSet(u64),
    num_bits_set: u64,

    pub const @"!bincode-config:bits" = BitVecConfig(u64);

    pub fn init(
        allocator: std.mem.Allocator,
        n_bits: u64,
        keys: std.ArrayListUnmanaged(u64),
    ) !Bloom {
        // note: we do this to match the rust deserialization
        // needs to be power of 2 < 64
        const bitset_bits = switch (n_bits) {
            0 => 0,
            1...63 => 64,
            else => std.math.pow(u64, 2, std.math.log2(n_bits)),
        };
        return .{
            .keys = keys,
            .bits = try DynamicArrayBitSet(u64).initEmpty(allocator, bitset_bits),
            .num_bits_set = 0,
        };
    }

    pub fn deinit(self: *Bloom, allocator: std.mem.Allocator) void {
        self.bits.deinit(allocator);
        self.keys.deinit(allocator);
    }

    // used in tests
    pub fn addKey(self: *Bloom, key: u64, allocator: std.mem.Allocator) !void {
        if (!builtin.is_test) @compileError("only use in tests");
        try self.keys.append(allocator, key);
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
            if (!self.bits.isSet(i)) return false;
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
        allocator: std.mem.Allocator,
        random: std.Random,
        num_items: usize,
        false_rate: f64,
        max_bits: usize,
    ) error{OutOfMemory}!Bloom {
        const n_items_f: f64 = @floatFromInt(num_items);
        const m = Bloom.numBits(n_items_f, false_rate);
        const n_bits = @max(1, @min(@as(usize, @intFromFloat(m)), max_bits));
        const n_keys = Bloom.numKeys(@floatFromInt(n_bits), n_items_f);

        const keys = try allocator.alloc(u64, n_keys);
        errdefer allocator.free(keys);
        for (keys) |*key| {
            key.* = random.int(u64);
        }
        return try init(allocator, n_bits, .fromOwnedSlice(keys));
    }

    fn numBits(num_items: f64, false_rate: f64) f64 {
        const n = num_items;
        const p = false_rate;
        const two: f64 = 2;

        // const d: f64 = -4.804530139182015e-01
        const d: f64 = @log(@as(f64, 1.0) / (std.math.pow(f64, two, @log(two))));
        return std.math.ceil((n * @log(p)) / d);
    }

    fn numKeys(n_bits: f64, num_items: f64) usize {
        const n = num_items;
        const m = n_bits;

        if (n == 0) {
            return 0;
        } else {
            return @intFromFloat(@max(@as(f64, 1.0), std.math.round((m / n) * @log(@as(f64, 2)))));
        }
    }
};

test "helper methods match rust" {
    const allocator = std.testing.allocator;

    const n_bits = Bloom.numBits(100.2, 1e-5);
    try testing.expectEqual(2402.0, n_bits);

    const n_keys = Bloom.numKeys(100.2, 10);
    try testing.expectEqual(7, n_keys);

    var prng = std.Random.Xoshiro256.init(123);
    var bloom = try Bloom.initRandom(allocator, prng.random(), 100, 0.1, 10000);
    defer bloom.deinit(allocator);
}

test "serializes/deserializes correctly" {
    const allocator = std.testing.allocator;

    const bloom = try Bloom.init(allocator, 0, .empty);

    var buffer: [100]u8 = undefined;
    const out = try bincode.writeToSlice(&buffer, bloom, .{});

    var deserialized: Bloom = try bincode.readFromSlice(allocator, Bloom, out, .{});
    defer bincode.free(allocator, deserialized);

    // allocate some memory to make sure we're cleaning up too
    try deserialized.addKey(10, allocator);

    try testing.expect(bloom.num_bits_set == deserialized.num_bits_set);
}

test "serializes/deserializes correctly with set bits" {
    const allocator = std.testing.allocator;

    var bloom = try Bloom.init(allocator, 128, .empty);
    defer bloom.deinit(allocator);

    try bloom.addKey(10, allocator);

    var buffer: [100]u8 = undefined;
    const out = try bincode.writeToSlice(&buffer, bloom, .{});

    var deserialized: Bloom = try bincode.readFromSlice(allocator, Bloom, out, .{});
    defer deserialized.deinit(allocator);

    try testing.expect(bloom.num_bits_set == deserialized.num_bits_set);
}

test "serialized bytes equal rust (one key)" {
    const allocator = std.testing.allocator;

    // note: need to init with len 2^i
    var bloom = try Bloom.init(allocator, 128, .empty);
    defer bloom.deinit(allocator);

    try bloom.addKey(1, allocator);
    bloom.add(&.{1});

    var buffer: [100]u8 = undefined;
    const bytes = try bincode.writeToSlice(&buffer, bloom, bincode.Params.standard);

    try testing.expectEqualSlices(
        u8,
        &.{
            1, 0, 0, 0,   0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 2, 0,
            0, 0, 0, 0,   0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
        },
        bytes,
    );
}

test "serialized bytes equal rust (multiple keys)" {
    const allocator = std.testing.allocator;

    var bloom = try Bloom.init(allocator, 128, .empty);
    defer bloom.deinit(allocator);

    try bloom.addKey(1, allocator);
    try bloom.addKey(2, allocator);
    try bloom.addKey(3, allocator);

    bloom.add(&.{ 1, 2 });
    bloom.add(&.{ 3, 4 });

    var buffer: [100]u8 = undefined;
    const bytes = try bincode.writeToSlice(&buffer, bloom, bincode.Params.standard);

    // let mut bloom = Bloom::new(128, vec![1, 2, 3]);
    // bloom.add(&[1, 2]);
    // bloom.add(&[3, 4]);
    // println!("{:?}", bincode::serialize(&bloom).unwrap());

    try testing.expectEqualSlices(
        u8,
        &.{
            3,  0,  0, 0,   0, 0,  0, 0, 1, 0, 0, 0, 0, 0, 0,  0, 2, 0,
            0,  0,  0, 0,   0, 0,  3, 0, 0, 0, 0, 0, 0, 0, 1,  2, 0, 0,
            0,  0,  0, 0,   0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 66,
            16, 32, 0, 128, 0, 0,  0, 0, 0, 0, 0, 6, 0, 0, 0,  0, 0, 0,
            0,
        },
        bytes,
    );
}
