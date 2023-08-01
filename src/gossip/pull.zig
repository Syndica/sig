const std = @import("std");
const SocketAddr = @import("net.zig").SocketAddr;
const Tuple = std.meta.Tuple;
const Hash = @import("../core/hash.zig").Hash;
const Signature = @import("../core/signature.zig").Signature;
const Transaction = @import("../core/transaction.zig").Transaction;
const Slot = @import("../core/slot.zig").Slot;
const Option = @import("../option.zig").Option;
const ContactInfo = @import("node.zig").ContactInfo;
const bincode = @import("../bincode/bincode.zig");
const ArrayList = std.ArrayList;
const ArrayListConfig = @import("../utils/arraylist.zig").ArrayListConfig;
const Bloom = @import("../bloom/bloom.zig").Bloom;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const ln = std.math.ln;
const exp = std.math.exp;

pub const FALSE_RATE: f64 = 0.1;
pub const KEYS: f64 = 8;

pub const CrdsFilterSet = struct {
    filters: ArrayList(Bloom),
    mask_bits: u32, // todo: make this a u6

    const Self = @This();

    pub fn init(alloc: std.mem.Allocator, num_items: usize, max_bytes: usize) !Self {
        var max_bits: f64 = @floatFromInt(max_bytes * 8);
        var max_items = CrdsFilter.compute_max_items(max_bits, FALSE_RATE, KEYS);
        // mask_bits = log2(..) number of filters
        var mask_bits = CrdsFilter.compute_mask_bits(@floatFromInt(num_items), max_bits);
        std.debug.assert(mask_bits > 0);

        const n_filters = mask_bits << 1;
        var filters = try ArrayList(Bloom).initCapacity(alloc, n_filters);
        for (0..n_filters) |_| {
            var filter = try Bloom.random(alloc, @intFromFloat(max_items), FALSE_RATE, @intFromFloat(max_bits));
            filters.appendAssumeCapacity(filter);
        }

        return Self{
            .filters = filters,
            .mask_bits = mask_bits,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.filters.items) |*f| {
            f.deinit();
        }
        self.filters.deinit();
    }

    pub fn add(self: *Self, hash: Hash) void {
        // 64 = u64 bits
        const shift_bits: u6 = @intCast(64 - self.mask_bits);
        // only look at the first `mask_bits` bits
        // which represents `n_filters` number of indexs
        const index = @as(usize, CrdsFilter.hash_to_u64(&hash) >> shift_bits);
        self.filters.items[index].add(&hash.data);
    }

    pub fn len(self: Self) usize {
        // return self.filters.items.len;
        return self.mask_bits << 1;
    }

    pub fn toCrdsFilters(self: Self, buf: []CrdsFilter) []CrdsFilter {
        const size = @min(buf.len, self.filters.capacity);
        for (0..size) |i| {
            var f = &buf[i];
            f.filter = self.filters.items[i];
            f.mask = CrdsFilter.compute_mask(i, self.mask_bits);
            f.mask_bits = self.mask_bits;
        }

        return buf[0..size];
    }
};

pub const CrdsFilter = struct {
    filter: Bloom,
    mask: u64,
    mask_bits: u32,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .filter = Bloom.init(allocator, 0, null),
            .mask = 18_446_744_073_709_551_615,
            .mask_bits = 0,
        };
    }

    pub fn compute_mask(index: u64, mask_bits: u32) u64 {
        std.debug.assert(mask_bits > 0);
        std.debug.assert(index <= std.math.pow(u64, 2, mask_bits));
        // eg, with index = 2 and mask_bits = 3
        // shift_bits = 61 (ie, only look at first 2 bits)
        const shift_bits: u6 = @intCast(64 - mask_bits);
        // 2 << 61 = 100...000
        const shifted_index = index << shift_bits;
        // OR with all the other zeros
        //  10                 111111..11111
        //   ^                         ^
        // index (mask_bits length) | rest
        return shifted_index | (~@as(u64, 0) >> @as(u6, @intCast(mask_bits)));
    }

    pub fn compute_mask_bits(num_items: f64, max: f64) u32 {
        return @intFromFloat(@max(0, (std.math.ceil(std.math.log2(num_items / max)))));
    }

    pub fn compute_max_items(max_bits: f64, false_rate: f64, num_keys: f64) f64 {
        const m = max_bits;
        const p = false_rate;
        const k = num_keys;
        return std.math.ceil(m / (-k / ln(@as(f64, 1) - exp(ln(p) / k))));
    }

    pub fn hash_to_u64(hash: *const Hash) u64 {
        const buf = hash.data[0..8];
        return std.mem.readIntLittle(u64, buf);
    }

    pub fn deinit(self: *Self) void {
        self.filter.deinit();
    }
};

test "gossip.pull: CrdsFilterSet deinits correct" {
    var filter_set = try CrdsFilterSet.init(std.testing.allocator, 10000, 200);
    defer filter_set.deinit();

    std.debug.print("mask bits: {any}", .{filter_set.mask_bits});

    const hash = Hash{ .data = .{ 1, 2, 3, 4 } ++ .{0} ** 28 };

    filter_set.add(hash);

    const shift_bits: u6 = @intCast(64 - filter_set.mask_bits);
    const index = @as(usize, CrdsFilter.hash_to_u64(&hash) >> shift_bits);
    var bloom = filter_set.filters.items[index];
    const v = bloom.contains(&hash.data);
    try std.testing.expect(v);

    var filters: [10]CrdsFilter = undefined;
    const f = filter_set.toCrdsFilters(&filters);
    try std.testing.expect(f.len == filter_set.len());
    const x = f[index];
    try std.testing.expect(x.filter.contains(&hash.data));
}

test "gossip.pull: helper functions are correct" {
    {
        const v = CrdsFilter.compute_max_items(100.5, 0.1, 10.0);
        try std.testing.expectEqual(@as(f64, 16), v);
    }

    {
        const v = CrdsFilter.compute_mask_bits(800, 100);
        try std.testing.expectEqual(@as(usize, 3), v);
    }

    {
        const v = Hash{ .data = .{1} ++ .{0} ** 31 };
        try std.testing.expectEqual(@as(u64, 1), CrdsFilter.hash_to_u64(&v));
    }

    {
        const v = CrdsFilter.compute_mask(2, 3);
        // 101111111111111111111111111111111111111111111111111111111111111
        try std.testing.expectEqual(@as(u64, 6917529027641081855), v);
    }
}

test "gossip.pull: crds filter matches rust bytes" {
    const rust_bytes = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0 };
    var filter = CrdsFilter.init(std.testing.allocator);
    defer filter.deinit();

    var buf = [_]u8{0} ** 1024;
    var bytes = try bincode.writeToSlice(buf[0..], filter, bincode.Params.standard);
    try std.testing.expectEqualSlices(u8, rust_bytes[0..], bytes);
}
