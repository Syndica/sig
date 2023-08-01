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
    mask_bits: u32,

    const Self = @This();

    pub fn init(alloc: std.mem.Allocator, num_items: usize, max_bytes: usize) !Self {
        var max_bits: f64 = @floatFromInt(max_bytes * 8);
        var max_items = CrdsFilter.compute_max_items(max_bits, FALSE_RATE, KEYS);
        var mask_bits = CrdsFilter.compute_mask_bits(@floatFromInt(num_items), max_bits);

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

    pub fn compute_mask_bits(num_items: f64, max: f64) u32 {
        return @intFromFloat(@max(0, (std.math.ceil(std.math.log2(num_items / max)))));
    }

    pub fn compute_max_items(max_bits: f64, false_rate: f64, num_keys: f64) f64 {
        const m = max_bits;
        const p = false_rate;
        const k = num_keys;
        return std.math.ceil(m / (-k / ln(@as(f64, 1) - exp(ln(p) / k))));
    }

    pub fn deinit(self: *Self) void {
        self.filter.deinit();
    }
};

test "gossip.pull: CrdsFilterSet deinits correct" {
    var filter_set = try CrdsFilterSet.init(std.testing.allocator, 100, 200);
    defer filter_set.deinit();
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
}

test "gossip.pull: crds filter matches rust bytes" {
    const rust_bytes = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0 };
    var filter = CrdsFilter.init(std.testing.allocator);
    defer filter.deinit();

    var buf = [_]u8{0} ** 1024;
    var bytes = try bincode.writeToSlice(buf[0..], filter, bincode.Params.standard);
    try std.testing.expectEqualSlices(u8, rust_bytes[0..], bytes);
}
