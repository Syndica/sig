const std = @import("std");
const AutoArrayHashMap = std.AutoArrayHashMap;
const AutoHashMap = std.AutoHashMap;

const Hash = @import("../core/hash.zig").Hash;

const crds = @import("./crds.zig");
const CrdsValue = crds.CrdsValue;
const CrdsData = crds.CrdsData;
const CrdsVersionedValue = crds.CrdsVersionedValue;
const CrdsValueLabel = crds.CrdsValueLabel;
const LegacyContactInfo = crds.LegacyContactInfo;

const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const RwLock = std.Thread.RwLock;

const CrdsPull = @import("./pull_request.zig");

pub const CRDS_SHARDS_BITS: u32 = 12;
pub const CRDS_SHARDS_LEN: u32 = 1 << CRDS_SHARDS_BITS;

pub const CrdsShards = struct {
    // shards[k] includes crds values which the first shard_bits of their hash
    // value is equal to k. Each shard is a mapping from crds values indices to
    // their hash value.
    shard_bits: u32 = CRDS_SHARDS_BITS,
    shards: [CRDS_SHARDS_LEN]AutoArrayHashMap(usize, u64),

    const Self = @This();

    pub fn init(alloc: std.mem.Allocator) !Self {
        var shards: [CRDS_SHARDS_LEN]AutoArrayHashMap(usize, u64) = undefined;
        for (0..CRDS_SHARDS_LEN) |i| {
            shards[i] = AutoArrayHashMap(usize, u64).init(alloc);
        }

        return Self{
            .shards = shards,
        };
    }

    pub fn deinit(self: *Self) void {
        for (0..self.shards.len) |i| {
            self.shards[i].deinit();
        }
    }

    pub fn insert(self: *Self, crds_index: usize, hash: *const Hash) !void {
        const uhash = CrdsPull.hash_to_u64(hash);
        const shard_index = CrdsShards.compute_shard_index(self.shard_bits, uhash);
        const shard = &self.shards[shard_index];
        try shard.put(crds_index, uhash);
    }

    pub fn remove(self: *Self, crds_index: usize, hash: *const Hash) void {
        const uhash = CrdsPull.hash_to_u64(hash);
        const shard_index = CrdsShards.compute_shard_index(self.shard_bits, uhash);
        const shard = &self.shards[shard_index];
        _ = shard.swapRemove(crds_index);
    }

    pub fn compute_shard_index(shard_bits: u32, hash: u64) usize {
        const shift_bits: u6 = @intCast(64 - shard_bits);
        return @intCast(hash >> shift_bits);
    }

    /// see filter_crds_values for more readable (but inefficient) version  of what this fcn is doing
    pub fn find(self: *const Self, alloc: std.mem.Allocator, mask: u64, mask_bits: u32) error{OutOfMemory}!std.ArrayList(usize) {
        const ones = (~@as(u64, 0) >> @as(u6, @intCast(mask_bits)));
        const match_mask = mask | ones;

        if (self.shard_bits < mask_bits) {
            // shard_bits is smaller, all matches with mask will be in the same shard index
            var shard = self.shards[CrdsShards.compute_shard_index(self.shard_bits, mask)];

            var shard_iter = shard.iterator();
            var result = std.ArrayList(usize).init(alloc);
            while (shard_iter.next()) |entry| {
                const hash = entry.value_ptr.*;

                // see check_mask
                if (hash | ones == match_mask) {
                    const index = entry.key_ptr.*;
                    try result.append(index);
                }
            }
            return result;
        } else if (self.shard_bits == mask_bits) {
            // when bits are equal we know the lookup will be exact
            var shard = self.shards[CrdsShards.compute_shard_index(self.shard_bits, mask)];

            var result = try std.ArrayList(usize).initCapacity(alloc, shard.count());
            try result.insertSlice(0, shard.keys());
            return result;
        } else {
            // shardbits > maskbits
            const shift_bits: u6 = @intCast(self.shard_bits - mask_bits);
            const count: usize = @intCast(@as(u64, 1) << shift_bits);
            const end = CrdsShards.compute_shard_index(self.shard_bits, match_mask) + 1;

            var result = std.ArrayList(usize).init(alloc);
            var insert_index: usize = 0;
            for ((end - count)..end) |shard_index| {
                const shard = self.shards[shard_index];
                try result.insertSlice(insert_index, shard.keys());
                insert_index += shard.count();
            }
            return result;
        }
    }
};

const CrdsTable = @import("crds_table.zig").CrdsTable;

test "gossip.crds_shards: tests CrdsShards" {
    var shards = try CrdsShards.init(std.testing.allocator);
    defer shards.deinit();

    const v = Hash.random();
    try shards.insert(10, &v);
    shards.remove(10, &v);

    const result = try shards.find(std.testing.allocator, 20, 10);
    defer result.deinit();
}

// test helper fcns
fn new_test_crds_value(rng: std.rand.Random, crds_table: *CrdsTable) !CrdsVersionedValue {
    const keypair = try KeyPair.create(null);
    var value = try CrdsValue.random(rng, keypair);
    try crds_table.insert(value, 0);
    const label = value.label();
    const x = crds_table.get(label).?;
    return x;
}

fn check_mask(value: *const CrdsVersionedValue, mask: u64, mask_bits: u32) bool {
    const uhash = CrdsPull.hash_to_u64(&value.value_hash);
    const ones = (~@as(u64, 0) >> @as(u6, @intCast(mask_bits)));
    return (uhash | ones) == (mask | ones);
}

// does the same thing as find() but a lot more inefficient
fn filter_crds_values(
    alloc: std.mem.Allocator,
    values: []CrdsVersionedValue,
    mask: u64,
    mask_bits: u32,
) !std.AutoHashMap(usize, void) {
    var result = std.AutoHashMap(usize, void).init(alloc);
    for (values, 0..) |value, i| {
        if (check_mask(&value, mask, mask_bits)) {
            try result.put(i, {});
        }
    }
    return result;
}

test "gossip.crds_shards: test shard find" {
    var crds_table = try CrdsTable.init(std.testing.allocator);
    defer crds_table.deinit();

    // gen ranndom values
    var values = try std.ArrayList(CrdsVersionedValue).initCapacity(std.testing.allocator, 1000);
    defer values.deinit();

    var seed: u64 = @intCast(std.time.milliTimestamp());
    var rand = std.rand.DefaultPrng.init(seed);
    const rng = rand.random();

    while (values.items.len < 50) {
        const value = try new_test_crds_value(rng, &crds_table);
        try values.append(value);
    }

    var crds_shards = crds_table.shards;
    // test find with different mask bit sizes  (< > == shard bits)
    for (0..10) |_| {
        var mask = rng.int(u64);
        for (0..12) |mask_bits| {
            var set = try filter_crds_values(std.testing.allocator, values.items, mask, @intCast(mask_bits));
            defer set.deinit();

            var indexs = try crds_shards.find(std.testing.allocator, mask, @intCast(mask_bits));
            defer indexs.deinit();

            try std.testing.expectEqual(set.count(), @as(u32, @intCast(indexs.items.len)));

            for (indexs.items) |index| {
                _ = set.remove(index);
            }
            try std.testing.expectEqual(set.count(), 0);
        }
    }
}
