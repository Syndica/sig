const std = @import("std");
const AutoArrayHashMap = std.AutoArrayHashMap;
const AutoHashMap = std.AutoHashMap;

const bincode = @import("../bincode/bincode.zig");

const Hash = @import("../core/hash.zig").Hash;

const SocketAddr = @import("net.zig").SocketAddr;

const crds = @import("./crds.zig");
const CrdsValue = crds.CrdsValue;
const CrdsData = crds.CrdsData;
const CrdsVersionedValue = crds.CrdsVersionedValue;
const CrdsValueLabel = crds.CrdsValueLabel;
const LegacyContactInfo = crds.LegacyContactInfo;

const Transaction = @import("../core/transaction.zig").Transaction;
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const RwLock = std.Thread.RwLock;

const CrdsPull = @import("./pull_request.zig");

pub const CrdsShards = struct {
    // shards[k] includes crds values which the first shard_bits of their hash
    // value is equal to k. Each shard is a mapping from crds values indices to
    // their hash value.
    shards: std.ArrayList(AutoArrayHashMap(usize, u64)),
    shard_bits: u32,

    const Self = @This();

    pub fn init(alloc: std.mem.Allocator, shard_bits: u32) !Self {
        const n_shards: usize = @intCast(@as(u64, 1) << @as(u6, @intCast(shard_bits)));
        var shards = try std.ArrayList(AutoArrayHashMap(usize, u64)).initCapacity(alloc, n_shards);
        for (0..n_shards) |_| {
            var shard = AutoArrayHashMap(usize, u64).init(alloc);
            shards.appendAssumeCapacity(shard);
        }

        return Self{
            .shards = shards,
            .shard_bits = shard_bits,
        };
    }

    pub fn deinit(self: *Self) void {
        for (0..self.shards.capacity) |i| {
            self.shards.items[i].deinit();
        }
        self.shards.deinit();
    }

    pub fn insert(self: *Self, crds_index: usize, hash: *const Hash) !void {
        const uhash = CrdsPull.hash_to_u64(hash);
        var shard = self.get_shard(uhash);
        try shard.put(crds_index, uhash);
    }

    pub fn remove(self: *Self, crds_index: usize, hash: *const Hash) !void {
        const uhash = CrdsPull.hash_to_u64(hash);
        var shard = self.get_shard(uhash);
        _ = shard.swapRemove(crds_index);
    }

    pub fn get_shard(self: *const Self, uhash: u64) *AutoArrayHashMap(usize, u64) {
        const shard_index = CrdsShards.compute_shard_index(self.shard_bits, uhash);
        var shard = &self.shards.items[shard_index];
        return shard;
    }

    pub fn compute_shard_index(shard_bits: u32, hash: u64) usize {
        const shift_bits: u6 = @intCast(64 - shard_bits);
        return @intCast(hash >> shift_bits);
    }

    /// see filter_crds_values for more readable (but inefficient) version  of what this fcn is doing
    pub fn find(self: *const Self, alloc: std.mem.Allocator, mask: u64, mask_bits: u32) !std.ArrayList(usize) {
        const ones = (~@as(u64, 0) >> @as(u6, @intCast(mask_bits)));
        const match_mask = mask | ones;

        // mask = hash request bits
        // shard_bits = current organization of this datastructure

        if (self.shard_bits < mask_bits) {
            // shard_bits is smaller, all matches with mask will be in the same shard index
            // eg,
            // shard_bits = 2, shardvalues == XX__
            // mask_bits = 4,  mask ==        ABCD
            // shards[AB]
            // all shard inserts will match mask AB
            // still need to scan bc of the last two bits of the shards

            const shard = self.get_shard(match_mask);
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
            // eg,
            // shard_bits == mask_bits == 3
            // mask = ABC, shard = XYZ
            // get_shard(ABC) == get_shard(XYZ)

            const shard = self.get_shard(match_mask);
            var result = try std.ArrayList(usize).initCapacity(alloc, shard.count());
            try result.insertSlice(0, shard.keys());
            return result;
        } else {
            // shardbits > maskbits
            // eg, shard_bits = 3, shardvalues == XYZ
            // mask_bits = 2,             mask == AB? 2
            // mask will match the mask + 2^(of the other bits)
            // and since its ordered we can just take the values before it
            // since AB will match XY and 2^1 (Z)

            const shift_bits: u6 = @intCast(self.shard_bits - mask_bits);
            const count: usize = @intCast(@as(u64, 1) << shift_bits);
            const end = CrdsShards.compute_shard_index(self.shard_bits, match_mask) + 1;

            var result = std.ArrayList(usize).init(alloc);
            var insert_index: usize = 0;
            for ((end - count)..end) |shard_index| {
                const shard = self.shards.items[shard_index];
                try result.insertSlice(insert_index, shard.keys());
                insert_index += shard.count();
            }
            return result;
        }
    }
};

const CrdsTable = @import("crds_table.zig").CrdsTable;

test "gossip.crds_shards: tests CrdsShards" {
    var shards = try CrdsShards.init(std.testing.allocator, 10);
    defer shards.deinit();

    const v = Hash.random();
    try shards.insert(10, &v);
    try shards.remove(10, &v);

    const result = try shards.find(std.testing.allocator, 20, 10);
    defer result.deinit();
}

// test helper fcns
fn new_test_crds_value(rng: std.rand.Random, crds_table: *CrdsTable) !CrdsVersionedValue {
    const keypair = try KeyPair.create(null);
    var value = try CrdsValue.random(rng, keypair);
    const label = value.label();
    try crds_table.insert(value, 0, null);
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
    var seed: u64 = @intCast(std.time.milliTimestamp());
    var rand = std.rand.DefaultPrng.init(seed);
    const rng = rand.random();

    var crds_table = try CrdsTable.init(std.testing.allocator);
    defer crds_table.deinit();

    var crds_shards = try CrdsShards.init(std.testing.allocator, 5);
    defer crds_shards.deinit();

    // gen ranndom values
    var values = try std.ArrayList(CrdsVersionedValue).initCapacity(std.testing.allocator, 1000);
    defer values.deinit();
    while (values.items.len < 1000) {
        const value = try new_test_crds_value(rng, &crds_table);
        try values.append(value);
        try crds_shards.insert(value.ordinal, &value.value_hash);
    }

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
