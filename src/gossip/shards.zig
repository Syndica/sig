const std = @import("std");
const sig = @import("../sig.zig");

const AutoArrayHashMap = std.AutoArrayHashMap;
const Hash = sig.core.Hash;
const SignedGossipData = sig.gossip.data.SignedGossipData;
const GossipVersionedData = sig.gossip.data.GossipVersionedData;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;

const hashToU64 = sig.gossip.pull_request.hashToU64;

pub const GOSSIP_SHARDS_BITS: u32 = 12;
pub const GOSSIP_SHARDS_LEN: u32 = 1 << GOSSIP_SHARDS_BITS;

/// Analogous to [CrdsShards](https://github.com/solana-labs/solana/blob/e0203f22dc83cb792fa97f91dbe6e924cbd08af1/gossip/src/crds_shards.rs#L11)
pub const GossipTableShards = struct {
    // shards[k] includes gossip values which the first shard_bits of their hash
    // value is equal to k. Each shard is a mapping from gossip values indices to
    // their hash value.
    shard_bits: u32 = GOSSIP_SHARDS_BITS,
    shards: [GOSSIP_SHARDS_LEN]AutoArrayHashMap(usize, u64),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) !Self {
        var shards: [GOSSIP_SHARDS_LEN]AutoArrayHashMap(usize, u64) = undefined;
        @memset(&shards, AutoArrayHashMap(usize, u64).init(allocator));

        return Self{
            .shards = shards,
        };
    }

    pub fn deinit(self: *Self) void {
        for (0..self.shards.len) |i| {
            self.shards[i].deinit();
        }
    }

    pub fn insert(self: *Self, gossip_index: usize, hash: *const Hash) !void {
        const uhash = hashToU64(hash);
        const shard_index = GossipTableShards.computeShardIndex(self.shard_bits, uhash);
        const shard = &self.shards[shard_index];
        try shard.put(gossip_index, uhash);
    }

    pub fn remove(self: *Self, gossip_index: usize, hash: *const Hash) void {
        const uhash = hashToU64(hash);
        const shard_index = GossipTableShards.computeShardIndex(self.shard_bits, uhash);
        const shard = &self.shards[shard_index];
        _ = shard.swapRemove(gossip_index);
    }

    pub fn computeShardIndex(shard_bits: u32, hash: u64) usize {
        const shift_bits: u6 = @intCast(64 - shard_bits);
        return @intCast(hash >> shift_bits);
    }

    /// see filterGossipVersionedDatas for more readable (but inefficient) version  of what this fcn is doing
    pub fn find(self: *const Self, alloc: std.mem.Allocator, mask: u64, mask_bits: u32) error{OutOfMemory}!std.array_list.Managed(usize) {
        const ones = (~@as(u64, 0) >> @as(u6, @intCast(mask_bits)));
        const match_mask = mask | ones;

        if (self.shard_bits < mask_bits) {
            // shard_bits is smaller, all matches with mask will be in the same shard index
            var shard = self.shards[GossipTableShards.computeShardIndex(self.shard_bits, mask)];

            var shard_iter = shard.iterator();
            var result = std.array_list.Managed(usize).init(alloc);
            while (shard_iter.next()) |entry| {
                const hash = entry.value_ptr.*;

                // see checkMask
                if (hash | ones == match_mask) {
                    const index = entry.key_ptr.*;
                    try result.append(index);
                }
            }
            return result;
        } else if (self.shard_bits == mask_bits) {
            // when bits are equal we know the lookup will be exact
            var shard = self.shards[GossipTableShards.computeShardIndex(self.shard_bits, mask)];

            var result = try std.array_list.Managed(usize).initCapacity(alloc, shard.count());
            try result.insertSlice(0, shard.keys());
            return result;
        } else {
            // shardbits > maskbits
            const shift_bits: u6 = @intCast(self.shard_bits - mask_bits);
            const count: usize = @intCast(@as(u64, 1) << shift_bits);
            const end = GossipTableShards.computeShardIndex(self.shard_bits, match_mask) + 1;

            var result = std.array_list.Managed(usize).init(alloc);
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

const GossipTable = sig.gossip.table.GossipTable;

test "GossipTableShards" {
    var shards = try GossipTableShards.init(std.testing.allocator);
    defer shards.deinit();

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const v = Hash.initRandom(random);
    try shards.insert(10, &v);
    shards.remove(10, &v);

    const result = try shards.find(std.testing.allocator, 20, 10);
    defer result.deinit();
}

// test helper fcns
fn newTestGossipVersionedData(random: std.Random, gossip_table: *GossipTable) !GossipVersionedData {
    const keypair = KeyPair.generate();
    const value = SignedGossipData.initRandom(random, &keypair);
    _ = try gossip_table.insert(value, 0);
    const label = value.label();
    return gossip_table.get(label).?;
}

fn checkMask(value: *const GossipVersionedData, mask: u64, mask_bits: u32) bool {
    const uhash = hashToU64(&value.metadata.value_hash);
    const ones = (~@as(u64, 0) >> @as(u6, @intCast(mask_bits)));
    return (uhash | ones) == (mask | ones);
}

// does the same thing as find() but a lot more inefficient
fn filterGossipVersionedDatas(
    alloc: std.mem.Allocator,
    values: []GossipVersionedData,
    mask: u64,
    mask_bits: u32,
) !std.AutoHashMap(usize, void) {
    var result = std.AutoHashMap(usize, void).init(alloc);
    for (values, 0..) |value, i| {
        if (checkMask(&value, mask, mask_bits)) {
            try result.put(i, {});
        }
    }
    return result;
}

test "gossip.gossip_shards: test shard find" {
    var gossip_table = try GossipTable.init(std.testing.allocator, std.testing.allocator);
    defer gossip_table.deinit();

    // gen ranndom values
    var values = try std.array_list.Managed(GossipVersionedData).initCapacity(std.testing.allocator, 1000);
    defer values.deinit();

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    while (values.items.len < 50) {
        const value = try newTestGossipVersionedData(random, &gossip_table);
        try values.append(value);
    }

    var gossip_shards = gossip_table.shards;
    // test find with different mask bit sizes  (< > == shard bits)
    for (0..10) |_| {
        const mask = random.int(u64);
        for (0..12) |mask_bits| {
            var set = try filterGossipVersionedDatas(std.testing.allocator, values.items, mask, @intCast(mask_bits));
            defer set.deinit();

            var indexs = try gossip_shards.find(std.testing.allocator, mask, @intCast(mask_bits));
            defer indexs.deinit();

            try std.testing.expectEqual(set.count(), @as(u32, @intCast(indexs.items.len)));

            for (indexs.items) |index| {
                _ = set.remove(index);
            }
            try std.testing.expectEqual(set.count(), 0);
        }
    }
}
