const std = @import("std");
const sig = @import("../sig.zig");

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
    shard_bits: u32,
    shards: [GOSSIP_SHARDS_LEN]std.AutoArrayHashMapUnmanaged(usize, u64),

    pub const EMPTY: GossipTableShards = .{
        .shard_bits = GOSSIP_SHARDS_BITS,
        .shards = @splat(.{}),
    };

    pub fn deinit(self: *GossipTableShards, allocator: std.mem.Allocator) void {
        for (&self.shards) |*shard| shard.deinit(allocator);
    }

    pub fn insert(
        self: *GossipTableShards,
        allocator: std.mem.Allocator,
        gossip_index: usize,
        hash: *const Hash,
    ) !void {
        const uhash = hashToU64(hash);
        const shard_index = GossipTableShards.computeShardIndex(self.shard_bits, uhash);
        const shard = &self.shards[shard_index];
        try shard.put(allocator, gossip_index, uhash);
    }

    pub fn remove(self: *GossipTableShards, gossip_index: usize, hash: *const Hash) void {
        const uhash = hashToU64(hash);
        const shard_index = GossipTableShards.computeShardIndex(self.shard_bits, uhash);
        const shard = &self.shards[shard_index];
        _ = shard.swapRemove(gossip_index);
    }

    /// Asserts `shard_bits` isn't 0.
    pub fn computeShardIndex(shard_bits: u32, hash: u64) usize {
        const shift_bits: u6 = @intCast(64 - shard_bits);
        return @intCast(hash >> shift_bits);
    }

    /// see filterGossipVersionedDatas for more readable (but inefficient)
    /// version of what this function is doing
    pub fn find(
        self: *const GossipTableShards,
        allocator: std.mem.Allocator,
        mask: u64,
        mask_bits: u32,
    ) error{OutOfMemory}![]const usize {
        const ones = (~@as(u64, 0) >> @intCast(mask_bits));
        const match_mask = mask | ones;

        if (self.shard_bits < mask_bits) {
            // shard_bits is smaller, all matches with mask will be in the same shard index
            var shard = self.shards[GossipTableShards.computeShardIndex(self.shard_bits, mask)];

            var result: std.ArrayListUnmanaged(usize) = .empty;
            defer result.deinit(allocator);

            var iterator = shard.iterator();
            while (iterator.next()) |entry| {
                const hash = entry.value_ptr.*;

                // see checkMask
                if (hash | ones == match_mask) {
                    const index = entry.key_ptr.*;
                    try result.append(allocator, index);
                }
            }

            return result.toOwnedSlice(allocator);
        } else if (self.shard_bits == mask_bits) {
            // when bits are equal we know the lookup will be exact
            var shard = self.shards[GossipTableShards.computeShardIndex(self.shard_bits, mask)];

            const result = try allocator.dupe(usize, shard.keys());
            return result;
        } else {
            // shardbits > maskbits
            const shift_bits: u6 = @intCast(self.shard_bits - mask_bits);
            const count = @as(u64, 1) << shift_bits;
            const end = GossipTableShards.computeShardIndex(self.shard_bits, match_mask) + 1;

            var result: std.ArrayListUnmanaged(usize) = .empty;
            defer result.deinit(allocator);
            for (0..count) |i| {
                const shard_index = (end - count) + i;
                const shard = self.shards[shard_index];
                try result.appendSlice(allocator, shard.keys());
            }

            return try result.toOwnedSlice(allocator);
        }
    }
};

const GossipTable = sig.gossip.table.GossipTable;

test "GossipTableShards" {
    const allocator = std.testing.allocator;

    var shards: GossipTableShards = .EMPTY;
    defer shards.deinit(allocator);

    var prng = std.Random.DefaultPrng.init(91);
    const random = prng.random();

    const v = Hash.initRandom(random);
    try shards.insert(allocator, 10, &v);
    shards.remove(10, &v);

    const result = try shards.find(allocator, 20, 10);
    defer allocator.free(result);
}

// test helper functions
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

// does the same thing as find() but a lot less efficient
fn filterGossipVersionedDatas(
    allocator: std.mem.Allocator,
    values: []GossipVersionedData,
    mask: u64,
    mask_bits: u32,
) !std.AutoHashMapUnmanaged(usize, void) {
    var result: std.AutoHashMapUnmanaged(usize, void) = .empty;
    errdefer result.deinit(allocator);

    for (values, 0..) |value, i| {
        if (checkMask(&value, mask, mask_bits)) {
            try result.put(allocator, i, {});
        }
    }

    return result;
}

test "gossip.gossip_shards: test shard find" {
    const allocator = std.testing.allocator;

    var gossip_table = try GossipTable.init(allocator, allocator);
    defer gossip_table.deinit();

    var prng = std.Random.DefaultPrng.init(91);
    const random = prng.random();

    const values = try allocator.alloc(GossipVersionedData, 50);
    defer allocator.free(values);
    for (values) |*value| {
        value.* = try newTestGossipVersionedData(random, &gossip_table);
    }

    // test find with different mask bit sizes  (< > == shard bits)
    for (0..10) |_| {
        const mask = random.int(u64);
        for (0..12) |mask_bits| {
            var set = try filterGossipVersionedDatas(
                allocator,
                values,
                mask,
                @intCast(mask_bits),
            );
            defer set.deinit(allocator);

            const indices = try gossip_table.shards.find(
                allocator,
                mask,
                @intCast(mask_bits),
            );
            defer allocator.free(indices);

            try std.testing.expectEqual(set.count(), indices.len);
            for (indices) |index| {
                _ = set.remove(index);
            }
            try std.testing.expectEqual(set.count(), 0);
        }
    }
}
