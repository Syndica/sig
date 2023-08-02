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

const CrdsPull = @import("./pull.zig");

pub const CrdsShards = struct {
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

    pub fn find(self: *const Self, alloc: std.mem.Allocator, mask: u64, mask_bits: u32) !std.ArrayList(usize) {
        const ones = (~@as(u64, 0) >> @as(u6, @intCast(mask_bits)));
        const match_mask = mask | ones;

        if (self.shard_bits < mask_bits) {
            const shard = self.get_shard(match_mask);
            var result = std.ArrayList(usize).init(alloc);
            var shard_iter = shard.iterator();
            while (shard_iter.next()) |entry| {
                const hash = entry.value_ptr.*;

                if (hash | ones == match_mask) {
                    const index = entry.key_ptr.*;
                    try result.append(index);
                }
            }
            return result;
        } else if (self.shard_bits == mask_bits) {
            const shard = self.get_shard(match_mask);
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
                const shard = self.get_shard(shard_index);
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

test "gossip.crds_shards: mask matches" {
    var seed: u64 = @intCast(std.time.milliTimestamp());
    var rand = std.rand.DefaultPrng.init(seed);
    const rng = rand.random();

    var crds_table = try CrdsTable.init(std.testing.allocator);
    defer crds_table.deinit();

    const keypair = try KeyPair.create([_]u8{1} ** 32);
    var value = try CrdsValue.random(rng, keypair);
    const label = value.label();

    try crds_table.insert(value, 0);
    const x = crds_table.get(label).?;
    _ = x;
}
