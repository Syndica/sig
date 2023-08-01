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

    pub fn get_shard(self: *Self, uhash: u64) *AutoArrayHashMap(usize, u64) {
        const shard_index = CrdsShards.compute_shard_index(self.shard_bits, uhash);
        var shard = &self.shards.items[shard_index];
        return shard;
    }

    pub fn compute_shard_index(shard_bits: u32, hash: u64) usize {
        const shift_bits: u6 = @intCast(64 - shard_bits);
        return @intCast(hash >> shift_bits);
    }

    pub fn deinit(self: *Self) void {
        for (0..self.shards.capacity) |i| {
            self.shards.items[i].deinit();
        }
        self.shards.deinit();
    }
};

test "gossip.crds_shards: tests CrdsShards" {
    var shards = try CrdsShards.init(std.testing.allocator, 10);
    defer shards.deinit();

    const v = Hash.random();
    try shards.insert(10, &v);
    try shards.remove(10, &v);
}
