const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;

const Hash = sig.core.Hash;

/// Analogous to [BlockhashQueue](https://github.com/anza-xyz/agave/blob/a79ba51741864e94a066a8e27100dfef14df835f/accounts-db/src/blockhash_queue.rs#L32)
pub const BlockhashQueue = struct {
    /// index of the last hash registered
    last_hash_index: u64,

    /// last hash to be registered
    last_hash: ?Hash,

    /// map of blockhash infos
    hash_infos: std.AutoArrayHashMapUnmanaged(Hash, BlockhashInfo),

    /// hashes older than `max_age` will be dropped from the queue
    max_age: usize,

    pub const DEFAULT = BlockhashQueue.init(MAX_RECENT_BLOCKHASHES);

    pub const MAX_RECENT_BLOCKHASHES = 300;

    /// Maximum age of a blockhash that is still considered valid for processing transactions.
    /// This is half of MAX_RECENT_BLOCKHASHES.
    /// Analogous to [MAX_PROCESSING_AGE](https://github.com/anza-xyz/solana-clock/blob/main/src/lib.rs)
    pub const MAX_PROCESSING_AGE: usize = MAX_RECENT_BLOCKHASHES / 2;

    pub const BlockhashInfo = struct {
        lamports_per_signature: u64,
        index: u64,
        timestamp: u64,
    };

    pub fn init(max_age: usize) BlockhashQueue {
        return .{
            .last_hash_index = 0,
            .last_hash = null,
            .hash_infos = .{},
            .max_age = max_age,
        };
    }

    pub fn deinit(self: BlockhashQueue, allocator: Allocator) void {
        var infos = self.hash_infos;
        infos.deinit(allocator);
    }

    pub fn clone(
        self: BlockhashQueue,
        allocator: Allocator,
    ) Allocator.Error!BlockhashQueue {
        var hash_infos = try self.hash_infos.clone(allocator);
        errdefer hash_infos.deinit(allocator);
        return .{
            .last_hash_index = self.last_hash_index,
            .last_hash = self.last_hash,
            .hash_infos = hash_infos,
            .max_age = self.max_age,
        };
    }

    pub fn getLamportsPerSignature(self: *const BlockhashQueue, hash: Hash) ?u64 {
        const hash_info = self.hash_infos.get(hash) orelse return null;
        return hash_info.lamports_per_signature;
    }

    pub fn isHashValidForAge(self: *const BlockhashQueue, hash: Hash, max_age: u64) bool {
        const hash_info = self.hash_infos.get(hash) orelse return false;
        return isHashIndexValid(self.last_hash_index, max_age, hash_info.index);
    }

    pub fn getHashInfoIfValid(self: BlockhashQueue, hash: Hash, max_age: usize) ?BlockhashInfo {
        const hash_info = self.hash_infos.get(hash) orelse return null;
        if (!isHashIndexValid(self.last_hash_index, max_age, hash_info.index)) {
            return null;
        }
        return hash_info;
    }

    pub fn insertGenesisHash(
        self: *BlockhashQueue,
        allocator: Allocator,
        hash: Hash,
        lamports_per_signature: u64,
    ) Allocator.Error!void {
        std.debug.assert(self.last_hash_index == 0);
        try self.hash_infos.put(allocator, hash, .{
            .index = 0,
            .timestamp = @intCast(std.time.milliTimestamp()),
            .lamports_per_signature = lamports_per_signature,
        });
        self.last_hash = hash;
    }

    pub fn insertHash(
        self: *BlockhashQueue,
        allocator: Allocator,
        hash: Hash,
        lamports_per_signature: u64,
    ) Allocator.Error!void {
        const last_hash_index = self.last_hash_index + 1;
        if (self.hash_infos.count() >= self.max_age) try self.purge(last_hash_index);

        try self.hash_infos.put(allocator, hash, .{
            .index = last_hash_index,
            .timestamp = @intCast(std.time.milliTimestamp()),
            .lamports_per_signature = lamports_per_signature,
        });

        self.last_hash_index = last_hash_index;
        self.last_hash = hash;
    }

    pub fn getHashAge(self: *const BlockhashQueue, hash: Hash) ?u64 {
        const hash_info = self.hash_infos.get(hash) orelse return null;
        return self.last_hash_index - hash_info.index;
    }

    fn isHashIndexValid(last_hash_index: u64, max_age: usize, hash_index: u64) bool {
        return last_hash_index - hash_index <= @as(u64, max_age);
    }

    fn purge(self: *BlockhashQueue, last_hash_index: u64) Allocator.Error!void {
        std.debug.assert(self.hash_infos.count() <= MAX_RECENT_BLOCKHASHES + 1);
        var keys = [_]Hash{Hash.ZEROES} ** (MAX_RECENT_BLOCKHASHES + 1);
        @memcpy(keys[0..self.hash_infos.count()], self.hash_infos.keys());
        for (keys[0..self.hash_infos.count()]) |key| {
            const hash_info = self.hash_infos.get(key) orelse unreachable;
            if (isHashIndexValid(last_hash_index, self.max_age, hash_info.index)) continue;
            _ = self.hash_infos.swapRemove(key);
        }
    }

    pub fn initRandom(
        allocator: Allocator,
        random: std.Random,
        max_list_entries: usize,
    ) Allocator.Error!BlockhashQueue {
        // Used by BankFeilds.initRandom inside accounts_db.manager.runLoop, should be made test only when possible.
        // if (!builtin.is_test) @compileError("only for testing");
        var self = BlockhashQueue.DEFAULT;
        var timestamp: u64 = @intCast(std.time.milliTimestamp());

        for (0..max_list_entries) |_| {
            const hash = Hash.initRandom(random);

            const last_hash_index = self.last_hash_index + 1;

            if (self.hash_infos.count() >= self.max_age) try self.purge(last_hash_index);

            try self.hash_infos.put(allocator, hash, .{
                .index = last_hash_index,
                .timestamp = timestamp,
                .lamports_per_signature = random.int(u64),
            });

            self.last_hash_index = last_hash_index;
            self.last_hash = hash;

            timestamp += random.intRangeAtMost(u64, 1, 1_000_000);
        }

        return self;
    }

    pub fn initWithSingleEntry(
        allocator: Allocator,
        hash: Hash,
        lamports_per_signature: u64,
    ) Allocator.Error!BlockhashQueue {
        if (!builtin.is_test) @compileError("only for testing");
        return .{
            .last_hash = hash,
            .max_age = 0,
            .hash_infos = try .init(
                allocator,
                &.{hash},
                &.{.{
                    .index = 0,
                    .timestamp = 0,
                    .lamports_per_signature = lamports_per_signature,
                }},
            ),
            .last_hash_index = 0,
        };
    }
};

test "insert hash" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const max_age = 100;
    const last_hash = Hash.initRandom(prng.random());

    var queue = BlockhashQueue.init(max_age);
    defer queue.deinit(allocator);

    try std.testing.expect(!queue.isHashValidForAge(last_hash, max_age));

    try queue.insertHash(allocator, last_hash, 0);

    try std.testing.expect(queue.isHashValidForAge(last_hash, max_age));
    try std.testing.expectEqual(1, queue.last_hash_index);
}

test "reject old last hash" {
    const allocator = std.testing.allocator;

    const max_age = 100;

    var queue = BlockhashQueue.init(max_age);
    defer queue.deinit(allocator);

    for (0..102) |i| {
        const last_hash_i = Hash.ZEROES.extend(&[_]u8{@intCast(i)});
        try queue.insertHash(allocator, last_hash_i, 0);
    }

    const hash_0 = Hash.ZEROES.extend(&[_]u8{@intCast(0)});
    try std.testing.expect(!queue.isHashValidForAge(hash_0, max_age));
    try std.testing.expect(!queue.isHashValidForAge(hash_0, 0));

    const hash_1 = Hash.ZEROES.extend(&[_]u8{@intCast(1)});
    try std.testing.expect(queue.isHashValidForAge(hash_1, max_age));
    try std.testing.expect(!queue.isHashValidForAge(hash_1, 0));
}

test "queue init blockhash" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const last_hash = Hash.initRandom(prng.random());

    var queue = BlockhashQueue.init(100);
    defer queue.deinit(allocator);

    try queue.insertHash(allocator, last_hash, 0);

    try std.testing.expectEqual(last_hash, queue.last_hash.?);
    try std.testing.expect(queue.isHashValidForAge(last_hash, 0));
}

test "len" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const max_age = 10;

    var queue = BlockhashQueue.init(max_age);
    defer queue.deinit(allocator);

    try std.testing.expectEqual(0, queue.hash_infos.count());

    for (0..max_age) |_| {
        try queue.insertHash(allocator, Hash.initRandom(prng.random()), 0);
    }
    try std.testing.expectEqual(max_age, queue.hash_infos.count());

    // BlockhashQueue actually holds max age + 1 entries due to a historical 'off-by-one' error in agave
    try queue.insertHash(allocator, Hash.initRandom(prng.random()), 0);
    try std.testing.expectEqual(max_age + 1, queue.hash_infos.count());

    try queue.insertHash(allocator, Hash.initRandom(prng.random()), 0);
    try std.testing.expectEqual(max_age + 1, queue.hash_infos.count());
}

test "get hash age" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const max_age = 10;

    const hash_list = try allocator.alloc(Hash, max_age + 1);
    defer allocator.free(hash_list);
    for (hash_list) |*hash| hash.* = Hash.initRandom(prng.random());

    var queue = BlockhashQueue.init(max_age);
    defer queue.deinit(allocator);

    for (hash_list) |hash| {
        try std.testing.expectEqual(null, queue.getHashAge(hash));
    }

    for (hash_list) |hash| {
        try queue.insertHash(allocator, hash, 0);
    }

    var age: u64 = 0;
    var hash_list_iter = std.mem.reverseIterator(hash_list);
    while (hash_list_iter.next()) |hash| {
        try std.testing.expectEqual(age, queue.getHashAge(hash).?);
        age += 1;
    }

    try queue.insertHash(allocator, Hash.initRandom(prng.random()), 0);
    try std.testing.expectEqual(null, queue.getHashAge(hash_list[0]));
}

test "is hash valid for age" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const max_age = 10;

    const hash_list = try allocator.alloc(Hash, max_age + 1);
    defer allocator.free(hash_list);
    for (hash_list) |*hash| hash.* = Hash.initRandom(prng.random());

    var queue = BlockhashQueue.init(max_age);
    defer queue.deinit(allocator);

    for (hash_list) |hash| {
        try std.testing.expect(!queue.isHashValidForAge(hash, max_age));
    }

    for (hash_list) |hash| {
        try queue.insertHash(allocator, hash, 0);
    }

    for (hash_list) |hash| {
        try std.testing.expect(queue.isHashValidForAge(hash, max_age));
    }

    try std.testing.expect(queue.isHashValidForAge(hash_list[max_age], 0));
    try std.testing.expect(!queue.isHashValidForAge(hash_list[max_age - 1], 0));
}

test "get hash info if valid" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const max_age = 10;

    const hash_list = try allocator.alloc(Hash, max_age + 1);
    defer allocator.free(hash_list);
    for (hash_list) |*hash| hash.* = Hash.initRandom(prng.random());

    var queue = BlockhashQueue.init(max_age);
    defer queue.deinit(allocator);

    for (hash_list) |hash| {
        try std.testing.expectEqual(null, queue.getHashInfoIfValid(hash, max_age));
    }

    for (hash_list) |hash| {
        try queue.insertHash(allocator, hash, 0);
    }

    for (hash_list) |hash| {
        try std.testing.expectEqual(
            queue.hash_infos.get(hash),
            queue.getHashInfoIfValid(hash, max_age),
        );
    }

    try std.testing.expectEqual(
        queue.hash_infos.get(hash_list[max_age]),
        queue.getHashInfoIfValid(hash_list[max_age], 0),
    );
    try std.testing.expectEqual(
        null,
        queue.getHashInfoIfValid(hash_list[max_age - 1], 0),
    );
}

test "initialise with genesis hash" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const max_age = 2;
    const genesis_hash = Hash.initRandom(prng.random());

    var queue = BlockhashQueue.init(max_age);
    defer queue.deinit(allocator);

    try queue.insertGenesisHash(allocator, genesis_hash, 0);

    try std.testing.expectEqual(0, queue.last_hash_index);
    try std.testing.expectEqual(genesis_hash, queue.last_hash.?);
    try std.testing.expectEqual(1, queue.hash_infos.count());
    try std.testing.expect(queue.isHashValidForAge(genesis_hash, 0));
}
