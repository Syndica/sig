const std = @import("std");
const sig = @import("../sig.zig");

const HashMap = std.AutoArrayHashMapUnmanaged;
const ArrayList = std.ArrayListUnmanaged;
const RwMux = sig.sync.RwMux;
const bincode = sig.bincode;

const Hash = sig.core.Hash;
const Slot = sig.core.Slot;

// StatusCache is only used with <Result<(), TransactionError>>
const T = ?sig.ledger.transaction_status.TransactionError;

const Fork = struct { slot: Slot, maybe_err: T = null };

/// [agave] https://github.com/anza-xyz/agave/blob/b6eacb135037ab1021683d28b67a3c60e9039010/runtime/src/status_cache.rs#L39
pub const StatusCache = struct {
    cache: HashMap(Hash, HighestFork),

    roots: HashMap(Slot, void),
    min_root: ?Slot,

    /// all keys seen during a fork/slot
    slot_deltas: HashMap(Slot, StatusKv),

    const CACHED_KEY_SIZE = 20;
    const Key = [CACHED_KEY_SIZE]u8;
    const ForkStatus = ArrayList(Fork);

    const StatusValues = ArrayList(struct { key: Key, maybe_err: T = null });
    // TODO: might be able to get rid of this RwMux, agave has one here
    const StatusKv = RwMux(HashMap(Hash, struct { key_index: usize, status: StatusValues }));
    const KeyMap = HashMap(Key, ForkStatus);

    const HighestFork = struct { slot: Slot, index: usize, key_map: KeyMap };

    const MAX_CACHE_ENTRIES = sig.accounts_db.snapshots.MAX_RECENT_BLOCKHASHES;

    pub fn default() StatusCache {
        return .{ .cache = .{}, .roots = .{}, .slot_deltas = .{}, .min_root = null };
    }

    pub fn deinit(self: *StatusCache, allocator: std.mem.Allocator) void {
        self.roots.deinit(allocator);

        for (self.cache.values()) |*highest_fork| {
            const highest_fork_map: *KeyMap = &highest_fork.key_map;
            for (highest_fork_map.values()) |*fork_status| {
                fork_status.deinit(allocator);
            }
            highest_fork_map.deinit(allocator);
        }
        self.cache.deinit(allocator);

        for (self.slot_deltas.values()) |*status_kv| {
            const status_map, var status_map_lg = status_kv.writeWithLock();
            defer status_map_lg.unlock();

            for (status_map.values()) |*value| {
                value.status.deinit(allocator);
            }
            status_map.deinit(allocator);
        }
        self.slot_deltas.deinit(allocator);
    }

    pub fn getStatus(
        self: *const StatusCache,
        key: []const u8,
        blockhash: *const Hash,
        ancestors: *const Ancestors,
    ) ?Fork {
        const map = self.cache.get(blockhash.*) orelse return null;

        const max_key_index = key.len -| (CACHED_KEY_SIZE + 1);
        const index = @min(map.index, max_key_index);

        const lookup_key: [CACHED_KEY_SIZE]u8 = key[index..][0..CACHED_KEY_SIZE].*;

        const stored_forks: ArrayList(Fork) = map.key_map.get(lookup_key) orelse return null;
        return for (stored_forks.items) |fork| {
            if (ancestors.ancestors.contains(fork.slot) or self.roots.contains(fork.slot)) {
                break fork;
            }
        } else null;
    }

    pub fn insert(
        self: *StatusCache,
        allocator: std.mem.Allocator,
        prng: std.Random,
        blockhash: *const Hash,
        key: []const u8,
        slot: Slot,
    ) error{OutOfMemory}!void {
        const max_key_index = key.len -| (CACHED_KEY_SIZE + 1);

        // Get the cache entry for this blockhash.
        const entry = try self.cache.getOrPut(allocator, blockhash.*);
        if (!entry.found_existing) {
            entry.key_ptr.* = blockhash.*;
            entry.value_ptr.* = .{
                .slot = slot,
                .index = prng.intRangeAtMost(usize, 0, max_key_index),
                .key_map = .{},
            };
        }

        const max_slot = &entry.value_ptr.slot;
        const key_index = @min(entry.value_ptr.index, max_key_index);
        const hash_map: *KeyMap = &entry.value_ptr.key_map;

        // Update the max slot observed to contain txs using this blockhash.
        max_slot.* = @max(max_slot.*, slot);

        const lookup_key: [CACHED_KEY_SIZE]u8 = key[key_index..][0..CACHED_KEY_SIZE].*;

        const forks = try hash_map.getOrPutValue(allocator, lookup_key, ForkStatus{});
        try forks.value_ptr.append(allocator, .{ .slot = slot });

        try self.addToSlotDelta(allocator, blockhash, slot, key_index, &lookup_key);
    }

    pub fn addRoot(self: *StatusCache, allocator: std.mem.Allocator, fork: Slot) !void {
        try self.roots.put(allocator, fork, {});

        self.min_root = if (self.min_root) |min_root|
            @min(min_root, fork)
        else
            fork;

        self.purgeRoots(allocator);
    }

    /// remove roots older than MAX_CACHE_ENTRIES
    pub fn purgeRoots(self: *StatusCache, allocator: std.mem.Allocator) void {
        if (self.roots.count() <= MAX_CACHE_ENTRIES) return;
        const min_root = self.min_root orelse return;

        _ = self.roots.orderedRemove(min_root);

        const cache_entries = self.cache.entries.slice();

        var n_removed: usize = 0;
        for (cache_entries.items(.key), cache_entries.items(.value), 0..) |key, highest_fork, i| {
            if (i >= cache_entries.len - n_removed) continue; // don't try to remove things twice!

            if (highest_fork.slot <= min_root) {
                var purged_fork: HighestFork = (self.cache.fetchOrderedRemove(key) orelse
                    unreachable).value; // we just found this key!

                for (purged_fork.key_map.values()) |*fork_status| fork_status.deinit(allocator);
                purged_fork.key_map.deinit(allocator);

                n_removed += 1;
            }
        }
    }

    // Add this key slice to the list of key slices for this slot and blockhash
    // combo.
    fn addToSlotDelta(
        self: *StatusCache,
        allocator: std.mem.Allocator,
        blockhash: *const Hash,
        slot: Slot,
        key_index: usize,
        key: *const [CACHED_KEY_SIZE]u8,
    ) error{OutOfMemory}!void {
        const fork_entry = try self.slot_deltas.getOrPutValue(allocator, slot, StatusKv.init(.{}));
        const fork: *StatusKv = fork_entry.value_ptr;
        {
            const fork_map, var fork_lg = fork.writeWithLock();
            defer fork_lg.unlock();

            const hash_entry = try fork_map.getOrPutValue(
                allocator,
                blockhash.*,
                .{ .status = .{}, .key_index = key_index },
            );
            const hash_entry_map: *StatusValues = &hash_entry.value_ptr.status;
            try hash_entry_map.append(allocator, .{ .key = key.* });
        }
    }
};

pub const Ancestors = struct {
    // agave uses a "RollingBitField" which seems to be just an optimisation for a set
    ancestors: Map = .{},

    pub const Map = HashMap(Slot, void);

    // For some reason, agave serializes Ancestors as HashMap(slot, usize). But deserializing
    // ignores the usize, and serializing just uses the value 0. So we need to serialize void
    // as if it's 0, and deserialize 0 as if it's void.
    pub const @"!bincode-config:ancestors" = bincode.hashmap.hashMapFieldConfig(
        Map,
        .{
            .key = .{},
            .value = .{ .serializer = voidSerialize, .deserializer = voidDeserialize },
        },
    );

    fn voidDeserialize(alloc: std.mem.Allocator, reader: anytype, params: bincode.Params) !void {
        _ = try bincode.read(alloc, usize, reader, params);
    }

    fn voidSerialize(writer: anytype, data: anytype, params: bincode.Params) !void {
        _ = data;
        try bincode.write(writer, @as(usize, 0), params);
    }

    pub fn clone(self: *const Ancestors, allocator: std.mem.Allocator) !Ancestors {
        return .{ .ancestors = try self.ancestors.clone(allocator) };
    }

    pub fn deinit(self: *Ancestors, allocator: std.mem.Allocator) void {
        self.ancestors.deinit(allocator);
    }
};

test "status cache (de)serialize Ancestors" {
    const allocator = std.testing.allocator;

    var ancestors: Ancestors = .{
        .ancestors = try Ancestors.Map.init(allocator, &.{ 1, 2, 3, 4 }, &.{}),
    };
    defer ancestors.deinit(allocator);

    const serialized = try bincode.writeAlloc(allocator, ancestors, .{});

    defer allocator.free(serialized);

    const deserialized = try bincode.readFromSlice(
        allocator,
        HashMap(Slot, usize),
        serialized,
        .{},
    );
    defer bincode.free(allocator, deserialized);

    try std.testing.expectEqual(ancestors.ancestors.count(), deserialized.count());
    try std.testing.expectEqualSlices(Slot, ancestors.ancestors.keys(), deserialized.keys());
    try std.testing.expectEqualSlices(usize, &.{ 0, 0, 0, 0 }, deserialized.values());
}

test "status cache empty" {
    const signature = sig.core.Signature.ZEROES;
    const block_hash = Hash.ZEROES;

    var status_cache = StatusCache.default();

    try std.testing.expectEqual(
        null,
        status_cache.getStatus(
            &signature.data,
            &block_hash,
            &Ancestors{},
        ),
    );
}

test "status cache find with ancestor fork" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);
    const random = prng.random();

    const signature = sig.core.Signature.ZEROES;
    const blockhash = Hash.ZEROES;

    var ancestors: Ancestors = .{
        .ancestors = try HashMap(Slot, void).init(allocator, &.{0}, &.{}),
    };
    defer ancestors.ancestors.deinit(allocator);

    var status_cache = StatusCache.default();
    defer status_cache.deinit(allocator);

    try status_cache.insert(allocator, random, &blockhash, &signature.data, 0);

    try std.testing.expectEqual(
        Fork{ .slot = 0 },
        status_cache.getStatus(&signature.data, &blockhash, &ancestors),
    );
}

test "status cache find without ancestor fork" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);
    const random = prng.random();

    const signature = sig.core.Signature.ZEROES;
    const blockhash = Hash.ZEROES;

    var ancestors: Ancestors = .{};

    var status_cache = StatusCache.default();
    defer status_cache.deinit(allocator);

    try status_cache.insert(allocator, random, &blockhash, &signature.data, 1);

    try std.testing.expectEqual(
        null,
        status_cache.getStatus(&signature.data, &blockhash, &ancestors),
    );
}

test "status cache find with root ancestor fork" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);
    const random = prng.random();

    const signature = sig.core.Signature.ZEROES;
    const blockhash = Hash.ZEROES;

    var ancestors: Ancestors = .{};

    var status_cache = StatusCache.default();
    defer status_cache.deinit(allocator);

    try status_cache.insert(allocator, random, &blockhash, &signature.data, 0);
    try status_cache.addRoot(allocator, 0);

    try std.testing.expectEqual(
        Fork{ .slot = 0 },
        status_cache.getStatus(&signature.data, &blockhash, &ancestors),
    );
}

test "status cache insert picks latest blockhash fork" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);
    const random = prng.random();

    const signature = sig.core.Signature.ZEROES;
    const blockhash = Hash.ZEROES;

    var ancestors: Ancestors = .{
        .ancestors = try HashMap(Slot, void).init(allocator, &.{0}, &.{}),
    };
    defer ancestors.ancestors.deinit(allocator);

    var status_cache = StatusCache.default();
    defer status_cache.deinit(allocator);

    try status_cache.insert(allocator, random, &blockhash, &signature.data, 0);
    try status_cache.insert(allocator, random, &blockhash, &signature.data, 1);

    for (0..StatusCache.MAX_CACHE_ENTRIES + 1) |i| try status_cache.addRoot(allocator, i);

    try std.testing.expect(
        status_cache.getStatus(&signature.data, &blockhash, &ancestors) != null,
    );
}

test "status cache root expires" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);
    const random = prng.random();

    const signature = sig.core.Signature.ZEROES;
    const blockhash = Hash.ZEROES;

    var ancestors: Ancestors = .{};

    var status_cache = StatusCache.default();
    defer status_cache.deinit(allocator);

    try status_cache.insert(allocator, random, &blockhash, &signature.data, 0);
    for (0..StatusCache.MAX_CACHE_ENTRIES + 1) |i| try status_cache.addRoot(allocator, i);

    try std.testing.expectEqual(
        null,
        status_cache.getStatus(&signature.data, &blockhash, &ancestors),
    );
}
