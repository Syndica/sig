const std = @import("std");
const tracy = @import("tracy");
const sig = @import("../sig.zig");

const HashMap = std.AutoArrayHashMapUnmanaged;
const ArrayList = std.ArrayListUnmanaged;
const RwMux = sig.sync.RwMux;
const bincode = sig.bincode;

const Hash = sig.core.Hash;
const Slot = sig.core.Slot;
const Ancestors = sig.core.Ancestors;

// StatusCache is only used with <Result<(), TransactionError>>
const T = ?sig.ledger.transaction_status.TransactionError;

const Fork = struct {
    slot: Slot,
    maybe_err: T = null,

    pub fn deinit(self: Fork, allocator: std.mem.Allocator) void {
        if (self.maybe_err) |err| {
            err.deinit(allocator);
        }
    }

    pub fn clone(self: *const Fork, allocator: std.mem.Allocator) !Fork {
        return .{
            .slot = self.slot,
            .maybe_err = if (self.maybe_err) |err| try err.clone(allocator) else null,
        };
    }
};

pub const Status = enum { pending, failed, succeeded };

/// This is internally locking and thread safe.
/// [agave] https://github.com/anza-xyz/agave/blob/b6eacb135037ab1021683d28b67a3c60e9039010/runtime/src/status_cache.rs#L39
pub const StatusCache = struct {
    state: RwMux(State),

    const State = struct {
        cache: HashMap(Hash, HighestFork),
        roots: HashMap(Slot, void),
        /// all keys seen during a fork/slot
        slot_deltas: HashMap(Slot, StatusKv),
    };

    const CACHED_KEY_SIZE = 20;
    const Key = [CACHED_KEY_SIZE]u8;
    const ForkStatus = ArrayList(Fork);

    const StatusValues = ArrayList(struct { key: Key, maybe_err: T = null });
    const StatusKv = HashMap(Hash, struct { key_index: usize, status: StatusValues });
    const KeyMap = HashMap(Key, ForkStatus);

    const HighestFork = struct { slot: Slot, index: usize, key_map: KeyMap };

    const MAX_CACHE_ENTRIES = sig.accounts_db.snapshot.data.MAX_RECENT_BLOCKHASHES;

    pub const DEFAULT = StatusCache{
        .state = .init(.{
            .cache = .empty,
            .roots = .empty,
            .slot_deltas = .empty,
        }),
    };

    fn deinitForks(allocator: std.mem.Allocator, fork_status: *ForkStatus) void {
        for (fork_status.items) |fork| {
            fork.deinit(allocator);
        }
        fork_status.deinit(allocator);
    }

    fn findVisibleFork(
        roots: *const HashMap(Slot, void),
        ancestors: *const Ancestors,
        stored_forks: ForkStatus,
    ) ?Fork {
        return for (stored_forks.items) |fork| {
            if (ancestors.ancestors.contains(fork.slot) or roots.contains(fork.slot)) {
                break fork;
            }
        } else null;
    }

    pub fn deinit(self: *StatusCache, allocator: std.mem.Allocator) void {
        var state = self.state.tryWrite() orelse
            @panic("attempted to deinit StatusCache while still in use");
        defer state.unlock();

        state.mut().roots.deinit(allocator);

        for (state.mut().cache.values()) |*highest_fork| {
            const highest_fork_map: *KeyMap = &highest_fork.key_map;
            for (highest_fork_map.values()) |*fork_status| {
                deinitForks(allocator, fork_status);
            }
            highest_fork_map.deinit(allocator);
        }
        state.mut().cache.deinit(allocator);

        for (state.mut().slot_deltas.values()) |*status_kv| {
            for (status_kv.values()) |*value| {
                value.status.deinit(allocator);
            }
            status_kv.deinit(allocator);
        }
        state.mut().slot_deltas.deinit(allocator);
    }

    /// Returns the fork for the given key and blockhash, if it exists and is in the ancestors or roots.
    /// The returned fork is owned by the caller, allocation only occurs if the inner transaction error
    /// contains an instruction error of the borsh variant which stores a heap string.
    fn getFork(
        self: *StatusCache,
        allocator: std.mem.Allocator,
        key: []const u8,
        blockhash: *const Hash,
        ancestors: *const Ancestors,
    ) !?Fork {
        const zone = tracy.Zone.init(@src(), .{ .name = "StatusCache.getFork" });
        defer zone.deinit();

        var state = self.state.read();
        defer state.unlock();

        const map = state.get().cache.get(blockhash.*) orelse return null;
        const lookup_key = cachedKeySlice(key, map.index);

        const stored_forks: ForkStatus = map.key_map.get(lookup_key) orelse return null;
        if (findVisibleFork(&state.get().roots, ancestors, stored_forks)) |fork| {
            return try fork.clone(allocator);
        }
        return null;
    }

    fn cachedKeySlice(key: []const u8, map_index: usize) [CACHED_KEY_SIZE]u8 {
        const max_key_index = key.len -| (CACHED_KEY_SIZE + 1);
        const index = @min(map_index, max_key_index);
        return key[index..][0..CACHED_KEY_SIZE].*;
    }

    pub fn getStatus(
        self: *StatusCache,
        key: []const u8,
        blockhash: *const Hash,
        ancestors: *const Ancestors,
    ) Status {
        const zone = tracy.Zone.init(@src(), .{ .name = "StatusCache.getStatus" });
        defer zone.deinit();

        var state = self.state.read();
        defer state.unlock();

        const map = state.get().cache.get(blockhash.*) orelse return .pending;
        const lookup_key = cachedKeySlice(key, map.index);

        const stored_forks: ArrayList(Fork) = map.key_map.get(lookup_key) orelse return .pending;
        return for (stored_forks.items) |fork| {
            if (ancestors.ancestors.contains(fork.slot) or state.get().roots.contains(fork.slot)) {
                break if (fork.maybe_err) |_| .failed else .succeeded;
            }
        } else .pending;
    }

    /// Like `getFork`, but iterates all blockhashes in the cache.
    /// Used when the caller doesn't know which blockhash the transaction used
    /// (e.g. RPC `getSignatureStatuses`).
    /// [agave] https://github.com/anza-xyz/agave/blob/b6eacb135037ab1021683d28b67a3c60e9039010/runtime/src/status_cache.rs#L146
    pub fn getForkAnyBlockhash(
        self: *StatusCache,
        allocator: std.mem.Allocator,
        key: []const u8,
        ancestors: *const Ancestors,
    ) !?Fork {
        const zone = tracy.Zone.init(@src(), .{ .name = "StatusCache.getForkAnyBlockhash" });
        defer zone.deinit();

        var state = self.state.read();
        defer state.unlock();

        for (state.get().cache.values()) |map| {
            const lookup_key = cachedKeySlice(key, map.index);

            const stored_forks: ArrayList(Fork) = map.key_map.get(lookup_key) orelse continue;
            for (stored_forks.items) |fork| {
                if (ancestors.ancestors.contains(fork.slot) or
                    state.get().roots.contains(fork.slot)) return try fork.clone(allocator);
            }
        }
        return null;
    }

    pub fn insert(
        self: *StatusCache,
        allocator: std.mem.Allocator,
        prng: std.Random,
        blockhash: *const Hash,
        key: []const u8,
        slot: Slot,
        maybe_err: T,
    ) error{OutOfMemory}!void {
        const zone = tracy.Zone.init(@src(), .{ .name = "StatusCache.insert" });
        defer zone.deinit();

        const max_key_index = key.len -| (CACHED_KEY_SIZE + 1);

        var state = self.state.write();
        defer state.unlock();

        // Get the cache entry for this blockhash.
        const entry = try state.mut().cache.getOrPut(allocator, blockhash.*);
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

        {
            const owned_err = if (maybe_err) |err| try err.clone(allocator) else null;
            errdefer if (owned_err) |err| err.deinit(allocator);

            const forks = try hash_map.getOrPutValue(allocator, lookup_key, .empty);
            try forks.value_ptr.append(allocator, .{ .slot = slot, .maybe_err = owned_err });
        }

        // Add this key slice to the list of key slices for this slot and blockhash combo.
        const fork_entry = try state.mut().slot_deltas.getOrPutValue(allocator, slot, .empty);
        const fork_map: *StatusKv = fork_entry.value_ptr;

        const hash_entry = try fork_map.getOrPutValue(
            allocator,
            blockhash.*,
            .{ .status = .{}, .key_index = key_index },
        );
        const hash_entry_map: *StatusValues = &hash_entry.value_ptr.status;
        try hash_entry_map.append(allocator, .{ .key = lookup_key, .maybe_err = maybe_err });
    }

    /// Returns the status-cache root slots as a sorted slice, allocated from `allocator`.
    /// In Agave this is `Bank::status_cache_ancestors()` and provides the recent
    /// ~150 rooted slots used for commitment aggregation.
    pub fn getSortedRoots(
        self: *StatusCache,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error![]Slot {
        var state = self.state.read();
        defer state.unlock();

        const roots = state.get().roots;
        const keys = roots.keys();
        const result = try allocator.alloc(Slot, keys.len);
        @memcpy(result, keys);
        std.mem.sort(Slot, result, {}, std.sort.asc(Slot));
        return result;
    }

    pub fn addRoot(self: *StatusCache, allocator: std.mem.Allocator, fork: Slot) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "StatusCache.addRoot" });
        defer zone.deinit();

        var state = self.state.write();
        defer state.unlock();

        const roots = &state.mut().roots;
        try roots.put(allocator, fork, {});

        // purgeRoot: when overflowing MAX_CACHE_ENTRIES, remove the smallest root slot from caches.
        if (roots.count() <= MAX_CACHE_ENTRIES) return;

        const min_root = blk: {
            var slot: ?Slot = null;
            for (roots.keys()) |rooted| slot = @min(rooted, slot orelse rooted);
            break :blk slot orelse return;
        };
        std.debug.assert(roots.swapRemove(min_root));

        {
            const cache = &state.mut().cache;
            var entries = cache.values();
            var i: usize = 0;

            while (i < cache.count()) {
                if (entries[i].slot <= min_root) {
                    var purged_fork_map = entries[i].key_map;
                    for (purged_fork_map.values()) |*fork_status| {
                        deinitForks(allocator, fork_status);
                    }
                    purged_fork_map.deinit(allocator);

                    cache.swapRemoveAt(i);
                    entries = cache.values();
                } else {
                    i += 1;
                }
            }
        }

        {
            const slot_deltas = &state.mut().slot_deltas;
            var entries = slot_deltas.entries.slice();
            var i: usize = 0;

            while (i < slot_deltas.count()) {
                if (entries.items(.key)[i] <= min_root) {
                    var status_kv = entries.items(.value)[i];
                    for (status_kv.values()) |*value| value.status.deinit(allocator);
                    status_kv.deinit(allocator);

                    slot_deltas.swapRemoveAt(i);
                    entries = slot_deltas.entries.slice();
                } else {
                    i += 1;
                }
            }
        }
    }
};

test "status cache (de)serialize Ancestors" {
    const allocator = std.testing.allocator;

    var ancestors = Ancestors{
        .ancestors = try .init(allocator, &.{ 1, 2, 3, 4 }, &.{}),
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

    var status_cache: StatusCache = .DEFAULT;

    try std.testing.expectEqual(
        null,
        try status_cache.getFork(
            std.testing.failing_allocator,
            &signature.toBytes(),
            &block_hash,
            &Ancestors{},
        ),
    );
}

test "status cache getForkAnyBlockhash finds across blockhashes" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const signature = sig.core.Signature.ZEROES;
    const blockhash = Hash.ZEROES;

    var ancestors: Ancestors = .{
        .ancestors = try HashMap(Slot, void).init(allocator, &.{0}, &.{}),
    };
    defer ancestors.ancestors.deinit(allocator);

    var status_cache: StatusCache = .DEFAULT;
    defer status_cache.deinit(allocator);

    try status_cache.insert(allocator, random, &blockhash, &signature.toBytes(), 0, null);

    // getForkAnyBlockhash should find it without needing the blockhash
    try std.testing.expectEqual(
        Fork{ .slot = 0 },
        try status_cache.getForkAnyBlockhash(
            std.testing.failing_allocator,
            &signature.toBytes(),
            &ancestors,
        ),
    );
}

test "status cache getForkAnyBlockhash returns null when empty" {
    const signature = sig.core.Signature.ZEROES;

    var status_cache: StatusCache = .DEFAULT;

    try std.testing.expectEqual(
        null,
        try status_cache.getForkAnyBlockhash(
            std.testing.failing_allocator,
            &signature.toBytes(),
            &Ancestors{},
        ),
    );
}

test "status cache getForkAnyBlockhash finds with root" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const signature = sig.core.Signature.ZEROES;
    const blockhash = Hash.ZEROES;

    var status_cache: StatusCache = .DEFAULT;
    defer status_cache.deinit(allocator);

    try status_cache.insert(allocator, random, &blockhash, &signature.toBytes(), 0, null);
    try status_cache.addRoot(allocator, 0);

    // Empty ancestors but root matches
    try std.testing.expectEqual(
        Fork{ .slot = 0 },
        try status_cache.getForkAnyBlockhash(
            std.testing.failing_allocator,
            &signature.toBytes(),
            &Ancestors{},
        ),
    );
}

test "status cache getForkAnyBlockhash returns null when fork does not match" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const signature = sig.core.Signature.ZEROES;
    const blockhash = Hash.ZEROES;

    // Ancestors contain slot 99, but the entry is stored at slot 5.
    var ancestors: Ancestors = .{
        .ancestors = try HashMap(Slot, void).init(allocator, &.{99}, &.{}),
    };
    defer ancestors.ancestors.deinit(allocator);

    var status_cache: StatusCache = .DEFAULT;
    defer status_cache.deinit(allocator);

    try status_cache.insert(allocator, random, &blockhash, &signature.toBytes(), 5, null);

    // Stored fork (slot 5) is neither in ancestors nor roots → should return null.
    try std.testing.expectEqual(
        null,
        try status_cache.getForkAnyBlockhash(
            std.testing.failing_allocator,
            &signature.toBytes(),
            &ancestors,
        ),
    );
}

test "status cache find with ancestor fork" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const signature = sig.core.Signature.ZEROES;
    const blockhash = Hash.ZEROES;

    var ancestors: Ancestors = .{
        .ancestors = try HashMap(Slot, void).init(allocator, &.{0}, &.{}),
    };
    defer ancestors.ancestors.deinit(allocator);

    var status_cache: StatusCache = .DEFAULT;
    defer status_cache.deinit(allocator);

    try status_cache.insert(allocator, random, &blockhash, &signature.toBytes(), 0, null);

    try std.testing.expectEqual(
        Fork{ .slot = 0 },
        try status_cache.getFork(
            std.testing.failing_allocator,
            &signature.toBytes(),
            &blockhash,
            &ancestors,
        ),
    );
}

test "status cache find without ancestor fork" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const signature = sig.core.Signature.ZEROES;
    const blockhash = Hash.ZEROES;

    var ancestors: Ancestors = .{};

    var status_cache: StatusCache = .DEFAULT;
    defer status_cache.deinit(allocator);

    try status_cache.insert(allocator, random, &blockhash, &signature.toBytes(), 1, null);

    try std.testing.expectEqual(
        null,
        try status_cache.getFork(
            std.testing.failing_allocator,
            &signature.toBytes(),
            &blockhash,
            &ancestors,
        ),
    );
}

test "status cache find with root ancestor fork" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const signature = sig.core.Signature.ZEROES;
    const blockhash = Hash.ZEROES;

    var ancestors: Ancestors = .{};

    var status_cache: StatusCache = .DEFAULT;
    defer status_cache.deinit(allocator);

    try status_cache.insert(allocator, random, &blockhash, &signature.toBytes(), 0, null);
    try status_cache.addRoot(allocator, 0);

    try std.testing.expectEqual(
        Fork{ .slot = 0 },
        try status_cache.getFork(
            std.testing.failing_allocator,
            &signature.toBytes(),
            &blockhash,
            &ancestors,
        ),
    );
}

test "status cache insert picks latest blockhash fork" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const signature = sig.core.Signature.ZEROES;
    const blockhash = Hash.ZEROES;

    var ancestors: Ancestors = .{
        .ancestors = try HashMap(Slot, void).init(allocator, &.{0}, &.{}),
    };
    defer ancestors.ancestors.deinit(allocator);

    var status_cache: StatusCache = .DEFAULT;
    defer status_cache.deinit(allocator);

    try status_cache.insert(allocator, random, &blockhash, &signature.toBytes(), 0, null);
    try status_cache.insert(allocator, random, &blockhash, &signature.toBytes(), 1, null);

    for (0..StatusCache.MAX_CACHE_ENTRIES + 1) |i| try status_cache.addRoot(allocator, i);

    try std.testing.expect(try status_cache.getFork(
        std.testing.failing_allocator,
        &signature.toBytes(),
        &blockhash,
        &ancestors,
    ) != null);
}

test "status cache root expires" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const signature = sig.core.Signature.ZEROES;
    const blockhash = Hash.ZEROES;

    var ancestors: Ancestors = .{};

    var status_cache: StatusCache = .DEFAULT;
    defer status_cache.deinit(allocator);

    try status_cache.insert(allocator, random, &blockhash, &signature.toBytes(), 0, null);
    for (0..StatusCache.MAX_CACHE_ENTRIES + 1) |i| try status_cache.addRoot(allocator, i);

    try std.testing.expectEqual(
        null,
        try status_cache.getFork(
            std.testing.failing_allocator,
            &signature.toBytes(),
            &blockhash,
            &ancestors,
        ),
    );
}

test "status cache any-blockhash lookup sees rooted entries and evicts old roots" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const signature = sig.core.Signature.ZEROES;
    const blockhash = Hash.ZEROES;

    var ancestors: Ancestors = .{};

    var status_cache: StatusCache = .DEFAULT;
    defer status_cache.deinit(allocator);

    try status_cache.insert(allocator, random, &blockhash, &signature.toBytes(), 0, null);
    try status_cache.addRoot(allocator, 0);

    try std.testing.expectEqual(
        Fork{ .slot = 0 },
        try status_cache.getForkAnyBlockhash(allocator, &signature.toBytes(), &ancestors),
    );

    for (1..StatusCache.MAX_CACHE_ENTRIES + 2) |i| try status_cache.addRoot(allocator, i);

    try std.testing.expectEqual(
        null,
        try status_cache.getForkAnyBlockhash(allocator, &signature.toBytes(), &ancestors),
    );
}

test "status cache retains transaction errors for any-blockhash lookup" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const signature = sig.core.Signature.ZEROES;
    const blockhash = Hash.ZEROES;
    var ancestors = try Ancestors.initWithSlots(allocator, &.{9});
    defer ancestors.deinit(allocator);

    const borsh_io = try allocator.dupe(u8, "borsh io");
    var tx_err: sig.ledger.transaction_status.TransactionError = .{
        .InstructionError = .{ 7, .{ .BorshIoError = borsh_io } },
    };
    defer tx_err.deinit(allocator);

    var status_cache: StatusCache = .DEFAULT;
    defer status_cache.deinit(allocator);

    try status_cache.insert(allocator, random, &blockhash, &signature.toBytes(), 9, tx_err);

    const maybe_got = try status_cache.getForkAnyBlockhash(
        allocator,
        &signature.toBytes(),
        &ancestors,
    );
    try std.testing.expect(maybe_got != null);
    const got = maybe_got.?;
    defer got.deinit(allocator);
    try std.testing.expectEqual(@as(Slot, 9), got.slot);
    try std.testing.expect(got.maybe_err != null);

    switch (got.maybe_err.?) {
        .InstructionError => |instruction_err| {
            try std.testing.expectEqual(@as(u8, 7), instruction_err[0]);
            try std.testing.expectEqualStrings("borsh io", instruction_err[1].BorshIoError);
        },
        else => try std.testing.expect(false),
    }
}

test "status cache insert and retrieve with transaction error" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const signature = sig.core.Signature.ZEROES;
    const blockhash = Hash.ZEROES;

    var ancestors: Ancestors = .{
        .ancestors = try HashMap(Slot, void).init(allocator, &.{0}, &.{}),
    };
    defer ancestors.ancestors.deinit(allocator);

    var status_cache: StatusCache = .DEFAULT;
    defer status_cache.deinit(allocator);

    const tx_err: sig.ledger.transaction_status.TransactionError = .AccountNotFound;
    try status_cache.insert(allocator, random, &blockhash, &signature.toBytes(), 0, tx_err);

    const result = try status_cache.getFork(
        std.testing.failing_allocator,
        &signature.toBytes(),
        &blockhash,
        &ancestors,
    );
    try std.testing.expect(result != null);
    try std.testing.expectEqual(@as(Slot, 0), result.?.slot);
    try std.testing.expectEqual(tx_err, result.?.maybe_err.?);

    const result2 = try status_cache.getForkAnyBlockhash(
        std.testing.failing_allocator,
        &signature.toBytes(),
        &ancestors,
    );
    try std.testing.expect(result2 != null);
    try std.testing.expectEqual(tx_err, result2.?.maybe_err.?);
}
