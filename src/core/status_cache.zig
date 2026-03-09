const std = @import("std");
const tracy = @import("tracy");
const sig = @import("../sig.zig");

const HashMap = std.AutoArrayHashMapUnmanaged;
const ArrayList = std.ArrayListUnmanaged;
const RwMux = sig.sync.RwMux;
const bincode = sig.bincode;

const Hash = sig.core.Hash;
const Signature = sig.core.Signature;
const Slot = sig.core.Slot;
const Ancestors = sig.core.Ancestors;

// StatusCache is only used with <Result<(), TransactionError>>
const T = ?sig.ledger.transaction_status.TransactionError;

const Fork = struct { slot: Slot, maybe_err: T = null };

/// This is internally locking and thread safe.
/// [agave] https://github.com/anza-xyz/agave/blob/b6eacb135037ab1021683d28b67a3c60e9039010/runtime/src/status_cache.rs#L39
pub const StatusCache = struct {
    /// Replay validation state (duplicate transaction detection).
    state: RwMux(State),
    /// RPC state for `getSignatureStatuses` lookups (separate lock to avoid contention).
    rpc_state: RwMux(RpcState),

    const State = struct {
        cache: HashMap(Hash, HighestFork),
        roots: HashMap(Slot, void),
        /// all keys seen during a fork/slot
        slot_deltas: HashMap(Slot, StatusKv),
    };

    const RpcState = struct {
        /// Signature → status entry.
        entries: HashMap(Signature, Fork),
        /// Slot → list of signatures in that slot (for slot-based eviction).
        slot_sigs: HashMap(Slot, ArrayList(Signature)),
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
        .rpc_state = .init(.{
            .entries = .empty,
            .slot_sigs = .empty,
        }),
    };

    pub fn deinit(self: *StatusCache, allocator: std.mem.Allocator) void {
        {
            var state = self.state.tryWrite() orelse
                @panic("attempted to deinit StatusCache while still in use");
            defer state.unlock();

            state.mut().roots.deinit(allocator);

            for (state.mut().cache.values()) |*highest_fork| {
                const highest_fork_map: *KeyMap = &highest_fork.key_map;
                for (highest_fork_map.values()) |*fork_status| {
                    fork_status.deinit(allocator);
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

        {
            var rpc = self.rpc_state.tryWrite() orelse
                @panic("attempted to deinit StatusCache rpc_state while still in use");
            defer rpc.unlock();
            const s = rpc.mut();

            for (s.slot_sigs.values()) |*sigs| {
                sigs.deinit(allocator);
            }
            s.slot_sigs.deinit(allocator);
            s.entries.deinit(allocator);
        }
    }

    pub fn getStatus(
        self: *StatusCache,
        key: []const u8,
        blockhash: *const Hash,
        ancestors: *const Ancestors,
    ) ?Fork {
        const zone = tracy.Zone.init(@src(), .{ .name = "StatusCache.getStatus" });
        defer zone.deinit();

        var state = self.state.read();
        defer state.unlock();

        const map = state.get().cache.get(blockhash.*) orelse return null;

        const max_key_index = key.len -| (CACHED_KEY_SIZE + 1);
        const index = @min(map.index, max_key_index);

        const lookup_key: [CACHED_KEY_SIZE]u8 = key[index..][0..CACHED_KEY_SIZE].*;

        const stored_forks: ArrayList(Fork) = map.key_map.get(lookup_key) orelse return null;
        return for (stored_forks.items) |fork| {
            if (ancestors.ancestors.contains(fork.slot) or state.get().roots.contains(fork.slot)) {
                break fork;
            }
        } else null;
    }

    /// Look up a recent transaction status by signature (called from RPC thread).
    /// Returns `null` if the signature is not in the cache (either too old or never seen).
    pub fn getTransactionStatus(self: *StatusCache, signature: Signature) ?Fork {
        var guard = self.rpc_state.read();
        defer guard.unlock();
        return guard.get().entries.get(signature);
    }

    /// Insert a transaction signature into both the replay validation cache and the
    /// RPC status cache.
    pub fn insertSignature(
        self: *StatusCache,
        allocator: std.mem.Allocator,
        prng: std.Random,
        blockhash: *const Hash,
        signature: Signature,
        slot: Slot,
        err: T,
    ) !void {
        {
            const zone = tracy.Zone.init(
                @src(),
                .{ .name = "status_cache.insert: signature.toBytes()" },
            );
            defer zone.deinit();
            try self.insert(allocator, prng, blockhash, &signature.toBytes(), slot);
        }

        var guard = self.rpc_state.write();
        defer guard.unlock();
        const s = guard.mut();

        try s.entries.put(allocator, signature, .{ .slot = slot, .maybe_err = err });

        const slot_list = try s.slot_sigs.getOrPutValue(allocator, slot, .empty);
        try slot_list.value_ptr.append(allocator, signature);
    }

    pub fn insert(
        self: *StatusCache,
        allocator: std.mem.Allocator,
        prng: std.Random,
        blockhash: *const Hash,
        key: []const u8,
        slot: Slot,
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

        const forks = try hash_map.getOrPutValue(allocator, lookup_key, .empty);
        try forks.value_ptr.append(allocator, .{ .slot = slot });

        // Add this key slice to the list of key slices for this slot and blockhash combo.
        const fork_entry = try state.mut().slot_deltas.getOrPutValue(allocator, slot, .empty);
        const fork_map: *StatusKv = fork_entry.value_ptr;

        const hash_entry = try fork_map.getOrPutValue(
            allocator,
            blockhash.*,
            .{ .status = .{}, .key_index = key_index },
        );
        const hash_entry_map: *StatusValues = &hash_entry.value_ptr.status;
        try hash_entry_map.append(allocator, .{ .key = lookup_key });
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
                    for (purged_fork_map.values()) |*fork_status| fork_status.deinit(allocator);
                    purged_fork_map.deinit(allocator);

                    cache.swapRemoveAt(i);
                    entries = cache.values();
                } else {
                    i += 1;
                }
            }
        }

        {
            var rpc = self.rpc_state.write();
            defer rpc.unlock();
            const rpc_s = rpc.mut();

            const slot_deltas = &state.mut().slot_deltas;
            var entries = slot_deltas.entries.slice();
            var i: usize = 0;

            while (i < slot_deltas.count()) {
                const evicted_slot = entries.items(.key)[i];
                if (evicted_slot <= min_root) {
                    var status_kv = entries.items(.value)[i];
                    for (status_kv.values()) |*value| value.status.deinit(allocator);
                    status_kv.deinit(allocator);

                    slot_deltas.swapRemoveAt(i);
                    entries = slot_deltas.entries.slice();

                    // Evict matching RPC state for this slot.
                    if (rpc_s.slot_sigs.fetchSwapRemove(evicted_slot)) |kv| {
                        var sigs = kv.value;
                        for (sigs.items) |sig_key| _ = rpc_s.entries.swapRemove(sig_key);
                        sigs.deinit(allocator);
                    }
                } else {
                    i += 1;
                }
            }

            // Clean up any orphaned RPC slots not present in slot_deltas.
            var j: usize = 0;
            while (j < rpc_s.slot_sigs.count()) {
                if (rpc_s.slot_sigs.keys()[j] > min_root) {
                    j += 1;
                    continue;
                }

                var sigs = rpc_s.slot_sigs.values()[j];
                for (sigs.items) |sig_key| _ = rpc_s.entries.swapRemove(sig_key);
                sigs.deinit(allocator);
                rpc_s.slot_sigs.swapRemoveAt(j);
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
        status_cache.getStatus(
            &signature.toBytes(),
            &block_hash,
            &Ancestors{},
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

    try status_cache.insert(allocator, random, &blockhash, &signature.toBytes(), 0);

    try std.testing.expectEqual(
        Fork{ .slot = 0 },
        status_cache.getStatus(&signature.toBytes(), &blockhash, &ancestors),
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

    try status_cache.insert(allocator, random, &blockhash, &signature.toBytes(), 1);

    try std.testing.expectEqual(
        null,
        status_cache.getStatus(&signature.toBytes(), &blockhash, &ancestors),
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

    try status_cache.insert(allocator, random, &blockhash, &signature.toBytes(), 0);
    try status_cache.addRoot(allocator, 0);

    try std.testing.expectEqual(
        Fork{ .slot = 0 },
        status_cache.getStatus(&signature.toBytes(), &blockhash, &ancestors),
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

    try status_cache.insert(allocator, random, &blockhash, &signature.toBytes(), 0);
    try status_cache.insert(allocator, random, &blockhash, &signature.toBytes(), 1);

    for (0..StatusCache.MAX_CACHE_ENTRIES + 1) |i| try status_cache.addRoot(allocator, i);

    try std.testing.expect(
        status_cache.getStatus(&signature.toBytes(), &blockhash, &ancestors) != null,
    );
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

    try status_cache.insert(allocator, random, &blockhash, &signature.toBytes(), 0);
    for (0..StatusCache.MAX_CACHE_ENTRIES + 1) |i| try status_cache.addRoot(allocator, i);

    try std.testing.expectEqual(
        null,
        status_cache.getStatus(&signature.toBytes(), &blockhash, &ancestors),
    );
}

test "RpcState: insert and get transaction status" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    const blockhash = Hash.ZEROES;

    var cache: StatusCache = .DEFAULT;
    defer cache.deinit(allocator);

    const sig1 = Signature.fromBytes([_]u8{1} ** 64);
    const sig2 = Signature.fromBytes([_]u8{2} ** 64);

    try cache.insertSignature(allocator, random, &blockhash, sig1, 100, null);
    try cache.insertSignature(allocator, random, &blockhash, sig2, 100, null);

    const entry1 = cache.getTransactionStatus(sig1).?;
    try std.testing.expectEqual(@as(Slot, 100), entry1.slot);
    try std.testing.expect(entry1.maybe_err == null);

    const entry2 = cache.getTransactionStatus(sig2).?;
    try std.testing.expectEqual(@as(Slot, 100), entry2.slot);

    const sig3 = Signature.fromBytes([_]u8{3} ** 64);
    try std.testing.expect(cache.getTransactionStatus(sig3) == null);
}

test "RpcState: addRoot evicts old transaction statuses" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    const blockhash = Hash.ZEROES;

    var cache: StatusCache = .DEFAULT;
    defer cache.deinit(allocator);

    const sig1 = Signature.fromBytes([_]u8{1} ** 64);
    const sig2 = Signature.fromBytes([_]u8{2} ** 64);
    const sig3 = Signature.fromBytes([_]u8{3} ** 64);

    try cache.insertSignature(allocator, random, &blockhash, sig1, 0, null);
    try cache.insertSignature(allocator, random, &blockhash, sig2, 1, null);
    try cache.insertSignature(allocator, random, &blockhash, sig3, 2, null);

    // Add enough roots to trigger eviction of slot 0.
    for (0..StatusCache.MAX_CACHE_ENTRIES + 1) |i| try cache.addRoot(allocator, i);

    try std.testing.expect(cache.getTransactionStatus(sig1) == null);
    try std.testing.expect(cache.getTransactionStatus(sig2) != null);
    try std.testing.expect(cache.getTransactionStatus(sig3) != null);
}

test "RpcState: orphaned slot_sigs are cleaned up by addRoot" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    const blockhash = Hash.ZEROES;

    var cache: StatusCache = .DEFAULT;
    defer cache.deinit(allocator);

    const sig1 = Signature.fromBytes([_]u8{1} ** 64);

    // Insert into rpc_state only (bypassing slot_deltas) to simulate an orphan.
    {
        var rpc = cache.rpc_state.write();
        defer rpc.unlock();
        const s = rpc.mut();
        try s.entries.put(allocator, sig1, .{ .slot = 0, .maybe_err = null });
        const slot_list = try s.slot_sigs.getOrPutValue(allocator, 0, .empty);
        try slot_list.value_ptr.append(allocator, sig1);
    }

    // Verify the orphan is visible.
    try std.testing.expect(cache.getTransactionStatus(sig1) != null);

    // Fill roots with slots 1..MAX_CACHE_ENTRIES+1 to trigger eviction of slot 0.
    // Start at 1 so slot 0 never appears in slot_deltas, keeping the orphan truly orphaned.
    for (1..StatusCache.MAX_CACHE_ENTRIES + 2) |i| {
        try cache.insert(
            allocator,
            random,
            &blockhash,
            &(Signature.fromBytes([_]u8{0} ** 64)).toBytes(),
            i,
        );
        try cache.addRoot(allocator, i);
    }

    // The orphaned rpc_state entry for slot 0 should be cleaned up.
    try std.testing.expect(cache.getTransactionStatus(sig1) == null);

    // Verify both slot_sigs and entries are cleaned up.
    {
        var rpc = cache.rpc_state.read();
        defer rpc.unlock();
        try std.testing.expect(rpc.get().slot_sigs.get(0) == null);
        try std.testing.expect(rpc.get().entries.get(sig1) == null);
    }
}
