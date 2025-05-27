const std = @import("std");
const sig = @import("../sig.zig");

const HashMap = std.AutoArrayHashMapUnmanaged;
const ArrayList = std.ArrayListUnmanaged;
const RwMux = sig.sync.RwMux;

// StatusCache is only used with <Result<(), TransactionError>>
const T = ?sig.ledger.transaction_status.TransactionError;
const Hash = sig.core.Hash;
const Slot = sig.core.Slot;

const Fork = struct { slot: Slot, maybe_err: T };

pub const StatusCache = struct {
    cache: HashMap(Hash, HighestFork),
    roots: HashMap(Slot, void),
    /// all keys seen during a fork/slot
    slot_deltas: HashMap(Slot, StatusKv),

    const CACHED_KEY_SIZE = 20;
    const KeySlice = [CACHED_KEY_SIZE]u8;
    const ForkStatus = ArrayList(Fork);

    const StatusVal = ArrayList(struct { key_slice: KeySlice, maybe_err: T });
    // TODO: might be able to get rid of this RwMux, agave has one here
    const StatusKv = RwMux(HashMap(Hash, StatusVal));
    const KeyMap = HashMap(KeySlice, ForkStatus);

    const HighestFork = struct { slot: Slot, index: usize, key_map: KeyMap };

    pub fn default(allocator: std.mem.Allocator) error{OutOfMemory}!StatusCache {
        const roots = try HashMap(Slot, void).init(allocator, &.{}, &.{});

        return .{
            .cache = .{},
            .roots = roots,
            .slot_deltas = .{},
        };
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
};

pub const Ancestors = struct {
    // agave uses a "RollingBitField" which seems to be just an optimisation for a set
    ancestors: HashMap(Slot, void) = .{},
};
