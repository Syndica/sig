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
    cache: KeyStatusMap,
    roots: HashMap(Slot, void),
    /// all keys seen during a fork/slot
    slot_deltas: SlotDeltaMap,

    const CACHED_KEY_SIZE = 20;
    const KeySlice = [CACHED_KEY_SIZE]u8;
    const ForkStatus = ArrayList(Fork);

    const statusValElement = struct { key_slice: KeySlice, maybe_err: T };
    const StatusVal = ArrayList(statusValElement);
    // TODO: might be able to get rid of this RwMux, agave has one here
    const StatusKv = RwMux(HashMap(Hash, StatusVal));
    const KeyMap = HashMap(KeySlice, ForkStatus);

    const HighestFork = struct { slot: Slot, index: usize, key_map: KeyMap };

    const KeyStatusMap = HashMap(Hash, HighestFork);
    const SlotDeltaMap = HashMap(Slot, StatusKv);

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
        tx_blockhash: *const Hash,
        ancestors: *const Ancestors,
    ) ?Fork {
        const map = self.cache.get(tx_blockhash.*) orelse return null;

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
