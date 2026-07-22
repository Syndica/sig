const std = @import("std");
const lib = @import("lib.zig");

comptime {
    if (@import("builtin").is_test) {
        _ = @import("accounts_db/pool.zig");
        _ = @import("accounts_db/rooted.zig");
        _ = @import("accounts_db/table.zig");
    }
}

const Pubkey = lib.solana.Pubkey;
const Epoch = lib.solana.Epoch;
const Hash = lib.solana.Hash;
const Slot = lib.solana.Slot;

pub const AccountPool = @import("accounts_db/pool.zig").AccountPool;
pub const Rooted = @import("accounts_db/rooted.zig").Rooted;
pub const Table = @import("accounts_db/table.zig").Table;

pub const RootedConfig = extern struct {
    file_len: u32,
    file_path: [std.fs.max_path_bytes]u8,

    memory_len: usize,
    memory: [0]u8, // VLA for [0..memory_len]
};

pub const AccountLookups = extern struct {
    in: lib.ipc.Ring(256, Request),
    out: lib.ipc.Ring(256, Result),

    pub const Request = Pubkey;
    pub const Result = extern struct {
        pubkey: Pubkey,
        account_index: AccountPool.AccountRef, // .invalid if not found
    };

    pub fn init(self: *AccountLookups) void {
        self.in.init();
        self.out.init();
    }
};

/// A deserialized snapshot Manifest + StatusCache.
///
/// All variable-sized data (blockhash queue is fixed at 300 entries inline;
/// pubkey maps, vote-account chains, etc.) points into the trailing `memory` (manifestBase)
/// VLA via `snapshot.RelativeSlice` / `snapshot.RelativeOffset`.
///
/// Before a consumer reads the fields, it must call `getSlotBlocking()`.
/// The producer that sets the fields will call `populateSlot()` to mark them as consumable.
pub const SnapshotMetadata = extern struct {
    slot: std.atomic.Value(u64),

    manifest: lib.solana.snapshot.Manifest,
    status_cache: lib.solana.snapshot.StatusCache,

    memory_len: usize,
    memory: [0]u8 align(16), // VLA for [0..memory_len]

    // 0 may be a valid slot, so use something that will never be reached.
    const invalid_slot = std.math.maxInt(Slot);

    pub fn init(self: *SnapshotMetadata, memory_len: usize) void {
        self.slot = .init(invalid_slot);
        self.memory_len = memory_len;
    }

    /// Returns the base pointer used to resolve `RelativeSlice`/`RelativeOffset`
    /// values inside `manifest` / `status_cache`.
    pub fn manifestBase(self: *SnapshotMetadata) [*]u8 {
        return @ptrCast(&self.memory);
    }

    /// Unblocks all getSlotBlocking() callers with the given slot value.
    /// Can be called only once.
    /// Should also only call after all other SnapshotMetadata fields are populated.
    pub fn populateSlot(self: *SnapshotMetadata, slot: Slot) void {
        std.debug.assert(slot != invalid_slot);
        std.debug.assert(self.slot.swap(slot, .release) == invalid_slot);
    }

    pub fn getSlotBlocking(self: *SnapshotMetadata, runner: lib.runner.Connection) !Slot {
        while (true) {
            const slot = self.slot.load(.acquire);
            if (slot != invalid_slot) {
                try runner.activity.signalActive();
                return slot;
            }
            try runner.activity.signalIdleSpinning();
        }
    }
};
