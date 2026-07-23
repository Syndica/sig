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

/// How to consume this struct:
/// 1. read all ring buffers in the correct order (specify the correct order
///    here if more are added, currently there is only one: the blockhash queue)
/// 2. call getSlotBlocking
/// 3. read other fields
pub const RuntimeMetadata = extern struct {
    slot: std.atomic.Value(u64),
    /// The merkle root of the last fec set (tower) or the root of roots (alpenglow)
    block_id: Hash,
    blockhash_queue: extern struct {
        /// read after consuming all of hashes
        max_age: u64,
        /// Accountsdb blocks until enough hashes are read from here to make
        /// room for accountsdb to write all of its block hashes here.
        hashes: lib.ipc.Ring(256, Hash),
    },

    // 0 may be a valid slot, so use something that will never be reached.
    const invalid_slot = std.math.maxInt(Slot);

    pub fn init(self: *RuntimeMetadata) void {
        self.slot = .init(invalid_slot);

        self.blockhash_queue.max_age = 0;
        self.blockhash_queue.hashes.init();
    }

    /// Unblocks all getSlotBlocking() callers with the given slot value.
    /// Can be called only once.
    /// Should also only call after all other RuntimeMetadata fields are populated.
    pub fn populateSlot(self: *RuntimeMetadata, slot: Slot) void {
        std.debug.assert(slot != invalid_slot);
        std.debug.assert(self.slot.swap(slot, .release) == invalid_slot);
    }

    /// Accountsdb writes the slot last, so you need to empty all the ring
    /// buffers before calling this.
    pub fn getSlotBlocking(self: *RuntimeMetadata, runner: lib.runner.Connection) !Slot {
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

pub const StatusCacheUpdates = lib.ipc.Ring(512, StatusCacheUpdate);

pub const StatusCacheUpdate = extern struct {
    slot: Slot,
    is_root: bool,
    /// Null if the status map is empty.
    status_map_entry: StatusMapEntry,

    pub const StatusMapEntry = extern struct {
        hash: lib.solana.Hash,
        status: StatusEntry,

        pub const StatusEntry = extern struct {
            key_slice: [20]u8,
            is_ok: bool,
        };
    };

    const Header = lib.solana.snapshot.StatusCacheHeader;

    pub fn from(
        slot_delta: Header.SlotDeltaHeader,
        status_map_entry: Header.StatusMapEntryHeader,
        status_list_entry: Header.Status,
    ) StatusCacheUpdate {
        if (status_map_entry.key_index != 0) {
            std.debug.panic("Deprecated 'key_index' field is a non-zero value ({})", .{status_map_entry.key_index});
        }
        return .{
            .slot = slot_delta.slot,
            .is_root = slot_delta.is_root,
            .status_map_entry = .{
                .hash = status_map_entry.hash,
                .status = .{
                    .key_slice = status_list_entry.key_slice,
                    .is_ok = status_list_entry.result == .ok,
                },
            },
        };
    }
};
