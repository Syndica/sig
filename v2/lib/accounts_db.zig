const std = @import("std");
const lib = @import("lib.zig");

comptime {
    if (@import("builtin").is_test) {
        _ = @import("accounts_db/pool.zig");
        _ = @import("accounts_db/rooted.zig");
        _ = @import("accounts_db/table.zig");
        _ = @import("accounts_db/unrooted.zig");
    }
}

const Pubkey = lib.solana.Pubkey;
const Hash = lib.solana.Hash;
const Slot = lib.solana.Slot;

pub const AccountPool = @import("accounts_db/pool.zig").AccountPool;
pub const Unrooted = @import("accounts_db/unrooted.zig").Unrooted;
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

    /// Request-supplied id to match responses to requests.
    /// Opaque to accounts_db service, so it's usage is up to the callers.
    pub const RequestUserData = u32;

    pub const Request = extern struct {
        /// Opaque to accounts_db service, so it's usage is up to the callers.
        req_user_data: RequestUserData,
        pubkey: Pubkey,
    };

    pub const Result = extern struct {
        /// Matches the `req_user_data` field of the Request that this Result is responding to.
        req_user_data: RequestUserData,
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
