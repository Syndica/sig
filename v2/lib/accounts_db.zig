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
        account_index: AccountPool.Index, // .invalid_index if not found
    };

    pub fn init(self: *AccountLookups) void {
        self.in.init();
        self.out.init();
    }
};

pub const RuntimeMetadata = struct {
    slot: std.atomic.Value(u64),
    blockhash_queue: struct {
        max_age: u64, // read after consuming all of hashes
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
        std.debug.assert(self.slot.swap(invalid_slot, .release) == invalid_slot);
    }

    pub fn getSlotBlocking(self: *RuntimeMetadata, runner: lib.runner.Connection) !Slot {
        const slot = while (true) {
            const slot = self.slot.load(.acquire);
            if (slot != invalid_slot) break slot;
            try runner.activity.signalIdleSpinning(); 
        };

        try runner.activity.signalActive();
        return slot;
    }
};