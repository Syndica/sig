const std = @import("std");
const lib = @import("lib");

pub const AccountPool = @import("pool.zig").AccountPool;

const Pubkey = lib.solana.Pubkey;
const Hash = lib.solana.Hash;
const Slot = lib.solana.Slot;

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

pub const RuntimeMetadata = extern struct {
    slot: std.atomic.Value(u64),
    blockhash_queue: extern struct {
        /// read after consuming all of hashes
        max_age: u64,
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
