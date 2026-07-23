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
