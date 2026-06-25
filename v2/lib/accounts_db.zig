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
    blockhash_queue: struct {
        max_age: u64,
        hashes: lib.ipc.Ring(256, Hash),
    },

    pub fn init(self: *RuntimeMetadata) void {
        self.blockhash_queue.max_age = 0;
        self.blockhash_queue.hashes.init();
    }
};