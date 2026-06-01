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
const Slot = lib.solana.Slot;

pub const AccountPool = @import("accounts_db/pool.zig").AccountPool;
pub const Rooted = @import("accounts_db/rooted.zig").Rooted;
pub const Table = @import("accounts_db/table.zig").Table;

pub const RootedConfig = extern struct {
    file_len: u32,
    file_path: [std.fs.max_path_bytes]u8,
    memory_len: usize,
};

pub const TableLookups = extern struct {
    count: std.atomic.Value(u64),
    put: lib.ipc.Ring(put_cap, Request),
    get: extern struct {
        in: lib.ipc.Ring(get_cap, Pubkey),
        out: lib.ipc.Ring(get_cap, Table.Value),
    },

    const put_cap = 1 * 1024 * 1024;
    const get_cap = 256;

    pub const Request = extern struct {
        pubkey: Pubkey,
        slot: Slot,
        value: Table.Value,
    };

    pub fn init(self: *TableLookups) void {
        self.count = .init(0);
        self.put.init();
        self.get.in.init();
        self.get.out.init();
    }
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
