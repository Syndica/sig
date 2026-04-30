const std = @import("std");
const lib = @import("lib.zig");

pub const io = @import("accounts_db/io.zig");
pub const Table = @import("accounts_db/table.zig").Table;

const tel = lib.telemetry;

const Pubkey = lib.solana.Pubkey;
const Epoch = lib.solana.Epoch;

pub const DbConfig = extern struct {
    file_path: [std.fs.max_path_bytes]u8,
    file_path_len: u32,
    memory_len: usize,
    memory: [0]u8, // VLA with memory_len allocated
};

pub const Account = extern struct {
    info: packed struct(u64) {
        executable: bool,
        data_len: u24,
        rent_epoch: u39,
    },
    pubkey: Pubkey,
    owner: Pubkey,
    lamports: u64,

    pub fn getRentEpoch(self: *const Account) Epoch {
        const epoch = self.info.rent_epoch;
        if (epoch == std.math.maxInt(@TypeOf(epoch))) return std.math.maxInt(Epoch);
        return epoch;
    }

    pub fn getExecutable(self: *const Account) bool {
        return self.info.executable;
    }

    pub fn getDataLength(self: *const Account) u32 {
        return self.info.data_len;
    }
};
