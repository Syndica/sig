const std = @import("std");
const lib = @import("lib.zig");

pub const io = @import("accounts_db/io.zig");
pub const Table = @import("accounts_db/table.zig").Table;
pub const Rooted = @import("accounts_db/rooted.zig").Rooted;
pub const AccountPool = @import("accounts_db/pool.zig").Pool;

const tel = lib.telemetry;

const Pubkey = lib.solana.Pubkey;
const Epoch = lib.solana.Epoch;
const Slot = lib.solana.Slot;

pub const DbConfig = extern struct {
    file_path: [std.fs.max_path_bytes]u8,
    file_path_len: u32,
    memory_len: usize,
    memory: [0]u8, // VLA with memory_len allocated
};

pub const Account = extern struct {
    info: packed struct(u64) {
        valid: bool,
        executable: bool,
        data_len: u24,
        rent_epoch: u38,
    } align(1),
    pubkey: Pubkey align(1),
    owner: Pubkey align(1),
    lamports: u64 align(1),
    slot: u32 align(1),

    pub inline fn init(
        pubkey: *const Pubkey,
        owner: *const Pubkey,
        lamports: u64,
        slot: Slot,
        rent_epoch: Epoch,
        data_len: usize,
        executable: bool,
    ) Account {
        std.debug.assert(data_len <= 10 * 1024 * 1024);
        return .{
            .info = .{
                .valid = true,
                .executable = executable,
                .data_len = @intCast(data_len),
                .rent_epoch = std.math.lossyCast(u38, rent_epoch),
            },
            .pubkey = pubkey.*,
            .owner = owner.*,
            .lamports = lamports,
            .slot = @intCast(slot),
        };
    }

    /// Invalid accounts are used for disk page padding inside accounts_db.
    pub inline fn initInvalid(data_len: u24) Account {
        return .{
            .info = .{
                .valid = false,
                .executable = false,
                .data_len = data_len,
                .rent_epoch = 0,
            },
            .pubkey = .ZEROES,
            .owner = .ZEROES,
            .lamports = 0,
            .slot = 0,
        };
    }

    pub fn getRentEpoch(self: *const Account) Epoch {
        std.debug.assert(self.info.valid);
        const epoch = self.info.rent_epoch;
        if (epoch == std.math.maxInt(@TypeOf(epoch))) return std.math.maxInt(Epoch);
        return epoch;
    }

    pub fn getExecutable(self: *const Account) bool {
        std.debug.assert(self.info.valid);
        return self.info.executable;
    }

    pub fn getDataLength(self: *const Account) u32 {
        std.debug.assert(self.info.valid);
        return self.info.data_len;
    }
};
