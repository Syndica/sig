const crypto = @import("crypto.zig");

comptime {
    if (@import("builtin").is_test) {
        _ = @import("solana/bincode.zig");
        _ = @import("solana/cluster.zig");
        _ = @import("solana/leader_schedule.zig");
    }
}

pub const bincode = @import("solana/bincode.zig");

pub const Hash = crypto.Hash;
pub const Pubkey = crypto.Pubkey;
pub const Signature = crypto.Signature;
pub const Cluster = @import("solana/cluster.zig").Cluster;
pub const LeaderSchedule = @import("solana/leader_schedule.zig").LeaderSchedule;

pub const Lamports = u64;
pub const Nonce = u32;
pub const Slot = u64;
pub const Epoch = u64;
