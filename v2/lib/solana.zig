comptime {
    if (@import("builtin").is_test) {
        _ = @import("solana/bincode.zig");
        _ = @import("solana/cluster.zig");
        _ = @import("solana/hash.zig");
        _ = @import("solana/leader_schedule.zig");
        _ = @import("solana/pubkey.zig");
        _ = @import("solana/signature.zig");
        _ = @import("solana/snapshot.zig");
    }
}

pub const bincode = @import("solana/bincode.zig");

pub const Hash = @import("solana/hash.zig").Hash;
pub const Pubkey = @import("solana/pubkey.zig").Pubkey;
pub const Signature = @import("solana/signature.zig").Signature;
pub const Cluster = @import("solana/cluster.zig").Cluster;
pub const LeaderSchedule = @import("solana/leader_schedule.zig").LeaderSchedule;
pub const snapshot = @import("solana/snapshot.zig");

pub const Lamports = u64;
pub const Nonce = u32;
pub const Slot = u64;
pub const Epoch = u64;
