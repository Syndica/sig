comptime {
    if (@import("builtin").is_test) {
        _ = @import("solana/bincode.zig");
        _ = @import("solana/cluster.zig");
        _ = @import("solana/epoch_schedule.zig");
        _ = @import("solana/features.zig");
        _ = @import("solana/hash.zig");
        _ = @import("solana/ids.zig");
        _ = @import("solana/leader_schedule.zig");
        _ = @import("solana/pubkey.zig");
        _ = @import("solana/signature.zig");
        _ = @import("solana/snapshot.zig");
    }
}

pub const bincode = @import("solana/bincode.zig");
pub const ids = @import("solana/ids.zig");
pub const features = @import("solana/features.zig");
pub const snapshot = @import("solana/snapshot.zig");
pub const transaction = @import("solana/transaction.zig");

pub const Hash = @import("solana/hash.zig").Hash;
pub const Pubkey = @import("solana/pubkey.zig").Pubkey;
pub const Signature = @import("solana/signature.zig").Signature;
pub const Cluster = @import("solana/cluster.zig").Cluster;
pub const LeaderSchedule = @import("solana/leader_schedule.zig").LeaderSchedule;
pub const EpochSchedule = @import("solana/epoch_schedule.zig").EpochSchedule;

pub const Lamports = u64;
pub const Nonce = u32;
pub const Slot = u64;
pub const Epoch = u64;

pub const time = struct {
    /// The default tick rate that the cluster attempts to achieve (160 per second).
    ///
    /// Note that the actual tick rate at any given time should be expected to drift.
    pub const DEFAULT_TICKS_PER_SECOND: u64 = 160;

    // At 160 ticks/s, 64 ticks per slot implies that leader rotation and voting will happen
    // every 400 ms. A fast voting cadence ensures faster finality and convergence
    pub const DEFAULT_TICKS_PER_SLOT: u64 = 64;

    pub const SECONDS_PER_DAY: u64 = 24 * 60 * 60;
    pub const TICKS_PER_DAY: u64 = DEFAULT_TICKS_PER_SECOND * SECONDS_PER_DAY;

    /// The number of slots per epoch after initial network warmup.
    /// 1 Epoch ~= 2 days.
    pub const DEFAULT_SLOTS_PER_EPOCH: u64 = 2 * TICKS_PER_DAY / DEFAULT_TICKS_PER_SLOT;
};
