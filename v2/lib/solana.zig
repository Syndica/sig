const std = @import("std");

comptime {
    _ = std.testing.refAllDecls(@This());
}

pub const bincode = @import("solana/bincode.zig");
pub const gossip = @import("solana/gossip.zig");
pub const snapshot = @import("solana/snapshot.zig");

pub const Hash = @import("solana/hash.zig").Hash;
pub const Pubkey = @import("solana/pubkey.zig").Pubkey;
pub const Signature = @import("solana/signature.zig").Signature;
pub const Cluster = @import("solana/cluster.zig").Cluster;
pub const LeaderSchedule = @import("solana/leader_schedule.zig").LeaderSchedule;

pub const Lamports = u64;
pub const Nonce = u32;
pub const Slot = u64;
pub const Epoch = u64;

pub const SlotAndHash = extern struct {
    slot: Slot,
    hash: Hash,
};

pub const MAX_ACCOUNT_SIZE = 10 * 1024 * 1024;

// TODO: file with Blake3 impl
pub const LtHash = extern struct {
    _: [1024]u16,
};
