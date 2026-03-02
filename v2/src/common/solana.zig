const std = @import("std");

test {
    _ = std.testing.refAllDecls(@This());
}

pub const Hash = @import("solana/hash.zig").Hash;
pub const Pubkey = @import("solana/pubkey.zig").Pubkey;
pub const Signature = @import("solana/signature.zig").Signature;
pub const LeaderSchedule = @import("solana/leader_schedule.zig").LeaderSchedule;

pub const Lamports = u64;
pub const Nonce = u32;
pub const Slot = u64;
pub const Epoch = u64;

pub const Cluster = enum(u8) {
    testnet,
    devnet,
    mainnet,

    pub fn getGossipEntrypoints(self: Cluster) []const []const u8 {
        return switch (self) {
            .mainnet => &.{
                "entrypoint.mainnet-beta.solana.com:8001",
                "entrypoint2.mainnet-beta.solana.com:8001",
                "entrypoint3.mainnet-beta.solana.com:8001",
                "entrypoint4.mainnet-beta.solana.com:8001",
                "entrypoint5.mainnet-beta.solana.com:8001",
            },
            .testnet => &.{
                "entrypoint.testnet.solana.com:8001",
                "entrypoint2.testnet.solana.com:8001",
                "entrypoint3.testnet.solana.com:8001",
            },
            .devnet => &.{
                "entrypoint.devnet.solana.com:8001",
                "entrypoint2.devnet.solana.com:8001",
                "entrypoint3.devnet.solana.com:8001",
                "entrypoint4.devnet.solana.com:8001",
                "entrypoint5.devnet.solana.com:8001",
            },
        };
    }
};
