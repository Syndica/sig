const std = @import("std");
const sig = @import("../../sig.zig");

const Epoch = sig.core.Epoch;
const Pubkey = sig.core.Pubkey;

/// [agave] https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/sysvar/src/stake_history.rs#L67
pub const StakeHistory = struct {
    entries: []const Entry,

    pub const ID =
        Pubkey.parseBase58String("SysvarStakeHistory1111111111111111111111111") catch unreachable;

    pub const DEFAULT = StakeHistory{
        .entries = &.{},
    };

    /// [stake] https://github.com/solana-program/stake/blob/bcec951fda5f2a30b1f4a058706d2e9ed23a8429/interface/src/stake_history.rs#L8
    pub const MAX_ENTRIES = 512;

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/ac11e3e568952977e63bce6bb20e37f26a61e151/sysvar/src/stake_history.rs#L66
    pub const SIZE_OF = 16_392;

    pub const Entry = struct {
        Epoch,
        struct {
            /// Effective stake at this epoch
            effective: u64,
            /// Sum of portion of stakes not fully warmed up
            activating: u64,
            /// Requested to be cooled down, not fully deactivated yet
            deactivating: u64,
        },
    };

    pub fn deinit(self: StakeHistory, allocator: std.mem.Allocator) void {
        allocator.free(self.entries);
    }
};
