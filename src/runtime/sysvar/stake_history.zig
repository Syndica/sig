const sig = @import("../../sig.zig");

const Epoch = sig.core.Epoch;
const Pubkey = sig.core.Pubkey;

/// [agave] https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/sysvar/src/stake_history.rs#L67
pub const StakeHistory = struct {
    entries: []const struct { Epoch, StakeHistoryEntry },

    pub const StakeHistoryEntry = struct {
        /// Effective stake at this epoch
        effective: u64,
        /// Sum of portion of stakes not fully warmed up
        activating: u64,
        /// Requested to be cooled down, not fully deactivated yet
        deactivating: u64,
    };

    pub const ID =
        Pubkey.parseBase58String("SysvarStakeHistory1111111111111111111111111") catch unreachable;
};
