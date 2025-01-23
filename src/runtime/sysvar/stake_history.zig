// https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/sysvar/src/stake_history.rs
// https://github.com/firedancer-io/firedancer/blob/82ecf8392fe076afce5f9cba02a5efa976e664c8/src/flamenco/runtime/sysvar/fd_sysvar_stake_history.h

const sig = @import("../../sig.zig");

const Pubkey = sig.core.Pubkey;
const Epoch = sig.core.Epoch;

pub const StakeHistory = struct {
    entries: []const .{ Epoch, StakeHistoryEntry },

    pub const StakeHistoryEntry = struct {
        /// Effective stake at this epoch
        effective: u64,
        /// Sum of portion of stakes not fully warmed up
        activating: u64,
        /// Requested to be cooled down, not fully deactivated yet
        deactivating: u64,
    };
};
