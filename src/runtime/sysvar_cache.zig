const sig = @import("../sig.zig");

const sysvar = sig.runtime.sysvar;

/// `SysvarCache` provides the runtime with access to sysvars during program execution
///
/// TODO:
///     - Evaluate storing as raw bytes or as object representations
///     - Why is SlotHistory not included?
///
/// `SysvarCache` provides the runtime with access to sysvars during program execution
///
/// TODO:\
/// - Evaluate storing as raw bytes or as object representations\
/// - Why is SlotHistory not included?\
///
/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/program-runtime/src/sysvar_cache.rs#L28
pub const SysvarCache = struct {
    // full account data as provided by bank, including any trailing zero bytes
    clock: ?sysvar.Clock = null,
    epoch_rewards: ?sysvar.EpochRewards = null,
    epoch_schedule: ?sysvar.EpochSchedule = null,
    last_restart_slot: ?sysvar.LastRestartSlot = null,
    rent: ?sysvar.Rent = null,
    slot_hashes: ?sysvar.SlotHashes = null,
    stake_history: ?sysvar.StakeHistory = null,

    // deprecated sysvars, these should be removed once practical
    fees: ?sysvar.Fees = null,
    recent_blockhashes: ?sysvar.RecentBlockhashes = null,

    pub fn get(self: SysvarCache, comptime T: type) ?T {
        return switch (T) {
            sysvar.Clock => self.clock,
            sysvar.EpochRewards => self.epoch_rewards,
            sysvar.EpochSchedule => self.epoch_schedule,
            sysvar.LastRestartSlot => self.last_restart_slot,
            sysvar.Rent => self.rent,
            sysvar.SlotHashes => self.slot_hashes,
            sysvar.StakeHistory => self.stake_history,
            sysvar.Fees => self.fees,
            sysvar.RecentBlockhashes => self.recent_blockhashes,
            else => @panic("Unsupported sysvar"),
        };
    }
};
