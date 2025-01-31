const sig = @import("../sig.zig");

const sysvar = sig.runtime.sysvar;

/// TODO:
///     - Evaluate storing as raw bytes or as object representations
///     - Why is SlotHistory not included?
/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/program-runtime/src/sysvar_cache.rs#L28
pub const SysvarCache = struct {
    // full account data as provided by bank, including any trailing zero bytes
    maybe_clock: ?sysvar.Clock = null,
    maybe_epoch_rewards: ?sysvar.EpochRewards = null,
    maybe_epoch_schedule: ?sysvar.EpochSchedule = null,
    maybe_last_restart_slot: ?sysvar.LastRestartSlot = null,
    maybe_rent: ?sysvar.Rent = null,
    maybe_slot_hashes: ?sysvar.SlotHashes = null,
    maybe_stake_history: ?sysvar.StakeHistory = null,

    // deprecated sysvars, these should be removed once practical
    maybe_fees: ?sysvar.Fees = null,
    maybe_recent_blockhashes: ?sysvar.RecentBlockhashes = null,

    pub fn get(self: SysvarCache, comptime T: type) ?T {
        return switch (T) {
            sysvar.Clock => self.maybe_clock,
            sysvar.EpochRewards => self.maybe_epoch_rewards,
            sysvar.EpochSchedule => self.maybe_epoch_schedule,
            sysvar.LastRestartSlot => self.maybe_last_restart_slot,
            sysvar.Rent => self.maybe_rent,
            sysvar.SlotHashes => self.maybe_slot_hashes,
            sysvar.StakeHistory => self.maybe_stake_history,
            sysvar.Fees => self.maybe_fees,
            sysvar.RecentBlockhashes => self.maybe_recent_blockhashes,
            else => @panic("Unsupported sysvar"),
        };
    }
};
