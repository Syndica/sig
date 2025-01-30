const sig = @import("../sig.zig");

const sysvar = sig.runtime.sysvar;

/// TODO: Why store these values as raw bytes??
pub const SysvarCache = struct {
    // full account data as provided by bank, including any trailing zero bytes
    // maybe_clock: ?[]const u8,
    // maybe_epoch_schedule: ?[]const u8,
    // maybe_epoch_rewards: ?[]const u8,
    maybe_rent: ?sysvar.Rent,
    // maybe_slot_hashes: ?[]const u8,
    // maybe_stake_history: ?[]const u8,
    // maybe_last_restart_slot: ?[]const u8,

    // object representations of large sysvars for convenience
    // these are used by the stake and vote builtin programs
    // these should be removed once those programs are ported to bpf
    // maybe_slot_hashes_obj: ?[]const u8,
    // maybe_stake_history_obj: ?[]const u8,

    // deprecated sysvars, these should be removed once practical
    maybe_fees: ?sysvar.Fees,
    maybe_recent_blockhashes: ?sysvar.RecentBlockhashes,

    pub const EMPTY = SysvarCache{
        // .maybe_clock = null,
        // .maybe_epoch_schedule = null,
        // .maybe_epoch_rewards = null,
        .maybe_rent = null,
        // .maybe_slot_hashes = null,
        // .maybe_stake_history = null,
        // .maybe_last_restart_slot = null,
        // .maybe_slot_hashes_obj = null,
        // .maybe_stake_history_obj = null,
        .maybe_fees = null,
        .maybe_recent_blockhashes = null,
    };

    pub fn get(self: SysvarCache, comptime T: type) ?T {
        return switch (T) {
            sysvar.Rent => self.maybe_rent,
            sysvar.Fees => self.maybe_fees,
            sysvar.RecentBlockhashes => self.maybe_recent_blockhashes,
            else => @panic("Unsupported sysvar"),
        };
    }
};
