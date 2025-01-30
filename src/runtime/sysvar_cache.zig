const sig = @import("../sig.zig");

const Fees = sig.runtime.sysvar.Fees;
const RecentBlockhashes = sig.runtime.sysvar.RecentBlockhashes;
const Rent = sig.runtime.sysvar.Rent;

/// TODO: Why store these values as raw bytes??
pub const SysvarCache = struct {
    // full account data as provided by bank, including any trailing zero bytes
    maybe_clock: ?[]const u8,
    maybe_epoch_schedule: ?[]const u8,
    maybe_epoch_rewards: ?[]const u8,
    maybe_rent: ?[]const u8,
    maybe_slot_hashes: ?[]const u8,
    maybe_stake_history: ?[]const u8,
    maybe_last_restart_slot: ?[]const u8,

    // object representations of large sysvars for convenience
    // these are used by the stake and vote builtin programs
    // these should be removed once those programs are ported to bpf
    maybe_slot_hashes_obj: ?[]const u8,
    maybe_stake_history_obj: ?[]const u8,

    // deprecated sysvars, these should be removed once practical
    maybe_fees: ?[]const u8,
    maybe_recent_blockhashes: ?[]const u8,

    pub fn empty() SysvarCache {
        return .{
            .maybe_clock = null,
            .maybe_epoch_schedule = null,
            .maybe_epoch_rewards = null,
            .maybe_rent = null,
            .maybe_slot_hashes = null,
            .maybe_stake_history = null,
            .maybe_last_restart_slot = null,
            .maybe_slot_hashes_obj = null,
            .maybe_stake_history_obj = null,
            .maybe_fees = null,
            .maybe_recent_blockhashes = null,
        };
    }

    pub fn get(self: SysvarCache, comptime T: type) ?T {
        _ = self;
        return switch (T) {
            // Fees => if (self.maybe_fees) |fees| @ptrCast(fees.ptr),
            // RecentBlockhashes => if (self.maybe_recent_blockhashes) |recent_blockhashes| @ptrCast(recent_blockhashes.ptr),
            // Rent => if (self.maybe_rent) |rent| @ptrCast(rent.ptr),
            else => @panic("Unsupported sysvar"),
        };
    }
};
