pub const std = @import("std");
pub const sig = @import("../sig.zig");

pub const SysvarCache = struct {
    // full account data as provided by bank, including any trailing zero bytes
    clock: ?[]const u8,
    epoch_schedule: ?[]const u8,
    epoch_rewards: ?[]const u8,
    rent: ?[]const u8,
    slot_hashes: ?[]const u8,
    stake_history: ?[]const u8,
    last_restart_slot: ?[]const u8,

    // object representations of large sysvars for convenience
    // these are used by the stake and vote builtin programs
    // these should be removed once those programs are ported to bpf
    slot_hashes_obj: ?[]const u8,
    stake_history_obj: ?[]const u8,

    // deprecated sysvars, these should be removed once practical
    fees: ?[]const u8,
    recent_blockhashes: ?[]const u8,

    pub fn default() SysvarCache {}
};
