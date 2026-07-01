const sig = @import("../../../lib.zig");

comptime {
    if (@import("builtin").is_test) {
        _ = @import("instruction.zig");
        _ = @import("state.zig");
    }
}

pub const state = @import("state.zig");
const instruction = @import("instruction.zig");

const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const FeatureSet = sig.core.FeatureSet;

pub const Instruction = instruction.Instruction;
pub const LockupArgs = instruction.LockupArgs;

pub const StakeStateV2 = state.StakeStateV2;

pub const ID: Pubkey = .parse("Stake11111111111111111111111111111111111111");

pub fn getMinimumDelegation(slot: Slot, feature_set: *const FeatureSet) u64 {
    const LAMPORTS_PER_SOL: u64 = 1_000_000_000;
    return if (feature_set.active(.upgrade_bpf_stake_program_to_v5, slot))
        1 * LAMPORTS_PER_SOL
    else
        1;
}
