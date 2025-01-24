const std = @import("std");
const sig = @import("../sig.zig");

/// This is direcly imported because it `utils.zig` will be removed in a follow up PR.
const utils = @import("utils.zig");

const Pubkey = sig.core.Pubkey;
const ExecuteInstructionContext = sig.runtime.ExecuteInstructionContext;
const InstructionError = sig.core.instruction.InstructionError;

const MAX_SEED_LEN = 32;
const PDA_MARKER = "ProgramDerivedAddress";

/// Agave returns this as a PubkeyError::MaxSeedLenExceeded which is the first
/// variant and hence encoded as 0.
const ERROR_MAX_SEED_LEN_EXCEEDED = 0;
const ERROR_ILLEGAL_OWNER = 2;

/// TODO: since we are assigning a custom error, this could logically be a
/// member function of ExecuteInstructionContext. Alternatively it could be
/// moved to our Pubkey module and we could implement the matching PubkeyError
/// enum in Zig, then we can set the custom error in the calling context thus
/// decoupling from the ExecuteInstructionContext.
pub fn createWithSeed(
    eic: *ExecuteInstructionContext,
    base: Pubkey,
    seed: []const u8,
    owner: Pubkey,
) InstructionError!Pubkey {
    if (seed.len > MAX_SEED_LEN) {
        eic.setCustomError(ERROR_MAX_SEED_LEN_EXCEEDED);
        return .Custom;
    }

    const offset = owner.data.len - PDA_MARKER.len;
    if (std.mem.eql(u8, owner.data[offset..], PDA_MARKER)) {
        eic.setCustomError(ERROR_ILLEGAL_OWNER);
        return .Custom;
    }

    return .{ .data = utils.hashv(&.{ base.data, seed, owner.data }) };
}
