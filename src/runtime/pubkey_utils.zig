const std = @import("std");
const sig = @import("../sig.zig");

const Pubkey = sig.core.Pubkey;
const ExecuteInstructionContext = sig.runtime.ExecuteInstructionContext;
const InstructionError = sig.core.instruction.InstructionError;

// TODO: Consider moving the below to the pubkey module

const MAX_SEED_LEN = 32;
const PDA_MARKER = "ProgramDerivedAddress";

pub const PubkeyError = error{
    MaxSeedLenExceeded,
    InvalidSeeds,
    IllegalOwner,
};

pub fn createWithSeed(
    base: Pubkey,
    seed: []const u8,
    owner: Pubkey,
) PubkeyError!Pubkey {
    if (seed.len > MAX_SEED_LEN) {
        return PubkeyError.MaxSeedLenExceeded;
    }

    const offset = owner.data.len - PDA_MARKER.len;
    if (std.mem.eql(u8, owner.data[offset..], PDA_MARKER))
        return PubkeyError.IllegalOwner;

    return .{ .data = sig.runtime.tmp_utils.hashv(&.{ &base.data, seed, &owner.data }) };
}
