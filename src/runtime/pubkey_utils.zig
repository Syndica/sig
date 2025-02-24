const std = @import("std");
const sig = @import("../sig.zig");

const Pubkey = sig.core.Pubkey;

// TODO: Consider moving the below to the pubkey module

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/pubkey.rs#L26
const MAX_SEED_LEN = 32;

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/pubkey.rs#L32
const PDA_MARKER = "ProgramDerivedAddress";

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/pubkey.rs#L35
pub const PubkeyError = error{
    MaxSeedLenExceeded,
    InvalidSeeds,
    IllegalOwner,
};

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/pubkey.rs#L200
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

    return .{ .data = sig.runtime.tmp_utils.hashv(&.{ &base.data, seed, &owner.data }).data };
}
