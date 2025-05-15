const sig = @import("../../../sig.zig");

pub const ID =
    sig.core.Pubkey.parseBase58String(
    "ZkE1Gama1Proof11111111111111111111111111111",
) catch unreachable;

pub const ProofInstruction = @import("instruction.zig").ProofInstruction;
pub const execute = @import("execute.zig").execute;
