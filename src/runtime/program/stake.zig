// https://github.com/anza-xyz/agave/blob/df5c9ad28e76fb487514ab7719358df3c42cb1d5/programs/stake/src/stake_instruction.rs#L52
pub fn execute(ctx: *ExecuteInstructionContext) !void {
    _ = ctx;
    @panic("Program not implemented");
}

const std = @import("std");
const sig = @import("../../sig.zig");

const ExecuteInstructionContext = @import("../ExecuteInstructionContext.zig");

const Pubkey = sig.core.Pubkey;
