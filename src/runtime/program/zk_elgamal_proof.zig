// https://github.com/anza-xyz/agave/blob/df5c9ad28e76fb487514ab7719358df3c42cb1d5/programs/zk-elgamal-proof/src/lib.rs#L173

pub fn execute(ctx: *ExecuteInstructionContext) !void {
    _ = ctx;
    @panic("Program not implemented");
}

const std = @import("std");
const sig = @import("../../sig.zig");

const ExecuteInstructionContext = @import("../ExecuteInstructionContext.zig");
