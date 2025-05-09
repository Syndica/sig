const std = @import("std");
const sig = @import("../../../sig.zig");

const Pubkey = sig.core.Pubkey;
const zk_elgamal_program = sig.runtime.program.zk_elgamal_program;
const InstructionError = sig.core.instruction.InstructionError;
const InstructionContext = sig.runtime.InstructionContext;

pub fn execute(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    _ = allocator;
    _ = ic;
}

test "zero balance" {
    const allocator = std.testing.allocator;
    const testing = sig.runtime.program.testing;

    var prng = std.Random.DefaultPrng.init(5083);

    const account_0_key = Pubkey.initRandom(prng.random());
    const account_1_key = Pubkey.initRandom(prng.random());
    _ = allocator;
    _ = testing;
    _ = account_0_key;
    _ = account_1_key;
}
