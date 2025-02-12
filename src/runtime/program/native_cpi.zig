const std = @import("std");
const sig = @import("../../sig.zig");

const Pubkey = sig.core.Pubkey;
const InstructionAccountMeta = sig.core.instruction.InstructionAccountMeta;
const InstructionError = sig.core.instruction.InstructionError;

const InstructionContext = sig.runtime.InstructionContext;
const SystemProgramInstruction = sig.runtime.program.system_program.SystemProgramInstruction;

pub fn executeSystemProgramInstruction(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    instruction: SystemProgramInstruction,
    instruction_account_metas: []const InstructionAccountMeta,
    signers: []const Pubkey,
) InstructionError!void {
    // TODO: Implement the execute function
    _ = allocator;
    _ = ic;
    _ = instruction;
    _ = instruction_account_metas;
    _ = signers;
}
