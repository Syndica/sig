const std = @import("std");
const sig = @import("../../sig.zig");

const Pubkey = sig.core.Pubkey;
const InstructionAccount = sig.core.instruction.InstructionAccount;
const InstructionError = sig.core.instruction.InstructionError;

const InstructionContext = sig.runtime.InstructionContext;
const SystemProgramInstruction = sig.runtime.program.system_program.Instruction;

/// [agave] https://github.com/anza-xyz/agave/blob/134be7c14066ea00c9791187d6bbc4795dd92f0e/program-runtime/src/invoke_context.rs#L308
///
pub fn executeSystemProgramInstruction(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    instruction: SystemProgramInstruction,
    instruction_account_metas: []const InstructionAccount,
    signers: []const Pubkey,
) InstructionError!void {
    // TODO: Implement the execute function
    _ = allocator;
    _ = ic;
    _ = instruction;
    _ = instruction_account_metas;
    _ = signers;

    // Prepare intruction
    // [agave] https://github.com/anza-xyz/agave/blob/134be7c14066ea00c9791187d6bbc4795dd92f0e/program-runtime/src/invoke_context.rs#L328
    // [fd] https://github.com/firedancer-io/firedancer/blob/5e9c865414c12b89f1e0c3a2775cb90e3ca3da60/src/flamenco/vm/syscall/fd_vm_syscall_cpi.c#L62

    // Process instruction
    // [agave] https://github.com/anza-xyz/agave/blob/134be7c14066ea00c9791187d6bbc4795dd92f0e/program-runtime/src/invoke_context.rs#L450
    // [fd] https://github.com/firedancer-io/firedancer/blob/5e9c865414c12b89f1e0c3a2775cb90e3ca3da60/src/flamenco/runtime/fd_executor.c#L1079

}
