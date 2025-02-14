const std = @import("std");
const sig = @import("../../../sig.zig");
const precompile_programs = sig.runtime.program.precompile_programs;

const PrecompileProgramError = precompile_programs.PrecompileProgramError;
const getInstructionValue = precompile_programs.getInstructionValue;
const getInstructionData = precompile_programs.getInstructionData;

// I don't see where this function is in firedancer?
pub fn verify(
    current_instruction_data: []const u8,
    all_instruction_datas: []const []const u8,
) PrecompileProgramError!void {
    _ = current_instruction_data;
    _ = all_instruction_datas;
    @panic("TODO");
}
