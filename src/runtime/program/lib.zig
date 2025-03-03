const std = @import("std");
const sig = @import("../../sig.zig");

const InstructionError = sig.core.instruction.InstructionError;
const InstructionContext = sig.runtime.InstructionContext;

pub const precompile_programs = @import("precompile_programs/lib.zig");
pub const system_program = @import("system_program/lib.zig");
pub const vote_program = @import("vote/lib.zig");

pub const test_program_execute = @import("test_program_execute.zig");

const PROGRAM_ENTRYPOINTS = std.StaticStringMap(
    *const fn (std.mem.Allocator, *InstructionContext) InstructionError!void,
).initComptime(&.{
    .{ system_program.ID.base58String().slice(), system_program.execute },
});
