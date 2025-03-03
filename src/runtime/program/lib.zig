const std = @import("std");
const sig = @import("../../sig.zig");

const InstructionError = sig.core.instruction.InstructionError;
const InstructionContext = sig.runtime.InstructionContext;

pub const bpf_loader_program = @import("bpf_loader_program/lib.zig");
pub const precompile_programs = @import("precompile_programs/lib.zig");
pub const system_program = @import("system_program/lib.zig");
pub const testing = @import("testing.zig");
pub const vote_program = @import("vote/lib.zig");

pub const PROGRAM_ENTRYPOINTS = initProgramEntrypoints();
pub const PRECOMPILE_ENTRYPOINTS = initPrecompileEntrypoints();

fn initProgramEntrypoints() std.StaticStringMap(
    *const fn (std.mem.Allocator, *InstructionContext) InstructionError!void,
) {
    @setEvalBranchQuota(5000);
    return std.StaticStringMap(
        *const fn (std.mem.Allocator, *InstructionContext) InstructionError!void,
    ).initComptime(&.{
        .{ system_program.ID.base58String().slice(), system_program.execute },
        .{ bpf_loader_program.v1.ID.base58String().slice(), bpf_loader_program.execute },
        .{ bpf_loader_program.v2.ID.base58String().slice(), bpf_loader_program.execute },
        .{ bpf_loader_program.v3.ID.base58String().slice(), bpf_loader_program.execute },
        .{ vote_program.ID.base58String().slice(), vote_program.execute },
    });
}

fn initPrecompileEntrypoints() std.StaticStringMap(
    *const fn (std.mem.Allocator, *InstructionContext) InstructionError!void,
) {
    return std.StaticStringMap(
        *const fn (std.mem.Allocator, *InstructionContext) InstructionError!void,
    ).initComptime(&.{});
}
