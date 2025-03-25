const std = @import("std");
const sig = @import("../../sig.zig");

pub const address_lookup_table = @import("address_lookup_table/lib.zig");
pub const precompile_programs = @import("precompile_programs/lib.zig");
pub const system_program = @import("system_program/lib.zig");
pub const testing = @import("testing.zig");
pub const vote_program = @import("vote/lib.zig");

const InstructionError = sig.core.instruction.InstructionError;
const InstructionContext = sig.runtime.InstructionContext;

pub const PROGRAM_ENTRYPOINTS = initProgramEntrypoints();
pub const PRECOMPILE_ENTRYPOINTS = initPrecompileEntrypoints();

const EntrypointFn =
    *const fn (
    std.mem.Allocator,
    *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void;

// reviewer's note: does this have to be a string map? might be better to keep as pubkeys
fn initProgramEntrypoints() std.StaticStringMap(EntrypointFn) {
    @setEvalBranchQuota(5000);
    return std.StaticStringMap(EntrypointFn).initComptime(&.{
        .{ system_program.ID.base58String().slice(), system_program.execute },
        .{ vote_program.ID.base58String().slice(), vote_program.execute },
        .{ address_lookup_table.ID.base58String().slice(), address_lookup_table.execute },
    });
}

fn initPrecompileEntrypoints() std.StaticStringMap(EntrypointFn) {
    return std.StaticStringMap(EntrypointFn).initComptime(&.{});
}
