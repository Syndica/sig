const std = @import("std");
const sig = @import("../../sig.zig");

pub const address_lookup_table = @import("address_lookup_table/lib.zig");
pub const bpf = @import("bpf/lib.zig");
pub const bpf_loader = @import("bpf_loader/lib.zig");
pub const builtin_costs = @import("builtin_costs.zig");
pub const config = @import("config/lib.zig");
pub const compute_budget = @import("compute_budget/lib.zig");
pub const precompiles = @import("precompiles/lib.zig");
pub const stake = @import("stake/lib.zig");
pub const system = @import("system/lib.zig");
pub const testing = @import("testing.zig");
pub const vote = @import("vote/lib.zig");

const InstructionError = sig.core.instruction.InstructionError;
const InstructionContext = sig.runtime.InstructionContext;

pub const PROGRAM_ENTRYPOINTS = initProgramEntrypoints();
pub const PRECOMPILE_ENTRYPOINTS = initPrecompileEntrypoints();

pub const EntrypointFn = *const fn (
    std.mem.Allocator,
    *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void;

// reviewer's note: does this have to be a string map? might be better to keep as pubkeys
fn initProgramEntrypoints() std.StaticStringMap(EntrypointFn) {
    @setEvalBranchQuota(10_000);
    return std.StaticStringMap(EntrypointFn).initComptime(&.{
        .{ bpf_loader.v1.ID.base58String().slice(), bpf_loader.execute },
        .{ bpf_loader.v2.ID.base58String().slice(), bpf_loader.execute },
        .{ bpf_loader.v3.ID.base58String().slice(), bpf_loader.execute },
        .{ bpf_loader.v4.ID.base58String().slice(), bpf_loader.execute },
        .{ system.ID.base58String().slice(), system.execute },
        .{ vote.ID.base58String().slice(), vote.execute },
        .{ address_lookup_table.ID.base58String().slice(), address_lookup_table.execute },
        .{ compute_budget.ID.base58String().slice(), compute_budget.entrypoint },
    });
}

fn initPrecompileEntrypoints() std.StaticStringMap(EntrypointFn) {
    return std.StaticStringMap(EntrypointFn).initComptime(&.{});
}
