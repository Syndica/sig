const std = @import("std");
const sig = @import("../../sig.zig");

pub const address_lookup_table = @import("address_lookup_table/lib.zig");
pub const bpf = @import("bpf/lib.zig");
pub const bpf_loader = @import("bpf_loader/lib.zig");
pub const builtin_costs = @import("builtin_costs.zig");
pub const compute_budget = @import("compute_budget/lib.zig");
pub const config = @import("config/lib.zig");
pub const precompiles = @import("precompiles/lib.zig");
pub const stake = @import("stake/lib.zig");
pub const state = @import("stake/lib.zig");
pub const system = @import("system/lib.zig");
pub const testing = @import("testing.zig");
pub const vote = @import("vote/lib.zig");
pub const zk_elgamal = @import("zk_elgamal/lib.zig");

const InstructionError = sig.core.instruction.InstructionError;
const InstructionContext = sig.runtime.InstructionContext;

/// Program instruction seeds should be no longer than 32 bytes (pubkey_utils.MAX_SEED_LEN).
/// Agave validates instruction seeds during program execution returning error.Custom if they are
/// invalid. Enforcing the seed limit during deserialization results in returning
/// error.InvalidInstructionData for instructions with invalid seeds. This is an issue for
/// conformance testing as the testing harness expects the same error code.
// const MAX_SEED_LEN = sig.runtime.pubkey_utils.MAX_SEED_LEN;
pub const SEED_FIELD_CONFIG = sig.bincode.utf8StringCodec([]const u8, 1024 * 1024);

pub const PROGRAM_ENTRYPOINTS = initProgramEntrypoints();
pub const PRECOMPILE_ENTRYPOINTS = initPrecompileEntrypoints();

const EntrypointFn = *const fn (
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
        .{ zk_elgamal.ID.base58String().slice(), zk_elgamal.execute },
        .{ stake.ID.base58String().slice(), stake.execute },
    });
}

fn initPrecompileEntrypoints() std.StaticStringMap(EntrypointFn) {
    return std.StaticStringMap(EntrypointFn).initComptime(&.{});
}
