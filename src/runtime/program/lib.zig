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

const EntrypointFn = *const fn (
    std.mem.Allocator,
    *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void;

pub const PROGRAM_ENTRYPOINTS = std.StaticStringMap(EntrypointFn).initComptime(&.{
    .{ &bpf_loader.v1.ID.data, bpf_loader.execute },
    .{ &bpf_loader.v2.ID.data, bpf_loader.execute },
    .{ &bpf_loader.v3.ID.data, bpf_loader.execute },
    .{ &bpf_loader.v4.ID.data, bpf_loader.execute },
    .{ &system.ID.data, system.execute },
    .{ &vote.ID.data, vote.execute },
    .{ &address_lookup_table.ID.data, address_lookup_table.execute },
    .{ &compute_budget.ID.data, compute_budget.entrypoint },
    .{ &zk_elgamal.ID.data, zk_elgamal.execute },
    .{ &stake.ID.data, stake.execute },
});
pub const PRECOMPILE_ENTRYPOINTS = std.StaticStringMap(EntrypointFn).initComptime(&.{
    .{ &precompiles.ed25519.ID.data, precompiles.ed25519.execute },
    .{ &precompiles.secp256k1.ID.data, precompiles.secp256k1.execute },
    .{ &precompiles.secp256r1.ID.data, precompiles.secp256r1.execute },
});
