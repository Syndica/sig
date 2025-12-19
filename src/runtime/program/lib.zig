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

const StaticFuncMap = struct {
    keys: []const sig.core.Pubkey,
    values: []const EntrypointFn,

    fn init(entries: []const struct { sig.core.Pubkey, EntrypointFn }) StaticFuncMap {
        var keys: []const sig.core.Pubkey = &.{};
        var values: []const EntrypointFn = &.{};
        for (entries) |entry| {
            keys = keys ++ [_]sig.core.Pubkey{entry.@"0"};
            values = values ++ [_]EntrypointFn{entry.@"1"};
        }
        return .{ .keys = keys, .values = values };
    }

    pub fn get(self: *const StaticFuncMap, key: *const sig.core.Pubkey) ?EntrypointFn {
        for (self.keys, 0..) |k, i|
            if (k.equals(key)) return self.values[i];
        return null;
    }
};

// zig fmt: off
pub const PROGRAM_ENTRYPOINTS: StaticFuncMap = .init(&.{
    .{ bpf_loader.v1.ID       , bpf_loader.execute           },
    .{ bpf_loader.v2.ID       , bpf_loader.execute           },
    .{ bpf_loader.v3.ID       , bpf_loader.execute           },
    .{ bpf_loader.v4.ID       , bpf_loader.execute           },
    .{ system.ID              , system.execute               },
    .{ vote.ID                , vote.execute                 },
    .{ address_lookup_table.ID, address_lookup_table.execute },
    .{ compute_budget.ID      , compute_budget.entrypoint    },
    .{ zk_elgamal.ID          , zk_elgamal.execute           },
    .{ stake.ID               , stake.execute                },
});
pub const PRECOMPILE_ENTRYPOINTS: StaticFuncMap = .init(&.{
    .{ precompiles.ed25519.ID  , precompiles.ed25519.execute  },
    .{ precompiles.secp256k1.ID, precompiles.secp256k1.execute },
    .{ precompiles.secp256r1.ID, precompiles.secp256r1.execute },

});
// zig fmt: on
