const std = @import("std");
const sig = @import("../sig.zig");

const Pubkey = sig.core.Pubkey;
const Feature = sig.core.features.Feature;

// const ReservedAccounts = struct {
//     active: std.AutoArrayHashMap(Pubkey, void),
//     pending:
// }

const ReservedAccount = struct {
    pubkey: Pubkey,
    feature: ?Feature,
};

const RESERVED_ACCOUNTS: []const ReservedAccount = &.{
    // builtins
    .{
        .pubkey = sig.runtime.program.address_lookup_table.ID,
        .feature = .add_new_reserved_account_keys,
    },
    .{
        .pubkey = sig.runtime.program.bpf_loader.v1.ID,
        .feature = null,
    },
    .{
        .pubkey = sig.runtime.program.bpf_loader.v2.ID,
        .feature = null,
    },
    .{
        .pubkey = sig.runtime.program.bpf_loader.v3.ID,
        .feature = null,
    },
    .{
        .pubkey = sig.runtime.program.bpf_loader.v4.ID,
        .feature = .add_new_reserved_account_keys,
    },
    .{
        .pubkey = sig.runtime.program.compute_budget.ID,
        .feature = .add_new_reserved_account_keys,
    },
    .{
        .pubkey = sig.runtime.program.config.ID,
        .feature = null,
    },
    .{
        .pubkey = sig.runtime.program.precompiles.ed25519.ID,
        .feature = .add_new_reserved_account_keys,
    },
    .{
        .pubkey = sig.runtime.ids.FEATURE_PROGRAM_ID,
        .feature = null,
    },
    .{
        .pubkey = sig.runtime.program.precompiles.secp256k1.ID,
        .feature = .add_new_reserved_account_keys,
    },
    .{
        .pubkey = sig.runtime.program.precompiles.secp256r1.ID,
        .feature = .enable_secp256r1_precompile,
    },
    .{
        .pubkey = sig.runtime.program.config.ID,
        .feature = null,
    },
    .{
        .pubkey = sig.runtime.program.stake.ID,
        .feature = null,
    },
    .{
        .pubkey = sig.runtime.program.system.ID,
        .feature = null,
    },
    .{
        .pubkey = sig.runtime.program.vote.ID,
        .feature = null,
    },
    .{
        .pubkey = sig.runtime.program.zk_elgamal.ID,
        .feature = .add_new_reserved_account_keys,
    },
    .{
        .pubkey = sig.runtime.ids.ZK_TOKEN_PROOF_PROGRAM_ID,
        .feature = .add_new_reserved_account_keys,
    },

    // sysvars
    .{
        .pubkey = sig.runtime.sysvar.OWNER_ID,
        .feature = .add_new_reserved_account_keys,
    },
    .{
        .pubkey = sig.runtime.sysvar.Clock.ID,
        .feature = null,
    },
    .{
        .pubkey = sig.runtime.sysvar.EpochRewards.ID,
        .feature = .add_new_reserved_account_keys,
    },
    .{
        .pubkey = sig.runtime.sysvar.EpochSchedule.ID,
        .feature = null,
    },
    .{
        .pubkey = sig.runtime.sysvar.Fees.ID,
        .feature = null,
    },
    .{
        .pubkey = sig.runtime.sysvar.instruction.ID,
        .feature = null,
    },
    .{
        .pubkey = sig.runtime.sysvar.LastRestartSlot.ID,
        .feature = .add_new_reserved_account_keys,
    },
    .{
        .pubkey = sig.runtime.sysvar.RecentBlockhashes.ID,
        .feature = null,
    },
    .{
        .pubkey = sig.runtime.sysvar.Rent.ID,
        .feature = null,
    },
    .{
        .pubkey = sig.runtime.ids.SYSVAR_REWARDS_ID,
        .feature = null,
    },
    .{
        .pubkey = sig.runtime.sysvar.SlotHashes.ID,
        .feature = null,
    },
    .{
        .pubkey = sig.runtime.sysvar.SlotHistory.ID,
        .feature = null,
    },
    .{
        .pubkey = sig.runtime.sysvar.StakeHistory.ID,
        .feature = null,
    },

    // other
    .{
        .pubkey = sig.runtime.ids.NATIVE_LOADER_ID,
        .feature = null,
    },
};

pub fn reservedAccountsForSlot(
    allocator: std.mem.Allocator,
    feature_set: *const sig.core.FeatureSet,
    slot: sig.core.Slot,
) !std.AutoArrayHashMapUnmanaged(Pubkey, void) {
    var reserved_keys = std.AutoArrayHashMapUnmanaged(Pubkey, void){};
    errdefer reserved_keys.deinit(allocator);

    try reserved_keys.ensureTotalCapacity(allocator, RESERVED_ACCOUNTS.len);

    for (RESERVED_ACCOUNTS) |reserved_account| {
        if (reserved_account.feature == null or
            feature_set.active(reserved_account.feature.?, slot))
        {
            try reserved_keys.put(allocator, reserved_account.pubkey, {});
        }
    }

    return reserved_keys;
}
