const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;

const Pubkey = sig.core.Pubkey;
const Feature = sig.core.features.Feature;
const FeatureSet = sig.core.FeatureSet;
const Slot = sig.core.Slot;

pub const ReservedAccounts = @This();

map: sig.utils.collections.PubkeyMap(void),

pub const empty: ReservedAccounts = .{ .map = .empty };

pub fn init(allocator: Allocator) Allocator.Error!ReservedAccounts {
    var reserved_accounts = ReservedAccounts{ .map = .empty };
    errdefer reserved_accounts.deinit(allocator);
    try reserved_accounts.map.ensureTotalCapacity(allocator, ACCOUNTS.len);

    for (ACCOUNTS) |account| {
        if (account.feature == null) reserved_accounts.map.putAssumeCapacity(account.pubkey, {});
    }

    return reserved_accounts;
}

pub fn deinit(self: ReservedAccounts, allocator: Allocator) void {
    var map = self.map;
    map.deinit(allocator);
}

pub fn initForSlot(
    allocator: Allocator,
    feature_set: *const FeatureSet,
    slot: Slot,
) Allocator.Error!ReservedAccounts {
    var reserved_accounts = try init(allocator);
    errdefer reserved_accounts.deinit(allocator);
    reserved_accounts.update(feature_set, slot);
    return reserved_accounts;
}

pub fn initAllActivated(allocator: Allocator) Allocator.Error!ReservedAccounts {
    var reserved_accounts = ReservedAccounts{ .map = .empty };
    errdefer reserved_accounts.deinit(allocator);
    try reserved_accounts.map.ensureTotalCapacity(allocator, ACCOUNTS.len);
    for (ACCOUNTS) |account| reserved_accounts.map.putAssumeCapacity(account.pubkey, {});
    return reserved_accounts;
}

pub fn update(
    self: *ReservedAccounts,
    feature_set: *const FeatureSet,
    slot: Slot,
) void {
    for (ACCOUNTS) |account| {
        if (account.feature) |feature| {
            if (feature_set.active(feature, slot)) {
                self.map.putAssumeCapacity(account.pubkey, {});
            }
        }
    }
}

const ACCOUNTS = [_]struct { pubkey: Pubkey, feature: ?Feature }{
    // zig fmt: off
    .{ .pubkey = sig.runtime.program.address_lookup_table.ID,  .feature = .add_new_reserved_account_keys },
    .{ .pubkey = sig.runtime.program.bpf_loader.v1.ID,         .feature = null },
    .{ .pubkey = sig.runtime.program.bpf_loader.v2.ID,         .feature = null },
    .{ .pubkey = sig.runtime.program.bpf_loader.v3.ID,         .feature = null },
    .{ .pubkey = sig.runtime.program.bpf_loader.v4.ID,         .feature = .add_new_reserved_account_keys },
    .{ .pubkey = sig.runtime.program.compute_budget.ID,        .feature = .add_new_reserved_account_keys },
    .{ .pubkey = sig.runtime.program.config.ID,                .feature = null },
    .{ .pubkey = sig.runtime.program.precompiles.ed25519.ID,   .feature = .add_new_reserved_account_keys },
    .{ .pubkey = sig.runtime.ids.FEATURE_PROGRAM_ID,           .feature = null },
    .{ .pubkey = sig.runtime.program.precompiles.secp256k1.ID, .feature = .add_new_reserved_account_keys },
    .{ .pubkey = sig.runtime.program.precompiles.secp256r1.ID, .feature = .enable_secp256r1_precompile },
    .{ .pubkey = sig.runtime.ids.STAKE_CONFIG_PROGRAM_ID,      .feature = null },
    .{ .pubkey = sig.runtime.program.stake.ID,                 .feature = null },
    .{ .pubkey = sig.runtime.program.system.ID,                .feature = null },
    .{ .pubkey = sig.runtime.program.vote.ID,                  .feature = null },
    .{ .pubkey = sig.runtime.program.zk_elgamal.ID,            .feature = .add_new_reserved_account_keys },
    .{ .pubkey = sig.runtime.ids.ZK_TOKEN_PROOF_PROGRAM_ID,    .feature = .add_new_reserved_account_keys },

    .{ .pubkey = sig.runtime.sysvar.OWNER_ID,                  .feature = .add_new_reserved_account_keys },
    .{ .pubkey = sig.runtime.sysvar.Clock.ID,                  .feature = null },
    .{ .pubkey = sig.runtime.sysvar.EpochRewards.ID,           .feature = .add_new_reserved_account_keys },
    .{ .pubkey = sig.runtime.sysvar.EpochSchedule.ID,          .feature = null },
    .{ .pubkey = sig.runtime.sysvar.Fees.ID,                   .feature = null },
    .{ .pubkey = sig.runtime.sysvar.instruction.ID,            .feature = null },
    .{ .pubkey = sig.runtime.sysvar.LastRestartSlot.ID,        .feature = .add_new_reserved_account_keys },
    .{ .pubkey = sig.runtime.sysvar.RecentBlockhashes.ID,      .feature = null },
    .{ .pubkey = sig.runtime.sysvar.Rent.ID,                   .feature = null },
    .{ .pubkey = sig.runtime.ids.SYSVAR_REWARDS_ID,            .feature = null },
    .{ .pubkey = sig.runtime.sysvar.SlotHashes.ID,             .feature = null },
    .{ .pubkey = sig.runtime.sysvar.SlotHistory.ID,            .feature = null },
    .{ .pubkey = sig.runtime.sysvar.StakeHistory.ID,           .feature = null },

    .{ .pubkey = sig.runtime.ids.NATIVE_LOADER_ID,             .feature = null },
    // zig fmt: on
};
