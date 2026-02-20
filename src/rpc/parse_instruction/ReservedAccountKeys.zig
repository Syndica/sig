const std = @import("std");
const sig = @import("../../sig.zig");

const Pubkey = sig.core.Pubkey;

const ReservedAccountKeys = @This();

/// Set of currently active reserved account keys
active: std.AutoHashMapUnmanaged(Pubkey, void),
/// Set of currently inactive reserved account keys that will be moved to the
/// active set when their feature id is activated
inactive: std.AutoHashMapUnmanaged(Pubkey, Pubkey),

pub fn deinit(self: *ReservedAccountKeys, allocator: std.mem.Allocator) void {
    self.active.deinit(allocator);
    self.inactive.deinit(allocator);
}

// TODO: add a function to update the active/inactive sets based on the current feature set
pub fn newAllActivated(allocator: std.mem.Allocator) !ReservedAccountKeys {
    var active: std.AutoHashMapUnmanaged(Pubkey, void) = .{};
    for (RESERVED_ACCOUNTS) |reserved_account| {
        try active.put(allocator, reserved_account.key, {});
    }

    return .{
        .active = active,
        .inactive = std.AutoHashMapUnmanaged(Pubkey, Pubkey).empty,
    };
}

pub const ReservedAccount = struct {
    key: Pubkey,
    feature_id: ?Pubkey = null,

    pub fn newPending(key: Pubkey, feature_id: Pubkey) ReservedAccount {
        return .{
            .key = key,
            .feature_id = feature_id,
        };
    }

    pub fn newActive(key: Pubkey) ReservedAccount {
        return .{
            .key = key,
            .feature_id = null,
        };
    }

    pub fn newPendingComptime(comptime key: Pubkey, comptime feature_id: Pubkey) ReservedAccount {
        return .{
            .key = key,
            .feature_id = feature_id,
        };
    }

    pub fn newActiveComptime(comptime key: Pubkey) ReservedAccount {
        return .{
            .key = key,
            .feature_id = null,
        };
    }
};

pub const RESERVED_ACCOUNTS = [_]ReservedAccount{
    // builtin programs
    ReservedAccount.newActiveComptime(sig.runtime.program.address_lookup_table.ID),
    ReservedAccount.newActiveComptime(sig.runtime.program.bpf_loader.v2.ID),
    ReservedAccount.newActiveComptime(sig.runtime.program.bpf_loader.v1.ID),
    ReservedAccount.newActiveComptime(sig.runtime.program.bpf_loader.v3.ID),
    ReservedAccount.newActiveComptime(sig.runtime.program.compute_budget.ID),
    ReservedAccount.newActiveComptime(sig.runtime.program.config.ID),
    ReservedAccount.newActiveComptime(sig.runtime.program.precompiles.ed25519.ID),
    ReservedAccount.newActiveComptime(sig.runtime.ids.FEATURE_PROGRAM_ID),
    ReservedAccount.newActiveComptime(sig.runtime.program.bpf_loader.v4.ID),
    ReservedAccount.newActiveComptime(sig.runtime.program.precompiles.secp256k1.ID),
    ReservedAccount.newActiveComptime(sig.runtime.program.precompiles.secp256k1.ID),
    ReservedAccount.newPendingComptime(sig.runtime.program.precompiles.secp256r1.ID,
        // TODO: figure out how to use features.zon values
        Pubkey.parse("srremy31J5Y25FrAApwVb9kZcfXbusYMMsvTK9aWv5q")),
    ReservedAccount.newActiveComptime(sig.runtime.ids.STAKE_CONFIG_PROGRAM_ID),
    ReservedAccount.newActiveComptime(sig.runtime.program.stake.ID),
    ReservedAccount.newActiveComptime(sig.runtime.program.system.ID),
    ReservedAccount.newActiveComptime(sig.runtime.program.vote.ID),

    ReservedAccount.newActiveComptime(sig.runtime.program.zk_elgamal.ID),
    ReservedAccount.newActiveComptime(sig.runtime.ids.ZK_TOKEN_PROOF_PROGRAM_ID),

    // sysvars
    ReservedAccount.newActiveComptime(sig.runtime.sysvar.Clock.ID),
    ReservedAccount.newActiveComptime(sig.runtime.sysvar.EpochRewards.ID),
    ReservedAccount.newActiveComptime(sig.runtime.sysvar.EpochSchedule.ID),
    ReservedAccount.newActiveComptime(sig.runtime.sysvar.Fees.ID),
    ReservedAccount.newActiveComptime(sig.runtime.sysvar.instruction.ID),
    ReservedAccount.newActiveComptime(sig.runtime.sysvar.LastRestartSlot.ID),
    ReservedAccount.newActiveComptime(sig.runtime.sysvar.RecentBlockhashes.ID),
    ReservedAccount.newActiveComptime(sig.runtime.sysvar.Rent.ID),
    ReservedAccount.newActiveComptime(sig.runtime.ids.SYSVAR_REWARDS_ID),
    ReservedAccount.newActiveComptime(sig.runtime.sysvar.SlotHashes.ID),
    ReservedAccount.newActiveComptime(sig.runtime.sysvar.SlotHistory.ID),
    ReservedAccount.newActiveComptime(sig.runtime.sysvar.StakeHistory.ID),
    // other
    ReservedAccount.newActiveComptime(sig.runtime.ids.NATIVE_LOADER_ID),
    ReservedAccount.newActiveComptime(sig.runtime.sysvar.OWNER_ID),
};
