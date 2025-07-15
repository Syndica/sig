const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");

const core = sig.core;

const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

const Hash = core.Hash;
const LtHash = core.LtHash;
const Pubkey = core.Pubkey;
const Slot = core.Slot;

const AccountsDB = sig.accounts_db.AccountsDB;

pub const FreezeParams = struct {
    state: *sig.core.SlotState,
    hash_slot: HashSlotParams,
    update_sysvar: replay.update_sysvar.UpdateSysvarAccountDeps,
    lamports_per_signature: u64,
    blockhash: Hash,

    pub fn init(
        accounts_db: *AccountsDB,
        epoch: *const sig.core.EpochConstants,
        state: *sig.core.SlotState,
        constants: *const sig.core.SlotConstants,
        slot: Slot,
        blockhash: Hash,
    ) FreezeParams {
        return .{
            .state = state,
            .hash_slot = .{
                .accounts_db = accounts_db,
                .slot = slot,
                .parent_slot_hash = &constants.parent_hash,
                .parent_lt_hash = &constants.parent_lt_hash,
                .ancestors = &constants.ancestors,
                .blockhash = blockhash,
                .feature_set = &constants.feature_set,
                .signature_count = state.signature_count.load(.monotonic),
            },
            .update_sysvar = .{
                .accounts_db = accounts_db,
                .slot = slot,
                .ancestors = &constants.ancestors,
                .rent = &epoch.rent_collector.rent,
                .capitalization = &state.capitalization,
            },
            .blockhash = blockhash,
            .lamports_per_signature = constants.fee_rate_governor.lamports_per_signature,
        };
    }
};

// TODO: params struct, conversion from bank, separate out hash function
/// Analogous to [Bank::freeze](https://github.com/anza-xyz/agave/blob/b948b97d2a08850f56146074c0be9727202ceeff/runtime/src/bank.rs#L2620)
pub fn freezeSlot(allocator: Allocator, params: FreezeParams) !void {
    // TODO: reconsider locking the hash for the entire function.
    var slot_hash = params.state.hash.write();
    defer slot_hash.unlock();

    if (slot_hash.get().* != null) return; // already frozen

    var signature_count: [8]u8 = undefined;
    std.mem.writeInt(u64, &signature_count, params.state.signature_count.load(.monotonic), .little);

    const maybe_lt_hash, slot_hash.mut().* = try hashSlot(allocator, params.hash_slot);
    if (maybe_lt_hash) |lt_hash| params.state.accounts_lt_hash.set(lt_hash);

    try replay.update_sysvar.updateSlotHistory(allocator, params.update_sysvar);

    {
        var q = params.state.blockhash_queue.write();
        defer q.unlock();
        try q.mut().insertHash(
            allocator,
            params.blockhash,
            params.lamports_per_signature,
        );
    }
    {
        var q = params.state.blockhash_queue.read();
        defer q.unlock();
        try replay.update_sysvar.updateRecentBlockhashes(allocator, q.get(), params.update_sysvar);
    }

    // NOTE: agave updates hard_forks and hash_overrides here
}

pub const HashSlotParams = struct {
    accounts_db: *AccountsDB,
    slot: Slot,
    signature_count: u64,
    parent_slot_hash: *const Hash,
    parent_lt_hash: *const ?LtHash,
    ancestors: *const sig.core.Ancestors,
    blockhash: Hash,
    feature_set: *const sig.core.FeatureSet,
};

pub fn hashSlot(allocator: Allocator, params: HashSlotParams) !struct { ?LtHash, Hash } {
    var signature_count_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &signature_count_bytes, params.signature_count, .little);

    if (params.feature_set.active.contains(sig.core.features.ACCOUNTS_LT_HASH)) {
        var parent_ancestors = try params.ancestors.clone(allocator);
        defer parent_ancestors.deinit(allocator);
        assert(parent_ancestors.ancestors.swapRemove(params.slot));

        var lt_hash = params.parent_lt_hash.* orelse return error.UnknownParentLtHash;
        lt_hash.mixIn(&try params.accounts_db.deltaLtHash(params.slot, &parent_ancestors));

        return .{ lt_hash, Hash.generateSha256(.{
            &Hash.generateSha256(.{
                &params.parent_slot_hash.data,
                &signature_count_bytes,
                &params.blockhash.data,
            }).data,
            lt_hash.bytes(),
        }) };
    } else {
        const accounts_hash = try params.accounts_db.deltaMerkleHash(allocator, params.slot);
        return .{ null, Hash.generateSha256(.{
            &params.parent_slot_hash.data,
            &accounts_hash.data,
            &signature_count_bytes,
            &params.blockhash.data,
        }) };
    }
}
