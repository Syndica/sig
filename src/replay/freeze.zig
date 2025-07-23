const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");

const core = sig.core;

const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

const Ancestors = core.Ancestors;
const Hash = core.Hash;
const LtHash = core.LtHash;
const Pubkey = core.Pubkey;
const Slot = core.Slot;

const AccountReader = sig.accounts_db.AccountReader;

pub const FreezeParams = struct {
    state: *sig.core.SlotState,
    hash_slot: HashSlotParams,
    lamports_per_signature: u64,
    blockhash: Hash,

    pub fn init(
        account_reader: AccountReader,
        state: *sig.core.SlotState,
        constants: *const sig.core.SlotConstants,
        slot: Slot,
        blockhash: Hash,
    ) FreezeParams {
        return .{
            .state = state,
            .hash_slot = .{
                .account_reader = account_reader,
                .slot = slot,
                .parent_slot_hash = &constants.parent_hash,
                .parent_lt_hash = &constants.parent_lt_hash,
                .ancestors = &constants.ancestors,
                .blockhash = blockhash,
                .feature_set = &constants.feature_set,
                .signature_count = state.signature_count.load(.monotonic),
            },
            .blockhash = blockhash,
            .lamports_per_signature = constants.fee_rate_governor.lamports_per_signature,
        };
    }
};

/// Analogous to [Bank::freeze](https://github.com/anza-xyz/agave/blob/b948b97d2a08850f56146074c0be9727202ceeff/runtime/src/bank.rs#L2620)
pub fn freezeSlot(allocator: Allocator, params: FreezeParams) !void {
    // TODO: reconsider locking the hash for the entire function. (this is how agave does it)
    var slot_hash = params.state.hash.write();
    defer slot_hash.unlock();

    if (slot_hash.get().* != null) return; // already frozen

    var signature_count: [8]u8 = undefined;
    std.mem.writeInt(u64, &signature_count, params.state.signature_count.load(.monotonic), .little);

    const maybe_lt_hash, slot_hash.mut().* = try hashSlot(allocator, params.hash_slot);
    if (maybe_lt_hash) |lt_hash| params.state.accounts_lt_hash.set(lt_hash);

    // TODO: after PR #801
    // try replay.update_sysvar.updateSlotHistory(allocator, params.update_sysvar);
    // {
    //     var q = params.state.blockhash_queue.write();
    //     defer q.unlock();
    //     try q.mut().insertHash(
    //         allocator,
    //         params.blockhash,
    //         params.lamports_per_signature,
    //     );
    // }
    // {
    //     var q = params.state.blockhash_queue.read();
    //     defer q.unlock();
    //     try replay.update_sysvar.updateRecentBlockhashes(allocator, q.get(), params.update_sysvar);
    // }

    // NOTE: agave updates hard_forks and hash_overrides here
}

pub const HashSlotParams = struct {
    account_reader: AccountReader,
    slot: Slot,
    signature_count: u64,
    parent_slot_hash: *const Hash,
    parent_lt_hash: *const ?LtHash,
    ancestors: *const Ancestors,
    blockhash: Hash,
    feature_set: *const sig.core.FeatureSet,
};

/// Calculates the slot hash (known as the "bank hash" in agave)
pub fn hashSlot(allocator: Allocator, params: HashSlotParams) !struct { ?LtHash, Hash } {
    var signature_count_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &signature_count_bytes, params.signature_count, .little);

    const initial_hash =
        if (params.feature_set.active.contains(sig.core.features.REMOVE_ACCOUNTS_DELTA_HASH))
            Hash.generateSha256(.{
                params.parent_slot_hash,
                try deltaMerkleHash(params.account_reader, allocator, params.slot),
                &signature_count_bytes,
                params.blockhash,
            })
        else
            Hash.generateSha256(.{
                params.parent_slot_hash,
                &signature_count_bytes,
                params.blockhash,
            });

    if (params.feature_set.active.contains(sig.core.features.ACCOUNTS_LT_HASH)) {
        var parent_ancestors = try params.ancestors.clone(allocator);
        defer parent_ancestors.deinit(allocator);
        assert(parent_ancestors.ancestors.swapRemove(params.slot));

        var lt_hash = params.parent_lt_hash.* orelse return error.UnknownParentLtHash;
        lt_hash.mixIn(&try deltaLtHash(params.account_reader, params.slot, &parent_ancestors));

        return .{ lt_hash, Hash.generateSha256(.{ initial_hash, lt_hash.bytes() }) };
    } else {
        return .{ null, initial_hash };
    }
}

/// Returns the merkle root of all accounts modified in the slot
pub fn deltaMerkleHash(
    account_reader: AccountReader,
    allocator: Allocator,
    slot: Slot,
) !Hash {
    const pubkey_hashes = pkh: {
        var iterator = account_reader.slotModifiedIterator(slot) orelse return .ZEROES;
        defer iterator.unlock();

        const pubkey_hashes = try allocator.alloc(struct { Pubkey, Hash }, iterator.len());
        defer allocator.free(pubkey_hashes);

        var i: usize = 0;
        while (try iterator.next()) |pubkey_account| : (i += 1) {
            const pubkey, const account = pubkey_account;
            pubkey_hashes[i] = .{ pubkey, account.hash(Hash, &pubkey) };
        }

        break :pkh pubkey_hashes;
    };

    std.mem.sort(struct { Pubkey, Hash }, pubkey_hashes, {}, struct {
        fn lt(_: void, lhs: struct { Pubkey, Hash }, rhs: struct { Pubkey, Hash }) bool {
            return std.mem.order(u8, &lhs[0].data, &rhs[0].data) == .lt;
        }
    }.lt);

    // TODO put more thought into the nesting - should there be multiple?
    // is NestedHashTree the right data structure?
    const hashes = try allocator.alloc(Hash, pubkey_hashes.len);
    defer allocator.free(hashes);
    for (hashes, 0..) |*h, j| {
        h.* = pubkey_hashes[j][1];
    }
    const hash_tree = sig.utils.merkle_tree.NestedHashTree{ .items = &.{hashes} };

    const hash = try sig.utils.merkle_tree
        .computeMerkleRoot(&hash_tree, sig.accounts_db.db.MERKLE_FANOUT);

    return hash.*;
}

/// Returns the lattice hash of every account that was modified in the slot.
pub fn deltaLtHash(
    account_reader: AccountReader,
    slot: Slot,
    parent_ancestors: *const Ancestors,
) !LtHash {
    assert(!parent_ancestors.ancestors.contains(slot));

    // TODO: perf - consider using a thread pool
    // TODO: perf - consider caching old hashes

    var iterator = account_reader.slotModifiedIterator(slot) orelse return .IDENTITY;
    defer iterator.unlock();

    var hash = LtHash.IDENTITY;
    var i: usize = 0;
    while (try iterator.next()) |pubkey_account| : (i += 1) {
        const pubkey, const account = pubkey_account;
        if (try account_reader.get(pubkey, parent_ancestors)) |old_acct| {
            if (!old_acct.equals(&account)) {
                hash.mixOut(&old_acct.hash(LtHash, &pubkey));
                hash.mixIn(&account.hash(LtHash, &pubkey));
            }
        } else {
            hash.mixIn(&account.hash(LtHash, &pubkey));
        }
    }

    return hash;
}
