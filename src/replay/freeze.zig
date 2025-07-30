const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");

const core = sig.core;
const features = sig.core.features;

const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

const Logger = sig.trace.ScopedLogger(@typeName(@This()));

const Ancestors = core.Ancestors;
const EpochConstants = core.EpochConstants;
const Hash = core.Hash;
const LtHash = core.LtHash;
const Pubkey = core.Pubkey;
const Slot = core.Slot;
const SlotState = core.SlotState;
const SlotConstants = core.SlotConstants;

const AccountSharedData = sig.runtime.AccountSharedData;
const Rent = sig.runtime.sysvar.Rent;

const AccountStore = sig.accounts_db.AccountStore;
const AccountReader = sig.accounts_db.AccountReader;
const SlotAccountReader = sig.accounts_db.SlotAccountReader;

const UpdateSysvarAccountDeps = replay.update_sysvar.UpdateSysvarAccountDeps;
const updateSlotHistory = replay.update_sysvar.updateSlotHistory;
const updateRecentBlockhashes = replay.update_sysvar.updateRecentBlockhashes;

pub const FreezeParams = struct {
    logger: Logger,

    slot_hash: *sig.sync.RwMux(?Hash),
    accounts_lt_hash: *sig.sync.Mux(?LtHash),

    hash_slot: HashSlotParams,
    finalize_state: FinalizeStateParams,

    pub fn init(
        logger: Logger,
        account_store: AccountStore,
        epoch: *const EpochConstants,
        state: *SlotState,
        constants: *const SlotConstants,
        slot: Slot,
        blockhash: Hash,
    ) FreezeParams {
        return .{
            .logger = logger,
            .slot_hash = &state.hash,
            .accounts_lt_hash = &state.accounts_lt_hash,
            .hash_slot = .{
                .account_reader = account_store.reader(),
                .slot = slot,
                .parent_slot_hash = &constants.parent_hash,
                .parent_lt_hash = &constants.parent_lt_hash,
                .ancestors = &constants.ancestors,
                .blockhash = blockhash,
                .feature_set = &constants.feature_set,
                .signature_count = state.signature_count.load(.monotonic),
            },
            .finalize_state = .{
                .update_sysvar = .{
                    .account_store = account_store,
                    .slot = slot,
                    .ancestors = &constants.ancestors,
                    .rent = &epoch.rent_collector.rent,
                    .capitalization = &state.capitalization,
                },
                .account_store = account_store,
                .account_reader = account_store.reader().forSlot(&constants.ancestors),
                .capitalization = &state.capitalization,
                .blockhash_queue = &state.blockhash_queue,
                .rent = epoch.rent_collector.rent,
                .slot = slot,
                .blockhash = blockhash,
                .lamports_per_signature = constants.fee_rate_governor.lamports_per_signature,
                .collector_id = constants.collector_id,
                .collected_transaction_fees = state.collected_transaction_fees.load(.monotonic),
                .collected_priority_fees = state.collected_priority_fees.load(.monotonic),
            },
        };
    }
};

/// Handles the "freezing" of a slot which occurs after a block has finished
/// execution. This finalizes some last bits of state and then calculates the
/// hash for the slot.
///
/// Analogous to [Bank::freeze](https://github.com/anza-xyz/agave/blob/b948b97d2a08850f56146074c0be9727202ceeff/runtime/src/bank.rs#L2620)
pub fn freezeSlot(allocator: Allocator, params: FreezeParams) !void {
    // TODO: reconsider locking the hash for the entire function. (this is how agave does it)
    var slot_hash = params.slot_hash.write();
    defer slot_hash.unlock();

    if (slot_hash.get().* != null) return; // already frozen

    try finalizeState(allocator, params.finalize_state);

    const maybe_lt_hash, slot_hash.mut().* = try hashSlot(allocator, params.hash_slot);
    if (maybe_lt_hash) |lt_hash| params.accounts_lt_hash.set(lt_hash);

    params.logger.info().logf(
        "froze slot {} with hash {s}",
        .{ params.hash_slot.slot, slot_hash.get().*.?.base58String().slice() },
    );

    // NOTE: agave updates hard_forks and hash_overrides here
}

const FinalizeStateParams = struct {
    /// nested dependencies
    update_sysvar: UpdateSysvarAccountDeps,

    // shared state
    account_store: AccountStore,
    account_reader: SlotAccountReader,
    capitalization: *std.atomic.Value(u64),
    blockhash_queue: *sig.sync.RwMux(sig.core.BlockhashQueue),

    // data params
    rent: Rent,
    slot: Slot,
    blockhash: Hash,
    lamports_per_signature: u64,
    collector_id: Pubkey,
    collected_transaction_fees: u64,
    collected_priority_fees: u64,
};

/// Updates some accounts and other shared state to finish up the slot execution.
fn finalizeState(allocator: Allocator, params: FinalizeStateParams) !void {
    // Update recent blockhashes (NOTE: agave does this in registerTick)
    {
        var q = params.blockhash_queue.write();
        defer q.unlock();
        try q.mut().insertHash(allocator, params.blockhash, params.lamports_per_signature);
    }
    {
        var q = params.blockhash_queue.read();
        defer q.unlock();
        try updateRecentBlockhashes(allocator, q.get(), params.update_sysvar);
    }

    try distributeTransactionFees(
        allocator,
        params.account_store,
        params.account_reader,
        params.capitalization,
        params.rent,
        params.slot,
        params.collector_id,
        params.collected_transaction_fees,
        params.collected_priority_fees,
    );

    // Run incinerator
    if (try params.account_reader.get(sig.runtime.ids.INCINERATOR)) |incinerator_account| {
        _ = params.capitalization.fetchSub(incinerator_account.lamports, .monotonic);
        try params.account_store.put(
            params.update_sysvar.slot,
            sig.runtime.ids.INCINERATOR,
            .EMPTY,
        );
    }

    try updateSlotHistory(allocator, params.update_sysvar);
}

/// Burn and payout the appropriate portions of collected fees.
fn distributeTransactionFees(
    allocator: Allocator,
    account_store: AccountStore,
    account_reader: SlotAccountReader,
    capitalization: *std.atomic.Value(u64),
    rent: Rent,
    slot: Slot,
    collector_id: Pubkey,
    collected_transaction_fees: u64,
    collected_priority_fees: u64,
) !void {
    var burn = collected_transaction_fees * 50 / 100;
    const total_fees = collected_priority_fees + collected_transaction_fees;
    const payout = total_fees -| burn;
    tryPayoutFees(
        allocator,
        account_store,
        account_reader,
        rent,
        slot,
        collector_id,
        payout,
    ) catch |e|
        switch (e) {
            error.InvalidAccountOwner,
            error.LamportOverflow,
            error.InvalidRentPayingAccount,
            => burn = total_fees,
            else => return e,
        };
    _ = capitalization.fetchSub(burn, .monotonic);
}

/// Attempt to pay the payout to the collector.
fn tryPayoutFees(
    allocator: Allocator,
    account_store: AccountStore,
    account_reader: SlotAccountReader,
    rent: Rent,
    slot: Slot,
    collector_id: Pubkey,
    payout: u64,
) !void {
    var fee_collector_account =
        if (try account_reader.get(collector_id)) |old_account|
            AccountSharedData{
                .data = try old_account.data.readAllAllocate(allocator),
                .lamports = old_account.lamports,
                .owner = old_account.owner,
                .executable = old_account.executable,
                .rent_epoch = old_account.rent_epoch,
            }
        else
            AccountSharedData.EMPTY;

    if (!fee_collector_account.owner.equals(&sig.runtime.program.system.ID)) {
        return error.InvalidAccountOwner;
    }
    fee_collector_account.lamports = std.math.add(u64, fee_collector_account.lamports, payout) catch
        return error.LamportOverflow;
    if (!rent.isExempt(fee_collector_account.lamports, fee_collector_account.data.len)) {
        return error.InvalidRentPayingAccount;
    }

    try account_store.put(slot, collector_id, fee_collector_account);
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
                &signature_count_bytes,
                params.blockhash,
            })
        else
            Hash.generateSha256(.{
                params.parent_slot_hash,
                try deltaMerkleHash(params.account_reader, allocator, params.slot),
                &signature_count_bytes,
                params.blockhash,
            });

    if (params.feature_set.active.contains(sig.core.features.ACCOUNTS_LT_HASH)) {
        var parent_ancestors = try params.ancestors.clone(allocator);
        defer parent_ancestors.deinit(allocator);
        assert(parent_ancestors.ancestors.swapRemove(params.slot));

        var lt_hash = params.parent_lt_hash.* orelse return error.UnknownParentLtHash;
        lt_hash.mixIn(try deltaLtHash(params.account_reader, params.slot, &parent_ancestors));

        return .{ lt_hash, Hash.generateSha256(.{ initial_hash, lt_hash.bytes() }) };
    } else {
        return .{ null, initial_hash };
    }
}

/// Returns the merkle root of all accounts modified in the slot
pub fn deltaMerkleHash(account_reader: AccountReader, allocator: Allocator, slot: Slot) !Hash {
    const pubkey_hashes = pkh: {
        var iterator = account_reader.slotModifiedIterator(slot) orelse return .ZEROES;
        defer iterator.unlock();

        const pubkey_hashes = try allocator.alloc(struct { Pubkey, Hash }, iterator.len());
        errdefer allocator.free(pubkey_hashes);

        var i: usize = 0;
        while (try iterator.next()) |pubkey_account| : (i += 1) {
            const pubkey, const account = pubkey_account;
            pubkey_hashes[i] = .{ pubkey, account.hash(pubkey) };
            account.deinit(allocator);
        }

        break :pkh pubkey_hashes;
    };
    defer allocator.free(pubkey_hashes);

    std.mem.sort(struct { Pubkey, Hash }, pubkey_hashes, {}, struct {
        fn lt(_: void, lhs: struct { Pubkey, Hash }, rhs: struct { Pubkey, Hash }) bool {
            return std.mem.order(u8, &lhs[0].data, &rhs[0].data) == .lt;
        }
    }.lt);

    // TODO put more thought into the nesting - should there be multiple?
    // is NestedHashTree the right data structure?
    const hashes = try allocator.alloc(Hash, pubkey_hashes.len);
    defer allocator.free(hashes);
    for (hashes, pubkey_hashes) |*h, pubkey_hash| {
        h.* = pubkey_hash[1];
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
    assert(!parent_ancestors.containsSlot(slot));

    // TODO: perf - consider using a thread pool
    // TODO: perf - consider caching old hashes

    var iterator = account_reader.slotModifiedIterator(slot) orelse return .IDENTITY;
    defer iterator.unlock();

    var hash = LtHash.IDENTITY;
    var i: usize = 0;
    while (try iterator.next()) |pubkey_account| : (i += 1) {
        const pubkey, const account = pubkey_account;
        defer account.deinit(account_reader.allocator());
        if (try account_reader.forSlot(parent_ancestors).get(pubkey)) |old_acct| {
            defer old_acct.deinit(account_reader.allocator());
            if (!old_acct.equals(&account)) {
                hash.mixOut(old_acct.ltHash(pubkey));
                hash.mixIn(account.ltHash(pubkey));
            }
        } else {
            hash.mixIn(account.ltHash(pubkey));
        }
    }

    return hash;
}

// Equivalent to this in agave:
// ```rust
// let bank = Bank::default_for_tests();
//
// let mut w_blockhash_queue = bank.blockhash_queue.write().unwrap();
// w_blockhash_queue.register_hash(&Hash::default(), 0);
// bank.update_recent_blockhashes_locked(&w_blockhash_queue);
// drop(w_blockhash_queue);
//
// bank.freeze();
// println!("{}", bank.hash());
// ```
test "freezeSlot: trivial e2e merkle hash test" {
    const allocator = std.testing.allocator;

    var accounts = sig.accounts_db.ThreadSafeAccountMap.init(allocator);
    defer accounts.deinit();
    const account_store = accounts.accountStore();

    const epoch = try EpochConstants.genesis(allocator, .default(allocator));
    defer epoch.deinit(allocator);

    const constants = try SlotConstants.genesis(allocator, .DEFAULT);
    defer constants.deinit(allocator);

    var state = SlotState.GENESIS;
    defer state.deinit(allocator);

    try freezeSlot(
        allocator,
        .init(.FOR_TESTS, account_store, &epoch, &state, &constants, 0, .ZEROES),
    );

    try std.testing.expectEqual(
        try Hash.parseBase58String("8C4gpDhMz9RfajteNCf9nFb5pyj3SkFcpTs6uXAzYKoF"),
        state.hash.readCopy().?,
    );
}

// Equivalent to this in agave:
// ```rust
// let mut bank = Bank::default_for_tests();
//
// let mut features = FeatureSet::default();
// features.activate(&feature_set::accounts_lt_hash::id(), 0);
// features.activate(&feature_set::remove_accounts_delta_hash::id(), 0);
// bank.feature_set = Arc::new(features);
//
// let mut w_blockhash_queue = bank.blockhash_queue.write().unwrap();
// w_blockhash_queue.register_hash(&Hash::default(), 0);
// bank.update_recent_blockhashes_locked(&w_blockhash_queue);
// drop(w_blockhash_queue);
//
// bank.freeze();
//
// println!("{}", bank.hash());
// ```
test "freezeSlot: trivial e2e lattice hash test" {
    const allocator = std.testing.allocator;

    var accounts = sig.accounts_db.ThreadSafeAccountMap.init(allocator);
    defer accounts.deinit();
    const account_store = accounts.accountStore();

    const epoch = try EpochConstants.genesis(allocator, .default(allocator));
    defer epoch.deinit(allocator);

    var constants = try SlotConstants.genesis(allocator, .DEFAULT);
    defer constants.deinit(allocator);
    try constants.feature_set.active.put(allocator, features.ACCOUNTS_LT_HASH, 0);
    try constants.feature_set.active.put(allocator, features.REMOVE_ACCOUNTS_DELTA_HASH, 0);

    var state = SlotState.GENESIS;
    defer state.deinit(allocator);

    try freezeSlot(
        allocator,
        .init(.FOR_TESTS, account_store, &epoch, &state, &constants, 0, .ZEROES),
    );

    try std.testing.expectEqual(
        try Hash.parseBase58String("B513RgkSxeiHv4hJ3aaBfkoveWKeB6575S3CtG64AirS"),
        state.hash.readCopy().?,
    );
}
