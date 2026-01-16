const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");
const tracy = @import("tracy");

const core = sig.core;
const features = sig.core.features;

const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

const Logger = sig.trace.Logger(@typeName(@This()));

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

    thread_pool: *sig.sync.ThreadPool,

    slot_hash: *sig.sync.RwMux(?Hash),
    accounts_lt_hash: *sig.sync.Mux(?LtHash),

    hash_slot: HashSlotParams,
    finalize_state: FinalizeStateParams,

    pub fn init(
        logger: Logger,
        account_store: AccountStore,
        thread_pool: *sig.sync.ThreadPool,
        epoch: *const EpochConstants,
        state: *SlotState,
        constants: *const SlotConstants,
        slot: Slot,
        blockhash: Hash,
    ) FreezeParams {
        return .{
            .logger = logger,
            .slot_hash = &state.hash,
            .thread_pool = thread_pool,
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
                    .slot = slot,
                    .slot_store = account_store.forSlot(slot, &constants.ancestors),
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
    var zone = tracy.Zone.init(@src(), .{ .name = "freezeSlot" });
    zone.value(params.finalize_state.slot);
    defer zone.deinit();

    // TODO: reconsider locking the hash for the entire function. (this is how agave does it)
    var slot_hash = params.slot_hash.write();
    defer slot_hash.unlock();

    if (slot_hash.get().* != null) return; // already frozen

    try finalizeState(allocator, params.finalize_state);

    const maybe_lt_hash, slot_hash.mut().* = try hashSlot(
        allocator,
        params.hash_slot,
        params.thread_pool,
    );
    if (maybe_lt_hash) |lt_hash| params.accounts_lt_hash.set(lt_hash);

    params.logger.info().logf(
        "froze slot {} with hash {s}",
        .{ params.hash_slot.slot, slot_hash.get().*.?.base58String().slice() },
    );

    tracy.frameMarkNamed("slots frozen");

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
    var zone = tracy.Zone.init(@src(), .{ .name = "finalizeState" });
    zone.value(params.slot);
    defer zone.deinit();

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
    if (try params.account_reader.get(
        allocator,
        sig.runtime.ids.INCINERATOR,
    )) |incinerator_account| {
        defer incinerator_account.deinit(allocator);

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
    const zone = tracy.Zone.init(@src(), .{ .name = "distributeTransactionFees" });
    defer zone.deinit();

    var burn = collected_transaction_fees * rent.burn_percent / 100;
    const total_fees = collected_priority_fees + collected_transaction_fees;
    const payout = total_fees -| burn;

    if (payout > 0) blk: {
        const post_balance = tryPayoutFees(
            allocator,
            account_store,
            account_reader,
            rent,
            slot,
            collector_id,
            payout,
        ) catch |err| switch (err) {
            error.InvalidAccountOwner,
            error.LamportOverflow,
            error.InvalidRentPayingAccount,
            => {
                burn = total_fees;
                break :blk;
            },
            else => return err,
        };
        // TODO: record rewards returned by tryPayoutFees
        _ = post_balance;
    }

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
) !u64 {
    var fee_collector_account =
        if (try account_reader.get(allocator, collector_id)) |old_account| blk: {
            defer old_account.deinit(allocator);

            break :blk AccountSharedData{
                .data = try old_account.data.readAllAllocate(allocator),
                .lamports = old_account.lamports,
                .owner = old_account.owner,
                .executable = old_account.executable,
                .rent_epoch = old_account.rent_epoch,
            };
        } else AccountSharedData.EMPTY;
    defer fee_collector_account.deinit(allocator);

    if (!fee_collector_account.owner.equals(&sig.runtime.program.system.ID)) {
        return error.InvalidAccountOwner;
    }
    fee_collector_account.lamports = std.math.add(u64, fee_collector_account.lamports, payout) catch
        return error.LamportOverflow;
    if (!rent.isExempt(fee_collector_account.lamports, fee_collector_account.data.len)) {
        return error.InvalidRentPayingAccount;
    }

    // duplicates fee_collector_account, so we need to free it.
    try account_store.put(slot, collector_id, fee_collector_account);

    return fee_collector_account.lamports;
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
pub fn hashSlot(
    allocator: Allocator,
    params: HashSlotParams,
    thread_pool: *sig.sync.ThreadPool,
) !struct { ?LtHash, Hash } {
    var zone = tracy.Zone.init(@src(), .{ .name = "hashSlot" });
    defer zone.deinit();

    var signature_count_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &signature_count_bytes, params.signature_count, .little);

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(&params.parent_slot_hash.data);
    const remove_delta_hash = params.feature_set.active(.remove_accounts_delta_hash, params.slot);
    if (!remove_delta_hash) {
        const merkle_hash = try deltaMerkleHash(params.account_reader, allocator, params.slot);
        hasher.update(&merkle_hash.data);
    }
    hasher.update(&signature_count_bytes);
    hasher.update(&params.blockhash.data);

    const initial_hash = hasher.finalResult();

    if (params.feature_set.active(.accounts_lt_hash, params.slot)) {
        var parent_ancestors = try params.ancestors.clone(allocator);
        defer parent_ancestors.deinit(allocator);
        assert(parent_ancestors.ancestors.swapRemove(params.slot));

        var lt_hash = params.parent_lt_hash.* orelse return error.UnknownParentLtHash;
        lt_hash.mixIn(try deltaLtHash(
            allocator,
            thread_pool,
            params.account_reader,
            params.slot,
            &parent_ancestors,
        ));

        return .{
            lt_hash,
            Hash.initMany(&.{ &initial_hash, lt_hash.constBytes() }),
        };
    } else {
        return .{
            null,
            .{ .data = initial_hash },
        };
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
        while (try iterator.next(allocator)) |pubkey_account| : (i += 1) {
            const pubkey, const account = pubkey_account;
            defer account.deinit(allocator);
            pubkey_hashes[i] = .{ pubkey, account.hash(pubkey) };
        }

        break :pkh pubkey_hashes;
    };
    defer allocator.free(pubkey_hashes);

    std.mem.sort(struct { Pubkey, Hash }, pubkey_hashes, {}, struct {
        fn lt(_: void, lhs: struct { Pubkey, Hash }, rhs: struct { Pubkey, Hash }) bool {
            return std.mem.order(u8, &lhs[0].data, &rhs[0].data) == .lt;
        }
    }.lt);

    // TODO put more thought into how to layout the merkle tree
    const hashes = try allocator.alloc(Hash, pubkey_hashes.len);
    defer allocator.free(hashes);
    for (hashes, pubkey_hashes) |*h, pubkey_hash| {
        h.* = pubkey_hash[1];
    }

    const hash = try sig.utils.merkle_tree.computeMerkleRoot(
        &.{hashes},
        sig.accounts_db.db.MERKLE_FANOUT,
    );

    return hash;
}

/// Returns the lattice hash of every account that was modified in the slot.
pub fn deltaLtHash(
    allocator: std.mem.Allocator,
    _: *sig.sync.ThreadPool, // TODO: remove
    account_reader: AccountReader,
    slot: Slot,
    parent_ancestors: *const Ancestors,
) !LtHash {
    assert(!parent_ancestors.containsSlot(slot));

    const Task = struct {
        fn run(
            gpa: std.mem.Allocator,
            slot_index: *sig.accounts_db.Two.Unrooted.SlotIndex,
            db: *sig.accounts_db.Two,
            ancestors: *const Ancestors,
            hash: *LtHash,
            start_index: usize,
            end_index: usize,
        ) !void {
            const entries = slot_index.entries;
            const accounts = entries.values()[start_index..end_index];
            const keys = entries.keys()[start_index..end_index];

            var arena_state: std.heap.ArenaAllocator = .init(gpa);
            defer arena_state.deinit();
            const arena = arena_state.allocator();

            for (accounts, keys) |data, key| {
                const account = data.asAccount();
                if (try db.get(arena, key, ancestors)) |old_account| {
                    if (!old_account.equals(&account)) {
                        hash.mixOut(old_account.ltHash(key));
                        hash.mixIn(account.ltHash(key));
                    }
                } else hash.mixIn(account.ltHash(key));
            }
        }
    };

    var iterator = account_reader.slotModifiedIterator(slot) orelse return .IDENTITY;
    defer iterator.unlock();

    const NUM_THREADS = 8;

    // TODO: We want to improve how the delta lthashes are computed even further.
    // We want to incrementally build up the lthash over the course of the runtime
    // execution, simply queuing it as a task in the general txn-exec pool. We have
    // large enough gaps in the transaction scheduling graph that we can trivially
    // compute (and over-compute, by re-hashing the same account modifications several times)
    // during the execution.
    const Pool = sig.utils.thread.ScopedThreadPool(Task.run);
    var tp: *Pool = try .init(allocator, NUM_THREADS);
    defer tp.deinit(allocator);

    var hashes: [NUM_THREADS]LtHash = @splat(.IDENTITY);
    var start_index: usize = 0;
    for (0..NUM_THREADS) |i| {
        const chunk_size = iterator.len() / NUM_THREADS;
        const end_index = switch (i) {
            NUM_THREADS - 1 => iterator.len(),
            else => start_index + chunk_size,
        };
        defer start_index = end_index;

        try tp.schedule(allocator, .{
            allocator,
            iterator.accounts_db_two.slot,
            account_reader.accounts_db_two,
            parent_ancestors,
            &hashes[i],
            start_index,
            end_index,
        });
    }

    try tp.join();

    var final: LtHash = .IDENTITY;
    for (hashes) |hash| final = final.add(hash);
    return final;
}

test "deltaLtHash is identity for 0 accounts" {
    const allocator = std.testing.allocator;

    var test_state = try sig.accounts_db.Two.initTest(allocator);
    defer test_state.deinit();

    var tp: sig.sync.ThreadPool = .init(.{});
    defer {
        tp.shutdown();
        tp.deinit();
    }

    try std.testing.expectEqual(LtHash.IDENTITY, try deltaLtHash(
        allocator,
        &tp,
        .{ .accounts_db_two = &test_state.db },
        0,
        &Ancestors{},
    ));
}

test "deltaMerkleHash for 0 accounts" {
    try std.testing.expectEqual(
        Hash.parse("GKot5hBsd81kMupNCXHaqbhv3huEbxAFMLnpcX2hniwn"),
        try deltaMerkleHash(.noop, sig.utils.allocators.failing.allocator(.{}), 0),
    );
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

    var test_state = try sig.accounts_db.Two.initTest(allocator);
    defer test_state.deinit();
    const account_store: AccountStore = .{ .accounts_db_two = &test_state.db };

    const epoch = EpochConstants.genesis(.default(allocator));
    defer epoch.deinit(allocator);

    const constants = try SlotConstants.genesis(allocator, .DEFAULT);
    defer constants.deinit(allocator);

    var state: SlotState = .GENESIS;
    defer state.deinit(allocator);

    var tp: sig.sync.ThreadPool = .init(.{});
    defer {
        tp.shutdown();
        tp.deinit();
    }
    try freezeSlot(allocator, .init(
        .FOR_TESTS,
        account_store,
        &tp,
        &epoch,
        &state,
        &constants,
        0,
        .ZEROES,
    ));

    try std.testing.expectEqual(
        Hash.parse("8C4gpDhMz9RfajteNCf9nFb5pyj3SkFcpTs6uXAzYKoF"),
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

    var test_state = try sig.accounts_db.Two.initTest(allocator);
    defer test_state.deinit();
    const real_state = &test_state.db;

    var tp: sig.sync.ThreadPool = .init(.{});
    defer {
        tp.shutdown();
        tp.deinit();
    }

    const account_store: sig.accounts_db.AccountStore = .{ .accounts_db_two = real_state };

    const epoch = EpochConstants.genesis(.default(allocator));
    defer epoch.deinit(allocator);

    var constants = try SlotConstants.genesis(allocator, .DEFAULT);
    defer constants.deinit(allocator);
    constants.feature_set.setSlot(.accounts_lt_hash, 0);
    constants.feature_set.setSlot(.remove_accounts_delta_hash, 0);

    var state: SlotState = .GENESIS;
    defer state.deinit(allocator);

    try freezeSlot(allocator, .init(
        .FOR_TESTS,
        account_store,
        &tp,
        &epoch,
        &state,
        &constants,
        0,
        .ZEROES,
    ));

    try std.testing.expectEqual(
        Hash.parse("B513RgkSxeiHv4hJ3aaBfkoveWKeB6575S3CtG64AirS"),
        state.hash.readCopy().?,
    );
}

// Ensures that the merkle and lattice hashes are both identical to agave for
// accountsdb with hundreds of accounts on multiple slots.
//
// Mostly the inputs are randomly generated, but there is special logic to
// ensure certain edge cases are covered:
// - 0 lamport accounts are hashed
// - some accounts need to be mixed out, but not all
// - mixed out accounts must come from 1 or 2 slots prior
// - the same pubkey from a non-ancestors slot must *not* be mixed out
// - irrelevant accounts exist in past and future slots that must be ignored
//
// Set `generate_rust_code` to true to print the exact code that you can copy
// into a test in agave to replicate these outputs.
test "delta hashes with many accounts" {
    const allocator = std.testing.allocator;
    const generate_rust_code = false;

    var test_state = try sig.accounts_db.Two.initTest(allocator);
    defer test_state.deinit();
    const db = &test_state.db;

    var rng: std.Random.Xoshiro256 = .init(0);
    const random = rng.random();

    var addresses = try std.ArrayListUnmanaged(Pubkey).initCapacity(allocator, 400);
    defer addresses.deinit(allocator);

    const hash_slot = 2; // changing this may require changing ancestors in 2 places

    if (generate_rust_code) std.debug.print(
        \\.
        \\let accounts_db = Arc::new(AccountsDb::default_for_tests());
        \\let accounts = Accounts::new(accounts_db.clone());
        \\let mut bank = Bank::default_with_accounts(accounts);
        \\bank.slot = {};
        \\bank.ancestors.insert(0, 0);
        \\bank.ancestors.insert(1, 0);
        \\let mut features = FeatureSet::default();
        \\features.activate(&feature_set::accounts_lt_hash::id(), 0);
        \\bank.feature_set = Arc::new(features);
        \\
    , .{hash_slot});

    for (0..4) |slot| {
        if (generate_rust_code)
            std.debug.print("accounts_db.store_cached(({}u64,\n    &[\n", .{slot});
        for (0..100) |_| {
            const address = if (slot == 0 or random.boolean()) a: {
                const address = Pubkey.initRandom(random);
                addresses.appendAssumeCapacity(address);
                break :a address;
            } else addresses.items[random.intRangeLessThan(usize, 0, addresses.items.len)];

            const data = try allocator.alloc(u8, random.int(u8));
            defer allocator.free(data);
            random.bytes(data);
            const account: AccountSharedData = .{
                .data = data,
                .owner = Pubkey.initRandom(random),
                .rent_epoch = random.int(sig.core.Epoch),
                .lamports = if (random.intRangeAtMost(u64, 0, 5) == 0) 0 else random.int(u64),
                .executable = random.boolean(),
            };

            if (generate_rust_code) {
                const data_string = try std.fmt.allocPrint(allocator, "{any}", .{data});
                defer allocator.free(data_string);
                std.debug.print(
                    \\        (
                    \\            Pubkey::try_from("{}").unwrap(),
                    \\            AccountSharedData::from(Account {{
                    \\                lamports: {},
                    \\                data: vec![{s}],
                    \\                owner: Pubkey::try_from("{}").unwrap(),
                    \\                executable: {},
                    \\                rent_epoch: {},
                    \\            }}),
                    \\        ),
                    \\
                , .{
                    address,
                    account.lamports,
                    data_string[1 .. data_string.len - 1],
                    account.owner,
                    account.executable,
                    account.rent_epoch,
                });
            }

            try db.put(slot, address, account);
        }
        if (generate_rust_code) std.debug.print("][0..]));\n", .{});
    }
    if (generate_rust_code) std.debug.print(
        \\let lt_hash = bank.calculate_delta_lt_hash();
        \\let merkle_hash = accounts_db.calculate_accounts_delta_hash_internal({}, None);
        \\println!("{{:?}}", lt_hash);
        \\println!("{{:?}}", merkle_hash);
        \\
    , .{hash_slot});

    // sig fmt: off
    const expected_lt_hash = [1024]u16{ 59065, 31437, 27738, 25731, 11852, 64853, 24563, 65217, 2574, 28248, 48973, 54236, 31227, 34672, 10334, 50851, 9755, 50155, 23973, 3940, 46299, 59334, 3457, 19944, 31013, 51016, 61238, 11264, 52234, 22371, 63359, 40808, 29506, 38480, 61126, 32981, 18656, 55133, 43826, 64915, 12868, 48590, 64092, 16948, 39842, 10881, 3830, 33824, 51862, 19124, 37113, 14987, 13612, 16481, 40416, 43673, 30160, 46125, 48490, 39628, 60561, 45886, 13100, 28846, 51252, 38464, 2505, 32562, 34168, 36883, 19013, 57338, 58461, 5218, 46768, 63917, 41703, 3042, 20008, 3608, 28577, 41909, 61434, 34322, 31777, 31041, 54259, 47319, 30155, 33980, 26006, 17180, 64163, 39087, 40260, 17840, 36897, 20227, 63721, 51310, 29573, 3365, 5730, 57531, 16551, 32529, 20345, 19295, 18450, 62905, 10600, 7070, 52747, 25234, 52965, 13951, 38929, 31482, 11625, 50608, 3925, 12545, 43693, 9078, 13244, 29024, 55139, 55296, 55435, 34308, 26996, 48018, 20965, 18205, 5945, 37920, 57243, 14696, 22051, 41949, 53453, 48681, 5615, 24213, 46972, 4848, 43171, 62006, 50184, 56064, 3555, 18000, 62438, 56680, 7137, 18579, 138, 6178, 24954, 62903, 6707, 56264, 8280, 8280, 63937, 42183, 37978, 45639, 23623, 48966, 19467, 60555, 57924, 10198, 16645, 26871, 59831, 26174, 12177, 38670, 54038, 29452, 52523, 3457, 7517, 10164, 30787, 45521, 32339, 20763, 35856, 35375, 38305, 41385, 49951, 41024, 39503, 46163, 37759, 45719, 28505, 48987, 21224, 14807, 35594, 24356, 30613, 2738, 25063, 52612, 45966, 222, 47797, 18695, 60179, 13144, 9478, 8121, 55327, 24676, 63089, 58411, 11029, 41621, 5605, 11322, 13503, 10187, 65179, 22480, 4600, 4797, 29310, 32464, 61964, 61964, 43522, 10495, 8813, 7186, 17535, 5007, 64426, 24399, 55013, 41527, 42771, 28010, 60343, 8810, 34518, 29266, 44028, 44094, 7435, 54675, 21580, 9424, 46419, 40613, 33550, 50606, 30195, 25772, 58279, 23830, 417, 44227, 19590, 51019, 612, 29431, 17578, 41313, 35100, 63770, 12748, 9207, 63238, 50622, 54747, 33913, 34255, 43959, 1732, 14108, 58596, 25137, 29570, 56648, 57962, 58946, 5583, 26218, 14917, 51851, 10485, 33038, 62769, 41900, 56273, 10180, 18256, 65333, 23741, 51749, 49225, 37910, 18587, 15792, 14317, 44510, 29121, 23232, 42910, 47527, 1301, 6046, 11068, 1827, 23556, 49209, 56843, 32030, 43751, 40384, 33830, 45745, 63379, 62215, 58986, 5590, 14630, 27329, 57986, 52077, 9857, 39940, 2712, 2740, 11150, 50770, 60261, 43521, 53045, 43594, 34498, 19860, 14867, 48661, 43917, 28698, 19644, 43046, 49473, 38570, 19896, 28378, 49872, 60084, 18229, 15017, 9200, 19595, 53653, 35206, 25881, 4558, 10223, 30811, 38137, 25254, 2704, 56696, 13681, 61024, 17725, 27180, 39877, 46091, 61209, 12173, 1384, 63631, 23215, 17754, 59890, 47168, 37438, 16090, 13355, 31571, 51100, 26377, 13184, 50362, 8597, 28365, 39967, 42974, 58412, 40861, 48715, 36626, 47179, 54098, 20544, 14246, 19588, 27748, 5574, 28924, 13351, 29802, 3306, 37287, 21258, 56230, 1014, 44959, 30395, 58494, 30526, 58409, 35800, 60857, 35023, 9108, 19650, 12316, 625, 3233, 50750, 52235, 51060, 29885, 4739, 1864, 37056, 1366, 63984, 6923, 12014, 35755, 23021, 44125, 13262, 5344, 15813, 37594, 40159, 9989, 23382, 7857, 31989, 50354, 36214, 58655, 4048, 37931, 57661, 43609, 51278, 7184, 8932, 41128, 50754, 34876, 51358, 59205, 49784, 28224, 28203, 42714, 21039, 60966, 24207, 64391, 19213, 15011, 55209, 24006, 1334, 59682, 6719, 59555, 33795, 17464, 22171, 62234, 29529, 23847, 19963, 48354, 42745, 29727, 29970, 20804, 48741, 13071, 64315, 45489, 19931, 45003, 27825, 60542, 63537, 42716, 35135, 40889, 60272, 14696, 63158, 10215, 57136, 48391, 56733, 57446, 48394, 16315, 44222, 16529, 47429, 50394, 30575, 13294, 50785, 20182, 3482, 38564, 60244, 41415, 59601, 37936, 4733, 7463, 6457, 52354, 1795, 21532, 59509, 9280, 50785, 8180, 42067, 43060, 21911, 37184, 55715, 46786, 17730, 22020, 56063, 62284, 18098, 40245, 48577, 34322, 39593, 57784, 1421, 12726, 52871, 22833, 63122, 32883, 49571, 33534, 19170, 7526, 61283, 305, 44504, 52280, 8842, 37533, 190, 889, 51741, 10381, 41083, 18442, 1665, 41590, 12596, 22990, 57601, 15437, 16764, 12929, 29732, 10785, 54742, 11724, 51436, 30716, 27338, 46479, 12500, 56846, 56906, 58684, 40563, 46077, 22072, 20559, 60597, 50599, 14866, 59995, 36667, 51209, 270, 38909, 31227, 40112, 28712, 60589, 2509, 267, 1689, 56152, 41676, 24971, 5462, 35300, 50485, 56245, 43532, 41256, 11787, 42487, 4214, 31585, 18199, 43993, 1647, 15709, 51555, 33851, 34285, 49686, 6959, 53296, 24047, 61028, 64425, 30988, 39035, 30645, 20041, 24550, 47010, 30740, 17729, 56949, 64780, 26802, 3326, 12427, 6173, 35307, 32224, 52771, 45951, 3259, 41573, 52374, 45273, 570, 54564, 28780, 31271, 14463, 22063, 19513, 29156, 50031, 42318, 64715, 63588, 10454, 52484, 10069, 57284, 62228, 20069, 33884, 24649, 10350, 15340, 56253, 31134, 64773, 9671, 35175, 38980, 18241, 28334, 28264, 27217, 30127, 46705, 62484, 20323, 31133, 33159, 55525, 47116, 56564, 4687, 46866, 36245, 35947, 29912, 26583, 20706, 2415, 16334, 3976, 53332, 20942, 32994, 60326, 19863, 64153, 38039, 18386, 1339, 28407, 37464, 8194, 16765, 26072, 47093, 14888, 43530, 58095, 42560, 52430, 50953, 59713, 62680, 55170, 15842, 25149, 15674, 35594, 54668, 48596, 65287, 23308, 49804, 56724, 13502, 35174, 10747, 35154, 59031, 52885, 48047, 44783, 59867, 61387, 61430, 6058, 30823, 56913, 558, 38185, 37941, 15973, 42369, 2000, 5373, 20769, 15408, 35716, 17423, 20667, 59590, 35118, 18561, 34677, 57928, 18010, 24931, 39298, 44419, 3982, 55509, 51154, 53051, 26058, 7655, 9807, 65095, 2669, 56240, 55209, 16162, 62680, 15399, 23612, 15857, 47200, 27388, 2834, 23887, 44069, 26669, 33507, 44804, 50110, 32846, 56502, 53949, 34173, 59701, 47450, 9388, 8557, 28533, 41968, 23786, 17029, 27280, 43382, 60940, 61536, 54980, 25686, 51167, 46778, 34609, 17869, 62315, 64257, 46295, 49357, 57116, 10247, 55706, 29943, 18153, 6143, 21741, 54918, 7660, 39475, 58377, 56028, 3931, 24947, 34404, 1110, 5799, 51499, 11708, 48267, 18523, 53406, 32584, 45269, 32213, 17136, 29926, 22882, 34379, 12992, 46833, 53614, 14152, 12872, 36340, 40665, 35202, 3702, 55356, 65336, 16160, 27084, 25642, 22131, 29682, 28259, 26351, 21859, 44345, 24029, 10345, 55079, 54714, 38143, 18305, 746, 22158, 22886, 14057, 355, 503, 10033, 23884, 38013, 62890, 36164, 48820, 9786, 49871, 51892, 46148, 681, 64689, 21264, 27906, 40353, 2092, 32003, 40026, 65235, 50055, 54960, 3424, 38582, 3939, 44007, 37703, 36481, 33042, 12488, 10149, 24056, 49583, 47324, 24681, 44681, 15888, 56668, 25901, 22561, 43099, 9671, 17307, 1372, 4456, 22270, 36388, 7790, 63731, 38670, 29346, 11580, 42628, 30791, 27510, 54732, 21986, 61471, 41223, 24230, 58361, 5234, 21841, 44141, 4838, 50486, 23208, 39845, 45749, 34085, 4477, 57658, 9073, 60723, 5197, 37631, 7504, 37994, 17225, 11815, 32232, 35221, 51979, 4211, 41423, 9802, 11493, 9399, 32785, 34409, 12252, 62755, 17328, 45301, 16573, 37229, 49948, 48111, 1782, 42920, 63976, 24308, 64581, 33675, 21055, 24960, 12926, 46324, 17052, 15666, 9357, 33232, 1920, 47884, 25427, 20881, 7294, 1718, 24777, 55421, 35855, 63261, 40672, 62018 };
    // sig fmt: on
    const expected_merkle_hash: Hash = .parse("5tpzYxp8ghAETjXaXnZvxZov11iNEvSbDZXNAMoJX6ov");

    var parent_ancestors: Ancestors = .{};
    defer parent_ancestors.deinit(allocator);
    try parent_ancestors.ancestors.put(allocator, 0, {});
    try parent_ancestors.ancestors.put(allocator, 1, {});

    var tp: sig.sync.ThreadPool = .init(.{});
    defer {
        tp.shutdown();
        tp.deinit();
    }

    const actual_lt_hash = try deltaLtHash(
        allocator,
        &tp,
        .{ .accounts_db_two = db },
        hash_slot,
        &parent_ancestors,
    );
    const actual_merkle_hash = try deltaMerkleHash(
        .{ .accounts_db_two = db },
        allocator,
        hash_slot,
    );

    try std.testing.expectEqualSlices(u16, &expected_lt_hash, &actual_lt_hash.data);
    try std.testing.expectEqualSlices(u8, &expected_merkle_hash.data, &actual_merkle_hash.data);
}
