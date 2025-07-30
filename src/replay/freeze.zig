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

    var accounts, var tmp_dir = try sig.accounts_db.AccountsDB.initForTest(allocator);
    defer tmp_dir.cleanup();
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

test "delta hashes with many accounts" {
    const allocator = std.testing.allocator;
    const generate_rust_code = true;

    var accounts = sig.accounts_db.ThreadSafeAccountMap.init(allocator);
    defer accounts.deinit();

    var rng = std.Random.DefaultPrng.init(0);
    const random = rng.random();

    var addresses = try std.ArrayListUnmanaged(Pubkey).initCapacity(allocator, 400);
    defer addresses.deinit(allocator);

    const hash_slot = 2;

    if (generate_rust_code) std.debug.print(
        \\.
        \\let accounts_db = Arc::new(AccountsDb::default_for_tests());
        \\let accounts = Accounts::new(accounts_db.clone());
        \\let mut bank = Bank::default_with_accounts(accounts);
        \\bank.slot = {};
        \\let mut features = FeatureSet::default();
        \\features.activate(&feature_set::accounts_lt_hash::id(), 0);
        \\bank.feature_set = Arc::new(features);
        \\
    , .{hash_slot});

    for (0..4) |slot| {
        if (generate_rust_code)
            std.debug.print("accounts_db.store_cached(({}u64,\n    &[\n", .{slot});
        for (0..2) |_| {
            const address = if (slot == 0 or random.boolean()) a: {
                const address = Pubkey.initRandom(random);
                addresses.appendAssumeCapacity(address);
                break :a address;
            } else addresses.items[random.intRangeLessThan(usize, 0, addresses.items.len)];

            const data = try allocator.alloc(u8, random.int(u8));
            defer allocator.free(data);
            random.bytes(data);
            const account = AccountSharedData{
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

            try accounts.put(slot, address, account);
        }
        if (generate_rust_code) std.debug.print("][0..]));\n", .{});
    }
    if (generate_rust_code) std.debug.print(
        \\let lt_hash = bank.calculate_delta_lt_hash();
        \\let merkle_hash = accounts_db.calculate_accounts_delta_hash_internal(1, None);
        \\println!("{{:?}}", lt_hash);
        \\println!("{{:?}}", merkle_hash);
        \\
    , .{});

    // sig fmt: off
    const expected_lt_hash = [1024]u16{ 57413, 22314, 10114, 23631, 2080, 39104, 30650, 30279, 13207, 62151, 4510, 4204, 35030, 24669, 27131, 30772, 21137, 57531, 51174, 19139, 35067, 13588, 50727, 20317, 2898, 62204, 21972, 11011, 36917, 16203, 23067, 4080, 61906, 16821, 58024, 10228, 52231, 55017, 15350, 15198, 54145, 26858, 48573, 62996, 6968, 62592, 56046, 7743, 1865, 53231, 49237, 47014, 27170, 23306, 20679, 53923, 63262, 60796, 9294, 12961, 6319, 25619, 25058, 20495, 33925, 64121, 48333, 46324, 15324, 37373, 18235, 58310, 32990, 2745, 4928, 18054, 31209, 64524, 16704, 58742, 64195, 48793, 58264, 28874, 21157, 51944, 57828, 17508, 5607, 32206, 64283, 32275, 17789, 63766, 39402, 21503, 14824, 48812, 59975, 58167, 28509, 44893, 55438, 13078, 23367, 1317, 46724, 24613, 23751, 7716, 34852, 14367, 12954, 53787, 29505, 7146, 56924, 33953, 43136, 6243, 61243, 14849, 12490, 35337, 37210, 6763, 10313, 14757, 22328, 64011, 2957, 27386, 18854, 8291, 18845, 4506, 4227, 35848, 8212, 2417, 50891, 23424, 50753, 6841, 4804, 63563, 20217, 62358, 11123, 46221, 32772, 59959, 4356, 42805, 1058, 21839, 1393, 56768, 16579, 17850, 25525, 46343, 38629, 52634, 26847, 18659, 25171, 32221, 31390, 62588, 40013, 36402, 56292, 35545, 8889, 64691, 42683, 16277, 19277, 31325, 26844, 43749, 2205, 40966, 7878, 15689, 36006, 16315, 65218, 23298, 50208, 23118, 56078, 14072, 60008, 38522, 31859, 54207, 56890, 61677, 63789, 44377, 55520, 35822, 55294, 21015, 5600, 7867, 28860, 8731, 59047, 42995, 21849, 52732, 21747, 56117, 5650, 19533, 26620, 17746, 1480, 57313, 1948, 21654, 22267, 43882, 59168, 48986, 19379, 38562, 22687, 12831, 4044, 15020, 35808, 24744, 7112, 11342, 50282, 53577, 50891, 10237, 35893, 6309, 33428, 9132, 36685, 19892, 12476, 37745, 26362, 5789, 32360, 32998, 50096, 36530, 4412, 2608, 51019, 52661, 32490, 24841, 55008, 59815, 62886, 8916, 37947, 12039, 36240, 25686, 27413, 42981, 25412, 654, 16471, 64665, 16112, 6357, 19899, 56589, 25671, 22306, 41545, 26775, 49383, 42418, 53821, 40407, 27615, 46684, 32154, 61500, 2479, 36544, 11812, 12357, 2289, 37563, 27053, 32332, 56309, 53091, 21103, 24254, 5683, 8431, 42344, 19245, 13140, 44950, 56563, 22009, 7972, 4506, 36900, 20751, 33042, 40759, 49109, 14051, 31491, 26297, 47675, 2140, 61926, 2536, 21594, 35128, 400, 54359, 11068, 55977, 50988, 27767, 27250, 3322, 38638, 35834, 15130, 40954, 26944, 29699, 40068, 63262, 13792, 28813, 53775, 44354, 12047, 48275, 64591, 29724, 33652, 34717, 48277, 52650, 54538, 58186, 19863, 32888, 62307, 39180, 10995, 48866, 2063, 53871, 45113, 46106, 3895, 26241, 55990, 12284, 57008, 40507, 24988, 41455, 16778, 58381, 32525, 19996, 55621, 12261, 3709, 46069, 26056, 12193, 10407, 58031, 62817, 28167, 27280, 23837, 32205, 584, 32996, 20088, 57642, 11530, 13099, 33277, 27446, 52389, 21550, 6017, 24852, 24452, 61396, 3877, 55081, 35723, 26043, 3582, 8562, 20449, 25759, 10728, 9062, 8592, 15262, 52275, 61687, 18899, 6608, 48096, 63167, 15432, 9063, 43638, 33948, 4929, 8038, 45747, 43380, 17556, 32447, 5569, 54755, 32149, 65080, 54707, 48838, 64910, 12126, 1058, 42543, 20752, 11689, 38357, 36149, 44336, 5878, 34244, 30454, 49836, 19838, 22078, 3313, 31293, 13353, 43939, 44167, 34433, 36445, 31777, 45176, 61375, 63326, 34161, 2670, 55934, 41781, 52048, 11356, 21368, 27552, 51423, 30660, 47659, 63687, 18652, 39129, 1879, 43476, 11065, 12062, 51470, 35694, 17907, 47666, 1714, 38204, 12647, 9775, 16512, 24812, 48750, 33517, 24378, 1349, 8325, 53808, 48200, 17925, 33293, 24795, 36310, 22345, 32587, 48910, 57108, 45206, 17701, 63636, 16178, 41253, 49332, 50417, 42946, 33129, 40505, 4420, 43310, 34862, 5322, 30692, 9550, 41283, 46274, 57762, 52692, 33495, 65535, 48275, 56301, 10828, 552, 56292, 37625, 55461, 17120, 25050, 7039, 22808, 32770, 28465, 63995, 28267, 62600, 61800, 34730, 43220, 28232, 63035, 57848, 37224, 61429, 56597, 40845, 31288, 61623, 41903, 33737, 9138, 1, 59286, 55151, 24823, 25286, 32279, 32482, 31154, 32183, 18374, 4513, 40781, 5226, 20614, 22558, 43942, 6336, 34590, 40194, 31675, 45338, 36097, 18642, 13956, 62690, 19091, 16865, 63111, 22273, 57870, 30389, 9371, 52501, 21167, 7739, 34157, 8431, 60465, 38829, 49976, 10778, 738, 29662, 50848, 60082, 25480, 34084, 17737, 44107, 35367, 60672, 33670, 56932, 64435, 47596, 60749, 31313, 57262, 36649, 20967, 34109, 21813, 37663, 50439, 10376, 33708, 44800, 28799, 60312, 44545, 22905, 62566, 23725, 56773, 54992, 13359, 64428, 11323, 38418, 26828, 50211, 25878, 12867, 12523, 37913, 16316, 16790, 18661, 23946, 44764, 48802, 16032, 37621, 60919, 41359, 62550, 54954, 3541, 42342, 24191, 7691, 26439, 43440, 47216, 51041, 19560, 3552, 17225, 37012, 53903, 30751, 63010, 27436, 49150, 4882, 43399, 30835, 7024, 2637, 23686, 46187, 19646, 63360, 424, 32584, 57550, 21499, 31445, 25944, 4877, 25525, 2778, 59010, 59245, 55518, 16028, 25851, 28168, 51575, 33167, 56336, 38548, 35784, 27232, 41397, 6069, 14673, 52816, 9995, 20565, 45310, 39166, 26904, 1946, 29633, 49167, 8599, 11884, 40123, 17502, 50721, 22076, 65524, 53101, 7307, 51738, 55515, 49433, 51779, 24435, 17006, 60505, 64909, 54250, 10860, 16067, 5333, 38236, 18566, 49627, 11908, 48662, 16287, 28627, 8149, 38663, 35581, 43021, 36579, 8523, 21066, 29182, 41155, 4526, 9835, 33762, 1947, 29807, 60475, 14354, 22708, 2995, 43382, 43297, 31012, 51587, 27425, 39774, 64359, 27016, 40610, 52258, 36941, 35807, 49938, 56487, 15023, 47173, 50056, 47985, 15073, 22661, 29057, 65258, 44608, 2337, 35796, 9273, 27370, 35262, 3036, 22782, 9139, 18077, 13144, 2357, 25467, 22341, 34610, 61383, 36367, 44275, 31010, 14161, 63807, 6322, 49973, 6421, 35497, 42382, 45587, 33372, 2178, 15156, 30117, 64581, 40469, 22007, 23192, 38178, 12585, 42321, 34011, 41253, 12004, 20671, 52775, 21623, 38475, 32644, 53439, 52345, 47641, 37011, 42318, 50102, 10800, 40587, 14071, 26970, 48921, 7105, 47942, 17206, 34725, 49562, 4293, 43582, 54832, 15155, 18778, 39539, 26595, 637, 60035, 65183, 46905, 44899, 41909, 3054, 28439, 34404, 47994, 57980, 2971, 59501, 8755, 64796, 44972, 51130, 36939, 62907, 59189, 64507, 64251, 11532, 40898, 63096, 40412, 30670, 50743, 38322, 15129, 55667, 43353, 51953, 41606, 53114, 51826, 8658, 32002, 59900, 34756, 49646, 56522, 20136, 61574, 9972, 29774, 16622, 31660, 48780, 4916, 29387, 8590, 8656, 35767, 41411, 55828, 59737, 5477, 60136, 58871, 6851, 21958, 50072, 31031, 15201, 63268, 17758, 42998, 18896, 22374, 37896, 13788, 8802, 61560, 56457, 52638, 26607, 54139, 59024, 8934, 58293, 15162, 14417, 63944, 43634, 5129, 59820, 41898, 10792, 30932, 58042, 25615, 245, 47625, 57318, 9403, 1940, 14801, 1869, 39782, 35109, 24506, 41450, 15108, 460, 12266, 41115, 37520, 51379, 1501, 37957, 46770, 52243, 55241, 6292, 48935, 33818, 35766, 58630, 18396, 56672, 31763, 56209, 3689, 31511, 34837, 62462, 62637, 25343, 20827, 3363, 23565, 55545, 30595, 20583, 61612, 53880, 42468, 64386, 2965, 63992, 14437, 40905, 7215, 60808, 6802, 52678, 37764, 21646, 28723, 18644, 9073, 6158, 58676, 5944, 62511, 23142, 63305, 10741, 63647, 52328, 48028, 60506, 28124, 39423, 51872, 50653, 10058 };
    // sig fmt: on
    const expected_merkle_hash =
        Hash.parseBase58String("91s3fZHJsGVBV52uAJjh7bqq8Jfd3Bpt6ykxDopVBsFJ") catch unreachable;

    var parent_ancestors = Ancestors{};
    defer parent_ancestors.deinit(allocator);
    try parent_ancestors.ancestors.put(allocator, 0, {});

    const actual_lt_hash = try deltaLtHash(accounts.accountReader(), hash_slot, &parent_ancestors);
    const actual_merkle_hash = try deltaMerkleHash(accounts.accountReader(), allocator, hash_slot);

    try std.testing.expectEqualSlices(u16, &expected_lt_hash, &actual_lt_hash.data);
    try std.testing.expectEqualSlices(u8, &expected_merkle_hash.data, &actual_merkle_hash.data);
}
