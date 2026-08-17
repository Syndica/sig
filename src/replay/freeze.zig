const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");
const tracy = @import("tracy");

const core = sig.core;
const features = sig.core.features;
const rewards = sig.replay.rewards;

const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

const Logger = sig.trace.Logger(@typeName(@This()));

const Ancestors = core.Ancestors;
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

const MERKLE_FANOUT: usize = 16;
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
        state: *SlotState,
        constants: *const SlotConstants,
        slot: Slot,
        blockhash: Hash,
        ledger: *sig.ledger.Ledger,
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
                .transaction_count = state.transaction_count.load(.monotonic),
                .collected_transaction_fees = state.collected_transaction_fees.load(.monotonic),
                .collected_priority_fees = state.collected_priority_fees.load(.monotonic),
                .collected_rent = state.collected_rent.load(.monotonic),
                .logger = logger,
                .precomputed_delta_lt_hash = &state.replay_lt_hash_delta,
                .precomputed_delta_lt_hash_keys = &state.replay_lt_hash_delta_keys,
            },
            .finalize_state = .{
                .update_sysvar = .{
                    .slot = slot,
                    .slot_store = account_store.forSlot(slot, &constants.ancestors),
                    .rent = &constants.rent_collector.rent,
                    .capitalization = &state.capitalization,
                },
                .account_store = account_store,
                .account_reader = account_store.reader().forSlot(&constants.ancestors),
                .capitalization = &state.capitalization,
                .blockhash_queue = &state.blockhash_queue,
                .rent = constants.rent_collector.rent,
                .fee_burn_percent = constants.fee_rate_governor.burn_percent,
                .slot = slot,
                .blockhash = blockhash,
                .lamports_per_signature = constants.fee_rate_governor.lamports_per_signature,
                .collector_id = constants.collector_id,
                .collected_transaction_fees = state.collected_transaction_fees.load(.monotonic),
                .collected_priority_fees = state.collected_priority_fees.load(.monotonic),
                .ledger = ledger,
                .reward_status = &state.reward_status,
                .block_height = constants.block_height,
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

    var total_timer = sig.time.Timer.start();

    // TODO: reconsider locking the hash for the entire function. (this is how agave does it)
    var phase_timer = sig.time.Timer.start();
    var slot_hash = params.slot_hash.write();
    defer slot_hash.unlock();
    const hash_lock_ns = phase_timer.read().asNanos();

    if (slot_hash.get().* != null) return; // already frozen

    phase_timer.reset();
    try finalizeState(allocator, params.finalize_state);
    const finalize_state_ns = phase_timer.read().asNanos();

    phase_timer.reset();
    const maybe_lt_hash, slot_hash.mut().* = try hashSlot(
        allocator,
        params.hash_slot,
        params.thread_pool,
    );
    const hash_slot_ns = phase_timer.read().asNanos();
    if (maybe_lt_hash) |lt_hash| params.accounts_lt_hash.set(lt_hash);
    const lt_hash_delta_source = if (params.hash_slot.precomputed_delta_lt_hash.readCopy() != null)
        "slot_cache"
    else
        "accounts_db";

    params.logger.info().logf(
        "froze slot {} with hash {s}",
        .{ params.hash_slot.slot, slot_hash.get().*.?.base58String().slice() },
    );

    tracy.frameMarkNamed("slots frozen");

    const total_ns = total_timer.read().asNanos();
    params.logger.info().logf(
        "replay_freeze_timing slot={} hash_lock_ns={} finalize_state_ns={} hash_slot_ns={} unattributed_ns={} total_ns={} lt_hash_delta_source={s}",
        .{
            params.hash_slot.slot,
            hash_lock_ns,
            finalize_state_ns,
            hash_slot_ns,
            total_ns -| (hash_lock_ns + finalize_state_ns + hash_slot_ns),
            total_ns,
            lt_hash_delta_source,
        },
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
    ledger: *sig.ledger.Ledger,
    reward_status: *const rewards.EpochRewardStatus,

    // data params
    rent: Rent,
    fee_burn_percent: u8,
    slot: Slot,
    blockhash: Hash,
    lamports_per_signature: u64,
    collector_id: Pubkey,
    collected_transaction_fees: u64,
    collected_priority_fees: u64,
    block_height: u64,
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
        params.fee_burn_percent,
        params.slot,
        params.collector_id,
        params.collected_transaction_fees,
        params.collected_priority_fees,
        params.ledger,
        params.reward_status,
        params.block_height,
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
/// Records all rewards (fee, vote, staking) and num_partitions to the blockstore.
/// Matches Agave's fee distribution in `runtime/src/bank/fee_distribution.rs`
/// and reward recording in `get_rewards_and_num_partitions`.
fn distributeTransactionFees(
    allocator: Allocator,
    account_store: AccountStore,
    account_reader: SlotAccountReader,
    capitalization: *std.atomic.Value(u64),
    rent: Rent,
    fee_burn_percent: u8,
    slot: Slot,
    collector_id: Pubkey,
    collected_transaction_fees: u64,
    collected_priority_fees: u64,
    ledger: *sig.ledger.Ledger,
    epoch_reward_status: *const rewards.EpochRewardStatus,
    block_height: u64,
) !void {
    const zone = tracy.Zone.init(@src(), .{ .name = "distributeTransactionFees" });
    defer zone.deinit();

    // Transaction-fee burning is governed by FeeRateGovernor, not the Rent
    // sysvar. Modern snapshots legitimately carry Rent.FREE after rent-fee
    // collection was disabled, while the mainnet fee governor still burns
    // half of the base transaction fee.
    var burn = collected_transaction_fees * fee_burn_percent / 100;
    const total_fees = collected_priority_fees + collected_transaction_fees;
    const payout = total_fees -| burn;

    if (payout > 0) blk: {
        const payout_result = tryPayoutFees(
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

        const fee_reward: sig.ledger.meta.Reward = .{
            .pubkey = collector_id,
            .lamports = @intCast(payout_result.payout_amount),
            .post_balance = payout_result.post_balance,
            .reward_type = .fee,
            .commission = null,
        };

        const keyed_rewards, const num_partitions = try getRewardsAndNumPartitions(
            allocator,
            epoch_reward_status,
            block_height,
            fee_reward,
        );
        defer allocator.free(keyed_rewards);

        try ledger.db.put(sig.ledger.schema.schema.rewards, slot, .{
            .rewards = keyed_rewards,
            .num_partitions = num_partitions,
        });
    }

    _ = capitalization.fetchSub(burn, .monotonic);
}

/// Collect all rewards for this slot and determine num_partitions.
/// Matches Agave's `get_rewards_and_num_partitions`.
///
/// On an epoch boundary block: returns vote rewards + fee reward + num_partitions.
/// On a distribution block: returns distributed stake rewards + fee reward.
/// On other blocks: returns just the fee reward.
fn getRewardsAndNumPartitions(
    allocator: Allocator,
    epoch_reward_status: *const rewards.EpochRewardStatus,
    block_height: u64,
    fee_reward: sig.ledger.meta.Reward,
) !struct { []const sig.ledger.meta.Reward, ?u64 } {
    switch (epoch_reward_status.*) {
        .active => |active| {
            // The epoch boundary block is the one right before distribution starts.
            // calculation.zig sets: distribution_starting_blockheight = block_height + 1
            const is_epoch_boundary = (block_height + 1 == active.distribution_start_block_height);

            if (is_epoch_boundary) {
                // Epoch boundary: record vote rewards + fee reward + num_partitions.
                const vote_entries = active.all_vote_rewards.entries;
                const num_partitions: u64 = if (active.partitioned_indices) |pi|
                    pi.entries.len
                else
                    0;

                const all_rewards = try allocator.alloc(
                    sig.ledger.meta.Reward,
                    1 + vote_entries.len,
                );
                all_rewards[0] = fee_reward;
                for (vote_entries, 1..) |vr, i| {
                    all_rewards[i] = .{
                        .pubkey = vr.vote_pubkey,
                        .lamports = @intCast(vr.rewards.lamports),
                        .post_balance = vr.rewards.post_balance,
                        .reward_type = .voting,
                        .commission = vr.rewards.commission,
                    };
                }
                return .{ all_rewards, num_partitions };
            } else {
                // Distribution block: record distributed stake rewards + fee reward.
                const all_rewards = try allocator.alloc(
                    sig.ledger.meta.Reward,
                    1 + active.distributed_rewards.items.len,
                );
                all_rewards[0] = fee_reward;
                @memcpy(all_rewards[1..], active.distributed_rewards.items);
                return .{ all_rewards, null };
            }
        },
        .inactive => {},
    }

    // Non-epoch-reward block: just the fee reward.
    const all_rewards = try allocator.alloc(sig.ledger.meta.Reward, 1);
    all_rewards[0] = fee_reward;
    return .{ all_rewards, null };
}

/// Attempt to pay the payout to the collector.
/// Returns the payout amount and post-balance on success.
const PayoutResult = struct {
    payout_amount: u64,
    post_balance: u64,
};

fn tryPayoutFees(
    allocator: Allocator,
    account_store: AccountStore,
    account_reader: SlotAccountReader,
    rent: Rent,
    slot: Slot,
    collector_id: Pubkey,
    payout: u64,
) !PayoutResult {
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

    return PayoutResult{
        .payout_amount = payout,
        .post_balance = fee_collector_account.lamports,
    };
}

pub const HashSlotParams = struct {
    account_reader: AccountReader,
    slot: Slot,
    signature_count: u64,
    transaction_count: u64 = 0,
    collected_transaction_fees: u64 = 0,
    collected_priority_fees: u64 = 0,
    collected_rent: u64 = 0,
    logger: ?Logger = null,
    parent_slot_hash: *const Hash,
    parent_lt_hash: *const ?LtHash,
    ancestors: *const Ancestors,
    blockhash: Hash,
    feature_set: *const sig.core.FeatureSet,
    precomputed_delta_lt_hash: *sig.sync.Mux(?LtHash),
    precomputed_delta_lt_hash_keys: *sig.sync.Mux(?[]Pubkey),
};

/// Calculates the slot hash (known as the "bank hash" in agave)
pub fn hashSlot(
    allocator: Allocator,
    params: HashSlotParams,
    thread_pool: *sig.sync.ThreadPool,
) !struct { ?LtHash, Hash } {
    var zone = tracy.Zone.init(@src(), .{ .name = "hashSlot" });
    defer zone.deinit();

    if (params.logger) |logger| {
        try logFreezeAccountFingerprints(allocator, params.account_reader, params.slot, logger);
    }

    var signature_count_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &signature_count_bytes, params.signature_count, .little);

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(&params.parent_slot_hash.data);
    const remove_delta_hash = params.feature_set.active(.remove_accounts_delta_hash, params.slot);
    var maybe_delta_merkle_hash: ?Hash = null;
    if (!remove_delta_hash) {
        const merkle_hash = try deltaMerkleHash(params.account_reader, allocator, params.slot);
        maybe_delta_merkle_hash = merkle_hash;
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
        const delta_lt_hash = if (params.precomputed_delta_lt_hash.readCopy()) |precomputed| blk: {
            const covered_keys = params.precomputed_delta_lt_hash_keys.readCopy() orelse
                return error.MissingPrecomputedLtHashDeltaKeys;
            var combined = precomputed;
            combined.mixIn(try deltaLtHashSkipping(
                allocator,
                thread_pool,
                params.account_reader,
                params.slot,
                &parent_ancestors,
                covered_keys,
            ));
            if (ltHashVerificationSlotEnabled(allocator, params.slot)) {
                const accounts_db_delta = try deltaLtHash(
                    allocator,
                    thread_pool,
                    params.account_reader,
                    params.slot,
                    &parent_ancestors,
                );
                const matched = std.mem.eql(u16, &combined.data, &accounts_db_delta.data);
                try maybeWriteLtHashVerificationArtifacts(
                    allocator,
                    params.slot,
                    combined,
                    accounts_db_delta,
                    params.logger,
                );
                if (params.logger) |logger| {
                    logger.logf(
                        if (matched) .info else .@"error",
                        "replay_lt_hash_dual_verification status={s} slot={} covered_keys={} slot_cache_delta_digest={s} accounts_db_delta_digest={s}",
                        .{
                            if (matched) "pass" else "fail",
                            params.slot,
                            covered_keys.len,
                            Hash.init(combined.constBytes()).base58String().slice(),
                            Hash.init(accounts_db_delta.constBytes()).base58String().slice(),
                        },
                    );
                }
            }
            break :blk combined;
        } else try deltaLtHash(
            allocator,
            thread_pool,
            params.account_reader,
            params.slot,
            &parent_ancestors,
        );
        lt_hash.mixIn(delta_lt_hash);

        const bank_hash = Hash.initMany(&.{ &initial_hash, lt_hash.constBytes() });
        if (params.logger) |logger| {
            const merkle_hash = maybe_delta_merkle_hash orelse Hash.ZEROES;
            const delta_lt_hash_digest = Hash.init(delta_lt_hash.constBytes());
            const accounts_lt_hash_digest = Hash.init(lt_hash.constBytes());
            logger.info().logf(
                "replay_freeze_fingerprint slot={} transactions={} signatures={} transaction_fees={} priority_fees={} rent={} delta_merkle={s} delta_lt_digest={s} accounts_lt_digest={s} initial_hash={s} bank_hash={s}",
                .{
                    params.slot,
                    params.transaction_count,
                    params.signature_count,
                    params.collected_transaction_fees,
                    params.collected_priority_fees,
                    params.collected_rent,
                    merkle_hash.base58String().slice(),
                    delta_lt_hash_digest.base58String().slice(),
                    accounts_lt_hash_digest.base58String().slice(),
                    (Hash{ .data = initial_hash }).base58String().slice(),
                    bank_hash.base58String().slice(),
                },
            );
        }
        return .{ lt_hash, bank_hash };
    } else {
        const bank_hash = Hash{ .data = initial_hash };
        if (params.logger) |logger| {
            const merkle_hash = maybe_delta_merkle_hash orelse Hash.ZEROES;
            logger.info().logf(
                "replay_freeze_fingerprint slot={} transactions={} signatures={} transaction_fees={} priority_fees={} rent={} delta_merkle={s} initial_hash={s} bank_hash={s}",
                .{
                    params.slot,
                    params.transaction_count,
                    params.signature_count,
                    params.collected_transaction_fees,
                    params.collected_priority_fees,
                    params.collected_rent,
                    merkle_hash.base58String().slice(),
                    bank_hash.base58String().slice(),
                    bank_hash.base58String().slice(),
                },
            );
        }
        return .{ null, bank_hash };
    }
}

fn ltHashVerificationSlotEnabled(allocator: Allocator, slot: Slot) bool {
    const raw_target = std.process.getEnvVarOwned(
        allocator,
        "SIG_REPLAY_LT_HASH_VERIFY_SLOT",
    ) catch return false;
    defer allocator.free(raw_target);
    const target = std.fmt.parseUnsigned(
        Slot,
        std.mem.trim(u8, raw_target, " \t\r\n"),
        10,
    ) catch return false;
    return target == slot;
}

fn writeLtHashFileAtomic(
    allocator: Allocator,
    path: []const u8,
    value: LtHash,
) !void {
    const next_path = try std.fmt.allocPrint(allocator, "{s}.next", .{path});
    defer allocator.free(next_path);
    errdefer std.fs.cwd().deleteFile(next_path) catch {};

    const file = try std.fs.cwd().createFile(next_path, .{ .truncate = true });
    defer file.close();
    try file.writeAll(value.constBytes());
    try file.sync();
    try std.fs.cwd().rename(next_path, path);
}

fn writeLtHashVerificationArtifactsAtDir(
    allocator: Allocator,
    output_dir: []const u8,
    slot: Slot,
    slot_cache_delta: LtHash,
    accounts_db_delta: LtHash,
) !void {
    if (!std.fs.path.isAbsolute(output_dir))
        return error.LtHashVerificationOutputMustBeAbsolute;
    if (std.mem.eql(u8, output_dir, "/Volumes") or
        std.mem.startsWith(u8, output_dir, "/Volumes/"))
    {
        return error.LtHashVerificationExternalStorageForbidden;
    }
    try std.fs.cwd().makePath(output_dir);

    const slot_cache_path = try std.fmt.allocPrint(
        allocator,
        "{s}/slot-{}-slot-cache.lt-hash",
        .{ output_dir, slot },
    );
    defer allocator.free(slot_cache_path);
    const accounts_db_path = try std.fmt.allocPrint(
        allocator,
        "{s}/slot-{}-accounts-db.lt-hash",
        .{ output_dir, slot },
    );
    defer allocator.free(accounts_db_path);
    const correction_path = try std.fmt.allocPrint(
        allocator,
        "{s}/slot-{}-correction.lt-hash",
        .{ output_dir, slot },
    );
    defer allocator.free(correction_path);

    var correction = accounts_db_delta;
    correction.mixOut(slot_cache_delta);
    try writeLtHashFileAtomic(allocator, slot_cache_path, slot_cache_delta);
    try writeLtHashFileAtomic(allocator, accounts_db_path, accounts_db_delta);
    try writeLtHashFileAtomic(allocator, correction_path, correction);
}

fn maybeWriteLtHashVerificationArtifacts(
    allocator: Allocator,
    slot: Slot,
    slot_cache_delta: LtHash,
    accounts_db_delta: LtHash,
    maybe_logger: ?Logger,
) !void {
    const output_dir = std.process.getEnvVarOwned(
        allocator,
        "SIG_REPLAY_LT_HASH_VERIFY_OUTPUT_DIR",
    ) catch return;
    defer allocator.free(output_dir);
    if (output_dir.len == 0) return;

    try writeLtHashVerificationArtifactsAtDir(
        allocator,
        output_dir,
        slot,
        slot_cache_delta,
        accounts_db_delta,
    );
    if (maybe_logger) |logger| {
        var correction = accounts_db_delta;
        correction.mixOut(slot_cache_delta);
        logger.info().logf(
            "replay_lt_hash_dual_artifacts status=pass slot={} output_dir={s} bytes_each={} correction_digest={s}",
            .{
                slot,
                output_dir,
                slot_cache_delta.constBytes().len,
                Hash.init(correction.constBytes()).base58String().slice(),
            },
        );
    }
}

test "LT hash dual verification artifacts preserve correction" {
    const allocator = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const output_dir = try temp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(output_dir);

    var slot_cache_delta = LtHash.IDENTITY;
    slot_cache_delta.data[0] = 5;
    slot_cache_delta.data[512] = 65_535;
    var accounts_db_delta = LtHash.IDENTITY;
    accounts_db_delta.data[0] = 8;
    accounts_db_delta.data[512] = 2;
    try writeLtHashVerificationArtifactsAtDir(
        allocator,
        output_dir,
        123,
        slot_cache_delta,
        accounts_db_delta,
    );

    const correction_path = try std.fmt.allocPrint(
        allocator,
        "{s}/slot-123-correction.lt-hash",
        .{output_dir},
    );
    defer allocator.free(correction_path);
    const correction_bytes = try std.fs.cwd().readFileAlloc(
        allocator,
        correction_path,
        @sizeOf(LtHash),
    );
    defer allocator.free(correction_bytes);
    try std.testing.expectEqual(@sizeOf(LtHash), correction_bytes.len);
    var correction = LtHash.IDENTITY;
    @memcpy(correction.bytes(), correction_bytes);

    var expected = accounts_db_delta;
    expected.mixOut(slot_cache_delta);
    try std.testing.expectEqualSlices(u16, &expected.data, &correction.data);
}

fn logFreezeAccountFingerprints(
    allocator: Allocator,
    account_reader: AccountReader,
    slot: Slot,
    logger: Logger,
) !void {
    const raw_target = std.process.getEnvVarOwned(
        allocator,
        "SIG_REPLAY_FREEZE_ACCOUNT_FINGERPRINT_SLOT",
    ) catch return;
    defer allocator.free(raw_target);
    const target = std.fmt.parseUnsigned(
        Slot,
        std.mem.trim(u8, raw_target, " \t\r\n"),
        10,
    ) catch return;
    if (target != slot) return;

    var iterator = account_reader.slotModifiedIterator(slot) orelse return;
    defer iterator.unlock();
    logger.info().logf(
        "replay_freeze_account_fingerprints_begin slot={} accounts={}",
        .{ slot, iterator.len() },
    );
    while (try iterator.next(allocator)) |pubkey_account| {
        const pubkey, const account = pubkey_account;
        defer account.deinit(allocator);
        const account_hash = account.hash(pubkey);
        logger.info().logf(
            "replay_freeze_account_fingerprint slot={} pubkey={s} account_hash={s} lamports={} data_len={} owner={s} executable={} rent_epoch={}",
            .{
                slot,
                pubkey.base58String().slice(),
                account_hash.base58String().slice(),
                account.lamports,
                account.data.len(),
                account.owner.base58String().slice(),
                account.executable,
                account.rent_epoch,
            },
        );
    }
    logger.info().logf("replay_freeze_account_fingerprints_end slot={}", .{slot});
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
        MERKLE_FANOUT,
    );

    return hash;
}

pub fn deltaLtHash(
    allocator: std.mem.Allocator,
    thread_pool: *sig.sync.ThreadPool,
    account_reader: AccountReader,
    slot: Slot,
    parent_ancestors: *const Ancestors,
) !LtHash {
    return deltaLtHashSkipping(
        allocator,
        thread_pool,
        account_reader,
        slot,
        parent_ancestors,
        &.{},
    );
}

fn deltaLtHashSkipping(
    allocator: std.mem.Allocator,
    thread_pool: *sig.sync.ThreadPool,
    account_reader: AccountReader,
    slot: Slot,
    parent_ancestors: *const Ancestors,
    sorted_skip_keys: []const Pubkey,
) !LtHash {
    assert(!parent_ancestors.containsSlot(slot));

    const zone = tracy.Zone.init(@src(), .{ .name = "deltaLtHash" });
    defer zone.deinit();

    const Worker = struct {
        task: sig.sync.ThreadPool.Task = .{ .callback = run },
        wg: *std.Thread.WaitGroup,
        range: struct { usize, usize },
        hash: LtHash = .IDENTITY,
        gpa: std.mem.Allocator,
        slot_index: *sig.accounts_db.Db.Unrooted.SlotIndex,
        db: *sig.accounts_db.Db,
        ancestors: *const Ancestors,
        sorted_skip_keys: []const Pubkey,

        fn run(task: *sig.sync.ThreadPool.Task) void {
            const worker_zone = tracy.Zone.init(@src(), .{ .name = "deltaLt worker" });
            defer worker_zone.deinit();

            const self: *@This() = @alignCast(@fieldParentPtr("task", task));
            defer self.wg.finish();

            const start_index, const end_index = self.range;
            const entries = self.slot_index.entries;

            var arena: std.heap.ArenaAllocator = .init(self.gpa);
            defer arena.deinit();

            for (
                entries.values()[start_index..end_index],
                entries.keys()[start_index..end_index],
            ) |data, key| {
                defer _ = arena.reset(.retain_capacity);
                if (containsSortedPubkey(self.sorted_skip_keys, key)) continue;

                const account = data.asAccount();

                const old_account = self.db.get(
                    arena.allocator(),
                    key,
                    self.ancestors,
                ) catch @panic("Rooted account get failed") orelse {
                    self.hash.mixIn(account.ltHash(key));
                    continue;
                };
                if (old_account.equals(&account)) continue;

                self.hash.mixOut(old_account.ltHash(key));
                self.hash.mixIn(account.ltHash(key));
            }
        }
    };

    var iterator = account_reader.slotModifiedIterator(slot) orelse return .IDENTITY;
    defer iterator.unlock();

    const num_workers = @max(1, @min(iterator.len(), thread_pool.max_threads));
    const chunk_size = iterator.len() / num_workers;

    var workers: std.ArrayListUnmanaged(Worker) = try .initCapacity(allocator, num_workers);
    defer workers.deinit(allocator);

    {
        var wg = std.Thread.WaitGroup{};
        wg.startMany(num_workers);
        defer wg.wait();

        var batch = sig.sync.ThreadPool.Batch{};
        defer thread_pool.schedule(batch);

        var start_index: usize = 0;
        for (0..num_workers) |i| {
            const end_index = if (i == num_workers - 1)
                iterator.len()
            else
                start_index + chunk_size;

            defer start_index = end_index;

            const worker = workers.addOneAssumeCapacity();
            worker.* = .{
                .wg = &wg,
                .range = .{ start_index, end_index },
                .gpa = allocator,
                .slot_index = iterator.accounts_db.slot,
                .db = account_reader.accounts_db,
                .ancestors = parent_ancestors,
                .sorted_skip_keys = sorted_skip_keys,
            };
            batch.push(.from(&worker.task));
        }
    }

    var final: LtHash = .IDENTITY;
    for (workers.items) |*worker| final = final.add(worker.hash);
    return final;
}

fn containsSortedPubkey(sorted_keys: []const Pubkey, needle: Pubkey) bool {
    var low: usize = 0;
    var high: usize = sorted_keys.len;
    while (low < high) {
        const mid = low + (high - low) / 2;
        const order = std.mem.order(u8, &sorted_keys[mid].data, &needle.data);
        switch (order) {
            .lt => low = mid + 1,
            .gt => high = mid,
            .eq => return true,
        }
    }
    return false;
}

test "deltaLtHash is identity for 0 accounts" {
    const allocator = std.testing.allocator;

    var test_state = try sig.accounts_db.Db.initTest(allocator);
    defer test_state.deinit();

    var tp: sig.sync.ThreadPool = .init(.{});
    defer {
        tp.shutdown();
        tp.deinit();
    }

    try std.testing.expectEqual(LtHash.IDENTITY, try deltaLtHash(
        allocator,
        &tp,
        .{ .accounts_db = &test_state.db },
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

    var test_state = try sig.accounts_db.Db.initTest(allocator);
    defer test_state.deinit();
    const account_store: AccountStore = .{ .accounts_db = &test_state.db };

    const constants = try SlotConstants.genesis(allocator, .DEFAULT);
    defer constants.deinit(allocator);

    var state: SlotState = .GENESIS;
    defer state.deinit(allocator);

    var tp: sig.sync.ThreadPool = .init(.{});
    defer {
        tp.shutdown();
        tp.deinit();
    }
    var ledger, var ledger_dir = try sig.ledger.Ledger.initForTest(allocator);
    defer {
        ledger.deinit();
        ledger_dir.cleanup();
    }

    try freezeSlot(allocator, .init(
        .FOR_TESTS,
        account_store,
        &tp,
        &state,
        &constants,
        0,
        .ZEROES,
        &ledger,
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

    var test_state = try sig.accounts_db.Db.initTest(allocator);
    defer test_state.deinit();
    const real_state = &test_state.db;

    var tp: sig.sync.ThreadPool = .init(.{});
    defer {
        tp.shutdown();
        tp.deinit();
    }

    const account_store: sig.accounts_db.AccountStore = .{ .accounts_db = real_state };

    var constants = try SlotConstants.genesis(allocator, .DEFAULT);
    defer constants.deinit(allocator);
    constants.feature_set.setSlot(.accounts_lt_hash, 0);
    constants.feature_set.setSlot(.remove_accounts_delta_hash, 0);

    var state: SlotState = .GENESIS;
    defer state.deinit(allocator);

    var ledger, var ledger_dir = try sig.ledger.Ledger.initForTest(allocator);
    defer {
        ledger.deinit();
        ledger_dir.cleanup();
    }

    try freezeSlot(allocator, .init(
        .FOR_TESTS,
        account_store,
        &tp,
        &state,
        &constants,
        0,
        .ZEROES,
        &ledger,
    ));

    try std.testing.expectEqual(
        Hash.parse("B513RgkSxeiHv4hJ3aaBfkoveWKeB6575S3CtG64AirS"),
        state.hash.readCopy().?,
    );
}

test "precomputed LT hash delta plus skipped DB scan equals full DB delta" {
    const allocator = std.testing.allocator;
    var test_state = try sig.accounts_db.Db.initTest(allocator);
    defer test_state.deinit();
    const db = &test_state.db;

    const transaction_key = Pubkey{ .data = @splat(21) };
    const finalizer_key = Pubkey{ .data = @splat(22) };
    var tx_old_data = "tx-old".*;
    var tx_new_data = "tx-new".*;
    var finalizer_old_data = "finalizer-old".*;
    var finalizer_new_data = "finalizer-new".*;
    const tx_old = AccountSharedData{
        .lamports = 10,
        .data = tx_old_data[0..],
        .owner = .ZEROES,
        .executable = false,
        .rent_epoch = 0,
    };
    const tx_new = AccountSharedData{
        .lamports = 11,
        .data = tx_new_data[0..],
        .owner = .ZEROES,
        .executable = false,
        .rent_epoch = 0,
    };
    const finalizer_old = AccountSharedData{
        .lamports = 20,
        .data = finalizer_old_data[0..],
        .owner = .ZEROES,
        .executable = false,
        .rent_epoch = 0,
    };
    const finalizer_new = AccountSharedData{
        .lamports = 21,
        .data = finalizer_new_data[0..],
        .owner = .ZEROES,
        .executable = false,
        .rent_epoch = 0,
    };

    try db.put(0, transaction_key, tx_old);
    try db.put(0, finalizer_key, finalizer_old);
    try db.put(1, transaction_key, tx_new);
    try db.put(1, finalizer_key, finalizer_new);

    var parent_ancestors: Ancestors = .{};
    defer parent_ancestors.deinit(allocator);
    try parent_ancestors.ancestors.put(allocator, 0, {});
    var thread_pool: sig.sync.ThreadPool = .init(.{ .max_threads = 2 });
    defer {
        thread_pool.shutdown();
        thread_pool.deinit();
    }

    const full_delta = try deltaLtHash(
        allocator,
        &thread_pool,
        .{ .accounts_db = db },
        1,
        &parent_ancestors,
    );
    var combined_delta = LtHash.IDENTITY;
    const tx_old_account = tx_old.asAccount();
    const tx_new_account = tx_new.asAccount();
    combined_delta.mixOut(tx_old_account.ltHash(transaction_key));
    combined_delta.mixIn(tx_new_account.ltHash(transaction_key));
    combined_delta.mixIn(try deltaLtHashSkipping(
        allocator,
        &thread_pool,
        .{ .accounts_db = db },
        1,
        &parent_ancestors,
        &.{transaction_key},
    ));

    try std.testing.expectEqualSlices(u16, &full_delta.data, &combined_delta.data);
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

    var test_state = try sig.accounts_db.Db.initTest(allocator);
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
        .{ .accounts_db = db },
        hash_slot,
        &parent_ancestors,
    );
    const actual_merkle_hash = try deltaMerkleHash(
        .{ .accounts_db = db },
        allocator,
        hash_slot,
    );

    try std.testing.expectEqualSlices(u16, &expected_lt_hash, &actual_lt_hash.data);
    try std.testing.expectEqualSlices(u8, &expected_merkle_hash.data, &actual_merkle_hash.data);
}
