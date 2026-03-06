//! The Consensus RPC hook context. These methods reflect consensus-derived state (commitment levels, vote accounts, block hashes, etc.)

const std = @import("std");
const sig = @import("../../sig.zig");

const common = sig.rpc.methods.common;

const Slot = sig.core.Slot;
const SlotRef = sig.replay.trackers.SlotTracker.Reference;
const Commitment = common.Commitment;
const ClientVersion = sig.version.ClientVersion;
const BlockhashQueue = sig.core.blockhash_queue.BlockhashQueue;

const GetSlot = sig.rpc.methods.GetSlot;
const GetBlockHeight = sig.rpc.methods.GetBlockHeight;
const GetTransactionCount = sig.rpc.methods.GetTransactionCount;
const GetHighestSnapshotSlot = sig.rpc.methods.GetHighestSnapshotSlot;
const GetEpochInfo = sig.rpc.methods.GetEpochInfo;
const GetLatestBlockhash = sig.rpc.methods.GetLatestBlockhash;
const GetVoteAccounts = sig.rpc.methods.GetVoteAccounts;
const IsBlockhashValid = sig.rpc.methods.IsBlockhashValid;

slot_tracker: *sig.replay.trackers.SlotTracker,
epoch_tracker: *sig.core.EpochTracker,

/// Resolves commitment and minContextSlot config to a slot number.
/// Defaults to finalized commitment if none is specified.
fn resolveCommitmentSlot(
    self: @This(),
    commitment: ?Commitment,
    min_context_slot: ?Slot,
) !Slot {
    const resolved_commitment = commitment orelse .finalized;
    const slot = self.slot_tracker.getSlotForCommitment(resolved_commitment);

    if (min_context_slot) |min_slot| {
        if (slot < min_slot) return error.RpcMinContextSlotNotMet;
    }

    return slot;
}

/// Resolves commitment config to a slot and returns the slot number along
/// with a reference to the slot's data. The caller must call `release()`
/// on the returned `SlotRef` when done (typically via `defer`).
fn resolveSlot(
    self: @This(),
    commitment: ?Commitment,
    min_context_slot: ?Slot,
) !struct { slot: Slot, ref: SlotRef } {
    const slot = try self.resolveCommitmentSlot(commitment, min_context_slot);
    const slot_ref = self.slot_tracker.get(slot) orelse return error.SlotNotAvailable;
    return .{ .slot = slot, .ref = slot_ref };
}

pub fn getSlot(self: @This(), _: std.mem.Allocator, params: GetSlot) !GetSlot.Response {
    const config: common.CommitmentSlotConfig = params.config orelse .{};
    return self.resolveCommitmentSlot(config.commitment, config.minContextSlot);
}

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L955-L958
pub fn getBlockHeight(
    self: @This(),
    _: std.mem.Allocator,
    params: GetBlockHeight,
) !GetBlockHeight.Response {
    const config: common.CommitmentSlotConfig = params.config orelse .{};
    const resolved = try self.resolveSlot(config.commitment, config.minContextSlot);
    defer resolved.ref.release();
    return resolved.ref.constants().block_height;
}

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L1022-L1025
pub fn getTransactionCount(
    self: @This(),
    _: std.mem.Allocator,
    params: GetTransactionCount,
) !GetTransactionCount.Response {
    const config: common.CommitmentSlotConfig = params.config orelse .{};
    const resolved = try self.resolveSlot(config.commitment, config.minContextSlot);
    defer resolved.ref.release();
    return resolved.ref.state().transaction_count.load(.monotonic);
}

/// for the time being we will return null
/// since accounts-db v2 don't have relevant implementation
pub fn getHighestSnapshotSlot(
    _: @This(),
    _: std.mem.Allocator,
    _: GetHighestSnapshotSlot,
) !GetHighestSnapshotSlot.Response {
    return null;
}

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L2791-L2799
pub fn getEpochInfo(
    self: @This(),
    _: std.mem.Allocator,
    params: GetEpochInfo,
) !GetEpochInfo.Response {
    const config: common.CommitmentSlotConfig = params.config orelse .{};
    const resolved = try self.resolveSlot(config.commitment, config.minContextSlot);
    defer resolved.ref.release();

    const epoch_and_slot_index = self.epoch_tracker.epoch_schedule.getEpochAndSlotIndex(
        resolved.slot,
    );
    const epoch = epoch_and_slot_index[0];
    const slot_index = epoch_and_slot_index[1];
    const slots_in_epoch = self.epoch_tracker.epoch_schedule.getSlotsInEpoch(epoch);

    return .{
        .epoch = epoch,
        .slotIndex = slot_index,
        .slotsInEpoch = slots_in_epoch,
        .absoluteSlot = resolved.slot,
        .blockHeight = resolved.ref.constants().block_height,
        .transactionCount = resolved.ref.state().transaction_count.load(.monotonic),
    };
}

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L2352-L2365
pub fn getLatestBlockhash(
    self: @This(),
    arena: std.mem.Allocator,
    params: GetLatestBlockhash,
) !GetLatestBlockhash.Response {
    const config: common.CommitmentSlotConfig = params.config orelse .{};
    const resolved = try self.resolveSlot(config.commitment, config.minContextSlot);
    defer resolved.ref.release();

    const hash_data: struct { last_hash: sig.core.Hash, hash_age: u64 } = result: {
        const bq, var bq_lock = resolved.ref.state().blockhash_queue.readWithLock();
        defer bq_lock.unlock();

        const last_hash = bq.last_hash orelse return error.SlotNotAvailable;
        const hash_age = bq.getHashAge(last_hash) orelse return error.SlotNotAvailable;

        break :result .{ .last_hash = last_hash, .hash_age = hash_age };
    };

    // [agave] get_blockhash_last_valid_block_height:
    // https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/bank.rs#L2765
    // last_valid_block_height = block_height + MAX_PROCESSING_AGE - age
    // where MAX_PROCESSING_AGE = MAX_RECENT_BLOCKHASHES / 2 = 150
    const max_processing_age: u64 = BlockhashQueue.MAX_RECENT_BLOCKHASHES / 2;
    const block_height = resolved.ref.constants().block_height;
    const last_valid_block_height = block_height + max_processing_age - hash_data.hash_age;

    // Allocate the base58 string so it outlives the function scope.
    // The server uses an arena allocator, so this will be freed with the arena.
    const blockhash_str = hash_data.last_hash.base58String();
    const blockhash = try arena.dupe(u8, blockhash_str.constSlice());

    return .{
        .context = .{
            .slot = resolved.slot,
            .apiVersion = ClientVersion.API_VERSION,
        },
        .value = .{
            .blockhash = blockhash,
            .lastValidBlockHeight = last_valid_block_height,
        },
    };
}

pub fn getVoteAccounts(
    self: @This(),
    allocator: std.mem.Allocator,
    params: GetVoteAccounts,
) !GetVoteAccounts.Response {
    const config: GetVoteAccounts.Config = params.config orelse .{};

    const resolved = try self.resolveSlot(config.commitment, null);
    defer resolved.ref.release();

    // Setup config consts for the request.
    const delinquent_distance = config.delinquentSlotDistance orelse
        GetVoteAccounts.DELINQUENT_VALIDATOR_SLOT_DISTANCE;
    const keep_unstaked = config.keepUnstakedDelinquents orelse false;
    const filter_pk = config.votePubkey;

    // Get epoch info for epochVoteAccounts check
    const epoch_constants = try self.epoch_tracker.getEpochInfo(resolved.slot);
    defer epoch_constants.release();
    const epoch_stakes = epoch_constants.stakes.stakes;
    const epoch_vote_accounts = &epoch_stakes.vote_accounts.vote_accounts;

    var current_list: std.ArrayListUnmanaged(GetVoteAccounts.VoteAccount) = .empty;
    errdefer {
        for (current_list.items) |va| allocator.free(va.epochCredits);
        current_list.deinit(allocator);
    }
    var delinqt_list: std.ArrayListUnmanaged(GetVoteAccounts.VoteAccount) = .empty;
    errdefer {
        for (delinqt_list.items) |va| allocator.free(va.epochCredits);
        delinqt_list.deinit(allocator);
    }

    // Access stakes cache (takes read lock).
    const stakes, var stakes_guard = resolved.ref.state().stakes_cache.stakes.readWithLock();
    defer stakes_guard.unlock();
    const vote_accounts_map = &stakes.vote_accounts.vote_accounts;
    for (vote_accounts_map.keys(), vote_accounts_map.values()) |vote_pk, stake_and_vote| {
        // Apply filter if specified.
        if (filter_pk) |f| {
            if (!vote_pk.equals(&f)) continue;
        }

        const vote_state = stake_and_vote.account.state;
        const activated_stake = stake_and_vote.stake;

        // Get the slot this vote account last voted on.
        // See: https://github.com/anza-xyz/agave/blob/01159e4643e1d8ee86d1ed0e58ea463b338d563f/rpc/src/rpc.rs#L1172
        const last_vote_slot = vote_state.lastVotedSlot() orelse 0;

        // Check if vote account is active in current epoch.
        const in_delegated_stakes = epoch_vote_accounts.contains(vote_pk);
        const is_epoch_vote_account = in_delegated_stakes or activated_stake > 0;

        // Partition by delinquent status. current is set when last_vote_slot > slot - delinquent_distance.
        // See: https://github.com/anza-xyz/agave/blob/01159e4643e1d8ee86d1ed0e58ea463b338d563f/rpc/src/rpc.rs#L1194
        const is_current = if (resolved.slot >= delinquent_distance)
            last_vote_slot > resolved.slot - delinquent_distance
        else
            last_vote_slot > 0;

        // Skip delinquent accounts with no stake unless explicitly requested.
        // See: https://github.com/anza-xyz/agave/blob/01159e4643e1d8ee86d1ed0e58ea463b338d563f/rpc/src/rpc.rs#L1203
        if (!is_current and !keep_unstaked and activated_stake == 0) continue;

        // Convert epoch credits to [3]u64 format
        // See: https://github.com/anza-xyz/agave/blob/01159e4643e1d8ee86d1ed0e58ea463b338d563f/rpc/src/rpc.rs#L1174
        const all_credits = vote_state.epochCreditsList();
        const num_credits_to_return = @min(
            all_credits.len,
            GetVoteAccounts.MAX_RPC_VOTE_ACCOUNT_INFO_EPOCH_CREDITS_HISTORY,
        );
        const epoch_credits = all_credits[all_credits.len - num_credits_to_return ..];
        const credits = try allocator.alloc([3]u64, num_credits_to_return);
        errdefer allocator.free(credits);
        for (epoch_credits, 0..) |ec, i| {
            credits[i] = .{ ec.epoch, ec.credits, ec.prev_credits };
        }

        const info = GetVoteAccounts.VoteAccount{
            .votePubkey = vote_pk,
            .nodePubkey = vote_state.nodePubkey().*,
            .activatedStake = activated_stake,
            .epochVoteAccount = is_epoch_vote_account,
            .commission = vote_state.commission(),
            .lastVote = last_vote_slot,
            .epochCredits = credits,
            // See: https://github.com/anza-xyz/agave/blob/01159e4643e1d8ee86d1ed0e58ea463b338d563f/rpc/src/rpc.rs#L1188
            .rootSlot = vote_state.rootSlot() orelse 0,
        };

        if (is_current) {
            try current_list.append(allocator, info);
        } else {
            try delinqt_list.append(allocator, info);
        }
    }

    const current = try current_list.toOwnedSlice(allocator);
    errdefer {
        for (current) |va| allocator.free(va.epochCredits);
        allocator.free(current);
    }
    const dlinqt = try delinqt_list.toOwnedSlice(allocator);
    errdefer {
        for (dlinqt) |va| allocator.free(va.epochCredits);
        allocator.free(dlinqt);
    }
    return .{
        .current = current,
        .delinquent = dlinqt,
    };
}

/// Checks if a blockhash is still valid for processing transactions.
/// Analogous to [is_blockhash_valid](https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L2367)
pub fn isBlockhashValid(
    self: @This(),
    _: std.mem.Allocator,
    params: IsBlockhashValid,
) !IsBlockhashValid.Response {
    const config = params.config orelse common.CommitmentSlotConfig{};
    // [agave] Default commitment is finalized:
    // https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L348
    const commitment = config.commitment orelse .finalized;

    const slot = self.slot_tracker.getSlotForCommitment(commitment);
    if (config.minContextSlot) |min_slot| {
        if (slot < min_slot) return error.RpcMinContextSlotNotMet;
    }

    // Get slot reference to access blockhash queue
    const ref = self.slot_tracker.get(slot) orelse return error.SlotNotAvailable;
    defer ref.release();

    // Check if blockhash is valid for processing
    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/bank.rs#L2714
    const blockhash_queue, var bhq_lg = ref.state().blockhash_queue.readWithLock();
    defer bhq_lg.unlock();

    const is_valid = blockhash_queue.isHashValidForAge(
        params.blockhash,
        sig.core.BlockhashQueue.MAX_PROCESSING_AGE,
    );

    return .{
        .context = .{
            .slot = slot,
        },
        .value = is_valid,
    };
}

const testing = std.testing;

fn testDummySlotConstants(slot: Slot, block_height: u64) sig.core.SlotConstants {
    return .{
        .parent_slot = slot -| 1,
        .parent_hash = .ZEROES,
        .parent_lt_hash = .IDENTITY,
        .block_height = block_height,
        .collector_id = .ZEROES,
        .max_tick_height = 0,
        .fee_rate_governor = .DEFAULT,
        .ancestors = .{ .ancestors = .empty },
        .feature_set = .ALL_DISABLED,
        .reserved_accounts = .empty,
        .inflation = .DEFAULT,
        .rent_collector = .DEFAULT,
    };
}

fn testDummySlotState(transaction_count: u64) sig.core.SlotState {
    var state: sig.core.SlotState = .GENESIS;
    state.transaction_count = .init(transaction_count);
    return state;
}

fn testSetupSlotTracker(
    root_slot: Slot,
    root_block_height: u64,
    root_tx_count: u64,
) !sig.replay.trackers.SlotTracker {
    return .init(testing.allocator, root_slot, .{
        .constants = testDummySlotConstants(root_slot, root_block_height),
        .state = testDummySlotState(root_tx_count),
        .allocator = testing.allocator,
    });
}

fn testRpcHookContext(slot_tracker: *sig.replay.trackers.SlotTracker) @This() {
    return .{
        .slot_tracker = slot_tracker,
        .epoch_tracker = undefined, // not used by getBlockHeight/getTransactionCount/getHighestSnapshotSlot
    };
}

fn testRpcHookContextWithEpochTracker(
    slot_tracker: *sig.replay.trackers.SlotTracker,
    epoch_tracker: *sig.core.EpochTracker,
) @This() {
    return .{
        .slot_tracker = slot_tracker,
        .epoch_tracker = epoch_tracker,
    };
}

test "RpcHookContext.getBlockHeight - returns block height for finalized slot" {
    var slot_tracker = try testSetupSlotTracker(42, 100, 0);
    defer slot_tracker.deinit(testing.allocator);

    const ctx = testRpcHookContext(&slot_tracker);
    const result = try ctx.getBlockHeight(testing.allocator, .{});
    try testing.expectEqual(@as(u64, 100), result);
}

test "RpcHookContext.getBlockHeight - respects commitment level" {
    var slot_tracker = try testSetupSlotTracker(10, 50, 0);
    defer slot_tracker.deinit(testing.allocator);

    // Add a processed slot with different block height
    try slot_tracker.put(testing.allocator, 15, .{
        .constants = testDummySlotConstants(15, 55),
        .state = testDummySlotState(0),
        .allocator = testing.allocator,
    });
    slot_tracker.latest_processed_slot.set(15);

    const ctx = testRpcHookContext(&slot_tracker);

    // Finalized (default) should return root slot's block height
    const finalized_result = try ctx.getBlockHeight(testing.allocator, .{});
    try testing.expectEqual(@as(u64, 50), finalized_result);

    // Processed should return the processed slot's block height
    const processed_result = try ctx.getBlockHeight(testing.allocator, .{
        .config = .{ .commitment = .processed },
    });
    try testing.expectEqual(@as(u64, 55), processed_result);
}

test "RpcHookContext.getBlockHeight - minContextSlot enforcement" {
    var slot_tracker = try testSetupSlotTracker(10, 50, 0);
    defer slot_tracker.deinit(testing.allocator);

    const ctx = testRpcHookContext(&slot_tracker);

    // minContextSlot <= current slot should succeed
    const result = try ctx.getBlockHeight(testing.allocator, .{
        .config = .{ .minContextSlot = 10 },
    });
    try testing.expectEqual(@as(u64, 50), result);

    // minContextSlot > current slot should fail
    const err = ctx.getBlockHeight(testing.allocator, .{
        .config = .{ .minContextSlot = 100 },
    });
    try testing.expectError(error.RpcMinContextSlotNotMet, err);
}

test "RpcHookContext.getBlockHeight - slot not available" {
    var slot_tracker: sig.replay.trackers.SlotTracker = try .initEmpty(testing.allocator, 10);
    defer slot_tracker.deinit(testing.allocator);

    const ctx = testRpcHookContext(&slot_tracker);

    // Root slot is 10 but no Element was inserted for it
    const err = ctx.getBlockHeight(testing.allocator, .{});
    try testing.expectError(error.SlotNotAvailable, err);
}

test "RpcHookContext.getTransactionCount - returns transaction count for finalized slot" {
    var slot_tracker = try testSetupSlotTracker(42, 0, 999_999);
    defer slot_tracker.deinit(testing.allocator);

    const ctx = testRpcHookContext(&slot_tracker);
    const result = try ctx.getTransactionCount(testing.allocator, .{});
    try testing.expectEqual(@as(u64, 999_999), result);
}

test "RpcHookContext.getTransactionCount - respects commitment level" {
    var slot_tracker = try testSetupSlotTracker(10, 0, 1000);
    defer slot_tracker.deinit(testing.allocator);

    // Add a processed slot with different transaction count
    try slot_tracker.put(testing.allocator, 15, .{
        .constants = testDummySlotConstants(15, 0),
        .state = testDummySlotState(2000),
        .allocator = testing.allocator,
    });
    slot_tracker.latest_processed_slot.set(15);

    const ctx = testRpcHookContext(&slot_tracker);

    // Finalized (default) should return root slot's transaction count
    const finalized_result = try ctx.getTransactionCount(testing.allocator, .{});
    try testing.expectEqual(@as(u64, 1000), finalized_result);

    // Processed should return the processed slot's transaction count
    const processed_result = try ctx.getTransactionCount(testing.allocator, .{
        .config = .{ .commitment = .processed },
    });
    try testing.expectEqual(@as(u64, 2000), processed_result);
}

test "RpcHookContext.getTransactionCount - minContextSlot enforcement" {
    var slot_tracker = try testSetupSlotTracker(10, 0, 1000);
    defer slot_tracker.deinit(testing.allocator);

    const ctx = testRpcHookContext(&slot_tracker);

    // minContextSlot <= current slot should succeed
    const result = try ctx.getTransactionCount(testing.allocator, .{
        .config = .{ .minContextSlot = 10 },
    });
    try testing.expectEqual(@as(u64, 1000), result);

    // minContextSlot > current slot should fail
    const err = ctx.getTransactionCount(testing.allocator, .{
        .config = .{ .minContextSlot = 100 },
    });
    try testing.expectError(error.RpcMinContextSlotNotMet, err);
}

test "RpcHookContext.getTransactionCount - slot not available" {
    var slot_tracker: sig.replay.trackers.SlotTracker = try .initEmpty(testing.allocator, 10);
    defer slot_tracker.deinit(testing.allocator);

    const ctx = testRpcHookContext(&slot_tracker);
    const err = ctx.getTransactionCount(testing.allocator, .{});
    try testing.expectError(error.SlotNotAvailable, err);
}

test "RpcHookContext.getHighestSnapshotSlot - returns null" {
    var slot_tracker = try testSetupSlotTracker(0, 0, 0);
    defer slot_tracker.deinit(testing.allocator);

    const ctx = testRpcHookContext(&slot_tracker);
    const result = try ctx.getHighestSnapshotSlot(testing.allocator, .{});
    try testing.expectEqual(@as(?GetHighestSnapshotSlot.SnapshotSlotInfo, null), result);
}

test "RpcHookContext.getEpochInfo - returns epoch info for finalized slot" {
    // Use a non-warmup schedule with 32 slots per epoch for simple math.
    const epoch_schedule: sig.core.epoch_schedule.EpochSchedule = .custom(.{
        .slots_per_epoch = 32,
        .leader_schedule_slot_offset = 32,
        .warmup = false,
    });
    var epoch_tracker = sig.core.EpochTracker.init(.default, 0, epoch_schedule);

    // Slot 42 with 32 slots/epoch (no warmup, first_normal_slot=0):
    //   epoch = 42 / 32 = 1, slot_index = 42 % 32 = 10, slots_in_epoch = 32
    var slot_tracker = try testSetupSlotTracker(42, 100, 5000);
    defer slot_tracker.deinit(testing.allocator);

    const ctx = testRpcHookContextWithEpochTracker(&slot_tracker, &epoch_tracker);
    const result = try ctx.getEpochInfo(testing.allocator, .{});

    try testing.expectEqual(@as(u64, 42), result.absoluteSlot);
    try testing.expectEqual(@as(u64, 100), result.blockHeight);
    try testing.expectEqual(@as(u64, 1), result.epoch);
    try testing.expectEqual(@as(u64, 10), result.slotIndex);
    try testing.expectEqual(@as(u64, 32), result.slotsInEpoch);
    try testing.expectEqual(@as(u64, 5000), result.transactionCount);
}

test "RpcHookContext.getEpochInfo - respects commitment level" {
    const epoch_schedule: sig.core.epoch_schedule.EpochSchedule = .custom(.{
        .slots_per_epoch = 32,
        .leader_schedule_slot_offset = 32,
        .warmup = false,
    });
    var epoch_tracker = sig.core.EpochTracker.init(.default, 0, epoch_schedule);

    var slot_tracker = try testSetupSlotTracker(10, 50, 1000);
    defer slot_tracker.deinit(testing.allocator);

    // Add a processed slot in a different epoch
    try slot_tracker.put(testing.allocator, 35, .{
        .constants = testDummySlotConstants(35, 80),
        .state = testDummySlotState(2000),
        .allocator = testing.allocator,
    });
    slot_tracker.latest_processed_slot.set(35);

    const ctx = testRpcHookContextWithEpochTracker(&slot_tracker, &epoch_tracker);

    // Finalized (default) returns root slot's info (slot 10, epoch 0)
    const finalized = try ctx.getEpochInfo(testing.allocator, .{});
    try testing.expectEqual(@as(u64, 10), finalized.absoluteSlot);
    try testing.expectEqual(@as(u64, 0), finalized.epoch);
    try testing.expectEqual(@as(u64, 10), finalized.slotIndex);
    try testing.expectEqual(@as(u64, 1000), finalized.transactionCount);

    // Processed returns processed slot's info (slot 35, epoch 1)
    const processed = try ctx.getEpochInfo(testing.allocator, .{
        .config = .{ .commitment = .processed },
    });
    try testing.expectEqual(@as(u64, 35), processed.absoluteSlot);
    try testing.expectEqual(@as(u64, 1), processed.epoch);
    try testing.expectEqual(@as(u64, 3), processed.slotIndex);
    try testing.expectEqual(@as(u64, 2000), processed.transactionCount);
}

test "RpcHookContext.getEpochInfo - minContextSlot enforcement" {
    const epoch_schedule: sig.core.epoch_schedule.EpochSchedule = .custom(.{
        .slots_per_epoch = 32,
        .leader_schedule_slot_offset = 32,
        .warmup = false,
    });
    var epoch_tracker = sig.core.EpochTracker.init(.default, 0, epoch_schedule);

    var slot_tracker = try testSetupSlotTracker(10, 50, 1000);
    defer slot_tracker.deinit(testing.allocator);

    const ctx = testRpcHookContextWithEpochTracker(&slot_tracker, &epoch_tracker);

    // minContextSlot <= current slot should succeed
    const result = try ctx.getEpochInfo(testing.allocator, .{
        .config = .{ .minContextSlot = 10 },
    });
    try testing.expectEqual(@as(u64, 10), result.absoluteSlot);

    // minContextSlot > current slot should fail
    const err = ctx.getEpochInfo(testing.allocator, .{
        .config = .{ .minContextSlot = 100 },
    });
    try testing.expectError(error.RpcMinContextSlotNotMet, err);
}

test "RpcHookContext.getEpochInfo - slot not available" {
    const epoch_schedule: sig.core.epoch_schedule.EpochSchedule = .custom(.{
        .slots_per_epoch = 32,
        .leader_schedule_slot_offset = 32,
        .warmup = false,
    });
    var epoch_tracker = sig.core.EpochTracker.init(.default, 0, epoch_schedule);

    var slot_tracker: sig.replay.trackers.SlotTracker = try .initEmpty(testing.allocator, 10);
    defer slot_tracker.deinit(testing.allocator);

    const ctx = testRpcHookContextWithEpochTracker(&slot_tracker, &epoch_tracker);
    const err = ctx.getEpochInfo(testing.allocator, .{});
    try testing.expectError(error.SlotNotAvailable, err);
}

test "RpcHookContext.getLatestBlockhash - returns blockhash and last valid block height" {
    var state = testDummySlotState(5000);
    // Insert a hash into the blockhash queue
    const test_hash = sig.core.Hash.ZEROES;
    {
        const bq, var bq_lock = state.blockhash_queue.writeWithLock();
        defer bq_lock.unlock();
        try bq.insertHash(testing.allocator, test_hash, 0);
    }

    // Ownership of state (including blockhash_queue) is transferred to slot_tracker.
    // slot_tracker.deinit will free the blockhash queue's internal allocations.
    var slot_tracker: sig.replay.trackers.SlotTracker = try .init(testing.allocator, 42, .{
        .constants = testDummySlotConstants(42, 100),
        .state = state,
        .allocator = testing.allocator,
    });
    defer slot_tracker.deinit(testing.allocator);

    const ctx = testRpcHookContext(&slot_tracker);
    const result = try ctx.getLatestBlockhash(testing.allocator, .{});
    defer testing.allocator.free(result.value.blockhash);

    // Verify context
    try testing.expectEqual(@as(u64, 42), result.context.slot);
    try testing.expectEqualStrings(ClientVersion.API_VERSION, result.context.apiVersion);

    // Verify blockhash is the base58 encoding of ZEROES
    const expected_hash_str = sig.core.Hash.ZEROES.base58String();
    try testing.expectEqualStrings(expected_hash_str.constSlice(), result.value.blockhash);

    // Verify lastValidBlockHeight:
    // block_height = 100, MAX_PROCESSING_AGE = 150, age = 0 (just inserted)
    // last_valid_block_height = 100 + 150 - 0 = 250
    try testing.expectEqual(@as(u64, 250), result.value.lastValidBlockHeight);
}

test "RpcHookContext.getLatestBlockhash - no blockhash available" {
    // Default SlotState has no last_hash (null)
    var slot_tracker = try testSetupSlotTracker(42, 100, 0);
    defer slot_tracker.deinit(testing.allocator);

    const ctx = testRpcHookContext(&slot_tracker);
    const err = ctx.getLatestBlockhash(testing.allocator, .{});
    try testing.expectError(error.SlotNotAvailable, err);
}

test "RpcHookContext.getLatestBlockhash - minContextSlot enforcement" {
    var slot_tracker = try testSetupSlotTracker(10, 50, 0);
    defer slot_tracker.deinit(testing.allocator);

    const ctx = testRpcHookContext(&slot_tracker);

    // minContextSlot > current slot should fail
    const err = ctx.getLatestBlockhash(testing.allocator, .{
        .config = .{ .minContextSlot = 100 },
    });
    try testing.expectError(error.RpcMinContextSlotNotMet, err);
}

test "RpcHookContext.getLatestBlockhash - slot not available" {
    var slot_tracker: sig.replay.trackers.SlotTracker = try .initEmpty(testing.allocator, 10);
    defer slot_tracker.deinit(testing.allocator);

    const ctx = testRpcHookContext(&slot_tracker);
    const err = ctx.getLatestBlockhash(testing.allocator, .{});
    try testing.expectError(error.SlotNotAvailable, err);
}
