//! RPC hook context for block-related methods.
//! Requires access to the Ledger and CommitmentTracker for commitment checks.
const std = @import("std");
const sig = @import("../../sig.zig");
const methods = @import("../methods.zig");
const block_encoding = @import("../block_encoding.zig");
const slot_resolution = @import("./slot_resolution.zig");

const Allocator = std.mem.Allocator;
const AncestorIterator = sig.ledger.Reader.AncestorIterator;
const GetBlock = methods.GetBlock;
const GetBlockCommitment = methods.GetBlockCommitment;
const GetBlockProduction = methods.GetBlockProduction;
const GetBlocks = methods.GetBlocks;
const GetBlockTime = methods.GetBlockTime;
const GetFirstAvailableBlock = methods.GetFirstAvailableBlock;
const GetMaxRetransmitSlot = methods.GetMaxRetransmitSlot;
const GetMaxShredInsertSlot = methods.GetMaxShredInsertSlot;
const GetBlocksWithLimit = methods.GetBlocksWithLimit;
const GetHealth = methods.GetHealth;
const GetInflationReward = methods.GetInflationReward;
const GetRecentPerformanceSamples = methods.GetRecentPerformanceSamples;
const GetSignatureStatuses = methods.GetSignatureStatuses;
const GetSignaturesForAddress = methods.GetSignaturesForAddress;
const GetTransaction = methods.GetTransaction;
const MinimumLedgerSlot = methods.MinimumLedgerSlot;
const Pubkey = sig.core.Pubkey;
const PubkeyMap = sig.utils.collections.PubkeyMap;
const Signature = sig.core.Signature;
const Slot = sig.core.Slot;
const SlotHistory = sig.runtime.sysvar.SlotHistory;

// Maximum allowed slot distance before node is considered unhealthy.
// See: https://github.com/anza-xyz/agave/blob/v3.1.8/rpc-client-types/src/request.rs#L158
const DELINQUENT_VALIDATOR_SLOT_DISTANCE: u64 = 128;
/// Maximum allowed number of signatures in a single getSignatureStatuses query.
/// See: https://github.com/anza-xyz/agave/blob/v3.1.8/rpc-client-types/src/request.rs#L144
const MAX_GET_SIGNATURE_STATUSES_QUERY_ITEMS: usize = 256;

const LedgerHookContext = @This();

ledger: *sig.ledger.Ledger,
/// Maximum allowed slot distance before node is considered unhealthy.
health_check_slot_distance: u64 = DELINQUENT_VALIDATOR_SLOT_DISTANCE,
epoch_tracker: *sig.core.EpochTracker,
status_cache: *sig.core.StatusCache,
slot_tracker: *sig.replay.trackers.SlotTracker,
commitments: *sig.replay.trackers.CommitmentTracker,
max_retransmit_slot: ?*const std.atomic.Value(Slot) = null,
max_shred_insert_slot: ?*const std.atomic.Value(Slot) = null,

pub fn getBlock(
    self: LedgerHookContext,
    arena: Allocator,
    params: GetBlock,
) !GetBlock.Response {
    const config = params.resolveConfig();
    const commitment = config.getCommitment();
    const transaction_details = config.getTransactionDetails();
    const show_rewards = config.getRewards();
    const encoding = config.getEncoding();
    const max_supported_version = config.maxSupportedTransactionVersion;

    // Reject processed commitment (Agave behavior: only confirmed and finalized supported)
    if (commitment == .processed) {
        return error.ProcessedNotSupported;
    }

    // Get block from ledger.
    // Finalized path uses getRootedBlock (adds checkLowestCleanupSlot + isRoot checks,
    // matching Agave's get_rooted_block).
    // Confirmed path uses getCompleteBlock (no cleanup check, slot may not be rooted yet).
    const reader = self.ledger.reader();
    const latest_confirmed_slot = self.commitments.get(.confirmed);
    const block = if (params.slot <= latest_confirmed_slot) reader.getRootedBlock(
        arena,
        params.slot,
        true,
    ) catch |err| switch (err) {
        // NOTE: we try getCompletedBlock incase SlotTracker has seen the slot
        // but ledger has not yet rooted it
        error.SlotNotRooted => try reader.getCompleteBlock(
            arena,
            params.slot,
            true,
        ),
        else => return err,
    } else if (commitment == .confirmed) try reader.getCompleteBlock(
        arena,
        params.slot,
        true,
    ) else return error.BlockNotAvailable;

    return try block_encoding.encodeBlockWithOptions(arena, block, encoding, .{
        .tx_details = transaction_details,
        .show_rewards = show_rewards,
        .max_supported_version = max_supported_version,
    });
}

pub fn getBlocks(
    self: LedgerHookContext,
    arena: std.mem.Allocator,
    params: GetBlocks,
) !GetBlocks.Response {
    const commitment = params.commitment();
    if (commitment == .processed) return error.ProcessedNotSupported;

    const highest_root = self.commitments.get(.finalized);
    const upper_bound = if (commitment == .finalized)
        highest_root
    else
        self.commitments.get(.confirmed);

    const end_slot = @min(
        params.endSlot() orelse params.start_slot +| GetBlocks.MAX_GET_CONFIRMED_BLOCKS_RANGE,
        upper_bound,
    );

    if (end_slot <= params.start_slot) return &.{};
    if (end_slot - params.start_slot > GetBlocks.MAX_GET_CONFIRMED_BLOCKS_RANGE) {
        return error.SlotRangeTooLarge;
    }

    // Collect rooted (finalized) slots in range.
    var blocks = try std.ArrayList(Slot).initCapacity(
        arena,
        end_slot - params.start_slot +| 1,
    );

    var rooted_iter = try self.ledger.db.iterator(
        sig.ledger.schema.schema.rooted_slots,
        .forward,
        params.start_slot,
    );
    defer rooted_iter.deinit();

    while (try rooted_iter.nextKey()) |slot| {
        if (slot > end_slot or slot > highest_root) break;
        try blocks.append(arena, slot);
    }

    // For confirmed commitment, also include confirmed-but-unrooted slots.
    if (commitment == .confirmed) {
        const last_rooted = if (blocks.items.len > 0)
            blocks.items[blocks.items.len - 1]
        else
            params.start_slot -| 1;

        if (last_rooted < end_slot) {
            const latest_confirmed = self.commitments.get(.confirmed);
            const confirmed = try self.getConfirmedUnrootedSlots(
                arena,
                latest_confirmed,
                highest_root,
            );

            for (confirmed) |slot| {
                if (slot > end_slot) continue;
                if (slot <= last_rooted) continue;
                try blocks.append(arena, slot);
            }
        }
    }

    return try blocks.toOwnedSlice(arena);
}

pub fn getBlocksWithLimit(
    self: LedgerHookContext,
    arena: std.mem.Allocator,
    params: GetBlocksWithLimit,
) !GetBlocksWithLimit.Response {
    const commitment = params.commitment();
    if (commitment == .processed) return error.ProcessedNotSupported;

    if (params.limit > GetBlocks.MAX_GET_CONFIRMED_BLOCKS_RANGE) {
        return error.SlotRangeTooLarge;
    }

    const highest_root = self.commitments.get(.finalized);

    // Collect rooted (finalized) slots starting from start_slot, up to limit.
    var blocks = try std.ArrayList(Slot).initCapacity(arena, params.limit);

    var rooted_iter = try self.ledger.db.iterator(
        sig.ledger.schema.schema.rooted_slots,
        .forward,
        params.start_slot,
    );
    defer rooted_iter.deinit();

    while (blocks.items.len < params.limit) {
        const slot = try rooted_iter.nextKey() orelse break;
        if (slot > highest_root) break;
        try blocks.append(arena, slot);
    }

    // For confirmed commitment, add confirmed-but-unrooted slots up to limit.
    if (commitment == .confirmed and blocks.items.len < params.limit) {
        const last_rooted = if (blocks.items.len > 0)
            blocks.items[blocks.items.len - 1]
        else
            params.start_slot -| 1;

        const latest_confirmed = self.commitments.get(.confirmed);
        const confirmed = try self.getConfirmedUnrootedSlots(
            arena,
            latest_confirmed,
            highest_root,
        );

        for (confirmed) |slot| {
            if (blocks.items.len >= params.limit) break;
            if (slot <= last_rooted) continue;
            try blocks.append(arena, slot);
        }
    }

    return try blocks.toOwnedSlice(arena);
}

/// Returns the commitment data for a given slot along with the total active stake.
///
/// [agave] https://github.com/anza-xyz/agave/blob/b6eacb135037ab1021683d28b67a3c60e9039010/rpc/src/rpc.rs#L940
pub fn getBlockCommitment(
    self: LedgerHookContext,
    arena: Allocator,
    params: GetBlockCommitment,
) !GetBlockCommitment.Response {
    const result = self.commitments.stakes.getBlockCommitment(params.slot);
    if (result.commitment) |commitment| {
        const slice = try arena.alloc(u64, commitment.len);
        @memcpy(slice, &commitment);
        return .{
            .commitment = slice,
            .totalStake = result.total_stake,
        };
    }
    return .{
        .commitment = null,
        .totalStake = result.total_stake,
    };
}

pub fn getBlockProduction(
    self: LedgerHookContext,
    arena: Allocator,
    params: GetBlockProduction,
) !GetBlockProduction.Response {
    const config: GetBlockProduction.Config = params.config orelse .{};
    const commitment = config.commitment orelse .finalized;
    if (commitment == .processed) return error.ProcessedNotSupported;

    // Parse optional identity filter.
    const identity_filter: ?Pubkey = if (config.identity) |id_str|
        Pubkey.parseRuntime(id_str) catch return error.InvalidParams // TODO: invalid params should return a more specific error
    else
        null;

    // Resolve current slot and epoch schedule.
    const current_slot = self.commitments.get(commitment);
    const epoch_schedule = &self.epoch_tracker.epoch_schedule;

    // Determine slot range (default: current epoch start to current slot).
    const first_slot: Slot = if (config.range) |range| range.firstSlot else blk: {
        const epoch = epoch_schedule.getEpoch(current_slot);
        break :blk epoch_schedule.getFirstSlotInEpoch(epoch);
    };
    const last_slot: Slot = if (config.range) |range|
        range.lastSlot orelse current_slot
    else
        current_slot;

    if (last_slot < first_slot) return error.InvalidParams; // TODO: invalid params should return a more specific error

    // Validate slot range against slot history bounds (mirrors Agave's
    // bank.get_slot_history() validation). current_slot corresponds to the
    // bank slot which equals slot_history.newest(), and oldest is
    // newest -| MAX_ENTRIES.
    const slot_history_oldest = current_slot -| SlotHistory.MAX_ENTRIES;
    if (first_slot < slot_history_oldest) return error.FirstSlotTooSmall;
    if (last_slot > current_slot) return error.LastSlotTooLarge;

    var slot_set: std.AutoHashMapUnmanaged(Slot, void) = .empty;

    // Collect rooted slots in range using forward iterator
    const highest_root = self.commitments.get(.finalized);
    {
        var rooted_iter = try self.ledger.db.iterator(
            sig.ledger.schema.schema.rooted_slots,
            .forward,
            first_slot,
        );
        defer rooted_iter.deinit();
        while (try rooted_iter.nextKey()) |slot| {
            if (slot > last_slot or slot > highest_root) break;
            try slot_set.put(arena, slot, {});
        }
    }
    // For confirmed commitment, also collect confirmed-but-unrooted slots.
    if (commitment == .confirmed) {
        const latest_confirmed = self.commitments.get(.confirmed);
        const confirmed_slots = try self.getConfirmedUnrootedSlots(
            arena,
            latest_confirmed,
            highest_root,
        );
        for (confirmed_slots) |slot| {
            if (slot >= first_slot and slot <= last_slot) try slot_set.put(
                arena,
                slot,
                {},
            );
        }
    }

    // Get leader schedules (RC-managed, must release).
    const ls = try self.epoch_tracker.getLeaderSchedules();
    defer ls.release();

    // Iterate slot range, build by_identity map using PubkeyMap internally
    // to avoid duplicate string key allocations.
    var by_identity: sig.utils.collections.PubkeyMap(struct { u64, u64 }) = .empty;
    for (first_slot..last_slot + 1) |slot| {
        const leader = ls.leader_schedules.getLeaderOrNull(slot) orelse continue;

        if (identity_filter) |filter| if (!leader.equals(&filter)) continue;

        const gop = try by_identity.getOrPut(arena, leader);
        if (!gop.found_existing) gop.value_ptr.* = .{ 0, 0 };
        gop.value_ptr.*[0] += 1; // leader_slots
        if (slot_set.contains(slot)) gop.value_ptr.*[1] += 1; // blocks_produced
    }

    return .{
        .context = .{ .slot = current_slot },
        .value = .{
            .byIdentity = .{ .map = by_identity },
            .range = .{ .firstSlot = first_slot, .lastSlot = last_slot },
        },
    };
}

/// [agave] https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/rpc/src/rpc.rs#L1577-L1609
pub fn getBlockTime(
    self: LedgerHookContext,
    arena: Allocator,
    params: GetBlockTime,
) !GetBlockTime.Response {
    const reader = self.ledger.reader();
    const highest_root = self.commitments.get(.finalized);

    if (params.slot <= highest_root) {
        return reader.getRootedBlockTime(arena, params.slot) catch |err| switch (err) {
            error.SlotNotRooted => return error.BlockNotAvailable,
            error.SlotUnavailable => return null,
            error.SlotCleanedUp => return error.SlotCleanedUp,
            else => return err,
        };
    } else {
        return try reader.getCompleteBlockTime(arena, params.slot);
    }
}

pub fn getFirstAvailableBlock(
    self: LedgerHookContext,
    _: Allocator,
    _: GetFirstAvailableBlock,
) !GetFirstAvailableBlock.Response {
    return self.ledger.reader().getFirstAvailableBlock() catch 0;
}

/// Check the health of the node.
///
/// A node is considered healthy if the node's latest optimistically confirmed
/// slot is within `health_check_slot_distance` of the cluster's latest
/// optimistically confirmed slot.
///
/// Returns `RpcHealthStatus` which is then formatted by the server layer:
/// - JSON-RPC: "ok" result on success, error with code -32005 on failure
/// - HTTP GET /health: always 200 OK with "ok", "behind", or "unknown"
///
/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L2806-L2818
pub fn getHealth(
    self: LedgerHookContext,
    _: Allocator,
    _: GetHealth,
) !GetHealth.Response {
    // Get the node's processed slot (replay tip according to vote tracking)
    const latest_processed_slot = self.commitments.get(.processed);
    if (latest_processed_slot == 0) {
        return .unknown;
    }

    // Get the cluster's latest optimistically confirmed slot
    // NOTE: this commitment confirmed value is from both replay and vote tracker gossip votes,
    // gossip has latest from the network which is what we need for comparison
    const latest_confirmed_slot = self.commitments.get(.confirmed);
    if (latest_confirmed_slot == 0) {
        return .unknown;
    }

    if (latest_processed_slot >=
        latest_confirmed_slot -| self.health_check_slot_distance)
    {
        return .ok;
    } else {
        const num_slots_behind = latest_confirmed_slot -|
            latest_processed_slot;
        return .{ .behind = num_slots_behind };
    }
}

pub fn getInflationReward(
    self: LedgerHookContext,
    arena: Allocator,
    params: GetInflationReward,
) !GetInflationReward.Response {
    const config: GetInflationReward.Config = params.config orelse .{};
    const commitment = config.commitment orelse .finalized;

    // Determine the epoch to query. Default: current_epoch - 1.
    const current_slot = self.commitments.get(commitment);

    try slot_resolution.validateMinContextSlot(current_slot, config.minContextSlot);

    const epoch = config.epoch orelse self.epoch_tracker.epoch_schedule.getEpoch(current_slot) -| 1;

    // Rewards are distributed in the first block of (epoch + 1).
    const first_slot_in_reward_epoch = self.epoch_tracker.epoch_schedule.getFirstSlotInEpoch(
        epoch +| 1,
    );

    const first_confirmed_block_in_epoch: u64 = blk: {
        const blocks = self.getBlocksWithLimit(arena, .{
            .start_slot = first_slot_in_reward_epoch,
            .limit = 1,
            .config = .{ .commitment = commitment },
        }) catch return error.BlockNotAvailable;
        if (blocks.len == 0) return error.BlockNotAvailable;
        break :blk blocks[0];
    };

    const epoch_boundary_block = self.getBlock(arena, .{
        .slot = first_confirmed_block_in_epoch,
        .encoding_or_config = .{ .config = .{
            .commitment = commitment,
            .transactionDetails = .none,
        } },
    }) catch return error.BlockNotAvailable;

    if (epoch_boundary_block.parentSlot >= first_slot_in_reward_epoch) {
        return error.SlotNotEpochBoundary;
    }

    const epoch_has_partitioned_rewards = epoch_boundary_block.numRewardPartitions != null;

    var addresses = blk: {
        var map = PubkeyMap(void).empty;
        for (params.addresses) |addr| _ = try map.getOrPut(arena, addr);
        break :blk map;
    };

    var reward_map: PubkeyMap(struct { GetBlock.Response.UiReward, Slot }) = .empty;
    if (epoch_boundary_block.rewards) |rewards| {
        for (rewards) |reward| {
            if (reward.rewardType != .Voting and
                (reward.rewardType != .Staking or epoch_has_partitioned_rewards)) continue;
            if (!addresses.contains(reward.pubkey)) continue;
            try reward_map.put(
                arena,
                reward.pubkey,
                .{ reward, first_confirmed_block_in_epoch },
            );
        }
    }

    if (epoch_has_partitioned_rewards) {
        const num_partitions = epoch_boundary_block.numRewardPartitions orelse
            @panic("numRewardPartitions should be set if epoch_has_partitioned_rewards is true");

        var partition_index_addresses: std.AutoArrayHashMapUnmanaged(
            usize,
            PubkeyMap(void),
        ) = .empty;
        const hasher = sig.replay.rewards.hasher.initHasher(
            &epoch_boundary_block.previousBlockhash,
        );
        for (addresses.entries.items(.key)) |addr| {
            if (reward_map.contains(addr)) continue;
            const partition_index = sig.replay.rewards.hasher.hashAddressToPartition(
                hasher,
                &addr,
                @intCast(num_partitions),
            );
            var entry = try partition_index_addresses.getOrPut(arena, partition_index);
            if (!entry.found_existing) entry.value_ptr.* = PubkeyMap(void).empty;
            _ = try entry.value_ptr.getOrPut(arena, addr);
        }

        const block_list = try self.getBlocksWithLimit(arena, .{
            .start_slot = first_confirmed_block_in_epoch + 1,
            .limit = num_partitions,
            .config = .{ .commitment = commitment },
        });

        for (
            partition_index_addresses.keys(),
            partition_index_addresses.values(),
        ) |partition_index, partition_addresses| {
            const slot = if (block_list.len > partition_index)
                block_list[partition_index]
            else
                return error.EpochRewardsPeriodActive;

            const block_rewards = blk: {
                const maybe_rewards_res = self.ledger.reader().getBlockRewards(
                    arena,
                    slot,
                ) catch return error.BlockNotAvailable;
                if (maybe_rewards_res) |res| break :blk res.rewards else continue;
            };
            for (block_rewards) |reward| {
                if (reward.reward_type != .staking) continue;
                if (!partition_addresses.contains(reward.pubkey)) continue;
                try reward_map.put(
                    arena,
                    reward.pubkey,
                    .{ .fromLedgerReward(reward), slot },
                );
            }
        }
    }

    const results = try arena.alloc(?GetInflationReward.InflationReward, addresses.count());
    @memset(results, null);
    for (addresses.keys(), results) |addr, *result| {
        const reward, const slot = reward_map.get(addr) orelse continue;
        result.* = .{
            .epoch = epoch,
            .effectiveSlot = slot,
            .amount = @intCast(@abs(reward.lamports)),
            .postBalance = reward.postBalance,
            .commission = reward.commission,
        };
    }

    return results;
}

pub fn getMaxRetransmitSlot(
    self: LedgerHookContext,
    _: Allocator,
    _: GetMaxRetransmitSlot,
) !GetMaxRetransmitSlot.Response {
    const max_retransmit_slot = self.max_retransmit_slot orelse return error.MethodUnavailable;
    return max_retransmit_slot.load(.monotonic);
}

pub fn getMaxShredInsertSlot(
    self: LedgerHookContext,
    _: Allocator,
    _: GetMaxShredInsertSlot,
) !GetMaxShredInsertSlot.Response {
    const max_shred_insert_slot = self.max_shred_insert_slot orelse return error.MethodUnavailable;
    return max_shred_insert_slot.load(.monotonic);
}

pub fn getRecentPerformanceSamples(
    self: LedgerHookContext,
    arena: Allocator,
    params: GetRecentPerformanceSamples,
) !GetRecentPerformanceSamples.Response {
    const limit: usize = if (params.limit) |l|
        std.math.cast(usize, l) orelse return error.InvalidParams
    else
        GetRecentPerformanceSamples.max_limit;

    if (limit > GetRecentPerformanceSamples.max_limit) {
        return error.InvalidParams;
    }

    const reader = self.ledger.reader();
    const samples = try reader.getRecentPerfSamples(arena, limit);

    const result = try arena.alloc(GetRecentPerformanceSamples.RpcPerfSample, samples.items.len);
    for (samples.items, 0..) |entry, i| {
        const slot = entry[0];
        const sample = entry[1];
        result[i] = .{
            .slot = slot,
            .numTransactions = sample.num_transactions,
            .numNonVoteTransactions = if (sample.version == 0)
                null // V1 samples don't have non-vote tx count
            else
                sample.num_non_vote_transactions,
            .numSlots = sample.num_slots,
            .samplePeriodSecs = sample.sample_period_secs,
        };
    }

    return result;
}

/// Look up the status of one or more transaction signatures.
///
/// Tier 1: Check the in-memory StatusCache for recent transactions (covers
/// processed, confirmed, and finalized that haven't been evicted yet).
/// Tier 2: If `searchTransactionHistory` is true, fall back to the on-disk
/// ledger for older finalized transactions.
///
/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.9/rpc/src/rpc.rs#L1641
pub fn getSignatureStatuses(
    self: LedgerHookContext,
    arena: Allocator,
    params: GetSignatureStatuses,
) !GetSignatureStatuses.Response {
    const config: GetSignatureStatuses.Config = params.config orelse .{};
    const search_history = config.searchTransactionHistory orelse false;

    if (params.signatures.len > MAX_GET_SIGNATURE_STATUSES_QUERY_ITEMS) {
        // TODO: invalid params should return a more specific error
        return error.InvalidParams;
    }

    const processed_slot = self.commitments.get(.processed);
    const processed_slot_ref = self.slot_tracker.get(
        processed_slot,
    ) orelse return error.InternalError;
    defer processed_slot_ref.release();

    const results = try arena.alloc(
        ?GetSignatureStatuses.Response.TransactionStatus,
        params.signatures.len,
    );
    @memset(results, null);

    for (params.signatures, results) |signature, *result| {
        // Tier 1: StatusCache (recent in-memory transactions)
        if (try self.getTransactionStatus(
            arena,
            signature,
            &processed_slot_ref,
        )) |status| {
            result.* = status;
            continue;
        }

        // Tier 2: Blockstore (historical finalized transactions)
        // getRootedTransactionStatus only returns transactions from rooted slots
        // (via isRoot check in the blockstore), which ensures fork safety — orphaned
        // fork slots are never rooted. The finalized_slot bound is an additional
        // consistency filter matching Agave's highest_super_majority_root() check.
        // [agave] https://github.com/anza-xyz/agave/blob/v3.1.9/rpc/src/rpc.rs#L1660-1670
        if (!search_history) continue;

        if (try self.ledger.reader().getRootedTransactionStatus(arena, signature)) |status| {
            const slot, const status_meta = status;
            if (slot <= self.commitments.get(.finalized)) {
                result.* = .{
                    .slot = slot,
                    .status = if (status_meta.status) |err| .{ .Err = err } else .{ .Ok = .{} },
                    .confirmations = null,
                    .err = status_meta.status,
                    .confirmationStatus = .finalized,
                };
            }
        }
    }

    return .{
        .context = .{ .slot = processed_slot },
        .value = results,
    };
}

pub fn getSignaturesForAddress(
    self: LedgerHookContext,
    arena: std.mem.Allocator,
    params: GetSignaturesForAddress,
) !GetSignaturesForAddress.Response {
    const config: GetSignaturesForAddress.Config = params.config orelse .{};
    const commitment = config.getCommitment();

    // processed is not supported
    if (commitment == .processed) return error.ProcessedNotSupported;

    const highest_finalized_slot = self.commitments.get(.finalized);
    const highest_slot: Slot = switch (commitment) {
        .confirmed => self.commitments.get(.confirmed),
        .finalized => highest_finalized_slot,
        .processed => unreachable,
    };

    const limit = config.getLimit();
    if (limit == 0 or limit > 1000) return error.InvalidParams; // TODO: invalid params should return a more specific error

    const result = try self.ledger.reader().getConfirmedSignaturesForAddress(
        arena,
        params.address,
        highest_slot,
        config.before,
        config.until,
        limit,
    );

    const response = try arena.alloc(
        @typeInfo(GetSignaturesForAddress.Response).pointer.child,
        result.infos.items.len,
    );
    for (result.infos.items, 0..) |info, i| {
        response[i] = .{
            .signature = info.signature,
            .slot = info.slot,
            .err = info.err,
            .memo = if (info.memo) |m| m.items else null,
            .blockTime = info.block_time,
            .confirmationStatus = if (info.slot <= highest_finalized_slot)
                .finalized
            else
                .confirmed,
            .transactionIndex = info.transaction_index,
        };
    }
    return response;
}

pub fn getTransaction(
    self: LedgerHookContext,
    arena: std.mem.Allocator,
    params: GetTransaction,
) !GetTransaction.Response {
    const config = params.resolveConfig();
    const commitment = config.getCommitment();
    const encoding = config.getEncoding();
    const max_supported_version = config.maxSupportedTransactionVersion;

    const reader = self.ledger.reader();
    const highest_confirmed_slot = self.commitments.get(.confirmed);

    // Get transaction from ledger.
    const confirmed_tx_with_meta = switch (commitment) {
        .processed => return error.ProcessedNotSupported,
        .confirmed => try reader.getCompleteTransaction(
            arena,
            params.signature,
            highest_confirmed_slot,
        ),
        .finalized => try reader.getRootedTransaction(arena, params.signature),
    } orelse return .none;

    return .{ .value = .{
        .slot = confirmed_tx_with_meta.slot,
        .transaction = try block_encoding.encodeTransactionWithStatusMeta(
            arena,
            confirmed_tx_with_meta.tx_with_meta,
            encoding,
            max_supported_version,
            true,
        ),
        .block_time = confirmed_tx_with_meta.block_time,
    } };
}

pub fn minimumLedgerSlot(
    self: LedgerHookContext,
    _: Allocator,
    _: MinimumLedgerSlot,
) !MinimumLedgerSlot.Response {
    var meta_iter = try self.ledger.reader().slotMetaIterator(0);
    defer meta_iter.deinit();
    return try meta_iter.nextKey() orelse 0;
}

fn getTransactionStatus(
    self: LedgerHookContext,
    arena: Allocator,
    signature: Signature,
    slot_ref: *const sig.replay.trackers.SlotTracker.Reference,
) !?GetSignatureStatuses.Response.TransactionStatus {
    const fork = try self.status_cache.getForkAnyBlockhash(
        arena,
        &signature.toBytes(),
        &slot_ref.constants().ancestors,
    ) orelse return null;
    const slot = fork.slot;
    const status = fork.maybe_err;

    const confirmed_slot_ref = self.slot_tracker.get(self.commitments.get(.confirmed));
    defer if (confirmed_slot_ref) |ref| ref.release();
    const confirmed_fork = if (confirmed_slot_ref) |ref| try self.status_cache.getForkAnyBlockhash(
        arena,
        &signature.toBytes(),
        &ref.constants().ancestors,
    ) else null;

    const is_finalized: bool =
        slot <= self.commitments.get(.finalized) and
        (slot_ref.constants().ancestors.containsSlot(slot) or
            self.ledger.reader().isRoot(arena, slot) catch false);

    const confirmations =
        if (self.slot_tracker.consensus_root.load(.monotonic) >= slot and is_finalized)
            null
        else
            self.commitments.stakes.getConfirmationCount(slot) orelse 0;

    return .{
        .slot = slot,
        .status = if (status) |err| .{ .Err = err } else .{ .Ok = .{} },
        .confirmations = confirmations,
        .err = status,
        .confirmationStatus = if (confirmations == null)
            .finalized
        else if (confirmed_fork != null)
            .confirmed
        else
            .processed,
    };
}

/// Walk from latest_confirmed back to the root, collecting confirmed-but-unrooted slots.
/// Returns slots sorted ascending.
fn getConfirmedUnrootedSlots(
    self: LedgerHookContext,
    arena: std.mem.Allocator,
    latest_confirmed: Slot,
    highest_root: Slot,
) ![]Slot {
    var slots = try std.ArrayList(Slot).initCapacity(arena, latest_confirmed - highest_root);

    var iterator = AncestorIterator.initInclusive(arena, &self.ledger.db, latest_confirmed);
    while (try iterator.next()) |slot| {
        if (slot <= highest_root) break;
        try slots.append(arena, slot);
    }

    // AncestorIterator walks backwards (high to low), so reverse to get ascending order.
    std.mem.reverse(Slot, slots.items);
    return try slots.toOwnedSlice(arena);
}

test "getInflationReward enforces minContextSlot" {
    // Only slot_tracker is dereferenced before the minContextSlot check (line 433).
    // All other pointer fields (ledger, epoch_tracker, status_cache) are unused
    // in this error path, following the same `undefined` pattern as Consensus.zig tests.
    var slot_tracker = try sig.replay.trackers.SlotTracker.initEmpty(std.testing.allocator, 5);
    defer slot_tracker.deinit(std.testing.allocator);

    var commitments = sig.replay.trackers.CommitmentTracker.init(std.testing.allocator, 5);
    defer commitments.deinit(std.testing.allocator);

    // CommitmentTracker.init(5) sets finalized=0, confirmed=0, processed=5.
    // Default commitment is .finalized, so current_slot will be 0.
    const ctx = LedgerHookContext{
        .ledger = undefined,
        .epoch_tracker = undefined,
        .status_cache = undefined,
        .slot_tracker = &slot_tracker,
        .commitments = &commitments,
    };

    const result = ctx.getInflationReward(std.testing.allocator, .{
        .addresses = &.{},
        .config = .{ .minContextSlot = 1 },
    });

    try std.testing.expectError(error.RpcMinContextSlotNotMet, result);
}
