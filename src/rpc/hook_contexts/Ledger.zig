//! RPC hook context for block-related methods.
//! Requires access to the Ledger and SlotTracker for commitment checks.
const std = @import("std");
const sig = @import("../../sig.zig");
const base58 = @import("base58");
const methods = @import("../methods.zig");
const parse_instruction = @import("../parse_instruction/lib.zig");

const AccountKeys = parse_instruction.AccountKeys;
const Allocator = std.mem.Allocator;
const AncestorIterator = sig.ledger.Reader.AncestorIterator;
const GetBlock = methods.GetBlock;
const GetBlocks = methods.GetBlocks;
const GetBlocksWithLimit = methods.GetBlocksWithLimit;
const GetInflationReward = methods.GetInflationReward;
const GetSignaturesForAddress = methods.GetSignaturesForAddress;
const GetTransaction = methods.GetTransaction;
const LoadedAddresses = sig.ledger.transaction_status.LoadedAddresses;
const Pubkey = sig.core.Pubkey;
const ReservedAccounts = sig.core.ReservedAccounts;
const Signature = sig.core.Signature;
const Slot = sig.core.Slot;
const TransactionDetails = methods.common.TransactionDetails;
const TransactionEncoding = methods.common.TransactionEncoding;

const LedgerHookContext = @This();

ledger: *sig.ledger.Ledger,
slot_tracker: *const sig.replay.trackers.SlotTracker,
epoch_schedule: sig.core.EpochSchedule,

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
    const max_supported_version = config.getMaxSupportedTransactionVersion();

    // Reject processed commitment (Agave behavior: only confirmed and finalized supported)
    if (commitment == .processed) {
        return error.ProcessedNotSupported;
    }

    // Get block from ledger.
    // Finalized path uses getRootedBlock (adds checkLowestCleanupSlot + isRoot checks,
    // matching Agave's get_rooted_block).
    // Confirmed path uses getCompleteBlock (no cleanup check, slot may not be rooted yet).
    const reader = self.ledger.reader();
    const latest_confirmed_slot = self.slot_tracker.getSlotForCommitment(.confirmed);
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

    return try encodeBlockWithOptions(arena, block, encoding, .{
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

    const highest_root = self.slot_tracker.getSlotForCommitment(.finalized);
    const upper_bound = if (commitment == .finalized)
        highest_root
    else
        self.slot_tracker.getSlotForCommitment(.confirmed);

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
            const latest_confirmed = self.slot_tracker.getSlotForCommitment(.confirmed);
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

    const highest_root = self.slot_tracker.getSlotForCommitment(.finalized);

    // Collect rooted (finalized) slots starting from start_slot, up to limit.
    var blocks = try std.ArrayList(Slot).initCapacity(arena, params.limit);

    var rooted_iter = try self.ledger.db.iterator(
        sig.ledger.schema.schema.rooted_slots,
        .forward,
        params.start_slot,
    );

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

        const latest_confirmed = self.slot_tracker.getSlotForCommitment(.confirmed);
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

pub fn getInflationReward(
    self: LedgerHookContext,
    arena: Allocator,
    params: GetInflationReward,
) !GetInflationReward.Response {
    const config: GetInflationReward.Config = params.config orelse .{};
    const commitment = config.commitment orelse .finalized;

    if (commitment == .processed) {
        return error.ProcessedNotSupported;
    }

    // Determine the epoch to query. Default: current_epoch - 1.
    const current_slot = self.slot_tracker.getSlotForCommitment(commitment);

    if (config.minContextSlot) |min_slot| {
        if (current_slot < min_slot) return error.RpcMinContextSlotNotMet;
    }

    const current_epoch = self.epoch_schedule.getEpoch(current_slot);
    const epoch = config.epoch orelse (current_epoch -| 1);

    // Rewards are distributed in the first block of (epoch + 1).
    const first_slot_in_reward_epoch = self.epoch_schedule.getFirstSlotInEpoch(epoch +| 1);

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
        var map = sig.utils.collections.PubkeyMap(void).empty;
        for (params.addresses) |addr| _ = try map.getOrPut(arena, addr);
        break :blk map;
    };

    var reward_map: sig.utils.collections.PubkeyMap(struct {
        GetBlock.Response.UiReward,
        Slot,
    }) = .empty;
    if (epoch_boundary_block.rewards) |rewards| {
        for (rewards) |reward| {
            if (!(reward.rewardType == .Voting or
                (!epoch_has_partitioned_rewards and reward.rewardType == .Staking))) continue;
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

        var partition_index_addresses: std.AutoHashMapUnmanaged(
            usize,
            std.ArrayListUnmanaged(Pubkey),
        ) = .empty;
        for (addresses.entries.items(.key)) |addr| {
            if (reward_map.contains(addr)) continue;
            const partition_index = sig.replay.rewards.hasher.hashAddressToPartition(
                &addr,
                &epoch_boundary_block.previousBlockhash,
                @intCast(num_partitions),
            );
            var entry = try partition_index_addresses.getOrPut(arena, partition_index);
            if (!entry.found_existing) entry.value_ptr.* = std.ArrayListUnmanaged(Pubkey).empty;
            try entry.value_ptr.append(arena, addr);
        }

        const block_list = try self.getBlocksWithLimit(arena, .{
            .start_slot = first_confirmed_block_in_epoch + 1,
            .limit = num_partitions,
            .config = .{ .commitment = commitment },
        });

        var partition_idx_addr_iter = partition_index_addresses.iterator();
        while (partition_idx_addr_iter.next()) |entry| {
            const partition_index = entry.key_ptr.*;
            const slot = if (block_list.len > partition_index)
                block_list[partition_index]
            else
                return error.EpochRewardsPeriodActive;

            const block = self.getBlock(arena, .{ .slot = slot, .encoding_or_config = .{
                .config = .{
                    .commitment = commitment,
                    .transactionDetails = .none,
                },
            } }) catch return error.BlockNotAvailable;

            const block_rewards = if (block.rewards) |rewards| rewards else continue;
            for (block_rewards) |reward| {
                if (reward.rewardType != .Staking) continue;
                if (!addresses.contains(reward.pubkey)) continue;
                try reward_map.put(arena, reward.pubkey, .{ reward, slot });
            }
        }
    }

    var results = try arena.alloc(?GetInflationReward.InflationReward, params.addresses.len);
    for (addresses.entries.items(.key), 0..) |addr, i| {
        const reward, const slot = reward_map.get(addr) orelse {
            results[i] = null;
            continue;
        };
        results[i] = .{
            .epoch = epoch,
            .effectiveSlot = slot,
            .amount = @intCast(@abs(reward.lamports)),
            .postBalance = reward.postBalance,
            .commission = reward.commission,
        };
    }

    return results;
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

    const highest_finalized_slot = self.slot_tracker.getSlotForCommitment(.finalized);
    const highest_slot: Slot = switch (commitment) {
        .confirmed => self.slot_tracker.getSlotForCommitment(.confirmed),
        .finalized => highest_finalized_slot,
        .processed => unreachable,
    };

    if (config.minContextSlot) |min_slot| {
        if (highest_slot < min_slot) return error.RpcMinContextSlotNotMet;
    }

    const limit = config.getLimit();
    if (limit == 0 or limit > 1000) return error.InvalidParams;

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
        };
    }
    return response;
}

pub fn getTransaction(
    self: LedgerHookContext,
    arena: std.mem.Allocator,
    params: GetTransaction,
) !GetTransaction.Response {
    const config: GetTransaction.Config = params.config orelse .{};
    const commitment = config.commitment orelse .finalized;
    const encoding = config.encoding orelse .json;
    const max_supported_version = config.maxSupportedTransactionVersion;

    const reader = self.ledger.reader();
    const highest_confirmed_slot = self.slot_tracker.getSlotForCommitment(.confirmed);

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
        .transaction = try encodeTransactionWithStatusMeta(
            arena,
            confirmed_tx_with_meta.tx_with_meta,
            encoding,
            max_supported_version,
            true,
        ),
        .block_time = confirmed_tx_with_meta.block_time,
    } };
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

/// Encode transactions and/or signatures based on the requested options.
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/lib.rs#L332
fn encodeBlockWithOptions(
    arena: Allocator,
    block: sig.ledger.Reader.VersionedConfirmedBlock,
    encoding: TransactionEncoding,
    options: struct {
        tx_details: TransactionDetails,
        show_rewards: bool,
        max_supported_version: ?u8,
    },
) !GetBlock.Response {
    const transactions, const signatures = blk: switch (options.tx_details) {
        .none => break :blk .{ null, null },
        .full => {
            const transactions = try arena.alloc(
                GetBlock.Response.EncodedTransactionWithStatusMeta,
                block.transactions.len,
            );

            for (block.transactions, 0..) |tx_with_meta, i| {
                transactions[i] = try encodeTransactionWithStatusMeta(
                    arena,
                    .{ .complete = tx_with_meta },
                    encoding,
                    options.max_supported_version,
                    options.show_rewards,
                );
            }

            break :blk .{ transactions, null };
        },
        .signatures => {
            const sigs = try arena.alloc(Signature, block.transactions.len);

            for (block.transactions, 0..) |tx_with_meta, i| {
                if (tx_with_meta.transaction.signatures.len == 0) {
                    return error.InvalidTransaction;
                }
                sigs[i] = tx_with_meta.transaction.signatures[0];
            }

            break :blk .{ null, sigs };
        },
        .accounts => {
            const transactions = try arena.alloc(
                GetBlock.Response.EncodedTransactionWithStatusMeta,
                block.transactions.len,
            );

            for (block.transactions, 0..) |tx_with_meta, i| {
                transactions[i] = try buildJsonAccounts(
                    arena,
                    .{ .complete = tx_with_meta },
                    options.max_supported_version,
                    options.show_rewards,
                );
            }

            break :blk .{ transactions, null };
        },
    };

    return .{
        .blockhash = block.blockhash,
        .previousBlockhash = block.previous_blockhash,
        .parentSlot = block.parent_slot,
        .transactions = transactions,
        .signatures = signatures,
        .rewards = if (options.show_rewards) try convertRewards(
            arena,
            block.rewards,
        ) else null,
        .numRewardPartitions = block.num_partitions,
        .blockTime = block.block_time,
        .blockHeight = block.block_height,
    };
}

/// Validates that the transaction version is supported by the provided max version
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/lib.rs#L496
fn validateVersion(
    version: sig.core.transaction.Version,
    max_supported_version: ?u8,
) !?GetBlock.Response.EncodedTransactionWithStatusMeta.TransactionVersion {
    if (max_supported_version) |max_version| switch (version) {
        .legacy => return .legacy,
        else => |tag| {
            const version_num = @intFromEnum(tag);
            if (version_num <= max_version)
                return .{ .number = version_num }
            else
                return error.UnsupportedTransactionVersion;
        },
    } else switch (version) {
        .legacy => return null,
        .v0 => return error.UnsupportedTransactionVersion,
    }
}

/// Encode a transaction with its metadata for the RPC response.
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/lib.rs#L452
fn encodeTransactionWithStatusMeta(
    arena: Allocator,
    tx_with_meta: sig.ledger.Reader.TransactionWithStatusMeta,
    encoding: TransactionEncoding,
    max_supported_version: ?u8,
    show_rewards: bool,
) !GetBlock.Response.EncodedTransactionWithStatusMeta {
    return switch (tx_with_meta) {
        .missing_metadata => |tx| .{
            .version = null,
            .transaction = try encodeTransactionWithoutMeta(
                arena,
                tx,
                encoding,
            ),
            .meta = null,
        },
        .complete => |vtx| try encodeVersionedTransactionWithStatusMeta(
            arena,
            vtx,
            encoding,
            max_supported_version,
            show_rewards,
        ),
    };
}

/// Encode a transaction missing metadata
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/lib.rs#L708
fn encodeTransactionWithoutMeta(
    arena: Allocator,
    transaction: sig.core.Transaction,
    encoding: TransactionEncoding,
) !GetBlock.Response.EncodedTransaction {
    switch (encoding) {
        .binary => {
            const bincode_bytes = try sig.bincode.writeAlloc(arena, transaction, .{});

            var base58_str = try arena.alloc(u8, base58.encodedMaxSize(bincode_bytes.len));
            const encoded_len = base58.Table.BITCOIN.encode(
                base58_str,
                bincode_bytes,
            );

            return .{ .legacy_binary = base58_str[0..encoded_len] };
        },
        .base58 => {
            const bincode_bytes = try sig.bincode.writeAlloc(arena, transaction, .{});

            var base58_str = try arena.alloc(u8, base58.encodedMaxSize(bincode_bytes.len));
            const encoded_len = base58.Table.BITCOIN.encode(
                base58_str,
                bincode_bytes,
            );

            return .{ .binary = .{ base58_str[0..encoded_len], .base58 } };
        },
        .base64 => {
            const bincode_bytes = try sig.bincode.writeAlloc(arena, transaction, .{});

            const encoded_len = std.base64.standard.Encoder.calcSize(bincode_bytes.len);
            const base64_buf = try arena.alloc(u8, encoded_len);
            _ = std.base64.standard.Encoder.encode(base64_buf, bincode_bytes);

            return .{ .binary = .{ base64_buf, .base64 } };
        },
        .json, .jsonParsed => |enc| return .{ .json = .{
            .signatures = try arena.dupe(Signature, transaction.signatures),
            .message = try encodeLegacyTransactionMessage(
                arena,
                transaction.msg,
                enc,
            ),
        } },
    }
}

/// Encode a full versioned transaction
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/lib.rs#L520
fn encodeVersionedTransactionWithStatusMeta(
    arena: Allocator,
    tx_with_meta: sig.ledger.Reader.VersionedTransactionWithStatusMeta,
    encoding: TransactionEncoding,
    max_supported_version: ?u8,
    show_rewards: bool,
) !GetBlock.Response.EncodedTransactionWithStatusMeta {
    const version = try validateVersion(
        tx_with_meta.transaction.version,
        max_supported_version,
    );
    return .{
        .transaction = try encodeVersionedTransactionWithMeta(
            arena,
            tx_with_meta.transaction,
            tx_with_meta.meta,
            encoding,
        ),
        .meta = switch (encoding) {
            .jsonParsed => try parseUiTransactionStatusMeta(
                arena,
                tx_with_meta.meta,
                tx_with_meta.transaction.msg.account_keys,
                show_rewards,
            ),
            else => try parseUiTransactionStatusMetaFromLedger(
                arena,
                tx_with_meta.meta,
                show_rewards,
            ),
        },
        .version = version,
    };
}

/// Parse a ledger transaction status meta directly into a UiTransactionStatusMeta (matches agave's From implementation)
/// [agave] https://github.com/anza-xyz/agave/blob/1c084acb9195fab0981b9876bcb409cabaf35d5c/transaction-status-client-types/src/lib.rs#L380
fn parseUiTransactionStatusMetaFromLedger(
    arena: Allocator,
    meta: sig.ledger.meta.TransactionStatusMeta,
    show_rewards: bool,
) !GetBlock.Response.UiTransactionStatusMeta {
    // Build status field
    const status: GetBlock.Response.UiTransactionResultStatus = if (meta.status) |err|
        .{ .Ok = null, .Err = err }
    else
        .{ .Ok = .{}, .Err = null };

    // Convert inner instructions
    const inner_instructions = if (meta.inner_instructions) |iis|
        try convertInnerInstructions(arena, iis)
    else
        &.{};

    // Convert token balances
    const pre_token_balances = if (meta.pre_token_balances) |balances|
        try convertTokenBalances(arena, balances)
    else
        &.{};

    const post_token_balances = if (meta.post_token_balances) |balances|
        try convertTokenBalances(arena, balances)
    else
        &.{};

    // Convert loaded addresses
    const loaded_addresses = try LedgerHookContext.convertLoadedAddresses(
        arena,
        meta.loaded_addresses,
    );

    // Convert return data
    const return_data = if (meta.return_data) |rd|
        try convertReturnData(arena, rd)
    else
        null;

    const rewards: ?[]GetBlock.Response.UiReward = if (show_rewards) rewards: {
        if (meta.rewards) |rewards| {
            const converted = try arena.alloc(GetBlock.Response.UiReward, rewards.len);
            for (rewards, 0..) |reward, i| {
                converted[i] = GetBlock.Response.UiReward.fromLedgerReward(reward);
            }
            break :rewards converted;
        } else break :rewards &.{};
    } else null;

    return .{
        .err = meta.status,
        .status = status,
        .fee = meta.fee,
        .preBalances = try arena.dupe(u64, meta.pre_balances),
        .postBalances = try arena.dupe(u64, meta.post_balances),
        .innerInstructions = .{ .value = inner_instructions },
        .logMessages = .{ .value = meta.log_messages orelse &.{} },
        .preTokenBalances = .{ .value = pre_token_balances },
        .postTokenBalances = .{ .value = post_token_balances },
        .rewards = if (rewards) |r| .{ .value = r } else .none,
        .loadedAddresses = .{ .value = loaded_addresses },
        .returnData = if (return_data) |rd| .{ .value = rd } else .skip,
        .computeUnitsConsumed = if (meta.compute_units_consumed) |cuc| .{
            .value = cuc,
        } else .skip,
        .costUnits = if (meta.cost_units) |cu| .{ .value = cu } else .skip,
    };
}

/// Encode a transaction with its metadata
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/lib.rs#L632
fn encodeVersionedTransactionWithMeta(
    arena: Allocator,
    transaction: sig.core.Transaction,
    meta: sig.ledger.transaction_status.TransactionStatusMeta,
    encoding: TransactionEncoding,
) !GetBlock.Response.EncodedTransaction {
    switch (encoding) {
        .binary => {
            const bincode_bytes = try sig.bincode.writeAlloc(arena, transaction, .{});

            var base58_str = try arena.alloc(u8, base58.encodedMaxSize(bincode_bytes.len));
            const encoded_len = base58.Table.BITCOIN.encode(
                base58_str,
                bincode_bytes,
            );

            return .{ .legacy_binary = base58_str[0..encoded_len] };
        },
        .base58 => {
            const bincode_bytes = try sig.bincode.writeAlloc(arena, transaction, .{});

            var base58_str = try arena.alloc(u8, base58.encodedMaxSize(bincode_bytes.len));
            const encoded_len = base58.Table.BITCOIN.encode(
                base58_str,
                bincode_bytes,
            );

            return .{ .binary = .{ base58_str[0..encoded_len], .base58 } };
        },
        .base64 => {
            const bincode_bytes = try sig.bincode.writeAlloc(arena, transaction, .{});

            const encoded_len = std.base64.standard.Encoder.calcSize(bincode_bytes.len);
            const base64_buf = try arena.alloc(u8, encoded_len);
            _ = std.base64.standard.Encoder.encode(base64_buf, bincode_bytes);

            return .{ .binary = .{ base64_buf, .base64 } };
        },
        .json => return try jsonEncodeVersionedTransaction(
            arena,
            transaction,
        ),
        .jsonParsed => return .{ .json = .{
            .signatures = try arena.dupe(Signature, transaction.signatures),
            .message = switch (transaction.version) {
                .legacy => try encodeLegacyTransactionMessage(
                    arena,
                    transaction.msg,
                    .jsonParsed,
                ),
                .v0 => try jsonEncodeV0TransactionMessageWithMeta(
                    arena,
                    transaction.msg,
                    meta,
                    .jsonParsed,
                ),
            },
        } },
    }
}

/// Encode a transaction to JSON format with its metadata
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/lib.rs#L663
fn jsonEncodeVersionedTransaction(
    arena: Allocator,
    transaction: sig.core.Transaction,
) !GetBlock.Response.EncodedTransaction {
    return .{ .json = .{
        .signatures = try arena.dupe(Signature, transaction.signatures),
        .message = switch (transaction.version) {
            .legacy => try encodeLegacyTransactionMessage(arena, transaction.msg, .json),
            .v0 => try jsonEncodeV0TransactionMessage(arena, transaction.msg),
        },
    } };
}

/// Encode a legacy transaction message
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/lib.rs#L743
fn encodeLegacyTransactionMessage(
    arena: Allocator,
    message: sig.core.transaction.Message,
    encoding: TransactionEncoding,
) !GetBlock.Response.UiMessage {
    switch (encoding) {
        .jsonParsed => {
            var reserved_account_keys = try ReservedAccounts.initAllActivated(arena);
            const account_keys = AccountKeys.init(
                message.account_keys,
                null,
            );

            var instructions = try arena.alloc(
                parse_instruction.UiInstruction,
                message.instructions.len,
            );
            for (message.instructions, 0..) |ix, i| {
                instructions[i] = try parse_instruction.parseUiInstruction(
                    arena,
                    .{
                        .program_id_index = ix.program_index,
                        .accounts = ix.account_indexes,
                        .data = ix.data,
                    },
                    &account_keys,
                    1,
                );
            }
            return .{ .parsed = .{
                .account_keys = try parseLegacyMessageAccounts(
                    arena,
                    message,
                    &reserved_account_keys,
                ),
                .recent_blockhash = message.recent_blockhash,
                .instructions = instructions,
                .address_table_lookups = null,
            } };
        },
        else => {
            var instructions = try arena.alloc(
                parse_instruction.UiCompiledInstruction,
                message.instructions.len,
            );
            for (message.instructions, 0..) |ix, i| {
                instructions[i] = .{
                    .programIdIndex = ix.program_index,
                    .accounts = try arena.dupe(u8, ix.account_indexes),
                    .data = blk: {
                        var ret = try arena.alloc(u8, base58.encodedMaxSize(ix.data.len));
                        break :blk ret[0..base58.Table.BITCOIN.encode(ret, ix.data)];
                    },
                    .stackHeight = 1,
                };
            }

            return .{ .raw = .{
                .header = .{
                    .numRequiredSignatures = message.signature_count,
                    .numReadonlySignedAccounts = message.readonly_signed_count,
                    .numReadonlyUnsignedAccounts = message.readonly_unsigned_count,
                },
                .account_keys = try arena.dupe(Pubkey, message.account_keys),
                .recent_blockhash = message.recent_blockhash,
                .instructions = instructions,
                .address_table_lookups = null,
            } };
        },
    }
}

/// Encode a v0 transaction message to JSON format
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/lib.rs#L859
fn jsonEncodeV0TransactionMessage(
    arena: Allocator,
    message: sig.core.transaction.Message,
) !GetBlock.Response.UiMessage {
    var instructions = try arena.alloc(
        parse_instruction.UiCompiledInstruction,
        message.instructions.len,
    );
    for (message.instructions, 0..) |ix, i| {
        instructions[i] = .{
            .programIdIndex = ix.program_index,
            .accounts = try arena.dupe(u8, ix.account_indexes),
            .data = blk: {
                var ret = try arena.alloc(u8, base58.encodedMaxSize(ix.data.len));
                break :blk ret[0..base58.Table.BITCOIN.encode(ret, ix.data)];
            },
            .stackHeight = 1,
        };
    }

    var address_table_lookups = try arena.alloc(
        GetBlock.Response.AddressTableLookup,
        message.address_lookups.len,
    );
    for (message.address_lookups, 0..) |lookup, i| {
        address_table_lookups[i] = .{
            .accountKey = lookup.table_address,
            .writableIndexes = try arena.dupe(u8, lookup.writable_indexes),
            .readonlyIndexes = try arena.dupe(u8, lookup.readonly_indexes),
        };
    }

    return .{ .raw = .{
        .header = .{
            .numRequiredSignatures = message.signature_count,
            .numReadonlySignedAccounts = message.readonly_signed_count,
            .numReadonlyUnsignedAccounts = message.readonly_unsigned_count,
        },
        .account_keys = try arena.dupe(Pubkey, message.account_keys),
        .recent_blockhash = message.recent_blockhash,
        .instructions = instructions,
        .address_table_lookups = address_table_lookups,
    } };
}

/// Encode a v0 transaction message with metadata to JSON format
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/lib.rs#L824
fn jsonEncodeV0TransactionMessageWithMeta(
    arena: Allocator,
    message: sig.core.transaction.Message,
    meta: sig.ledger.transaction_status.TransactionStatusMeta,
    encoding: TransactionEncoding,
) !GetBlock.Response.UiMessage {
    switch (encoding) {
        .jsonParsed => {
            var reserved_account_keys = try ReservedAccounts.initAllActivated(arena);
            const account_keys = AccountKeys.init(
                message.account_keys,
                meta.loaded_addresses,
            );

            var instructions = try arena.alloc(
                parse_instruction.UiInstruction,
                message.instructions.len,
            );
            for (message.instructions, 0..) |ix, i| {
                instructions[i] = try parse_instruction.parseUiInstruction(
                    arena,
                    .{
                        .program_id_index = ix.program_index,
                        .accounts = ix.account_indexes,
                        .data = ix.data,
                    },
                    &account_keys,
                    1,
                );
            }

            var address_table_lookups = try arena.alloc(
                GetBlock.Response.AddressTableLookup,
                message.address_lookups.len,
            );
            for (message.address_lookups, 0..) |lookup, i| {
                address_table_lookups[i] = .{
                    .accountKey = lookup.table_address,
                    .writableIndexes = try arena.dupe(u8, lookup.writable_indexes),
                    .readonlyIndexes = try arena.dupe(u8, lookup.readonly_indexes),
                };
            }

            return .{ .parsed = .{
                .account_keys = try parseV0MessageAccounts(
                    arena,
                    message,
                    account_keys,
                    &reserved_account_keys,
                ),
                .recent_blockhash = message.recent_blockhash,
                .instructions = instructions,
                .address_table_lookups = address_table_lookups,
            } };
        },
        else => |_| return try jsonEncodeV0TransactionMessage(
            arena,
            message,
        ),
    }
}

/// Parse account keys for a legacy transaction message
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/parse_accounts.rs#L7
fn parseLegacyMessageAccounts(
    arena: Allocator,
    message: sig.core.transaction.Message,
    reserved_account_keys: *const ReservedAccounts,
) ![]const GetBlock.Response.ParsedAccount {
    var accounts = try arena.alloc(
        GetBlock.Response.ParsedAccount,
        message.account_keys.len,
    );
    for (message.account_keys, 0..) |account_key, i| {
        accounts[i] = .{
            .pubkey = account_key,
            .writable = message.isWritable(
                i,
                null,
                reserved_account_keys,
            ),
            .signer = message.isSigner(i),
            .source = .transaction,
        };
    }
    return accounts;
}

/// Parse account keys for a versioned transaction message
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/parse_accounts.rs#L21
fn parseV0MessageAccounts(
    arena: Allocator,
    message: sig.core.transaction.Message,
    account_keys: AccountKeys,
    reserved_account_keys: *const ReservedAccounts,
) ![]const GetBlock.Response.ParsedAccount {
    const loaded_addresses: LoadedAddresses = account_keys.dynamic_keys orelse .{
        .writable = &.{},
        .readonly = &.{},
    };
    const total_len = account_keys.len();
    var accounts = try arena.alloc(GetBlock.Response.ParsedAccount, total_len);

    for (0..total_len) |i| {
        const account_key = account_keys.get(i).?;
        accounts[i] = .{
            .pubkey = account_key,
            .writable = message.isWritable(i, .{
                .writable = loaded_addresses.writable,
                .readonly = loaded_addresses.readonly,
            }, reserved_account_keys),
            .signer = message.isSigner(i),
            .source = if (i < message.account_keys.len) .transaction else .lookupTable,
        };
    }
    return accounts;
}

/// Parse transaction and its metadata into the UiTransactionStatusMeta format for the jsonParsed encoding
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/lib.rs#L200
fn parseUiTransactionStatusMeta(
    arena: Allocator,
    meta: sig.ledger.transaction_status.TransactionStatusMeta,
    static_keys: []const Pubkey,
    show_rewards: bool,
) !GetBlock.Response.UiTransactionStatusMeta {
    const account_keys = AccountKeys.init(
        static_keys,
        meta.loaded_addresses,
    );

    // Build status field
    const status: GetBlock.Response.UiTransactionResultStatus = if (meta.status) |err|
        .{ .Ok = null, .Err = err }
    else
        .{ .Ok = .{}, .Err = null };

    // Convert inner instructions
    const inner_instructions: []const parse_instruction.UiInnerInstructions = blk: {
        if (meta.inner_instructions) |iis| {
            var inner_instructions = try arena.alloc(
                parse_instruction.UiInnerInstructions,
                iis.len,
            );
            for (iis, 0..) |ii, i| {
                inner_instructions[i] = try parse_instruction.parseUiInnerInstructions(
                    arena,
                    ii,
                    &account_keys,
                );
            }
            break :blk inner_instructions;
        } else break :blk &.{};
    };

    // Convert token balances
    const pre_token_balances = if (meta.pre_token_balances) |balances|
        try convertTokenBalances(arena, balances)
    else
        &.{};

    const post_token_balances = if (meta.post_token_balances) |balances|
        try convertTokenBalances(arena, balances)
    else
        &.{};

    // Convert return data
    const return_data = if (meta.return_data) |rd|
        try convertReturnData(arena, rd)
    else
        null;

    // Duplicate log messages (original memory will be freed with block.deinit)
    const log_messages: []const []const u8 = if (meta.log_messages) |logs| blk: {
        const duped = try arena.alloc([]const u8, logs.len);
        for (logs, 0..) |log, i| {
            duped[i] = try arena.dupe(u8, log);
        }
        break :blk duped;
    } else &.{};

    const rewards = if (show_rewards) try convertRewards(
        arena,
        meta.rewards,
    ) else &.{};

    return .{
        .err = meta.status,
        .status = status,
        .fee = meta.fee,
        .preBalances = try arena.dupe(u64, meta.pre_balances),
        .postBalances = try arena.dupe(u64, meta.post_balances),
        .innerInstructions = .{ .value = inner_instructions },
        .logMessages = .{ .value = log_messages },
        .preTokenBalances = .{ .value = pre_token_balances },
        .postTokenBalances = .{ .value = post_token_balances },
        .rewards = .{ .value = rewards },
        .loadedAddresses = .skip,
        .returnData = if (return_data) |rd| .{ .value = rd } else .skip,
        .computeUnitsConsumed = if (meta.compute_units_consumed) |cuc| .{
            .value = cuc,
        } else .skip,
        .costUnits = if (meta.cost_units) |cu| .{ .value = cu } else .skip,
    };
}

/// Encode a transaction for transactionDetails=accounts
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/lib.rs#L477
fn buildJsonAccounts(
    arena: Allocator,
    tx_with_meta: sig.ledger.Reader.TransactionWithStatusMeta,
    max_supported_version: ?u8,
    show_rewards: bool,
) !GetBlock.Response.EncodedTransactionWithStatusMeta {
    switch (tx_with_meta) {
        .missing_metadata => |tx| return .{
            .version = null,
            .transaction = try buildTransactionJsonAccounts(
                arena,
                tx,
            ),
            .meta = null,
        },
        .complete => |vtx| return try buildJsonAccountsWithMeta(
            arena,
            vtx,
            max_supported_version,
            show_rewards,
        ),
    }
}

/// Parse json accounts for a transaction without metadata
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/lib.rs#L733
fn buildTransactionJsonAccounts(
    arena: Allocator,
    transaction: sig.core.Transaction,
) !GetBlock.Response.EncodedTransaction {
    var reserved_account_keys = try ReservedAccounts.initAllActivated(arena);
    return .{ .accounts = .{
        .signatures = try arena.dupe(Signature, transaction.signatures),
        .accountKeys = try parseLegacyMessageAccounts(
            arena,
            transaction.msg,
            &reserved_account_keys,
        ),
    } };
}

/// Parse json accounts for a versioned transaction with metadata
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/lib.rs#L555
fn buildJsonAccountsWithMeta(
    arena: Allocator,
    tx_with_meta: sig.ledger.Reader.VersionedTransactionWithStatusMeta,
    max_supported_version: ?u8,
    show_rewards: bool,
) !GetBlock.Response.EncodedTransactionWithStatusMeta {
    const version = try validateVersion(
        tx_with_meta.transaction.version,
        max_supported_version,
    );
    const reserved_account_keys = try ReservedAccounts.initAllActivated(
        arena,
    );

    const account_keys = switch (tx_with_meta.transaction.version) {
        .legacy => try parseLegacyMessageAccounts(
            arena,
            tx_with_meta.transaction.msg,
            &reserved_account_keys,
        ),
        .v0 => try parseV0MessageAccounts(
            arena,
            tx_with_meta.transaction.msg,
            AccountKeys.init(
                tx_with_meta.transaction.msg.account_keys,
                tx_with_meta.meta.loaded_addresses,
            ),
            &reserved_account_keys,
        ),
    };

    return .{
        .transaction = .{ .accounts = .{
            .signatures = try arena.dupe(Signature, tx_with_meta.transaction.signatures),
            .accountKeys = account_keys,
        } },
        .meta = try buildSimpleUiTransactionStatusMeta(
            arena,
            tx_with_meta.meta,
            show_rewards,
        ),
        .version = version,
    };
}

/// Build a simplified UiTransactionStatusMeta with only the fields required for transactionDetails=accounts
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/lib.rs#L168
fn buildSimpleUiTransactionStatusMeta(
    arena: Allocator,
    meta: sig.ledger.transaction_status.TransactionStatusMeta,
    show_rewards: bool,
) !GetBlock.Response.UiTransactionStatusMeta {
    return .{
        .err = meta.status,
        .status = if (meta.status) |err|
            .{ .Ok = null, .Err = err }
        else
            .{ .Ok = .{}, .Err = null },
        .fee = meta.fee,
        .preBalances = try arena.dupe(u64, meta.pre_balances),
        .postBalances = try arena.dupe(u64, meta.post_balances),
        .innerInstructions = .skip,
        .logMessages = .skip,
        .preTokenBalances = .{ .value = if (meta.pre_token_balances) |balances|
            try LedgerHookContext.convertTokenBalances(arena, balances)
        else
            &.{} },
        .postTokenBalances = .{ .value = if (meta.post_token_balances) |balances|
            try LedgerHookContext.convertTokenBalances(arena, balances)
        else
            &.{} },
        .rewards = if (show_rewards) rewards: {
            if (meta.rewards) |rewards| {
                const converted = try arena.alloc(GetBlock.Response.UiReward, rewards.len);
                for (rewards, 0..) |reward, i| {
                    converted[i] = GetBlock.Response.UiReward.fromLedgerReward(reward);
                }
                break :rewards .{ .value = converted };
            } else break :rewards .{ .value = &.{} };
        } else .skip,
        .loadedAddresses = .skip,
        .returnData = .skip,
        .computeUnitsConsumed = .skip,
        .costUnits = .skip,
    };
}

/// Convert inner instructions to wire format.
fn convertInnerInstructions(
    arena: Allocator,
    inner_instructions: []const sig.ledger.transaction_status.InnerInstructions,
) ![]const parse_instruction.UiInnerInstructions {
    const result = try arena.alloc(
        parse_instruction.UiInnerInstructions,
        inner_instructions.len,
    );

    for (inner_instructions, 0..) |ii, i| {
        const instructions = try arena.alloc(
            parse_instruction.UiInstruction,
            ii.instructions.len,
        );

        for (ii.instructions, 0..) |inner_ix, j| {
            const data_str = blk: {
                var ret = try arena.alloc(
                    u8,
                    base58.encodedMaxSize(inner_ix.instruction.data.len),
                );
                break :blk ret[0..base58.Table.BITCOIN.encode(
                    ret,
                    inner_ix.instruction.data,
                )];
            };

            instructions[j] = .{ .compiled = .{
                .programIdIndex = inner_ix.instruction.program_id_index,
                .accounts = try arena.dupe(u8, inner_ix.instruction.accounts),
                .data = data_str,
                .stackHeight = inner_ix.stack_height,
            } };
        }

        result[i] = .{
            .index = ii.index,
            .instructions = instructions,
        };
    }

    return result;
}

/// Convert token balances to wire format.
fn convertTokenBalances(
    arena: Allocator,
    balances: []const sig.ledger.transaction_status.TransactionTokenBalance,
) ![]const GetBlock.Response.UiTransactionTokenBalance {
    const result = try arena.alloc(
        GetBlock.Response.UiTransactionTokenBalance,
        balances.len,
    );

    for (balances, 0..) |b, i| {
        result[i] = .{
            .accountIndex = b.account_index,
            .mint = b.mint,
            .owner = b.owner,
            .programId = b.program_id,
            .uiTokenAmount = .{
                .amount = try arena.dupe(u8, b.ui_token_amount.amount),
                .decimals = b.ui_token_amount.decimals,
                .uiAmount = b.ui_token_amount.ui_amount,
                .uiAmountString = try arena.dupe(u8, b.ui_token_amount.ui_amount_string),
            },
        };
    }

    return result;
}

/// Convert loaded addresses to wire format.
fn convertLoadedAddresses(
    arena: Allocator,
    loaded: LoadedAddresses,
) !GetBlock.Response.UiLoadedAddresses {
    return .{
        .writable = try arena.dupe(Pubkey, loaded.writable),
        .readonly = try arena.dupe(Pubkey, loaded.readonly),
    };
}

/// Convert return data to wire format.
fn convertReturnData(
    arena: Allocator,
    return_data: sig.ledger.transaction_status.TransactionReturnData,
) !GetBlock.Response.UiTransactionReturnData {
    // Base64 encode the return data
    const encoded_len = std.base64.standard.Encoder.calcSize(return_data.data.len);
    const base64_data = try arena.alloc(u8, encoded_len);
    _ = std.base64.standard.Encoder.encode(base64_data, return_data.data);

    return .{
        .programId = return_data.program_id,
        .data = .{ base64_data, .base64 },
    };
}

/// Convert internal reward format to RPC response format.
fn convertRewards(
    arena: Allocator,
    internal_rewards: ?[]const sig.ledger.meta.Reward,
) ![]const GetBlock.Response.UiReward {
    if (internal_rewards == null) return &.{};
    const rewards_value = internal_rewards orelse return &.{};
    const rewards = try arena.alloc(GetBlock.Response.UiReward, rewards_value.len);

    for (rewards_value, 0..) |r, i| {
        rewards[i] = GetBlock.Response.UiReward.fromLedgerReward(r);
    }
    return rewards;
}

fn convertBlockRewards(
    arena: Allocator,
    block_rewards: *const sig.replay.rewards.BlockRewards,
) ![]const GetBlock.Response.UiReward {
    const items = block_rewards.items();
    const rewards = try arena.alloc(GetBlock.Response.UiReward, items.len);

    for (items, 0..) |r, i| {
        rewards[i] = .{
            .pubkey = r.pubkey,
            .lamports = r.reward_info.lamports,
            .postBalance = r.reward_info.post_balance,
            .rewardType = switch (r.reward_info.reward_type) {
                .fee => .Fee,
                .rent => .Rent,
                .staking => .Staking,
                .voting => .Voting,
            },
            .commission = r.reward_info.commission,
        };
    }
    return rewards;
}

test "validateVersion: legacy with max_supported_version" {
    const result = try LedgerHookContext.validateVersion(.legacy, 0);
    try std.testing.expect(result != null);
    try std.testing.expect(result.? == .legacy);
}

test "validateVersion: v0 with max_supported_version >= 0" {
    const result = try LedgerHookContext.validateVersion(.v0, 0);
    try std.testing.expect(result != null);
    try std.testing.expectEqual(@as(u8, 0), result.?.number);
}

test "validateVersion: legacy without max_supported_version returns null" {
    const result = try LedgerHookContext.validateVersion(.legacy, null);
    try std.testing.expect(result == null);
}

test "validateVersion: v0 without max_supported_version errors" {
    const result = LedgerHookContext.validateVersion(.v0, null);
    try std.testing.expectError(error.UnsupportedTransactionVersion, result);
}

test "buildSimpleUiTransactionStatusMeta: basic" {
    const arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.reset(.free_all);
    const allocator = arena.allocator();

    const meta = sig.ledger.transaction_status.TransactionStatusMeta.EMPTY_FOR_TEST;
    const result = try LedgerHookContext.buildSimpleUiTransactionStatusMeta(allocator, meta, false);

    // Basic fields
    try std.testing.expectEqual(@as(u64, 0), result.fee);
    try std.testing.expect(result.err == null);
    // innerInstructions and logMessages should be skipped for accounts mode
    try std.testing.expect(result.innerInstructions == .skip);
    try std.testing.expect(result.logMessages == .skip);
    // show_rewards false → skip
    try std.testing.expect(result.rewards == .skip);
}

test "buildSimpleUiTransactionStatusMeta: show_rewards true with empty rewards" {
    const arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.reset(.free_all);
    const allocator = arena.allocator();

    const meta = sig.ledger.transaction_status.TransactionStatusMeta.EMPTY_FOR_TEST;
    const result = try LedgerHookContext.buildSimpleUiTransactionStatusMeta(allocator, meta, true);

    // show_rewards true but meta.rewards is null → empty value
    try std.testing.expect(result.rewards == .value);
}

test "encodeLegacyTransactionMessage: json encoding" {
    const arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.reset(.free_all);
    const allocator = arena.allocator();

    const msg = sig.core.transaction.Message{
        .signature_count = 1,
        .readonly_signed_count = 0,
        .readonly_unsigned_count = 1,
        .account_keys = &.{ Pubkey.ZEROES, Pubkey{ .data = [_]u8{0xFF} ** 32 } },
        .recent_blockhash = sig.core.Hash.ZEROES,
        .instructions = &.{},
        .address_lookups = &.{},
    };

    const result = try LedgerHookContext.encodeLegacyTransactionMessage(allocator, msg, .json);
    // Result should be a raw message
    const raw = result.raw;

    try std.testing.expectEqual(@as(u8, 1), raw.header.numRequiredSignatures);
    try std.testing.expectEqual(@as(u8, 0), raw.header.numReadonlySignedAccounts);
    try std.testing.expectEqual(@as(u8, 1), raw.header.numReadonlyUnsignedAccounts);
    try std.testing.expectEqual(@as(usize, 2), raw.account_keys.len);
    try std.testing.expectEqual(@as(usize, 0), raw.instructions.len);
    // Legacy should have no address table lookups
    try std.testing.expect(raw.address_table_lookups == null);
}

test "jsonEncodeV0TransactionMessage: with address lookups" {
    const arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.reset(.free_all);
    const allocator = arena.allocator();

    const msg = sig.core.transaction.Message{
        .signature_count = 1,
        .readonly_signed_count = 0,
        .readonly_unsigned_count = 0,
        .account_keys = &.{Pubkey.ZEROES},
        .recent_blockhash = sig.core.Hash.ZEROES,
        .instructions = &.{},
        .address_lookups = &.{.{
            .table_address = Pubkey{ .data = [_]u8{0xAA} ** 32 },
            .writable_indexes = &[_]u8{ 0, 1 },
            .readonly_indexes = &[_]u8{2},
        }},
    };

    const result = try LedgerHookContext.jsonEncodeV0TransactionMessage(allocator, msg);
    const raw = result.raw;

    try std.testing.expectEqual(@as(usize, 1), raw.account_keys.len);
    // V0 should have address table lookups
    try std.testing.expect(raw.address_table_lookups != null);
    try std.testing.expectEqual(@as(usize, 1), raw.address_table_lookups.?.len);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0, 1 },
        raw.address_table_lookups.?[0].writableIndexes,
    );
    try std.testing.expectEqualSlices(u8, &.{2}, raw.address_table_lookups.?[0].readonlyIndexes);

    // Clean up
    arena.free(raw.account_keys);
    for (raw.address_table_lookups.?) |atl| {
        arena.free(atl.writableIndexes);
        arena.free(atl.readonlyIndexes);
    }
    arena.free(raw.address_table_lookups.?);
}

test "encodeLegacyTransactionMessage: base64 encoding" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.reset(.free_all);
    const allocator = arena.allocator();

    const msg = sig.core.transaction.Message{
        .signature_count = 1,
        .readonly_signed_count = 0,
        .readonly_unsigned_count = 1,
        .account_keys = &.{ Pubkey{ .data = [_]u8{0x11} ** 32 }, Pubkey.ZEROES },
        .recent_blockhash = sig.core.Hash.ZEROES,
        .instructions = &.{},
        .address_lookups = &.{},
    };

    // Non-json encodings fall through to the else branch producing raw messages
    const result = try LedgerHookContext.encodeLegacyTransactionMessage(allocator, msg, .base64);
    const raw = result.raw;

    try std.testing.expectEqual(@as(u8, 1), raw.header.numRequiredSignatures);
    try std.testing.expectEqual(@as(usize, 2), raw.account_keys.len);
    try std.testing.expect(raw.address_table_lookups == null);

    arena.free(raw.account_keys);
}

test "encodeTransactionWithoutMeta: base64 encoding" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.reset(.free_all);
    const allocator = arena.allocator();
    const tx = sig.core.Transaction.EMPTY;

    const result = try LedgerHookContext.encodeTransactionWithoutMeta(allocator, tx, .base64);
    const binary = result.binary;

    try std.testing.expect(binary[1] == .base64);
    // base64 encoded data should be non-empty (even empty tx has some bincode overhead)
    try std.testing.expect(binary[0].len > 0);
}

test "encodeTransactionWithoutMeta: json encoding" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.reset(.free_all);
    const allocator = arena.allocator();
    const tx = sig.core.Transaction.EMPTY;

    const result = try LedgerHookContext.encodeTransactionWithoutMeta(allocator, tx, .json);
    const json = result.json;

    // Should produce a json result with signatures and message
    try std.testing.expectEqual(@as(usize, 0), json.signatures.len);
    // Message should be a raw (non-parsed) message for legacy
    const raw = json.message.raw;
    try std.testing.expectEqual(@as(u8, 0), raw.header.numRequiredSignatures);
    try std.testing.expect(raw.address_table_lookups == null);
}

test "encodeTransactionWithoutMeta: base58 encoding" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.reset(.free_all);
    const allocator = arena.allocator();
    const tx = sig.core.Transaction.EMPTY;

    const result = try LedgerHookContext.encodeTransactionWithoutMeta(allocator, tx, .base58);
    const binary = result.binary;

    try std.testing.expect(binary[1] == .base58);
    try std.testing.expect(binary[0].len > 0);
}

test "encodeTransactionWithoutMeta: legacy binary encoding" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.reset(.free_all);
    const allocator = arena.allocator();
    const tx = sig.core.Transaction.EMPTY;

    const result = try LedgerHookContext.encodeTransactionWithoutMeta(allocator, tx, .binary);
    const legacy_binary = result.legacy_binary;

    try std.testing.expect(legacy_binary.len > 0);
}

test "parseUiTransactionStatusMetaFromLedger: always includes loadedAddresses" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.reset(.free_all);
    const allocator = arena.allocator();
    const meta = sig.ledger.transaction_status.TransactionStatusMeta.EMPTY_FOR_TEST;
    const result = try parseUiTransactionStatusMetaFromLedger(
        allocator,
        meta,
        true,
    );
    defer {
        arena.free(result.preBalances);
        arena.free(result.postBalances);
        if (result.loadedAddresses == .value) {
            arena.free(result.loadedAddresses.value.writable);
            arena.free(result.loadedAddresses.value.readonly);
        }
    }
    // loadedAddresses should always have a value
    try std.testing.expect(result.loadedAddresses == .value);
}

test "parseUiTransactionStatusMetaFromLedger: show_rewards false skips rewards" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.reset(.free_all);
    const allocator = arena.allocator();
    const meta = sig.ledger.transaction_status.TransactionStatusMeta.EMPTY_FOR_TEST;
    const result = try parseUiTransactionStatusMetaFromLedger(
        allocator,
        meta,
        false,
    );
    defer {
        arena.free(result.preBalances);
        arena.free(result.postBalances);
    }
    // Rewards should be .none (serialized as null) when show_rewards is false
    try std.testing.expect(result.rewards == .none);
}

test "parseUiTransactionStatusMetaFromLedger: show_rewards true includes rewards" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.reset(.free_all);
    const allocator = arena.allocator();
    const meta = sig.ledger.transaction_status.TransactionStatusMeta.EMPTY_FOR_TEST;
    const result = try parseUiTransactionStatusMetaFromLedger(
        allocator,
        meta,
        true,
    );
    defer {
        arena.free(result.preBalances);
        arena.free(result.postBalances);
    }
    // Rewards should be present (as value) when show_rewards is true
    try std.testing.expect(result.rewards != .skip);
}

test "parseUiTransactionStatusMetaFromLedger: compute_units_consumed present" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.reset(.free_all);
    const allocator = arena.allocator();

    var meta = sig.ledger.transaction_status.TransactionStatusMeta.EMPTY_FOR_TEST;
    meta.compute_units_consumed = 42_000;
    const result = try parseUiTransactionStatusMetaFromLedger(
        allocator,
        meta,
        false,
    );
    try std.testing.expect(result.computeUnitsConsumed == .value);
    try std.testing.expectEqual(@as(u64, 42_000), result.computeUnitsConsumed.value);
}

test "parseUiTransactionStatusMetaFromLedger: compute_units_consumed absent" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.reset(.free_all);
    const allocator = arena.allocator();

    const meta = sig.ledger.transaction_status.TransactionStatusMeta.EMPTY_FOR_TEST;
    const result = try parseUiTransactionStatusMetaFromLedger(
        allocator,
        meta,
        false,
    );
    try std.testing.expect(result.computeUnitsConsumed == .skip);
}
