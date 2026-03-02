///! RPC hook context for block-related methods.
///! Requires access to the Ledger and SlotTracker for commitment checks.
const std = @import("std");
const sig = @import("../../sig.zig");
const base58 = @import("base58");
const methods = @import("../methods.zig");
const parse_instruction = @import("../parse_instruction/lib.zig");

const AccountKeys = parse_instruction.AccountKeys;
const Allocator = std.mem.Allocator;
const GetBlock = methods.GetBlock;
const LoadedAddresses = sig.ledger.transaction_status.LoadedAddresses;
const Pubkey = sig.core.Pubkey;
const ReservedAccounts = sig.core.ReservedAccounts;
const Signature = sig.core.Signature;
const TransactionDetails = methods.common.TransactionDetails;
const TransactionEncoding = methods.common.TransactionEncoding;

const LedgerHookContext = @This();

ledger: *sig.ledger.Ledger,
slot_tracker: *const sig.replay.trackers.SlotTracker,

pub fn getBlock(
    self: LedgerHookContext,
    allocator: Allocator,
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
        allocator,
        params.slot,
        true,
    ) catch |err| switch (err) {
        // NOTE: we try getCompletedBlock incase SlotTracker has seen the slot
        // but ledger has not yet rooted it
        error.SlotNotRooted => try reader.getCompleteBlock(
            allocator,
            params.slot,
            true,
        ),
        else => return err,
    } else if (commitment == .confirmed) try reader.getCompleteBlock(
        allocator,
        params.slot,
        true,
    ) else return error.BlockNotAvailable;

    return try encodeBlockWithOptions(allocator, block, encoding, .{
        .tx_details = transaction_details,
        .show_rewards = show_rewards,
        .max_supported_version = max_supported_version,
    });
}

/// Encode transactions and/or signatures based on the requested options.
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/lib.rs#L332
fn encodeBlockWithOptions(
    allocator: Allocator,
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
            const transactions = try allocator.alloc(
                GetBlock.Response.EncodedTransactionWithStatusMeta,
                block.transactions.len,
            );
            errdefer allocator.free(transactions);

            for (block.transactions, 0..) |tx_with_meta, i| {
                transactions[i] = try encodeTransactionWithStatusMeta(
                    allocator,
                    .{ .complete = tx_with_meta },
                    encoding,
                    options.max_supported_version,
                    options.show_rewards,
                );
            }

            break :blk .{ transactions, null };
        },
        .signatures => {
            const sigs = try allocator.alloc(Signature, block.transactions.len);
            errdefer allocator.free(sigs);

            for (block.transactions, 0..) |tx_with_meta, i| {
                if (tx_with_meta.transaction.signatures.len == 0) {
                    return error.InvalidTransaction;
                }
                sigs[i] = tx_with_meta.transaction.signatures[0];
            }

            break :blk .{ null, sigs };
        },
        .accounts => {
            const transactions = try allocator.alloc(
                GetBlock.Response.EncodedTransactionWithStatusMeta,
                block.transactions.len,
            );
            errdefer allocator.free(transactions);

            for (block.transactions, 0..) |tx_with_meta, i| {
                transactions[i] = try buildJsonAccounts(
                    allocator,
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
            allocator,
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
        // TODO: update this to use the version number
        // that would be stored inside the version enum
        .v0 => if (max_version >= 0) {
            return .{ .number = 0 };
        } else return error.UnsupportedTransactionVersion,
    } else switch (version) {
        .legacy => return null,
        .v0 => return error.UnsupportedTransactionVersion,
    }
}

/// Encode a transaction with its metadata for the RPC response.
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/lib.rs#L452
fn encodeTransactionWithStatusMeta(
    allocator: Allocator,
    tx_with_meta: sig.ledger.Reader.TransactionWithStatusMeta,
    encoding: TransactionEncoding,
    max_supported_version: ?u8,
    show_rewards: bool,
) !GetBlock.Response.EncodedTransactionWithStatusMeta {
    return switch (tx_with_meta) {
        .missing_metadata => |tx| .{
            .version = null,
            .transaction = try encodeTransactionWithoutMeta(
                allocator,
                tx,
                encoding,
            ),
            .meta = null,
        },
        .complete => |vtx| try encodeVersionedTransactionWithStatusMeta(
            allocator,
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
    allocator: Allocator,
    transaction: sig.core.Transaction,
    encoding: TransactionEncoding,
) !GetBlock.Response.EncodedTransaction {
    switch (encoding) {
        .binary => {
            const bincode_bytes = try sig.bincode.writeAlloc(allocator, transaction, .{});
            defer allocator.free(bincode_bytes);

            var base58_str = try allocator.alloc(u8, base58.encodedMaxSize(bincode_bytes.len));
            const encoded_len = base58.Table.BITCOIN.encode(
                base58_str,
                bincode_bytes,
            );

            return .{ .legacy_binary = base58_str[0..encoded_len] };
        },
        .base58 => {
            const bincode_bytes = try sig.bincode.writeAlloc(allocator, transaction, .{});
            defer allocator.free(bincode_bytes);

            var base58_str = try allocator.alloc(u8, base58.encodedMaxSize(bincode_bytes.len));
            const encoded_len = base58.Table.BITCOIN.encode(
                base58_str,
                bincode_bytes,
            );

            return .{ .binary = .{ base58_str[0..encoded_len], .base58 } };
        },
        .base64 => {
            const bincode_bytes = try sig.bincode.writeAlloc(allocator, transaction, .{});
            defer allocator.free(bincode_bytes);

            const encoded_len = std.base64.standard.Encoder.calcSize(bincode_bytes.len);
            const base64_buf = try allocator.alloc(u8, encoded_len);
            _ = std.base64.standard.Encoder.encode(base64_buf, bincode_bytes);

            return .{ .binary = .{ base64_buf, .base64 } };
        },
        .json, .jsonParsed => |enc| return .{ .json = .{
            .signatures = try allocator.dupe(Signature, transaction.signatures),
            .message = try encodeLegacyTransactionMessage(
                allocator,
                transaction.msg,
                enc,
            ),
        } },
    }
}

/// Encode a full versioned transaction
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/lib.rs#L520
fn encodeVersionedTransactionWithStatusMeta(
    allocator: Allocator,
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
            allocator,
            tx_with_meta.transaction,
            tx_with_meta.meta,
            encoding,
        ),
        .meta = switch (encoding) {
            .jsonParsed => try parseUiTransactionStatusMeta(
                allocator,
                tx_with_meta.meta,
                tx_with_meta.transaction.msg.account_keys,
                show_rewards,
            ),
            else => try parseUiTransactionStatusMetaFromLedger(
                allocator,
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
    allocator: Allocator,
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
        try convertInnerInstructions(allocator, iis)
    else
        &.{};

    // Convert token balances
    const pre_token_balances = if (meta.pre_token_balances) |balances|
        try convertTokenBalances(allocator, balances)
    else
        &.{};

    const post_token_balances = if (meta.post_token_balances) |balances|
        try convertTokenBalances(allocator, balances)
    else
        &.{};

    // Convert loaded addresses
    const loaded_addresses = try LedgerHookContext.convertLoadedAddresses(
        allocator,
        meta.loaded_addresses,
    );

    // Convert return data
    const return_data = if (meta.return_data) |rd|
        try convertReturnData(allocator, rd)
    else
        null;

    const rewards: ?[]GetBlock.Response.UiReward = if (show_rewards) rewards: {
        if (meta.rewards) |rewards| {
            const converted = try allocator.alloc(GetBlock.Response.UiReward, rewards.len);
            for (rewards, 0..) |reward, i| {
                converted[i] = try GetBlock.Response.UiReward.fromLedgerReward(reward);
            }
            break :rewards converted;
        } else break :rewards &.{};
    } else null;

    return .{
        .err = meta.status,
        .status = status,
        .fee = meta.fee,
        .preBalances = try allocator.dupe(u64, meta.pre_balances),
        .postBalances = try allocator.dupe(u64, meta.post_balances),
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
    allocator: Allocator,
    transaction: sig.core.Transaction,
    meta: sig.ledger.transaction_status.TransactionStatusMeta,
    encoding: TransactionEncoding,
) !GetBlock.Response.EncodedTransaction {
    switch (encoding) {
        .binary => {
            const bincode_bytes = try sig.bincode.writeAlloc(allocator, transaction, .{});
            defer allocator.free(bincode_bytes);

            var base58_str = try allocator.alloc(u8, base58.encodedMaxSize(bincode_bytes.len));
            const encoded_len = base58.Table.BITCOIN.encode(
                base58_str,
                bincode_bytes,
            );

            return .{ .legacy_binary = base58_str[0..encoded_len] };
        },
        .base58 => {
            const bincode_bytes = try sig.bincode.writeAlloc(allocator, transaction, .{});
            defer allocator.free(bincode_bytes);

            var base58_str = try allocator.alloc(u8, base58.encodedMaxSize(bincode_bytes.len));
            const encoded_len = base58.Table.BITCOIN.encode(
                base58_str,
                bincode_bytes,
            );

            return .{ .binary = .{ base58_str[0..encoded_len], .base58 } };
        },
        .base64 => {
            const bincode_bytes = try sig.bincode.writeAlloc(allocator, transaction, .{});
            defer allocator.free(bincode_bytes);

            const encoded_len = std.base64.standard.Encoder.calcSize(bincode_bytes.len);
            const base64_buf = try allocator.alloc(u8, encoded_len);
            _ = std.base64.standard.Encoder.encode(base64_buf, bincode_bytes);

            return .{ .binary = .{ base64_buf, .base64 } };
        },
        .json => return try jsonEncodeVersionedTransaction(
            allocator,
            transaction,
        ),
        .jsonParsed => return .{ .json = .{
            .signatures = try allocator.dupe(Signature, transaction.signatures),
            .message = switch (transaction.version) {
                .legacy => try encodeLegacyTransactionMessage(
                    allocator,
                    transaction.msg,
                    .jsonParsed,
                ),
                .v0 => try jsonEncodeV0TransactionMessageWithMeta(
                    allocator,
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
    allocator: Allocator,
    transaction: sig.core.Transaction,
) !GetBlock.Response.EncodedTransaction {
    return .{ .json = .{
        .signatures = try allocator.dupe(Signature, transaction.signatures),
        .message = switch (transaction.version) {
            .legacy => try encodeLegacyTransactionMessage(allocator, transaction.msg, .json),
            .v0 => try jsonEncodeV0TransactionMessage(allocator, transaction.msg),
        },
    } };
}

/// Encode a legacy transaction message
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/lib.rs#L743
fn encodeLegacyTransactionMessage(
    allocator: Allocator,
    message: sig.core.transaction.Message,
    encoding: TransactionEncoding,
) !GetBlock.Response.UiMessage {
    switch (encoding) {
        .jsonParsed => {
            var reserved_account_keys = try ReservedAccounts.initAllActivated(allocator);
            errdefer reserved_account_keys.deinit(allocator);
            const account_keys = AccountKeys.init(
                message.account_keys,
                null,
            );

            var instructions = try allocator.alloc(
                parse_instruction.UiInstruction,
                message.instructions.len,
            );
            for (message.instructions, 0..) |ix, i| {
                instructions[i] = try parse_instruction.parseUiInstruction(
                    allocator,
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
                    allocator,
                    message,
                    &reserved_account_keys,
                ),
                .recent_blockhash = message.recent_blockhash,
                .instructions = instructions,
                .address_table_lookups = null,
            } };
        },
        else => {
            var instructions = try allocator.alloc(
                parse_instruction.UiCompiledInstruction,
                message.instructions.len,
            );
            for (message.instructions, 0..) |ix, i| {
                instructions[i] = .{
                    .programIdIndex = ix.program_index,
                    .accounts = try allocator.dupe(u8, ix.account_indexes),
                    .data = blk: {
                        var ret = try allocator.alloc(u8, base58.encodedMaxSize(ix.data.len));
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
                .account_keys = try allocator.dupe(Pubkey, message.account_keys),
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
    allocator: Allocator,
    message: sig.core.transaction.Message,
) !GetBlock.Response.UiMessage {
    var instructions = try allocator.alloc(
        parse_instruction.UiCompiledInstruction,
        message.instructions.len,
    );
    for (message.instructions, 0..) |ix, i| {
        instructions[i] = .{
            .programIdIndex = ix.program_index,
            .accounts = try allocator.dupe(u8, ix.account_indexes),
            .data = blk: {
                var ret = try allocator.alloc(u8, base58.encodedMaxSize(ix.data.len));
                break :blk ret[0..base58.Table.BITCOIN.encode(ret, ix.data)];
            },
            .stackHeight = 1,
        };
    }

    var address_table_lookups = try allocator.alloc(
        GetBlock.Response.AddressTableLookup,
        message.address_lookups.len,
    );
    for (message.address_lookups, 0..) |lookup, i| {
        address_table_lookups[i] = .{
            .accountKey = lookup.table_address,
            .writableIndexes = try allocator.dupe(u8, lookup.writable_indexes),
            .readonlyIndexes = try allocator.dupe(u8, lookup.readonly_indexes),
        };
    }

    return .{ .raw = .{
        .header = .{
            .numRequiredSignatures = message.signature_count,
            .numReadonlySignedAccounts = message.readonly_signed_count,
            .numReadonlyUnsignedAccounts = message.readonly_unsigned_count,
        },
        .account_keys = try allocator.dupe(Pubkey, message.account_keys),
        .recent_blockhash = message.recent_blockhash,
        .instructions = instructions,
        .address_table_lookups = address_table_lookups,
    } };
}

/// Encode a v0 transaction message with metadata to JSON format
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/lib.rs#L824
fn jsonEncodeV0TransactionMessageWithMeta(
    allocator: Allocator,
    message: sig.core.transaction.Message,
    meta: sig.ledger.transaction_status.TransactionStatusMeta,
    encoding: TransactionEncoding,
) !GetBlock.Response.UiMessage {
    switch (encoding) {
        .jsonParsed => {
            var reserved_account_keys = try ReservedAccounts.initAllActivated(allocator);
            defer reserved_account_keys.deinit(allocator);
            const account_keys = AccountKeys.init(
                message.account_keys,
                meta.loaded_addresses,
            );

            var instructions = try allocator.alloc(
                parse_instruction.UiInstruction,
                message.instructions.len,
            );
            for (message.instructions, 0..) |ix, i| {
                instructions[i] = try parse_instruction.parseUiInstruction(
                    allocator,
                    .{
                        .program_id_index = ix.program_index,
                        .accounts = ix.account_indexes,
                        .data = ix.data,
                    },
                    &account_keys,
                    1,
                );
            }

            var address_table_lookups = try allocator.alloc(
                GetBlock.Response.AddressTableLookup,
                message.address_lookups.len,
            );
            for (message.address_lookups, 0..) |lookup, i| {
                address_table_lookups[i] = .{
                    .accountKey = lookup.table_address,
                    .writableIndexes = try allocator.dupe(u8, lookup.writable_indexes),
                    .readonlyIndexes = try allocator.dupe(u8, lookup.readonly_indexes),
                };
            }

            return .{ .parsed = .{
                .account_keys = try parseV0MessageAccounts(
                    allocator,
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
            allocator,
            message,
        ),
    }
}

/// Parse account keys for a legacy transaction message
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/parse_accounts.rs#L7
fn parseLegacyMessageAccounts(
    allocator: Allocator,
    message: sig.core.transaction.Message,
    reserved_account_keys: *const ReservedAccounts,
) ![]const GetBlock.Response.ParsedAccount {
    var accounts = try allocator.alloc(
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
    allocator: Allocator,
    message: sig.core.transaction.Message,
    account_keys: AccountKeys,
    reserved_account_keys: *const ReservedAccounts,
) ![]const GetBlock.Response.ParsedAccount {
    const loaded_addresses: LoadedAddresses = account_keys.dynamic_keys orelse .{
        .writable = &.{},
        .readonly = &.{},
    };
    const total_len = account_keys.len();
    var accounts = try allocator.alloc(GetBlock.Response.ParsedAccount, total_len);

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
    allocator: Allocator,
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
            var inner_instructions = try allocator.alloc(
                parse_instruction.UiInnerInstructions,
                iis.len,
            );
            for (iis, 0..) |ii, i| {
                inner_instructions[i] = try parse_instruction.parseUiInnerInstructions(
                    allocator,
                    ii,
                    &account_keys,
                );
            }
            break :blk inner_instructions;
        } else break :blk &.{};
    };

    // Convert token balances
    const pre_token_balances = if (meta.pre_token_balances) |balances|
        try convertTokenBalances(allocator, balances)
    else
        &.{};

    const post_token_balances = if (meta.post_token_balances) |balances|
        try convertTokenBalances(allocator, balances)
    else
        &.{};

    // Convert return data
    const return_data = if (meta.return_data) |rd|
        try convertReturnData(allocator, rd)
    else
        null;

    // Duplicate log messages (original memory will be freed with block.deinit)
    const log_messages: []const []const u8 = if (meta.log_messages) |logs| blk: {
        const duped = try allocator.alloc([]const u8, logs.len);
        for (logs, 0..) |log, i| {
            duped[i] = try allocator.dupe(u8, log);
        }
        break :blk duped;
    } else &.{};

    const rewards = if (show_rewards) try convertRewards(
        allocator,
        meta.rewards,
    ) else &.{};

    return .{
        .err = meta.status,
        .status = status,
        .fee = meta.fee,
        .preBalances = try allocator.dupe(u64, meta.pre_balances),
        .postBalances = try allocator.dupe(u64, meta.post_balances),
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
    allocator: Allocator,
    tx_with_meta: sig.ledger.Reader.TransactionWithStatusMeta,
    max_supported_version: ?u8,
    show_rewards: bool,
) !GetBlock.Response.EncodedTransactionWithStatusMeta {
    switch (tx_with_meta) {
        .missing_metadata => |tx| return .{
            .version = null,
            .transaction = try buildTransactionJsonAccounts(
                allocator,
                tx,
            ),
            .meta = null,
        },
        .complete => |vtx| return try buildJsonAccountsWithMeta(
            allocator,
            vtx,
            max_supported_version,
            show_rewards,
        ),
    }
}

/// Parse json accounts for a transaction without metadata
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/lib.rs#L733
fn buildTransactionJsonAccounts(
    allocator: Allocator,
    transaction: sig.core.Transaction,
) !GetBlock.Response.EncodedTransaction {
    var reserved_account_keys = try ReservedAccounts.initAllActivated(allocator);
    return .{ .accounts = .{
        .signatures = try allocator.dupe(Signature, transaction.signatures),
        .accountKeys = try parseLegacyMessageAccounts(
            allocator,
            transaction.msg,
            &reserved_account_keys,
        ),
    } };
}

/// Parse json accounts for a versioned transaction with metadata
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/lib.rs#L555
fn buildJsonAccountsWithMeta(
    allocator: Allocator,
    tx_with_meta: sig.ledger.Reader.VersionedTransactionWithStatusMeta,
    max_supported_version: ?u8,
    show_rewards: bool,
) !GetBlock.Response.EncodedTransactionWithStatusMeta {
    const version = try validateVersion(
        tx_with_meta.transaction.version,
        max_supported_version,
    );
    const reserved_account_keys = try ReservedAccounts.initAllActivated(
        allocator,
    );

    const account_keys = switch (tx_with_meta.transaction.version) {
        .legacy => try parseLegacyMessageAccounts(
            allocator,
            tx_with_meta.transaction.msg,
            &reserved_account_keys,
        ),
        .v0 => try parseV0MessageAccounts(
            allocator,
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
            .signatures = try allocator.dupe(Signature, tx_with_meta.transaction.signatures),
            .accountKeys = account_keys,
        } },
        .meta = try buildSimpleUiTransactionStatusMeta(
            allocator,
            tx_with_meta.meta,
            show_rewards,
        ),
        .version = version,
    };
}

/// Build a simplified UiTransactionStatusMeta with only the fields required for transactionDetails=accounts
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/transaction-status/src/lib.rs#L168
fn buildSimpleUiTransactionStatusMeta(
    allocator: Allocator,
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
        .preBalances = try allocator.dupe(u64, meta.pre_balances),
        .postBalances = try allocator.dupe(u64, meta.post_balances),
        .innerInstructions = .skip,
        .logMessages = .skip,
        .preTokenBalances = .{ .value = if (meta.pre_token_balances) |balances|
            try LedgerHookContext.convertTokenBalances(allocator, balances)
        else
            &.{} },
        .postTokenBalances = .{ .value = if (meta.post_token_balances) |balances|
            try LedgerHookContext.convertTokenBalances(allocator, balances)
        else
            &.{} },
        .rewards = if (show_rewards) rewards: {
            if (meta.rewards) |rewards| {
                const converted = try allocator.alloc(GetBlock.Response.UiReward, rewards.len);
                for (rewards, 0..) |reward, i| {
                    converted[i] = try GetBlock.Response.UiReward.fromLedgerReward(reward);
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
    allocator: Allocator,
    inner_instructions: []const sig.ledger.transaction_status.InnerInstructions,
) ![]const parse_instruction.UiInnerInstructions {
    const result = try allocator.alloc(
        parse_instruction.UiInnerInstructions,
        inner_instructions.len,
    );
    errdefer allocator.free(result);

    for (inner_instructions, 0..) |ii, i| {
        const instructions = try allocator.alloc(
            parse_instruction.UiInstruction,
            ii.instructions.len,
        );
        errdefer allocator.free(instructions);

        for (ii.instructions, 0..) |inner_ix, j| {
            const data_str = blk: {
                var ret = try allocator.alloc(
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
                .accounts = try allocator.dupe(u8, inner_ix.instruction.accounts),
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
    allocator: Allocator,
    balances: []const sig.ledger.transaction_status.TransactionTokenBalance,
) ![]const GetBlock.Response.UiTransactionTokenBalance {
    const result = try allocator.alloc(
        GetBlock.Response.UiTransactionTokenBalance,
        balances.len,
    );
    errdefer allocator.free(result);

    for (balances, 0..) |b, i| {
        result[i] = .{
            .accountIndex = b.account_index,
            .mint = b.mint,
            .owner = b.owner,
            .programId = b.program_id,
            .uiTokenAmount = .{
                .amount = try allocator.dupe(u8, b.ui_token_amount.amount),
                .decimals = b.ui_token_amount.decimals,
                .uiAmount = b.ui_token_amount.ui_amount,
                .uiAmountString = try allocator.dupe(u8, b.ui_token_amount.ui_amount_string),
            },
        };
    }

    return result;
}

/// Convert loaded addresses to wire format.
fn convertLoadedAddresses(
    allocator: Allocator,
    loaded: LoadedAddresses,
) !GetBlock.Response.UiLoadedAddresses {
    return .{
        .writable = try allocator.dupe(Pubkey, loaded.writable),
        .readonly = try allocator.dupe(Pubkey, loaded.readonly),
    };
}

/// Convert return data to wire format.
fn convertReturnData(
    allocator: Allocator,
    return_data: sig.ledger.transaction_status.TransactionReturnData,
) !GetBlock.Response.UiTransactionReturnData {
    // Base64 encode the return data
    const encoded_len = std.base64.standard.Encoder.calcSize(return_data.data.len);
    const base64_data = try allocator.alloc(u8, encoded_len);
    _ = std.base64.standard.Encoder.encode(base64_data, return_data.data);

    return .{
        .programId = return_data.program_id,
        .data = .{ base64_data, .base64 },
    };
}

/// Convert internal reward format to RPC response format.
fn convertRewards(
    allocator: Allocator,
    internal_rewards: ?[]const sig.ledger.meta.Reward,
) ![]const GetBlock.Response.UiReward {
    if (internal_rewards == null) return &.{};
    const rewards_value = internal_rewards orelse return &.{};
    const rewards = try allocator.alloc(GetBlock.Response.UiReward, rewards_value.len);
    errdefer allocator.free(rewards);

    for (rewards_value, 0..) |r, i| {
        rewards[i] = try GetBlock.Response.UiReward.fromLedgerReward(r);
    }
    return rewards;
}

fn convertBlockRewards(
    allocator: Allocator,
    block_rewards: *const sig.replay.rewards.BlockRewards,
) ![]const GetBlock.Response.UiReward {
    const items = block_rewards.items();
    const rewards = try allocator.alloc(GetBlock.Response.UiReward, items.len);
    errdefer allocator.free(rewards);

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
    const allocator = std.testing.allocator;
    const meta = sig.ledger.transaction_status.TransactionStatusMeta.EMPTY_FOR_TEST;
    const result = try LedgerHookContext.buildSimpleUiTransactionStatusMeta(allocator, meta, false);
    defer {
        allocator.free(result.preBalances);
        allocator.free(result.postBalances);
    }

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
    const allocator = std.testing.allocator;
    const meta = sig.ledger.transaction_status.TransactionStatusMeta.EMPTY_FOR_TEST;
    const result = try LedgerHookContext.buildSimpleUiTransactionStatusMeta(allocator, meta, true);
    defer {
        allocator.free(result.preBalances);
        allocator.free(result.postBalances);
    }

    // show_rewards true but meta.rewards is null → empty value
    try std.testing.expect(result.rewards == .value);
}

test "encodeLegacyTransactionMessage: json encoding" {
    const allocator = std.testing.allocator;

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

    allocator.free(raw.account_keys);
}

test "jsonEncodeV0TransactionMessage: with address lookups" {
    const allocator = std.testing.allocator;

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
    allocator.free(raw.account_keys);
    for (raw.address_table_lookups.?) |atl| {
        allocator.free(atl.writableIndexes);
        allocator.free(atl.readonlyIndexes);
    }
    allocator.free(raw.address_table_lookups.?);
}

test "encodeLegacyTransactionMessage: base64 encoding" {
    const allocator = std.testing.allocator;

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

    allocator.free(raw.account_keys);
}

test "encodeTransactionWithoutMeta: base64 encoding" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
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
    defer _ = arena.reset(.free_all);
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
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();
    const tx = sig.core.Transaction.EMPTY;

    const result = try LedgerHookContext.encodeTransactionWithoutMeta(allocator, tx, .base58);
    const binary = result.binary;

    try std.testing.expect(binary[1] == .base58);
    try std.testing.expect(binary[0].len > 0);
}

test "encodeTransactionWithoutMeta: legacy binary encoding" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer _ = arena.reset(.free_all);
    const allocator = arena.allocator();
    const tx = sig.core.Transaction.EMPTY;

    const result = try LedgerHookContext.encodeTransactionWithoutMeta(allocator, tx, .binary);
    const legacy_binary = result.legacy_binary;

    try std.testing.expect(legacy_binary.len > 0);
}

test "parseUiTransactionStatusMetaFromLedger: always includes loadedAddresses" {
    const allocator = std.testing.allocator;
    const meta = sig.ledger.transaction_status.TransactionStatusMeta.EMPTY_FOR_TEST;
    const result = try parseUiTransactionStatusMetaFromLedger(
        allocator,
        meta,
        true,
    );
    defer {
        allocator.free(result.preBalances);
        allocator.free(result.postBalances);
        if (result.loadedAddresses == .value) {
            allocator.free(result.loadedAddresses.value.writable);
            allocator.free(result.loadedAddresses.value.readonly);
        }
    }
    // loadedAddresses should always have a value
    try std.testing.expect(result.loadedAddresses == .value);
}

test "parseUiTransactionStatusMetaFromLedger: show_rewards false skips rewards" {
    const allocator = std.testing.allocator;
    const meta = sig.ledger.transaction_status.TransactionStatusMeta.EMPTY_FOR_TEST;
    const result = try parseUiTransactionStatusMetaFromLedger(
        allocator,
        meta,
        false,
    );
    defer {
        allocator.free(result.preBalances);
        allocator.free(result.postBalances);
    }
    // Rewards should be .none (serialized as null) when show_rewards is false
    try std.testing.expect(result.rewards == .none);
}

test "parseUiTransactionStatusMetaFromLedger: show_rewards true includes rewards" {
    const allocator = std.testing.allocator;
    const meta = sig.ledger.transaction_status.TransactionStatusMeta.EMPTY_FOR_TEST;
    const result = try parseUiTransactionStatusMetaFromLedger(
        allocator,
        meta,
        true,
    );
    defer {
        allocator.free(result.preBalances);
        allocator.free(result.postBalances);
    }
    // Rewards should be present (as value) when show_rewards is true
    try std.testing.expect(result.rewards != .skip);
}

test "parseUiTransactionStatusMetaFromLedger: compute_units_consumed present" {
    const allocator = std.testing.allocator;
    var meta = sig.ledger.transaction_status.TransactionStatusMeta.EMPTY_FOR_TEST;
    meta.compute_units_consumed = 42_000;
    const result = try parseUiTransactionStatusMetaFromLedger(
        allocator,
        meta,
        false,
    );
    defer {
        allocator.free(result.preBalances);
        allocator.free(result.postBalances);
    }
    try std.testing.expect(result.computeUnitsConsumed == .value);
    try std.testing.expectEqual(@as(u64, 42_000), result.computeUnitsConsumed.value);
}

test "parseUiTransactionStatusMetaFromLedger: compute_units_consumed absent" {
    const allocator = std.testing.allocator;
    const meta = sig.ledger.transaction_status.TransactionStatusMeta.EMPTY_FOR_TEST;
    const result = try parseUiTransactionStatusMetaFromLedger(
        allocator,
        meta,
        false,
    );
    defer {
        allocator.free(result.preBalances);
        allocator.free(result.postBalances);
    }
    try std.testing.expect(result.computeUnitsConsumed == .skip);
}
