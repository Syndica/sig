const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const sig = @import("sig");
const std = @import("std");
const utils = @import("utils.zig");

const Transaction = sig.core.Transaction;

const RuntimeTransaction = sig.runtime.transaction_execution.RuntimeTransaction;

const VerifyTransactionResult = union(enum(u8)) {
    ok: RuntimeTransaction,
    err: pb.TxnResult,
};

const FeatureSet = sig.core.FeatureSet;
const SlotAccountReader = sig.accounts_db.SlotAccountReader;

pub fn verifyTransaction(
    allocator: std.mem.Allocator,
    transaction: Transaction,
    feature_set: *const FeatureSet,
    slot: sig.core.Slot,
    account_reader: SlotAccountReader,
) !VerifyTransactionResult {
    const serialized_msg = transaction.msg.serializeBounded(
        transaction.version,
    ) catch {
        std.debug.print("SanitizedTransaction.msg.serializeBounded failed\n", .{});
        return .{ .err = .{
            .sanitization_error = true,
            .status = transactionErrorToInt(.SanitizeFailure),
        } };
    };
    const msg_hash = sig.core.transaction.Message.hash(serialized_msg.slice());

    if (!feature_set.active(.move_precompile_verification_to_svm, slot)) {
        const maybe_verify_error = try sig.runtime.program.precompiles.verifyPrecompiles(
            allocator,
            transaction,
            feature_set,
            slot,
        );
        if (maybe_verify_error) |verify_error| {
            const converted = utils.convertTransactionError(verify_error);
            return .{ .err = .{
                .sanitization_error = true,
                .status = converted.err,
                .instruction_error = converted.instruction_error,
                .instruction_error_index = converted.instruction_index,
                .custom_error = converted.custom_error,
            } };
        }
    }

    const resolved_batch = sig.replay.resolve_lookup.resolveBatch(
        allocator,
        account_reader,
        &.{transaction},
    ) catch |err| {
        const err_code = switch (err) {
            error.AddressLookupTableNotFound => transactionErrorToInt(
                .AddressLookupTableNotFound,
            ),
            error.InvalidAddressLookupTableOwner => transactionErrorToInt(
                .InvalidAddressLookupTableOwner,
            ),
            error.InvalidAddressLookupTableData => transactionErrorToInt(
                .InvalidAddressLookupTableData,
            ),
            error.InvalidAddressLookupTableIndex => transactionErrorToInt(
                .InvalidAddressLookupTableIndex,
            ),
            else => std.debug.panic("Unexpected error: {s}\n", .{@errorName(err)}),
        };
        return .{ .err = .{
            .sanitization_error = true,
            .status = err_code,
        } };
    };
    defer resolved_batch.deinit(allocator);

    const resolved_txn = resolved_batch.transactions[0];

    const instrs = try allocator.dupe(sig.runtime.InstructionInfo, resolved_txn.instructions);
    for (instrs) |*instr| instr.instruction_data = try allocator.dupe(u8, instr.instruction_data);

    return .{ .ok = .{
        .signature_count = resolved_txn.transaction.signatures.len,
        .fee_payer = resolved_txn.transaction.msg.account_keys[0],
        .msg_hash = msg_hash,
        .recent_blockhash = resolved_txn.transaction.msg.recent_blockhash,
        .instruction_infos = instrs,
        .accounts = try resolved_txn.accounts.clone(allocator),
    } };
}

fn verifyErrorToInt(err: sig.core.transaction.Transaction.VerifyError) u32 {
    return switch (err) {
        error.SignatureVerificationFailed => transactionErrorToInt(.SignatureFailure),
        error.SerializationFailed => transactionErrorToInt(.SanitizeFailure),
        else => std.debug.panic("Should not happen: {s}", .{@errorName(err)}),
    };
}

fn transactionErrorToInt(err: sig.ledger.transaction_status.TransactionError) u32 {
    return @intFromEnum(err) + 1;
}
