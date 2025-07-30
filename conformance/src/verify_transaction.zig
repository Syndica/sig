const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const sig = @import("sig");
const std = @import("std");
const utils = @import("utils.zig");

const features = sig.core.features;

const Transaction = sig.core.Transaction;

const RuntimeTransaction = sig.runtime.transaction_execution.RuntimeTransaction;

const VerifyTransactionResult = union(enum(u8)) {
    ok: RuntimeTransaction,
    err: pb.TxnResult,
};

const FeatureSet = sig.core.features.FeatureSet;
const SlotAccountReader = sig.accounts_db.SlotAccountReader;

pub fn verifyTransaction(
    allocator: std.mem.Allocator,
    transaction: Transaction,
    feature_set: *const FeatureSet,
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

    if (!feature_set.active.contains(features.MOVE_PRECOMPILE_VERIFICATION_TO_SVM)) {
        const maybe_verify_error = try sig.runtime.program.precompiles.verifyPrecompiles(
            allocator,
            transaction,
            feature_set,
        );
        if (maybe_verify_error) |verify_error| {
            std.debug.print("Precompile verification failed\n", .{});
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
            error.Overflow => 123456,
            error.OutOfMemory => return error.OutOfMemory,
            else => @panic("TODO: unsure how to handle errors here atm"),
            // TODO: doesn't exist in the error set yet, missing some logic?
            // error.UnsupportedVersion => transactionErrorToInt(.UnsupportedVersion),
            // error.AddressLookupTableNotFound => transactionErrorToInt(.AddressLookupTableNotFound),
            // error.InvalidAddressLookupTableOwner => transactionErrorToInt(.InvalidAddressLookupTableOwner),
            // error.InvalidAddressLookupTableData => transactionErrorToInt(.InvalidAddressLookupTableData),
            // error.InvalidAddressLookupTableIndex => transactionErrorToInt(.InvalidAddressLookupTableIndex),
        };
        std.debug.print("resolve_lookup.resolveBatch failed\n", .{});
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
