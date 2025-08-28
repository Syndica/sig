const std = @import("std");
const sig = @import("../sig.zig");

const compute_budget = sig.runtime.program.compute_budget;

const Hash = sig.core.Hash;
const Message = sig.core.transaction.Message;
const Transaction = sig.core.transaction.Transaction;

const TransactionResult = sig.runtime.transaction_execution.TransactionResult;
const ComputeBudgetInstructionDetails = compute_budget.ComputeBudgetInstructionDetails;

pub const VerifyTransactionResult = TransactionResult(struct {
    Hash,
    ComputeBudgetInstructionDetails,
});

pub fn verifyTransaction(txn: Transaction) VerifyTransactionResult {
    return verifyTransactionInner(txn, false);
}

pub fn verifyTransactionWithoutSignatureVerification(txn: Transaction) VerifyTransactionResult {
    return verifyTransactionInner(txn, true);
}

fn verifyTransactionInner(txn: Transaction, skip_sig_verify: bool) VerifyTransactionResult {
    // If skipping signature verification, we still need to serialize and compute the hash
    // to ensure the transaction is well-formed.
    const msg_hash = if (skip_sig_verify)
        Message.hash((txn.msg.serializeBounded(txn.version) catch
            return .{ .err = .SanitizeFailure }).slice())
    else
        txn.verifyAndHashMessage() catch return .{ .err = .SanitizeFailure };

    txn.validate() catch return .{ .err = .SanitizeFailure };

    const compute_budget_instruction_details = switch (compute_budget.execute(&txn.msg)) {
        .ok => |details| details,
        .err => |err| return .{ .err = err },
    };

    return .{ .ok = .{
        msg_hash,
        compute_budget_instruction_details,
    } };
}

test "verify transaction" {
    const allocator = std.testing.allocator;

    const Pubkey = sig.core.Pubkey;
    const Signature = sig.core.Signature;
    const TransactionError = sig.ledger.transaction_status.TransactionError;

    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    { // Verify succeeds
        const txn = try Transaction.initRandom(allocator, random);
        defer txn.deinit(allocator);
        _ = verifyTransaction(txn).ok;
        _ = verifyTransactionWithoutSignatureVerification(txn).ok;
    }

    { // Transaction serialize fails
        const data = try allocator.alloc(u8, Transaction.MAX_BYTES);
        defer allocator.free(data);
        @memset(data, 0);

        const txn = Transaction{
            .signatures = &.{ Signature.ZEROES, Signature.ZEROES },
            .version = .legacy,
            .msg = .{
                .signature_count = 1,
                .readonly_signed_count = 0,
                .readonly_unsigned_count = 1,
                .account_keys = &.{},
                .recent_blockhash = Hash.ZEROES,
                .instructions = &.{.{
                    .program_index = 0,
                    .account_indexes = &.{},
                    .data = data,
                }},
                .address_lookups = &.{},
            },
        };

        const err = verifyTransactionWithoutSignatureVerification(txn).err;
        try std.testing.expectEqual(TransactionError.SanitizeFailure, err);
    }

    { // Transaction validate fails
        const txn = Transaction{
            .signatures = &.{ Signature.ZEROES, Signature.ZEROES },
            .version = .legacy,
            .msg = .{
                .signature_count = 1,
                .readonly_signed_count = 0,
                .readonly_unsigned_count = 1,
                .account_keys = &.{},
                .recent_blockhash = Hash.ZEROES,
                .instructions = &.{},
                .address_lookups = &.{},
            },
        };

        const err = verifyTransactionWithoutSignatureVerification(txn).err;
        try std.testing.expectEqual(TransactionError.SanitizeFailure, err);
    }

    { // Compute budget succeeds
        const txn = Transaction{
            .signatures = &.{Signature.ZEROES},
            .version = .legacy,
            .msg = .{
                .signature_count = 1,
                .readonly_signed_count = 0,
                .readonly_unsigned_count = 1,
                .account_keys = &.{ Pubkey.ZEROES, compute_budget.ID },
                .recent_blockhash = Hash.ZEROES,
                .instructions = &.{
                    try compute_budget.testCreateComputeBudgetInstruction(
                        allocator,
                        1,
                        .{ .set_compute_unit_limit = 1_000_000 },
                    ),
                },
                .address_lookups = &.{},
            },
        };
        defer for (txn.msg.instructions) |instr| allocator.free(instr.data);

        _, const details = verifyTransactionWithoutSignatureVerification(txn).ok;
        const compute_limits = compute_budget.sanitize(details, &.ALL_DISABLED, 0).ok;
        try std.testing.expectEqual(1_000_000, compute_limits.compute_unit_limit);
    }

    { // Compute budget fails with duplicate instructions
        const txn = Transaction{
            .signatures = &.{Signature.ZEROES},
            .version = .legacy,
            .msg = .{
                .signature_count = 1,
                .readonly_signed_count = 0,
                .readonly_unsigned_count = 1,
                .account_keys = &.{ Pubkey.ZEROES, compute_budget.ID },
                .recent_blockhash = Hash.ZEROES,
                .instructions = &.{
                    try compute_budget.testCreateComputeBudgetInstruction(
                        allocator,
                        1,
                        .{ .set_compute_unit_limit = 1_000_000 },
                    ),
                    try compute_budget.testCreateComputeBudgetInstruction(
                        allocator,
                        1,
                        .{ .set_compute_unit_limit = 1_000_000 },
                    ),
                },
                .address_lookups = &.{},
            },
        };
        defer for (txn.msg.instructions) |instr| allocator.free(instr.data);

        const err = verifyTransactionWithoutSignatureVerification(txn).err;
        try std.testing.expectEqual(TransactionError{ .DuplicateInstruction = 1 }, err);
    }
}
