const std = @import("std");
const sig = @import("../sig.zig");

const compute_budget = sig.runtime.program.compute_budget;

const Hash = sig.core.Hash;
const Message = sig.core.transaction.Message;
const Transaction = sig.core.transaction.Transaction;

const TransactionResult = sig.runtime.transaction_execution.TransactionResult;
const ComputeBudgetInstructionDetails = compute_budget.ComputeBudgetInstructionDetails;

pub const PreprocessTransactionResult = TransactionResult(struct {
    Hash,
    ComputeBudgetInstructionDetails,
});

pub const SigVerifyOption = enum {
    run_sig_verify,
    skip_sig_verify,
};

/// Checks that a transaction is valid for execution.
///     1. Ensure the transaction is valid i.e. signature counts make sense, there are enough accounts, etc.
///     2. Ensure the transaction message is serialisable
///     3. Ensure all signatures are verified against the serialized transaction message
///     4. Ensure that the compute budget program is executed succesfully
/// Returns the message hash and the compute budget instruction details on success.
///
/// [agave] https://github.com/firedancer-io/agave/blob/52daf1a021b716bf3ac4f20f9f301f20077f4d54/runtime/src/bank.rs#L4777
pub fn preprocessTransaction(
    txn: Transaction,
    sig_verify: SigVerifyOption,
) PreprocessTransactionResult {
    txn.validate() catch return .{ .err = .SanitizeFailure };

    const msg_bytes = txn.msg.serializeBounded(txn.version) catch return .{
        .err = .SanitizeFailure,
    };

    if (sig_verify == .run_sig_verify) {
        txn.verifySignatures(msg_bytes.constSlice()) catch |err| return switch (err) {
            error.SignatureVerificationFailed => .{ .err = .SignatureFailure },
            else => .{ .err = .SanitizeFailure },
        };
    }

    const compute_budget_instruction_details = switch (compute_budget.execute(&txn.msg)) {
        .ok => |details| details,
        .err => |err| return .{ .err = err },
    };

    return .{ .ok = .{
        Message.hash(msg_bytes.constSlice()),
        compute_budget_instruction_details,
    } };
}

test preprocessTransaction {
    const allocator = std.testing.allocator;

    const Pubkey = sig.core.Pubkey;
    const Signature = sig.core.Signature;
    const TransactionError = sig.ledger.transaction_status.TransactionError;

    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    { // Verify succeeds
        const txn = try Transaction.initRandom(allocator, random);
        defer txn.deinit(allocator);
        _ = preprocessTransaction(txn, .run_sig_verify).ok;
        _ = preprocessTransaction(txn, .skip_sig_verify).ok;
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

        const err = preprocessTransaction(txn, .skip_sig_verify).err;
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

        const err = preprocessTransaction(txn, .skip_sig_verify).err;
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

        _, const details = preprocessTransaction(txn, .skip_sig_verify).ok;
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

        const err = preprocessTransaction(txn, .skip_sig_verify).err;
        try std.testing.expectEqual(TransactionError{ .DuplicateInstruction = 1 }, err);
    }
}
