const std = @import("std");
const sig = @import("../sig.zig");
const tracy = @import("tracy");

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

const MAX_ACCOUNTS_PER_INSTRUCTION = sig.runtime.transaction_context.MAX_ACCOUNTS_PER_INSTRUCTION;

/// Checks that a transaction is valid for execution.
///     1. Ensure the transaction is valid i.e. signature counts make sense, there are enough accounts, etc.
///     2. Ensure the transaction message is serialisable
///     3. Ensure all signatures are verified against the serialized transaction message
///     4. Ensure that the compute budget program is executed succesfully
/// Returns the message hash and the compute budget instruction details on success.
///
/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.4/runtime/src/bank.rs#L4694
pub fn preprocessTransaction(
    txn: Transaction,
    sig_verify: SigVerifyOption,
    static_instruction_limit: bool,
    instruction_accounts_limit: bool,
    require_static_nonce_account: bool,
) PreprocessTransactionResult {
    var zone = tracy.Zone.init(@src(), .{ .name = "preprocessTransaction" });
    defer zone.deinit();

    txn.validate() catch return .{ .err = .SanitizeFailure };

    const msg_bytes = txn.msg.serializeBounded(txn.version) catch return .{
        .err = .SanitizeFailure,
    };

    // Check that the full serialized transaction (signatures + message) fits in a packet.
    // [agave] https://github.com/anza-xyz/agave/blob/v4.0.0-beta.6/runtime/src/bank.rs#L5041-5044
    {
        const sig_count: u16 = @intCast(txn.signatures.len);
        const sig_count_size: usize = if (sig_count < 0x80) 1 else if (sig_count < 0x4000) 2 else 3;
        const sigs_size = txn.signatures.len * @sizeOf(sig.core.Signature);
        const total_size = sig_count_size + sigs_size + msg_bytes.len;
        if (total_size > Transaction.MAX_BYTES) return .{ .err = .SanitizeFailure };
    }

    // SIMD-0406: Reject transactions with instructions that reference more than 255 accounts.
    // Runs before sig verification, matching Agave's sanitize_instructions ordering.
    // [agave] https://github.com/anza-xyz/agave/blob/v4.0.0-rc.0/transaction-view/src/sanitize.rs#L98-L102
    if (instruction_accounts_limit) {
        for (txn.msg.instructions) |instr| {
            if (instr.account_indexes.len > MAX_ACCOUNTS_PER_INSTRUCTION) {
                return .{ .err = .SanitizeFailure };
            }
        }
    }

    // SIMD-0242: a nonce transaction (one whose first instruction is
    // SystemInstruction::AdvanceNonceAccount) must reference its nonce account
    // statically. The nonce account index, which is the first account index of
    // that instruction, must be < the number of static account keys.
    if (require_static_nonce_account and isAdvanceNonceTransaction(&txn.msg)) {
        const inst = txn.msg.instructions[0];
        if (inst.account_indexes.len == 0 or
            inst.account_indexes[0] >= txn.msg.account_keys.len)
        {
            return .{ .err = .SanitizeFailure };
        }
    }

    if (sig_verify == .run_sig_verify) {
        if (static_instruction_limit and
            txn.msg.instructions.len > sig.runtime.transaction_context.MAX_INSTRUCTION_TRACE_LENGTH)
        {
            return .{ .err = .SanitizeFailure };
        }

        txn.verifySignatures(msg_bytes.constSlice()) catch |err| {
            return switch (err) {
                error.SignatureVerificationFailed => .{ .err = .SignatureFailure },
                else => .{ .err = .SanitizeFailure },
            };
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

/// Returns true if the message's first instruction is
/// `SystemInstruction::AdvanceNonceAccount`, the marker for a nonce transaction.
/// Mirrors the equivalent check on resolved transactions in `getDurableNonce`.
pub fn isAdvanceNonceTransaction(msg: *const Message) bool {
    if (msg.instructions.len == 0) return false;
    const inst = msg.instructions[0];
    if (inst.program_index >= msg.account_keys.len) return false;
    if (!msg.account_keys[inst.program_index].equals(&sig.runtime.program.system.ID)) return false;
    if (inst.data.len < 4) return false;
    return std.mem.eql(u8, inst.data[0..4], &.{ 4, 0, 0, 0 });
}

test preprocessTransaction {
    const allocator = std.testing.allocator;

    const Pubkey = sig.core.Pubkey;
    const Signature = sig.core.Signature;
    const TransactionError = sig.ledger.transaction_status.TransactionError;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    { // Verify succeeds
        const txn = try Transaction.initRandom(allocator, random, null);
        defer txn.deinit(allocator);

        try std.testing.expectEqual(
            .ok,
            std.meta.activeTag(preprocessTransaction(txn, .run_sig_verify, false, false, false)),
        );
        try std.testing.expectEqual(
            .ok,
            std.meta.activeTag(preprocessTransaction(txn, .skip_sig_verify, false, false, false)),
        );
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

        const err = preprocessTransaction(txn, .skip_sig_verify, false, false, false).err;
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

        const err = preprocessTransaction(txn, .skip_sig_verify, false, false, false).err;
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

        _, const details = preprocessTransaction(txn, .skip_sig_verify, false, false, false).ok;
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

        const err = preprocessTransaction(txn, .skip_sig_verify, false, false, false).err;
        try std.testing.expectEqual(TransactionError{ .DuplicateInstruction = 1 }, err);
    }

    { // SIMD-160, message with more instructions than the limit.

        const inst = try compute_budget.testCreateComputeBudgetInstruction(
            allocator,
            1,
            .{ .set_compute_unit_limit = 1_000_000 },
        );
        defer allocator.free(inst.data);

        const instructions: [100]sig.core.transaction.Instruction = @splat(inst);

        const txn = Transaction{
            .signatures = &.{Signature.ZEROES},
            .version = .legacy,
            .msg = .{
                .signature_count = 1,
                .readonly_signed_count = 0,
                .readonly_unsigned_count = 1,
                .account_keys = &.{ Pubkey.ZEROES, compute_budget.ID },
                .recent_blockhash = Hash.ZEROES,
                .instructions = &instructions,
                .address_lookups = &.{},
            },
        };

        const err = preprocessTransaction(txn, .run_sig_verify, true, false, false).err;
        try std.testing.expectEqual(.SanitizeFailure, err);
    }

    { // SIMD-0406, instruction with more than 255 accounts should fail when limit is enabled.
        var account_indexes: [256]u8 = undefined;
        @memset(&account_indexes, 0);

        // Use a non-compute-budget program, matching Agave's test which uses Pubkey::new_unique().
        // https://github.com/anza-xyz/agave/blob/v4.0.0-rc.0/runtime-transaction/src/runtime_transaction/sdk_transactions.rs#L396-L452
        const dummy_program = Pubkey{ .data = .{1} ** 32 };
        const txn = Transaction{
            .signatures = &.{Signature.ZEROES},
            .version = .legacy,
            .msg = .{
                .signature_count = 1,
                .readonly_signed_count = 0,
                .readonly_unsigned_count = 1,
                .account_keys = &.{ Pubkey.ZEROES, dummy_program },
                .recent_blockhash = Hash.ZEROES,
                .instructions = &.{.{
                    .program_index = 1,
                    .account_indexes = &account_indexes,
                    .data = &.{},
                }},
                .address_lookups = &.{},
            },
        };

        // Skip sig verify — Agave's equivalent test (try_create) only runs sanitization.
        // With limit enabled, 256 accounts should fail.
        const err = preprocessTransaction(txn, .skip_sig_verify, false, true, false).err;
        try std.testing.expectEqual(.SanitizeFailure, err);

        // With limit disabled, 256 accounts should pass sanitization.
        try std.testing.expectEqual(
            .ok,
            std.meta.activeTag(
                preprocessTransaction(txn, .skip_sig_verify, false, false, false),
            ),
        );
    }

    { // SIMD-0406, instruction with exactly 255 accounts should pass.
        var account_indexes: [255]u8 = undefined;
        @memset(&account_indexes, 0);

        const dummy_program = Pubkey{ .data = .{1} ** 32 };
        const txn = Transaction{
            .signatures = &.{Signature.ZEROES},
            .version = .legacy,
            .msg = .{
                .signature_count = 1,
                .readonly_signed_count = 0,
                .readonly_unsigned_count = 1,
                .account_keys = &.{ Pubkey.ZEROES, dummy_program },
                .recent_blockhash = Hash.ZEROES,
                .instructions = &.{.{
                    .program_index = 1,
                    .account_indexes = &account_indexes,
                    .data = &.{},
                }},
                .address_lookups = &.{},
            },
        };

        // With limit enabled, exactly 255 accounts should pass.
        try std.testing.expectEqual(
            .ok,
            std.meta.activeTag(preprocessTransaction(txn, .skip_sig_verify, false, true, false)),
        );
    }

    { // SIMD-0242: nonce transaction with statically-included nonce account is accepted
        // when the gate is on (account_indexes[0] < account_keys.len).
        const advance_nonce_data = [_]u8{ 4, 0, 0, 0 };
        const account_indexes = [_]u8{ 2, 0, 0 }; // nonce, recent_blockhashes (mock), authority
        const txn = Transaction{
            .signatures = &.{Signature.ZEROES},
            .version = .legacy,
            .msg = .{
                .signature_count = 1,
                .readonly_signed_count = 0,
                .readonly_unsigned_count = 1,
                .account_keys = &.{
                    Pubkey.ZEROES,
                    sig.runtime.program.system.ID,
                    Pubkey.initRandom(random),
                },
                .recent_blockhash = Hash.ZEROES,
                .instructions = &.{.{
                    .program_index = 1,
                    .account_indexes = &account_indexes,
                    .data = &advance_nonce_data,
                }},
                .address_lookups = &.{},
            },
        };

        try std.testing.expectEqual(
            .ok,
            std.meta.activeTag(preprocessTransaction(txn, .skip_sig_verify, false, true, false)),
        );
    }

    { // SIMD-0242: nonce transaction with ALT-resolved nonce account is rejected when
        // the gate is on, and accepted when off (account_indexes[0] >= account_keys.len).
        const advance_nonce_data = [_]u8{ 4, 0, 0, 0 };
        // Two static account keys + one writable ALT slot → max_account_index = 2.
        // account_indexes[0] = 2 references the ALT-resolved account (not static).
        const account_indexes = [_]u8{ 2, 0, 0 };
        const writable_indexes = [_]u8{0};
        const txn = Transaction{
            .signatures = &.{Signature.ZEROES},
            .version = .v0,
            .msg = .{
                .signature_count = 1,
                .readonly_signed_count = 0,
                .readonly_unsigned_count = 1,
                .account_keys = &.{ Pubkey.ZEROES, sig.runtime.program.system.ID },
                .recent_blockhash = Hash.ZEROES,
                .instructions = &.{.{
                    .program_index = 1,
                    .account_indexes = &account_indexes,
                    .data = &advance_nonce_data,
                }},
                .address_lookups = &.{.{
                    .table_address = Pubkey.initRandom(random),
                    .writable_indexes = &writable_indexes,
                    .readonly_indexes = &.{},
                }},
            },
        };

        // Gate on: rejected.
        try std.testing.expectEqual(
            TransactionError.SanitizeFailure,
            preprocessTransaction(txn, .skip_sig_verify, false, false, true).err,
        );
        // Gate off: accepted.
        try std.testing.expectEqual(
            .ok,
            std.meta.activeTag(preprocessTransaction(txn, .skip_sig_verify, false, false, false)),
        );
    }

    { // SIMD-0242: non-nonce transaction is unaffected by the gate (data prefix is
        // not [4,0,0,0], so isAdvanceNonceTransaction returns false even if other
        // markers match).
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

        try std.testing.expectEqual(
            .ok,
            std.meta.activeTag(preprocessTransaction(txn, .skip_sig_verify, false, true, false)),
        );
    }

    { // SIMD-0242: a nonce-shaped tx with empty account_indexes is rejected (the
        // guard prevents an out-of-bounds read; the tx is invalid anyway because
        // AdvanceNonceAccount needs accounts).
        const advance_nonce_data = [_]u8{ 4, 0, 0, 0 };
        const txn = Transaction{
            .signatures = &.{Signature.ZEROES},
            .version = .legacy,
            .msg = .{
                .signature_count = 1,
                .readonly_signed_count = 0,
                .readonly_unsigned_count = 1,
                .account_keys = &.{ Pubkey.ZEROES, sig.runtime.program.system.ID },
                .recent_blockhash = Hash.ZEROES,
                .instructions = &.{.{
                    .program_index = 1,
                    .account_indexes = &.{},
                    .data = &advance_nonce_data,
                }},
                .address_lookups = &.{},
            },
        };

        try std.testing.expectEqual(
            TransactionError.SanitizeFailure,
            preprocessTransaction(txn, .skip_sig_verify, false, false, true).err,
        );
    }
}

test isAdvanceNonceTransaction {
    const Pubkey = sig.core.Pubkey;
    const Instruction = sig.core.transaction.Instruction;

    const system_id = sig.runtime.program.system.ID;
    const advance_nonce_data = [_]u8{ 4, 0, 0, 0 };

    // Helper to construct a Message with one instruction, parameterized.
    const buildMsg = struct {
        fn f(
            account_keys: []const Pubkey,
            instructions: []const Instruction,
        ) Message {
            return .{
                .signature_count = 1,
                .readonly_signed_count = 0,
                .readonly_unsigned_count = 1,
                .account_keys = account_keys,
                .recent_blockhash = Hash.ZEROES,
                .instructions = instructions,
                .address_lookups = &.{},
            };
        }
    }.f;

    { // empty instructions: false
        const msg = buildMsg(&.{ Pubkey.ZEROES, system_id }, &.{});
        try std.testing.expect(!isAdvanceNonceTransaction(&msg));
    }

    { // program_index out of bounds: false
        const inst: Instruction = .{
            .program_index = 9,
            .account_indexes = &.{0},
            .data = &advance_nonce_data,
        };
        const msg = buildMsg(&.{ Pubkey.ZEROES, system_id }, &.{inst});
        try std.testing.expect(!isAdvanceNonceTransaction(&msg));
    }

    { // program is not system: false (system is Pubkey.ZEROES, so use a non-zero pubkey)
        var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
        const non_system = Pubkey.initRandom(prng.random());
        const inst: Instruction = .{
            .program_index = 1,
            .account_indexes = &.{0},
            .data = &advance_nonce_data,
        };
        const msg = buildMsg(&.{ Pubkey.ZEROES, non_system }, &.{inst});
        try std.testing.expect(!isAdvanceNonceTransaction(&msg));
    }

    { // data length < 4: false
        const short_data = [_]u8{ 4, 0, 0 };
        const inst: Instruction = .{
            .program_index = 1,
            .account_indexes = &.{0},
            .data = &short_data,
        };
        const msg = buildMsg(&.{ Pubkey.ZEROES, system_id }, &.{inst});
        try std.testing.expect(!isAdvanceNonceTransaction(&msg));
    }

    { // wrong tag (a different SystemInstruction discriminant): false
        const transfer_data = [_]u8{ 2, 0, 0, 0 }; // SystemInstruction::Transfer
        const inst: Instruction = .{
            .program_index = 1,
            .account_indexes = &.{0},
            .data = &transfer_data,
        };
        const msg = buildMsg(&.{ Pubkey.ZEROES, system_id }, &.{inst});
        try std.testing.expect(!isAdvanceNonceTransaction(&msg));
    }

    { // happy path: true
        const inst: Instruction = .{
            .program_index = 1,
            .account_indexes = &.{ 0, 1 },
            .data = &advance_nonce_data,
        };
        const msg = buildMsg(&.{ Pubkey.ZEROES, system_id }, &.{inst});
        try std.testing.expect(isAdvanceNonceTransaction(&msg));
    }

    { // happy path with extra bytes after the discriminant: still true
        const data_with_extra = [_]u8{ 4, 0, 0, 0, 0xFF, 0xFF };
        const inst: Instruction = .{
            .program_index = 1,
            .account_indexes = &.{0},
            .data = &data_with_extra,
        };
        const msg = buildMsg(&.{ Pubkey.ZEROES, system_id }, &.{inst});
        try std.testing.expect(isAdvanceNonceTransaction(&msg));
    }
}
