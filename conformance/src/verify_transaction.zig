const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const sig = @import("sig");
const std = @import("std");

const sysvar = sig.runtime.sysvar;
const features = sig.core.features;

const Hash = sig.core.Hash;
const Signature = sig.core.Signature;
const Transaction = sig.core.Transaction;
const AccountSharedData = sig.runtime.AccountSharedData;

const Ancestors = sig.core.status_cache.Ancestors;
const Pubkey = sig.core.Pubkey;
const InstructionError = sig.core.instruction.InstructionError;
const TransactionContext = sig.runtime.transaction_context.TransactionContext;
const TransactionVersion = sig.core.transaction.Version;
const TransactionMessage = sig.core.transaction.Message;
const TransactionInstruction = sig.core.transaction.Instruction;
const TransactionAddressLookup = sig.core.transaction.AddressLookup;
const FeeRateGovernor = sig.core.FeeRateGovernor;
const GenesisConfig = sig.core.GenesisConfig;
const Inflation = sig.core.Inflation;
const PohConfig = sig.core.PohConfig;
const SysvarCache = sig.runtime.SysvarCache;
const RuntimeTransaction = sig.runtime.transaction_execution.RuntimeTransaction;
const TransactionExecutionEnvironment = sig.runtime.transaction_execution.TransactionExecutionEnvironment;
const TransactionExecutionConfig = sig.runtime.transaction_execution.TransactionExecutionConfig;
const BatchAccountCache = sig.runtime.account_loader.BatchAccountCache;
const loadAndExecuteTransaction = sig.runtime.transaction_execution.loadAndExecuteTransaction;

const EMIT_LOGS = false;

const VerifyTransactionResult = union(enum(u8)) {
    ok: RuntimeTransaction,
    err: pb.TxnResult,
};

const FeatureSet = sig.core.features.FeatureSet;
const AccountsDb = sig.accounts_db.AccountsDB;
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
            const instr_err, const instr_idx, const custom_err = switch (verify_error) {
                .InstructionError => |err| blk: {
                    const instr_err = sig.core.instruction.intFromInstructionErrorEnum(err[1]);
                    const custom_err = switch (err[1]) {
                        .Custom => |e| e,
                        else => 0,
                    };
                    break :blk .{ instr_err, err[0], custom_err };
                },
                else => .{ 0, 0, 0 },
            };
            return .{ .err = .{
                .sanitization_error = true,
                .status = transactionErrorToInt(verify_error),
                .instruction_error = instr_err,
                .instruction_error_index = instr_idx,
                .custom_error = custom_err,
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
        .version = transaction.version,
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
    return switch (err) {
        .AccountInUse => 1,
        .AccountLoadedTwice => 2,
        .AccountNotFound => 3,
        .ProgramAccountNotFound => 4,
        .InsufficientFundsForFee => 5,
        .InvalidAccountForFee => 6,
        .AlreadyProcessed => 7,
        .BlockhashNotFound => 8,
        .InstructionError => |_| 9,
        .CallChainTooDeep => 10,
        .MissingSignatureForFee => 11,
        .InvalidAccountIndex => 12,
        .SignatureFailure => 13,
        .InvalidProgramForExecution => 14,
        .SanitizeFailure => 15,
        .ClusterMaintenance => 16,
        .AccountBorrowOutstanding => 17,
        .WouldExceedMaxBlockCostLimit => 18,
        .UnsupportedVersion => 19,
        .InvalidWritableAccount => 20,
        .WouldExceedMaxAccountCostLimit => 21,
        .WouldExceedAccountDataBlockLimit => 22,
        .TooManyAccountLocks => 23,
        .AddressLookupTableNotFound => 24,
        .InvalidAddressLookupTableOwner => 25,
        .InvalidAddressLookupTableData => 26,
        .InvalidAddressLookupTableIndex => 27,
        .InvalidRentPayingAccount => 28,
        .WouldExceedMaxVoteCostLimit => 29,
        .WouldExceedAccountDataTotalLimit => 30,
        .DuplicateInstruction => |_| 31,
        .InsufficientFundsForRent => |_| 32,
        .MaxLoadedAccountsDataSizeExceeded => 33,
        .InvalidLoadedAccountsDataSizeLimit => 34,
        .ResanitizationNeeded => 35,
        .ProgramExecutionTemporarilyRestricted => |_| 36,
        .UnbalancedTransaction => 37,
        .ProgramCacheHitMaxLimit => 38,
    };
}
