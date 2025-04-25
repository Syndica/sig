const std = @import("std");
const builtin = @import("builtin");
const sig = @import("../sig.zig");

const account_loader = sig.runtime.account_loader;
const AccountLoader = account_loader.AccountLoader;
const TransactionError = sig.ledger.transaction_status.TransactionError;
const Pubkey = sig.core.Pubkey;
const AccountSharedData = sig.runtime.AccountSharedData;

const ProcessingEnv = struct {
    blockhash: sig.core.Hash,
    blockhash_lamports_per_signature: u64,
    epoch_total_stake: u64,
    rent_collector: *const sig.runtime.rent_collector.RentCollector,
    slot_context: *const sig.runtime.SlotContext,

    fn testingDefault() ProcessingEnv {
        const epoch_context: sig.runtime.EpochContext = .{
            .allocator = std.testing.failing_allocator,
            .feature_set = sig.runtime.FeatureSet.EMPTY,
        };

        return .{
            .blockhash = sig.core.Hash.ZEROES,
            .blockhash_lamports_per_signature = 0,
            .epoch_total_stake = 1,
            .rent_collector = &sig.runtime.rent_collector.defaultCollector(0),
            .slot_context = &.{
                .allocator = std.testing.failing_allocator,
                .sysvar_cache = .{},
                .ec = &epoch_context,
            },
        };
    }
};

// const TransactionCheck = union(enum) {
//     Err: TransactionError,
//     Ok: CheckedTransactionDetails,
// };
// const NonceInfo = struct {
//     address: Pubkey,
//     account: AccountSharedData,
// };
// const CheckedTransactionDetails = struct {
//     nonce: ?NonceInfo,
//     compute_budget_and_limits:
// };

const TransactionResult = struct {
    /// log[instr_idx] -> string
    /// null => failed to load accounts | failed to allocate logs
    logs: ?[]const []const u8,
    err: ?anyerror, // TODO: use transaction error set
};

const Output = struct {
    // .len == raw_instructions.len
    processing_results: []const TransactionResult,
};

// simplified ~= agave's load_and_execute_sanitized_transactions
pub fn loadAndExecuteBatch(
    gpa_allocator: std.mem.Allocator,
    env: *const ProcessingEnv,
    bank: sig.runtime.account_loader.MockedBank,
    raw_transactions: []const sig.core.Transaction, // TODO: assuming sanitized already (!)
) !Output {
    var batch_arena = std.heap.ArenaAllocator.init(gpa_allocator);
    defer batch_arena.deinit();

    const allocator = batch_arena.allocator();

    // largest-case capacity estimate
    var loader = try AccountLoader(.Mocked).newWithCacheCapacity(
        allocator,
        bank,
        &env.slot_context.ec.feature_set,
        account_keys_sum: {
            var sum: usize = 0;
            for (raw_transactions) |tx| sum += tx.msg.account_keys.len;
            break :account_keys_sum sum;
        },
    );

    // incorrect - transaction details should contain this as a field
    const requested_max_total_data_size = 100 * 1024 * 1024;

    const transaction_result = try gpa_allocator.alloc(TransactionResult, raw_transactions.len);
    errdefer gpa_allocator.free(transaction_result);

    // transactions must be executed in order
    for (raw_transactions, 0..) |tx, tx_idx| {
        // now would be a great time to *validate_transaction_nonce_and_fee_payer*
        // not doing it yet. Pretending it's valid for now.

        // TODO: this loop needs a bunch more error handling

        transaction_result[tx_idx].logs = null;
        const loaded_accounts = account_loader.loadTransactionAccounts(
            allocator,
            &tx,
            requested_max_total_data_size,
            &loader,
            &env.slot_context.ec.feature_set,
            env.rent_collector,
        ) catch |err| { // TODO: actual error handling
            transaction_result[tx_idx].err = err;
            continue;
        };

        const accounts = loaded_accounts.accounts_buf[0..tx.msg.account_keys.len];

        var ctx = try makeTransactionContext(allocator, env, accounts, &tx);

        defer transaction_result[tx_idx].logs = blk: {
            if (ctx.log_collector) |logger| {
                break :blk logger.collectCloned(gpa_allocator) catch null;
            }
            break :blk null;
        };

        executeLoadedTransaction(
            allocator,
            env,
            &ctx,
            accounts,
            &tx,
        ) catch |err| {
            transaction_result[tx_idx].err = err;
            continue;
        };

        transaction_result[tx_idx].err = null;
    }

    return .{
        .processing_results = transaction_result,
    };
}

fn makeTransactionContext(
    allocator: std.mem.Allocator,
    env: *const ProcessingEnv,
    accounts: []const AccountSharedData,
    raw_transaction: *const sig.core.Transaction,
) !sig.runtime.TransactionContext {
    const context_accounts = try allocator.alloc(sig.runtime.TransactionContextAccount, accounts.len);
    errdefer allocator.free(context_accounts);

    for (accounts, raw_transaction.msg.account_keys, 0..) |account, key, account_idx| {
        context_accounts[account_idx] = sig.runtime.TransactionContextAccount.init(key, account);
    }

    // bit of a nasty init here
    return .{
        .allocator = allocator,
        .ec = env.slot_context.ec,
        .sc = env.slot_context,
        .instruction_stack = .{ .len = 0 },
        .instruction_trace = .{ .len = 0 },
        .accounts = context_accounts,
        .return_data = .{},
        .accounts_resize_delta = 0,
        .compute_meter = 0,
        .custom_error = null,
        .log_collector = sig.runtime.LogCollector.init(null), // TODO: should probably limit this
        .prev_blockhash = env.blockhash,

        .prev_lamports_per_signature = env.blockhash_lamports_per_signature,
        // I'll find where to get this later
        .compute_budget = undefined,
        .serialized_accounts = undefined, // serialized means?
    };
}

// ~= agave's process_message
fn executeLoadedTransaction(
    allocator: std.mem.Allocator,
    env: *const ProcessingEnv,
    ctx: *sig.runtime.TransactionContext,
    accounts: []const AccountSharedData,
    raw_transaction: *const sig.core.Transaction,
) !void {
    _ = env;
    errdefer {
        ctx.log("trace: {?}\n", .{@errorReturnTrace()}) catch {};
    }

    const lamports_before_tx = blk: {
        var sum: u128 = 128; // no idea why we start =128
        for (accounts) |account| sum += account.lamports;
        break :blk sum;
    };

    for (raw_transaction.msg.instructions) |instruction| {
        var account_metas = std.BoundedArray(sig.runtime.InstructionInfo.AccountMeta, 256){};
        for (raw_transaction.msg.account_keys, 0..) |key, tx_acc_idx| {
            const index_in_callee: u16 = blk: {
                if (instruction.account_indexes.len < tx_acc_idx)
                    return error.InvalidAccountIndex;
                for (instruction.account_indexes[0..tx_acc_idx], 0..) |instr_acc_idx, i| {
                    if (instr_acc_idx == tx_acc_idx) break :blk @intCast(i);
                }
                break :blk @intCast(tx_acc_idx);
            };

            account_metas.appendAssumeCapacity(.{
                .pubkey = key,
                .index_in_transaction = @intCast(tx_acc_idx),
                .index_in_caller = @intCast(tx_acc_idx),
                .index_in_callee = index_in_callee,
                .is_signer = raw_transaction.msg.isSigner(tx_acc_idx),
                .is_writable = raw_transaction.msg.isWritable(tx_acc_idx),
            });
        }

        // hopefully matches dyn InvokeContextCallback::is_precompile...
        const is_precompile_program =
            for (sig.runtime.program.precompile_programs.PRECOMPILES) |precompile|
        {
            if (precompile.program_id.equals(&raw_transaction.msg.account_keys[instruction.program_index]))
                break true;
        } else false;

        if (is_precompile_program) {
            // TODO
        } else {
            // ~= process_instruction
            try sig.runtime.executor.executeInstruction(allocator, ctx, .{
                .initial_account_lamports = lamports_before_tx, // TODO: double check this
                .account_metas = account_metas,
                .instruction_data = instruction.data,
                .program_meta = .{
                    .index_in_transaction = instruction.program_index,
                    .pubkey = raw_transaction.msg.account_keys[instruction.program_index],
                },
            });
        }
    }
}

test {
    std.testing.refAllDecls(@This());

    const allocator = std.testing.allocator;
    const env = ProcessingEnv.testingDefault();

    var bank = sig.runtime.account_loader.MockedBank{
        .allocator = allocator,
        .rent_collector = env.rent_collector.*,
        .slot = 1,
    };
    defer bank.accounts.deinit(allocator);
    try bank.accounts.put(allocator, sig.runtime.ids.PRECOMPILE_ED25519_PROGRAM_ID, .{
        .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        .executable = true,
        .data = .{ .empty = .{ .len = 0 } },
        .lamports = 1,
        .rent_epoch = sig.runtime.rent_collector.RENT_EXEMPT_RENT_EPOCH,
    });

    // empty
    const tx1 = sig.core.Transaction.EMPTY;

    // zero instructions
    const tx2: sig.core.Transaction = .{
        .signatures = &.{},
        .version = .legacy,
        .msg = .{
            .signature_count = 0,
            .readonly_signed_count = 0,
            .readonly_unsigned_count = 0,
            .account_keys = &.{sig.runtime.ids.SYSVAR_INSTRUCTIONS_ID},
            .recent_blockhash = .{ .data = [_]u8{0x00} ** sig.core.Hash.SIZE },
            .instructions = &.{},
            .address_lookups = &.{},
        },
    };
    const Ed25519 = std.crypto.sign.Ed25519;

    const keypair = try Ed25519.KeyPair.create(null);
    const ed25519_instruction = try sig.runtime.program.precompile_programs.ed25519.newInstruction(
        std.testing.allocator,
        keypair,
        "hello!",
    );
    defer std.testing.allocator.free(ed25519_instruction.data);

    // a precompile instruction (slightly different codepath)
    const tx3: sig.core.Transaction = .{
        .msg = .{
            .account_keys = &.{sig.runtime.ids.PRECOMPILE_ED25519_PROGRAM_ID},
            .instructions = &.{
                .{ .program_index = 0, .account_indexes = &.{0}, .data = ed25519_instruction.data },
            },
            .signature_count = 1,
            .readonly_signed_count = 1,
            .readonly_unsigned_count = 0,
            .recent_blockhash = sig.core.Hash.ZEROES,
        },
        .version = .legacy,
        .signatures = &.{},
    };

    // program not found
    const tx4 = sig.core.Transaction{
        .msg = .{
            .account_keys = &.{Pubkey.ZEROES},
            .instructions = &.{
                .{ .program_index = 0, .account_indexes = &.{0}, .data = "" },
            },
            .signature_count = 1,
            .readonly_signed_count = 1,
            .readonly_unsigned_count = 0,
            .recent_blockhash = sig.core.Hash.ZEROES,
        },
        .version = .legacy,
        .signatures = &.{},
    };

    const result = try loadAndExecuteBatch(allocator, &env, bank, &.{ tx1, tx2, tx3, tx4 });
    defer allocator.free(result.processing_results);

    for (result.processing_results, 0..) |res, i| {
        std.debug.print("tx{} - err?: {?}\n", .{ i, res.err });
        if (res.logs) |logs| {
            for (logs) |log| std.debug.print("\t{s}\n", .{log});
        }
    }
}
