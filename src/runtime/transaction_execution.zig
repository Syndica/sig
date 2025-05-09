const std = @import("std");
const builtin = @import("builtin");
const sig = @import("../sig.zig");

const account_loader = sig.runtime.account_loader;
const compute_budget = sig.runtime.program.compute_budget;

const AccountLoader = account_loader.AccountLoader;
const AccountSharedData = sig.runtime.AccountSharedData;
const LoadedAccounts = account_loader.LoadedAccounts;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;

/// Various constants needed for the block and slot, a reference into accountsdb, and a slice of
/// transactions.
/// Can be reused for any transaction in a slot.
const ProcessingEnv = struct {
    // replace with reference to blockhash queue?
    prev_blockhash: sig.core.Hash,
    prev_blockhash_lamports_per_signature: u64,

    rent_collector: sig.core.rent_collector.RentCollector,
    slot_context: sig.runtime.SlotContext,
    slot: Slot,

    // epoch_total_stake: ignored - don't see usage

    fn testingDefault() ProcessingEnv {
        if (!builtin.is_test) @compileError("testingDefault for testing only");

        const epoch_context: sig.runtime.EpochContext = .{
            .allocator = std.testing.failing_allocator,
            .feature_set = sig.runtime.FeatureSet.EMPTY,
        };

        return .{
            .prev_blockhash = sig.core.Hash.ZEROES,
            .prev_blockhash_lamports_per_signature = 0,
            .slot = 1,
            .rent_collector = sig.core.rent_collector.defaultCollector(0),
            .slot_context = .{
                .allocator = std.testing.failing_allocator,
                .sysvar_cache = .{},
                .ec = &epoch_context,
            },
        };
    }
};

pub const Kind = enum { FeesOnly, Executed };

pub const TransactionResult = union(Kind) {
    FeesOnly: FeesOnlyTransaction,
    Executed: ExecutedTransaction,

    fn err(self: TransactionResult) ?anyerror {
        return switch (self) {
            .FeesOnly => |fees_only| fees_only.err,
            .Executed => |executed| executed.err,
        };
    }

    fn logs(self: TransactionResult) ?[]const []const u8 {
        return switch (self) {
            .FeesOnly => null,
            .Executed => |executed| if (executed.logs.len > 0) executed.logs else null,
        };
    }
};

// Transaction was not executed. Fees can be collected.
pub const FeesOnlyTransaction = struct {
    err: anyerror, // TODO: narrow this to accountsdb load error
    // rollback_accounts: ignored for now, still unclear on what exactly it's for
    // fee_details: ignored - this is passed in
};

/// Transaction was executed, may have failed. Fees can be collected.
pub const ExecutedTransaction = struct {
    executed_units: u64 = 0,
    /// only valid in successful transactions
    accounts_data_len_delta: i64 = 0,
    return_data: ?sig.runtime.transaction_context.TransactionReturnData = null,
    err: ?anyerror = null, // TODO: narrow to transaction error
    logs: []const []const u8 = &.{},

    programs_modified_by_tx: void = {}, // TODO: program cache not yet implemented (!)
    // rollback_accounts: ignored for now, still unclear on what exactly it's for
    // fee_details: ignored - this is passed in
    // compute_budget: ignored - this is passed in
    // program_indicies: seems useless, skipping

    fn deinit(self: ExecutedTransaction, allocator: std.mem.Allocator) void {
        if (self.logs.len > 0) {
            for (self.logs) |log_entry| allocator.free(log_entry);
            allocator.free(self.logs);
        }
    }
};

pub const Output = struct {
    // .len == raw_instructions.len
    processing_result: []const TransactionResult,

    pub fn deinit(self: *Output, allocator: std.mem.Allocator) void {
        var iter = self.loader_cache.iterator();
        while (iter.next()) |entry| allocator.free(entry.value_ptr.data);
        self.loader_cache.deinit(allocator);

        for (self.processing_result) |result| {
            const logs = result.logs() orelse continue;
            for (logs) |log| allocator.free(log);
            allocator.free(logs);
        }
        allocator.free(self.processing_result);

        for (self.instruction_account_datas) |data| {
            allocator.free(data);
        }
        allocator.free(self.instruction_account_datas);
    }
};

// simplified ~= agave's load_and_execute_sanitized_transactions
pub fn executeTransaction(
    allocator: std.mem.Allocator,
    tx: *const sig.core.Transaction,
    /// reusable for a whole slot
    env: ProcessingEnv,
    budget_limits: compute_budget.ComputeBudgetLimits,
    loaded_accounts: *const LoadedAccounts,
) error{OutOfMemory}!ExecutedTransaction {
    std.debug.assert(loaded_accounts.load_failure == null); // don't execute an improperly loaded tx
    const accounts = loaded_accounts.accounts.constSlice();

    var tc = try makeTransactionContext(
        allocator,
        &env,
        accounts,
        tx,
        budget_limits.intoComputeBudget(),
    );
    defer tc.deinit();

    executeLoadedTransaction(allocator, &tc, accounts, tx) catch |err| {
        switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {},
        }

        return .{
            .err = err,
            .logs = blk: {
                if (tc.log_collector) |logger| {
                    break :blk logger.collectCloned(allocator) catch &.{};
                }
                break :blk &.{};
            },
        };
    };

    return .{
        .executed_units = tc.compute_meter,
        .accounts_data_len_delta = tc.accounts_resize_delta,
        .return_data = tc.return_data,
        .logs = blk: {
            if (tc.log_collector) |logger| {
                break :blk logger.collectCloned(allocator) catch &.{};
            }
            break :blk &.{};
        },
    };
}

fn makeTransactionContext(
    allocator: std.mem.Allocator,
    env: *const ProcessingEnv,
    accounts: []const AccountSharedData,
    raw_transaction: *const sig.core.Transaction,
    tx_compute_budget: sig.runtime.ComputeBudget,
) error{OutOfMemory}!sig.runtime.TransactionContext {
    const context_accounts = try allocator.alloc(
        sig.runtime.TransactionContextAccount,
        accounts.len,
    );
    errdefer allocator.free(context_accounts);

    for (accounts, raw_transaction.msg.account_keys, 0..) |account, key, account_idx| {
        context_accounts[account_idx] = sig.runtime.TransactionContextAccount.init(key, account);
    }

    // bit of a nasty init here
    return .{
        .allocator = allocator,
        .ec = env.slot_context.ec,
        .sc = &env.slot_context,
        .instruction_stack = .{ .len = 0 },
        .instruction_trace = .{ .len = 0 },
        .accounts = context_accounts,
        .return_data = .{},
        .accounts_resize_delta = 0,
        .compute_meter = tx_compute_budget.compute_unit_limit,
        .custom_error = null,
        // 100KiB max log (we need *a* limit, but this is arbitrary)
        .log_collector = sig.runtime.LogCollector.init(100 * 1024),
        .prev_blockhash = env.prev_blockhash,
        .serialized_accounts = .{},
        .prev_lamports_per_signature = env.prev_blockhash_lamports_per_signature,
        .compute_budget = tx_compute_budget,
        .rent = env.rent_collector.rent,
    };
}

// ~= agave's process_message
fn executeLoadedTransaction(
    allocator: std.mem.Allocator,
    ctx: *sig.runtime.TransactionContext,
    accounts: []const AccountSharedData,
    raw_transaction: *const sig.core.Transaction,
) !void {
    errdefer {
        if (@errorReturnTrace()) |trace|
            ctx.log("trace: {}\n", .{trace}) catch {};
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
            if (precompile.program_id.equals(
                &raw_transaction.msg.account_keys[instruction.program_index],
            ))
                break true;
        } else false;

        if (is_precompile_program) {
            // TODO
            @panic("TODO");
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

    var bank = account_loader.MockedAccountsDb{ .allocator = allocator };
    defer bank.accounts.deinit(allocator);
    try bank.accounts.put(allocator, sig.runtime.ids.PRECOMPILE_ED25519_PROGRAM_ID, .{
        .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        .executable = true,
        .data = .{ .empty = .{ .len = 0 } },
        .lamports = 1,
        .rent_epoch = sig.core.rent_collector.RENT_EXEMPT_RENT_EPOCH,
    });
    try bank.accounts.put(allocator, sig.runtime.program.vote_program.ID, .{
        .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        .executable = true,
        .data = .{ .empty = .{ .len = 0 } },
        .lamports = 1,
        .rent_epoch = sig.core.rent_collector.RENT_EXEMPT_RENT_EPOCH,
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

    // a precompile instruction (slightly different codepath) - impl
    // const tx3: sig.core.Transaction = .{
    //     .msg = .{
    //         .account_keys = &.{sig.runtime.ids.PRECOMPILE_ED25519_PROGRAM_ID},
    //         .instructions = &.{
    //             .{ .program_index = 0, .account_indexes = &.{0}, .data = ed25519_instruction.data },
    //         },
    //         .signature_count = 1,
    //         .readonly_signed_count = 1,
    //         .readonly_unsigned_count = 0,
    //         .recent_blockhash = sig.core.Hash.ZEROES,
    //     },
    //     .version = .legacy,
    //     .signatures = &.{},
    // };

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

    // program that should fail
    const tx5 = sig.core.Transaction{
        .msg = .{
            .account_keys = &.{sig.runtime.program.vote_program.ID},
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

    const transactions: []const sig.core.Transaction = &.{ tx1, tx2, tx4, tx5 };

    var loader = try AccountLoader(.Mocked).newWithCacheCapacity(allocator, allocator, bank, 100);
    defer loader.deinit();

    const batch_loadedaccounts = try allocator.alloc(LoadedAccounts, transactions.len);
    defer allocator.free(batch_loadedaccounts);

    const batch_budgetlimits = try allocator.alloc(
        compute_budget.Error!compute_budget.ComputeBudgetLimits,
        transactions.len,
    );
    defer allocator.free(batch_budgetlimits);

    for (transactions, batch_budgetlimits) |*tx, *tx_budgetlimits| {
        tx_budgetlimits.* = compute_budget.execute(tx);
    }

    for (
        transactions,
        batch_loadedaccounts,
        batch_budgetlimits,
    ) |*tx, *tx_loaded_account, tx_budgetlimit| {
        const max_account_bytes = (try tx_budgetlimit).loaded_accounts_bytes;

        const loaded = try account_loader.loadTransactionAccounts(
            .Mocked,
            allocator,
            tx,
            max_account_bytes,
            &loader,
            &sig.runtime.FeatureSet.EMPTY,
            &sig.core.rent_collector.defaultCollector(0),
        );

        tx_loaded_account.* = loaded;
    }

    const env = ProcessingEnv.testingDefault();

    for (transactions, batch_budgetlimits, 0..) |*tx, tx_budgetlimit, tx_idx| {
        const loaded = &batch_loadedaccounts[tx_idx];

        const err: ?anyerror = if (loaded.load_failure) |failure|
            failure.err
        else exec_err: {
            const output = try executeTransaction(allocator, tx, env, try tx_budgetlimit, loaded);
            defer output.deinit(allocator);

            break :exec_err output.err;
        };

        const expected_err: ?anyerror = switch (tx_idx) {
            0, 1 => null,
            2 => error.ProgramAccountNotFound,
            3 => error.InvalidAccountOwner,
            else => unreachable,
        };

        try std.testing.expectEqual(expected_err, err);
    }
}

// example of usage
fn loadAndExecuteBatchExample(
    allocator: std.mem.Allocator,
    bank: account_loader.MockedAccountsDb,
    env: ProcessingEnv,
    transactions: []const sig.core.Transaction,
    features: *const sig.runtime.FeatureSet,
) !void {
    if (!builtin.is_test) @compileError("example/testing usage only");

    const per_tx_budget_limit = try allocator.alloc(
        compute_budget.Error!compute_budget.ComputeBudgetLimits,
        transactions.len,
    );
    defer allocator.free(per_tx_budget_limit);

    for (transactions, per_tx_budget_limit) |*tx, *tx_budgetlimits| {
        tx_budgetlimits.* = compute_budget.execute(tx);
    }

    var loader = try AccountLoader(.Mocked).newWithCacheCapacity(allocator, allocator, bank, max: {
        // capacity over-estimate
        var n_accounts: usize = 0;
        for (transactions) |tx| n_accounts += tx.msg.account_keys.len;
        break :max n_accounts;
    });
    defer loader.deinit();

    const per_ex_loaded_accounts = try allocator.alloc(LoadedAccounts, transactions.len);
    defer allocator.free(per_ex_loaded_accounts);

    // load single-threaded (writing to account loader)
    for (
        transactions,
        per_ex_loaded_accounts,
        per_tx_budget_limit,
    ) |*tx, *tx_loaded_accounts, tx_budget_limit| {
        const max_account_bytes = (tx_budget_limit catch continue).loaded_accounts_bytes;

        const loaded = try account_loader.loadTransactionAccounts(
            .Mocked,
            allocator,
            tx,
            max_account_bytes,
            &loader,
            features,
            &env.rent_collector,
        );

        tx_loaded_accounts.* = loaded;
    }

    // easy to parallelize (assuming no lock violations)
    for (
        transactions,
        per_ex_loaded_accounts,
        per_tx_budget_limit,
        0..,
    ) |tx, tx_loaded_accounts, tx_budget_limit, tx_idx| {
        const budget = tx_budget_limit catch |err| {
            std.debug.print("tx{}, bad budget program: {}\n", .{ tx_idx, err });
            continue;
        };
        if (tx_loaded_accounts.load_failure) |failure| {
            std.debug.print("tx{}, failed to load: {}\n", .{ tx_idx, failure });
            continue;
        }

        const output = try executeTransaction(allocator, &tx, env, budget, &tx_loaded_accounts);
        defer output.deinit(allocator);

        if (output.err) |err| {
            std.debug.print("tx{}, failed to execute: {}\n", .{ tx_idx, err });
            if (output.logs.len > 0) {
                std.debug.print("logs: {{\n", .{});
                for (output.logs) |log_entry| std.debug.print("{}:\t{s}", .{ tx_idx, log_entry });
                std.debug.print("logs: }}\n", .{});
            }
        }
    }
}

test "example batch" {
    const allocator = std.testing.allocator;

    var bank = account_loader.MockedAccountsDb{ .allocator = allocator };
    defer bank.accounts.deinit(allocator);

    const transactions = &.{sig.core.Transaction.EMPTY};
    const env = ProcessingEnv.testingDefault();

    try loadAndExecuteBatchExample(
        allocator,
        bank,
        env,
        transactions,
        &sig.runtime.FeatureSet.EMPTY,
    );
}
