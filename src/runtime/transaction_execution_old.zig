const std = @import("std");
const builtin = @import("builtin");
const sig = @import("../sig.zig");

const executor = sig.runtime.executor;
const account_loader = sig.runtime.account_loader;
const compute_budget = sig.runtime.program.compute_budget;

const AccountLoader = account_loader.AccountLoader;
const AccountSharedData = sig.runtime.AccountSharedData;
const ComputeBudgetLimits = compute_budget.ComputeBudgetLimits;
const ComputeBudetError = compute_budget.Error;
const LoadedAccounts = account_loader.LoadedAccounts;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const Hash = sig.core.Hash;
const BlockhashQueue = sig.core.bank.BlockhashQueue;
const RentCollector = sig.core.rent_collector.RentCollector;
const SysvarCache = sig.runtime.SysvarCache;
const FeatureSet = sig.runtime.FeatureSet;
const TransactionReturnData = sig.runtime.transaction_context.TransactionReturnData;
const TransactionContext = sig.runtime.TransactionContext;
const Transaction = sig.core.Transaction;
const InstructionInfo = sig.runtime.InstructionInfo;

pub const RuntimeTransaction = struct {
    instruction_infos: []const InstructionInfo,
};

pub const TransactionResult = union(enum(u8)) {
    fees_only: FeesOnlyTransaction,
    executed: ExecutedTransaction,

    fn err(self: TransactionResult) ?anyerror {
        return switch (self) {
            .fees_only => |fees_only| fees_only.err,
            .executed => |executed| executed.err,
        };
    }

    fn logs(self: TransactionResult) ?[]const []const u8 {
        return switch (self) {
            .fees_only => null,
            .executed => |executed| if (executed.logs.len > 0) executed.logs else null,
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
    return_data: ?TransactionReturnData = null,
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

fn executeBatch(
    transactions: []RuntimeTransaction
    environment: *ProcessingEnvironment,
    account_cache: *std.AutoHashMap(Pubkey, AccountSharedData),
) {
    
}

const ProcessingEnvironment = struct {
    slot: Slot,
    rent_collector: RentCollector,

    feature_set: *const FeatureSet,
    sysvar_cache: *const SysvarCache,
    blochash_queue: *const BlockhashQueue,

    fn testingDefault() ProcessingEnvironment {
        if (!builtin.is_test) @compileError("testingDefault for testing only");

        const epoch_context: sig.runtime.EpochContext = .{
            .allocator = std.testing.failing_allocator,
            .feature_set = sig.runtime.FeatureSet.EMPTY,
        };

        return .{
            .prev_blockhash = Hash.ZEROES,
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

pub fn executeTransaction(
    allocator: std.mem.Allocator,
    tc: *TransactionContext,
) ExecutedTransaction {
    errdefer {
        if (@errorReturnTrace()) |trace|
            tc.log("trace: {}\n", .{trace}) catch {};
    }

    for (tc.instruction_infos, 0..) |instruction, index| {
        executor.executeInstruction(
            allocator,
            tc,
            instruction,
        ) catch |err| {
            tc.instruction_error = err;
            tc.instruction_error_index = index;
        };
    }

    executeTransactionContext(allocator, &tc) catch |err| {
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

/// TODO: move to TransactionContext.init(...)
fn initTransactionContext(
    allocator: std.mem.Allocator,
    transaction: *const RuntimeTransaction,
    environment: *const ProcessingEnvironment,
) error{OutOfMemory}!sig.runtime.TransactionContext {
    std.debug.assert(environment.loaded_accounts.load_failure == null); // don't execute an improperly loaded tx
    const accounts = environment.loaded_accounts.accounts.constSlice();

    const context_accounts = try allocator.alloc(
        sig.runtime.TransactionContextAccount,
        accounts.len,
    );
    errdefer allocator.free(context_accounts);

    for (accounts, transaction.accounts, 0..) |account, key, account_idx| {
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
    const tx1 = Transaction.EMPTY;

    // zero instructions
    const tx2: Transaction = .{
        .signatures = &.{},
        .version = .legacy,
        .msg = .{
            .signature_count = 0,
            .readonly_signed_count = 0,
            .readonly_unsigned_count = 0,
            .account_keys = &.{sig.runtime.ids.SYSVAR_INSTRUCTIONS_ID},
            .recent_blockhash = .{ .data = [_]u8{0x00} ** Hash.SIZE },
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
    // const tx3: Transaction = .{
    //     .msg = .{
    //         .account_keys = &.{sig.runtime.ids.PRECOMPILE_ED25519_PROGRAM_ID},
    //         .instructions = &.{
    //             .{ .program_index = 0, .account_indexes = &.{0}, .data = ed25519_instruction.data },
    //         },
    //         .signature_count = 1,
    //         .readonly_signed_count = 1,
    //         .readonly_unsigned_count = 0,
    //         .recent_blockhash = Hash.ZEROES,
    //     },
    //     .version = .legacy,
    //     .signatures = &.{},
    // };

    // program not found
    const tx4 = Transaction{
        .msg = .{
            .account_keys = &.{Pubkey.ZEROES},
            .instructions = &.{
                .{ .program_index = 0, .account_indexes = &.{0}, .data = "" },
            },
            .signature_count = 1,
            .readonly_signed_count = 1,
            .readonly_unsigned_count = 0,
            .recent_blockhash = Hash.ZEROES,
        },
        .version = .legacy,
        .signatures = &.{},
    };

    // program that should fail
    const tx5 = Transaction{
        .msg = .{
            .account_keys = &.{sig.runtime.program.vote_program.ID},
            .instructions = &.{
                .{ .program_index = 0, .account_indexes = &.{0}, .data = "" },
            },
            .signature_count = 1,
            .readonly_signed_count = 1,
            .readonly_unsigned_count = 0,
            .recent_blockhash = Hash.ZEROES,
        },
        .version = .legacy,
        .signatures = &.{},
    };

    const transactions: []const Transaction = &.{ tx1, tx2, tx4, tx5 };

    var loader = try AccountLoader(.Mocked).newWithCacheCapacity(allocator, allocator, bank, 100);
    defer loader.deinit();

    const batch_loaded_accounts = try allocator.alloc(LoadedAccounts, transactions.len);
    defer allocator.free(batch_loaded_accounts);

    const batch_budget_limits = try allocator.alloc(
        compute_budget.Error!compute_budget.ComputeBudgetLimits,
        transactions.len,
    );
    defer allocator.free(batch_budget_limits);

    for (transactions, batch_budget_limits) |*tx, *budget_limits| {
        budget_limits.* = compute_budget.execute(tx);
    }

    for (
        transactions,
        batch_loaded_accounts,
        batch_budget_limits,
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

    const env = ProcessingEnvironment.testingDefault();

    for (transactions, batch_budget_limits, 0..) |*tx, tx_budgetlimit, tx_idx| {
        const loaded = &batch_loaded_accounts[tx_idx];

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

// Replay: fn preloadAccountCache() -> Pubkey -> AccountSharedData 
//
// |
// v
//
// ExecuteBatch: AccountLoader(account_cache: Pubkey -> AccountSharedData)
// ExecuteBatch: AccountLoader(account_cache: Pubkey -> AccountSharedData)
// ExecuteBatch: AccountLoader(account_cache: Pubkey -> AccountSharedData)

// Batch
//  Raw Transaction
//  Sig Verification
//  Load Address Lookup Tables 
//  Apply Compute Budget Program
//  Load Accounts
//  Iterate Transactions
//    Execute Transaction

pub const ExecuteTransactionTask = struct {
    tc: TransactionContext,
    err: TransactionError,
};

// Verify Signature
// Load Address Lookup Tables
// Failures result in invalid slot
// Array of RuntimeTransactions from txn address lookups
// Obtain Locks / Check for Conflicts in Batch
// Execute Batches
// Load Shared Account Map / Enforce Compute Budget
// Send Batches to Thread Pool
// Commit Results

fn loadAndExecuteBatches(
    allocator: std.mem.Allocator,
    environment: ProcessingEnvironment,
    accounts_db: MockedAccountsDb,
    batches: []const []const RuntimeTransaction,
) {
    var loader = try AccountLoader(.Mocked).newWithCacheCapacity(allocator, allocator, accounts_db, max: {
        // capacity over-estimate
        var n_accounts: usize = 0;
        for (transactions) |tx| n_accounts += tx.msg.account_keys.len;
        break :max n_accounts;
    });
    defer loader.deinit();

    const transaction_accounts = try allocator.alloc(
        TransactionContext.TransactionContextAccount,
        transactions.len,
    );

    var batch_accounts = try allocator.alloc(
        []*?AccountSharedData,
        transactions.len,
    );

    for (batches) |transactions| {
        for (transaction_accounts, transactions) |*tc_accounts, *tx| {
            const tc_accounts: []*AccountSharedData = try loader.loadTransactionAccounts(
                .Mocked,
                allocator,
                tx,
                max_loaded_accounts_bytes,
                &loader,
                environment.features,
                &environment.rent_collector,
            );
        }
    }
}

// example of usage
fn loadAndExecuteBatch(
    allocator: std.mem.Allocator,
    environment: ProcessingEnvironment,
    batches: []const []const RuntimeTransaction,
    batch_account_cache: std.AutoArrayHashMap(Pubkey, AccountSharedData),
) !void {
    if (!builtin.is_test) @compileError("example/testing usage only");

    var loader = try AccountLoader(.Mocked).newWithCacheCapacity(allocator, allocator, accounts_db, max: {
        // capacity over-estimate
        var n_accounts: usize = 0;
        for (transactions) |tx| n_accounts += tx.msg.account_keys.len;
        break :max n_accounts;
    });
    defer loader.deinit();

    for (transactions) |*tx| {
        try loader.loadTransactionAccounts(
            .Mocked,
            allocator,
            tx,
            max_loaded_accounts_bytes,
            &loader,
            environment.features,
            &environment.rent_collector,
        );
    }

    // In thread pool
    for (batches) |batch| {
        executeBatch(allocator, batch, environment, loader);
    }

    commitResults(allocator, transaction_contexts);
}

test "example batch" {
    const allocator = std.testing.allocator;

    var bank = account_loader.MockedAccountsDb{ .allocator = allocator };
    defer bank.accounts.deinit(allocator);

    const transactions = &.{Transaction.EMPTY};
    const env = ProcessingEnvironment.testingDefault();

    try loadAndExecuteBatchExample(
        allocator,
        bank,
        env,
        transactions,
        &sig.runtime.FeatureSet.EMPTY,
    );
}
