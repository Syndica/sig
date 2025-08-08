const std = @import("std");
const sig = @import("../sig.zig");

const account_loader = sig.runtime.account_loader;
const program_loader = sig.runtime.program_loader;
const executor = sig.runtime.executor;
const compute_budget_program = sig.runtime.program.compute_budget;
const vm = sig.vm;

const Ancestors = sig.core.Ancestors;
const BlockhashQueue = sig.core.BlockhashQueue;
const EpochStakes = sig.core.EpochStakes;
const Hash = sig.core.Hash;
const InstructionError = sig.core.instruction.InstructionError;
const InstructionErrorEnum = sig.core.instruction.InstructionErrorEnum;
const Pubkey = sig.core.Pubkey;
const RentCollector = sig.core.rent_collector.RentCollector;
const StatusCache = sig.core.StatusCache;

const AccountSharedData = sig.runtime.AccountSharedData;
const BatchAccountCache = sig.runtime.account_loader.BatchAccountCache;
const CachedAccount = sig.runtime.account_loader.CachedAccount;
const FeatureSet = sig.core.FeatureSet;
const FeeDetails = sig.runtime.check_transactions.FeeDetails;
const InstructionInfo = sig.runtime.InstructionInfo;
const LoadedTransactionAccounts = sig.runtime.account_loader.LoadedTransactionAccounts;
const LogCollector = sig.runtime.LogCollector;
const SysvarCache = sig.runtime.SysvarCache;
const TransactionContext = sig.runtime.TransactionContext;
const TransactionContextAccount = sig.runtime.TransactionContextAccount;
const TransactionReturnData = sig.runtime.transaction_context.TransactionReturnData;
const AccountMeta = sig.core.instruction.InstructionAccount;
const ProgramMap = sig.runtime.program_loader.ProgramMap;

const TransactionError = sig.ledger.transaction_status.TransactionError;
const ComputeBudgetLimits = compute_budget_program.ComputeBudgetLimits;
const InstructionTrace = TransactionContext.InstructionTrace;

// Transaction execution involves logic and validation which occurs in replay
// and the svm. The location of key processes in Agave are outlined below:
//
// Replay: (Failure results in slot rejection)
//     - Signature verification
//     - Load accounts from address lookup tables
//     - Verify precompiles (if move_verify_precompiles_to_svm is false)
//     - Acquire and check batch account locks
//
// Svm:
//     - Check transactions
//     - Validate fee payer
//     - Load accounts
//
// Once the accounts have been loaded, the transaction is commitable, even if its
// execution fails.

pub const RuntimeTransaction = struct {
    signature_count: u64,
    fee_payer: Pubkey,
    msg_hash: Hash,
    recent_blockhash: Hash,
    instruction_infos: []const InstructionInfo,
    accounts: std.MultiArrayList(AccountMeta) = .{},
};

pub const TransactionExecutionEnvironment = struct {
    ancestors: *const Ancestors,
    feature_set: *const FeatureSet,
    status_cache: *const StatusCache,
    sysvar_cache: *const SysvarCache,
    rent_collector: *const RentCollector,
    blockhash_queue: *const BlockhashQueue,
    epoch_stakes: *const EpochStakes,
    vm_environment: *const vm.Environment,
    next_vm_environment: ?*const vm.Environment,

    slot: u64,
    max_age: u64,
    last_blockhash: Hash,
    next_durable_nonce: Hash,
    next_lamports_per_signature: u64,
    last_lamports_per_signature: u64,

    lamports_per_signature: u64,
};

pub const TransactionExecutionConfig = struct {
    log: bool,
    log_messages_byte_limit: ?u64,
};

/// [agave] https://github.com/anza-xyz/agave/blob/5bcdd4934475fde094ffbddd3f8c4067238dc9b0/svm/src/rollback_accounts.rs#L11
pub const TransactionRollbacks = union(enum(u8)) {
    fee_payer_only: CopiedAccount,
    same_nonce_and_fee_payer: CopiedAccount,
    separate_nonce_and_fee_payer: struct { CopiedAccount, CopiedAccount },

    pub fn init(
        allocator: std.mem.Allocator,
        /// Takes ownership of this
        maybe_nonce: ?CopiedAccount,
        fee_payer: CachedAccount,
        fee_payer_rent_debit: u64,
        fee_payer_rent_epoch: sig.core.Epoch,
    ) error{OutOfMemory}!TransactionRollbacks {
        const payer_lamports = fee_payer.account.lamports +| fee_payer_rent_debit;

        if (maybe_nonce) |nonce| {
            errdefer allocator.free(nonce.account.data);
            if (fee_payer.pubkey.equals(&nonce.pubkey)) {
                const account = CopiedAccount.init(fee_payer, nonce.account.data, payer_lamports);
                return .{ .same_nonce_and_fee_payer = account };
            } else {
                const payer_data = try allocator.dupe(u8, fee_payer.account.data);
                const payer = CopiedAccount.init(fee_payer, payer_data, payer_lamports);
                return .{ .separate_nonce_and_fee_payer = .{ nonce, payer } };
            }
        } else {
            const payer_data = try allocator.dupe(u8, fee_payer.account.data);
            var copied_fee_payer = CopiedAccount.init(fee_payer, payer_data, payer_lamports);
            copied_fee_payer.account.rent_epoch = fee_payer_rent_epoch;
            return .{ .fee_payer_only = copied_fee_payer };
        }
    }

    pub fn deinit(self: TransactionRollbacks, allocator: std.mem.Allocator) void {
        switch (self) {
            .fee_payer_only => |fee_payer_account| allocator.free(fee_payer_account.account.data),
            .same_nonce_and_fee_payer => |account| allocator.free(account.account.data),
            .separate_nonce_and_fee_payer => |accounts| {
                const nonce, const fee_payer = accounts;
                allocator.free(nonce.account.data);
                allocator.free(fee_payer.account.data);
            },
        }
    }

    /// Number of accounts tracked for rollback
    ///
    /// Analogous to [count](https://github.com/anza-xyz/agave/blob/10fe1eb29aac9c236fd72d08ae60a3ef61ee8353/svm/src/rollback_accounts.rs#L80).
    pub fn count(self: *const TransactionRollbacks) usize {
        return switch (self.*) {
            .fee_payer_only, .same_nonce_and_fee_payer => 1,
            .separate_nonce_and_fee_payer => 2,
        };
    }

    /// Size of accounts tracked for rollback, used when calculating
    /// the actual cost of transaction processing in the cost model.
    ///
    /// Analogous to [data_size](https://github.com/anza-xyz/agave/blob/10fe1eb29aac9c236fd72d08ae60a3ef61ee8353/svm/src/rollback_accounts.rs#L89).
    pub fn dataSize(self: *const TransactionRollbacks) usize {
        return switch (self.*) {
            .fee_payer_only => |fee_payer_account| fee_payer_account.account.data.len,
            .same_nonce_and_fee_payer => |nonce| nonce.account.data.len,
            .separate_nonce_and_fee_payer => |pair| blk: {
                const nonce, const fee_payer_account = pair;
                break :blk fee_payer_account.account.data.len +| nonce.account.data.len;
            },
        };
    }
};

pub const CopiedAccount = struct {
    pubkey: Pubkey,
    account: AccountSharedData,

    pub fn init(cached_account: CachedAccount, data: []u8, lamports: u64) CopiedAccount {
        return .{
            .pubkey = cached_account.pubkey,
            .account = .{
                .data = data,
                .lamports = lamports,
                .owner = cached_account.account.owner,
                .executable = cached_account.account.executable,
                .rent_epoch = cached_account.account.rent_epoch,
            },
        };
    }
};

pub const ExecutedTransaction = struct {
    instr_err: ?struct { u8, InstructionErrorEnum },
    log_collector: ?LogCollector,
    instruction_trace: ?InstructionTrace,
    return_data: ?TransactionReturnData,
    compute_limit: u64,
    compute_meter: u64,
    accounts_data_len_delta: i64,

    pub fn deinit(self: ExecutedTransaction, allocator: std.mem.Allocator) void {
        if (self.log_collector) |lc| lc.deinit(allocator);
    }
};

pub const ProcessedTransaction = union(enum(u8)) {
    fees_only: struct {
        err: TransactionError,
        fees: FeeDetails,
        rollbacks: TransactionRollbacks,
    },
    executed: struct {
        fees: FeeDetails,
        rollbacks: TransactionRollbacks,
        loaded_accounts: LoadedTransactionAccounts,
        executed_transaction: ExecutedTransaction,
    },

    pub fn deinit(self: *ProcessedTransaction, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .executed => |*executed| {
                executed.executed_transaction.deinit(allocator);
                executed.rollbacks.deinit(allocator);
            },
            .fees_only => |*fees_only| {
                fees_only.rollbacks.deinit(allocator);
            },
        }
    }

    /// Analogous to [executed_units](https://github.com/anza-xyz/agave/blob/10fe1eb29aac9c236fd72d08ae60a3ef61ee8353/svm/src/transaction_processing_result.rs#L91).
    pub fn executedUnits(self: *const ProcessedTransaction) ?u64 {
        return switch (self.*) {
            .executed => |executed| {
                const compute_start = executed.executed_transaction.compute_limit;
                const compute_remain = executed.executed_transaction.compute_meter;
                return compute_start - compute_remain;
            },
            .fees_only => null,
        };
    }

    /// Analogous to [loaded_accounts_data_size](https://github.com/anza-xyz/agave/blob/10fe1eb29aac9c236fd72d08ae60a3ef61ee8353/svm/src/transaction_processing_result.rs#L97).
    pub fn loadedAccountsDataSize(self: *const ProcessedTransaction) u32 {
        return switch (self.*) {
            .executed => |context| context.loaded_accounts.loaded_accounts_data_size,
            .fees_only => |fees_only| @intCast(fees_only.rollbacks.dataSize()),
        };
    }
};

pub fn TransactionResult(comptime T: type) type {
    return union(enum(u8)) {
        ok: T,
        err: TransactionError,
    };
}

/// [agave] https://github.com/firedancer-io/agave/blob/403d23b809fc513e2c4b433125c127cf172281a2/svm/src/transaction_processor.rs#L323-L324
pub fn loadAndExecuteTransactions(
    allocator: std.mem.Allocator,
    transactions: []const RuntimeTransaction,
    batch_account_cache: *BatchAccountCache,
    environment: *const TransactionExecutionEnvironment,
    config: *const TransactionExecutionConfig,
) error{OutOfMemory}![]TransactionResult(ProcessedTransaction) {
    var program_map = try program_loader.loadPrograms(
        allocator,
        &batch_account_cache.account_cache,
        environment.vm_environment,
        environment.slot,
    );
    defer program_map.deinit(allocator);

    const transaction_results = try allocator.alloc(
        TransactionResult(ProcessedTransaction),
        transactions.len,
    );
    for (transactions, 0..) |*transaction, index| {
        transaction_results[index] = try loadAndExecuteTransaction(
            allocator,
            transaction,
            batch_account_cache,
            environment,
            config,
            &program_map,
        );
    }
    return transaction_results;
}

/// [agave] https://github.com/firedancer-io/agave/blob/403d23b809fc513e2c4b433125c127cf172281a2/svm/src/transaction_processor.rs#L323-L324
pub fn loadAndExecuteTransaction(
    allocator: std.mem.Allocator,
    transaction: *const RuntimeTransaction,
    batch_account_cache: *BatchAccountCache,
    environment: *const TransactionExecutionEnvironment,
    config: *const TransactionExecutionConfig,
    program_map: *const ProgramMap,
) error{OutOfMemory}!TransactionResult(ProcessedTransaction) {
    const check_age_result = try sig.runtime.check_transactions.checkAge(
        allocator,
        transaction,
        batch_account_cache,
        environment.blockhash_queue,
        environment.max_age,
        &environment.next_durable_nonce,
        environment.next_lamports_per_signature,
    );
    const maybe_nonce_info = switch (check_age_result) {
        .ok => |copied_account| copied_account,
        .err => |err| return .{ .err = err },
    };
    var nonce_account_is_owned = true;
    defer if (nonce_account_is_owned) if (maybe_nonce_info) |n| allocator.free(n.account.data);

    if (sig.runtime.check_transactions.checkStatusCache(
        &transaction.msg_hash,
        &transaction.recent_blockhash,
        environment.ancestors,
        environment.status_cache,
    )) |err| return .{ .err = err };

    // NOTE: in agave nonce validation occurs during check_transactions and validate_nonce_and_fee_payer.
    // Since we do not perform check transactions at the batch level, the secondary checks may not be necessary.
    // We will however need to return the corresponding errors which may occur in agave's validate_transaction_nonce.
    // [agave] hhttps://github.com/firedancer-io/agave/blob/403d23b809fc513e2c4b433125c127cf172281a2/svm/src/transaction_processor.rs#L632-L688

    // TODO: Should the compute budget program require the feature set?
    const compute_budget_result = compute_budget_program.execute(
        transaction.instruction_infos,
        environment.feature_set,
    );
    const compute_budget_limits = switch (compute_budget_result) {
        .ok => |limits| limits,
        .err => |err| return .{ .err = err },
    };

    nonce_account_is_owned = false;
    const check_fee_payer_result = try sig.runtime.check_transactions.checkFeePayer(
        allocator,
        transaction,
        batch_account_cache,
        &compute_budget_limits,
        maybe_nonce_info,
        environment.rent_collector,
        environment.feature_set,
        environment.lamports_per_signature,
    );
    const fees, const rollbacks = switch (check_fee_payer_result) {
        .ok => |result| result,
        .err => |err| return .{ .err = err },
    };
    errdefer rollbacks.deinit(allocator);

    const loaded_accounts_result = try batch_account_cache.loadTransactionAccounts(
        allocator,
        transaction,
        environment.rent_collector,
        environment.feature_set,
        &compute_budget_limits,
    );
    const loaded_accounts = switch (loaded_accounts_result) {
        .ok => |loaded_accounts| loaded_accounts,
        .err => |err| return .{ .ok = .{
            .fees_only = .{
                .err = err,
                .fees = fees,
                .rollbacks = rollbacks,
            },
        } },
    };

    const executed_transaction = try executeTransaction(
        allocator,
        transaction,
        loaded_accounts.accounts.constSlice(),
        &compute_budget_limits,
        environment,
        config,
        program_map,
    );

    return .{ .ok = .{
        .executed = .{
            .fees = fees,
            .rollbacks = rollbacks,
            .loaded_accounts = loaded_accounts,
            .executed_transaction = executed_transaction,
        },
    } };
}

/// [agave] https://github.com/firedancer-io/agave/blob/403d23b809fc513e2c4b433125c127cf172281a2/svm/src/transaction_processor.rs#L909
pub fn executeTransaction(
    allocator: std.mem.Allocator,
    transaction: *const RuntimeTransaction,
    loaded_accounts: []const CachedAccount,
    compute_budget_limits: *const ComputeBudgetLimits,
    environment: *const TransactionExecutionEnvironment,
    config: *const TransactionExecutionConfig,
    program_map: *const ProgramMap,
) error{OutOfMemory}!ExecutedTransaction {
    const compute_budget = compute_budget_limits.intoComputeBudget();

    const log_collector = if (config.log)
        LogCollector.init(config.log_messages_byte_limit)
    else
        null;

    const accounts = try allocator.alloc(
        TransactionContextAccount,
        loaded_accounts.len,
    );
    defer allocator.free(accounts);
    for (loaded_accounts, 0..) |account, index| {
        accounts[index] = .{
            .pubkey = account.pubkey,
            .account = account.account,
            .read_refs = 0,
            .write_ref = false,
        };
    }

    var tc: TransactionContext = .{
        .allocator = allocator,
        .feature_set = environment.feature_set,
        .epoch_stakes = environment.epoch_stakes,
        .sysvar_cache = environment.sysvar_cache,
        .vm_environment = environment.vm_environment,
        .next_vm_environment = environment.next_vm_environment,
        .program_map = program_map,
        .accounts = accounts,
        .serialized_accounts = .{},
        .instruction_stack = .{},
        .instruction_trace = .{},
        .return_data = .{},
        .accounts_resize_delta = 0,
        .compute_meter = compute_budget.compute_unit_limit,
        .compute_budget = compute_budget,
        .custom_error = null,
        .log_collector = log_collector,
        .rent = environment.rent_collector.rent,
        .prev_blockhash = environment.last_blockhash,
        .prev_lamports_per_signature = environment.last_lamports_per_signature,
    };

    const maybe_instruction_error: ?struct { u8, InstructionErrorEnum } =
        for (transaction.instruction_infos, 0..) |instruction_info, index| {
            executor.executeInstruction(
                allocator,
                &tc,
                instruction_info,
            ) catch |exec_err| {
                switch (exec_err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => |instr_err| break .{
                        @intCast(index),
                        InstructionErrorEnum.fromError(instr_err, tc.custom_error, null) catch |err| {
                            std.debug.panic("Error conversion failed: error={}", .{err});
                        },
                    },
                }
            };
        } else null;

    return .{
        .instr_err = maybe_instruction_error,
        .log_collector = tc.takeLogCollector(),
        .instruction_trace = tc.instruction_trace,
        .return_data = tc.takeReturnData(),
        .compute_limit = compute_budget.compute_unit_limit,
        .compute_meter = tc.compute_meter,
        .accounts_data_len_delta = tc.accounts_resize_delta,
    };
}

test "loadAndExecuteTransactions: no transactions" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);

    const transactions: []RuntimeTransaction = &.{};
    var batch_account_cache: account_loader.BatchAccountCache = .{};

    const ancestors: Ancestors = .{};
    const feature_set: FeatureSet = FeatureSet.EMPTY;
    const status_cache = StatusCache.default();
    const sysvar_cache: SysvarCache = .{};
    const rent_collector: RentCollector = sig.core.rent_collector.defaultCollector(10);
    const blockhash_queue: BlockhashQueue = try BlockhashQueue.initRandom(
        allocator,
        prng.random(),
        10,
    );
    defer blockhash_queue.deinit(allocator);
    const epoch_stakes = try EpochStakes.initEmptyWithGenesisStakeHistoryEntry(allocator);
    defer epoch_stakes.deinit(allocator);
    const vm_environment = vm.Environment{};
    defer vm_environment.deinit(allocator);

    const environment: TransactionExecutionEnvironment = .{
        .ancestors = &ancestors,
        .feature_set = &feature_set,
        .status_cache = &status_cache,
        .sysvar_cache = &sysvar_cache,
        .rent_collector = &rent_collector,
        .blockhash_queue = &blockhash_queue,
        .epoch_stakes = &epoch_stakes,
        .vm_environment = &vm_environment,
        .next_vm_environment = null,

        .slot = 0,
        .max_age = 0,
        .last_blockhash = Hash.ZEROES,
        .next_durable_nonce = Hash.ZEROES,
        .next_lamports_per_signature = 0,
        .last_lamports_per_signature = 0,

        .lamports_per_signature = 0,
    };

    const config = TransactionExecutionConfig{
        .log = false,
        .log_messages_byte_limit = null,
    };

    const result = try loadAndExecuteTransactions(
        allocator,
        transactions,
        &batch_account_cache,
        &environment,
        &config,
    );

    _ = result;
}

test "loadAndExecuteTransactions: invalid compute budget instruction" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(0);

    const max_age = 5;
    const recent_blockhash = Hash.initRandom(prng.random());

    const transaction = RuntimeTransaction{
        .signature_count = 0,
        .fee_payer = Pubkey.ZEROES,
        .msg_hash = Hash.ZEROES,
        .recent_blockhash = recent_blockhash,
        .instruction_infos = &.{.{
            .program_meta = .{
                .pubkey = sig.runtime.program.compute_budget.ID,
                .index_in_transaction = 0,
            },
            .account_metas = .{},
            .instruction_data = &.{},
        }},
    };

    var blockhash_queue = try BlockhashQueue.initWithSingleEntry(
        allocator,
        recent_blockhash,
        5000,
    );
    defer blockhash_queue.deinit(allocator);

    var account_cache = BatchAccountCache{};
    defer account_cache.deinit(allocator);

    const epoch_stakes = try EpochStakes.initEmptyWithGenesisStakeHistoryEntry(allocator);
    defer epoch_stakes.deinit(allocator);

    const results = try loadAndExecuteTransactions(
        allocator,
        &.{transaction},
        &account_cache,
        &.{
            .ancestors = &Ancestors{},
            .feature_set = &FeatureSet.EMPTY,
            .status_cache = &StatusCache.default(),
            .sysvar_cache = &SysvarCache{},
            .rent_collector = &sig.core.rent_collector.defaultCollector(10),
            .vm_environment = &vm.Environment{},
            .next_vm_environment = null,
            .blockhash_queue = &blockhash_queue,
            .epoch_stakes = &epoch_stakes,
            .slot = 0,
            .max_age = max_age,
            .last_blockhash = recent_blockhash,
            .next_durable_nonce = Hash.ZEROES,
            .next_lamports_per_signature = 0,
            .last_lamports_per_signature = 0,
            .lamports_per_signature = 0,
        },
        &.{
            .log = false,
            .log_messages_byte_limit = null,
        },
    );
    defer {
        for (results) |*result| {
            switch (result.*) {
                .ok => |*ok| ok.deinit(allocator),
                .err => |err| err.deinit(allocator),
            }
        }
        allocator.free(results);
    }

    try std.testing.expectEqual(
        TransactionError{ .InstructionError = .{ 0, .InvalidInstructionData } },
        results[0].err,
    );
}

test "loadAndExecuteTransaction: simple transfer transaction" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);

    const sender_key = Pubkey.initRandom(prng.random());
    const receiver_key = Pubkey.initRandom(prng.random());
    const recent_blockhash = Hash.initRandom(prng.random());

    const transfer_instruction_data = try sig.bincode.writeAlloc(
        allocator,
        sig.runtime.program.system.Instruction{
            .transfer = .{ .lamports = 10_000 },
        },
        .{},
    );
    defer allocator.free(transfer_instruction_data);

    var accounts = std.MultiArrayList(AccountMeta){};
    defer accounts.deinit(allocator);
    try accounts.append(allocator, .{
        .pubkey = sender_key,
        .is_signer = true,
        .is_writable = true,
    });
    try accounts.append(allocator, .{
        .pubkey = receiver_key,
        .is_signer = false,
        .is_writable = true,
    });
    try accounts.append(allocator, .{
        .pubkey = sig.runtime.program.system.ID,
        .is_signer = false,
        .is_writable = false,
    });

    const transaction = RuntimeTransaction{
        .signature_count = 1,
        .fee_payer = sender_key,
        .msg_hash = Hash.initRandom(prng.random()),
        .recent_blockhash = recent_blockhash,
        .instruction_infos = &.{.{
            .program_meta = .{
                .pubkey = sig.runtime.program.system.ID,
                .index_in_transaction = 2,
            },
            .account_metas = try .fromSlice(&.{ // sender, receiver, system program
                .{
                    .pubkey = sender_key,
                    .index_in_transaction = 0,
                    .index_in_callee = 0,
                    .index_in_caller = 0,
                    .is_signer = true,
                    .is_writable = true,
                },
                .{
                    .pubkey = receiver_key,
                    .index_in_transaction = 1,
                    .index_in_callee = 1,
                    .index_in_caller = 1,
                    .is_signer = false,
                    .is_writable = true,
                },
            }),
            .instruction_data = transfer_instruction_data,
        }},
        .accounts = accounts,
    };

    var account_cache = BatchAccountCache{};
    defer account_cache.deinit(allocator);
    try account_cache.account_cache.put(
        allocator,
        sender_key,
        .{
            .lamports = 100_000,
            .data = &.{},
            .owner = sig.runtime.program.system.ID,
            .executable = false,
            .rent_epoch = 0,
        },
    );
    try account_cache.account_cache.put(
        allocator,
        receiver_key,
        .{
            .lamports = 100_000,
            .data = &.{},
            .owner = sig.runtime.program.system.ID,
            .executable = false,
            .rent_epoch = 0,
        },
    );
    try account_cache.account_cache.put(
        allocator,
        sig.runtime.program.system.ID,
        .{
            .lamports = 1,
            .data = &.{},
            .owner = sig.runtime.ids.NATIVE_LOADER_ID,
            .executable = true,
            .rent_epoch = 0,
        },
    );

    var ancestors = Ancestors{};
    defer ancestors.deinit(allocator);

    const feature_set = try FeatureSet.allEnabled(allocator);
    defer feature_set.deinit(allocator);

    var status_cache = StatusCache.default();
    defer status_cache.deinit(allocator);

    const sysvar_cache = SysvarCache{};
    defer sysvar_cache.deinit(allocator);

    const rent_collector = sig.core.rent_collector.defaultCollector(10);

    var blockhash_queue = try BlockhashQueue.initWithSingleEntry(
        allocator,
        recent_blockhash,
        5000,
    );
    defer blockhash_queue.deinit(allocator);

    const epoch_stakes = try EpochStakes.initEmptyWithGenesisStakeHistoryEntry(allocator);
    defer epoch_stakes.deinit(allocator);

    const environment = TransactionExecutionEnvironment{
        .ancestors = &ancestors,
        .feature_set = &feature_set,
        .status_cache = &status_cache,
        .sysvar_cache = &sysvar_cache,
        .rent_collector = &rent_collector,
        .blockhash_queue = &blockhash_queue,
        .epoch_stakes = &epoch_stakes,
        .vm_environment = &vm.Environment{},
        .next_vm_environment = null,
        .slot = 0,
        .max_age = 0,
        .last_blockhash = transaction.recent_blockhash,
        .next_durable_nonce = Hash.ZEROES,
        .next_lamports_per_signature = 0,
        .last_lamports_per_signature = 0,
        .lamports_per_signature = 5000, // Default value
    };

    const config = TransactionExecutionConfig{
        .log = false,
        .log_messages_byte_limit = null,
    };

    const result = try loadAndExecuteTransaction(
        allocator,
        &transaction,
        &account_cache,
        &environment,
        &config,
        &ProgramMap{},
    );

    var processed_transaction = result.ok;
    defer processed_transaction.deinit(allocator);

    const executed_transaction = processed_transaction.executed.executed_transaction;

    const transaction_fee = processed_transaction.executed.fees.transaction_fee;
    const prioritization_fee = processed_transaction.executed.fees.prioritization_fee;
    const rent_collected = processed_transaction.executed.loaded_accounts.rent_collected;

    const sender_account = account_cache.account_cache.get(sender_key).?;
    const receiver_account = account_cache.account_cache.get(receiver_key).?;

    // TODO: verify these numbers against agave
    try std.testing.expectEqual(5_000, transaction_fee);
    try std.testing.expectEqual(0, prioritization_fee);
    try std.testing.expectEqual(0, rent_collected);
    try std.testing.expectEqual(85_000, sender_account.lamports);
    try std.testing.expectEqual(110_000, receiver_account.lamports);
    try std.testing.expectEqual(null, executed_transaction.instr_err);
    try std.testing.expectEqual(null, executed_transaction.log_collector);
    try std.testing.expectEqual(1, executed_transaction.instruction_trace.?.len);
    try std.testing.expectEqual(null, executed_transaction.return_data);
    try std.testing.expectEqual(2_850, executed_transaction.compute_meter);
    try std.testing.expectEqual(0, executed_transaction.accounts_data_len_delta);
}
