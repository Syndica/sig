const std = @import("std");
const sig = @import("../sig.zig");
const tracy = @import("tracy");

const account_loader = sig.runtime.account_loader;
const program_loader = sig.runtime.program_loader;
const executor = sig.runtime.executor;
const compute_budget_program = sig.runtime.program.compute_budget;
const vm = sig.vm;

const Ancestors = sig.core.Ancestors;
const BlockhashQueue = sig.core.BlockhashQueue;
const EpochStakes = sig.core.EpochStakes;
const Hash = sig.core.Hash;
const InstructionErrorEnum = sig.core.instruction.InstructionErrorEnum;
const Pubkey = sig.core.Pubkey;
const RentCollector = sig.core.rent_collector.RentCollector;
const StatusCache = sig.core.StatusCache;
const Slot = sig.core.Slot;
const RentState = sig.core.RentCollector.RentState;

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
const ComputeBudgetInstructionDetails = compute_budget_program.ComputeBudgetInstructionDetails;
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
    instructions: []const InstructionInfo,
    accounts: std.MultiArrayList(AccountMeta) = .{},
    compute_budget_instruction_details: ComputeBudgetInstructionDetails = .{},
    num_lookup_tables: u64,
};

pub const TransactionExecutionEnvironment = struct {
    ancestors: *const Ancestors,
    feature_set: *const FeatureSet,
    status_cache: *StatusCache,
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
    separate_nonce_and_fee_payer: [2]CopiedAccount,

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

    pub fn accounts(self: *const TransactionRollbacks) []const CopiedAccount {
        return switch (self.*) {
            .fee_payer_only, .same_nonce_and_fee_payer => |*item| item[0..1],
            .separate_nonce_and_fee_payer => |*items| items,
        };
    }

    pub fn deinit(self: TransactionRollbacks, allocator: std.mem.Allocator) void {
        switch (self) {
            .fee_payer_only => |fee_payer_account| allocator.free(fee_payer_account.account.data),
            .same_nonce_and_fee_payer => |account| allocator.free(account.account.data),
            .separate_nonce_and_fee_payer => |both_accounts| for (both_accounts) |account| {
                allocator.free(account.account.data);
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

    pub fn getAccount(self: *const CopiedAccount) *const AccountSharedData {
        return &self.account;
    }
};

pub const ExecutedTransaction = struct {
    err: ?TransactionError,
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

    pub const Accounts = union(enum) {
        /// *all* of the accounts that were loaded for this transaction, in the
        /// same order that they were present in the transaction.
        all_loaded: []const CachedAccount,
        /// *only* the accounts that definitely need to be written back to
        /// accountsdb, in no particular order.
        written: []const CopiedAccount,
    };

    pub fn accounts(self: *const ProcessedTransaction) Accounts {
        return switch (self.*) {
            .fees_only => |f| .{ .written = f.rollbacks.accounts() },
            .executed => |e| if (e.executed_transaction.err != null) .{
                .written = e.rollbacks.accounts(),
            } else .{
                .all_loaded = e.loaded_accounts.accounts.slice(),
            },
        };
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
    env: *const TransactionExecutionEnvironment,
    config: *const TransactionExecutionConfig,
    program_map: *ProgramMap,
) error{OutOfMemory}!TransactionResult(ProcessedTransaction) {
    var zone = tracy.Zone.init(@src(), .{ .name = "executeTransaction" });
    defer zone.deinit();
    errdefer zone.color(0xFF0000);

    const max_tx_locks: usize = if (env.feature_set.active(
        .increase_tx_account_lock_limit,
        env.slot,
    )) 128 else 64;

    if (transaction.accounts.len > max_tx_locks) {
        return .{ .err = .TooManyAccountLocks };
    }

    if (hasDuplicates(transaction.accounts.items(.pubkey))) {
        return .{ .err = .AccountLoadedTwice };
    }

    const check_age_result = try sig.runtime.check_transactions.checkAge(
        allocator,
        transaction,
        batch_account_cache,
        env.blockhash_queue,
        env.max_age,
        &env.next_durable_nonce,
        env.next_lamports_per_signature,
    );
    const maybe_nonce_info = switch (check_age_result) {
        .ok => |copied_account| copied_account,
        .err => |err| return .{ .err = err },
    };
    var nonce_account_is_owned = true;
    defer if (nonce_account_is_owned) if (maybe_nonce_info) |n| allocator.free(n.account.data);

    const compute_budget_result = compute_budget_program.sanitize(
        transaction.compute_budget_instruction_details,
        env.feature_set,
        env.slot,
    );
    const compute_budget_limits = switch (compute_budget_result) {
        .ok => |limits| limits,
        .err => |err| return .{ .err = err },
    };

    if (sig.runtime.check_transactions.checkStatusCache(
        &transaction.msg_hash,
        &transaction.recent_blockhash,
        env.ancestors,
        env.status_cache,
    )) |err| return .{ .err = err };

    nonce_account_is_owned = false;
    const check_fee_payer_result = try sig.runtime.check_transactions.checkFeePayer(
        allocator,
        transaction,
        batch_account_cache,
        &compute_budget_limits,
        maybe_nonce_info,
        env.rent_collector,
        env.feature_set,
        env.slot,
        env.lamports_per_signature,
    );
    const fees, const rollbacks = switch (check_fee_payer_result) {
        .ok => |result| result,
        .err => |err| return .{ .err = err },
    };
    errdefer rollbacks.deinit(allocator);

    const loaded_accounts_result = try batch_account_cache.loadTransactionAccounts(
        allocator,
        transaction,
        env.rent_collector,
        env.feature_set,
        env.slot,
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
        env,
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

/// Check for duplicate account keys.
///
/// NOTE: in agave, this check is done while creating/loading the account batch:
/// * [prepare_sanitized_batch](https://github.com/firedancer-io/agave/blob/10fe1eb29aac9c236fd72d08ae60a3ef61ee8353/runtime/src/bank.rs#L3173)
/// * [try_lock_accounts](https://github.com/firedancer-io/agave/blob/10fe1eb29aac9c236fd72d08ae60a3ef61ee8353/runtime/src/bank.rs#L3164)
/// * [lock_accounts](https://github.com/firedancer-io/agave/blob/10fe1eb29aac9c236fd72d08ae60a3ef61ee8353/accounts-db/src/accounts.rs#L569)
/// * [validate_account_locks](https://github.com/firedancer-io/agave/blob/10fe1eb29aac9c236fd72d08ae60a3ef61ee8353/accounts-db/src/account_locks.rs#L122-L123)
/// and then it is propagated to and through `load_and_execute_transactions`.
///
/// Our account batch creation/load process isn't designed to accommodate this, so what we do
/// instead is do the check when we're actually trying to load and execute the transaction.
fn hasDuplicates(account_keys: []const Pubkey) bool {
    for (account_keys, 0..) |current_key, idx| {
        for (account_keys[idx + 1 ..]) |next_key| {
            if (current_key.equals(&next_key)) {
                return true;
            }
        }
    }
    return false;
}

test hasDuplicates {
    const pk1: Pubkey = .{ .data = @splat(1) };
    const pk2: Pubkey = .{ .data = @splat(2) };
    const pk3: Pubkey = .{ .data = @splat(3) };

    try std.testing.expectEqual(false, hasDuplicates(&.{}));
    try std.testing.expectEqual(false, hasDuplicates(&.{pk1}));
    try std.testing.expectEqual(false, hasDuplicates(&.{ pk1, pk2 }));
    try std.testing.expectEqual(false, hasDuplicates(&.{ pk1, pk2, pk3 }));
    try std.testing.expectEqual(true, hasDuplicates(&.{ pk1, pk2, pk3, pk3 }));
    try std.testing.expectEqual(true, hasDuplicates(&.{ pk2, pk1, pk2, pk3 }));
}

/// [agave] https://github.com/firedancer-io/agave/blob/403d23b809fc513e2c4b433125c127cf172281a2/svm/src/transaction_processor.rs#L909
pub fn executeTransaction(
    allocator: std.mem.Allocator,
    transaction: *const RuntimeTransaction,
    loaded_accounts: []const CachedAccount,
    compute_budget_limits: *const ComputeBudgetLimits,
    environment: *const TransactionExecutionEnvironment,
    config: *const TransactionExecutionConfig,
    program_map: *ProgramMap,
) error{OutOfMemory}!ExecutedTransaction {
    var zone = tracy.Zone.init(@src(), .{ .name = "executeTransaction" });
    defer zone.deinit();

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

    const instruction_datas = try getInstructionDatasSliceForPrecompiles(
        allocator,
        transaction.instructions,
        environment.feature_set,
        environment.slot,
    );
    defer if (instruction_datas) |ids| allocator.free(ids);

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
        .slot = environment.slot,
        .instruction_datas = instruction_datas,
    };

    const pre_account_rent_states = try transactionAccountsRentState(
        allocator,
        &tc,
        transaction,
        environment.rent_collector,
    );
    defer allocator.free(pre_account_rent_states);

    var maybe_instruction_error: ?TransactionError =
        for (transaction.instructions, 0..) |instruction_info, index| {
            executor.executeInstruction(
                allocator,
                &tc,
                instruction_info,
            ) catch |exec_err| {
                switch (exec_err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => |ixn_err| break .{ .InstructionError = .{
                        @intCast(index),
                        InstructionErrorEnum.fromError(
                            ixn_err,
                            tc.custom_error,
                            null,
                        ) catch |err| {
                            std.debug.panic("Error conversion failed: error={}", .{err});
                        },
                    } },
                }
            };
        } else null;

    if (maybe_instruction_error == null) {
        const post_account_rent_states = try transactionAccountsRentState(
            allocator,
            &tc,
            transaction,
            environment.rent_collector,
        );
        defer allocator.free(post_account_rent_states);

        maybe_instruction_error = verifyAccountRentStateChanges(
            &tc,
            pre_account_rent_states,
            post_account_rent_states,
        );
    }

    return .{
        .err = maybe_instruction_error,
        .log_collector = tc.takeLogCollector(),
        .instruction_trace = tc.instruction_trace,
        .return_data = tc.takeReturnData(),
        .compute_limit = compute_budget.compute_unit_limit,
        .compute_meter = tc.compute_meter,
        .accounts_data_len_delta = tc.accounts_resize_delta,
    };
}

fn verifyAccountRentStateChanges(
    tc: *TransactionContext,
    pre_account_rent_states: []const ?RentState,
    post_account_rent_states: []const ?RentState,
) ?TransactionError {
    for (pre_account_rent_states, post_account_rent_states, 0..) |pre, post, i| {
        if (pre != null and post != null) {
            const account = tc.getAccountAtIndex(@intCast(i)) orelse
                @panic("account must exist in transaction context");

            if (RentCollector.checkRentStateWithAccount(
                pre.?,
                post.?,
                &account.pubkey,
                @intCast(i),
            )) |err| return err;
        }
    }
    return null;
}

fn transactionAccountsRentState(
    allocator: std.mem.Allocator,
    tc: *TransactionContext,
    txn: *const RuntimeTransaction,
    rent_collector: *const RentCollector,
) ![]const ?RentState {
    const rent_states = try allocator.alloc(?RentState, txn.accounts.len);
    for (0..txn.accounts.len) |i| {
        const rent_state = if (txn.accounts.items(.is_writable)[i]) blk: {
            const account = tc.borrowAccountAtIndex(@intCast(i), .{
                .program_id = Pubkey.ZEROES,
                .remove_accounts_executable_flag_checks = false,
                .accounts_lamport_delta = &tc.accounts_lamport_delta,
            }) catch @panic("Account must exist in transaction context");
            defer account.release();

            if (sig.runtime.ids.NATIVE_LOADER_ID.equals(&account.account.owner)) {
                // TODO: Native programs should not be writable. Returning null here is correct
                // with respect to this function. However, we need to fix the is writable bug
                // and reenable this panic.
                // @panic("Native programs should not be writable");
                break :blk null;
            } else {
                break :blk rent_collector.getAccountRentState(
                    account.account.lamports,
                    account.account.data.len,
                );
            }
        } else null;
        rent_states[i] = rent_state;
    }
    return rent_states;
}

// TODO: RuntimeTransaction already contains this information which we should use in the future
// instead of allocating a new array here.
fn getInstructionDatasSliceForPrecompiles(
    allocator: std.mem.Allocator,
    instructions: []const InstructionInfo,
    feature_set: *const FeatureSet,
    slot: Slot,
) !?[]const []const u8 {
    const contains_precompile = for (instructions) |ixn_info| {
        if (ixn_info.program_meta.pubkey.equals(&sig.runtime.program.precompiles.ed25519.ID) or
            ixn_info.program_meta.pubkey.equals(&sig.runtime.program.precompiles.secp256k1.ID) or
            ixn_info.program_meta.pubkey.equals(&sig.runtime.program.precompiles.secp256r1.ID))
            break true;
    } else false;

    const move_verify_precompiles_to_svm = feature_set.active(
        .move_precompile_verification_to_svm,
        slot,
    );

    const instruction_datas = if (contains_precompile and move_verify_precompiles_to_svm) blk: {
        const instruction_datas = try allocator.alloc([]const u8, instructions.len);
        for (instructions, 0..) |instruction_info, index| {
            instruction_datas[index] = instruction_info.instruction_data;
        }
        break :blk instruction_datas;
    } else null;

    return instruction_datas;
}

test getInstructionDatasSliceForPrecompiles {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    var feature_set = sig.core.FeatureSet.ALL_DISABLED;
    feature_set.setSlot(.move_precompile_verification_to_svm, 0);

    {
        const instructions = [_]InstructionInfo{.{
            .program_meta = .{
                .pubkey = Pubkey.initRandom(random),
                .index_in_transaction = 0,
            },
            .account_metas = .{},
            .dedup_map = @splat(0xff),
            .instruction_data = "data",
            .initial_account_lamports = 0,
        }};

        const maybe_instruction_datas = try getInstructionDatasSliceForPrecompiles(
            allocator,
            &instructions,
            &feature_set,
            0,
        );
        defer if (maybe_instruction_datas) |data| allocator.free(data);

        try std.testing.expectEqual(null, maybe_instruction_datas);
    }

    {
        const instructions = [_]InstructionInfo{
            .{
                .program_meta = .{
                    .pubkey = Pubkey.initRandom(random),
                    .index_in_transaction = 0,
                },
                .account_metas = .{},
                .dedup_map = @splat(0xff),
                .instruction_data = "one",
                .initial_account_lamports = 0,
            },
            .{
                .program_meta = .{
                    .pubkey = Pubkey.initRandom(random),
                    .index_in_transaction = 0,
                },
                .account_metas = .{},
                .dedup_map = @splat(0xff),
                .instruction_data = "two",
                .initial_account_lamports = 0,
            },
            .{
                .program_meta = .{
                    .pubkey = sig.runtime.program.precompiles.ed25519.ID,
                    .index_in_transaction = 0,
                },
                .account_metas = .{},
                .dedup_map = @splat(0xff),
                .instruction_data = "three",
                .initial_account_lamports = 0,
            },
        };

        const maybe_instruction_datas = try getInstructionDatasSliceForPrecompiles(
            allocator,
            &instructions,
            &feature_set,
            0,
        );
        defer if (maybe_instruction_datas) |datas| allocator.free(datas);

        try std.testing.expectEqualSlices(u8, "one", maybe_instruction_datas.?[0]);
        try std.testing.expectEqualSlices(u8, "two", maybe_instruction_datas.?[1]);
        try std.testing.expectEqualSlices(u8, "three", maybe_instruction_datas.?[2]);
    }
}

test "loadAndExecuteTransactions: no transactions" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);

    const transactions: []RuntimeTransaction = &.{};
    var batch_account_cache: account_loader.BatchAccountCache = .{};

    const ancestors: Ancestors = .{};
    const feature_set: FeatureSet = .ALL_DISABLED;
    var status_cache: StatusCache = .DEFAULT;
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
    const Signature = sig.core.Signature;
    var prng = std.Random.DefaultPrng.init(0);

    const recent_blockhash = Hash.initRandom(prng.random());

    const transaction = sig.core.Transaction{
        .signatures = &.{Signature.ZEROES},
        .version = .legacy,
        .msg = .{
            .signature_count = 1,
            .readonly_signed_count = 0,
            .readonly_unsigned_count = 1,
            .account_keys = &.{ Pubkey.ZEROES, sig.runtime.program.compute_budget.ID },
            .recent_blockhash = recent_blockhash,
            .instructions = &.{.{ // invalid compute budget instruction
                .program_index = 1,
                .account_indexes = &.{},
                .data = &.{},
            }},
        },
    };

    const result =
        sig.replay.preprocess_transaction.preprocessTransaction(transaction, .skip_sig_verify);

    try std.testing.expectEqual(
        TransactionError{ .InstructionError = .{ 0, .InvalidInstructionData } },
        result.err,
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
            .transfer = .{ .lamports = 5_000_000 },
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

    var transaction = RuntimeTransaction{
        .signature_count = 1,
        .fee_payer = sender_key,
        .msg_hash = Hash.initRandom(prng.random()),
        .recent_blockhash = recent_blockhash,
        .instructions = &.{.{
            .program_meta = .{
                .pubkey = sig.runtime.program.system.ID,
                .index_in_transaction = 2,
            },
            .account_metas = try .fromSlice(&.{ // sender, receiver, system program
                .{
                    .pubkey = sender_key,
                    .index_in_transaction = 0,
                    .is_signer = true,
                    .is_writable = true,
                },
                .{
                    .pubkey = receiver_key,
                    .index_in_transaction = 1,
                    .is_signer = false,
                    .is_writable = true,
                },
            }),
            .dedup_map = blk: {
                var dedup_map: [InstructionInfo.MAX_ACCOUNT_METAS]u8 = @splat(0xff);
                dedup_map[0] = 0;
                dedup_map[1] = 1;
                break :blk dedup_map;
            },
            .instruction_data = transfer_instruction_data,
        }},
        .accounts = accounts,
        .num_lookup_tables = 0,
    };

    // Set a compute budget that is sufficient for the transaction to succeed
    transaction.compute_budget_instruction_details.num_non_compute_budget_instructions = 1;
    transaction.compute_budget_instruction_details.num_non_migratable_builtin_instructions = 1;

    var account_cache = BatchAccountCache{};
    defer account_cache.deinit(allocator);
    try account_cache.account_cache.put(
        allocator,
        sender_key,
        .{
            .lamports = 10_000_000,
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
            .lamports = 10_000_000,
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

    var ancestors: Ancestors = .{};
    defer ancestors.deinit(allocator);

    const feature_set: FeatureSet = .ALL_ENABLED_AT_GENESIS;

    var status_cache: StatusCache = .DEFAULT;
    defer status_cache.deinit(allocator);

    const sysvar_cache: SysvarCache = .{};
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

    { // Okay
        var program_map = ProgramMap{};
        defer program_map.deinit(allocator);
        const result = try loadAndExecuteTransaction(
            allocator,
            &transaction,
            &account_cache,
            &environment,
            &config,
            &program_map,
        );

        var processed_transaction = result.ok;
        defer processed_transaction.deinit(allocator);

        const executed_transaction = processed_transaction.executed.executed_transaction;

        const transaction_fee = processed_transaction.executed.fees.transaction_fee;
        const prioritization_fee = processed_transaction.executed.fees.prioritization_fee;
        const rent_collected = processed_transaction.executed.loaded_accounts.rent_collected;

        const sender_account = account_cache.account_cache.get(sender_key).?;
        const receiver_account = account_cache.account_cache.get(receiver_key).?;

        try std.testing.expectEqual(5_000, transaction_fee);
        try std.testing.expectEqual(0, prioritization_fee);
        try std.testing.expectEqual(0, rent_collected);
        try std.testing.expectEqual(4_995_000, sender_account.lamports);
        try std.testing.expectEqual(15_000_000, receiver_account.lamports);
        try std.testing.expectEqual(null, executed_transaction.err);
        try std.testing.expectEqual(null, executed_transaction.log_collector);
        try std.testing.expectEqual(1, executed_transaction.instruction_trace.?.len);
        try std.testing.expectEqual(null, executed_transaction.return_data);
        try std.testing.expectEqual(2_850, executed_transaction.compute_meter);
        try std.testing.expectEqual(0, executed_transaction.accounts_data_len_delta);
    }

    { // Insufficient funds
        var program_map = ProgramMap{};
        defer program_map.deinit(allocator);
        const result = try loadAndExecuteTransaction(
            allocator,
            &transaction,
            &account_cache,
            &environment,
            &config,
            &program_map,
        );

        var processed_transaction = result.ok;
        defer processed_transaction.deinit(allocator);

        const executed_transaction = processed_transaction.executed.executed_transaction;

        const transaction_fee = processed_transaction.executed.fees.transaction_fee;
        const prioritization_fee = processed_transaction.executed.fees.prioritization_fee;
        const rent_collected = processed_transaction.executed.loaded_accounts.rent_collected;

        const sender_account = account_cache.account_cache.get(sender_key).?;
        const receiver_account = account_cache.account_cache.get(receiver_key).?;

        try std.testing.expectEqual(5_000, transaction_fee);
        try std.testing.expectEqual(0, prioritization_fee);
        try std.testing.expectEqual(0, rent_collected);
        try std.testing.expectEqual(4_990_000, sender_account.lamports);
        try std.testing.expectEqual(15_000_000, receiver_account.lamports);
        try std.testing.expectEqual(0, executed_transaction.err.?.InstructionError[0]);
        try std.testing.expectEqual(
            InstructionErrorEnum{ .Custom = 1 },
            executed_transaction.err.?.InstructionError[1],
        );
        try std.testing.expectEqual(null, executed_transaction.log_collector);
        try std.testing.expectEqual(1, executed_transaction.instruction_trace.?.len);
        try std.testing.expectEqual(null, executed_transaction.return_data);
        try std.testing.expectEqual(2_850, executed_transaction.compute_meter);
        try std.testing.expectEqual(0, executed_transaction.accounts_data_len_delta);
    }
}

// key-0=[69, 194, 105, 15, 185, 208, 236, 14, 84, 140, 152, 139, 94, 172, 27, 33, 255, 78, 202, 172, 70, 184, 121, 32, 90, 56, 175, 188, 168, 82, 168, 222]
// sig-0=[155, 87, 32, 223, 129, 117, 229, 211, 253, 25, 4, 87, 248, 101, 175, 208, 252, 84, 33, 26, 139, 231, 160, 168, 5, 101, 229, 82, 6, 40, 202, 102, 30, 192, 249, 188, 158, 62, 213, 190, 41, 196, 41, 42, 238, 243, 75, 189, 76, 90, 219, 158, 130, 91, 173, 235, 84, 62, 161, 156, 157, 127, 204, 0]
// msg_bytes=[128, 1, 0, 6, 14, 69, 194, 105, 15, 185, 208, 236, 14, 84, 140, 152, 139, 94, 172, 27, 33, 255, 78, 202, 172, 70, 184, 121, 32, 90, 56, 175, 188, 168, 82, 168, 222, 20, 88, 152, 7, 137, 134, 165, 173, 129, 171, 162, 69, 217, 115, 213, 202, 150, 43, 59, 21, 139, 72, 22, 224, 112, 142, 184, 129, 182, 212, 86, 247, 28, 114, 129, 159, 43, 49, 150, 40, 77, 183, 38, 250, 239, 67, 62, 53, 181, 71, 135, 70, 159, 88, 64, 50, 100, 195, 106, 223, 233, 211, 227, 179, 161, 130, 196, 60, 93, 68, 170, 211, 126, 158, 71, 9, 134, 253, 16, 67, 150, 103, 132, 103, 125, 153, 218, 163, 161, 72, 86, 36, 63, 9, 141, 39, 167, 205, 217, 27, 101, 95, 133, 97, 33, 100, 129, 109, 116, 140, 216, 129, 5, 229, 1, 85, 119, 151, 78, 250, 82, 211, 28, 191, 242, 94, 177, 164, 202, 218, 201, 239, 208, 158, 153, 150, 156, 135, 143, 166, 228, 55, 157, 194, 84, 225, 214, 18, 95, 128, 103, 34, 46, 122, 208, 128, 181, 91, 24, 172, 218, 208, 183, 151, 57, 203, 88, 33, 157, 102, 177, 86, 250, 127, 156, 147, 126, 77, 55, 245, 6, 21, 86, 89, 214, 228, 168, 183, 7, 101, 176, 177, 248, 160, 244, 97, 158, 163, 151, 6, 77, 98, 107, 101, 204, 228, 107, 160, 108, 212, 114, 115, 17, 157, 73, 38, 17, 102, 30, 92, 157, 26, 224, 67, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 114, 150, 0, 223, 85, 124, 35, 192, 1, 32, 133, 140, 164, 228, 194, 31, 51, 55, 77, 64, 175, 87, 204, 179, 30, 175, 41, 40, 141, 230, 218, 66, 3, 125, 70, 214, 124, 147, 251, 190, 18, 249, 66, 143, 131, 141, 64, 255, 5, 112, 116, 73, 39, 244, 138, 100, 252, 202, 112, 68, 128, 0, 0, 0, 198, 27, 28, 2, 37, 236, 21, 177, 94, 200, 67, 113, 65, 152, 82, 131, 48, 81, 45, 74, 136, 82, 123, 27, 143, 245, 104, 197, 10, 80, 66, 212, 6, 167, 213, 23, 24, 123, 209, 102, 53, 218, 212, 4, 85, 253, 194, 192, 193, 36, 198, 143, 33, 86, 117, 165, 219, 186, 203, 95, 8, 0, 0, 0, 6, 221, 246, 225, 238, 117, 143, 222, 24, 66, 93, 188, 228, 108, 205, 218, 182, 26, 252, 77, 131, 185, 13, 39, 254, 189, 249, 40, 216, 161, 139, 252, 124, 189, 130, 14, 159, 69, 151, 184, 219, 141, 237, 150, 6, 240, 160, 25, 194, 12, 136, 193, 167, 98, 98, 230, 35, 216, 186, 57, 105, 187, 17, 188, 2, 10, 0, 161, 1, 1, 0, 16, 0, 255, 255, 80, 0, 255, 255, 112, 0, 49, 0, 255, 255, 39, 102, 174, 202, 179, 46, 241, 130, 81, 38, 137, 231, 59, 245, 115, 216, 180, 43, 52, 200, 123, 233, 64, 93, 84, 178, 169, 15, 204, 206, 161, 44, 46, 115, 188, 213, 10, 58, 239, 66, 80, 223, 51, 126, 117, 198, 134, 183, 112, 52, 219, 109, 20, 126, 114, 230, 208, 110, 17, 136, 147, 80, 25, 1, 226, 165, 46, 121, 33, 247, 40, 127, 191, 206, 215, 208, 93, 158, 23, 65, 198, 40, 49, 149, 74, 238, 3, 35, 142, 120, 76, 79, 169, 151, 207, 215, 49, 124, 53, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 124, 48, 50, 56, 100, 50, 51, 51, 97, 102, 53, 52, 55, 52, 51, 48, 55, 97, 53, 51, 55, 98, 50, 48, 48, 53, 100, 56, 54, 54, 56, 101, 51, 11, 12, 9, 0, 2, 1, 7, 6, 4, 5, 3, 8, 13, 12, 120, 231, 46, 227, 123, 117, 212, 219, 247, 32, 0, 0, 0, 48, 50, 56, 100, 50, 51, 51, 97, 102, 53, 52, 55, 52, 51, 48, 55, 97, 53, 51, 55, 98, 50, 48, 48, 53, 100, 56, 54, 54, 56, 101, 51, 0, 32, 61, 136, 121, 45, 0, 0, 64, 0, 0, 0, 39, 102, 174, 202, 179, 46, 241, 130, 81, 38, 137, 231, 59, 245, 115, 216, 180, 43, 52, 200, 123, 233, 64, 93, 84, 178, 169, 15, 204, 206, 161, 44, 46, 115, 188, 213, 10, 58, 239, 66, 80, 223, 51, 126, 117, 198, 134, 183, 112, 52, 219, 109, 20, 126, 114, 230, 208, 110, 17, 136, 147, 80, 25, 1, 0]
// test "deserializeProcessedTransaction" {
//     const allocator = std.testing.allocator;

//     const msg_bytes = [_]u8{ 1, 0, 6, 14, 69, 194, 105, 15, 185, 208, 236, 14, 84, 140, 152, 139, 94, 172, 27, 33, 255, 78, 202, 172, 70, 184, 121, 32, 90, 56, 175, 188, 168, 82, 168, 222, 20, 88, 152, 7, 137, 134, 165, 173, 129, 171, 162, 69, 217, 115, 213, 202, 150, 43, 59, 21, 139, 72, 22, 224, 112, 142, 184, 129, 182, 212, 86, 247, 28, 114, 129, 159, 43, 49, 150, 40, 77, 183, 38, 250, 239, 67, 62, 53, 181, 71, 135, 70, 159, 88, 64, 50, 100, 195, 106, 223, 233, 211, 227, 179, 161, 130, 196, 60, 93, 68, 170, 211, 126, 158, 71, 9, 134, 253, 16, 67, 150, 103, 132, 103, 125, 153, 218, 163, 161, 72, 86, 36, 63, 9, 141, 39, 167, 205, 217, 27, 101, 95, 133, 97, 33, 100, 129, 109, 116, 140, 216, 129, 5, 229, 1, 85, 119, 151, 78, 250, 82, 211, 28, 191, 242, 94, 177, 164, 202, 218, 201, 239, 208, 158, 153, 150, 156, 135, 143, 166, 228, 55, 157, 194, 84, 225, 214, 18, 95, 128, 103, 34, 46, 122, 208, 128, 181, 91, 24, 172, 218, 208, 183, 151, 57, 203, 88, 33, 157, 102, 177, 86, 250, 127, 156, 147, 126, 77, 55, 245, 6, 21, 86, 89, 214, 228, 168, 183, 7, 101, 176, 177, 248, 160, 244, 97, 158, 163, 151, 6, 77, 98, 107, 101, 204, 228, 107, 160, 108, 212, 114, 115, 17, 157, 73, 38, 17, 102, 30, 92, 157, 26, 224, 67, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 114, 150, 0, 223, 85, 124, 35, 192, 1, 32, 133, 140, 164, 228, 194, 31, 51, 55, 77, 64, 175, 87, 204, 179, 30, 175, 41, 40, 141, 230, 218, 66, 3, 125, 70, 214, 124, 147, 251, 190, 18, 249, 66, 143, 131, 141, 64, 255, 5, 112, 116, 73, 39, 244, 138, 100, 252, 202, 112, 68, 128, 0, 0, 0, 198, 27, 28, 2, 37, 236, 21, 177, 94, 200, 67, 113, 65, 152, 82, 131, 48, 81, 45, 74, 136, 82, 123, 27, 143, 245, 104, 197, 10, 80, 66, 212, 6, 167, 213, 23, 24, 123, 209, 102, 53, 218, 212, 4, 85, 253, 194, 192, 193, 36, 198, 143, 33, 86, 117, 165, 219, 186, 203, 95, 8, 0, 0, 0, 6, 221, 246, 225, 238, 117, 143, 222, 24, 66, 93, 188, 228, 108, 205, 218, 182, 26, 252, 77, 131, 185, 13, 39, 254, 189, 249, 40, 216, 161, 139, 252, 124, 189, 130, 14, 159, 69, 151, 184, 219, 141, 237, 150, 6, 240, 160, 25, 194, 12, 136, 193, 167, 98, 98, 230, 35, 216, 186, 57, 105, 187, 17, 188, 2, 10, 0, 161, 1, 1, 0, 16, 0, 255, 255, 80, 0, 255, 255, 112, 0, 49, 0, 255, 255, 39, 102, 174, 202, 179, 46, 241, 130, 81, 38, 137, 231, 59, 245, 115, 216, 180, 43, 52, 200, 123, 233, 64, 93, 84, 178, 169, 15, 204, 206, 161, 44, 46, 115, 188, 213, 10, 58, 239, 66, 80, 223, 51, 126, 117, 198, 134, 183, 112, 52, 219, 109, 20, 126, 114, 230, 208, 110, 17, 136, 147, 80, 25, 1, 226, 165, 46, 121, 33, 247, 40, 127, 191, 206, 215, 208, 93, 158, 23, 65, 198, 40, 49, 149, 74, 238, 3, 35, 142, 120, 76, 79, 169, 151, 207, 215, 49, 124, 53, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 124, 48, 50, 56, 100, 50, 51, 51, 97, 102, 53, 52, 55, 52, 51, 48, 55, 97, 53, 51, 55, 98, 50, 48, 48, 53, 100, 56, 54, 54, 56, 101, 51, 11, 12, 9, 0, 2, 1, 7, 6, 4, 5, 3, 8, 13, 12, 120, 231, 46, 227, 123, 117, 212, 219, 247, 32, 0, 0, 0, 48, 50, 56, 100, 50, 51, 51, 97, 102, 53, 52, 55, 52, 51, 48, 55, 97, 53, 51, 55, 98, 50, 48, 48, 53, 100, 56, 54, 54, 56, 101, 51, 0, 32, 61, 136, 121, 45, 0, 0, 64, 0, 0, 0, 39, 102, 174, 202, 179, 46, 241, 130, 81, 38, 137, 231, 59, 245, 115, 216, 180, 43, 52, 200, 123, 233, 64, 93, 84, 178, 169, 15, 204, 206, 161, 44, 46, 115, 188, 213, 10, 58, 239, 66, 80, 223, 51, 126, 117, 198, 134, 183, 112, 52, 219, 109, 20, 126, 114, 230, 208, 110, 17, 136, 147, 80, 25, 1, 0 };
//     var limit_allocator = sig.bincode.LimitAllocator.init(allocator, 1024 * 1024);
//     var fbs = std.io.fixedBufferStream(&msg_bytes);
//     const msg = try sig.core.transaction.Message.deserialize(&limit_allocator, fbs.reader(), .v0);
//     defer msg.deinit(allocator);
//     for (msg.instructions) |ixn| {
//         const program_id = msg.account_keys[ixn.program_index];
//         std.debug.print("program_id: {}\n", .{program_id});
//         std.debug.print("instruction: {any}\n", .{ixn});
//     }
//     std.debug.print("msg: {any}\n", .{msg});

//     const transaction = RuntimeTransaction{
//         .signature_count = 1,
//         .fee_payer = Pubkey.parse("5hK4z4MsSfGANrafVEKnxUcFiN6C9PecZtBQ4A8EimUy"),
//         .msg_hash = Hash.parse(""),
//         .recent_blockhash = Hash.parse("9PwA56XLxCrrmKCa8SZbvDteT1V8jqQMcvDE5UnEm5Gw"),
//         .instructions = &.{
//             .{
//                 .program_meta = .{
//                     .pubkey = msg.account_keys[msg.instructions[0].program_index],
//                     .index_in_transaction = msg.instructions[0].program_index,
//                 },
//                 .account_metas = .{},
//                 .dedup_map = @splat(0xff), // TODO,
//                 .instruction_data = msg.instructions[0].data,
//                 .initial_account_lamports = 0,
//             },
//             .{
//                 .program_meta = .{
//                     .pubkey = msg.account_keys[msg.instructions[1].program_index],
//                     .index_in_transaction = msg.instructions[1].program_index,
//                 },
//                 .account_metas = .{},
//                 .dedup_map = @splat(0xff), // TODO,
//                 .instruction_data = msg.instructions[1].data,
//                 .initial_account_lamports = 0,
//                 }
//             }
//         },
//     };

//     const result = loadAndExecuteTransaction(
//         allocator,
//         &transaction,
//         &batch_account_cache,
//         &env,
//         &config,
//         &program_map,
//     );
// }
