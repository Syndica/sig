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
const AccountMap = sig.runtime.account_preload.AccountMap;
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

pub const ExecutedTransaction = struct {
    err: ?TransactionError,
    log_collector: ?LogCollector,
    instruction_trace: ?InstructionTrace,
    return_data: ?TransactionReturnData,
    compute_limit: u64,
    compute_meter: u64,
    accounts_data_len_delta: i64,

    pub fn deinit(self: *ExecutedTransaction, allocator: std.mem.Allocator) void {
        if (self.log_collector) |*lc| lc.deinit(allocator);
    }
};

pub const ProcessedTransaction = struct {
    fees: FeeDetails,
    rent: u64,
    writes: Writes,
    err: ?TransactionError,
    /// Analogous to [loaded_accounts_data_size](https://github.com/anza-xyz/agave/blob/10fe1eb29aac9c236fd72d08ae60a3ef61ee8353/svm/src/transaction_processing_result.rs#L97).
    loaded_accounts_data_size: u32,
    /// If null, the transaction did not execute, due to a failure before
    /// execution could begin.
    outputs: ?ExecutedTransaction,

    /// this is populated when a transaction executes and fails. it contains all
    /// the loaded accounts. it's only used for conformance testing.
    /// TODO: come up with a cleaner approach for this
    failed_accounts_for_conformance: ?LoadedTransactionAccounts.Accounts,

    pub const Writes = LoadedTransactionAccounts.Accounts;

    pub fn deinit(self: ProcessedTransaction, allocator: std.mem.Allocator) void {
        for (self.writes.slice()) |account| account.deinit(allocator);
        if (self.outputs) |out| if (out.log_collector) |log| log.deinit(allocator);
        if (self.failed_accounts_for_conformance) |accounts| {
            for (accounts.slice()) |account| account.deinit(allocator);
        }
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
    account_map: *AccountMap,
    environment: *const TransactionExecutionEnvironment,
    config: *const TransactionExecutionConfig,
) error{OutOfMemory}![]TransactionResult(ProcessedTransaction) {
    var program_map = try program_loader.loadPrograms(
        allocator,
        account_map,
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
            account_map,
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
    account_map: *AccountMap,
    env: *const TransactionExecutionEnvironment,
    config: *const TransactionExecutionConfig,
    program_map: *ProgramMap,
) error{OutOfMemory}!TransactionResult(ProcessedTransaction) {
    var zone = tracy.Zone.init(@src(), .{ .name = "executeTransaction" });
    defer zone.deinit();
    errdefer zone.color(0xFF0000);

    var failed_accounts_for_conformance: ?LoadedTransactionAccounts.Accounts = null;

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

    const maybe_nonce_info = switch (try sig.runtime.check_transactions.checkAge(
        allocator,
        transaction,
        account_map,
        env.blockhash_queue,
        env.max_age,
        &env.next_durable_nonce,
        env.next_lamports_per_signature,
    )) {
        .ok => |x| x,
        .err => |e| return .{ .err = e },
    };
    var nonce_account_is_owned = true;
    defer if (nonce_account_is_owned) if (maybe_nonce_info) |n| allocator.free(n.account.data);

    const compute_budget_limits = switch (compute_budget_program.sanitize(
        transaction.compute_budget_instruction_details,
        env.feature_set,
        env.slot,
    )) {
        .ok => |x| x,
        .err => |e| return .{ .err = e },
    };

    if (sig.runtime.check_transactions.checkStatusCache(
        &transaction.msg_hash,
        &transaction.recent_blockhash,
        env.ancestors,
        env.status_cache,
    )) |err| return .{ .err = err };

    nonce_account_is_owned = false;
    const fees, var rollbacks = switch (try sig.runtime.check_transactions.checkFeePayer(
        allocator,
        transaction,
        account_map,
        &compute_budget_limits,
        maybe_nonce_info,
        env.rent_collector,
        env.feature_set,
        env.slot,
        env.lamports_per_signature,
    )) {
        .ok => |x| x,
        .err => |e| return .{ .err = e },
    };
    errdefer for (rollbacks.slice()) |r| r.deinit(allocator);

    var loaded_accounts = switch (try account_loader.loadTransactionAccounts(
        account_map,
        allocator,
        transaction,
        env.rent_collector,
        env.feature_set,
        env.slot,
        &compute_budget_limits,
    )) {
        .ok => |x| x,
        .err => |err| {
            var writes = ProcessedTransaction.Writes{};
            var loaded_accounts_data_size: u32 = 0;
            while (rollbacks.pop()) |rollback| {
                const item = writes.addOne() catch unreachable;
                item.* = rollback;
                account_loader.store(account_map, allocator, item);
                loaded_accounts_data_size += @intCast(rollback.account.data.len);
            }
            return .{ .ok = .{
                .fees = fees,
                .rent = 0,
                .writes = writes,
                .err = err,
                .loaded_accounts_data_size = loaded_accounts_data_size,
                .outputs = null,
                .failed_accounts_for_conformance = failed_accounts_for_conformance,
            } };
        },
    };
    errdefer for (loaded_accounts.accounts.slice()) |acct| acct.deinit(allocator);

    const executed_transaction = try executeTransaction(
        allocator,
        transaction,
        loaded_accounts.accounts.slice(),
        &compute_budget_limits,
        env,
        config,
        program_map,
    );

    var writes = ProcessedTransaction.Writes{};
    if (executed_transaction.err == null) {
        for (
            loaded_accounts.accounts.slice(),
            transaction.accounts.items(.is_writable),
        ) |account, is_writable| {
            if (is_writable)
                writes.append(account) catch unreachable
            else
                account.deinit(allocator);
        }
        while (rollbacks.pop()) |rollback| rollback.deinit(allocator);
    } else {
        while (rollbacks.pop()) |account| writes.append(account) catch unreachable;
        failed_accounts_for_conformance = loaded_accounts.accounts;
    }

    for (writes.slice()) |*acct| account_loader.store(account_map, allocator, acct);

    return .{
        .ok = .{
            .fees = fees,
            .rent = 0,
            .writes = writes,
            .err = executed_transaction.err,
            .loaded_accounts_data_size = loaded_accounts.loaded_accounts_data_size,
            .outputs = executed_transaction,
            .failed_accounts_for_conformance = failed_accounts_for_conformance,
        },
    };
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
    loaded_accounts: []CachedAccount,
    compute_budget_limits: *const ComputeBudgetLimits,
    environment: *const TransactionExecutionEnvironment,
    config: *const TransactionExecutionConfig,
    program_map: *ProgramMap,
) error{OutOfMemory}!ExecutedTransaction {
    var zone = tracy.Zone.init(@src(), .{ .name = "executeTransaction" });
    defer zone.deinit();

    const compute_budget = compute_budget_limits.intoComputeBudget();

    const log_collector = if (config.log)
        try LogCollector.init(allocator, config.log_messages_byte_limit)
    else
        null;

    const accounts = try allocator.alloc(
        TransactionContextAccount,
        loaded_accounts.len,
    );
    defer allocator.free(accounts);
    for (loaded_accounts, 0..) |*account, index| {
        accounts[index] = .{
            .pubkey = account.pubkey,
            .account = &account.account,
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
            .dedupe_map = @splat(0xff),
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
                .dedupe_map = @splat(0xff),
                .instruction_data = "one",
                .initial_account_lamports = 0,
            },
            .{
                .program_meta = .{
                    .pubkey = Pubkey.initRandom(random),
                    .index_in_transaction = 0,
                },
                .account_metas = .{},
                .dedupe_map = @splat(0xff),
                .instruction_data = "two",
                .initial_account_lamports = 0,
            },
            .{
                .program_meta = .{
                    .pubkey = sig.runtime.program.precompiles.ed25519.ID,
                    .index_in_transaction = 0,
                },
                .account_metas = .{},
                .dedupe_map = @splat(0xff),
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
    var account_map: AccountMap = .{};

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
        &account_map,
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
            .dedupe_map = blk: {
                var dedupe_map: [InstructionInfo.MAX_ACCOUNT_METAS]u8 = @splat(0xff);
                dedupe_map[0] = 0;
                dedupe_map[1] = 1;
                break :blk dedupe_map;
            },
            .instruction_data = transfer_instruction_data,
        }},
        .accounts = accounts,
        .num_lookup_tables = 0,
    };

    // Set a compute budget that is sufficient for the transaction to succeed
    transaction.compute_budget_instruction_details.num_non_compute_budget_instructions = 1;
    transaction.compute_budget_instruction_details.num_non_migratable_builtin_instructions = 1;

    var account_map = AccountMap{};
    defer sig.runtime.account_preload.deinit(account_map, allocator);
    try account_map.put(
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
    try account_map.put(
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
    try account_map.put(
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
            &account_map,
            &environment,
            &config,
            &program_map,
        );

        var processed_transaction = result.ok;
        defer processed_transaction.deinit(allocator);

        const executed_transaction = processed_transaction.outputs.?;

        const transaction_fee = processed_transaction.fees.transaction_fee;
        const prioritization_fee = processed_transaction.fees.prioritization_fee;

        const sender_account = account_map.get(sender_key).?;
        const receiver_account = account_map.get(receiver_key).?;

        try std.testing.expectEqual(5_000, transaction_fee);
        try std.testing.expectEqual(0, prioritization_fee);
        try std.testing.expectEqual(0, processed_transaction.rent);
        try std.testing.expectEqual(4_995_000, sender_account.lamports);
        try std.testing.expectEqual(15_000_000, receiver_account.lamports);
        try std.testing.expectEqual(null, processed_transaction.err);
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
            &account_map,
            &environment,
            &config,
            &program_map,
        );

        var processed_transaction = result.ok;
        defer processed_transaction.deinit(allocator);

        const executed_transaction = processed_transaction.outputs.?;

        const transaction_fee = processed_transaction.fees.transaction_fee;
        const prioritization_fee = processed_transaction.fees.prioritization_fee;

        const sender_account = account_map.get(sender_key).?;
        const receiver_account = account_map.get(receiver_key).?;

        try std.testing.expectEqual(5_000, transaction_fee);
        try std.testing.expectEqual(0, prioritization_fee);
        try std.testing.expectEqual(0, processed_transaction.rent);
        try std.testing.expectEqual(4_990_000, sender_account.lamports);
        try std.testing.expectEqual(15_000_000, receiver_account.lamports);
        try std.testing.expectEqual(0, processed_transaction.err.?.InstructionError[0]);
        try std.testing.expectEqual(
            InstructionErrorEnum{ .Custom = 1 },
            processed_transaction.err.?.InstructionError[1],
        );
        try std.testing.expectEqual(null, executed_transaction.log_collector);
        try std.testing.expectEqual(1, executed_transaction.instruction_trace.?.len);
        try std.testing.expectEqual(null, executed_transaction.return_data);
        try std.testing.expectEqual(2_850, executed_transaction.compute_meter);
        try std.testing.expectEqual(0, executed_transaction.accounts_data_len_delta);
    }
}
