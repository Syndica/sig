const std = @import("std");
const std14 = @import("std14");
const sig = @import("../lib.zig");
const tracy = @import("tracy");

const loaded_accounts_mod = @import("loaded_accounts.zig");
const program_loader = sig.runtime.program_loader;
const executor = sig.runtime.executor;
const compute_budget_program = sig.runtime.program.compute_budget;
const cost_model = sig.runtime.cost_model;
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

const LoadedAccount = loaded_accounts_mod.LoadedAccount;
const FeatureSet = sig.core.FeatureSet;
const FeeDetails = @import("fee_details.zig").FeeDetails;
const InstructionInfo = sig.runtime.InstructionInfo;
const LoadedTransactionAccounts = loaded_accounts_mod.LoadedTransactionAccounts;
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

const AccountLoadError = loaded_accounts_mod.AccountLoadError;

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
    is_simple_vote_transaction: bool,
};

pub const TransactionExecutionConfig = struct {
    log: bool,
    log_messages_byte_limit: ?u64,

    /// Optionally pass in a pointer here to have it populated it with all
    /// loaded accounts when a transaction executes and fails. The list is
    /// assumed to be empty, and any pre-existing entries in the list will be
    /// discarded when this list is repopulated.
    ///
    /// These accounts are not useful to persist on-chain, but can be used to
    /// debug a transaction failure. The original use case for this was
    /// conformance testing.
    failed_accounts: ?*LoadedTransactionAccounts.Accounts = null,
};

pub const ExecutedTransaction = struct {
    err: ?TransactionError,
    log_collector: ?LogCollector,
    instruction_trace: ?InstructionTrace,
    return_data: ?TransactionReturnData,
    executed_units: u64,
    compute_limit: u64,
    compute_meter: u64,
    accounts_data_len_delta: i64,

    pub fn deinit(self: *const ExecutedTransaction, allocator: std.mem.Allocator) void {
        if (self.log_collector) |*lc| lc.deinit(allocator);
        // Top-level instructions (depth == 1) are owned by the RuntimeTransaction.
        // Only CPI instructions (depth > 1) are owned by this trace.
        if (self.instruction_trace) |trace| for (trace.slice()) |entry| {
            if (entry.depth > 1) {
                entry.ixn_info.deinit(allocator);
            }
        };
    }

    pub fn total_cost(self: *const ExecutedTransaction) u64 {
        return self.executed_units;
    }
};

pub fn TransactionResult(comptime T: type) type {
    return union(enum(u8)) {
        ok: T,
        err: TransactionError,
    };
}

pub const ExecutionEnvironment = struct {
    feature_set: *const FeatureSet,
    sysvar_cache: *const SysvarCache,
    rent_collector: *const RentCollector,
    epoch_stakes: *const EpochStakes,
    vm_environment: *const vm.Environment,
    next_vm_environment: ?*const vm.Environment,

    slot: u64,
    last_blockhash: Hash,
    last_lamports_per_signature: u64,
};

/// [agave] https://github.com/firedancer-io/agave/blob/403d23b809fc513e2c4b433125c127cf172281a2/svm/src/transaction_processor.rs#L909
pub fn executeTransaction(
    allocator: std.mem.Allocator,
    programs_allocator: std.mem.Allocator,
    transaction: *const RuntimeTransaction,
    /// transaction execution modifies accounts, which is implemented by
    /// directly mutating the data in this slice
    loaded_accounts: []LoadedAccount,
    compute_budget_limits: *const ComputeBudgetLimits,
    environment: *const ExecutionEnvironment,
    config: *const TransactionExecutionConfig,
    /// may be mutated by the bpf loader
    program_map: *ProgramMap,
) error{OutOfMemory}!ExecutedTransaction {
    var zone = tracy.Zone.init(@src(), .{ .name = "executeTransaction" });
    defer zone.deinit();

    const compute_budget = compute_budget_limits.intoComputeBudget(
        environment.feature_set,
        environment.slot,
    );

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
        .programs_allocator = programs_allocator,
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
        .executed_units = tc.consumed_units,
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

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
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
            .dedupe_map = @splat(0xffff),
            .instruction_data = "data",
            .owned_instruction_data = false,
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
                .dedupe_map = @splat(0xffff),
                .instruction_data = "one",
                .owned_instruction_data = false,
                .initial_account_lamports = 0,
            },
            .{
                .program_meta = .{
                    .pubkey = Pubkey.initRandom(random),
                    .index_in_transaction = 0,
                },
                .account_metas = .{},
                .dedupe_map = @splat(0xffff),
                .instruction_data = "two",
                .owned_instruction_data = false,
                .initial_account_lamports = 0,
            },
            .{
                .program_meta = .{
                    .pubkey = sig.runtime.program.precompiles.ed25519.ID,
                    .index_in_transaction = 0,
                },
                .account_metas = .{},
                .dedupe_map = @splat(0xffff),
                .instruction_data = "three",
                .owned_instruction_data = false,
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
