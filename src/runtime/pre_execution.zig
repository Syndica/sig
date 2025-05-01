const std = @import("std");
const builtin = @import("builtin");
const sig = @import("../sig.zig");

const account_loader = sig.runtime.account_loader;
const AccountLoader = account_loader.AccountLoader;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const AccountSharedData = sig.runtime.AccountSharedData;

/// Various constants needed for the block and slot, a reference into accountsdb, and a slice of
/// transactions.
pub fn ProcessingEnv(accountsdb_kind: sig.runtime.account_loader.AccountsDbKind) type {
    return struct {
        const Self = @This();
        const AccountsDb = accountsdb_kind.T();

        // replace with reference to blockhash queue?
        prev_blockhash: sig.core.Hash, // should this be "prev_blockhash"? We use it as one.
        prev_blockhash_lamports_per_signature: u64,

        rent_collector: sig.core.rent_collector.RentCollector,
        slot_context: sig.runtime.SlotContext,
        // TODO: assuming sanitized already (!)
        raw_transactions: []const sig.core.Transaction,
        accounts_db: AccountsDb,
        slot: Slot,

        // epoch_total_stake: ignored - don't see usage

        fn testingDefault(
            transactions: []const sig.core.Transaction,
            accounts_db: AccountsDb,
        ) Self {
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
                .raw_transactions = transactions,
                .accounts_db = accounts_db,
            };
        }
    };
}

pub const TransactionResult = struct {
    pub const Kind = enum { FeesOnly, Executed };
    pub const Result = union(Kind) { FeesOnly: FeesOnly, Executed: Executed };

    // Transaction was not executed. Fees can be collected.
    pub const FeesOnly = struct {
        err: anyerror, // TODO: narrow this to accountsdb load error
        // rollback_accounts: ignored for now, still unclear on what exactly it's for
        // fee_details: ignored - this is passed in
    };

    /// Transaction was executed, may have failed. Fees can be collected.
    pub const Executed = struct {
        loaded_accounts: sig.runtime.account_loader.LoadedAccounts,
        executed_units: u64,
        /// only valid in successful transactions
        accounts_data_len_delta: i64,
        return_data: ?sig.runtime.transaction_context.TransactionReturnData,
        err: ?anyerror, // TODO: narrow to transaction error

        programs_modified_by_tx: void = {}, // TODO: program cache not yet implemented (!)
        // rollback_accounts: ignored for now, still unclear on what exactly it's for
        // fee_details: ignored - this is passed in
        // compute_budget: ignored - this is passed in
        // program_indicies: seems useless, skipping

        pub fn init(
            loaded_accounts: sig.runtime.account_loader.LoadedAccounts,
        ) Executed {
            return .{
                .loaded_accounts = loaded_accounts,
                .executed_units = 0,
                .accounts_data_len_delta = 0,
                .return_data = null,
                .err = null,
            };
        }
    };

    /// null => failed to load accounts | failed to allocate logs
    logs: ?[]const []const u8,
    result: Result,

    fn err(self: TransactionResult) ?anyerror { // TODO: should narrow this
        return switch (self.result) {
            inline .FeesOnly, .Executed => |x| x.err,
        };
    }
};

pub const Output = struct {
    // .len == raw_instructions.len
    processing_results: []const TransactionResult,

    // useful as the account cache effectively de-duplicates account datas (we can't just loop over
    // the accounts and deallocate them one by one)
    arena: std.heap.ArenaAllocator,

    pub fn deinit(self: Output) void {
        self.arena.deinit();
    }
};

// simplified ~= agave's load_and_execute_sanitized_transactions
pub fn loadAndExecuteBatch(
    comptime accountsdb_kind: sig.runtime.account_loader.AccountsDbKind,
    gpa_allocator: std.mem.Allocator,
    env: ProcessingEnv(accountsdb_kind),
) !Output {
    var tmp_arena = std.heap.ArenaAllocator.init(gpa_allocator);
    defer tmp_arena.deinit();
    const tmp_allocator = tmp_arena.allocator();

    var output_arena = std.heap.ArenaAllocator.init(gpa_allocator);
    errdefer output_arena.deinit();
    const output_allocator = output_arena.allocator();

    var loader = try AccountLoader(accountsdb_kind).newWithCacheCapacity(
        output_allocator,
        tmp_allocator,
        env.accounts_db,
        &env.slot_context.ec.feature_set,
        env.rent_collector,
        env.slot,
        // largest-case capacity estimate
        account_keys_sum: {
            var sum: usize = 0;
            for (env.raw_transactions) |tx| sum += tx.msg.account_keys.len;
            break :account_keys_sum sum;
        },
    );
    defer loader.deinit();

    const transaction_result = try output_allocator.alloc(
        TransactionResult,
        env.raw_transactions.len,
    );
    errdefer output_allocator.free(transaction_result);

    // transactions must be executed in order
    for (env.raw_transactions, 0..) |tx, tx_idx| {
        transaction_result[tx_idx].logs = null;
        // now would be a great time to *validate_transaction_nonce_and_fee_payer*
        // not doing it yet. Pretending it's valid for now.

        // TODO: this loop needs a bunch more error handling

        const instr_details = try ComputeBudgetInstructionDetails.fromInstructions(&tx);
        const budget_limits = try instr_details.sanitizeAndConvertToComputeBudgetLimits();
        const compute_budget = budget_limits.intoComputeBudget();

        const loaded_accounts = account_loader.loadTransactionAccountsInner(
            accountsdb_kind,
            tmp_allocator,
            &tx,
            budget_limits.loaded_accounts_bytes,
            &loader,
            &env.slot_context.ec.feature_set,
            &env.rent_collector,
        ) catch |err| {
            transaction_result[tx_idx] = .{
                .result = .{ .FeesOnly = .{ .err = err } },
                .logs = null,
            };
            continue;
        };

        const accounts = loaded_accounts.accounts_buf[0..tx.msg.account_keys.len];

        var ctx = try makeTransactionContext(
            accountsdb_kind,
            tmp_allocator,
            &env,
            accounts,
            &tx,
            compute_budget,
        );

        var tx_executed: TransactionResult = .{
            .logs = null,
            .result = .{ .Executed = TransactionResult.Executed.init(loaded_accounts) },
        };
        defer {
            tx_executed.logs = blk: {
                if (ctx.log_collector) |logger| {
                    break :blk logger.collectCloned(output_allocator) catch null;
                }
                break :blk null;
            };
            transaction_result[tx_idx] = tx_executed;
        }

        executeLoadedTransaction(
            accountsdb_kind,
            tmp_allocator,
            &env,
            &ctx,
            accounts,
            &tx,
        ) catch |err| {
            tx_executed.result.Executed.err = err;
            continue;
        };

        // successful transaction
        tx_executed.result.Executed.executed_units = ctx.compute_meter;
        tx_executed.result.Executed.accounts_data_len_delta = ctx.accounts_resize_delta;
        tx_executed.result.Executed.return_data = ctx.return_data;
    }

    return .{
        .processing_results = transaction_result,
        .arena = output_arena,
    };
}

// [agave] SVMTransactionExecutionBudget
pub const ExecutionBudget = struct {
    /// Number of compute units that a transaction or individual instruction is
    /// allowed to consume. Compute units are consumed by program execution,
    /// resources they use, etc...
    compute_unit_limit: u64,
    /// Maximum program instruction invocation stack depth. Invocation stack
    /// depth starts at 1 for transaction instructions and the stack depth is
    /// incremented each time a program invokes an instruction and decremented
    /// when a program returns.
    max_instruction_stack_depth: usize,
    /// Maximum cross-program invocation and instructions per transaction
    max_instruction_trace_length: usize,
    /// Maximum number of slices hashed per syscall
    sha256_max_slices: u64,
    /// Maximum SBF to BPF call depth
    max_call_depth: usize,
    /// Size of a stack frame in bytes, must match the size specified in the LLVM SBF backend
    stack_frame_size: usize,
    /// Maximum cross-program invocation instruction size
    max_cpi_instruction_size: usize,
    /// program heap region size, default: solana_sdk::entrypoint::HEAP_LENGTH
    heap_size: u32,

    const MAX_COMPUTE_UNIT_LIMIT = 1_400_00;
    const MAX_INSTRUCTION_STACK_DEPTH = 5;
    const MAX_CALL_DEPTH = 64;
    const STACK_FRAME_SIZE = 4096;
    const HEAP_LENGTH = 32 * 1024;

    // [agave] https://github.com/anza-xyz/agave/blob/f4e69de681ea220608524b5e205c4ad3b2e4b871/program-runtime/src/execution_budget.rs#L57
    pub const DEFAULT: ExecutionBudget = .{
        .compute_unit_limit = MAX_COMPUTE_UNIT_LIMIT,
        .max_instruction_stack_depth = 5,
        .max_instruction_trace_length = 64,
        .sha256_max_slices = 20_000,
        .max_call_depth = MAX_CALL_DEPTH,
        .stack_frame_size = STACK_FRAME_SIZE,
        .max_cpi_instruction_size = 1280, // "IPv6 Min MTU size"
        .heap_size = HEAP_LENGTH,
    };
};

pub const FeeDetails = struct { transaction_fee: u64, prioritization_fee: u64 };

// ~= SVMTransactionExecutionAndFeeBudgetLimits
// This should come from the bytes of the transaction, but we don't yet have it
pub const TransactionExecutionDetails = struct {
    pub const MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES = 64 * 1024 * 1024; // MVP <- use this as default

    budget: ExecutionBudget,
    // unused for now, needed for validation
    fee_details: FeeDetails,
    /// non-zero
    loaded_accounts_data_size_limit: u32,
};

fn makeTransactionContext(
    comptime accountsdb_kind: account_loader.AccountsDbKind,
    allocator: std.mem.Allocator,
    env: *const ProcessingEnv(accountsdb_kind),
    accounts: []const AccountSharedData,
    raw_transaction: *const sig.core.Transaction,
    compute_budget: sig.runtime.ComputeBudget,
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
        .compute_meter = 0,
        .custom_error = null,
        // 100KiB max log (we need *a* limit, but this is arbitrary)
        .log_collector = sig.runtime.LogCollector.init(100 * 1024),
        .prev_blockhash = env.prev_blockhash,
        .serialized_accounts = .{},
        .prev_lamports_per_signature = env.prev_blockhash_lamports_per_signature,
        .compute_budget = compute_budget,
    };
}

// ~= agave's process_message
fn executeLoadedTransaction(
    comptime accountsdb_kind: account_loader.AccountsDbKind,
    allocator: std.mem.Allocator,
    env: *const ProcessingEnv(accountsdb_kind),
    ctx: *sig.runtime.TransactionContext,
    accounts: []const AccountSharedData,
    raw_transaction: *const sig.core.Transaction,
) !void {
    _ = env;
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

    var bank = sig.runtime.account_loader.MockedAccountsDb{ .allocator = allocator };
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

    const env = ProcessingEnv(.Mocked).testingDefault(&.{ tx1, tx2, tx4, tx5 }, bank);

    const output = try loadAndExecuteBatch(.Mocked, allocator, env);
    defer output.deinit();

    for (output.processing_results, 0..) |res, i| {
        try switch (i) {
            0, 1 => std.testing.expect(res.err() == null),
            2 => std.testing.expect(res.err().? == error.ProgramAccountNotFound),
            3 => std.testing.expect(res.err().? == error.ComputationalBudgetExceeded), // correct?
            else => unreachable,
        };
    }
}

// [agave] https://github.com/anza-xyz/agave/blob/b70cac38827e499d34c3a521eac17c68fb1b5b1f/compute-budget-instruction/src/compute_budget_instruction_details.rs#L39
const ComputeBudgetInstructionDetails = struct {
    /// unimpl
    const MigrationBuiltinFeatureCounter = struct {};

    const Value32 = struct { instr_idx: u8, value: u32 };
    const Value64 = struct { instr_idx: u8, value: u32 };

    // compute-budget instruction details:
    // the first field in tuple is instruction index, second field is the unsanitized value set by user
    requested_compute_unit_limit: ?Value32,
    requested_compute_unit_price: ?Value64,
    requested_heap_size: ?Value32,
    requested_loaded_accounts_data_size_limit: ?Value32,
    num_non_compute_budget_instructions: u16,
    // Additional builtin program counters
    num_non_migratable_builtin_instructions: u16,
    num_non_builtin_instructions: u16,
    migrating_builtin_feature_counters: MigrationBuiltinFeatureCounter,

    const DEFAULT: ComputeBudgetInstructionDetails = .{
        .requested_compute_unit_limit = null,
        .requested_compute_unit_price = null,
        .requested_heap_size = null,
        .requested_loaded_accounts_data_size_limit = null,
        .num_non_compute_budget_instructions = 0,
        .num_non_migratable_builtin_instructions = 0,
        .num_non_builtin_instructions = 0,
        .migrating_builtin_feature_counters = .{},
    };

    // This impl is a bit of a stub
    // [agave] https://github.com/anza-xyz/agave/blob/b70cac38827e499d34c3a521eac17c68fb1b5b1f/compute-budget-instruction/src/compute_budget_instruction_details.rs#L54
    fn fromInstructions(
        tx: *const sig.core.Transaction,
    ) !ComputeBudgetInstructionDetails {
        const details = DEFAULT;

        for (tx.msg.instructions) |instr| {
            if (tx.msg.account_keys[instr.program_index].equals(
                &sig.runtime.ids.COMPUTE_BUDGET_PROGRAM_ID,
            )) {
                @panic("TODO: compute budget program unsupported");
            }
        }

        return details;
    }

    const MIN_HEAP_FRAME_BYTES = ExecutionBudget.HEAP_LENGTH;
    const MAX_HEAP_FRAME_BYTES = 256 * 1024;
    const DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT = 200_000;
    const MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES = 64 * 1024 * 1024;

    fn sanitizeRequestedHeapSize(bytes: u32) bool {
        return bytes % 1024 == 0 and
            bytes >= MIN_HEAP_FRAME_BYTES and bytes <= MAX_HEAP_FRAME_BYTES;
    }

    fn sanitizeAndConvertToComputeBudgetLimits(
        self: ComputeBudgetInstructionDetails,
    ) !ComputeBudgetLimits {
        const updated_heap_bytes = @min(
            MAX_HEAP_FRAME_BYTES,
            if (self.requested_heap_size) |requested_heap_size| blk: {
                if (sanitizeRequestedHeapSize(requested_heap_size.value)) {
                    break :blk requested_heap_size.value;
                } else {
                    return error.InvalidInstructionData;
                }
            } else MIN_HEAP_FRAME_BYTES,
        );

        // TODO: the real impl for this one is more complicated
        const compute_unit_limit = if (self.requested_compute_unit_limit) |limit|
            limit.value
        else
            DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT;

        const compute_unit_price = if (self.requested_compute_unit_price) |price|
            price.value
        else
            0;

        const loaded_bytes = if (self.requested_loaded_accounts_data_size_limit) |size_limit| blk: {
            if (size_limit.value == 0) return error.InvalidLoadedAccountsDataSizeLimit;
            break :blk @min(MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES, size_limit.value);
        } else MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES;

        return .{
            .updated_heap_bytes = updated_heap_bytes,
            .compute_unit_limit = compute_unit_limit,
            .compute_unit_price = compute_unit_price,
            .loaded_accounts_bytes = loaded_bytes,
        };
    }
};

// [agave] https://github.com/anza-xyz/agave/blob/3e9af14f3a145070773c719ad104b6a02aefd718/compute-budget/src/compute_budget_limits.rs#L28
const ComputeBudgetLimits = struct {
    updated_heap_bytes: u32,
    compute_unit_limit: u32,
    compute_unit_price: u64,
    /// non-zero
    loaded_accounts_bytes: u32,

    fn intoComputeBudget(self: ComputeBudgetLimits) sig.runtime.ComputeBudget {
        var default = sig.runtime.ComputeBudget.default(self.compute_unit_limit);
        default.heap_size = self.updated_heap_bytes;
        return default;
    }
};
