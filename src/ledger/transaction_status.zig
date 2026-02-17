const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;
const InstructionErrorEnum = sig.core.instruction.InstructionErrorEnum;
const Pubkey = sig.core.Pubkey;
const RewardType = sig.replay.rewards.RewardType;

pub const TransactionStatusMeta = struct {
    /// Indicates whether the transaction succeeded, or exactly what error caused it to fail
    status: ?TransactionError,
    /// Transaction fee that was paid by the fee payer.
    fee: u64,
    /// Lamport balances of every account in this transaction before it was executed.
    pre_balances: []const u64,
    /// Lamport balances of every account in this transaction after it was executed.
    post_balances: []const u64,
    /// Instructions that were executed as part of this transaction.
    inner_instructions: ?[]const InnerInstructions,
    /// Messages that were printed by the programs as they executed the instructions.
    log_messages: ?[]const []const u8,
    /// SPL Token account balances of every account in this transaction before it was executed.
    pre_token_balances: ?[]const TransactionTokenBalance,
    /// SPL Token account balances of every account in this transaction after it was executed.
    post_token_balances: ?[]const TransactionTokenBalance,
    /// Block rewards issued to the leader for executing this transaction.
    rewards: ?[]const Reward,
    /// Addresses for any accounts that were used in the transaction.
    loaded_addresses: LoadedAddresses,
    /// The return value that was provided by the last instruction to have a return value.
    return_data: ?TransactionReturnData,
    /// The amount of BPF instructions that were executed in order to complete this transaction.
    compute_units_consumed: ?u64,
    /// The total cost units for this transaction, used for block scheduling/packing.
    /// This is the sum of: signature_cost + write_lock_cost + data_bytes_cost +
    /// programs_execution_cost + loaded_accounts_data_size_cost.
    cost_units: ?u64,

    pub const EMPTY_FOR_TEST = TransactionStatusMeta{
        .status = null,
        .fee = 0,
        .pre_balances = &.{},
        .post_balances = &.{},
        .inner_instructions = null,
        .log_messages = null,
        .pre_token_balances = null,
        .post_token_balances = null,
        .rewards = null,
        .loaded_addresses = .{},
        .return_data = null,
        .compute_units_consumed = null,
        .cost_units = null,
    };

    pub fn deinit(self: @This(), allocator: Allocator) void {
        allocator.free(self.pre_balances);
        allocator.free(self.post_balances);
        if (self.log_messages) |log_messages| allocator.free(log_messages);
        inline for (.{
            self.inner_instructions,
            self.pre_token_balances,
            self.post_token_balances,
            self.rewards,
        }) |maybe_slice| {
            if (maybe_slice) |slice| {
                allocator.free(slice);
            }
        }
        self.loaded_addresses.deinit(allocator);
        if (self.return_data) |it| it.deinit(allocator);
    }
};

pub const InnerInstructions = struct {
    /// Transaction instruction index
    index: u8,
    /// List of inner instructions
    instructions: []const InnerInstruction,

    pub fn deinit(self: @This(), allocator: Allocator) void {
        for (self.instructions) |ix| ix.deinit(allocator);
        allocator.free(self.instructions);
    }
};

pub const InnerInstruction = struct {
    /// Compiled instruction
    instruction: CompiledInstruction,
    /// Invocation stack height of the instruction,
    stack_height: ?u32,

    pub fn deinit(self: @This(), allocator: Allocator) void {
        self.instruction.deinit(allocator);
    }
};

pub const CompiledInstruction = struct {
    /// Index into the transaction keys array indicating the program account that executes this instruction.
    program_id_index: u8,
    /// Ordered indices into the transaction keys array indicating which accounts to pass to the program.
    accounts: []const u8,
    /// The program input data.
    data: []const u8,

    pub fn deinit(self: @This(), allocator: Allocator) void {
        allocator.free(self.accounts);
        allocator.free(self.data);
    }
};

pub const TransactionTokenBalance = struct {
    account_index: u8,
    mint: Pubkey,
    ui_token_amount: UiTokenAmount,
    owner: Pubkey,
    program_id: Pubkey,

    pub fn deinit(self: @This(), allocator: Allocator) void {
        self.ui_token_amount.deinit(allocator);
    }
};

pub const UiTokenAmount = struct {
    ui_amount: ?f64,
    decimals: u8,
    amount: []const u8,
    ui_amount_string: []const u8,

    pub fn deinit(self: @This(), allocator: Allocator) void {
        allocator.free(self.amount);
        allocator.free(self.ui_amount_string);
    }
};

pub const Rewards = std.array_list.Managed(Reward);

pub const Reward = struct {
    pubkey: Pubkey,
    lamports: i64,
    /// Account balance in lamports after `lamports` was applied
    post_balance: u64,
    reward_type: ?RewardType,
    /// Vote account commission when the reward was credited, only present for voting and staking rewards
    commission: ?u8,
};

pub const LoadedAddresses = struct {
    /// List of addresses for writable loaded accounts
    writable: []const Pubkey = &.{},
    /// List of addresses for read-only loaded accounts
    readonly: []const Pubkey = &.{},

    pub fn deinit(self: @This(), allocator: Allocator) void {
        allocator.free(self.writable);
        allocator.free(self.readonly);
    }
};

pub const TransactionReturnData = struct {
    program_id: Pubkey = Pubkey.ZEROES,
    data: []const u8 = &.{},

    pub fn deinit(self: @This(), allocator: Allocator) void {
        allocator.free(self.data);
    }
};

/// Builder for creating TransactionStatusMeta from execution results.
/// This is used by the replay system to persist transaction status metadata
/// to the ledger for RPC queries like getBlock and getTransaction.
pub const TransactionStatusMetaBuilder = struct {
    const runtime = sig.runtime;
    const TransactionContext = runtime.transaction_context.TransactionContext;
    const LogCollector = runtime.LogCollector;
    const InstructionTrace = TransactionContext.InstructionTrace;
    const RuntimeInstructionInfo = runtime.InstructionInfo;
    const RuntimeTransactionReturnData = runtime.transaction_context.TransactionReturnData;
    const ProcessedTransaction = runtime.transaction_execution.ProcessedTransaction;
    const ExecutedTransaction = runtime.transaction_execution.ExecutedTransaction;

    /// Build TransactionStatusMeta from a ProcessedTransaction and pre-captured balances.
    ///
    /// Arguments:
    /// - allocator: Used to allocate the returned slices (caller owns the memory)
    /// - processed_tx: The result of transaction execution
    /// - pre_balances: Lamport balances of accounts before execution (caller must capture these)
    /// - post_balances: Lamport balances of accounts after execution (caller must capture these)
    /// - loaded_addresses: Addresses loaded from address lookup tables
    /// - pre_token_balances: SPL Token balances before execution (optional)
    /// - post_token_balances: SPL Token balances after execution (optional)
    ///
    /// Returns owned TransactionStatusMeta that must be freed with deinit().
    pub fn build(
        allocator: Allocator,
        processed_tx: ProcessedTransaction,
        pre_balances: []const u64,
        post_balances: []const u64,
        loaded_addresses: LoadedAddresses,
        pre_token_balances: ?[]const TransactionTokenBalance,
        post_token_balances: ?[]const TransactionTokenBalance,
    ) error{OutOfMemory}!TransactionStatusMeta {
        // Convert log messages from LogCollector
        const log_messages: ?[]const []const u8 = if (processed_tx.outputs) |outputs| blk: {
            if (outputs.log_collector) |log_collector| {
                break :blk try extractLogMessages(allocator, log_collector);
            }
            break :blk null;
        } else null;
        errdefer if (log_messages) |logs| allocator.free(logs);

        // Convert inner instructions from InstructionTrace
        const inner_instructions = if (processed_tx.outputs) |outputs| blk: {
            if (outputs.instruction_trace) |trace| {
                break :blk try convertInstructionTrace(allocator, trace);
            }
            break :blk null;
        } else null;
        errdefer if (inner_instructions) |inner| {
            for (inner) |item| item.deinit(allocator);
            allocator.free(inner);
        };

        // Convert return data
        const return_data: ?TransactionReturnData = if (processed_tx.outputs) |outputs| blk: {
            if (outputs.return_data) |rd| {
                break :blk try convertReturnData(allocator, rd);
            }
            break :blk null;
        } else null;
        errdefer if (return_data) |rd| rd.deinit(allocator);

        // Calculate compute units consumed
        const compute_units_consumed: ?u64 = if (processed_tx.outputs) |outputs|
            outputs.compute_limit - outputs.compute_meter
        else
            null;

        // Copy balances (caller provided these, we need to own them)
        const owned_pre_balances = try allocator.dupe(u64, pre_balances);
        errdefer allocator.free(owned_pre_balances);

        const owned_post_balances = try allocator.dupe(u64, post_balances);
        errdefer allocator.free(owned_post_balances);

        // Copy loaded addresses
        const owned_loaded_addresses = LoadedAddresses{
            .writable = try allocator.dupe(sig.core.Pubkey, loaded_addresses.writable),
            .readonly = try allocator.dupe(sig.core.Pubkey, loaded_addresses.readonly),
        };

        return TransactionStatusMeta{
            .status = processed_tx.err,
            .fee = processed_tx.fees.total(),
            .pre_balances = owned_pre_balances,
            .post_balances = owned_post_balances,
            .inner_instructions = inner_instructions,
            .log_messages = log_messages,
            .pre_token_balances = pre_token_balances,
            .post_token_balances = post_token_balances,
            .rewards = null, // Transaction-level rewards are not typically populated
            .loaded_addresses = owned_loaded_addresses,
            .return_data = return_data,
            .compute_units_consumed = compute_units_consumed,
            .cost_units = processed_tx.cost_units,
        };
    }

    /// Extract log messages from a LogCollector into an owned slice.
    fn extractLogMessages(
        allocator: Allocator,
        log_collector: LogCollector,
    ) error{OutOfMemory}![]const []const u8 {
        // Count messages first
        var count: usize = 0;
        var iter = log_collector.iterator();
        while (iter.next()) |_| {
            count += 1;
        }

        if (count == 0) return &.{};

        const messages = try allocator.alloc([]const u8, count);
        errdefer allocator.free(messages);

        iter = log_collector.iterator();
        var i: usize = 0;
        while (iter.next()) |msg| : (i += 1) {
            // The log collector returns sentinel-terminated strings, we just store the slice
            messages[i] = msg;
        }

        return messages;
    }

    /// Convert InstructionTrace to InnerInstructions array.
    /// The trace contains all CPI calls; we need to group them by top-level instruction index.
    fn convertInstructionTrace(
        allocator: Allocator,
        trace: InstructionTrace,
    ) error{OutOfMemory}![]const InnerInstructions {
        if (trace.len == 0) return &.{};

        // Group instructions by their top-level instruction index (depth == 1 starts a new group)
        // Instructions at depth > 1 are inner instructions of the most recent depth == 1 instruction

        var result = std.ArrayList(InnerInstructions).init(allocator);
        errdefer {
            for (result.items) |item| item.deinit(allocator);
            result.deinit();
        }

        var current_inner = std.ArrayList(InnerInstruction).init(allocator);
        defer current_inner.deinit();

        var current_top_level_index: u8 = 0;
        var has_top_level: bool = false;

        for (trace.slice()) |entry| {
            if (entry.depth == 1) {
                // This is a top-level instruction - flush previous group if any
                if (has_top_level and current_inner.items.len > 0) {
                    try result.append(InnerInstructions{
                        .index = current_top_level_index,
                        .instructions = try current_inner.toOwnedSlice(),
                    });
                }
                current_inner.clearRetainingCapacity();
                current_top_level_index = @intCast(result.items.len);
                has_top_level = true;
            } else if (entry.depth > 1) {
                // This is an inner instruction (CPI)
                const inner = try convertToInnerInstruction(allocator, entry.ixn_info, entry.depth);
                try current_inner.append(inner);
            }
        }

        // Flush final group
        if (has_top_level and current_inner.items.len > 0) {
            try result.append(InnerInstructions{
                .index = current_top_level_index,
                .instructions = try current_inner.toOwnedSlice(),
            });
        }

        return try result.toOwnedSlice();
    }

    /// Convert a single instruction from InstructionInfo to InnerInstruction format.
    fn convertToInnerInstruction(
        allocator: Allocator,
        ixn_info: RuntimeInstructionInfo,
        depth: u8,
    ) error{OutOfMemory}!InnerInstruction {
        // Build account indices array
        const accounts = try allocator.alloc(u8, ixn_info.account_metas.items.len);
        errdefer allocator.free(accounts);

        for (ixn_info.account_metas.items, 0..) |meta, i| {
            accounts[i] = @intCast(meta.index_in_transaction);
        }

        // Copy instruction data
        const data = try allocator.dupe(u8, ixn_info.instruction_data);
        errdefer allocator.free(data);

        return InnerInstruction{
            .instruction = CompiledInstruction{
                .program_id_index = @intCast(ixn_info.program_meta.index_in_transaction),
                .accounts = accounts,
                .data = data,
            },
            .stack_height = depth,
        };
    }

    /// Convert runtime TransactionReturnData to ledger TransactionReturnData.
    fn convertReturnData(
        allocator: Allocator,
        rd: RuntimeTransactionReturnData,
    ) error{OutOfMemory}!TransactionReturnData {
        return TransactionReturnData{
            .program_id = rd.program_id,
            .data = try allocator.dupe(u8, rd.data.slice()),
        };
    }
};

pub const TransactionError = union(enum(u32)) {
    /// An account is already being processed in another transaction in a way
    /// that does not support parallelism
    AccountInUse,

    /// A `Pubkey` appears twice in the transaction's `account_keys`.  Instructions can reference
    /// `Pubkey`s more than once but the message must contain a list with no duplicate keys
    AccountLoadedTwice,

    /// Attempt to debit an account but found no record of a prior credit.
    AccountNotFound,

    /// Attempt to load a program that does not exist
    ProgramAccountNotFound,

    /// The from `Pubkey` does not have sufficient balance to pay the fee to schedule the transaction
    InsufficientFundsForFee,

    /// This account may not be used to pay transaction fees
    InvalidAccountForFee,

    /// The bank has seen this transaction before. This can occur under normal operation
    /// when a UDP packet is duplicated, as a user error from a client not updating
    /// its `recent_blockhash`, or as a double-spend attack.
    AlreadyProcessed,

    /// The bank has not seen the given `recent_blockhash` or the transaction is too old and
    /// the `recent_blockhash` has been discarded.
    BlockhashNotFound,

    /// An error occurred while processing an instruction. The first element of the tuple
    /// indicates the instruction index in which the error occurred.
    InstructionError: struct { u8, InstructionErrorEnum },

    /// Loader call chain is too deep
    CallChainTooDeep,

    /// Transaction requires a fee but has no signature present
    MissingSignatureForFee,

    /// Transaction contains an invalid account reference
    InvalidAccountIndex,

    /// Transaction did not pass signature verification
    SignatureFailure,

    /// This program may not be used for executing instructions
    InvalidProgramForExecution,

    /// Transaction failed to sanitize accounts offsets correctly
    /// implies that account locks are not taken for this TX, and should
    /// not be unlocked.
    SanitizeFailure,

    ClusterMaintenance,

    /// Transaction processing left an account with an outstanding borrowed reference
    AccountBorrowOutstanding,

    /// Transaction would exceed max Block Cost Limit
    WouldExceedMaxBlockCostLimit,

    /// Transaction version is unsupported
    UnsupportedVersion,

    /// Transaction loads a writable account that cannot be written
    InvalidWritableAccount,

    /// Transaction would exceed max account limit within the block
    WouldExceedMaxAccountCostLimit,

    /// Transaction would exceed account data limit within the block
    WouldExceedAccountDataBlockLimit,

    /// Transaction locked too many accounts
    TooManyAccountLocks,

    /// Address lookup table not found
    AddressLookupTableNotFound,

    /// Attempted to lookup addresses from an account owned by the wrong program
    InvalidAddressLookupTableOwner,

    /// Attempted to lookup addresses from an invalid account
    InvalidAddressLookupTableData,

    /// Address table lookup uses an invalid index
    InvalidAddressLookupTableIndex,

    /// Transaction leaves an account with a lower balance than rent-exempt minimum
    InvalidRentPayingAccount,

    /// Transaction would exceed max Vote Cost Limit
    WouldExceedMaxVoteCostLimit,

    /// Transaction would exceed total account data limit
    WouldExceedAccountDataTotalLimit,

    /// Transaction contains a duplicate instruction that is not allowed
    DuplicateInstruction: u8,

    /// Transaction results in an account with insufficient funds for rent
    InsufficientFundsForRent: struct { account_index: u8 },

    /// Transaction exceeded max loaded accounts data size cap
    MaxLoadedAccountsDataSizeExceeded,

    /// LoadedAccountsDataSizeLimit set for transaction must be greater than 0.
    InvalidLoadedAccountsDataSizeLimit,

    /// Sanitized transaction differed before/after feature activiation. Needs to be resanitized.
    ResanitizationNeeded,

    /// Program execution is temporarily restricted on an account.
    ProgramExecutionTemporarilyRestricted: struct { account_index: u8 },

    /// The total balance before the transaction does not equal the total balance after the transaction
    UnbalancedTransaction,

    /// Program cache hit max limit.
    ProgramCacheHitMaxLimit,

    pub fn deinit(self: @This(), allocator: Allocator) void {
        switch (self) {
            .InstructionError => |it| it[1].deinit(allocator),
            else => {},
        }
    }

    /// Serialize to JSON matching Agave's serde format for UiTransactionError.
    /// - Unit variants: "VariantName"
    /// - Tuple variants: {"VariantName": value}
    /// - Struct variants: {"VariantName": {"field": value}}
    /// - InstructionError: {"InstructionError": [index, error]}
    pub fn jsonStringify(self: @This(), jw: anytype) !void {
        switch (self) {
            .InstructionError => |payload| {
                try jw.beginObject();
                try jw.objectField("InstructionError");
                try jw.beginArray();
                try jw.write(payload.@"0");
                switch (payload.@"1") {
                    .BorshIoError => try jw.write("BorshIoError"),
                    inline else => |inner_payload, tag| {
                        if (@TypeOf(inner_payload) == void) {
                            try jw.write(@tagName(tag));
                        } else {
                            try jw.beginObject();
                            try jw.objectField(@tagName(tag));
                            try jw.write(inner_payload);
                            try jw.endObject();
                        }
                    },
                }
                try jw.endArray();
                try jw.endObject();
            },
            inline else => |payload, tag| {
                if (@TypeOf(payload) == void) {
                    try jw.write(@tagName(tag));
                } else {
                    try jw.beginObject();
                    try jw.objectField(@tagName(tag));
                    try jw.write(payload);
                    try jw.endObject();
                }
            },
        }
    }
};

test "TransactionError jsonStringify" {
    const expectJsonStringify = struct {
        fn run(expected: []const u8, value: TransactionError) !void {
            const actual = try std.json.stringifyAlloc(std.testing.allocator, value, .{});
            defer std.testing.allocator.free(actual);
            try std.testing.expectEqualStrings(expected, actual);
        }
    }.run;

    // InstructionError with Custom inner error (matches Agave test)
    try expectJsonStringify(
        \\{"InstructionError":[42,{"Custom":3735928559}]}
    ,
        .{ .InstructionError = .{ 42, .{ .Custom = 0xdeadbeef } } },
    );

    // Struct variant: InsufficientFundsForRent (matches Agave test)
    try expectJsonStringify(
        \\{"InsufficientFundsForRent":{"account_index":42}}
    ,
        .{ .InsufficientFundsForRent = .{ .account_index = 42 } },
    );

    // Single-value tuple variant: DuplicateInstruction (matches Agave test)
    try expectJsonStringify(
        \\{"DuplicateInstruction":42}
    ,
        .{ .DuplicateInstruction = 42 },
    );

    // Unit variant (matches Agave test)
    try expectJsonStringify(
        \\"InsufficientFundsForFee"
    ,
        .InsufficientFundsForFee,
    );

    // InstructionError with BorshIoError (serialized as unit variant per Agave v3)
    try expectJsonStringify(
        \\{"InstructionError":[0,"BorshIoError"]}
    ,
        .{ .InstructionError = .{ 0, .{ .BorshIoError = @constCast("Unknown") } } },
    );
}
