const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;
const InstructionErrorEnum = sig.core.instruction.InstructionErrorEnum;
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
                for (slice) |item| item.deinit(allocator);
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
    mint: []const u8,
    ui_token_amount: UiTokenAmount,
    owner: []const u8,
    program_id: []const u8,

    pub fn deinit(self: @This(), allocator: Allocator) void {
        self.ui_token_amount.deinit(allocator);
        allocator.free(self.mint);
        allocator.free(self.owner);
        allocator.free(self.program_id);
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
    pubkey: []const u8,
    lamports: i64,
    /// Account balance in lamports after `lamports` was applied
    post_balance: u64,
    reward_type: ?RewardType,
    /// Vote account commission when the reward was credited, only present for voting and staking rewards
    commission: ?u8,

    pub fn deinit(self: @This(), allocator: Allocator) void {
        allocator.free(self.pubkey);
    }
};

pub const LoadedAddresses = struct {
    /// List of addresses for writable loaded accounts
    writable: []const sig.core.Pubkey = &.{},
    /// List of addresses for read-only loaded accounts
    readonly: []const sig.core.Pubkey = &.{},

    pub fn deinit(self: @This(), allocator: Allocator) void {
        allocator.free(self.writable);
        allocator.free(self.readonly);
    }
};

pub const TransactionReturnData = struct {
    program_id: sig.core.Pubkey = sig.core.Pubkey.ZEROES,
    data: []const u8 = &.{},

    pub fn deinit(self: @This(), allocator: Allocator) void {
        allocator.free(self.data);
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
};
