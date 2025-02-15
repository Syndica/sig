const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;

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

pub const Rewards = std.ArrayList(Reward);

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

pub const RewardType = enum {
    Fee,
    Rent,
    Staking,
    Voting,
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

pub const TransactionError = union(enum) {
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
    InstructionError: struct { u8, InstructionError },

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

pub const InstructionError = union(enum) {
    /// Deprecated! Use CustomError instead!
    /// The program instruction returned an error
    GenericError,

    /// The arguments provided to a program were invalid
    InvalidArgument,

    /// An instruction's data contents were invalid
    InvalidInstructionData,

    /// An account's data contents was invalid
    InvalidAccountData,

    /// An account's data was too small
    AccountDataTooSmall,

    /// An account's balance was too small to complete the instruction
    InsufficientFunds,

    /// The account did not have the expected program id
    IncorrectProgramId,

    /// A signature was required but not found
    MissingRequiredSignature,

    /// An initialize instruction was sent to an account that has already been initialized.
    AccountAlreadyInitialized,

    /// An attempt to operate on an account that hasn't been initialized.
    UninitializedAccount,

    /// Program's instruction lamport balance does not equal the balance after the instruction
    UnbalancedInstruction,

    /// Program illegally modified an account's program id
    ModifiedProgramId,

    /// Program spent the lamports of an account that doesn't belong to it
    ExternalAccountLamportSpend,

    /// Program modified the data of an account that doesn't belong to it
    ExternalAccountDataModified,

    /// Read-only account's lamports modified
    ReadonlyLamportChange,

    /// Read-only account's data was modified
    ReadonlyDataModified,

    /// An account was referenced more than once in a single instruction
    // Deprecated, instructions can now contain duplicate accounts
    DuplicateAccountIndex,

    /// Executable bit on account changed, but shouldn't have
    ExecutableModified,

    /// Rent_epoch account changed, but shouldn't have
    RentEpochModified,

    /// The instruction expected additional account keys
    NotEnoughAccountKeys,

    /// Program other than the account's owner changed the size of the account data
    AccountDataSizeChanged,

    /// The instruction expected an executable account
    AccountNotExecutable,

    /// Failed to borrow a reference to account data, already borrowed
    AccountBorrowFailed,

    /// Account data has an outstanding reference after a program's execution
    AccountBorrowOutstanding,

    /// The same account was multiply passed to an on-chain program's entrypoint, but the program
    /// modified them differently.  A program can only modify one instance of the account because
    /// the runtime cannot determine which changes to pick or how to merge them if both are modified
    DuplicateAccountOutOfSync,

    /// Allows on-chain programs to implement program-specific error types and see them returned
    /// by the Solana runtime. A program-specific error may be any type that is represented as
    /// or serialized to a u32 integer.
    Custom: u32,

    /// The return value from the program was invalid.  Valid errors are either a defined builtin
    /// error value or a user-defined error in the lower 32 bits.
    InvalidError,

    /// Executable account's data was modified
    ExecutableDataModified,

    /// Executable account's lamports modified
    ExecutableLamportChange,

    /// Executable accounts must be rent exempt
    ExecutableAccountNotRentExempt,

    /// Unsupported program id
    UnsupportedProgramId,

    /// Cross-program invocation call depth too deep
    CallDepth,

    /// An account required by the instruction is missing
    MissingAccount,

    /// Cross-program invocation reentrancy not allowed for this instruction
    ReentrancyNotAllowed,

    /// Length of the seed is too long for address generation
    MaxSeedLengthExceeded,

    /// Provided seeds do not result in a valid address
    InvalidSeeds,

    /// Failed to reallocate account data of this length
    InvalidRealloc,

    /// Computational budget exceeded
    ComputationalBudgetExceeded,

    /// Cross-program invocation with unauthorized signer or writable account
    PrivilegeEscalation,

    /// Failed to create program execution environment
    ProgramEnvironmentSetupFailure,

    /// Program failed to complete
    ProgramFailedToComplete,

    /// Program failed to compile
    ProgramFailedToCompile,

    /// Account is immutable
    Immutable,

    /// Incorrect authority provided
    IncorrectAuthority,

    /// Failed to serialize or deserialize account data
    ///
    /// Warning: This error should never be emitted by the runtime.
    ///
    /// This error includes strings from the underlying 3rd party Borsh crate
    /// which can be dangerous because the error strings could change across
    /// Borsh versions. Only programs can use this error because they are
    /// consistent across Solana software versions.
    ///
    BorshIoError: []u8,
    /// An account does not have enough lamports to be rent-exempt
    AccountNotRentExempt,

    /// Invalid account owner
    InvalidAccountOwner,

    /// Program arithmetic overflowed
    ArithmeticOverflow,

    /// Unsupported sysvar
    UnsupportedSysvar,

    /// Illegal account owner
    IllegalOwner,

    /// Accounts data allocations exceeded the maximum allowed per transaction
    MaxAccountsDataAllocationsExceeded,

    /// Max accounts exceeded
    MaxAccountsExceeded,

    /// Max instruction trace length exceeded
    MaxInstructionTraceLengthExceeded,

    /// Builtin programs must consume compute units
    BuiltinProgramsMustConsumeComputeUnits,
    // Note: For any new error added here an equivalent ProgramError and its
    // conversions must also be added

    pub fn deinit(self: @This(), allocator: Allocator) void {
        switch (self) {
            .BorshIoError => |it| allocator.free(it),
            else => {},
        }
    }
};
