const std = @import("std");
pub const Pubkey = @import("../core/pubkey.zig").Pubkey;
const json = std.json;
pub const Hash = @import("../core/hash.zig").Hash;
const SocketAddr = @import("../net/net.zig").SocketAddr;
pub const Signature = @import("../core/signature.zig").Signature;
const InstructionError = @import("../core/transaction.zig").InstructionError;
var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const gpa_allocator = gpa.allocator();

pub const Slot = u64;
pub const Epoch = u64;
pub const UnixTimestamp = i64;

pub const jrpc_error_code_parse_error: i32 = -32700;
pub const jrpc_error_code_invalid_request: i32 = -32600;
pub const jrpc_error_code_method_not_found: i32 = -32601;
pub const jrpc_error_code_invalid_params: i32 = -32602;
pub const jrpc_error_code_internal_error: i32 = -32603;

pub const Error = union(enum(u8)) {
    BlockCleanedUp: struct {
        slot: Slot,
        first_available_block: Slot,
    },
    SendTransactionPreflightFailure: struct {
        message: []const u8,
        result: RpcSimulateTransactionResult,
    },
    TransactionSignatureVerificationFailure,
    BlockNotAvailable: struct {
        slot: Slot,
    },
    NodeUnhealthy: struct {
        num_slots_behind: ?Slot,
    },
    TransactionPrecompileVerificationFailure: TransactionError,
    SlotSkipped: struct {
        slot: Slot,
    },
    NoSnapshot,
    LongTermStorageSlotSkipped: struct {
        slot: Slot,
    },
    KeyExcludedFromSecondaryIndex: struct {
        index_key: []const u8,
    },
    TransactionHistoryNotAvailable,
    ScanError: struct {
        message: []const u8,
    },
    TransactionSignatureLenMismatch,
    BlockStatusNotAvailableYet: struct {
        slot: Slot,
    },
    UnsupportedTransactionVersion: u8,
    MinContextSlotNotReached: struct {
        context_slot: Slot,
    },
    Unimplemented,
    Internal,

    pub fn toErrorObject(self: *const Error) ErrorObject {
        return switch (self.*) {
            .Unimplemented => ErrorObject.init(jrpc_error_code_internal_error, "not implemented"),
            .Internal => ErrorObject.init(jrpc_error_code_internal_error, "internal error"),
            else => ErrorObject.init(jrpc_error_code_invalid_request, "invalid request"),
        };
    }
};

// TODO: incorporate a way to `free` memory allocated
pub fn Result(comptime T: type) type {
    return union(enum(u8)) {
        Ok: T,
        Err: Error,
    };
}

pub fn RpcServiceImpl(comptime Self: type) type {
    return struct {
        getAccountInfo: *const fn (ctx: *Self, allocator: std.mem.Allocator, pubkey: Pubkey, config: ?RpcAccountInfoConfig) Result(RpcResponse(?UiAccount)),
        getBalance: *const fn (ctx: *Self, allocator: std.mem.Allocator, pubkey: Pubkey, config: RpcContextConfig) Result(RpcResponse(u64)),
        getBlock: *const fn (ctx: *Self, allocator: std.mem.Allocator, slot: Slot, config: ?RpcBlockConfig) Result(UiConfirmedBlock),
        getBlockCommitment: *const fn (ctx: *Self, allocator: std.mem.Allocator, block: Slot) Result(RpcBlockCommitment),
        getBlockHeight: *const fn (ctx: *Self, allocator: std.mem.Allocator, config: RpcContextConfig) Result(u64),
        getBlockProduction: *const fn (ctx: *Self, allocator: std.mem.Allocator, config: ?RpcBlockProductionConfig) Result(RpcResponse(RpcBlockProduction)),
        getBlocks: *const fn (ctx: *Self, allocator: std.mem.Allocator, start_slot: Slot, end_slot: Slot, commitment: ?CommitmentConfig) Result([]Slot),
        getBlocksWithLimit: *const fn (ctx: *Self, allocator: std.mem.Allocator, start_slot: Slot, limit: usize, commitment: ?CommitmentConfig) Result([]Slot),
        getBlockTime: *const fn (ctx: *Self, allocator: std.mem.Allocator, slot: Slot) Result(?UnixTimestamp),
        getClusterNodes: *const fn (ctx: *Self, allocator: std.mem.Allocator) Result([]RpcContactInfo),
        getConfirmedBlock: *const fn (ctx: *Self, allocator: std.mem.Allocator, slot: Slot, config: RpcEncodingConfigWrapper(RpcConfirmedBlockConfig)) Result(?UiConfirmedBlock),
        getConfirmedBlocks: *const fn (ctx: *Self, allocator: std.mem.Allocator, start_slot: Slot, config: ?RpcConfirmedBlocksConfigWrapper, commitment: ?CommitmentConfig) Result([]Slot),
        getConfirmedBlocksWithLimit: *const fn (ctx: *Self, allocator: std.mem.Allocator, start_slot: Slot, limit: usize, commitment: ?CommitmentConfig) Result([]Slot),
        getConfirmedSignaturesForAddress2: *const fn (ctx: *Self, allocator: std.mem.Allocator, address: []const u8, config: ?RpcGetConfirmedSignaturesForAddress2Config) Result([]RpcConfirmedTransactionStatusWithSignature),
        getConfirmedTransaction: *const fn (ctx: *Self, allocator: std.mem.Allocator, signature: []const u8, config: ?RpcEncodingConfigWrapper(RpcConfirmedTransactionConfig)) Result(?EncodedConfirmedTransactionWithStatusMeta),
        getEpochInfo: *const fn (ctx: *Self, allocator: std.mem.Allocator, config: ?RpcContextConfig) Result(EpochInfo),
        getEpochSchedule: *const fn (ctx: *Self, allocator: std.mem.Allocator) Result(EpochSchedule),
        getFeeCalculatorForBlockhash: *const fn (ctx: *Self, allocator: std.mem.Allocator, blockhash: Hash, commitment: ?CommitmentConfig) Result(RpcResponse(?RpcFeeCalculator)),
        getFeeForMessage: *const fn (ctx: *Self, allocator: std.mem.Allocator, data: []const u8, config: ?RpcContextConfig) Result(RpcResponse(?u64)),
        getFeeRateGovernor: *const fn (ctx: *Self, allocator: std.mem.Allocator) Result(RpcResponse(RpcFeeRateGovernor)),
        getFees: *const fn (ctx: *Self, allocator: std.mem.Allocator, commitment: ?CommitmentConfig) Result(RpcResponse(RpcFees)),
        getFirstAvailableBlock: *const fn (ctx: *Self, allocator: std.mem.Allocator) Result(u64),
        getGenesisHash: *const fn (ctx: *Self, allocator: std.mem.Allocator) Result([]const u8),
        getHealth: *const fn (ctx: *Self, allocator: std.mem.Allocator) Result([]const u8),
        getHighestSnapshotSlot: *const fn (ctx: *Self, allocator: std.mem.Allocator) Result(RpcSnapshotSlotInfo),
        getIdentity: *const fn (ctx: *Self, allocator: std.mem.Allocator) Result(RpcIdentity),
        getInflationGovernor: *const fn (ctx: *Self, allocator: std.mem.Allocator, commitment: ?CommitmentConfig) Result(RpcInflationGovernor),
        getInflationRate: *const fn (ctx: *Self, allocator: std.mem.Allocator) Result(RpcInflationRate),
        getInflationReward: *const fn (ctx: *Self, allocator: std.mem.Allocator, addresses: []Pubkey, config: ?RpcEpochConfig) Result([]?RpcInflationReward),
        getLargestAccounts: *const fn (ctx: *Self, allocator: std.mem.Allocator, config: ?RpcLargestAccountsConfig) Result(RpcResponse([]RpcAccountBalance)),
        getLatestBlockhash: *const fn (ctx: *Self, allocator: std.mem.Allocator, config: ?RpcContextConfig) Result(RpcResponse(RpcBlockhash)),
        getLeaderSchedule: *const fn (ctx: *Self, allocator: std.mem.Allocator, options: ?RpcLeaderScheduleConfigWrapper, config: ?RpcLeaderScheduleConfig) Result(?RpcLeaderSchedule),
        getMaxRetransmitSlot: *const fn (ctx: *Self, allocator: std.mem.Allocator) Result(Slot),
        getMaxShredInsertSlot: *const fn (ctx: *Self, allocator: std.mem.Allocator) Result(Slot),
        getMinimumBalanceForRentExemption: *const fn (ctx: *Self, allocator: std.mem.Allocator, data_len: usize, commitment_config: ?CommitmentConfig) Result(u64),
        getMultipleAccounts: *const fn (ctx: *Self, allocator: std.mem.Allocator, publeys: []Pubkey, config: ?RpcAccountInfoConfig) Result(RpcResponse([]?UiAccount)),
        getProgramAccounts: *const fn (ctx: *Self, allocator: std.mem.Allocator, program_id: Pubkey, config: ?RpcAccountInfoConfig, filters: []AccountFilter, with_context: bool) Result(OptionalContext([]RpcKeyedAccount)),
        getRecentBlockhash: *const fn (ctx: *Self, allocator: std.mem.Allocator, commitment: ?CommitmentConfig) Result(RpcResponse(RpcBlockhashFeeCalculator)),
        getRecentPerformanceSamples: *const fn (ctx: *Self, allocator: std.mem.Allocator, limit: ?usize) Result([]RpcPerfSample),
        getRecentPrioritizationFees: *const fn (ctx: *Self, allocator: std.mem.Allocator, pubkeys: []Pubkey) Result([]RpcPrioritizationFee),
        getSignaturesForAddress: *const fn (ctx: *Self, allocator: std.mem.Allocator, address: Pubkey, before: ?Signature, until: ?Signature, limit: usize, config: RpcContextConfig) Result([]RpcConfirmedTransactionStatusWithSignature),
        getSignatureStatuses: *const fn (ctx: *Self, allocator: std.mem.Allocator, signatures: [][]const u8, config: ?RpcSignatureStatusConfig) Result(RpcResponse([]?TransactionStatus)),
        getSlot: *const fn (ctx: *Self, allocator: std.mem.Allocator, config: RpcContextConfig) Result(Slot),
        getSlotLeader: *const fn (ctx: *Self, allocator: std.mem.Allocator, config: RpcContextConfig) Result([]const u8),
        getSlotLeaders: *const fn (ctx: *Self, allocator: std.mem.Allocator, commitment: ?CommitmentConfig, start_slot: Slot, limit: usize) Result([]Pubkey),
        getSnapshotSlot: *const fn (ctx: *Self, allocator: std.mem.Allocator) Result(Slot),
        getStakeActivation: *const fn (ctx: *Self, allocator: std.mem.Allocator, pubkey: Pubkey, config: ?RpcEpochConfig) Result(RpcStakeActivation),
        getStakeMinimumDelegation: *const fn (ctx: *Self, allocator: std.mem.Allocator, config: RpcContextConfig) Result(RpcResponse(u64)),
        getSupply: *const fn (ctx: *Self, allocator: std.mem.Allocator, config: ?RpcSupplyConfig) Result(RpcResponse(RpcSupply)),
        getTokenAccountBalance: *const fn (ctx: *Self, allocator: std.mem.Allocator, pubkey: Pubkey, commitment: ?CommitmentConfig) Result(RpcResponse(UiTokenAmount)),
        getTokenAccountsByDelegate: *const fn (ctx: *Self, allocator: std.mem.Allocator, delegate: Pubkey, token_account_filter: TokenAccountsFilter, config: ?RpcAccountInfoConfig) Result(RpcResponse([]RpcKeyedAccount)),
        getTokenAccountsByOwner: *const fn (ctx: *Self, allocator: std.mem.Allocator, owner: Pubkey, token_account_filter: TokenAccountsFilter, config: ?RpcAccountInfoConfig) Result(RpcResponse([]RpcKeyedAccount)),
        getTokenLargestAccounts: *const fn (ctx: *Self, allocator: std.mem.Allocator, mint: Pubkey, commitment: ?CommitmentConfig) Result(RpcResponse([]RpcTokenAccountBalance)),
        getTokenSupply: *const fn (ctx: *Self, allocator: std.mem.Allocator, mint: Pubkey, commitment: CommitmentConfig) Result(RpcResponse(UiTokenAmount)),
        getTotalSupply: *const fn (ctx: *Self, allocator: std.mem.Allocator, commitment: ?CommitmentConfig) Result(u64),
        getTransaction: *const fn (ctx: *Self, allocator: std.mem.Allocator, signature: Signature, config: RpcEncodingConfigWrapper(RpcTransactionConfig)) Result(?EncodedConfirmedTransactionWithStatusMeta),
        getTransactionCount: *const fn (ctx: *Self, allocator: std.mem.Allocator, config: RpcContextConfig) Result(u64),
        getVersion: *const fn (ctx: *Self, allocator: std.mem.Allocator) Result(RpcVersionInfo),
        getVoteAccounts: *const fn (ctx: *Self, allocator: std.mem.Allocator, config: ?RpcGetVoteAccountsConfig) Result(RpcVoteAccountStatus),
        isBlockhashValid: *const fn (ctx: *Self, allocator: std.mem.Allocator, hash: Hash, config: RpcContextConfig) Result(RpcResponse(bool)),
        minimumLedgerSlot: *const fn (ctx: *Self, allocator: std.mem.Allocator) Result(Slot),
        requestAirdrop: *const fn (ctx: *Self, allocator: std.mem.Allocator, pubkey: Pubkey, lamports: u64, config: ?RpcRequestAirdropConfig) Result([]const u8),
        sendTransaction: *const fn (ctx: *Self, allocator: std.mem.Allocator, data: []const u8, config: ?RpcSendTransactionConfig) Result([]const u8),
        simulateTransaction: *const fn (ctx: *Self, allocator: std.mem.Allocator, data: []const u8, config: ?RpcSimulateTransactionConfig) Result(RpcResponse(RpcSimulateTransactionResult)),
    };
}

const TwoPointZero = *const [3:0]u8;

pub const Id = union(enum(u8)) {
    string: []const u8,
    number: i64,
    null,

    pub fn jsonParse(allocator: std.mem.Allocator, source: anytype, options: std.json.ParseOptions) !Id {
        var value = try std.json.Value.jsonParse(allocator, source, options);
        switch (value) {
            .string => |str| {
                return .{ .string = str };
            },
            .integer => |int| {
                return .{ .number = int };
            },
            .null => {
                return .null;
            },
            else => {
                return error.InvalidNumber;
            },
        }
    }

    pub fn jsonParseFromValue(_: std.mem.Allocator, source: anytype, _: std.json.ParseOptions) !Id {
        switch (source.*) {
            .string => |str| {
                return .{ .string = str };
            },
            .integer => |int| {
                return .{ .number = int };
            },
            .null => {
                return .null;
            },
            else => {
                return error.InvalidNumber;
            },
        }
    }

    pub fn jsonStringify(
        self: *const Id,
        jw: anytype,
    ) !void {
        switch (self.*) {
            .string => |str| {
                try jw.write(str);
            },
            .number => |int| {
                try jw.write(int);
            },
            .null => {
                try jw.write(null);
            },
        }
    }

    pub fn toValue(self: *const Id) std.json.Value {
        return switch (self.*) {
            .string => |str| {
                std.json.Value{ .string = str };
            },
            .number => |num| {
                std.json.Value{ .integer = num };
            },
            .null => {
                std.json.Value{.null};
            },
        };
    }
};

pub const JsonRpcRequest = struct {
    id: Id,
    jsonrpc: TwoPointZero,
    method: []const u8,
    params: std.json.Value,
};

pub fn JsonRpcResponse(comptime T: type) type {
    return struct {
        id: Id,
        jsonrpc: TwoPointZero,
        @"error": ?ErrorObject,
        result: ?T,
    };
}

pub const ErrorObject = struct {
    code: i32,
    message: []const u8,

    pub fn init(code: i32, message: []const u8) ErrorObject {
        return ErrorObject{
            .code = code,
            .message = message,
        };
    }

    pub fn deinit(self: *ErrorObject) void {
        _ = self;
    }
};

pub const TransactionError = union(enum(u8)) {
    /// An account is already being processed in another transaction in a way
    /// that does not support parallelism
    // #[error("Account in use")]
    AccountInUse,

    /// A `Pubkey` appears twice in the transaction's `account_keys`.  Instructions can reference
    /// `Pubkey`s more than once but the message must contain a list with no duplicate keys
    // #[error("Account loaded twice")]
    AccountLoadedTwice,

    /// Attempt to debit an account but found no record of a prior credit.
    // #[error("Attempt to debit an account but found no record of a prior credit.")]
    AccountNotFound,

    /// Attempt to load a program that does not exist
    // #[error("Attempt to load a program that does not exist")]
    ProgramAccountNotFound,

    /// The from `Pubkey` does not have sufficient balance to pay the fee to schedule the transaction
    // #[error("Insufficient funds for fee")]
    InsufficientFundsForFee,

    /// This account may not be used to pay transaction fees
    // #[error("This account may not be used to pay transaction fees")]
    InvalidAccountForFee,

    /// The bank has seen this transaction before. This can occur under normal operation
    /// when a UDP packet is duplicated, as a user error from a client not updating
    /// its `recent_blockhash`, or as a double-spend attack.
    // #[error("This transaction has already been processed")]
    AlreadyProcessed,

    /// The bank has not seen the given `recent_blockhash` or the transaction is too old and
    /// the `recent_blockhash` has been discarded.
    // #[error("Blockhash not found")]
    BlockhashNotFound,

    /// An error occurred while processing an instruction. The first element of the tuple
    /// indicates the instruction index in which the error occurred.
    // #[error("Error processing Instruction {0}: {1}")]
    InstructionError: struct { u8, InstructionError },

    /// Loader call chain is too deep
    // #[error("Loader call chain is too deep")]
    CallChainTooDeep,

    /// Transaction requires a fee but has no signature present
    // #[error("Transaction requires a fee but has no signature present")]
    MissingSignatureForFee,

    /// Transaction contains an invalid account reference
    // #[error("Transaction contains an invalid account reference")]
    InvalidAccountIndex,

    /// Transaction did not pass signature verification
    // #[error("Transaction did not pass signature verification")]
    SignatureFailure,

    /// This program may not be used for executing instructions
    // #[error("This program may not be used for executing instructions")]
    InvalidProgramForExecution,

    /// Transaction failed to sanitize accounts offsets correctly
    /// implies that account locks are not taken for this TX, and should
    /// not be unlocked.
    // #[error("Transaction failed to sanitize accounts offsets correctly")]
    SanitizeFailure,

    // #[error("Transactions are currently disabled due to cluster maintenance")]
    ClusterMaintenance,

    /// Transaction processing left an account with an outstanding borrowed reference
    // #[error("Transaction processing left an account with an outstanding borrowed reference")]
    AccountBorrowOutstanding,

    /// Transaction would exceed max Block Cost Limit
    // #[error("Transaction would exceed max Block Cost Limit")]
    WouldExceedMaxBlockCostLimit,

    /// Transaction version is unsupported
    // #[error("Transaction version is unsupported")]
    UnsupportedVersion,

    /// Transaction loads a writable account that cannot be written
    // #[error("Transaction loads a writable account that cannot be written")]
    InvalidWritableAccount,

    /// Transaction would exceed max account limit within the block
    // #[error("Transaction would exceed max account limit within the block")]
    WouldExceedMaxAccountCostLimit,

    /// Transaction would exceed account data limit within the block
    // #[error("Transaction would exceed account data limit within the block")]
    WouldExceedAccountDataBlockLimit,

    /// Transaction locked too many accounts
    // #[error("Transaction locked too many accounts")]
    TooManyAccountLocks,

    /// Address lookup table not found
    // #[error("Transaction loads an address table account that doesn't exist")]
    AddressLookupTableNotFound,

    /// Attempted to lookup addresses from an account owned by the wrong program
    // #[error("Transaction loads an address table account with an invalid owner")]
    InvalidAddressLookupTableOwner,

    /// Attempted to lookup addresses from an invalid account
    // #[error("Transaction loads an address table account with invalid data")]
    InvalidAddressLookupTableData,

    /// Address table lookup uses an invalid index
    // #[error("Transaction address table lookup uses an invalid index")]
    InvalidAddressLookupTableIndex,

    /// Transaction leaves an account with a lower balance than rent-exempt minimum
    // #[error("Transaction leaves an account with a lower balance than rent-exempt minimum")]
    InvalidRentPayingAccount,

    /// Transaction would exceed max Vote Cost Limit
    // #[error("Transaction would exceed max Vote Cost Limit")]
    WouldExceedMaxVoteCostLimit,

    /// Transaction would exceed total account data limit
    // #[error("Transaction would exceed total account data limit")]
    WouldExceedAccountDataTotalLimit,

    /// Transaction contains a duplicate instruction that is not allowed
    // #[error("Transaction contains a duplicate instruction ({0}) that is not allowed")]
    DuplicateInstruction: u8,

    /// Transaction results in an account with insufficient funds for rent
    // #[error(
    //     "Transaction results in an account ({account_index}) with insufficient funds for rent"
    // )]
    InsufficientFundsForRent: struct { account_index: u8 },

    /// Transaction exceeded max loaded accounts data size cap
    // #[error("Transaction exceeded max loaded accounts data size cap")]
    MaxLoadedAccountsDataSizeExceeded,

    /// LoadedAccountsDataSizeLimit set for transaction must be greater than 0.
    // #[error("LoadedAccountsDataSizeLimit set for transaction must be greater than 0.")]
    InvalidLoadedAccountsDataSizeLimit,

    /// Sanitized transaction differed before/after feature activiation. Needs to be resanitized.
    // #[error("ResanitizationNeeded")]
    ResanitizationNeeded,

    /// The total balance before the transaction does not equal the total balance after the transaction
    // #[error("Sum of account balances before and after transaction do not match")]
    UnbalancedTransaction,
};

pub const RpcFeeCalculator = struct {
    fee_calculator: FeeCalculator,
};

pub const RpcFeeRateGovernor = struct {
    fee_rate_governor: FeeRateGovernor,
};

pub const RpcConfirmedTransactionConfig = struct {
    encoding: ?UiTransactionEncoding,
    commitment: ?CommitmentConfig,
};

pub const RpcGetConfirmedSignaturesForAddress2Config = struct {
    before: ?[]const u8, // Signature as base-58 string
    until: ?[]const u8, // Signature as base-58 string
    limit: ?usize,
    commitment: ?CommitmentConfig,
};

pub const RpcConfirmedBlocksConfigWrapper = union(enum(u8)) {
    end_slot_only: ?Slot,
    commitment_only: ?CommitmentConfig,
};

pub const RpcConfirmedBlockConfig = struct {
    encoding: ?UiTransactionEncoding,
    transaction_details: ?TransactionDetails,
    rewards: ?bool,
    commitment: ?CommitmentConfig,
};

pub const RpcSimulateTransactionConfig = struct {
    sig_verify: bool,
    replace_recent_blockhash: bool,
    commitment: ?CommitmentConfig,
    encoding: ?UiTransactionEncoding,
    accounts: ?RpcSimulateTransactionAccountsConfig,
    min_context_slot: ?Slot,
};

pub const RpcSimulateTransactionAccountsConfig = struct {
    encoding: ?UiAccountEncoding,
    addresses: [][]const u8,
};

pub const RpcSendTransactionConfig = struct {
    skip_preflight: bool,
    preflight_commitment: ?CommitmentLevel = null,
    encoding: ?UiTransactionEncoding = null,
    max_retries: ?usize = null,
    min_context_slot: ?Slot = null,
};

pub const RpcRequestAirdropConfig = struct {
    recent_blockhash: ?[]const u8, // base-58 encoded blockhash
    commitment: ?CommitmentConfig,
};

pub const RpcVersionInfo = struct {
    /// The current version of solana-core
    solana_core: []const u8,
    /// first 4 bytes of the FeatureSet identifier
    feature_set: ?u32,
};

pub const EncodedConfirmedTransactionWithStatusMeta = struct {
    slot: Slot,
    transaction: EncodedTransactionWithStatusMeta,
    block_time: ?UnixTimestamp,
};

pub fn RpcEncodingConfigWrapper(comptime Config: type) type {
    return union(enum(u8)) {
        deprecated: ?UiTransactionEncoding,
        current: ?Config,
    };
}

pub const RpcTransactionConfig = struct {
    encoding: ?UiTransactionEncoding,
    commitment: ?CommitmentConfig,
    max_supported_transaction_version: ?u8,
};

pub const RpcTokenAccountBalance = struct {
    address: []const u8,
    amount: UiTokenAmount,
};

pub const TokenAccountsFilter = union(enum(u8)) {
    mint: Pubkey,
    program_id: Pubkey,
};

pub const RpcStakeActivation = struct {
    state: StakeActivationState,
    active: u64,
    inactive: u64,
};

pub const StakeActivationState = enum {
    activating,
    active,
    deactivating,
    inactive,
};

pub const RpcEpochConfig = struct {
    epoch: ?Epoch,
    commitment: ?CommitmentConfig,
    min_context_slot: ?Slot,
};

pub const TransactionStatus = struct {
    slot: Slot,
    confirmations: ?usize, // None = rooted
    status: ?TransactionError, // formerly: TransactionResult - legacy field
    err: ?TransactionError,
    confirmation_status: ?TransactionConfirmationStatus,
};

pub const RpcSignatureStatusConfig = struct {
    search_transaction_history: bool,
};

pub const RpcConfirmedTransactionStatusWithSignature = struct {
    signature: []const u8,
    slot: Slot,
    err: ?TransactionError,
    memo: ?[]const u8,
    block_time: ?UnixTimestamp,
    confirmation_status: ?TransactionConfirmationStatus,
};

pub const TransactionConfirmationStatus = enum {
    processed,
    confirmed,
    finalized,
};

pub const RpcPrioritizationFee = struct {
    slot: Slot,
    prioritization_fee: u64,
};

pub const RpcPerfSample = struct {
    slot: Slot,
    num_transactions: u64,
    num_non_vote_transactions: ?u64,
    num_slots: u64,
    sample_period_secs: u16,
};

pub const RpcLeaderSchedule = std.StringArrayHashMap([]Slot);

pub const RpcLeaderScheduleConfigWrapper = union(enum(u8)) {
    slot_only: ?Slot,
    config_only: ?RpcLeaderScheduleConfig,
};

pub const RpcLeaderScheduleConfig = struct {
    identity: ?[]const u8, // validator identity, as a base-58 encoded string
    commitment: ?CommitmentConfig,
};

pub const RpcBlockhash = struct {
    blockhash: []const u8,
    last_valid_block_height: u64,
};

pub const RpcIdentity = struct {
    /// The current node identity pubkey
    identity: []const u8,
};

pub const RpcSnapshotSlotInfo = struct {
    full: Slot,
    incremental: ?Slot,
};

pub const EpochInfo = struct {
    /// The current epoch
    epoch: Epoch,
    /// The current slot, relative to the start of the current epoch
    slot_index: u64,
    /// The number of slots in this epoch
    slots_in_epoch: u64,
    /// The absolute current slot
    absolute_slot: Slot,
    /// The current block height
    block_height: u64,
    /// Total number of transactions processed without error since genesis
    transaction_count: ?u64,
};

pub const RpcContactInfo = struct {
    /// Pubkey of the node as a base-58 string
    pubkey: Pubkey,
    /// Gossip port
    gossip: ?SocketAddr,
    /// Tpu UDP port
    tpu: ?SocketAddr,
    /// Tpu QUIC port
    tpu_quic: ?SocketAddr,
    /// JSON RPC port
    rpc: ?SocketAddr,
    /// WebSocket PubSub port
    pubsub: ?SocketAddr,
    /// Software version
    version: ?[]const u8,
    /// First 4 bytes of the FeatureSet identifier
    feature_set: ?u32,
    /// Shred version
    shred_version: ?u16,
};

pub const RpcBlockProduction = struct {
    /// Map of leader base58 identity pubkeys to a tuple of `(number of leader slots, number of blocks produced)`
    by_identity: std.StringArrayHashMap(struct { usize, usize }),
    range: RpcBlockProductionRange,
};

pub const RpcBlockProductionConfig = struct {
    identity: ?[]const u8, // validator identity, as a base-58 encoded string
    range: ?RpcBlockProductionConfigRange, // current epoch if `None`
    commitment: ?CommitmentConfig,
};

pub const RpcBlockProductionRange = struct {
    first_slot: Slot,
    last_slot: Slot,
};

pub const RpcBlockProductionConfigRange = struct {
    first_slot: Slot,
    last_slot: ?Slot,
};

pub const RpcSimulateTransactionResult = struct {
    err: ?TransactionError,
    logs: ?[][]const u8,
    accounts: ?[]?UiAccount,
    units_consumed: ?u64,
    return_data: ?UiTransactionReturnData,
    inner_instructions: ?[]UiInnerInstructions,
};

pub const UiTransactionReturnData = struct {
    program_id: []const u8,
    data: struct { []const u8, UiReturnDataEncoding },
};

pub const UiReturnDataEncoding = enum {
    base64,
};

pub const UiInnerInstructions = struct {
    /// Transaction instruction index
    index: u8,
    /// List of inner instructions
    instructions: []UiInstruction,
};

pub const EncodedTransaction = union(enum(u8)) {
    legacy_binary: []const u8, // Old way of expressing base-58, retained for RPC backwards compatibility
    binary: struct { []const u8, TransactionBinaryEncoding },
    json: UiTransaction,
    accounts: UiAccountsList,
};

pub const UiAccountsList = struct {
    signatures: [][]const u8,
    account_keys: []ParsedAccount,
};

pub const UiTransaction = struct {
    signatures: [][]const u8,
    message: UiMessage,
};

pub const UiMessage = union(enum(u8)) {
    parsed: UiParsedMessage,
    raw: UiRawMessage,
};

pub const MessageHeader = struct {
    /// The number of signatures required for this message to be considered
    /// valid. The signers of those signatures must match the first
    /// `num_required_signatures` of [`Message::account_keys`].
    // NOTE: Serialization-related changes must be paired with the direct read at sigverify.
    num_required_signatures: u8,

    /// The last `num_readonly_signed_accounts` of the signed keys are read-only
    /// accounts.
    num_readonly_signed_accounts: u8,

    /// The last `num_readonly_unsigned_accounts` of the unsigned keys are
    /// read-only accounts.
    num_readonly_unsigned_accounts: u8,
};

pub const UiRawMessage = struct {
    header: MessageHeader,
    account_keys: [][]const u8,
    recent_blockhash: []const u8,
    instructions: []UiCompiledInstruction,
    address_table_lookups: ?[]UiAddressTableLookup,
};

pub const UiParsedMessage = struct {
    account_keys: []ParsedAccount,
    recent_blockhash: []const u8,
    instructions: []UiInstruction,
    address_table_lookups: ?[]UiAddressTableLookup,
};

pub const UiAddressTableLookup = struct {
    account_key: []const u8,
    writable_indexes: []u8,
    readonly_indexes: []u8,
};

pub const UiInstruction = union(enum(u8)) {
    compiled: UiCompiledInstruction,
    parsed: UiParsedInstruction,
};

pub const UiParsedInstruction = union(enum(u8)) {
    parsed: ParsedInstruction,
    partially_decoded: UiPartiallyDecodedInstruction,
};

pub const UiPartiallyDecodedInstruction = struct {
    program_id: []const u8,
    accounts: []const u8,
    data: []const u8,
    stack_height: ?u32,
};

pub const ParsedInstruction = struct {
    program: []const u8,
    program_id: []const u8,
    parsed: std.json.Value,
    stack_height: ?u32,
};

pub const UiCompiledInstruction = struct {
    program_id_index: u8,
    accounts: []u8,
    data: []const u8,
    stack_height: ?u32,
};

pub const ParsedAccount = struct {
    pubkey: []const u8,
    writable: bool,
    signer: bool,
    source: ?ParsedAccountSource,
};

pub const ParsedAccountSource = enum {
    transaction,
    lookup_table,
};

pub const TransactionBinaryEncoding = enum {
    base58,
    base64,
};

pub const UiTransactionStatusMeta = struct {
    err: ?TransactionError,
    status: ?Error, // This field is deprecated.  See https://github.com/solana-labs/solana/issues/9302
    fee: u64,
    pre_balances: []u64,
    post_balances: []u64,
    inner_instructions: ?[]UiInnerInstructions,
    log_messages: ?[][]const u8,
    pre_token_balances: ?[]UiTransactionTokenBalance,
    post_token_balances: ?[]UiTransactionTokenBalance,
    rewards: ?[]Reward,
    loaded_addresses: ?UiLoadedAddresses,
    return_data: ?UiTransactionReturnData,
    compute_units_consumed: ?u64,
};

pub const UiLoadedAddresses = struct {
    writable: [][]const u8,
    readonly: [][]const u8,
};

pub const Reward = struct {
    pubkey: []const u8,
    lamports: i64,
    post_balance: u64, // Account balance in lamports after `lamports` was applied
    reward_type: ?RewardType,
    commission: ?u8, // Vote account commission when the reward was credited, only present for voting and staking rewards
};

pub const RewardType = enum {
    fee,
    rent,
    staking,
    voting,
};

pub const UiTransactionTokenBalance = struct {
    account_index: u8,
    mint: []const u8,
    ui_token_amount: UiTokenAmount,
    owner: ?[]const u8,
    program_id: ?[]const u8,
};

pub const UiTokenAmount = struct {
    ui_amount: ?f64,
    decimals: u8,
    amount: []const u8,
    ui_amount_string: []const u8,
};

pub const EncodedTransactionWithStatusMeta = struct {
    transaction: EncodedTransaction,
    meta: ?UiTransactionStatusMeta,
    version: ?TransactionVersion,
};

pub const TransactionVersion = union(enum(u8)) {
    legacy: Legacy,
    number: u8,
};

pub const Legacy = enum {
    legacy,
};

pub const UiConfirmedBlock = struct {
    previous_blockhash: []const u8,
    blockhash: []const u8,
    parent_slot: Slot,
    transactions: ?[]EncodedTransactionWithStatusMeta,
    signatures: ?[][]const u8,
    rewards: ?[]Reward,
    block_time: ?UnixTimestamp,
    block_height: ?u64,
};

pub const RpcBlockConfig = struct {
    encoding: ?UiTransactionEncoding,
    transaction_details: ?TransactionDetails,
    rewards: ?bool,
    commitment: ?CommitmentConfig,
    max_supported_transaction_version: ?u8,
};

pub const UiTransactionEncoding = enum {
    binary, // Legacy. Retained for RPC backwards compatibility
    base64,
    base58,
    json,
    json_parsed,
};

pub const TransactionDetails = enum {
    Full,
    Signatures,
    None,
    Accounts,
};

pub const RpcVoteAccountStatus = struct {
    current: []RpcVoteAccountInfo,
    delinquent: []RpcVoteAccountInfo,
};

pub const RpcVoteAccountInfo = struct {
    /// Vote account address, as base-58 encoded string
    vote_pubkey: []const u8,

    /// The validator identity, as base-58 encoded string
    node_pubkey: []const u8,

    /// The current stake, in lamports, delegated to this vote account
    activated_stake: u64,

    /// An 8-bit integer used as a fraction (commission/MAX_U8) for rewards payout
    commission: u8,

    /// Whether this account is staked for the current epoch
    epoch_vote_account: bool,

    /// Latest history of earned credits for up to `MAX_RPC_VOTE_ACCOUNT_INFO_EPOCH_CREDITS_HISTORY` epochs
    ///   each tuple is (Epoch, credits, prev_credits)
    epoch_credits: []struct { Epoch, u64, u64 },

    /// Most recent slot voted on by this vote account (0 if no votes exist)
    last_vote: u64,

    /// Current root slot for this vote account (0 if no root slot exists)
    root_slot: Slot,
};

pub const RpcGetVoteAccountsConfig = struct {
    vote_pubkey: ?[]const u8, // validator vote address, as a base-58 encoded string
    commitment: ?CommitmentConfig,
    keep_unstaked_delinquents: ?bool,
    delinquent_slot_distance: ?u64,
};

pub const RpcSupply = struct {
    total: u64,
    circulating: u64,
    non_circulating: u64,
    non_circulating_accounts: [][]const u8,
};

pub const RpcSupplyConfig = struct {
    commitment: ?CommitmentConfig,
    exclude_non_circulating_accounts_list: bool,
};

pub const RpcAccountBalance = struct {
    address: []const u8,
    lamports: u64,
};

pub const RpcLargestAccountsFilter = enum {
    Circulating,
    NonCirculating,
};

pub const RpcLargestAccountsConfig = struct {
    commitment: ?CommitmentConfig,
    filter: ?RpcLargestAccountsFilter,
};

pub const RpcBlockCommitment = struct {
    commitment: ?BlockCommitmentArray,
    total_stake: u64,
};

pub const MAX_LOCKOUT_HISTORY: usize = 31;

pub const BlockCommitmentArray = [MAX_LOCKOUT_HISTORY + 1]u64;

pub const FeeRateGovernor = struct {
    // The current cost of a signature  This amount may increase/decrease over time based on
    // cluster processing load.
    lamports_per_signature: u64,

    // The target cost of a signature when the cluster is operating around target_signatures_per_slot
    // signatures
    target_lamports_per_signature: u64,

    // Used to estimate the desired processing capacity of the cluster.  As the signatures for
    // recent slots are fewer/greater than this value, lamports_per_signature will decrease/increase
    // for the next slot.  A value of 0 disables lamports_per_signature fee adjustments
    target_signatures_per_slot: u64,

    min_lamports_per_signature: u64,
    max_lamports_per_signature: u64,

    // What portion of collected fees are to be destroyed, as a fraction of std::u8::MAX
    burn_percent: u8,
};

pub const RpcFees = struct {
    blockhash: []const u8,
    fee_calculator: FeeCalculator,
    last_valid_slot: Slot,
    last_valid_block_height: u64,
};

pub const RpcBlockhashFeeCalculator = struct {
    blockhash: []const u8,
    fee_calculator: FeeCalculator,
};

pub const RpcFeeCalculdator = struct {
    fee_calculator: FeeCalculator,
};

pub const FeeCalculator = struct {
    /// The current cost of a signature.
    ///
    /// This amount may increase/decrease over time based on cluster processing
    /// load.
    lamports_per_signature: u64,
};

pub const RpcContextConfig = struct {
    commitment: ?CommitmentConfig,
    min_context_slot: ?Slot,
};

pub const EpochSchedule = struct {
    /// The maximum number of slots in each epoch.
    slots_per_epoch: u64,

    /// A number of slots before beginning of an epoch to calculate
    /// a leader schedule for that epoch.
    leader_schedule_slot_offset: u64,

    /// Whether epochs start short and grow.
    warmup: bool,

    /// The first epoch after the warmup period.
    ///
    /// Basically: `log2(slots_per_epoch) - log2(MINIMUM_SLOTS_PER_EPOCH)`.
    first_normal_epoch: Epoch,

    /// The first slot after the warmup period.
    ///
    /// Basically: `MINIMUM_SLOTS_PER_EPOCH * (2.pow(first_normal_epoch) - 1)`.
    first_normal_slot: Slot,
};

pub const RpcInflationRate = struct {
    total: f64,
    validator: f64,
    foundation: f64,
    epoch: Epoch,
};

pub const RpcInflationGovernor = struct {
    initial: f64,
    terminal: f64,
    taper: f64,
    foundation: f64,
    foundation_term: f64,
};

pub const RpcInflationReward = struct {
    epoch: Epoch,
    effective_slot: Slot,
    amount: u64, // lamports
    post_balance: u64, // lamports
    commission: ?u8, // Vote account commission when the reward was credited
};

pub const RpcKeyedAccount = struct {
    pubkey: []const u8,
    account: UiAccount,
};

pub fn OptionalContext(comptime T: type) type {
    return union(enum(u8)) {
        Context: RpcResponse(T),
        NoContext: T,
    };
}

pub const AccountFilter = union(enum(u8)) {
    data_size: u64,
    memcmp: MemCmp,
    TokenAccountState,
};

pub const MemCmp = struct {};

pub const UiAccount = struct {
    lamports: u64,
    data: UiAccountData,
    owner: []const u8,
    executable: bool,
    rent_epoch: Epoch,
    space: ?u64,
};

pub const UiAccountData = union(enum(u8)) {
    legacy_binary: []const u8, // Legacy. Retained for RPC backwards compatibility
    json: UiParsedAccount,
    binary: struct { []const u8, UiAccountEncoding },
};

// Renamed due to conflict - original is solana_account_decoder::parse_account_data::ParsedAccount
pub const UiParsedAccount = struct {
    program: []const u8,
    parsed: json.Value,
    space: u64,
};

pub const UiAccountEncoding = enum {
    binary, // Legacy. Retained for RPC backwards compatibility
    base58,
    base64,
    jsonParsed,
    base64Zstd,
};

pub const UiDataSliceConfig = struct {
    offset: usize,
    length: usize,
};

pub const CommitmentConfig = struct {
    commitment: CommitmentLevel,
};

pub const CommitmentLevel = enum {
    /// (DEPRECATED) The highest slot having reached max vote lockout, as recognized by a supermajority of the cluster.
    Max,

    /// (DEPRECATED) The highest slot of the heaviest fork. Ledger state at this slot is not derived from a finalized
    /// block, but if multiple forks are present, is from the fork the validator believes is most likely
    /// to finalize.
    Recent,

    /// (DEPRECATED) The highest slot having reached max vote lockout.
    Root,

    /// (DEPRECATED) The highest slot having reached 1 confirmation by supermajority of the cluster.
    Single,

    /// (DEPRECATED) The highest slot that has been voted on by supermajority of the cluster
    /// This differs from `single` in that:
    /// 1) It incorporates votes from gossip and replay.
    /// 2) It does not count votes on descendants of a block, only direct votes on that block.
    /// 3) This confirmation level also upholds "optimistic confirmation" guarantees in
    /// release 1.3 and onwards.
    SingleGossip,

    /// The highest slot of the heaviest fork processed by the node. Ledger state at this slot is
    /// not derived from a confirmed or finalized block, but if multiple forks are present, is from
    /// the fork the validator believes is most likely to finalize.
    Processed,

    /// The highest slot that has been voted on by supermajority of the cluster, ie. is confirmed.
    /// Confirmation incorporates votes from gossip and replay. It does not count votes on
    /// descendants of a block, only direct votes on that block, and upholds "optimistic
    /// confirmation" guarantees in release 1.3 and onwards.
    Confirmed,

    /// The highest slot having reached max vote lockout, as recognized by a supermajority of the
    /// cluster.
    Finalized,
};

pub const RpcAccountInfoConfig = struct {
    encoding: ?UiAccountEncoding,
    data_slice: ?UiDataSliceConfig,
    commitment: ?CommitmentConfig,
    min_context_slot: ?Slot,
};

pub const RpcResponseContext = struct {
    slot: Slot,
    api_version: []const u8,
};

pub fn RpcResponse(comptime T: type) type {
    return struct {
        context: RpcResponseContext,
        value: T,
    };
}
