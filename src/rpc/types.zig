const std = @import("std");
pub const Pubkey = @import("../core/pubkey.zig").Pubkey;
const json = std.json;
pub const Hash = @import("../core/hash.zig").Hash;
const SocketAddr = @import("../net/net.zig").SocketAddr;
pub const Signature = @import("../core/signature.zig").Signature;
const InstructionError = @import("../core/transaction.zig").InstructionError;
const Parsed = std.json.Parsed;

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
    ClientError: []const u8,
    Internal,
    Unimplemented,

    pub fn toErrorObject(self: *const Error, allocator: std.mem.Allocator) ErrorObject {
        var msg = std.ArrayList(u8).init(allocator);
        errdefer msg.deinit();
        var writer = msg.writer();

        inline for (@typeInfo(Error).Union.fields) |field| {
            if (std.mem.eql(u8, @tagName(self.*), field.name)) {
                switch (@typeInfo(field.type)) {
                    .Struct => |struct_type| {
                        writer.writeAll(field.name) catch unreachable;
                        writer.writeAll("{") catch unreachable;
                        inline for (struct_type.fields, 0..) |struct_field, i| {
                            writer.writeAll(struct_field.name) catch unreachable;
                            writer.writeAll(" = ") catch unreachable;
                            writer.writeAll(std.fmt.allocPrint(allocator, if (struct_field.type == []const u8) "\"{s}\"" else "{any}", .{@field(@field(self.*, field.name), struct_field.name)}) catch unreachable) catch unreachable;
                            if (i != struct_type.fields.len - 1) {
                                writer.writeAll(", ") catch unreachable;
                            }
                        }
                        writer.writeAll("}") catch unreachable;
                    },
                    else => {
                        std.fmt.format(writer, "{any}", .{self.*}) catch unreachable;
                    },
                }

                msg.shrinkAndFree(msg.items.len);
                return ErrorObject.init(jrpc_error_code_internal_error, msg.items);
            }
        }
        unreachable;
    }
};

pub const UiTransactionStatusError = union(enum(u8)) {
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
};

// TODO: incorporate a way to `free` memory allocated
pub fn Result(comptime T: type) type {
    return union(enum(u8)) {
        Ok: T,
        Err: Error,
    };
}

pub fn RpcServiceImpl(comptime Self: type, comptime Wrapper: anytype) type {
    return struct {
        getAccountInfo: *const fn (ctx: *Self, allocator: std.mem.Allocator, pubkey: Pubkey, config: ?RpcAccountInfoConfig) Wrapper(RpcResponse(?UiAccount)),
        getBalance: *const fn (ctx: *Self, allocator: std.mem.Allocator, pubkey: Pubkey, config: RpcContextConfig) Wrapper(RpcResponse(u64)),
        getBlock: *const fn (ctx: *Self, allocator: std.mem.Allocator, slot: Slot, config: ?RpcBlockConfig) Wrapper(UiConfirmedBlock),
        getBlockCommitment: *const fn (ctx: *Self, allocator: std.mem.Allocator, block: Slot) Wrapper(RpcBlockCommitment),
        getBlockHeight: *const fn (ctx: *Self, allocator: std.mem.Allocator, config: RpcContextConfig) Wrapper(u64),
        getBlockProduction: *const fn (ctx: *Self, allocator: std.mem.Allocator, config: ?RpcBlockProductionConfig) Wrapper(RpcResponse(RpcBlockProduction)),
        getBlocks: *const fn (ctx: *Self, allocator: std.mem.Allocator, start_slot: Slot, end_slot: Slot, commitment: ?CommitmentConfig) Wrapper([]Slot),
        getBlocksWithLimit: *const fn (ctx: *Self, allocator: std.mem.Allocator, start_slot: Slot, limit: usize, commitment: ?CommitmentConfig) Wrapper([]Slot),
        getBlockTime: *const fn (ctx: *Self, allocator: std.mem.Allocator, slot: Slot) Wrapper(?UnixTimestamp),
        getClusterNodes: *const fn (ctx: *Self, allocator: std.mem.Allocator) Wrapper([]RpcContactInfo),
        getConfirmedBlock: *const fn (ctx: *Self, allocator: std.mem.Allocator, slot: Slot, config: RpcEncodingConfigWrapper(RpcConfirmedBlockConfig)) Wrapper(?UiConfirmedBlock),
        getConfirmedBlocks: *const fn (ctx: *Self, allocator: std.mem.Allocator, start_slot: Slot, config: ?RpcConfirmedBlocksConfigWrapper, commitment: ?CommitmentConfig) Wrapper([]Slot),
        getConfirmedBlocksWithLimit: *const fn (ctx: *Self, allocator: std.mem.Allocator, start_slot: Slot, limit: usize, commitment: ?CommitmentConfig) Wrapper([]Slot),
        getConfirmedSignaturesForAddress2: *const fn (ctx: *Self, allocator: std.mem.Allocator, address: []const u8, config: ?RpcGetConfirmedSignaturesForAddress2Config) Wrapper([]RpcConfirmedTransactionStatusWithSignature),
        getConfirmedTransaction: *const fn (ctx: *Self, allocator: std.mem.Allocator, signature: []const u8, config: ?RpcEncodingConfigWrapper(RpcConfirmedTransactionConfig)) Wrapper(?EncodedConfirmedTransactionWithStatusMeta),
        getEpochInfo: *const fn (ctx: *Self, allocator: std.mem.Allocator, config: ?RpcContextConfig) Wrapper(EpochInfo),
        getEpochSchedule: *const fn (ctx: *Self, allocator: std.mem.Allocator) Wrapper(EpochSchedule),
        getFeeCalculatorForBlockhash: *const fn (ctx: *Self, allocator: std.mem.Allocator, blockhash: Hash, commitment: ?CommitmentConfig) Wrapper(RpcResponse(?RpcFeeCalculator)),
        getFeeForMessage: *const fn (ctx: *Self, allocator: std.mem.Allocator, data: []const u8, config: ?RpcContextConfig) Wrapper(RpcResponse(?u64)),
        getFeeRateGovernor: *const fn (ctx: *Self, allocator: std.mem.Allocator) Wrapper(RpcResponse(RpcFeeRateGovernor)),
        getFees: *const fn (ctx: *Self, allocator: std.mem.Allocator, commitment: ?CommitmentConfig) Wrapper(RpcResponse(RpcFees)),
        getFirstAvailableBlock: *const fn (ctx: *Self, allocator: std.mem.Allocator) Wrapper(u64),
        getGenesisHash: *const fn (ctx: *Self, allocator: std.mem.Allocator) Wrapper([]const u8),
        getHealth: *const fn (ctx: *Self, allocator: std.mem.Allocator) Wrapper([]const u8),
        getHighestSnapshotSlot: *const fn (ctx: *Self, allocator: std.mem.Allocator) Wrapper(RpcSnapshotSlotInfo),
        getIdentity: *const fn (ctx: *Self, allocator: std.mem.Allocator) Wrapper(RpcIdentity),
        getInflationGovernor: *const fn (ctx: *Self, allocator: std.mem.Allocator, commitment: ?CommitmentConfig) Wrapper(RpcInflationGovernor),
        getInflationRate: *const fn (ctx: *Self, allocator: std.mem.Allocator) Wrapper(RpcInflationRate),
        getInflationReward: *const fn (ctx: *Self, allocator: std.mem.Allocator, addresses: []Pubkey, config: ?RpcEpochConfig) Wrapper([]?RpcInflationReward),
        getLargestAccounts: *const fn (ctx: *Self, allocator: std.mem.Allocator, config: ?RpcLargestAccountsConfig) Wrapper(RpcResponse([]RpcAccountBalance)),
        getLatestBlockhash: *const fn (ctx: *Self, allocator: std.mem.Allocator, config: ?RpcContextConfig) Wrapper(RpcResponse(RpcBlockhash)),
        getLeaderSchedule: *const fn (ctx: *Self, allocator: std.mem.Allocator, options: ?RpcLeaderScheduleConfigWrapper, config: ?RpcLeaderScheduleConfig) Wrapper(?RpcLeaderSchedule),
        getMaxRetransmitSlot: *const fn (ctx: *Self, allocator: std.mem.Allocator) Wrapper(Slot),
        getMaxShredInsertSlot: *const fn (ctx: *Self, allocator: std.mem.Allocator) Wrapper(Slot),
        getMinimumBalanceForRentExemption: *const fn (ctx: *Self, allocator: std.mem.Allocator, data_len: usize, commitment_config: ?CommitmentConfig) Wrapper(u64),
        getMultipleAccounts: *const fn (ctx: *Self, allocator: std.mem.Allocator, publeys: []Pubkey, config: ?RpcAccountInfoConfig) Wrapper(RpcResponse([]?UiAccount)),
        getProgramAccounts: *const fn (ctx: *Self, allocator: std.mem.Allocator, program_id: Pubkey, config: ?RpcAccountInfoConfig, filters: []AccountFilter, with_context: bool) Wrapper(OptionalContext([]RpcKeyedAccount)),
        getRecentBlockhash: *const fn (ctx: *Self, allocator: std.mem.Allocator, commitment: ?CommitmentConfig) Wrapper(RpcResponse(RpcBlockhashFeeCalculator)),
        getRecentPerformanceSamples: *const fn (ctx: *Self, allocator: std.mem.Allocator, limit: ?usize) Wrapper([]RpcPerfSample),
        getRecentPrioritizationFees: *const fn (ctx: *Self, allocator: std.mem.Allocator, pubkeys: []Pubkey) Wrapper([]RpcPrioritizationFee),
        getSignaturesForAddress: *const fn (ctx: *Self, allocator: std.mem.Allocator, address: Pubkey, before: ?Signature, until: ?Signature, limit: usize, config: RpcContextConfig) Wrapper([]RpcConfirmedTransactionStatusWithSignature),
        getSignatureStatuses: *const fn (ctx: *Self, allocator: std.mem.Allocator, signatures: [][]const u8, config: ?RpcSignatureStatusConfig) Wrapper(RpcResponse([]?TransactionStatus)),
        getSlot: *const fn (ctx: *Self, allocator: std.mem.Allocator, config: RpcContextConfig) Wrapper(Slot),
        getSlotLeader: *const fn (ctx: *Self, allocator: std.mem.Allocator, config: RpcContextConfig) Wrapper([]const u8),
        getSlotLeaders: *const fn (ctx: *Self, allocator: std.mem.Allocator, commitment: ?CommitmentConfig, start_slot: Slot, limit: usize) Wrapper([]Pubkey),
        getSnapshotSlot: *const fn (ctx: *Self, allocator: std.mem.Allocator) Wrapper(Slot),
        getStakeActivation: *const fn (ctx: *Self, allocator: std.mem.Allocator, pubkey: Pubkey, config: ?RpcEpochConfig) Wrapper(RpcStakeActivation),
        getStakeMinimumDelegation: *const fn (ctx: *Self, allocator: std.mem.Allocator, config: RpcContextConfig) Wrapper(RpcResponse(u64)),
        getSupply: *const fn (ctx: *Self, allocator: std.mem.Allocator, config: ?RpcSupplyConfig) Wrapper(RpcResponse(RpcSupply)),
        getTokenAccountBalance: *const fn (ctx: *Self, allocator: std.mem.Allocator, pubkey: Pubkey, commitment: ?CommitmentConfig) Wrapper(RpcResponse(UiTokenAmount)),
        getTokenAccountsByDelegate: *const fn (ctx: *Self, allocator: std.mem.Allocator, delegate: Pubkey, token_account_filter: TokenAccountsFilter, config: ?RpcAccountInfoConfig) Wrapper(RpcResponse([]RpcKeyedAccount)),
        getTokenAccountsByOwner: *const fn (ctx: *Self, allocator: std.mem.Allocator, owner: Pubkey, token_account_filter: TokenAccountsFilter, config: ?RpcAccountInfoConfig) Wrapper(RpcResponse([]RpcKeyedAccount)),
        getTokenLargestAccounts: *const fn (ctx: *Self, allocator: std.mem.Allocator, mint: Pubkey, commitment: ?CommitmentConfig) Wrapper(RpcResponse([]RpcTokenAccountBalance)),
        getTokenSupply: *const fn (ctx: *Self, allocator: std.mem.Allocator, mint: Pubkey, commitment: CommitmentConfig) Wrapper(RpcResponse(UiTokenAmount)),
        getTotalSupply: *const fn (ctx: *Self, allocator: std.mem.Allocator, commitment: ?CommitmentConfig) Wrapper(u64),
        getTransaction: *const fn (ctx: *Self, allocator: std.mem.Allocator, signature: Signature, config: RpcEncodingConfigWrapper(RpcTransactionConfig)) Wrapper(?EncodedConfirmedTransactionWithStatusMeta),
        getTransactionCount: *const fn (ctx: *Self, allocator: std.mem.Allocator, config: RpcContextConfig) Wrapper(u64),
        getVersion: *const fn (ctx: *Self, allocator: std.mem.Allocator) Wrapper(RpcVersionInfo),
        getVoteAccounts: *const fn (ctx: *Self, allocator: std.mem.Allocator, config: ?RpcGetVoteAccountsConfig) Wrapper(RpcVoteAccountStatus),
        isBlockhashValid: *const fn (ctx: *Self, allocator: std.mem.Allocator, hash: Hash, config: RpcContextConfig) Wrapper(RpcResponse(bool)),
        minimumLedgerSlot: *const fn (ctx: *Self, allocator: std.mem.Allocator) Wrapper(Slot),
        requestAirdrop: *const fn (ctx: *Self, allocator: std.mem.Allocator, pubkey: Pubkey, lamports: u64, config: ?RpcRequestAirdropConfig) Wrapper([]const u8),
        sendTransaction: *const fn (ctx: *Self, allocator: std.mem.Allocator, data: []const u8, config: ?RpcSendTransactionConfig) Wrapper([]const u8),
        simulateTransaction: *const fn (ctx: *Self, allocator: std.mem.Allocator, data: []const u8, config: ?RpcSimulateTransactionConfig) Wrapper(RpcResponse(RpcSimulateTransactionResult)),
    };
}

const TwoPointZero = *const [3:0]u8;

pub const Id = union(enum(u8)) {
    string: []const u8,
    number: i64,
    null,

    pub fn free(self: *Id, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .string => |str| {
                allocator.free(str);
            },
            else => {},
        }
    }

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

    pub fn jsonParseFromValue(_: std.mem.Allocator, source: std.json.Value, _: std.json.ParseOptions) !Id {
        switch (source) {
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

pub fn TypedJsonRpcRequest(comptime T: type) type {
    return struct {
        id: Id,
        jsonrpc: TwoPointZero,
        method: []const u8,
        params: T,
    };
}

pub fn JsonRpcResponse(comptime T: type) type {
    return struct {
        id: Id,
        jsonrpc: TwoPointZero,
        @"error": ?ErrorObject = null,
        result: ?T = null,
    };
}

pub fn JsonRpcSuccessResponse(comptime T: type) type {
    return struct {
        id: Id,
        jsonrpc: TwoPointZero,
        result: ?T = null,
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

    pub fn format(self: *const ErrorObject, fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;

        try writer.writeAll("ErrorObject{");
        try std.fmt.format(writer, "{d}, ", .{self.code});
        try writer.writeAll(self.message);
        try writer.writeAll("}");
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
    feeCalculator: FeeCalculator,
};

pub const RpcFeeRateGovernor = struct {
    feeRateGovernor: FeeRateGovernor,
};

pub const RpcConfirmedTransactionConfig = struct {
    encoding: ?UiTransactionEncoding = null,
    commitment: ?CommitmentConfig = null,
};

pub const RpcGetConfirmedSignaturesForAddress2Config = struct {
    before: ?[]const u8 = null, // Signature as base-58 string
    until: ?[]const u8 = null, // Signature as base-58 string
    limit: ?usize = null,
    commitment: ?CommitmentConfig = null,
};

pub const RpcConfirmedBlocksConfigWrapper = union(enum(u8)) {
    endSlotOnly: ?Slot,
    commitmentOnly: ?CommitmentConfig,
};

pub const RpcConfirmedBlockConfig = struct {
    encoding: ?UiTransactionEncoding = null,
    transactionDetails: ?TransactionDetails = null,
    rewards: ?bool = null,
    commitment: ?CommitmentConfig = null,
};

pub const RpcSimulateTransactionConfig = struct {
    sigVerify: bool,
    replaceRecentBlockhash: bool,
    commitment: ?CommitmentConfig = null,
    encoding: ?UiTransactionEncoding = null,
    accounts: ?RpcSimulateTransactionAccountsConfig = null,
    minContextSlot: ?Slot = null,
};

pub const RpcSimulateTransactionAccountsConfig = struct {
    encoding: ?UiAccountEncoding = null,
    addresses: [][]const u8,
};

pub const RpcSendTransactionConfig = struct {
    skipPreflight: bool,
    preflightCommitment: ?CommitmentLevel = null,
    encoding: ?UiTransactionEncoding = null,
    maxRetries: ?usize = null,
    minContextSlot: ?Slot = null,
};

pub const RpcRequestAirdropConfig = struct {
    recentBlockhash: ?[]const u8 = null, // base-58 encoded blockhash
    commitment: ?CommitmentConfig = null,
};

pub const RpcVersionInfo = struct {
    /// The current version of solana-core
    @"solana-core": []const u8,
    /// first 4 bytes of the FeatureSet identifier
    @"feature-set": ?u32 = null,
};

pub const EncodedConfirmedTransactionWithStatusMeta = struct {
    slot: Slot,
    transaction: EncodedTransactionWithStatusMeta,
    blockTime: ?UnixTimestamp = null,
};

pub fn RpcEncodingConfigWrapper(comptime Config: type) type {
    return union(enum(u8)) {
        deprecated: ?UiTransactionEncoding,
        current: ?Config,
    };
}

pub const RpcTransactionConfig = struct {
    encoding: ?UiTransactionEncoding = null,
    commitment: ?CommitmentConfig = null,
    maxSupportedTransactionVersion: ?u8 = null,
};

pub const RpcTokenAccountBalance = struct {
    address: []const u8,
    amount: UiTokenAmount,
};

pub const TokenAccountsFilter = union(enum(u8)) {
    mint: Pubkey,
    programId: Pubkey,
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
    epoch: ?Epoch = null,
    commitment: ?CommitmentConfig = null,
    minContextSlot: ?Slot = null,
};

pub const TransactionStatus = struct {
    slot: Slot,
    confirmations: ?usize = null, // None = rooted
    status: ?TransactionError = null, // formerly: TransactionResult - legacy field
    err: ?TransactionError = null,
    confirmationStatus: ?TransactionConfirmationStatus = null,
};

pub const RpcSignatureStatusConfig = struct {
    searchTransactionHistory: bool,
};

pub const RpcConfirmedTransactionStatusWithSignature = struct {
    signature: []const u8,
    slot: Slot,
    err: ?TransactionError = null,
    memo: ?[]const u8 = null,
    blockTime: ?UnixTimestamp = null,
    confirmationStatus: ?TransactionConfirmationStatus = null,
};

pub const TransactionConfirmationStatus = enum {
    processed,
    confirmed,
    finalized,
};

pub const RpcPrioritizationFee = struct {
    slot: Slot,
    prioritizationFee: u64,
};

pub const RpcPerfSample = struct {
    slot: Slot,
    numTransactions: u64,
    numNonVoteTransactions: ?u64 = null,
    numSlots: u64,
    samplePeriodSecs: u16,
};

pub const RpcLeaderSchedule = std.json.ArrayHashMap([]Slot);

pub const RpcLeaderScheduleConfigWrapper = union(enum(u8)) {
    slotOnly: ?Slot,
    configOnly: ?RpcLeaderScheduleConfig,
};

pub const RpcLeaderScheduleConfig = struct {
    identity: ?[]const u8 = null, // validator identity, as a base-58 encoded string
    commitment: ?CommitmentConfig = null,
};

pub const RpcBlockhash = struct {
    blockhash: []const u8,
    lastValidBlockHeight: u64,
};

pub const RpcIdentity = struct {
    /// The current node identity pubkey
    identity: []const u8,
};

pub const RpcSnapshotSlotInfo = struct {
    full: Slot,
    incremental: ?Slot = null,
};

pub const EpochInfo = struct {
    /// The current epoch
    epoch: Epoch,
    /// The current slot, relative to the start of the current epoch
    slotIndex: u64,
    /// The number of slots in this epoch
    slotsInEpoch: u64,
    /// The absolute current slot
    absoluteSlot: Slot,
    /// The current block height
    blockHeight: u64,
    /// Total number of transactions processed without error since genesis
    transactionCount: ?u64 = null,
};

pub const RpcContactInfo = struct {
    /// Pubkey of the node as a base-58 string
    pubkey: Pubkey,
    /// Gossip port
    gossip: ?SocketAddr = null,
    /// Tpu UDP port
    tpu: ?SocketAddr = null,
    /// Tpu QUIC port
    tpuQuic: ?SocketAddr = null,
    /// JSON RPC port
    rpc: ?SocketAddr = null,
    /// WebSocket PubSub port
    pubsub: ?SocketAddr = null,
    /// Software version
    version: ?[]const u8 = null,
    /// First 4 bytes of the FeatureSet identifier
    featureSet: ?u32 = null,
    /// Shred version
    shredVersion: ?u16 = null,
};

pub const RpcBlockProduction = struct {
    /// Map of leader base58 identity pubkeys to a tuple of `(number of leader slots, number of blocks produced)`
    byIdentity: std.json.ArrayHashMap(struct { usize, usize }),
    range: RpcBlockProductionRange,
};

pub const RpcBlockProductionConfig = struct {
    identity: ?[]const u8 = null, // validator identity, as a base-58 encoded string
    range: ?RpcBlockProductionConfigRange = null, // current epoch if `None`
    commitment: ?CommitmentConfig = null,
};

pub const RpcBlockProductionRange = struct {
    firstSlot: Slot,
    lastSlot: Slot,
};

pub const RpcBlockProductionConfigRange = struct {
    firstSlot: Slot,
    lastSlot: ?Slot = null,
};

pub const RpcSimulateTransactionResult = struct {
    err: ?TransactionError = null,
    logs: ?[][]const u8 = null,
    accounts: ?[]?UiAccount = null,
    unitsConsumed: ?u64 = null,
    returnData: ?UiTransactionReturnData = null,
    innerInstructions: ?[]UiInnerInstructions = null,
};

pub const UiTransactionReturnData = struct {
    programId: []const u8,
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
    legacyBinary: []const u8, // Old way of expressing base-58, retained for RPC backwards compatibility
    binary: struct { []const u8, TransactionBinaryEncoding },
    json: UiTransaction,
    accounts: UiAccountsList,
};

pub const UiAccountsList = struct {
    signatures: [][]const u8,
    accountKeys: []ParsedAccount,
};

pub const UiTransaction = struct {
    signatures: [][]const u8,
    message: UiRawMessage, // TODO: UiMessage,
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
    numRequiredSignatures: u8,

    /// The last `num_readonly_signed_accounts` of the signed keys are read-only
    /// accounts.
    numReadonlySignedAccounts: u8,

    /// The last `num_readonly_unsigned_accounts` of the unsigned keys are
    /// read-only accounts.
    numReadonlyUnsignedAccounts: u8,
};

pub const UiRawMessage = struct {
    header: MessageHeader,
    accountKeys: [][]const u8,
    recentBlockhash: []const u8,
    instructions: []UiCompiledInstruction,
    addressTableLookups: ?[]UiAddressTableLookup = null,
};

pub const UiParsedMessage = struct {
    accountKeys: []ParsedAccount,
    recentBlockhash: []const u8,
    instructions: []UiInstruction,
    addressTableLookups: ?[]UiAddressTableLookup = null,
};

pub const UiAddressTableLookup = struct {
    accountKey: []const u8,
    writableIndexes: []u8,
    readonlyIndexes: []u8,
};

pub const UiInstruction = union(enum(u8)) {
    compiled: UiCompiledInstruction,
    parsed: UiParsedInstruction,
};

pub const UiParsedInstruction = union(enum(u8)) {
    parsed: ParsedInstruction,
    partiallyDecoded: UiPartiallyDecodedInstruction,
};

pub const UiPartiallyDecodedInstruction = struct {
    programId: []const u8,
    accounts: []const u8,
    data: []const u8,
    stackHeight: ?u32,
};

pub const ParsedInstruction = struct {
    program: []const u8,
    programId: []const u8,
    parsed: std.json.Value,
    stackHeight: ?u32,
};

pub const UiCompiledInstruction = struct {
    programIdIndex: u8,
    accounts: []u8,
    data: []const u8,
    stackHeight: ?u32,
};

pub const ParsedAccount = struct {
    pubkey: []const u8,
    writable: bool,
    signer: bool,
    source: ?ParsedAccountSource,
};

pub const ParsedAccountSource = enum {
    transaction,
    lookupTable,
};

pub const TransactionBinaryEncoding = enum {
    base58,
    base64,
};

pub const UiTransactionStatusMeta = struct {
    err: ?TransactionError,
    status: ?UiTransactionStatusError, // This field is deprecated.  See https://github.com/solana-labs/solana/issues/9302
    fee: u64,
    preBalances: []u64,
    postBalances: []u64,
    innerInstructions: ?[]UiInnerInstructions,
    logMessages: ?[][]const u8,
    preTokenBalances: ?[]UiTransactionTokenBalance,
    postTokenBalances: ?[]UiTransactionTokenBalance,
    rewards: ?[]Reward,
    loadedAddresses: ?UiLoadedAddresses,
    returnData: ?UiTransactionReturnData,
    computeUnitsConsumed: ?u64,
};

pub const UiLoadedAddresses = struct {
    writable: [][]const u8,
    readonly: [][]const u8,
};

pub const Reward = struct {
    pubkey: []const u8,
    lamports: i64,
    postBalance: u64, // Account balance in lamports after `lamports` was applied
    rewardType: ?RewardType,
    commission: ?u8, // Vote account commission when the reward was credited, only present for voting and staking rewards
};

pub const RewardType = enum {
    fee,
    rent,
    staking,
    voting,
};

pub const UiTransactionTokenBalance = struct {
    accountIndex: u8,
    mint: []const u8,
    uiTokenAmount: UiTokenAmount,
    owner: ?[]const u8,
    programId: ?[]const u8,
};

pub const UiTokenAmount = struct {
    uiAmount: ?f64,
    decimals: u8,
    amount: []const u8,
    uiAmountString: []const u8,
};

pub const EncodedTransactionWithStatusMeta = struct {
    transaction: UiTransaction, // TODO: EncodedTransaction,
    meta: ?UiTransactionStatusMeta = null,
    version: ?TransactionVersion = null,
};

pub const TransactionVersion = union(enum(u8)) {
    legacy: Legacy,
    number: u8,
};

pub const Legacy = enum {
    legacy,
};

pub const UiConfirmedBlock = struct {
    previousBlockhash: []const u8,
    blockhash: []const u8,
    parentSlot: Slot,
    transactions: ?[]EncodedTransactionWithStatusMeta = null,
    signatures: ?[][]const u8 = null,
    rewards: ?[]Reward = null,
    blockTime: ?UnixTimestamp = null,
    blockHeight: ?u64 = null,
};

pub const RpcBlockConfig = struct {
    encoding: ?UiTransactionEncoding = null,
    transactionDetails: ?TransactionDetails = null,
    rewards: ?bool = null,
    commitment: ?CommitmentConfig = null,
    maxSupportedTransactionVersion: ?u8 = null,
};

pub const UiTransactionEncoding = enum {
    binary, // Legacy. Retained for RPC backwards compatibility
    base64,
    base58,
    json,
    jsonParsed,
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
    votePubkey: []const u8,

    /// The validator identity, as base-58 encoded string
    nodePubkey: []const u8,

    /// The current stake, in lamports, delegated to this vote account
    activatedStake: u64,

    /// An 8-bit integer used as a fraction (commission/MAX_U8) for rewards payout
    commission: u8,

    /// Whether this account is staked for the current epoch
    epochVoteAccount: bool,

    /// Latest history of earned credits for up to `MAX_RPC_VOTE_ACCOUNT_INFO_EPOCH_CREDITS_HISTORY` epochs
    ///   each tuple is (Epoch, credits, prev_credits)
    epochCredits: []struct { Epoch, u64, u64 },

    /// Most recent slot voted on by this vote account (0 if no votes exist)
    lastVote: u64,

    /// Current root slot for this vote account (0 if no root slot exists)
    rootSlot: Slot,
};

pub const RpcGetVoteAccountsConfig = struct {
    votePubkey: ?[]const u8 = null, // validator vote address, as a base-58 encoded string
    commitment: ?CommitmentConfig = null,
    keepUnstakedDelinquents: ?bool = null,
    delinquentSlotDistance: ?u64 = null,
};

pub const RpcSupply = struct {
    total: u64,
    circulating: u64,
    nonCirculating: u64,
    nonCirculatingAccounts: [][]const u8,
};

pub const RpcSupplyConfig = struct {
    commitment: ?CommitmentConfig = null,
    excludeNonCirculatingAccountsList: bool,
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
    commitment: ?CommitmentConfig = null,
    filter: ?RpcLargestAccountsFilter = null,
};

pub const RpcBlockCommitment = struct {
    commitment: ?BlockCommitmentArray = null,
    totalStake: u64,
};

pub const MAX_LOCKOUT_HISTORY: usize = 31;

pub const BlockCommitmentArray = [MAX_LOCKOUT_HISTORY + 1]u64;

pub const FeeRateGovernor = struct {
    // The current cost of a signature  This amount may increase/decrease over time based on
    // cluster processing load.
    lamportsPerSignature: u64,

    // The target cost of a signature when the cluster is operating around target_signatures_per_slot
    // signatures
    targetLamportsPerSignature: u64,

    // Used to estimate the desired processing capacity of the cluster.  As the signatures for
    // recent slots are fewer/greater than this value, lamports_per_signature will decrease/increase
    // for the next slot.  A value of 0 disables lamports_per_signature fee adjustments
    targetSignaturesPerSlot: u64,

    minLamportsPerSignature: u64,
    maxLamportsPerSignature: u64,

    // What portion of collected fees are to be destroyed, as a fraction of std::u8::MAX
    burnPercent: u8,
};

pub const RpcFees = struct {
    blockhash: []const u8,
    feeCalculator: FeeCalculator,
    lastValidSlot: Slot,
    lastValidBlockHeight: u64,
};

pub const RpcBlockhashFeeCalculator = struct {
    blockhash: []const u8,
    feeCalculator: FeeCalculator,
};

pub const RpcFeeCalculdator = struct {
    feeCalculator: FeeCalculator,
};

pub const FeeCalculator = struct {
    /// The current cost of a signature.
    ///
    /// This amount may increase/decrease over time based on cluster processing
    /// load.
    lamportsPerSignature: u64,
};

pub const RpcContextConfig = struct {
    commitment: ?CommitmentConfig = null,
    minContextSlot: ?Slot = null,
};

pub const EpochSchedule = struct {
    /// The maximum number of slots in each epoch.
    slotsPerEpoch: u64,

    /// A number of slots before beginning of an epoch to calculate
    /// a leader schedule for that epoch.
    leaderScheduleSlotOffset: u64,

    /// Whether epochs start short and grow.
    warmup: bool,

    /// The first epoch after the warmup period.
    ///
    /// Basically: `log2(slots_per_epoch) - log2(MINIMUM_SLOTS_PER_EPOCH)`.
    firstNormalEpoch: Epoch,

    /// The first slot after the warmup period.
    ///
    /// Basically: `MINIMUM_SLOTS_PER_EPOCH * (2.pow(first_normal_epoch) - 1)`.
    firstNormalSlot: Slot,
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
    foundationTerm: f64,
};

pub const RpcInflationReward = struct {
    epoch: Epoch,
    effectiveSlot: Slot,
    amount: u64, // lamports
    postBalance: u64, // lamports
    commission: ?u8 = null, // Vote account commission when the reward was credited
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
    dataSize: u64,
    memcmp: MemCmp,
    TokenAccountState,
};

pub const MemCmp = struct {};

pub const UiAccount = struct {
    lamports: u64,
    data: []const u8, // TODO: UiAccountData,
    owner: []const u8,
    executable: bool,
    rentEpoch: Epoch,
    space: ?u64 = null,
};

pub const UiAccountData = union(enum(u8)) {
    legacyBinary: []const u8, // Legacy. Retained for RPC backwards compatibility
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
    encoding: ?UiAccountEncoding = null,
    dataSlice: ?UiDataSliceConfig = null,
    commitment: ?CommitmentConfig = null,
    minContextSlot: ?Slot = null,
};

pub const RpcResponseContext = struct {
    slot: Slot,
    apiVersion: []const u8,
};

pub fn RpcResponse(comptime T: type) type {
    return struct {
        context: RpcResponseContext,
        value: T,
    };
}
