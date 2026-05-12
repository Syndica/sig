const std = @import("std");
const sig = @import("../lib.zig");

const Allocator = std.mem.Allocator;
const InstructionErrorEnum = sig.core.instruction.InstructionErrorEnum;
const Pubkey = sig.core.Pubkey;

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

    pub fn clone(self: @This(), allocator: Allocator) !TransactionError {
        return switch (self) {
            .InstructionError => |payload| switch (payload[1]) {
                .BorshIoError => |borsh_err| .{ .InstructionError = .{
                    payload[0], .{ .BorshIoError = try allocator.dupe(u8, borsh_err) },
                } },
                else => self,
            },
            else => self,
        };
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
