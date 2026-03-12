//! Every RPC method defined as a struct, where the fields are the parameters
//! for the rpc method.
//!
//! The order of the fields in the struct definition must match the
//! order of the parameters for the RPC method.
//!
//! Each method's response type is defined as a nested struct called `Response`.
//!
//! https://solana.com/de/docs/rpc

const std = @import("std");
const sig = @import("../sig.zig");
const rpc = @import("lib.zig");
const base58 = @import("base58");
const parse_instruction = @import("parse_instruction/lib.zig");

const Allocator = std.mem.Allocator;
const ParseOptions = std.json.ParseOptions;

const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;
const Slot = sig.core.Slot;
const ClientVersion = sig.version.ClientVersion;

const account_codec = sig.rpc.account_codec;

pub fn Result(comptime method: MethodAndParams.Tag) type {
    return union(enum) {
        ok: Request(method).Response,
        err: rpc.response.Error,
    };
}

/// Returns t
pub fn Request(comptime method: MethodAndParams.Tag) type {
    const FieldType = @FieldType(MethodAndParams, @tagName(method));
    if (FieldType == noreturn) @compileError("TODO: impl " ++ @tagName(method));
    return FieldType;
}

pub const MethodAndParams = union(enum) {
    getAccountInfo: GetAccountInfo,
    getBalance: GetBalance,
    getBlock: GetBlock,
    getBlockCommitment: GetBlockCommitment,
    getBlockHeight: GetBlockHeight,
    getBlockProduction: GetBlockProduction,
    getBlocks: GetBlocks,
    getBlocksWithLimit: GetBlocksWithLimit,
    getBlockTime: noreturn,
    getClusterNodes: GetClusterNodes,
    getEpochInfo: GetEpochInfo,
    getEpochSchedule: GetEpochSchedule,
    getFeeForMessage: GetFeeForMessage,
    getFirstAvailableBlock: noreturn,

    /// https://github.com/Syndica/sig/issues/557
    getGenesisHash: GetGenesisHash,
    /// https://github.com/Syndica/sig/issues/558
    getHealth: GetHealth,
    /// Custom (not standardized) RPC method for "GET /*snapshot*.tar.bz2"
    getSnapshot: GetSnapshot,

    getHighestSnapshotSlot: GetHighestSnapshotSlot,
    getIdentity: GetIdentity,
    getInflationGovernor: GetInflationGovernor,
    getInflationRate: GetInflationRate,
    getInflationReward: GetInflationReward,
    getLargestAccounts: noreturn,
    getLatestBlockhash: GetLatestBlockhash,
    getLeaderSchedule: GetLeaderSchedule,
    getMaxRetransmitSlot: noreturn,
    getMaxShredInsertSlot: noreturn,
    getMinimumBalanceForRentExemption: GetMinimumBalanceForRentExemption,
    getMultipleAccounts: GetMultipleAccounts,
    getProgramAccounts: noreturn,
    getRecentPerformanceSamples: GetRecentPerformanceSamples,
    getRecentPrioritizationFees: GetRecentPrioritizationFees,
    getSignaturesForAddress: GetSignaturesForAddress,
    getSignatureStatuses: GetSignatureStatuses,
    getSlot: GetSlot,
    getSlotLeader: GetSlotLeader,
    getSlotLeaders: GetSlotLeaders,
    getStakeMinimumDelegation: GetStakeMinimumDelegation,
    getSupply: noreturn,
    getTokenAccountBalance: GetTokenAccountBalance,
    getTokenAccountsByDelegate: noreturn,
    getTokenAccountsByOwner: noreturn,
    getTokenLargestAccounts: noreturn,
    getTokenSupply: GetTokenSupply,
    getTransaction: GetTransaction,
    getTransactionCount: GetTransactionCount,
    getVersion: GetVersion,
    getVoteAccounts: GetVoteAccounts,
    isBlockhashValid: IsBlockhashValid,
    minimumLedgerSlot: noreturn,
    requestAirdrop: RequestAirdrop,
    sendTransaction: SendTransaction,
    simulateTransaction: noreturn,

    pub const Tag = @typeInfo(MethodAndParams).@"union".tag_type.?;

    /// Returns a wrapper over `self` which will be stringified as an array.
    pub fn jsonStringifyAsParamsArray(self: MethodAndParams) JsonStringifiedAsParamsArray {
        return .{ .data = self };
    }

    pub const JsonStringifiedAsParamsArray = struct {
        data: MethodAndParams,

        pub fn jsonStringify(
            self: JsonStringifiedAsParamsArray,
            /// `*std.json.WriteStream(...)`
            jw: anytype,
        ) @TypeOf(jw.*).Error!void {
            switch (self.data) {
                inline else => |method| {
                    const T = @TypeOf(method);
                    if (@hasDecl(T, "jsonStringify")) {
                        try jw.write(method);
                    } else {
                        var null_count: usize = 0;

                        try jw.beginArray();
                        inline for (@typeInfo(T).@"struct".fields) |field| cont: {
                            const maybe_value = @field(method, field.name);
                            const value = blk: {
                                if (@typeInfo(field.type) != .optional) break :blk maybe_value;
                                if (maybe_value) |value| break :blk value;
                                null_count += 1;
                                break :cont;
                            };

                            // we counted `null_count` null element before this
                            // without writing anything, and instead of writing
                            // them we just skipped them. but since this element
                            // isn't null, we have to write out the leading null
                            // elements so that this one is at the correct index
                            for (0..null_count) |_| try jw.write(null);
                            null_count = 0;
                            try jw.write(value);
                        }
                        try jw.endArray();
                    }
                },
            }
        }
    };
};

pub const GetSnapshot = struct {
    path: []const u8,
    get: Getter,

    pub const Getter = enum { file, size };

    pub fn jsonParse(
        _: std.mem.Allocator,
        source: anytype,
        _: std.json.ParseOptions,
    ) std.json.ParseError(@TypeOf(source.*))!GetSnapshot {
        @compileError("GetSnapshot is not a real JSON-RPC method" ++
            "It is meant only for RPC server. Do not serialize");
    }

    pub const Response = union(Getter) {
        file: std.fs.File,
        size: u64,

        pub fn jsonStringify(
            _: Response,
            /// `*std.json.WriteStream(...)`
            jw: anytype,
        ) @TypeOf(jw.*).Error!void {
            @compileError("GetSnapshot is not a real JSON-RPC method" ++
                "It is meant only for RPC server. Do not serialize");
        }
    };
};

pub const GetAccountInfo = struct {
    pubkey: Pubkey,
    config: ?Config = null,

    pub const Config = struct {
        commitment: ?common.Commitment = null,
        minContextSlot: ?u64 = null,
        encoding: ?account_codec.AccountEncoding = null,
        dataSlice: ?common.DataSlice = null,
    };

    pub const Response = struct {
        context: common.Context,
        value: ?Value,

        pub const Value = struct {
            data: account_codec.AccountData,
            executable: bool,
            lamports: u64,
            owner: Pubkey,
            rentEpoch: u64,
            space: u64,
        };
    };
};

pub const GetBalance = struct {
    pubkey: Pubkey,
    config: ?common.CommitmentSlotConfig = null,

    pub const Response = struct {
        context: common.Context,
        value: u64,
    };
};

pub const GetHealth = struct {
    /// Response carries the health status of the node.
    ///
    /// When healthy, the JSON-RPC response is: `{"result": "ok"}`
    /// When unhealthy, the JSON-RPC response is an error:
    ///   `{"error": {"code": -32005, "message": "...", "data": {"numSlotsBehind": ...}}}`
    ///
    /// The HTTP GET /health endpoint always returns 200 with "ok", "behind", or "unknown".
    ///
    /// See agave: https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L2806-L2818
    /// See agave: https://github.com/anza-xyz/agave/blob/v3.1.8/rpc-client-api/src/custom_error.rs#L49-L50
    pub const Response = RpcHealthStatus;

    /// JSON-RPC error code for NodeUnhealthy, matching agave's JSON_RPC_SERVER_ERROR_NODE_UNHEALTHY.
    /// See: https://github.com/anza-xyz/agave/blob/v3.1.8/rpc-client-api/src/custom_error.rs#L16
    pub const node_unhealthy_code: i64 = -32005;
};

pub const GetBlock = struct {
    /// The slot to get the block for (first positional argument)
    slot: Slot,
    encoding_or_config: ?EncodingOrConfig = null,

    pub const Config = struct {
        /// Only `confirmed` and `finalized` are supported. `processed` is rejected.
        commitment: ?common.Commitment = null,
        encoding: ?common.TransactionEncoding = null,
        transactionDetails: ?common.TransactionDetails = null,
        maxSupportedTransactionVersion: ?u8 = null,
        rewards: ?bool = null,

        pub fn getCommitment(self: Config) common.Commitment {
            return self.commitment orelse common.Commitment.finalized;
        }

        pub fn getEncoding(self: Config) common.TransactionEncoding {
            return self.encoding orelse common.TransactionEncoding.json;
        }

        pub fn getTransactionDetails(self: Config) common.TransactionDetails {
            return self.transactionDetails orelse common.TransactionDetails.full;
        }

        pub fn getMaxSupportedTransactionVersion(self: Config) u8 {
            return self.maxSupportedTransactionVersion orelse 0;
        }

        pub fn getRewards(self: Config) bool {
            return self.rewards orelse true;
        }
    };

    /// RPC spec allows either a config or just an encoding
    /// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/rpc-client-types/src/config.rs#L233
    pub const EncodingOrConfig = union(enum) {
        encoding: common.TransactionEncoding,
        config: Config,

        pub fn jsonParseFromValue(
            allocator: std.mem.Allocator,
            source: std.json.Value,
            options: std.json.ParseOptions,
        ) std.json.ParseFromValueError!EncodingOrConfig {
            return switch (source) {
                .string => |s| .{
                    .encoding = std.meta.stringToEnum(common.TransactionEncoding, s) orelse
                        return error.InvalidEnumTag,
                },
                .object => .{ .config = try std.json.innerParseFromValue(
                    Config,
                    allocator,
                    source,
                    options,
                ) },
                else => error.UnexpectedToken,
            };
        }

        pub fn jsonStringify(self: EncodingOrConfig, jw: anytype) !void {
            switch (self) {
                .encoding => |enc| try jw.write(@tagName(enc)),
                .config => |c| try jw.write(c),
            }
        }
    };

    pub fn resolveConfig(self: GetBlock) Config {
        const eoc = self.encoding_or_config orelse return Config{};
        return switch (eoc) {
            .encoding => |enc| Config{
                .encoding = enc,
            },
            .config => |c| c,
        };
    }

    /// Response for getBlock RPC method (UiConfirmedBlock equivalent)
    pub const Response = struct {
        /// The blockhash of the previous block
        previousBlockhash: Hash,
        /// The blockhash of this block
        blockhash: Hash,
        /// The slot of the parent block
        parentSlot: u64,
        /// Transactions in the block (present when transactionDetails is full or accounts)
        transactions: ?[]const EncodedTransactionWithStatusMeta = null,
        /// Transaction signatures (present when transactionDetails is signatures)
        signatures: ?[]const Signature = null,
        /// Block rewards (present when rewards=true, which is the default)
        rewards: ?[]const UiReward = null,
        /// Number of reward partitions (if applicable)
        numRewardPartitions: ?u64 = null,
        /// Estimated production time as Unix timestamp (seconds since epoch)
        blockTime: ?i64 = null,
        /// Block height
        blockHeight: ?u64 = null,

        pub fn jsonStringify(self: Response, jw: anytype) !void {
            try jw.beginObject();
            if (self.blockHeight) |h| {
                try jw.objectField("blockHeight");
                try jw.write(h);
            }
            if (self.blockTime) |t| {
                try jw.objectField("blockTime");
                try jw.write(t);
            }
            try jw.objectField("blockhash");
            try jw.write(self.blockhash);
            if (self.numRewardPartitions) |npw| {
                try jw.objectField("numRewardPartitions");
                try jw.write(npw);
            }
            try jw.objectField("parentSlot");
            try jw.write(self.parentSlot);
            try jw.objectField("previousBlockhash");
            try jw.write(self.previousBlockhash);
            if (self.rewards) |r| {
                try jw.objectField("rewards");
                try jw.write(r);
            }
            if (self.transactions) |txs| {
                try jw.objectField("transactions");
                try jw.write(txs);
            }
            if (self.signatures) |sigs| {
                try jw.objectField("signatures");
                try jw.write(sigs);
            }
            try jw.endObject();
        }

        /// Write a `[]const u8` as a JSON array of integers instead of a string.
        /// Zig's JSON writer treats `[]const u8` as a string, but Agave's serde
        /// serializes `Vec<u8>` as an array of integers (e.g. `[0, 1, 4]`).
        fn writeU8SliceAsIntArray(slice: []const u8, jw: anytype) !void {
            try jw.beginArray();
            for (slice) |byte| {
                try jw.write(byte);
            }
            try jw.endArray();
        }

        /// Encoded transaction with status metadata for RPC response.
        pub const EncodedTransactionWithStatusMeta = struct {
            /// The transaction - either base64 encoded binary or JSON structure
            transaction: EncodedTransaction,
            /// Transaction status metadata
            meta: ?UiTransactionStatusMeta = null,
            /// Transaction version ("legacy" or version number)
            version: ?TransactionVersion = null,

            pub const TransactionVersion = union(enum) {
                legacy,
                number: u8,

                pub fn jsonStringify(self: TransactionVersion, jw: anytype) !void {
                    switch (self) {
                        .legacy => try jw.write("legacy"),
                        .number => |n| try jw.write(n),
                    }
                }
            };

            pub fn jsonStringify(self: EncodedTransactionWithStatusMeta, jw: anytype) !void {
                try jw.beginObject();
                if (self.meta) |m| {
                    try jw.objectField("meta");
                    try jw.write(m);
                }
                try jw.objectField("transaction");
                try jw.write(self.transaction);
                if (self.version) |v| {
                    try jw.objectField("version");
                    try v.jsonStringify(jw);
                }
                try jw.endObject();
            }
        };

        /// Encoded transaction - can be either base64/base58 binary or JSON structure.
        /// For base64/base58: serializes as [data, encoding] array
        /// For JSON: serializes as object with signatures and message
        pub const EncodedTransaction = union(enum) {
            legacy_binary: []const u8,
            /// Binary encoding: [base64_data, "base64"] or [base58_data, "base58"]
            binary: struct {
                []const u8,
                enum { base58, base64 },
            },
            /// JSON encoding: object with signatures and message
            json: struct {
                signatures: []const Signature,
                message: UiMessage,
            },
            accounts: struct {
                signatures: []const Signature,
                accountKeys: []const ParsedAccount,
            },

            pub fn jsonStringify(self: EncodedTransaction, jw: anytype) !void {
                switch (self) {
                    .legacy_binary => |b| try jw.write(b),
                    .binary => |b| try jw.write(b),
                    .json => |j| try jw.write(j),
                    .accounts => |a| try jw.write(a),
                }
            }
        };

        pub const UiMessage = union(enum) {
            parsed: UiParsedMessage,
            raw: UiRawMessage,

            pub fn jsonStringify(self: UiMessage, jw: anytype) !void {
                switch (self) {
                    .parsed => |p| try jw.write(p),
                    .raw => |r| try jw.write(r),
                }
            }
        };

        pub const UiParsedMessage = struct {
            account_keys: []const ParsedAccount,
            recent_blockhash: Hash,
            instructions: []const parse_instruction.UiInstruction,
            address_table_lookups: ?[]const AddressTableLookup = null,

            pub fn jsonStringify(self: UiParsedMessage, jw: anytype) !void {
                try jw.beginObject();
                try jw.objectField("accountKeys");
                try jw.write(self.account_keys);
                try jw.objectField("recentBlockhash");
                try jw.write(self.recent_blockhash);
                try jw.objectField("instructions");
                try jw.write(self.instructions);
                if (self.address_table_lookups) |atl| {
                    try jw.objectField("addressTableLookups");
                    try jw.write(atl);
                }
                try jw.endObject();
            }
        };

        pub const MessageHeader = struct {
            numRequiredSignatures: u8,
            numReadonlySignedAccounts: u8,
            numReadonlyUnsignedAccounts: u8,
        };

        pub const UiRawMessage = struct {
            header: MessageHeader,
            account_keys: []const Pubkey,
            recent_blockhash: Hash,
            instructions: []const parse_instruction.UiCompiledInstruction,
            address_table_lookups: ?[]const AddressTableLookup = null,

            pub fn jsonStringify(self: UiRawMessage, jw: anytype) !void {
                try jw.beginObject();
                try jw.objectField("accountKeys");
                try jw.write(self.account_keys);
                try jw.objectField("header");
                try jw.write(self.header);
                try jw.objectField("recentBlockhash");
                try jw.write(self.recent_blockhash);
                try jw.objectField("instructions");
                try jw.write(self.instructions);
                if (self.address_table_lookups) |atl| {
                    try jw.objectField("addressTableLookups");
                    try jw.write(atl);
                }
                try jw.endObject();
            }
        };

        /// JSON-encoded message
        pub const EncodedMessage = struct {
            accountKeys: []const Pubkey,
            header: MessageHeader,
            recentBlockhash: Hash,
            instructions: []const EncodedInstruction,
            addressTableLookups: ?[]const AddressTableLookup = null,

            pub fn jsonStringify(self: EncodedMessage, jw: anytype) !void {
                try jw.beginObject();
                try jw.objectField("accountKeys");
                try jw.write(self.accountKeys);
                try jw.objectField("header");
                try jw.write(self.header);
                try jw.objectField("recentBlockhash");
                try jw.write(self.recentBlockhash);
                try jw.objectField("instructions");
                try jw.write(self.instructions);
                if (self.addressTableLookups) |atl| {
                    try jw.objectField("addressTableLookups");
                    try jw.write(atl);
                }
                try jw.endObject();
            }
        };

        pub const EncodedInstruction = struct {
            programIdIndex: u8,
            accounts: []const u8,
            data: []const u8,
            stackHeight: ?u32 = null,

            pub fn jsonStringify(self: EncodedInstruction, jw: anytype) !void {
                try jw.beginObject();
                try jw.objectField("programIdIndex");
                try jw.write(self.programIdIndex);
                try jw.objectField("accounts");
                try writeU8SliceAsIntArray(self.accounts, jw);
                try jw.objectField("data");
                try jw.write(self.data);
                if (self.stackHeight) |sh| {
                    try jw.objectField("stackHeight");
                    try jw.write(sh);
                }
                try jw.endObject();
            }
        };

        pub const AddressTableLookup = struct {
            accountKey: Pubkey,
            writableIndexes: []const u8,
            readonlyIndexes: []const u8,

            pub fn jsonStringify(self: AddressTableLookup, jw: anytype) !void {
                try jw.beginObject();
                try jw.objectField("accountKey");
                try jw.write(self.accountKey);
                try jw.objectField("readonlyIndexes");
                try writeU8SliceAsIntArray(self.readonlyIndexes, jw);
                try jw.objectField("writableIndexes");
                try writeU8SliceAsIntArray(self.writableIndexes, jw);
                try jw.endObject();
            }
        };

        /// Account key with metadata (for jsonParsed and accounts modes)
        pub const ParsedAccount = struct {
            pubkey: Pubkey,
            writable: bool,
            signer: bool,
            source: ParsedAccountSource,

            pub fn jsonStringify(self: ParsedAccount, jw: anytype) !void {
                try jw.beginObject();
                try jw.objectField("pubkey");
                try jw.write(self.pubkey);
                try jw.objectField("signer");
                try jw.write(self.signer);
                try jw.objectField("source");
                try jw.write(@tagName(self.source));
                try jw.objectField("writable");
                try jw.write(self.writable);
                try jw.endObject();
            }
        };

        pub const ParsedAccountSource = enum {
            transaction,
            lookupTable,
        };

        /// UI representation of transaction status metadata
        pub const UiTransactionStatusMeta = struct {
            err: ?sig.ledger.transaction_status.TransactionError = null,
            status: UiTransactionResultStatus,
            fee: u64,
            preBalances: []const u64,
            postBalances: []const u64,
            innerInstructions: JsonSkippable([]const parse_instruction.UiInnerInstructions) = .{
                .value = &.{},
            },
            logMessages: JsonSkippable([]const []const u8) = .{
                .value = &.{},
            },
            preTokenBalances: JsonSkippable([]const UiTransactionTokenBalance) = .{
                .value = &.{},
            },
            postTokenBalances: JsonSkippable([]const UiTransactionTokenBalance) = .{
                .value = &.{},
            },
            rewards: JsonSkippable([]const UiReward) = .{ .value = &.{} },
            loadedAddresses: JsonSkippable(UiLoadedAddresses) = .skip,
            returnData: JsonSkippable(UiTransactionReturnData) = .skip,
            computeUnitsConsumed: JsonSkippable(u64) = .skip,
            costUnits: JsonSkippable(u64) = .skip,

            pub fn jsonStringify(self: UiTransactionStatusMeta, jw: anytype) !void {
                try jw.beginObject();
                if (self.computeUnitsConsumed != .skip) {
                    try jw.objectField("computeUnitsConsumed");
                    try jw.write(self.computeUnitsConsumed);
                }
                if (self.costUnits != .skip) {
                    try jw.objectField("costUnits");
                    try jw.write(self.costUnits);
                }
                try jw.objectField("err");
                try jw.write(self.err);
                try jw.objectField("fee");
                try jw.write(self.fee);
                if (self.innerInstructions != .skip) {
                    try jw.objectField("innerInstructions");
                    try jw.write(self.innerInstructions);
                }
                if (self.loadedAddresses != .skip) {
                    try jw.objectField("loadedAddresses");
                    try jw.write(self.loadedAddresses);
                }
                if (self.logMessages != .skip) {
                    try jw.objectField("logMessages");
                    try jw.write(self.logMessages);
                }
                try jw.objectField("postBalances");
                try jw.write(self.postBalances);
                try jw.objectField("postTokenBalances");
                try jw.write(self.postTokenBalances);
                try jw.objectField("preBalances");
                try jw.write(self.preBalances);
                try jw.objectField("preTokenBalances");
                try jw.write(self.preTokenBalances);
                if (self.returnData != .skip) {
                    try jw.objectField("returnData");
                    try jw.write(self.returnData);
                }
                if (self.rewards != .skip) {
                    try jw.objectField("rewards");
                    try jw.write(self.rewards);
                }
                try jw.objectField("status");
                try jw.write(self.status);
                try jw.endObject();
            }
        };

        /// Transaction result status for RPC compatibility.
        /// Serializes as `{"Ok": null}` on success or `{"Err": <error>}` on failure.
        pub const UiTransactionResultStatus = struct {
            Ok: ?struct {} = null,
            Err: ?sig.ledger.transaction_status.TransactionError = null,

            pub fn jsonStringify(self: UiTransactionResultStatus, jw: anytype) !void {
                try jw.beginObject();
                if (self.Err) |err| {
                    try jw.objectField("Err");
                    try jw.write(err);
                } else {
                    try jw.objectField("Ok");
                    try jw.write(null);
                }
                try jw.endObject();
            }
        };

        /// Token balance for RPC response (placeholder)
        pub const UiTransactionTokenBalance = struct {
            accountIndex: u8,
            mint: Pubkey,
            owner: ?Pubkey = null,
            programId: ?Pubkey = null,
            uiTokenAmount: UiTokenAmount,

            pub fn jsonStringify(self: UiTransactionTokenBalance, jw: anytype) !void {
                try jw.beginObject();
                try jw.objectField("accountIndex");
                try jw.write(self.accountIndex);
                try jw.objectField("mint");
                try jw.write(self.mint);
                if (self.owner) |o| {
                    try jw.objectField("owner");
                    try jw.write(o);
                }
                if (self.programId) |p| {
                    try jw.objectField("programId");
                    try jw.write(p);
                }
                try jw.objectField("uiTokenAmount");
                try jw.write(self.uiTokenAmount);
                try jw.endObject();
            }
        };

        pub const UiTokenAmount = struct {
            amount: []const u8,
            decimals: u8,
            uiAmount: ?f64 = null,
            uiAmountString: []const u8,

            pub fn jsonStringify(self: UiTokenAmount, jw: anytype) !void {
                try jw.beginObject();
                try jw.objectField("amount");
                try jw.write(self.amount);
                try jw.objectField("decimals");
                try jw.write(self.decimals);
                if (self.uiAmount) |ua| {
                    try jw.objectField("uiAmount");
                    try writeExactFloat(jw, ua);
                }
                try jw.objectField("uiAmountString");
                try jw.write(self.uiAmountString);
                try jw.endObject();
            }

            /// Write an f64 as a JSON number matching Rust's serde_json output.
            /// Zig's std.json serializes 3.0 as "3e0", but serde serializes it as "3.0".
            fn writeExactFloat(jw: anytype, value: f64) !void {
                var buf: [64]u8 = undefined;
                const result = std.fmt.bufPrint(&buf, "{d}", .{value}) catch unreachable;
                if (std.mem.indexOf(u8, result, ".") == null) {
                    try jw.print("{s}.0", .{result});
                } else {
                    try jw.print("{s}", .{result});
                }
            }
        };

        pub const UiLoadedAddresses = struct {
            readonly: []const Pubkey,
            writable: []const Pubkey,
        };

        pub const UiTransactionReturnData = struct {
            programId: Pubkey,
            data: struct { []const u8, enum { base64 } },

            pub fn jsonStringify(self: UiTransactionReturnData, jw: anytype) !void {
                try jw.beginObject();
                try jw.objectField("programId");
                try jw.write(self.programId);
                try jw.objectField("data");
                try jw.beginArray();
                try jw.write(self.data.@"0");
                try jw.write(@tagName(self.data.@"1"));
                try jw.endArray();
                try jw.endObject();
            }
        };

        pub const UiReward = struct {
            /// The public key of the account that received the reward (base-58 encoded)
            pubkey: Pubkey,
            /// Number of lamports credited or debited
            lamports: i64,
            /// Account balance in lamports after the reward was applied
            postBalance: u64,
            /// Type of reward
            rewardType: ?RewardType = null,
            /// Vote account commission when reward was credited (for voting/staking rewards)
            commission: ?u8 = null,

            pub const RewardType = enum {
                Fee,
                Rent,
                Staking,
                Voting,

                pub fn jsonStringify(self: RewardType, jw: anytype) !void {
                    try jw.write(@tagName(self));
                }
            };

            pub fn jsonStringify(self: UiReward, jw: anytype) !void {
                try jw.beginObject();
                try jw.objectField("pubkey");
                try jw.write(self.pubkey);
                try jw.objectField("lamports");
                try jw.write(self.lamports);
                try jw.objectField("postBalance");
                try jw.write(self.postBalance);
                try jw.objectField("rewardType");
                try jw.write(self.rewardType);
                try jw.objectField("commission");
                try jw.write(self.commission);
                try jw.endObject();
            }

            pub fn fromLedgerReward(reward: sig.ledger.meta.Reward) UiReward {
                return .{
                    .pubkey = reward.pubkey,
                    .lamports = reward.lamports,
                    .postBalance = reward.post_balance,
                    .rewardType = if (reward.reward_type) |rt| switch (rt) {
                        .fee => RewardType.Fee,
                        .rent => RewardType.Rent,
                        .staking => RewardType.Staking,
                        .voting => RewardType.Voting,
                    } else null,
                    .commission = reward.commission,
                };
            }
        };
    };
};

pub const GetBlockCommitment = struct {
    slot: u64,

    pub const Response = struct {
        commitment: ?[]const u64 = null,
        totalStake: u64,
    };
};

pub const GetBlockHeight = struct {
    config: ?common.CommitmentSlotConfig = null,

    pub const Response = u64;
};

pub const GetBlockProduction = struct {
    config: ?Config = null,

    pub const Config = struct {
        commitment: ?common.Commitment = null,
        /// Filter results to a single validator identity (base-58 encoded pubkey)
        identity: ?[]const u8 = null,
        range: ?Range = null,
    };

    pub const Range = struct {
        firstSlot: Slot,
        lastSlot: ?Slot = null,
    };

    pub const Response = struct {
        context: common.Context,
        value: Value,
    };

    pub const Value = struct {
        byIdentity: ByIdentity,
        range: ResponseRange,
    };

    pub const ResponseRange = struct {
        firstSlot: Slot,
        lastSlot: Slot,
    };

    /// Map of base58 pubkey string -> [leader_slots, blocks_produced]
    pub const ByIdentity = struct {
        map: sig.utils.collections.PubkeyMap(struct { u64, u64 }),

        pub fn jsonStringify(self: ByIdentity, jw: anytype) !void {
            try jw.beginObject();
            for (self.map.keys(), self.map.values()) |key, value| {
                const base58string = key.base58String();
                try jw.objectField(base58string.constSlice());
                try jw.write(value);
            }
            try jw.endObject();
        }
    };
};

// TODO: getBlockTime

pub const GetBlocks = struct {
    start_slot: Slot,
    end_slot_or_config: ?EndSlotOrConfig = null,

    pub const MAX_GET_CONFIRMED_BLOCKS_RANGE: u64 = 500_000;

    pub const Config = struct {
        commitment: ?common.Commitment = null,
    };

    /// The second positional param can be either an end_slot (integer) or a
    /// commitment config (object), matching Agave's RpcBlocksConfigWrapper.
    pub const EndSlotOrConfig = union(enum) {
        end_slot: Slot,
        config: Config,

        pub fn jsonStringify(self: EndSlotOrConfig, jw: anytype) !void {
            switch (self) {
                .end_slot => |s| try jw.write(s),
                .config => |c| try jw.write(c),
            }
        }

        pub fn jsonParseFromValue(
            allocator: std.mem.Allocator,
            source: std.json.Value,
            options: std.json.ParseOptions,
        ) std.json.ParseFromValueError!EndSlotOrConfig {
            return switch (source) {
                .integer => |i| .{ .end_slot = @intCast(i) },
                .object => .{ .config = try std.json.innerParseFromValue(
                    Config,
                    allocator,
                    source,
                    options,
                ) },
                else => error.UnexpectedToken,
            };
        }
    };

    pub fn endSlot(self: GetBlocks) ?Slot {
        if (self.end_slot_or_config) |eoc| switch (eoc) {
            .end_slot => |s| return s,
            .config => {},
        };
        return null;
    }

    pub fn commitment(self: GetBlocks) common.Commitment {
        if (self.end_slot_or_config) |eoc| switch (eoc) {
            .end_slot => {},
            .config => |c| if (c.commitment) |cm| return cm,
        };
        return .finalized;
    }

    pub const Response = []const Slot;
};

/// https://solana.com/docs/rpc/http/getblockswithlimit
pub const GetBlocksWithLimit = struct {
    start_slot: Slot,
    limit: u64,
    config: ?Config = null,

    pub const Config = struct {
        commitment: ?common.Commitment = null,
    };

    pub fn commitment(self: GetBlocksWithLimit) common.Commitment {
        if (self.config) |c| if (c.commitment) |cm| return cm;
        return .finalized;
    }

    pub const Response = []const Slot;
};

pub const GetClusterNodes = struct {
    pub const Response = []const common.RpcContactInfo;
};

pub const GetEpochInfo = struct {
    config: ?common.CommitmentSlotConfig = null,

    pub const Response = struct {
        absoluteSlot: u64,
        blockHeight: u64,
        epoch: u64,
        slotIndex: u64,
        slotsInEpoch: u64,
        transactionCount: u64,
    };
};

pub const GetEpochSchedule = struct {
    pub const Response = struct {
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
        firstNormalEpoch: u64,
        /// The first slot after the warmup period.
        ///
        /// Basically: `MINIMUM_SLOTS_PER_EPOCH * (2.pow(first_normal_epoch) - 1)`.
        firstNormalSlot: u64,
    };
};

// TODO: getFeeForMessage
// TODO: getFirstAvailableBlock

pub const GetGenesisHash = struct {
    pub const Response = struct {
        hash: sig.core.Hash,

        pub fn jsonParse(
            _: std.mem.Allocator,
            source: anytype,
            _: std.json.ParseOptions,
        ) std.json.ParseError(@TypeOf(source.*))!Response {
            return switch (try source.next()) {
                .string => |str| .{
                    .hash = sig.core.Hash.parseRuntime(str) catch return error.UnexpectedToken,
                },
                else => error.UnexpectedToken,
            };
        }

        pub fn jsonStringify(
            self: Response,
            /// `*std.json.WriteStream(...)`
            jw: anytype,
        ) !void {
            try jw.write(self.hash.base58String().slice());
        }
    };
};

// TODO: getHealth

/// [agave] https://github.com/anza-xyz/agave/blob/d70b1714b1153674c16e2b15b68790d274dfe953/rpc/src/rpc.rs#L3580-L3586
pub const GetFeeForMessage = struct {
    /// Base64-encoded serialized VersionedMessage
    message: []const u8,
    config: ?Config = null,

    pub const Config = struct {
        commitment: ?common.Commitment = null,
        minContextSlot: ?Slot = null,
    };

    pub const Response = struct {
        context: common.Context,
        /// Fee in lamports, or null if the blockhash has expired.
        value: ?u64,
    };
};

pub const GetHighestSnapshotSlot = struct {
    pub const Response = ?SnapshotSlotInfo;

    pub const SnapshotSlotInfo = struct {
        full: Slot,
        incremental: ?Slot = null,
    };
};

// TODO: getIdentity

pub const GetInflationReward = struct {
    addresses: []const Pubkey,
    config: ?Config = null,

    pub const Config = struct {
        commitment: ?common.Commitment = null,
        epoch: ?u64 = null,
        minContextSlot: ?Slot = null,
    };

    pub const Response = []const ?InflationReward;

    pub const InflationReward = struct {
        epoch: u64,
        effectiveSlot: Slot,
        amount: u64,
        postBalance: u64,
        commission: ?u8,
    };
};

pub const GetInflationGovernor = struct {
    config: ?Config = null,

    pub const Config = struct {
        commitment: ?common.Commitment = null,
    };

    pub const Response = struct {
        initial: f64,
        terminal: f64,
        taper: f64,
        foundation: f64,
        foundationTerm: f64,
    };
};

pub const GetInflationRate = struct {
    // This RPC method takes no parameters (matches Agave behavior)

    pub const Response = struct {
        total: f64,
        validator: f64,
        foundation: f64,
        epoch: u64,
    };
};

// TODO: getLargeAccounts

pub const GetLatestBlockhash = struct {
    config: ?common.CommitmentSlotConfig = null,

    pub const Response = struct {
        context: common.Context,
        value: Value,

        pub const Value = struct {
            blockhash: []const u8,
            lastValidBlockHeight: u64,
        };
    };
};

pub const GetLeaderSchedule = struct {
    slot: ?u64 = null,
    config: ?Config = null,

    pub const Config = struct {
        commitment: ?common.Commitment = null,
        identity: ?[]const u8 = null,
    };

    /// [agave] RpcLeaderSchedule = HashMap<String, Vec<usize>>; returns null when epoch not in cache
    pub const Response = ?LeaderScheduleValue;

    pub const LeaderScheduleValue = struct {
        value: sig.utils.collections.PubkeyMap([]const u64),

        pub fn deinit(self: LeaderScheduleValue, allocator: std.mem.Allocator) void {
            self.value.deinit(allocator);
        }

        pub fn jsonParse(
            allocator: std.mem.Allocator,
            source: anytype,
            options: std.json.ParseOptions,
        ) std.json.ParseError(@TypeOf(source.*))!LeaderScheduleValue {
            const json_object = switch (try std.json.Value.jsonParse(allocator, source, options)) {
                .object => |obj| obj,
                else => return error.UnexpectedToken,
            };

            var map = sig.utils.collections.PubkeyMap([]const u64){};
            for (json_object.keys(), json_object.values()) |key, value| {
                const slots = try allocator.alloc(u64, value.array.items.len);
                for (value.array.items, 0..) |slot, i| {
                    slots[i] = @intCast(slot.integer);
                }
                const pubkey = Pubkey.parseRuntime(key) catch return error.InvalidNumber;
                try map.put(allocator, pubkey, slots);
            }

            return .{ .value = map };
        }

        pub fn jsonStringify(
            self: LeaderScheduleValue,
            /// `*std.json.WriteStream(...)`
            jw: anytype,
        ) !void {
            try jw.beginObject();

            var it = self.value.iterator();
            while (it.next()) |entry| {
                try jw.objectField(entry.key_ptr.base58String().slice());
                try jw.write(entry.value_ptr.*);
            }

            try jw.endObject();
        }
    };
};

// TODO: getMaxRetransmitSlot
// TODO: getMaxShredInsertSlot

/// Returns minimum balance required to make account rent exempt.
/// https://solana.com/docs/rpc/http/getminimumbalanceforrentexemption
pub const GetMinimumBalanceForRentExemption = struct {
    /// The Account's data length
    data_len: usize,
    config: ?common.CommitmentSlotConfig = null,

    /// Returns minimum lamports required in account to remain rent free.
    pub const Response = u64;
};

pub const GetMultipleAccounts = struct {
    pubkeys: []const Pubkey,
    config: ?GetAccountInfo.Config = null,

    /// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc-client-types/src/request.rs#L148
    pub const MAX_PUBKEYS = 100;

    pub const Response = struct {
        context: common.Context,
        value: []const ?GetAccountInfo.Response.Value,
    };
};

// TODO: getProgramAccounts

pub const GetRecentPerformanceSamples = struct {
    /// Number of samples to return (maximum 720).
    limit: ?u64 = null,

    pub const max_limit = 720;

    pub const Response = []const RpcPerfSample;

    pub const RpcPerfSample = struct {
        slot: Slot,
        numTransactions: u64,
        numNonVoteTransactions: ?u64,
        numSlots: u64,
        samplePeriodSecs: u16,
    };
};

pub const GetRecentPrioritizationFees = struct {
    /// Optional list of up to 128 account pubkeys to filter by.
    account_keys: ?[]const Pubkey = null,

    pub const Response = []const FeeResult;

    pub const FeeResult = struct {
        slot: u64,
        prioritizationFee: u64,
    };
};

pub const GetSignatureStatuses = struct {
    signatures: []const Signature,
    config: ?Config = null,

    pub const Config = struct {
        searchTransactionHistory: ?bool = null,
    };

    pub const Response = struct {
        context: common.Context,
        value: []const ?TransactionStatus,

        pub const TransactionStatus = struct {
            slot: u64,
            confirmations: ?usize = null,
            // TODO: should transaction_status move to core?
            err: ?sig.ledger.transaction_status.TransactionError = null,
            confirmationStatus: ?[]const u8 = null,
        };
    };
};

pub const GetSignaturesForAddress = struct {
    address: Pubkey,
    config: ?Config = null,

    pub const Config = struct {
        commitment: ?common.Commitment = null,
        minContextSlot: ?u64 = null,
        limit: ?usize = null,
        before: ?Signature = null,
        until: ?Signature = null,

        pub fn getCommitment(self: Config) common.Commitment {
            return self.commitment orelse common.Commitment.finalized;
        }

        pub fn getLimit(self: Config) usize {
            return self.limit orelse 1000;
        }
    };

    pub const Response = []const struct {
        signature: Signature,
        slot: u64,
        err: ?sig.ledger.transaction_status.TransactionError,
        memo: ?[]const u8,
        blockTime: ?i64,
        confirmationStatus: ?common.Commitment,
    };
};

pub const GetSlot = struct {
    config: ?common.CommitmentSlotConfig = null,

    pub const Response = Slot;
};

/// Returns the current slot leader.
/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L968-L971
pub const GetSlotLeader = struct {
    config: ?common.CommitmentSlotConfig = null,

    pub const Response = Pubkey;
};

/// Returns the slot leaders for a range of slots.
/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L973-L1007
/// [agave] MAX_GET_SLOT_LEADERS: https://github.com/anza-xyz/agave/blob/v3.1.8/rpc-client-types/src/request.rs#L151
pub const GetSlotLeaders = struct {
    start_slot: Slot,
    limit: u64,

    pub const MAX_GET_SLOT_LEADERS: u64 = 5000;
    pub const Response = []const Pubkey;
};

// TODO: getStakeActivation

pub const GetStakeMinimumDelegation = struct {
    config: ?common.CommitmentSlotConfig = null,

    pub const Response = struct {
        context: common.Context,
        value: u64,
    };
};

// TODO: getSupply
pub const GetTokenAccountBalance = struct {
    pubkey: Pubkey,
    config: ?Config = null,

    pub const Config = struct {
        commitment: ?common.Commitment = null,
    };

    pub const Response = struct {
        context: common.Context,
        value: account_codec.parse_token.UiTokenAmount,
    };
};

// TODO: getTokenAccountsByDelegate
// TODO: getTokenAccountsByOwner
// TODO: getTokenLargestAccounts

pub const GetTokenSupply = struct {
    /// Pubkey of the token Mint to query, as base-58 encoded string
    mint: Pubkey,
    config: ?Config = null,

    pub const Config = struct {
        commitment: ?common.Commitment = null,
    };

    pub const Response = struct {
        context: common.Context,
        value: account_codec.parse_token.UiTokenAmount,
    };
};

pub const GetTransaction = struct {
    /// Transaction signature, as base-58 encoded string
    signature: Signature,
    config: ?Config = null,

    pub const Config = struct {
        /// processed is not supported.
        commitment: ?common.Commitment = null,
        /// Set the max transaction version to return in responses.
        /// If the requested transaction is a higher version, an error will be returned.
        /// If this parameter is omitted, only legacy transactions will be returned,
        /// and any versioned transaction will prompt the error.
        maxSupportedTransactionVersion: ?u8 = null,
        /// Encoding for the returned Transaction
        /// jsonParsed encoding attempts to use program-specific state parsers to return
        /// more human-readable and explicit data in the transaction.message.instructions
        /// list. If jsonParsed is requested but a parser cannot be found, the instruction
        /// falls back to regular JSON encoding (accounts, data, and programIdIndex fields).
        encoding: ?common.TransactionEncoding = null,
    };

    pub const Response = union(enum) {
        none,
        value: struct {
            /// the slot this transaction was processed in
            slot: Slot,
            /// Transaction object
            transaction: GetBlock.Response.EncodedTransactionWithStatusMeta,
            /// estimated production time, as Unix timestamp (seconds since the Unix epoch) of when the transaction was processed. null if not available
            block_time: ?i64,

            pub fn jsonStringify(self: @This(), jw: anytype) !void {
                try jw.beginObject();
                try jw.objectField("slot");
                try jw.write(self.slot);

                // Flatten EncodedTransactionWithStatusMeta fields to top level
                if (self.transaction.meta) |m| {
                    try jw.objectField("meta");
                    try jw.write(m);
                }
                try jw.objectField("transaction");
                try jw.write(self.transaction.transaction);
                if (self.transaction.version) |v| {
                    try jw.objectField("version");
                    try v.jsonStringify(jw);
                }

                if (self.block_time) |bt| {
                    try jw.objectField("blockTime");
                    try jw.write(bt);
                }
                try jw.endObject();
            }
        },

        pub fn jsonStringify(self: @This(), jw: anytype) !void {
            switch (self) {
                .none => try jw.write(null),
                .value => |v| try v.jsonStringify(jw),
            }
        }
    };
};

pub const GetTransactionCount = struct {
    config: ?common.CommitmentSlotConfig = null,

    pub const Response = u64;
};

pub const GetIdentity = struct {
    pub const Response = struct {
        identity: Pubkey,
    };
};

pub const GetVersion = struct {
    pub const Response = struct {
        solana_core: []const u8,
        feature_set: ?u32 = null,

        pub fn jsonParse(allocator: Allocator, reader: anytype, options: ParseOptions) !Response {
            const value = try std.json.Value.jsonParse(allocator, reader, options);
            const initial_parsed = try std.json.parseFromValue(struct {
                @"solana-core": []const u8,
                @"feature-set": ?u32 = null,
            }, allocator, value, options);
            return .{
                .solana_core = initial_parsed.value.@"solana-core",
                .feature_set = initial_parsed.value.@"feature-set",
            };
        }

        pub fn jsonStringify(
            self: Response,
            /// `*std.json.WriteStream(...)`
            jw: anytype,
        ) !void {
            try jw.write(.{
                .@"solana-core" = self.solana_core,
                .@"feature-set" = self.feature_set,
            });
        }
    };
};

pub const GetVoteAccounts = struct {
    config: ?Config,

    /// Limit the length of the `epoch_credits` array for each validator in a `get_vote_accounts`
    /// response.
    /// See: https://github.com/anza-xyz/agave/blob/cd00ceb1fdf43f694caf7af23cb87987922fce2c/rpc-client-types/src/request.rs#L159
    pub const MAX_RPC_VOTE_ACCOUNT_INFO_EPOCH_CREDITS_HISTORY: usize = 5;

    /// Validators that are this number of slots behind are considered delinquent.
    /// See: https://github.com/anza-xyz/agave/blob/cd00ceb1fdf43f694caf7af23cb87987922fce2c/rpc-client-types/src/request.rs#L162
    pub const DELINQUENT_VALIDATOR_SLOT_DISTANCE: u64 = 128;

    pub const Config = struct {
        commitment: ?common.Commitment = null,
        votePubkey: ?Pubkey = null,
        keepUnstakedDelinquents: ?bool = null,
        delinquentSlotDistance: ?u64 = null,
    };

    pub const Response = struct {
        current: []const VoteAccount,
        delinquent: []const VoteAccount,
    };

    pub const VoteAccount = struct {
        votePubkey: sig.core.Pubkey,
        nodePubkey: sig.core.Pubkey,
        activatedStake: u64,
        epochVoteAccount: bool,
        commission: u8,
        lastVote: u64,
        epochCredits: []const [3]u64,
        rootSlot: u64,
    };
};

pub const IsBlockhashValid = struct {
    blockhash: sig.core.Hash,
    config: ?common.CommitmentSlotConfig = null,

    pub const Response = struct {
        context: common.Context,
        value: bool,
    };
};

// TODO: minimumLedgerSlot

pub const RequestAirdrop = struct {
    pubkey: Pubkey,
    lamports: u64,
    config: ?struct { commitment: common.Commitment } = null,

    pub const Response = sig.core.Signature;
};

pub const SendTransaction = struct {
    transaction: sig.core.Transaction,
    config: ?Config = null,

    pub const Config = struct {
        encoding: ?enum { base58, bas64 } = null,
        skipPreflight: ?bool = null,
        preflightCommitment: ?common.Commitment = null,
        maxRetries: ?usize = null,
        minContextSlot: ?Slot = null,
    };

    pub const Response = sig.core.Signature;
};

// TODO: simulateTransaction

/// Types that are used in multiple RPC methods.
pub const common = struct {
    pub const DataSlice = account_codec.DataSlice;

    pub const Commitment = enum {
        finalized,
        confirmed,
        processed,
    };

    /// Used to configure several RPC method requests
    pub const CommitmentSlotConfig = struct {
        commitment: ?common.Commitment = null,
        minContextSlot: ?sig.core.Slot = null,
    };

    pub const Context = struct {
        slot: u64,
        apiVersion: []const u8 = ClientVersion.API_VERSION,
    };

    pub const AccountEncoding = account_codec.AccountEncoding;

    // TODO field types
    pub const RpcContactInfo = struct {
        /// Pubkey of the node as a base-58 string
        pubkey: []const u8,
        /// Gossip port
        gossip: ?[]const u8 = null,
        /// Tvu UDP port
        tvu: ?[]const u8 = null,
        /// Tpu UDP port
        tpu: ?[]const u8 = null,
        /// Tpu QUIC port
        tpuQuic: ?[]const u8 = null,
        /// Tpu UDP forwards port
        tpuForwards: ?[]const u8 = null,
        /// Tpu QUIC forwards port
        tpuForwardsQuic: ?[]const u8 = null,
        /// Tpu UDP vote port
        tpuVote: ?[]const u8 = null,
        /// Server repair UDP port
        serveRepair: ?[]const u8 = null,
        /// JSON RPC port
        rpc: ?[]const u8 = null,
        /// WebSocket PubSub port
        pubsub: ?[]const u8 = null,
        /// Software version
        version: ?[]const u8 = null,
        /// First 4 bytes of the FeatureSet identifier
        featureSet: ?u32 = null,
        /// Shred version
        shredVersion: ?u16 = null,
    };

    pub const TransactionEncoding = enum {
        binary,
        base58,
        base64,
        json,
        jsonParsed,
    };

    pub const TransactionDetails = enum {
        full,
        accounts,
        signatures,
        none,
    };
};

/// Health check status for the RPC node.
/// Analogous to [RpcHealthStatus](https://github.com/anza-xyz/agave/blob/8803776d/rpc/src/rpc_health.rs#L11-L16)
pub const RpcHealthStatus = union(enum) {
    /// Node is healthy
    ok,
    /// Cannot determine health (unknown state)
    unknown,
    /// Node is behind cluster by specified number of slots
    behind: u64,

    pub fn eql(self: RpcHealthStatus, other: RpcHealthStatus) bool {
        return switch (self) {
            .ok => other == .ok,
            .unknown => other == .unknown,
            .behind => |n| switch (other) {
                .behind => |m| n == m,
                else => false,
            },
        };
    }

    /// Returns the HTTP /health endpoint response string.
    /// Agave always returns "ok", "behind", or "unknown" with HTTP 200.
    /// See: https://github.com/anza-xyz/agave/blob/master/rpc/src/rpc_service.rs#L332-L340
    pub fn httpStatusString(self: RpcHealthStatus) []const u8 {
        return switch (self) {
            .ok => "ok",
            .behind => "behind",
            .unknown => "unknown",
        };
    }

    /// Custom JSON serialization for the JSON-RPC response.
    ///
    /// When healthy, serializes as the string "ok" (the JSON-RPC result value).
    /// When unhealthy, this should NOT be used directly - the server layer must
    /// intercept and format it as a JSON-RPC error response with code -32005.
    pub fn jsonStringify(
        self: RpcHealthStatus,
        /// `*std.json.WriteStream(...)`
        jw: anytype,
    ) !void {
        switch (self) {
            .ok => try jw.write("ok"),
            // These cases shouldn't be serialized via the normal .result path.
            // They're handled by the server as JSON-RPC errors.
            // But if they are serialized, output something reasonable.
            .unknown => try jw.write("unknown"),
            .behind => |n| {
                try jw.beginObject();
                try jw.objectField("status");
                try jw.write("behind");
                try jw.objectField("numSlotsBehind");
                try jw.write(n);
                try jw.endObject();
            },
        }
    }
};

fn JsonSkippable(comptime T: type) type {
    return union(enum) {
        value: T,
        none,
        skip,

        pub fn jsonStringify(self: JsonSkippable(T), jw: anytype) !void {
            switch (self) {
                .value => |v| try jw.write(v),
                .none => try jw.write(null),
                .skip => {},
            }
        }
    };
}
