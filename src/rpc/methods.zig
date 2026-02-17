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
const Commitment = common.Commitment;
const ClientVersion = sig.version.ClientVersion;

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
    getBlockProduction: noreturn,
    getBlocks: noreturn,
    getBlocksWithLimit: noreturn,
    getBlockTime: noreturn,
    getClusterNodes: GetClusterNodes,
    getEpochInfo: GetEpochInfo,
    getEpochSchedule: GetEpochSchedule,
    getFeeForMessage: noreturn,
    getFirstAvailableBlock: noreturn,

    /// https://github.com/Syndica/sig/issues/557
    getGenesisHash: GetGenesisHash,
    /// https://github.com/Syndica/sig/issues/558
    getHealth: GetHealth,
    /// Custom (not standardized) RPC method for "GET /*snapshot*.tar.bz2"
    getSnapshot: GetSnapshot,

    getHighestSnapshotSlot: noreturn,
    getIdentity: GetIdentity,
    getInflationGovernor: noreturn,
    getInflationRate: noreturn,
    getInflationReward: noreturn,
    getLargestAccounts: noreturn,
    getLatestBlockhash: GetLatestBlockhash,
    getLeaderSchedule: GetLeaderSchedule,
    getMaxRetransmitSlot: noreturn,
    getMaxShredInsertSlot: noreturn,
    getMinimumBalanceForRentExemption: noreturn,
    getMultipleAccounts: noreturn,
    getProgramAccounts: noreturn,
    getRecentPerformanceSamples: noreturn,
    getRecentPrioritizationFees: noreturn,
    getSignaturesForAddress: noreturn,
    getSignatureStatuses: GetSignatureStatuses,
    getSlot: GetSlot,
    getSlotLeader: noreturn,
    getSlotLeaders: noreturn,
    getStakeMinimumDelegation: noreturn,
    getSupply: noreturn,
    getTokenAccountBalance: noreturn,
    getTokenAccountsByDelegate: noreturn,
    getTokenAccountsByOwner: noreturn,
    getTokenLargestAccounts: noreturn,
    getTokenSupply: noreturn,
    getTransaction: GetTransaction,
    getTransactionCount: noreturn,
    getVersion: GetVersion,
    getVoteAccounts: GetVoteAccounts,
    isBlockhashValid: noreturn,
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

    pub const Encoding = enum {
        base58,
        base64,
        @"base64+zstd",
        jsonParsed,
    };

    pub const Config = struct {
        commitment: ?common.Commitment = null,
        minContextSlot: ?u64 = null,
        encoding: ?Encoding = null,
        dataSlice: ?common.DataSlice = null,
    };

    pub const Response = struct {
        context: common.Context,
        value: ?Value,

        pub const Value = struct {
            data: Data,
            executable: bool,
            lamports: u64,
            owner: Pubkey,
            rentEpoch: u64,
            space: u64,

            pub const Data = union(enum) {
                encoded: struct { []const u8, Encoding },
                // TODO: this should be a json value/map, test cases can't compare that though
                jsonParsed: noreturn,

                /// This field is only set when the request object asked for `jsonParsed` encoding,
                /// and the server couldn't find a parser, therefore falling back to simply returning
                /// the account data in base64 encoding directly as a string.
                ///
                /// [Solana documentation REF](https://solana.com/docs/rpc/http/getaccountinfo):
                /// In the drop-down documentation for the encoding field:
                /// > * `jsonParsed` encoding attempts to use program-specific state parsers to
                /// return more human-readable and explicit account state data.
                /// > * If `jsonParsed` is requested but a parser cannot be found, the field falls
                /// back to base64 encoding, detectable when the data field is type string.
                json_parsed_base64_fallback: []const u8,

                pub fn jsonStringify(
                    self: Data,
                    /// `*std.json.WriteStream(...)`
                    jw: anytype,
                ) @TypeOf(jw.*).Error!void {
                    switch (self) {
                        .encoded => |pair| try jw.write(pair),
                        .jsonParsed => |map| try jw.write(map),
                        .json_parsed_base64_fallback => |str| try jw.write(str),
                    }
                }

                pub fn jsonParse(
                    allocator: std.mem.Allocator,
                    source: anytype,
                    options: std.json.ParseOptions,
                ) std.json.ParseError(@TypeOf(source.*))!Data {
                    return switch (try source.peekNextTokenType()) {
                        .array_begin => .{ .encoded = try std.json.innerParse(
                            struct { []const u8, Encoding },
                            allocator,
                            source,
                            options,
                        ) },
                        .object_begin => if (true)
                            std.debug.panic("TODO: implement jsonParsed for GetAccountInfo", .{})
                        else
                            .{ .jsonParsed = try std.json.innerParse(
                                std.json.ArrayHashMap(std.json.Value),
                                allocator,
                                source,
                                options,
                            ) },
                        .string => .{ .json_parsed_base64_fallback = try std.json.innerParse(
                            []const u8,
                            allocator,
                            source,
                            options,
                        ) },
                        .array_end, .object_end => error.UnexpectedToken,
                        else => {
                            try source.skipValue();
                            return error.UnexpectedToken;
                        },
                    };
                }
            };
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
    pub const Response = union(enum) {
        ok,
        err: struct {}, // TODO: Our implementation-specifc error information

        pub fn jsonStringify(
            self: Response,
            /// `*std.json.WriteStream(...)`
            jw: anytype,
        ) !void {
            switch (self) {
                .ok => try jw.write("ok"),
                .err => |e| try jw.write(e),
            }
        }
    };
};

pub const GetBlock = struct {
    /// The slot to get the block for (first positional argument)
    slot: Slot,
    config: ?Config = null,

    pub const TransactionDetails = enum {
        full,
        accounts,
        signatures,
        none,
    };

    /// Transaction encoding format
    pub const Encoding = enum { binary, base58, base64, json, jsonParsed };

    pub const Config = struct {
        /// Only `confirmed` and `finalized` are supported. `processed` is rejected.
        commitment: ?common.Commitment = null,
        encoding: ?Encoding = null,
        transactionDetails: ?TransactionDetails = null,
        maxSupportedTransactionVersion: ?u8 = null,
        rewards: ?bool = null,
    };

    /// Response for getBlock RPC method (UiConfirmedBlock equivalent)
    pub const Response = struct {
        /// The blockhash of the previous block
        previousBlockhash: Hash,
        /// The blockhash of this block
        blockhash: Hash,
        /// The slot of the parent block
        parentSlot: u64,
        /// Transactions in the block (present when transactionDetails is full or accounts)
        /// TODO: Phase 2 - implement EncodedTransactionWithStatusMeta
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

        pub fn jsonStringify(self: @This(), jw: anytype) !void {
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

                pub fn jsonStringify(self: @This(), jw: anytype) !void {
                    switch (self) {
                        .legacy => try jw.write("legacy"),
                        .number => |n| try jw.write(n),
                    }
                }
            };

            pub fn jsonStringify(self: @This(), jw: anytype) !void {
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
                data: []const u8,
                encoding: enum { base58, base64 },

                pub fn jsonStringify(self: @This(), jw: anytype) !void {
                    try jw.beginArray();
                    try jw.write(self.data);
                    try jw.write(@tagName(self.encoding));
                    try jw.endArray();
                }
            },
            /// JSON encoding: object with signatures and message
            json: struct {
                signatures: []const Signature,
                message: EncodedMessage,
            },

            pub fn jsonStringify(self: @This(), jw: anytype) !void {
                switch (self) {
                    .legacy_binary => |b| try jw.write(b),
                    .binary => |b| try b.jsonStringify(jw),
                    .json => |j| try jw.write(j),
                }
            }
        };

        /// JSON-encoded message
        pub const EncodedMessage = struct {
            accountKeys: []const Pubkey,
            header: MessageHeader,
            recentBlockhash: Hash,
            instructions: []const EncodedInstruction,
            addressTableLookups: ?[]const AddressTableLookup = null,

            pub fn jsonStringify(self: @This(), jw: anytype) !void {
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

        pub const MessageHeader = struct {
            numRequiredSignatures: u8,
            numReadonlySignedAccounts: u8,
            numReadonlyUnsignedAccounts: u8,
        };

        pub const EncodedInstruction = struct {
            programIdIndex: u8,
            accounts: []const u8,
            data: []const u8,
            stackHeight: ?u32 = null,

            pub fn jsonStringify(self: @This(), jw: anytype) !void {
                try jw.beginObject();
                try jw.objectField("programIdIndex");
                try jw.write(self.programIdIndex);
                try jw.objectField("accounts");
                try jw.write(self.accounts);
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
        };

        /// UI representation of transaction status metadata
        pub const UiTransactionStatusMeta = struct {
            err: ?sig.ledger.transaction_status.TransactionError = null,
            status: UiTransactionResultStatus,
            fee: u64,
            preBalances: []const u64,
            postBalances: []const u64,
            innerInstructions: []const parse_instruction.UiInnerInstructions = &.{},
            logMessages: []const []const u8 = &.{},
            preTokenBalances: []const UiTransactionTokenBalance = &.{},
            postTokenBalances: []const UiTransactionTokenBalance = &.{},
            rewards: []const UiReward = &.{},
            loadedAddresses: ?UiLoadedAddresses = null,
            returnData: ?UiTransactionReturnData = null,
            computeUnitsConsumed: ?u64 = null,
            costUnits: ?u64 = null,

            pub fn jsonStringify(self: @This(), jw: anytype) !void {
                try jw.beginObject();
                if (self.computeUnitsConsumed) |cuc| {
                    try jw.objectField("computeUnitsConsumed");
                    try jw.write(cuc);
                }
                if (self.costUnits) |cw| {
                    try jw.objectField("costUnits");
                    try jw.write(cw);
                }
                try jw.objectField("err");
                try jw.write(self.err);
                try jw.objectField("fee");
                try jw.write(self.fee);
                try jw.objectField("innerInstructions");
                try jw.write(self.innerInstructions);
                if (self.loadedAddresses) |la| {
                    try jw.objectField("loadedAddresses");
                    try jw.write(la);
                }
                try jw.objectField("logMessages");
                try jw.write(self.logMessages);
                try jw.objectField("postBalances");
                try jw.write(self.postBalances);
                try jw.objectField("postTokenBalances");
                try jw.write(self.postTokenBalances);
                try jw.objectField("preBalances");
                try jw.write(self.preBalances);
                try jw.objectField("preTokenBalances");
                try jw.write(self.preTokenBalances);
                if (self.returnData) |rd| {
                    try jw.objectField("returnData");
                    try jw.write(rd);
                }
                try jw.objectField("rewards");
                try jw.write(self.rewards);
                try jw.objectField("status");
                try jw.write(self.status);
                try jw.endObject();
            }

            pub fn from(
                allocator: Allocator,
                meta: sig.ledger.meta.TransactionStatusMeta,
            ) !UiTransactionStatusMeta {
                // Build status field
                const status: UiTransactionResultStatus = if (meta.status) |err|
                    .{ .Ok = null, .Err = err }
                else
                    .{ .Ok = .{}, .Err = null };

                // Convert inner instructions
                const inner_instructions = if (meta.inner_instructions) |iis|
                    try BlockHookContext.convertInnerInstructions(allocator, iis)
                else
                    &.{};

                // Convert token balances
                const pre_token_balances = if (meta.pre_token_balances) |balances|
                    try BlockHookContext.convertTokenBalances(allocator, balances)
                else
                    &.{};

                const post_token_balances = if (meta.post_token_balances) |balances|
                    try BlockHookContext.convertTokenBalances(allocator, balances)
                else
                    &.{};

                // Convert loaded addresses
                const loaded_addresses = try BlockHookContext.convertLoadedAddresses(
                    allocator,
                    meta.loaded_addresses,
                );

                // Convert return data
                const return_data = if (meta.return_data) |rd|
                    try BlockHookContext.convertReturnData(allocator, rd)
                else
                    null;

                // Duplicate log messages (original memory will be freed with block.deinit)
                const log_messages = if (meta.log_messages) |logs|
                    try allocator.dupe([]const u8, logs)
                else
                    &.{};

                const rewards = rewards: {
                    if (meta.rewards) |rewards| {
                        const converted = try allocator.alloc(UiReward, rewards.len);
                        for (rewards, 0..) |reward, i| {
                            converted[i] = try UiReward.fromLedgerReward(reward);
                        }
                        break :rewards converted;
                    } else break :rewards &.{};
                };

                return .{
                    .err = meta.status,
                    .status = status,
                    .fee = meta.fee,
                    .preBalances = try allocator.dupe(u64, meta.pre_balances),
                    .postBalances = try allocator.dupe(u64, meta.post_balances),
                    .innerInstructions = inner_instructions,
                    .logMessages = log_messages,
                    .preTokenBalances = pre_token_balances,
                    .postTokenBalances = post_token_balances,
                    .rewards = rewards,
                    .loadedAddresses = loaded_addresses,
                    .returnData = return_data,
                    .computeUnitsConsumed = meta.compute_units_consumed,
                    .costUnits = meta.cost_units,
                };
            }
        };

        /// Transaction result status for RPC compatibility.
        /// Serializes as `{"Ok": null}` on success or `{"Err": <error>}` on failure.
        pub const UiTransactionResultStatus = struct {
            Ok: ?struct {} = null,
            Err: ?sig.ledger.transaction_status.TransactionError = null,

            pub fn jsonStringify(self: @This(), jw: anytype) !void {
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

            pub fn jsonStringify(self: @This(), jw: anytype) !void {
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

            pub fn jsonStringify(self: @This(), jw: anytype) !void {
                try jw.beginObject();
                try jw.objectField("amount");
                try jw.write(self.amount);
                try jw.objectField("decimals");
                try jw.write(self.decimals);
                if (self.uiAmount) |ua| {
                    try jw.objectField("uiAmount");
                    try jw.write(ua);
                }
                try jw.objectField("uiAmountString");
                try jw.write(self.uiAmountString);
                try jw.endObject();
            }
        };

        pub const UiLoadedAddresses = struct {
            readonly: []const Pubkey,
            writable: []const Pubkey,
        };

        pub const UiTransactionReturnData = struct {
            programId: Pubkey,
            data: struct { []const u8, enum { base64 } },

            pub fn jsonStringify(self: @This(), jw: anytype) !void {
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

            pub fn jsonStringify(self: @This(), jw: anytype) !void {
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

            pub fn fromLedgerReward(
                reward: sig.ledger.meta.Reward,
            ) !UiReward {
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

// TODO: getBlockProduction
// TODO: getBlockTime
// TODO: getBlocks
// TODO: getBlocksWithLimit

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
// TODO: getHighestSnapshotSlot
// TODO: getIdentity
// TODO: getInflationGovernor
// TODO: getInflationRate
// TODO: getInflationReward
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

    pub const Response = struct {
        value: sig.utils.collections.PubkeyMap([]const u64),

        pub fn deinit(self: Response, allocator: std.mem.Allocator) void {
            self.value.deinit(allocator);
        }

        pub fn jsonParse(
            allocator: std.mem.Allocator,
            source: anytype,
            options: std.json.ParseOptions,
        ) std.json.ParseError(@TypeOf(source.*))!Response {
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
            self: Response,
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
// TODO: getMinimumBalanceForRentExemption
// TODO: getMultipleAccounts
// TODO: getProgramAccounts
// TODO: getRecentPerformanceSamples
// TODO: getRecentPrioritizationFees

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

// TODO: getSignaturesForAddress

pub const GetSlot = struct {
    config: ?common.CommitmentSlotConfig = null,

    pub const Response = Slot;
};

// TODO: getSlotLeader
// TODO: getSlotLeaders
// TODO: getStakeActivation
// TODO: getStakeMinimumDelegation
// TODO: getSupply
// TODO: getTokenAccountBalance
// TODO: getTokenAccountsByDelegate
// TODO: getTokenAccountsByOwner
// TODO: getTokenLargestAccounts
// TODO: getTokenSupply

pub const GetTransaction = struct {
    /// Transaction signature, as base-58 encoded string
    signature: Signature,
    config: ?Config = null,

    pub const Config = struct {
        /// processed is not supported.
        commitment: ?enum { confirmed, finalized },
        /// Set the max transaction version to return in responses.
        /// If the requested transaction is a higher version, an error will be returned.
        /// If this parameter is omitted, only legacy transactions will be returned,
        /// and any versioned transaction will prompt the error.
        max_supported_transaction_version: ?u8,
        /// Encoding for the returned Transaction
        /// jsonParsed encoding attempts to use program-specific state parsers to return
        /// more human-readable and explicit data in the transaction.message.instructions
        /// list. If jsonParsed is requested but a parser cannot be found, the instruction
        /// falls back to regular JSON encoding (accounts, data, and programIdIndex fields).
        encoding: ?enum { json, jsonParsed, base64, base58 },
    };

    pub const Response = struct {
        /// the slot this transaction was processed in
        slot: Slot,
        /// Transaction object, either in JSON format or encoded binary data, depending on encoding parameter
        transaction: void,
        /// estimated production time, as Unix timestamp (seconds since the Unix epoch) of when the transaction was processed. null if not available
        blocktime: ?i64,
        /// transaction status metadata object:
        meta: void,
        /// Transaction version. Undefined if maxSupportedTransactionVersion is not set in request params.
        version: union(enum) { legacy, version: u8, not_defined },
    };
};

// TODO: getTransactionCount

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

    const Config = struct {
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

// TODO: isBlockhashValid
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
    pub const DataSlice = struct {
        offset: usize,
        length: usize,
    };

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
        apiVersion: []const u8,
    };

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
};

pub const RpcHookContext = struct {
    slot_tracker: *const sig.replay.trackers.SlotTracker,
    epoch_tracker: *const sig.core.EpochTracker,
    account_reader: sig.accounts_db.AccountReader,

    // Limit the length of the `epoch_credits` array for each validator in a `get_vote_accounts`
    // response.
    // See: https://github.com/anza-xyz/agave/blob/cd00ceb1fdf43f694caf7af23cb87987922fce2c/rpc-client-types/src/request.rs#L159
    const MAX_RPC_VOTE_ACCOUNT_INFO_EPOCH_CREDITS_HISTORY: usize = 5;

    // Validators that are this number of slots behind are considered delinquent.
    // See: https://github.com/anza-xyz/agave/blob/cd00ceb1fdf43f694caf7af23cb87987922fce2c/rpc-client-types/src/request.rs#L162
    const DELINQUENT_VALIDATOR_SLOT_DISTANCE: u64 = 128;

    pub fn getSlot(self: RpcHookContext, _: std.mem.Allocator, params: GetSlot) !GetSlot.Response {
        const config = params.config orelse common.CommitmentSlotConfig{};
        const commitment = config.commitment orelse .finalized;
        const slot = self.slot_tracker.getSlotForCommitment(commitment);
        const min_slot = config.minContextSlot orelse return slot;
        return if (slot >= min_slot) slot else error.RpcMinContextSlotNotMet;
    }

    pub fn getVoteAccounts(
        self: RpcHookContext,
        allocator: std.mem.Allocator,
        params: GetVoteAccounts,
    ) !GetVoteAccounts.Response {
        const config: GetVoteAccounts.Config = params.config orelse .{};

        // get slot for requested commitment. Agave uses finalized as default.
        const slot = self.slot_tracker.getSlotForCommitment(config.commitment orelse .finalized);

        // Get the state for the requested commitment slot.
        const slot_ref = self.slot_tracker.get(slot) orelse return error.SlotNotAvailable;

        // Setup config consts for the request.
        const delinquent_distance = config.delinquentSlotDistance orelse
            DELINQUENT_VALIDATOR_SLOT_DISTANCE;
        const keep_unstaked = config.keepUnstakedDelinquents orelse false;
        const filter_pk = config.votePubkey;

        // Get epoch info for epochVoteAccounts check
        const epoch_constants = try self.epoch_tracker.getEpochInfo(slot);
        const epoch_stakes = epoch_constants.stakes.stakes;
        const epoch_vote_accounts = &epoch_stakes.vote_accounts.vote_accounts;

        var current_list: std.ArrayListUnmanaged(GetVoteAccounts.VoteAccount) = .empty;
        errdefer {
            for (current_list.items) |va| allocator.free(va.epochCredits);
            current_list.deinit(allocator);
        }
        var delinqt_list: std.ArrayListUnmanaged(GetVoteAccounts.VoteAccount) = .empty;
        errdefer {
            for (delinqt_list.items) |va| allocator.free(va.epochCredits);
            delinqt_list.deinit(allocator);
        }

        // Access stakes cache (takes read lock).
        const stakes, var stakes_guard = slot_ref.state.stakes_cache.stakes.readWithLock();
        defer stakes_guard.unlock();
        const vote_accounts_map = &stakes.vote_accounts.vote_accounts;
        for (vote_accounts_map.keys(), vote_accounts_map.values()) |vote_pk, stake_and_vote| {
            // Apply filter if specified.
            if (filter_pk) |f| {
                if (!vote_pk.equals(&f)) continue;
            }

            const vote_state = stake_and_vote.account.state;
            const activated_stake = stake_and_vote.stake;

            // Get the slot this vote account last voted on.
            // See: https://github.com/anza-xyz/agave/blob/01159e4643e1d8ee86d1ed0e58ea463b338d563f/rpc/src/rpc.rs#L1172
            const last_vote_slot = vote_state.lastVotedSlot() orelse 0;

            // Check if vote account is active in current epoch.
            const in_delegated_stakes = epoch_vote_accounts.contains(vote_pk);
            const is_epoch_vote_account = in_delegated_stakes or activated_stake > 0;

            // Partition by delinquent status. current is set when last_vote_slot > slot - delinquent_distance.
            // See: https://github.com/anza-xyz/agave/blob/01159e4643e1d8ee86d1ed0e58ea463b338d563f/rpc/src/rpc.rs#L1194
            const is_current = if (slot >= delinquent_distance)
                last_vote_slot > slot - delinquent_distance
            else
                last_vote_slot > 0;

            // Skip delinquent accounts with no stake unless explicitly requested.
            // See: https://github.com/anza-xyz/agave/blob/01159e4643e1d8ee86d1ed0e58ea463b338d563f/rpc/src/rpc.rs#L1203
            if (!is_current and !keep_unstaked and activated_stake == 0) continue;

            // Convert epoch credits to [3]u64 format
            // See: https://github.com/anza-xyz/agave/blob/01159e4643e1d8ee86d1ed0e58ea463b338d563f/rpc/src/rpc.rs#L1174
            const all_credits = vote_state.epoch_credits.items;
            const num_credits_to_return = @min(
                all_credits.len,
                MAX_RPC_VOTE_ACCOUNT_INFO_EPOCH_CREDITS_HISTORY,
            );
            const epoch_credits = all_credits[all_credits.len - num_credits_to_return ..];
            const credits = try allocator.alloc([3]u64, num_credits_to_return);
            errdefer allocator.free(credits);
            for (epoch_credits, 0..) |ec, i| {
                credits[i] = .{ ec.epoch, ec.credits, ec.prev_credits };
            }

            const info = GetVoteAccounts.VoteAccount{
                .votePubkey = vote_pk,
                .nodePubkey = vote_state.node_pubkey,
                .activatedStake = activated_stake,
                .epochVoteAccount = is_epoch_vote_account,
                .commission = vote_state.commission(),
                .lastVote = last_vote_slot,
                .epochCredits = credits,
                // See: https://github.com/anza-xyz/agave/blob/01159e4643e1d8ee86d1ed0e58ea463b338d563f/rpc/src/rpc.rs#L1188
                .rootSlot = vote_state.root_slot orelse 0,
            };

            if (is_current) {
                try current_list.append(allocator, info);
            } else {
                try delinqt_list.append(allocator, info);
            }
        }

        const current = try current_list.toOwnedSlice(allocator);
        errdefer {
            for (current) |va| allocator.free(va.epochCredits);
            allocator.free(current);
        }
        const dlinqt = try delinqt_list.toOwnedSlice(allocator);
        errdefer {
            for (dlinqt) |va| allocator.free(va.epochCredits);
            allocator.free(dlinqt);
        }
        return .{
            .current = current,
            .delinquent = dlinqt,
        };
    }

    pub fn getBalance(
        self: RpcHookContext,
        allocator: std.mem.Allocator,
        params: GetBalance,
    ) !GetBalance.Response {
        const config = params.config orelse common.CommitmentSlotConfig{};
        // [agave] Default commitment is finalized:
        // https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L348
        const commitment = config.commitment orelse .finalized;

        const slot = self.slot_tracker.getSlotForCommitment(commitment);
        if (config.minContextSlot) |min_slot| {
            if (slot < min_slot) return error.RpcMinContextSlotNotMet;
        }

        // Get slot reference to access ancestors
        const ref = self.slot_tracker.get(slot) orelse return error.SlotNotAvailable;
        const slot_reader = self.account_reader.forSlot(&ref.constants.ancestors);

        // Look up account
        const maybe_account = try slot_reader.get(allocator, params.pubkey);

        const lamports: u64 = if (maybe_account) |account| blk: {
            defer account.deinit(allocator);
            break :blk account.lamports;
        } else 0;

        return .{
            .context = .{
                .slot = slot,
                .apiVersion = ClientVersion.API_VERSION,
            },
            .value = lamports,
        };
    }
};

pub const StaticHookContext = struct {
    genesis_hash: sig.core.Hash,

    pub fn getGenesisHash(
        self: *const @This(),
        _: std.mem.Allocator,
        _: GetGenesisHash,
    ) !GetGenesisHash.Response {
        return .{ .hash = self.genesis_hash };
    }
};

/// RPC hook context for block-related methods.
/// Requires access to the Ledger and SlotTracker for commitment checks.
pub const BlockHookContext = struct {
    ledger: *sig.ledger.Ledger,
    slot_tracker: *const sig.replay.trackers.SlotTracker,

    const SlotTrackerRef = sig.replay.trackers.SlotTracker.Reference;

    pub fn getBlock(
        self: @This(),
        allocator: std.mem.Allocator,
        params: GetBlock,
    ) !GetBlock.Response {
        const config = params.config orelse GetBlock.Config{};
        const commitment = config.commitment orelse .finalized;
        const transaction_details = config.transactionDetails orelse .full;
        const show_rewards = config.rewards orelse true;
        const encoding = config.encoding orelse .json;
        const max_supported_version = config.maxSupportedTransactionVersion;

        // Reject processed commitment (Agave behavior: only confirmed and finalized supported)
        if (commitment == .processed) {
            return error.ProcessedNotSupported;
        }

        const root = self.slot_tracker.root.load(.monotonic);

        // Determine whether the slot is available at the requested commitment level.
        //
        // Agave flow (https://github.com/anza-xyz/agave/blob/71aac0b755c052835f581cfaea15b2682894b959/rpc/src/rpc.rs#L1305-1401):
        //   1. If slot <= highest_super_majority_root → finalized path (get_rooted_block)
        //   2. Else if commitment == confirmed AND slot in status_cache_ancestors → confirmed path (get_complete_block)
        //   3. Else → BlockNotAvailable
        //
        // For the finalized path, the slot must be at or below root.
        // For the confirmed path, the slot must be between root and the latest
        // confirmed slot (inclusive), and tracked in the SlotTracker.
        //
        // When the SlotTracker has the slot, we use it for block_time, block_height,
        // and rewards (equivalent to Agave's bank fallback at rpc.rs:1371-1383 where
        // it fills block_time from bank.clock().unix_timestamp and block_height from
        // bank.block_height() when they're missing from the blockstore).
        const maybe_slot_elem: ?SlotTrackerRef = if (params.slot <= root) blk: {
            // Finalized path: slot is at or below root, serve regardless of commitment level.
            break :blk self.slot_tracker.get(params.slot) orelse
                return error.SlotUnavailableSomehow;
        } else if (commitment == .confirmed) blk: {
            // Confirmed path: slot is above root but at or below the confirmed slot.
            const confirmed_slot = self.slot_tracker.latest_confirmed_slot.get();
            if (params.slot > confirmed_slot) {
                return error.BlockNotAvailable;
            }
            // The slot may have been pruned from SlotTracker but still be in the blockstore.
            break :blk self.slot_tracker.get(params.slot);
        } else {
            // Finalized commitment was requested but slot is not yet finalized.
            return error.BlockNotAvailable;
        };

        // Get block from ledger
        const reader = self.ledger.reader();
        const block = try reader.getCompleteBlock(
            allocator,
            params.slot,
            true,
        );
        defer block.deinit(allocator);

        const blockhash = block.blockhash;
        const previous_blockhash = block.previous_blockhash;
        const parent_slot = block.parent_slot;
        const num_partitions = block.num_partitions;

        // Resolve block_time and block_height:
        // - If the SlotTracker has the slot, use its values (authoritative).
        // - Otherwise, fall back to what the blockstore returned (may be null for
        //   confirmed-but-not-yet-finalized blocks).
        const block_height: ?u64 = blk: {
            if (maybe_slot_elem) |elem| {
                break :blk elem.constants.block_height;
            } else {
                break :blk block.block_height;
            }
        };
        const block_time: ?i64 = blk: {
            if (maybe_slot_elem) |elem| {
                break :blk elem.state.unix_timestamp.load(.monotonic);
            } else {
                break :blk block.block_time;
            }
        };

        // Convert rewards if requested.
        // Prefer SlotTracker rewards (in-memory, most current) when available,
        // otherwise fall back to blockstore rewards.
        const rewards: ?[]const GetBlock.Response.UiReward = if (show_rewards) blk: {
            if (maybe_slot_elem) |elem| {
                const slot_rewards, var slot_rewards_lock = elem.state.rewards.readWithLock();
                defer slot_rewards_lock.unlock();
                break :blk try convertBlockRewards(allocator, slot_rewards);
            } else {
                break :blk try convertRewards(allocator, block.rewards);
            }
        } else null;

        const transactions, const signatures = try encodeWithOptionsV2(
            allocator,
            block,
            encoding,
            .{
                .tx_details = transaction_details,
                .show_rewards = show_rewards,
                .max_supported_version = max_supported_version,
            },
        );

        return .{
            .blockhash = blockhash,
            .previousBlockhash = previous_blockhash,
            .parentSlot = parent_slot,
            .transactions = transactions,
            .signatures = signatures,
            .rewards = rewards,
            .numRewardPartitions = num_partitions,
            .blockTime = block_time,
            .blockHeight = block_height,
        };
    }

    fn encodeWithOptionsV2(
        allocator: Allocator,
        block: sig.ledger.Reader.VersionedConfirmedBlock,
        encoding: GetBlock.Encoding,
        options: struct {
            tx_details: GetBlock.TransactionDetails,
            show_rewards: bool,
            max_supported_version: ?u8,
        },
    ) !struct { ?[]const GetBlock.Response.EncodedTransactionWithStatusMeta, ?[]const Signature } {
        switch (options.tx_details) {
            .none => return .{ null, null },
            .full => {
                const transactions = try allocator.alloc(
                    GetBlock.Response.EncodedTransactionWithStatusMeta,
                    block.transactions.len,
                );
                errdefer allocator.free(transactions);

                for (block.transactions, 0..) |tx_with_meta, i| {
                    transactions[i] = try encodeTransactionWithMeta(
                        allocator,
                        tx_with_meta,
                        encoding,
                        options.max_supported_version,
                        options.show_rewards,
                    );
                }

                return .{ transactions, null };
            },
            .signatures => {
                const sigs = try allocator.alloc(Signature, block.transactions.len);
                errdefer allocator.free(sigs);

                for (block.transactions, 0..) |tx_with_meta, i| {
                    if (tx_with_meta.transaction.signatures.len == 0) {
                        return error.InvalidTransaction;
                    }
                    sigs[i] = tx_with_meta.transaction.signatures[0];
                }

                return .{ null, sigs };
            },
            // TODO: implement json parsing
            .accounts => return error.NotImplemented,
        }
    }

    /// Encode a transaction with its metadata for the RPC response.
    fn encodeTransactionWithMeta(
        allocator: std.mem.Allocator,
        tx_with_meta: sig.ledger.Reader.VersionedTransactionWithStatusMeta,
        encoding: GetBlock.Encoding,
        max_supported_version: ?u8,
        show_rewards: bool,
    ) !GetBlock.Response.EncodedTransactionWithStatusMeta {
        const version: ?sig.core.transaction.Version = ver: {
            const version = tx_with_meta.transaction.version;
            if (max_supported_version) |max_version| switch (version) {
                .legacy => break :ver .legacy,
                .v0 => if (max_version >= 0) {
                    break :ver .v0;
                } else return error.UnsupportedTransactionVersion,
            } else switch (version) {
                .legacy => break :ver null,
                .v0 => return error.UnsupportedTransactionVersion,
            }
        };

        const encoded_tx = try encodeTransaction(
            allocator,
            tx_with_meta.transaction,
            encoding,
        );
        const meta: GetBlock.Response.UiTransactionStatusMeta = switch (encoding) {
            .jsonParsed => try encodeTransactionStatusMeta(
                allocator,
                tx_with_meta.meta,
                tx_with_meta.transaction.msg.account_keys,
                show_rewards,
            ),
            else => try GetBlock.Response.UiTransactionStatusMeta.from(allocator, tx_with_meta.meta),
        };

        return .{
            .transaction = encoded_tx,
            .meta = meta,
            .version = if (version) |v| switch (v) {
                .legacy => .legacy,
                .v0 => .{ .number = 0 },
            } else null,
        };
    }

    /// Encode a transaction to the specified format.
    fn encodeTransaction(
        allocator: std.mem.Allocator,
        transaction: sig.core.Transaction,
        encoding: GetBlock.Encoding,
    ) !GetBlock.Response.EncodedTransaction {
        switch (encoding) {
            .binary => {
                // Serialize transaction to bincode
                const bincode_bytes = try sig.bincode.writeAlloc(allocator, transaction, .{});
                defer allocator.free(bincode_bytes);

                // Base58 encode
                const base58_str = base58.Table.BITCOIN.encodeAlloc(allocator, bincode_bytes) catch {
                    return error.EncodingError;
                };

                return .{ .legacy_binary = base58_str };
            },
            .base58 => {
                // Serialize transaction to bincode
                const bincode_bytes = try sig.bincode.writeAlloc(allocator, transaction, .{});
                defer allocator.free(bincode_bytes);

                // Base58 encode
                const base58_str = base58.Table.BITCOIN.encodeAlloc(allocator, bincode_bytes) catch {
                    return error.EncodingError;
                };

                return .{ .binary = .{
                    .data = base58_str,
                    .encoding = .base58,
                } };
            },
            .base64 => {
                // Serialize transaction to bincode
                const bincode_bytes = try sig.bincode.writeAlloc(allocator, transaction, .{});
                defer allocator.free(bincode_bytes);

                // Base64 encode
                const encoded_len = std.base64.standard.Encoder.calcSize(bincode_bytes.len);
                const base64_buf = try allocator.alloc(u8, encoded_len);
                _ = std.base64.standard.Encoder.encode(base64_buf, bincode_bytes);

                return .{ .binary = .{
                    .data = base64_buf,
                    .encoding = .base64,
                } };
            },
            // TODO: implement json and jsonParsed encoding
            .json, .jsonParsed => return error.NotImplemented,
        }
    }

    /// Convert internal TransactionStatusMeta to wire format UiTransactionStatusMeta.
    fn encodeTransactionStatusMeta(
        allocator: std.mem.Allocator,
        meta: sig.ledger.transaction_status.TransactionStatusMeta,
        static_keys: []const Pubkey,
        show_rewards: bool,
    ) !GetBlock.Response.UiTransactionStatusMeta {
        const account_keys = parse_instruction.AccountKeys.init(static_keys, meta.loaded_addresses);

        // Build status field
        const status: GetBlock.Response.UiTransactionResultStatus = if (meta.status) |err|
            .{ .Ok = null, .Err = err }
        else
            .{ .Ok = .{}, .Err = null };

        // Convert inner instructions
        const inner_instructions: []const parse_instruction.UiInnerInstructions = blk: {
            if (meta.inner_instructions) |iis| {
                var inner_instructions = try allocator.alloc(
                    parse_instruction.UiInnerInstructions,
                    iis.len,
                );
                for (iis, 0..) |ii, i| {
                    inner_instructions[i] = try parse_instruction.parseUiInnerInstructions(
                        allocator,
                        ii,
                        &account_keys,
                    );
                }
                break :blk inner_instructions;
            } else break :blk &.{};
        };

        // Convert token balances
        const pre_token_balances = if (meta.pre_token_balances) |balances|
            try convertTokenBalances(allocator, balances)
        else
            &.{};

        const post_token_balances = if (meta.post_token_balances) |balances|
            try convertTokenBalances(allocator, balances)
        else
            &.{};

        // Convert loaded addresses
        const loaded_addresses = try convertLoadedAddresses(allocator, meta.loaded_addresses);

        // Convert return data
        const return_data = if (meta.return_data) |rd|
            try convertReturnData(allocator, rd)
        else
            null;

        // Duplicate log messages (original memory will be freed with block.deinit)
        const log_messages: []const []const u8 = if (meta.log_messages) |logs| blk: {
            const duped = try allocator.alloc([]const u8, logs.len);
            for (logs, 0..) |log, i| {
                duped[i] = try allocator.dupe(u8, log);
            }
            break :blk duped;
        } else &.{};

        const rewards = if (show_rewards) try convertRewards(
            allocator,
            meta.rewards,
        ) else &.{};

        return .{
            .err = meta.status,
            .status = status,
            .fee = meta.fee,
            .preBalances = try allocator.dupe(u64, meta.pre_balances),
            .postBalances = try allocator.dupe(u64, meta.post_balances),
            .innerInstructions = inner_instructions,
            .logMessages = log_messages,
            .preTokenBalances = pre_token_balances,
            .postTokenBalances = post_token_balances,
            .rewards = rewards,
            .loadedAddresses = loaded_addresses,
            .returnData = return_data,
            .computeUnitsConsumed = meta.compute_units_consumed,
            .costUnits = meta.cost_units,
        };
    }

    /// Convert inner instructions to wire format.
    fn convertInnerInstructions(
        allocator: std.mem.Allocator,
        inner_instructions: []const sig.ledger.transaction_status.InnerInstructions,
    ) ![]const parse_instruction.UiInnerInstructions {
        const result = try allocator.alloc(
            parse_instruction.UiInnerInstructions,
            inner_instructions.len,
        );
        errdefer allocator.free(result);

        for (inner_instructions, 0..) |ii, i| {
            const instructions = try allocator.alloc(
                parse_instruction.UiInstruction,
                ii.instructions.len,
            );
            errdefer allocator.free(instructions);

            for (ii.instructions, 0..) |inner_ix, j| {
                // Base58 encode the instruction data
                const data_str = base58.Table.BITCOIN.encodeAlloc(
                    allocator,
                    inner_ix.instruction.data,
                ) catch {
                    return error.EncodingError;
                };

                instructions[j] = .{ .compiled = .{
                    .programIdIndex = inner_ix.instruction.program_id_index,
                    .accounts = try allocator.dupe(u8, inner_ix.instruction.accounts),
                    .data = data_str,
                    .stackHeight = inner_ix.stack_height,
                } };
            }

            result[i] = .{
                .index = ii.index,
                .instructions = instructions,
            };
        }

        return result;
    }

    /// Convert token balances to wire format.
    fn convertTokenBalances(
        allocator: std.mem.Allocator,
        balances: []const sig.ledger.transaction_status.TransactionTokenBalance,
    ) ![]const GetBlock.Response.UiTransactionTokenBalance {
        const result = try allocator.alloc(
            GetBlock.Response.UiTransactionTokenBalance,
            balances.len,
        );
        errdefer allocator.free(result);

        for (balances, 0..) |b, i| {
            result[i] = .{
                .accountIndex = b.account_index,
                .mint = b.mint,
                .owner = b.owner,
                .programId = b.program_id,
                .uiTokenAmount = .{
                    .amount = try allocator.dupe(u8, b.ui_token_amount.amount),
                    .decimals = b.ui_token_amount.decimals,
                    .uiAmount = b.ui_token_amount.ui_amount,
                    .uiAmountString = try allocator.dupe(u8, b.ui_token_amount.ui_amount_string),
                },
            };
        }

        return result;
    }

    /// Convert loaded addresses to wire format.
    fn convertLoadedAddresses(
        allocator: std.mem.Allocator,
        loaded: sig.ledger.transaction_status.LoadedAddresses,
    ) !GetBlock.Response.UiLoadedAddresses {
        return .{
            .writable = try allocator.dupe(Pubkey, loaded.writable),
            .readonly = try allocator.dupe(Pubkey, loaded.readonly),
        };
    }

    /// Convert return data to wire format.
    fn convertReturnData(
        allocator: std.mem.Allocator,
        return_data: sig.ledger.transaction_status.TransactionReturnData,
    ) !GetBlock.Response.UiTransactionReturnData {
        // Base64 encode the return data
        const encoded_len = std.base64.standard.Encoder.calcSize(return_data.data.len);
        const base64_data = try allocator.alloc(u8, encoded_len);
        _ = std.base64.standard.Encoder.encode(base64_data, return_data.data);

        return .{
            .programId = return_data.program_id,
            .data = .{ base64_data, .base64 },
        };
    }

    /// Convert internal reward format to RPC response format.
    fn convertRewards(
        allocator: std.mem.Allocator,
        internal_rewards: ?[]const sig.ledger.meta.Reward,
    ) ![]const GetBlock.Response.UiReward {
        if (internal_rewards == null) return &.{};
        const rewards_value = internal_rewards orelse return &.{};
        const rewards = try allocator.alloc(GetBlock.Response.UiReward, rewards_value.len);
        errdefer allocator.free(rewards);

        for (rewards_value, 0..) |r, i| {
            rewards[i] = try GetBlock.Response.UiReward.fromLedgerReward(r);
        }
        return rewards;
    }

    fn convertBlockRewards(
        allocator: std.mem.Allocator,
        block_rewards: *const sig.replay.rewards.BlockRewards,
    ) ![]const GetBlock.Response.UiReward {
        const items = block_rewards.items();
        const rewards = try allocator.alloc(GetBlock.Response.UiReward, items.len);
        errdefer allocator.free(rewards);

        for (items, 0..) |r, i| {
            rewards[i] = .{
                .pubkey = r.pubkey,
                .lamports = r.reward_info.lamports,
                .postBalance = r.reward_info.post_balance,
                .rewardType = switch (r.reward_info.reward_type) {
                    .fee => .Fee,
                    .rent => .Rent,
                    .staking => .Staking,
                    .voting => .Voting,
                },
                .commission = r.reward_info.commission,
            };
        }
        return rewards;
    }
};
