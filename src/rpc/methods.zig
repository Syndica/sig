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
const zstd = @import("zstd");

const Allocator = std.mem.Allocator;
const ParseOptions = std.json.ParseOptions;

const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;
const Slot = sig.core.Slot;
const ClientVersion = sig.version.ClientVersion;

const account_decoder = sig.rpc.account_decoder;

const MAX_BASE58_INPUT_LEN = 128;
const MAX_BASE58_OUTPUT_LEN = base58.encodedMaxSize(MAX_BASE58_INPUT_LEN);

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

    pub const Config = struct {
        commitment: ?common.Commitment = null,
        minContextSlot: ?u64 = null,
        encoding: ?common.AccountEncoding = null,
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
                encoded: struct { []const u8, common.AccountEncoding },
                jsonParsed: account_decoder.ParsedAccount,

                /// This field is only set when the request object asked for `jsonParsed` encoding,
                /// and the server couldn't find a parser, therefore falling back to returning
                /// the account data in base64 encoding as an array tuple `["data", "base64"]`.
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
                        // Fallback must return array format ["data", "base64"] like testnet
                        .json_parsed_base64_fallback => |str| {
                            try jw.write(.{ str, common.AccountEncoding.base64 });
                        },
                    }
                }

                pub fn jsonParse(
                    allocator: std.mem.Allocator,
                    source: anytype,
                    options: std.json.ParseOptions,
                ) std.json.ParseError(@TypeOf(source.*))!Data {
                    return switch (try source.peekNextTokenType()) {
                        .array_begin => .{ .encoded = try std.json.innerParse(
                            struct { []const u8, common.AccountEncoding },
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
    config: ?Config = null,

    pub const Config = struct {
        commitment: ?common.Commitment = null,
        encoding: ?enum { json, jsonParsed, base58, base64 } = null,
        transactionDetails: ?[]const u8 = null,
        maxSupportedTransactionVersion: ?u64 = null,
        rewards: ?bool = null,
    };

    // TODO: response
    pub const Response = noreturn;
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

/// https://solana.com/docs/rpc/http/getgenesishash
/// Returns the genesis hash as a base-58 encoded string.
pub const GetGenesisHash = struct {
    /// Response is a base-58 encoded hash string representing the genesis hash.
    pub const Response = sig.core.Hash;
};

// TODO: getGenesisHash - implemented below as GetGenesisHash
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
        delinquintSlotDistance: ?u64 = null,
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
        commitment: ?Commitment = null,
        minContextSlot: ?sig.core.Slot = null,
    };

    pub const Context = struct {
        slot: u64,
        apiVersion: []const u8,
    };

    pub const AccountEncoding = enum {
        base58,
        base64,
        @"base64+zstd",
        jsonParsed,
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

pub const SlotHookContext = struct {
    slot_tracker: *const sig.replay.trackers.SlotTracker,

    pub fn getSlot(self: SlotHookContext, _: std.mem.Allocator, params: GetSlot) !GetSlot.Response {
        const config = params.config orelse common.CommitmentSlotConfig{};
        const commitment = config.commitment orelse .finalized;
        const slot = self.slot_tracker.getSlotForCommitment(commitment);
        const min_slot = config.minContextSlot orelse return slot;
        return if (slot >= min_slot) slot else error.RpcMinContextSlotNotMet;
    }
};

pub const AccountHookContext = struct {
    slot_tracker: *const sig.replay.trackers.SlotTracker,
    account_reader: sig.accounts_db.AccountReader,

    pub fn getAccountInfo(
        self: AccountHookContext,
        allocator: std.mem.Allocator,
        params: GetAccountInfo,
    ) !GetAccountInfo.Response {
        const config = params.config orelse GetAccountInfo.Config{};
        // [agave] Default commitment is finalized:
        // https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L348
        const commitment = config.commitment orelse .finalized;
        // [agave] Default encoding in AGave is `Binary` (legacy base58):
        // https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L545
        // However, `Binary` is deprecated and `Base64` is preferred for performance.
        // We default to base64 as it's more efficient and the recommended encoding.
        const encoding = config.encoding orelse common.AccountEncoding.base64;

        const slot = self.slot_tracker.getSlotForCommitment(commitment);
        if (config.minContextSlot) |min_slot| {
            if (slot < min_slot) return error.RpcMinContextSlotNotMet;
        }

        // TODO: is this the best way to get the right slot to use?
        const ref = self.slot_tracker.get(slot) orelse return error.SlotNotFound;
        const slot_reader = self.account_reader.forSlot(&ref.constants.ancestors);
        const maybe_account = try slot_reader.get(allocator, params.pubkey);

        if (maybe_account) |account| {
            defer account.deinit(allocator);

            const data: GetAccountInfo.Response.Value.Data = if (encoding == .jsonParsed)
                try encodeJsonParsed(allocator, params.pubkey, account, slot_reader)
            else
                try encodeStandard(allocator, account, encoding, config.dataSlice);

            return GetAccountInfo.Response{
                .context = .{ .slot = slot, .apiVersion = ClientVersion.API_VERSION },
                .value = .{
                    .data = data,
                    .executable = account.executable,
                    .lamports = account.lamports,
                    .owner = account.owner,
                    .rentEpoch = account.rent_epoch,
                    .space = account.data.len(),
                },
            };
        } else {
            return .{
                .context = .{ .slot = slot, .apiVersion = ClientVersion.API_VERSION },
                .value = null,
            };
        }
    }

    /// Handles jsonParsed encoding with fallback to base64
    fn encodeJsonParsed(
        allocator: std.mem.Allocator,
        pubkey: sig.core.Pubkey,
        account: sig.core.Account,
        slot_reader: sig.accounts_db.SlotAccountReader,
    ) !GetAccountInfo.Response.Value.Data {
        // Build additional data for token accounts, fetch mint and clock for Token-2022 responses.
        const additional_data = account_decoder.buildTokenAdditionalData(
            allocator,
            account,
            slot_reader,
        );

        var account_data_iter = account.data.iterator();
        // Try to parse based on owner program
        if (try account_decoder.parse_account(
            allocator,
            pubkey,
            account.owner,
            account_data_iter.reader(),
            account.data.len(),
            if (additional_data.spl_token != null) additional_data else null,
        )) |parsed| {
            return .{ .jsonParsed = parsed };
        }
        // Fallback: encode as base64 string when jsonParsed fails.
        // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/lib.rs#L81-L88
        // When parse_account_data_v3 fails, AGave falls back to base64 encoding.
        var encoded = try std.ArrayListUnmanaged(u8).initCapacity(
            allocator,
            // If jsonParsed fails, we fallback to base64 encoding, so we need to allocate
            // enough capacity for the encoded string here.
            std.base64.standard.Encoder.calcSize(account.data.len()),
        );
        errdefer encoded.deinit(allocator);
        try encodeAccountData(allocator, account, .base64, null, encoded.writer(allocator));
        return .{ .json_parsed_base64_fallback = try encoded.toOwnedSlice(allocator) };
    }

    fn estimateEncodedSize(
        account: sig.core.Account,
        encoding: common.AccountEncoding,
        data_slice: ?common.DataSlice,
    ) usize {
        const start, const end = calculateSliceRange(account, data_slice);
        const data_len = end - start;
        return switch (encoding) {
            .base58 => base58.encodedMaxSize(data_len),
            .base64 => std.base64.standard.Encoder.calcSize(data_len),
            // NOTE: we just use base64 size as a catch-all.
            .@"base64+zstd" => std.base64.standard.Encoder.calcSize(data_len),
            .jsonParsed => unreachable, // should be handled in encodeJsonParsed
        };
    }

    /// Handles base58, base64, base64+zstd encodings
    fn encodeStandard(
        allocator: std.mem.Allocator,
        account: sig.core.Account,
        encoding: common.AccountEncoding,
        data_slice: ?common.DataSlice,
    ) !GetAccountInfo.Response.Value.Data {
        const estimated_size = estimateEncodedSize(account, encoding, data_slice);
        var encoded_data = try std.ArrayListUnmanaged(u8).initCapacity(allocator, estimated_size);
        errdefer encoded_data.deinit(allocator);
        try encodeAccountData(
            allocator,
            account,
            encoding,
            data_slice,
            encoded_data.writer(allocator),
        );
        return .{
            .encoded = .{
                try encoded_data.toOwnedSlice(allocator),
                encoding,
            },
        };
    }

    fn encodeAccountData(
        allocator: std.mem.Allocator,
        account: sig.core.Account,
        encoding: common.AccountEncoding,
        data_slice: ?common.DataSlice,
        // std.io.Writer
        writer: anytype,
    ) !void {
        const start, const end = calculateSliceRange(account, data_slice);
        return switch (encoding) {
            .base58 => {
                const data_len = end - start;

                if (data_len > MAX_BASE58_INPUT_LEN) {
                    // [agave] Returns "error: data too large for bs58 encoding" string instead of error:
                    // https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/lib.rs#L44-L47
                    // We return an error here since returning a fake "error" string would be misleading.
                    return error.Base58DataTooLarge;
                }

                var input_buf: [MAX_BASE58_INPUT_LEN]u8 = undefined;
                var output_buf: [MAX_BASE58_OUTPUT_LEN]u8 = undefined;
                _ = account.data.read(start, input_buf[0..data_len]);
                const encoded_len = base58.Table.BITCOIN.encode(&output_buf, input_buf[0..data_len]);

                try writer.writeAll(output_buf[0..encoded_len]);
            },
            .base64 => {
                var stream = sig.utils.base64.EncodingStream.init(std.base64.standard.Encoder);
                const base64_ctx = stream.writerCtx(writer);
                var iter = account.data.iteratorRanged(start, end);

                while (iter.nextFrame()) |frame_slice| {
                    try base64_ctx.writer().writeAll(frame_slice);
                }
                try base64_ctx.flush();
            },
            .@"base64+zstd" => {
                var stream = sig.utils.base64.EncodingStream.init(std.base64.standard.Encoder);
                const base64_ctx = stream.writerCtx(writer);
                // TODO: propagate more specifi errors.
                const compressor = zstd.Compressor.init(.{}) catch return error.OutOfMemory;
                defer compressor.deinit();

                // TODO: recommOutSize is usually 128KiB. We could stack allocate this or re-use
                // buffer set in AccountHookContext instead of allocating it on each call
                // since the server is single-threaded. Unfortunately, the zstd lib's doesn't give us a
                // comptime-known size to use for stack allocation. Instead of assuming, just allocate for now.
                const zstd_out_buf = try allocator.alloc(
                    u8,
                    zstd.Compressor.recommOutSize(),
                );
                defer allocator.free(zstd_out_buf);
                var zstd_ctx = zstd.writerCtx(
                    base64_ctx.writer(),
                    &compressor,
                    zstd_out_buf,
                );
                var iter = account.data.iteratorRanged(start, end);

                while (iter.nextFrame()) |frame_slice| {
                    try zstd_ctx.writer().writeAll(frame_slice);
                }
                try zstd_ctx.finish();
                try base64_ctx.flush();
            },
            .jsonParsed => unreachable, // handled in encodeJsonParsed
        };
    }

    fn calculateSliceRange(
        account: sig.core.Account,
        data_slice: ?common.DataSlice,
    ) struct { u32, u32 } {
        const len = account.data.len();
        const slice_start, const slice_end = blk: {
            const ds = data_slice orelse break :blk .{ 0, len };
            const start = @min(ds.offset, len);
            const end = @min(ds.offset + ds.length, len);
            break :blk .{ start, end };
        };
        return .{ slice_start, slice_end };
    }
};
