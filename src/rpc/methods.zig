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

const Allocator = std.mem.Allocator;
const ParseOptions = std.json.ParseOptions;

const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;
const Slot = sig.core.Slot;

/// NOTE: for the sake of simplicity, we only support `method: ..., params: ...`,
/// and reject `params: ..., method: ...`; this is a reasonable expectation for
/// clients to satisfy.
pub const Call = struct {
    id: Id,
    method: Method,

    pub fn jsonStringify(
        self: Call,
        /// `*std.json.WriteStream(...)`
        jw: anytype,
    ) @TypeOf(jw.*).Error!void {
        try jw.beginObject();

        try jw.objectField("jsonrpc");
        try jw.write("2.0");

        try jw.objectField("id");
        switch (self.id) {
            .null => try jw.write(null),
            .int => |int| try jw.write(int),
            .str => |str| try jw.write(str),
        }

        try jw.objectField("method");
        try jw.write(@tagName(self.method));

        try jw.objectField("params");
        switch (self.method) {
            inline else => |maybe_method| {
                const T = @TypeOf(maybe_method);
                if (@hasDecl(T, "jsonStringify")) {
                    try jw.write(maybe_method);
                } else {
                    var null_count: usize = 0;

                    try jw.beginArray();
                    inline for (@typeInfo(T).Struct.fields) |field| cont: {
                        const maybe_value = @field(maybe_method, field.name);
                        const value = blk: {
                            if (@typeInfo(field.type) != .Optional) break :blk maybe_value;
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

        try jw.endObject();
    }

    pub fn jsonParse(
        allocator: std.mem.Allocator,
        /// * `std.json.Scanner`
        /// * `std.json.Reader(...)`
        source: anytype,
        options: std.json.ParseOptions,
    ) std.json.ParseError(@TypeOf(source.*))!Call {
        var jsonrpc_version_field = false;

        const IdState = union(enum) {
            null,
            int: i128,
            str_alloc,
            str_ref: []const u8,
        };
        var maybe_id_state: ?IdState = null;
        // this is the buffer used if `id_state == .str_alloc`
        var id_buf = std.ArrayList(u8).init(allocator);
        defer id_buf.deinit();

        var maybe_method_tag: ?Method.Tag = null;
        var maybe_method_payload: ?Method.UntaggedPayload = null;

        if (try source.next() != .object_begin) {
            return error.UnexpectedToken;
        }

        while (true) {
            switch (try source.peekNextTokenType()) {
                .object_end => {
                    std.debug.assert(try source.next() == .object_end);
                    break;
                },
                .string => {},
                else => return error.UnexpectedToken,
            }

            const FieldName = enum { jsonrpc, id, method, params };
            const field_name = try jsonParseEnumTag(
                FieldName,
                source,
            ) orelse if (!options.ignore_unknown_fields) {
                return error.UnknownField;
            } else continue;

            switch (field_name) {
                .jsonrpc => {
                    if (jsonrpc_version_field) switch (options.duplicate_field_behavior) {
                        .use_first => {
                            try source.skipValue();
                            continue;
                        },
                        .@"error" => return error.DuplicateField,
                        // it's an error if it's not the expected value regardless
                        .use_last => {},
                    };

                    if (try source.peekNextTokenType() != .string) {
                        try source.skipValue();
                        return error.UnexpectedToken;
                    }

                    jsonrpc_version_field = true;
                    if (!try jsonParseExpectValue(source, "2.0")) {
                        return error.UnexpectedToken;
                    }
                },
                .id => {
                    if (maybe_id_state != null) switch (options.duplicate_field_behavior) {
                        .use_first => {
                            try source.skipValue();
                            continue;
                        },
                        .@"error" => return error.DuplicateField,
                        .use_last => {},
                    };

                    const TokType = enum { null, number, string };
                    const tok_type: TokType = switch (try source.peekNextTokenType()) {
                        .null => .null,
                        .number => .number,
                        .string => .string,
                        else => {
                            try source.skipValue();
                            return error.UnexpectedToken;
                        },
                    };

                    id_buf.clearRetainingCapacity();
                    maybe_id_state = switch (tok_type) {
                        .null => id: {
                            std.debug.assert(try source.next() == .null);
                            break :id .null;
                        },
                        .number, .string => id: {
                            const maybe_str =
                                try source.allocNextIntoArrayList(&id_buf, options.allocate.?);
                            if (std.fmt.parseInt(i128, maybe_str orelse id_buf.items, 10)) |int|
                                break :id .{ .int = int }
                            else |err| switch (err) {
                                error.Overflow,
                                error.InvalidCharacter,
                                => {},
                            }
                            const str_ref = maybe_str orelse break :id .str_alloc;
                            break :id .{ .str_ref = str_ref };
                        },
                    };
                },
                .method => {
                    if (maybe_method_tag != null) switch (options.duplicate_field_behavior) {
                        .use_first => {
                            try source.skipValue();
                            continue;
                        },
                        .@"error" => return error.DuplicateField,
                        .use_last => {},
                    };

                    if (try source.peekNextTokenType() != .string) {
                        try source.skipValue();
                        return error.UnexpectedToken;
                    }

                    maybe_method_tag = try jsonParseEnumTag(Method.Tag, source) orelse {
                        return error.UnexpectedToken;
                    };
                },
                .params => {
                    if (maybe_method_payload != null) {
                        std.debug.assert(maybe_method_tag != null);
                        switch (options.duplicate_field_behavior) {
                            .use_first => {
                                try source.skipValue();
                                continue;
                            },
                            .@"error" => return error.DuplicateField,
                            .use_last => {},
                        }
                    }

                    const method_tag = maybe_method_tag orelse return error.MissingField;
                    maybe_method_payload = switch (method_tag) {
                        inline else => |method| payload: {
                            const Params = std.meta.FieldType(Method, method);
                            if (Params == noreturn) std.debug.panic(
                                "TODO: implement {s}",
                                .{@tagName(method)},
                            );

                            const params = try jsonParseOptFieldStructAsArray(
                                Params,
                                allocator,
                                source,
                                options,
                            );
                            break :payload @unionInit(
                                Method.UntaggedPayload,
                                @tagName(method),
                                params,
                            );
                        },
                    };
                },
            }
        }

        if (!jsonrpc_version_field) return error.MissingField;
        const id_state = maybe_id_state orelse return error.MissingField;
        const method_tag = maybe_method_tag orelse return error.MissingField;
        const method_payload = maybe_method_payload orelse return error.MissingField;

        return .{
            .id = switch (id_state) {
                .null => .null,
                .int => |int| .{ .int = int },
                .str_alloc => .{ .str = try id_buf.toOwnedSlice() },
                .str_ref => |str| .{ .str = str },
            },
            .method = switch (method_tag) {
                inline else => |tag| @unionInit(
                    Method,
                    @tagName(tag),
                    @field(method_payload, @tagName(tag)),
                ),
            },
        };
    }
};

pub const Id = union(enum) {
    null,
    int: i128,
    str: []const u8,
};

pub const Method = union(enum) {
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
    getGenesisHash: noreturn,
    getHealth: noreturn,
    getHighestSnapshotSlot: noreturn,
    getIdentity: noreturn,
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

    pub const Tag = @typeInfo(Method).Union.tag_type.?;

    const UntaggedPayload = @Type(.{ .Union = blk: {
        var info = @typeInfo(Method).Union;
        info.tag_type = null;
        info.decls = &.{};
        break :blk info;
    } });
};

pub const GetAccountInfo = struct {
    pubkey: Pubkey,
    config: ?Config = null,

    pub const Config = struct {
        commitment: ?common.Commitment = null,
        minContextSlot: ?u64 = null,
        encoding: ?enum { base58, base64, @"base64+zstd", jsonParsed } = null,
        dataSlice: ?common.DataSlice = null,
    };

    pub const Response = struct {
        context: common.Context,
        value: ?Value,

        pub const Value = struct {
            data: []const u8,
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
// TODO: getGenesisHash
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
        value: std.AutoArrayHashMapUnmanaged(Pubkey, []const u64),

        pub fn jsonParse(
            allocator: std.mem.Allocator,
            source: anytype,
            options: std.json.ParseOptions,
        ) std.json.ParseError(@TypeOf(source.*))!Response {
            const json_object = switch (try std.json.Value.jsonParse(allocator, source, options)) {
                .object => |obj| obj,
                else => return error.UnexpectedToken,
            };

            var map = std.AutoArrayHashMapUnmanaged(Pubkey, []const u64){};
            for (json_object.keys(), json_object.values()) |key, value| {
                const slots = try allocator.alloc(u64, value.array.items.len);
                for (value.array.items, 0..) |slot, i| {
                    slots[i] = @intCast(slot.integer);
                }
                const pubkey = Pubkey.parseBase58String(key) catch return error.InvalidNumber;
                try map.put(allocator, pubkey, slots);
            }

            return .{ .value = map };
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

        pub fn jsonStringify(self: *Response, out_stream: anytype) !void {
            try std.json.stringify(.{
                .@"solana-core" = self.solana_core,
                .@"feature-set" = self.feature_set,
            }, .{}, out_stream);
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
};

fn jsonParseOptFieldStructAsArray(
    comptime T: type,
    allocator: std.mem.Allocator,
    source: anytype,
    options: std.json.ParseOptions,
) std.json.ParseError(@TypeOf(source.*))!T {
    if (try source.next() != .array_begin) {
        return error.UnexpectedToken;
    }

    var result: T = undefined;
    var array_ended = false;

    inline for (@typeInfo(T).Struct.fields) |field| cont: {
        const t_info = @typeInfo(field.type);
        const field_ptr = &@field(result, field.name);

        const tok_type: std.json.TokenType = if (array_ended)
            .array_end
        else tt: {
            const tt = try source.peekNextTokenType();
            if (tt == .array_end) {
                std.debug.assert(try source.next() == .array_end);
            }
            break :tt tt;
        };

        switch (tok_type) {
            .array_end => {
                array_ended = true;
                if (t_info != .Optional) return error.LengthMismatch;
                field_ptr.* = null;
                break :cont;
            },
            else => field_ptr.* = try std.json.innerParse(
                field.type,
                allocator,
                source,
                options,
            ),
        }
    }

    if (!array_ended and try source.next() != .array_end) {
        return error.LengthMismatch;
    }

    return result;
}

fn jsonParseEnumTag(
    comptime E: type,
    source: anytype,
) std.json.ParseError(@TypeOf(source.*))!?E {
    const longest_tag_name_len = comptime max: {
        var max: usize = 0;
        const fields = @typeInfo(E).Enum.fields;
        @setEvalBranchQuota(fields.len + 1);
        for (fields) |e_field| max = @max(max, e_field.name.len);
        break :max max;
    };
    const str = try jsonParseBoundedStr(source, longest_tag_name_len) orelse return null;
    return std.meta.stringToEnum(E, str.constSlice());
}

/// Assumes this is the first token in a sequence of strings predicted by `source.peekNextTokenType()`,
/// either of type `.string` or `.number`.
/// Returns true if the parsed string matches `value` exactly, false otherwise.
fn jsonParseExpectValue(
    source: anytype,
    value: []const u8,
) std.json.ParseError(@TypeOf(source.*))!bool {
    var index: usize = 0;

    var first_iter = true;
    while (true) : (first_iter = false) {
        const tok = try source.next();

        const str: []const u8, const not_partial: bool = switch (tok) {
            .string => |str| .{ str, true },
            .partial_string => |str| .{ str, false },

            inline //
            .partial_string_escaped_1,
            .partial_string_escaped_2,
            .partial_string_escaped_3,
            .partial_string_escaped_4,
            => |*str| .{ str, false },

            .number => |str| .{ str, true },
            .partial_number => |str| .{ str, false },

            .allocated_string => unreachable,
            .allocated_number => unreachable,

            else => return error.UnexpectedToken,
        };

        if (!std.mem.startsWith(u8, value[index..], str)) return false;
        index += str.len;

        if (str.len == 0) break;
        if (first_iter and not_partial) break;
    }

    return index == value.len;
}

fn jsonParseBoundedStr(
    source: anytype,
    comptime max_len: usize,
) std.json.ParseError(@TypeOf(source.*))!?std.BoundedArray(u8, max_len) {
    var result: std.BoundedArray(u8, max_len) = .{};

    var first_iter = true;
    while (true) : (first_iter = false) {
        const tok = try source.next();
        const str: []const u8, const not_partial: bool = switch (tok) {
            .string => |str| .{ str, true },
            .partial_string => |str| .{ str, false },

            inline //
            .partial_string_escaped_1,
            .partial_string_escaped_2,
            .partial_string_escaped_3,
            .partial_string_escaped_4,
            => |*str| .{ str, false },

            else => return error.UnexpectedToken,
        };

        result.appendSlice(str) catch return null;
        if (str.len == 0) break;
        if (first_iter and not_partial) break;
    }

    return result;
}

test Call {
    const test_pubkey1 = comptime sig.core.Pubkey.parseBase58String(
        "vinesvinesvinesvinesvinesvinesvinesvinesvin",
    ) catch unreachable;
    const test_pubkey2 = comptime sig.core.Pubkey.ZEROES;

    try testParseCall(
        .{},
        \\{
        \\  "jsonrpc": "2.0",
        \\  "id": 123,
        \\  "method": "getAccountInfo",
        \\  "params": [
        \\    "vinesvinesvinesvinesvinesvinesvinesvinesvin",
        \\    {
        \\      "encoding": "base58"
        \\    }
        \\  ]
        \\}
    ,
        .{
            .id = .{ .int = 123 },
            .method = .{ .getAccountInfo = .{
                .pubkey = test_pubkey1,
                .config = .{
                    .encoding = .base58,
                },
            } },
        },
    );

    try testParseCall(
        .{},
        \\{
        \\  "jsonrpc": "2.0",
        \\  "id": "a44",
        \\  "method": "getBalance",
        \\  "params": [
        \\    "11111111111111111111111111111111",
        \\    {
        \\      "commitment": "processed",
        \\      "minContextSlot": 64
        \\    }
        \\  ]
        \\}
    ,
        .{
            .id = .{ .str = "a44" },
            .method = .{ .getBalance = .{
                .pubkey = test_pubkey2,
                .config = .{
                    .commitment = .processed,
                    .minContextSlot = 64,
                },
            } },
        },
    );

    try testParseCall(
        .{ .duplicate_field_behavior = .use_first, .ignore_unknown_fields = true },
        \\{
        \\  "jsonrpc": "2.0",
        \\  "jsonrpc": "2.0",
        \\  "id": "a33",
        \\  "method": "getBalance",
        \\  "params": [
        \\    "11111111111111111111111111111111",
        \\    {
        \\      "commitment": "processed",
        \\      "minContextSlot": 64
        \\    }
        \\  ],
        \\  "ignored": "foo"
        \\}
    ,
        .{
            .id = .{ .str = "a33" },
            .method = .{ .getBalance = .{
                .pubkey = test_pubkey2,
                .config = .{
                    .commitment = .processed,
                    .minContextSlot = 64,
                },
            } },
        },
    );

    try std.testing.expectError(
        error.MissingField,
        std.json.parseFromSliceLeaky(Call, std.testing.allocator,
            \\{"jsonrpc":"2.0","id":42,"id":"33","method":"getBalance","method":"getAccountInfo"}
        , .{ .duplicate_field_behavior = .use_first }),
    );
    try std.testing.expectError(
        error.MissingField,
        std.json.parseFromSliceLeaky(Call, std.testing.allocator,
            \\{"jsonrpc":"2.0","id":null,"method":"getBalance"}
        , .{}),
    );
    try std.testing.expectError(
        error.DuplicateField,
        std.json.parseFromSliceLeaky(Call, std.testing.allocator,
            \\{"jsonrpc":"2.0","id":null,"method":"getBalance","method":"getAccountInfo"}
        , .{}),
    );
    try std.testing.expectError(
        error.DuplicateField,
        std.json.parseFromSliceLeaky(Call, std.testing.allocator,
            \\{"jsonrpc":"2.0","id":42,"id":"33"}
        , .{ .duplicate_field_behavior = .@"error" }),
    );

    try std.testing.expectError(
        error.DuplicateField,
        std.json.parseFromSliceLeaky(Call, std.testing.allocator,
            \\{"jsonrpc":"2.0","jsonrpc":"2.0"}
        , .{}),
    );
    try std.testing.expectError(
        error.UnexpectedToken,
        std.json.parseFromSliceLeaky(Call, std.testing.allocator,
            \\{"jsonrpc":"2.0","method":null}
        , .{}),
    );

    try std.testing.expectError(
        error.UnexpectedToken,
        std.json.parseFromSliceLeaky(Call, std.testing.allocator,
            \\{"jsonrpc":2.0}
        , .{}),
    );

    try std.testing.expectError(
        error.UnknownField,
        std.json.parseFromSliceLeaky(Call, std.testing.allocator,
            \\{"unexpected":"foo"}
        , .{}),
    );
}

fn testParseCall(
    options: std.json.ParseOptions,
    actual_str: []const u8,
    expected_call: Call,
) !void {
    const actual_call = try std.json.parseFromSlice(
        Call,
        std.testing.allocator,
        actual_str,
        options,
    );
    defer actual_call.deinit();
    try std.testing.expectEqualDeep(expected_call, actual_call.value);
}
