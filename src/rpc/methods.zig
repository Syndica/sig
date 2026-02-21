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
const Commitment = common.Commitment;

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
        defer slot_ref.release();

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
        const stakes, var stakes_guard = slot_ref.state().stakes_cache.stakes.readWithLock();
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
