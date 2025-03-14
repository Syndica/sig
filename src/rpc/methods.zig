//! Every RPC method defined as a struct, where the fields are the parameters
//! for the rpc method. The order of the fields in the struct definition must
//! match the order of the parameters for the RPC method. Each method's response
//! type is defined as a nested struct called Response.

const std = @import("std");
const sig = @import("../sig.zig");
const rpc = @import("lib.zig");

const Allocator = std.mem.Allocator;
const ParseOptions = std.json.ParseOptions;

const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;
const Slot = sig.core.Slot;

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
