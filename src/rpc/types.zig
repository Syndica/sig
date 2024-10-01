const std = @import("std");
const sig = @import("../sig.zig");
const TransactionError = sig.ledger.transaction_status.TransactionError;

pub const Commitment = enum {
    finalized,
    confirmed,
    processed,
};

pub const Context = struct {
    slot: u64,
    apiVersion: []const u8,
};

pub const AccountInfo = struct {
    context: Context,
    value: ?Value,

    pub const Value = struct {
        data: []const u8,
        executable: bool,
        lamports: u64,
        owner: []const u8,
        rentEpoch: u64,
        space: u64,
    };
};

pub const Balance = struct {
    context: Context,
    value: u64,
};

pub const BlockCommitment = struct {
    commitment: ?[]const u64,
    totalStake: u64,
};

// TODO: BlockProduction
// TODO: BlockTime
// TODO: Blocks
// TODO: BlocksWithLimit

pub const RpcContactInfo = struct {
    /// Pubkey of the node as a base-58 string
    pubkey: []const u8,
    /// Gossip port
    gossip: ?[]const u8,
    /// Tvu UDP port
    tvu: ?[]const u8,
    /// Tpu UDP port
    tpu: ?[]const u8,
    /// Tpu QUIC port
    tpuQuic: ?[]const u8,
    /// Tpu UDP forwards port
    tpuForwards: ?[]const u8,
    /// Tpu QUIC forwards port
    tpuForwardsQuic: ?[]const u8,
    /// Tpu UDP vote port
    tpuVote: ?[]const u8,
    /// Server repair UDP port
    serveRepair: ?[]const u8,
    /// JSON RPC port
    rpc: ?[]const u8,
    /// WebSocket PubSub port
    pubsub: ?[]const u8,
    /// Software version
    version: ?[]const u8,
    /// First 4 bytes of the FeatureSet identifier
    featureSet: ?u32,
    /// Shred version
    shredVersion: ?u16,
};

pub const EpochInfo = struct {
    absoluteSlot: u64,
    blockHeight: u64,
    epoch: u64,
    slotIndex: u64,
    slotsInEpoch: u64,
    transactionCount: u64,
};

pub const EpochSchedule = struct {
    slotsPerEpoch: u64,
    leaderScheduleSlotOffset: u64,
    warmup: bool,
    firstNormalEpoch: u64,
    firstNormalSlot: u64,
};

// TODO: FeeForMessage
// TODO: FirstAvailableBlock
// TODO: GenesisHash
// TODO: Health
// TODO: HighestSnapshotSlot
// TODO: Identity
// TODO: InflationGovernor
// TODO: InflationRate
// TODO: InflationReward
// TODO: LargeAccounts

pub const LatestBlockhash = struct {
    context: Context,
    value: Value,

    pub const Value = struct {
        blockhash: []const u8,
        lastValidBlockHeight: u64,
    };
};

pub const LeaderSchedule = std.StringArrayHashMap([]const u64);

// TODO: MaxRetransmitSlot
// TODO: MaxShredInsertSlot
// TODO: MinimumBalanceForRentExemption
// TODO: MultipleAccounts
// TODO: ProgramAccounts
// TODO: RecentPerformanceSamples
// TODO: RecentPrioritizationFees

pub const SignatureStatuses = struct {
    context: Context,
    value: []const ?TransactionStatus,

    pub const TransactionStatus = struct {
        slot: u64,
        confirmations: ?usize,
        err: ?TransactionError,
        confirmationStatus: ?[]const u8,
    };
};

pub const ClusterType = union(enum(u8)) {
    MainnetBeta,
    Testnet,
    Devnet,
    LocalHost,
    Custom: struct {
        url: []const u8,
    },
};

pub const RpcVersionInfo = struct {
    // TODO: figure out how to support "solana_core" and "feature_set"
    // rn to correctly parse the json response we need to have '-' in the field name
    @"solana-core": []const u8,
    @"feature-set": ?u32,
};

pub const Signature = []const u8;
