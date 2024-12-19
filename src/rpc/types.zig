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
    commitment: ?[]const u64 = null,
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

pub const EpochInfo = struct {
    absoluteSlot: u64,
    blockHeight: u64,
    epoch: u64,
    slotIndex: u64,
    slotsInEpoch: u64,
    transactionCount: u64,
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
    firstNormalEpoch: u64,
    /// The first slot after the warmup period.
    ///
    /// Basically: `MINIMUM_SLOTS_PER_EPOCH * (2.pow(first_normal_epoch) - 1)`.
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
        confirmations: ?usize = null,
        err: ?TransactionError = null,
        confirmationStatus: ?[]const u8 = null,
    };
};

pub const RpcVersionInfo = struct {
    // TODO: figure out how to support "solana_core" and "feature_set"
    // rn to correctly parse the json response we need to have '-' in the field name
    @"solana-core": []const u8,
    @"feature-set": ?u32 = null,
};

pub const Signature = []const u8;

pub const GetVoteAccountsResponse = struct {
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
