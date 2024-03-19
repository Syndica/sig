const std = @import("std");
const t = @import("types.zig");
const ContactInfo = @import("../gossip/data.zig").ContactInfo;
const GossipService = @import("../gossip/service.zig").GossipService;
const GossipTable = @import("../gossip/table.zig").GossipTable;

pub const RpcRequestProcessor = struct {
    gossip_service: *GossipService,

    const Self = @This();

    pub fn init(gossip_service: *GossipService) Self {
        return Self{
            .gossip_service = gossip_service,
        };
    }

    pub fn getAccountInfo(self: *Self, allocator: std.mem.Allocator, pubkey: t.Pubkey, config: ?t.RpcAccountInfoConfig) t.Result(t.RpcResponse(?t.UiAccount)) {
        _ = allocator;
        _ = self;
        _ = pubkey;
        _ = config;
        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getBalance(self: *Self, allocator: std.mem.Allocator, pubkey: t.Pubkey, config: t.RpcContextConfig) t.Result(t.RpcResponse(u64)) {
        _ = allocator;
        _ = self;
        _ = pubkey;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getBlock(self: *Self, allocator: std.mem.Allocator, slot: t.Slot, config: ?t.RpcBlockConfig) t.Result(t.UiConfirmedBlock) {
        _ = allocator;
        _ = self;
        _ = slot;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getBlockCommitment(self: *Self, allocator: std.mem.Allocator, block: t.Slot) t.Result(t.RpcBlockCommitment) {
        _ = allocator;
        _ = self;
        _ = block;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getBlockHeight(self: *Self, allocator: std.mem.Allocator, config: t.RpcContextConfig) t.Result(u64) {
        _ = allocator;
        _ = self;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getBlockProduction(self: *Self, allocator: std.mem.Allocator, config: ?t.RpcBlockProductionConfig) t.Result(t.RpcResponse(t.RpcBlockProduction)) {
        _ = allocator;
        _ = self;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getBlocks(self: *Self, allocator: std.mem.Allocator, start_slot: t.Slot, end_slot: t.Slot, commitment: ?t.CommitmentConfig) t.Result([]t.Slot) {
        _ = allocator;
        _ = self;
        _ = start_slot;
        _ = end_slot;
        _ = commitment;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getBlocksWithLimit(self: *Self, allocator: std.mem.Allocator, start_slot: t.Slot, limit: usize, commitment: ?t.CommitmentConfig) t.Result([]t.Slot) {
        _ = allocator;
        _ = self;
        _ = start_slot;
        _ = limit;
        _ = commitment;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getBlockTime(self: *Self, allocator: std.mem.Allocator, slot: t.Slot) t.Result(?t.UnixTimestamp) {
        _ = allocator;
        _ = self;
        _ = slot;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getClusterNodes(
        self: *Self,
        allocator: std.mem.Allocator,
    ) t.Result([]t.RpcContactInfo) {
        var table_rlock = self.gossip_service.gossip_table_rw.read();
        defer table_rlock.unlock();
        var table: *const GossipTable = table_rlock.get();

        var contact_infos = table.getAllContactInfos() catch return .{ .Err = t.Error.Internal };
        var rpc_contact_infos = std.ArrayList(t.RpcContactInfo).initCapacity(allocator, contact_infos.items.len) catch return .{ .Err = t.Error.Internal };

        for (contact_infos.items) |contact_info| {
            rpc_contact_infos.appendAssumeCapacity(t.RpcContactInfo{
                .featureSet = null,
                .gossip = contact_info.getSocket(ContactInfo.SOCKET_TAG_GOSSIP),
                .pubkey = contact_info.pubkey,
                .pubsub = contact_info.getSocket(ContactInfo.SOCKET_TAG_RPC_PUBSUB),
                .rpc = contact_info.getSocket(ContactInfo.SOCKET_TAG_RPC),
                .shredVersion = contact_info.shred_version,
                .tpu = contact_info.getSocket(ContactInfo.SOCKET_TAG_TPU),
                .tpuQuic = contact_info.getSocket(ContactInfo.SOCKET_TAG_TPU_QUIC), // TODO: correct value
                .version = null, // TODO: populate
            });
        }
        return .{ .Ok = rpc_contact_infos.items };
    }

    pub fn getConfirmedBlock(self: *Self, allocator: std.mem.Allocator, slot: t.Slot, config: t.RpcEncodingConfigWrapper(t.RpcConfirmedBlockConfig)) t.Result(?t.UiConfirmedBlock) {
        _ = allocator;
        _ = self;
        _ = slot;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getConfirmedBlocks(self: *Self, allocator: std.mem.Allocator, start_slot: t.Slot, config: ?t.RpcConfirmedBlocksConfigWrapper, commitment: ?t.CommitmentConfig) t.Result([]t.Slot) {
        _ = allocator;
        _ = self;
        _ = start_slot;
        _ = config;
        _ = commitment;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getConfirmedBlocksWithLimit(self: *Self, allocator: std.mem.Allocator, start_slot: t.Slot, limit: usize, commitment: ?t.CommitmentConfig) t.Result([]t.Slot) {
        _ = allocator;
        _ = self;
        _ = start_slot;
        _ = limit;
        _ = commitment;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getConfirmedSignaturesForAddress2(self: *Self, allocator: std.mem.Allocator, address: []const u8, config: ?t.RpcGetConfirmedSignaturesForAddress2Config) t.Result([]t.RpcConfirmedTransactionStatusWithSignature) {
        _ = allocator;
        _ = self;
        _ = address;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getConfirmedTransaction(self: *Self, allocator: std.mem.Allocator, signature: []const u8, config: ?t.RpcEncodingConfigWrapper(t.RpcConfirmedTransactionConfig)) t.Result(?t.EncodedConfirmedTransactionWithStatusMeta) {
        _ = allocator;
        _ = self;
        _ = signature;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getEpochInfo(self: *Self, allocator: std.mem.Allocator, config: ?t.RpcContextConfig) t.Result(t.EpochInfo) {
        _ = allocator;
        _ = self;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getEpochSchedule(self: *Self, allocator: std.mem.Allocator) t.Result(t.EpochSchedule) {
        _ = allocator;

        _ = self;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getFeeCalculatorForBlockhash(self: *Self, allocator: std.mem.Allocator, blockhash: t.Hash, commitment: ?t.CommitmentConfig) t.Result(t.RpcResponse(?t.RpcFeeCalculator)) {
        _ = allocator;
        _ = self;
        _ = blockhash;
        _ = commitment;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getFeeForMessage(self: *Self, allocator: std.mem.Allocator, data: []const u8, config: ?t.RpcContextConfig) t.Result(t.RpcResponse(?u64)) {
        _ = allocator;
        _ = self;
        _ = data;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getFeeRateGovernor(self: *Self, allocator: std.mem.Allocator) t.Result(t.RpcResponse(t.RpcFeeRateGovernor)) {
        _ = allocator;

        _ = self;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getFees(self: *Self, allocator: std.mem.Allocator, commitment: ?t.CommitmentConfig) t.Result(t.RpcResponse(t.RpcFees)) {
        _ = allocator;
        _ = self;
        _ = commitment;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getFirstAvailableBlock(self: *Self, allocator: std.mem.Allocator) t.Result(u64) {
        _ = allocator;

        _ = self;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getGenesisHash(self: *Self, allocator: std.mem.Allocator) t.Result([]const u8) {
        _ = allocator;

        _ = self;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getHealth(self: *Self, allocator: std.mem.Allocator) t.Result([]const u8) {
        _ = allocator;

        _ = self;

        return .{ .Ok = "ok" };
    }

    pub fn getHighestSnapshotSlot(self: *Self, allocator: std.mem.Allocator) t.Result(t.RpcSnapshotSlotInfo) {
        _ = allocator;

        _ = self;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getIdentity(self: *Self, allocator: std.mem.Allocator) t.Result(t.RpcIdentity) {
        var identity: []const u8 = self.gossip_service.my_pubkey.toString(allocator) catch @panic("could not toString a Pubkey");
        return .{
            .Ok = t.RpcIdentity{
                .identity = identity,
            },
        };
    }

    pub fn getInflationGovernor(self: *Self, allocator: std.mem.Allocator, commitment: ?t.CommitmentConfig) t.Result(t.RpcInflationGovernor) {
        _ = allocator;
        _ = self;
        _ = commitment;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getInflationRate(self: *Self, allocator: std.mem.Allocator) t.Result(t.RpcInflationRate) {
        _ = allocator;

        _ = self;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getInflationReward(self: *Self, allocator: std.mem.Allocator, addresses: []t.Pubkey, config: ?t.RpcEpochConfig) t.Result([]?t.RpcInflationReward) {
        _ = allocator;
        _ = self;
        _ = addresses;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getLargestAccounts(self: *Self, allocator: std.mem.Allocator, config: ?t.RpcLargestAccountsConfig) t.Result(t.RpcResponse([]t.RpcAccountBalance)) {
        _ = allocator;
        _ = self;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getLatestBlockhash(self: *Self, allocator: std.mem.Allocator, config: ?t.RpcContextConfig) t.Result(t.RpcResponse(t.RpcBlockhash)) {
        _ = allocator;
        _ = self;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getLeaderSchedule(self: *Self, allocator: std.mem.Allocator, options: ?t.RpcLeaderScheduleConfigWrapper, config: ?t.RpcLeaderScheduleConfig) t.Result(?t.RpcLeaderSchedule) {
        _ = allocator;
        _ = self;
        _ = options;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getMaxRetransmitSlot(self: *Self, allocator: std.mem.Allocator) t.Result(t.Slot) {
        _ = allocator;

        _ = self;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getMaxShredInsertSlot(self: *Self, allocator: std.mem.Allocator) t.Result(t.Slot) {
        _ = allocator;

        _ = self;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getMinimumBalanceForRentExemption(self: *Self, allocator: std.mem.Allocator, data_len: usize, commitment_config: ?t.CommitmentConfig) t.Result(u64) {
        _ = allocator;
        _ = self;
        _ = data_len;
        _ = commitment_config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getMultipleAccounts(self: *Self, allocator: std.mem.Allocator, publeys: []t.Pubkey, config: ?t.RpcAccountInfoConfig) t.Result(t.RpcResponse([]?t.UiAccount)) {
        _ = allocator;
        _ = self;
        _ = publeys;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getProgramAccounts(self: *Self, allocator: std.mem.Allocator, program_id: t.Pubkey, config: ?t.RpcAccountInfoConfig, filters: []t.AccountFilter, with_context: bool) t.Result(t.OptionalContext([]t.RpcKeyedAccount)) {
        _ = allocator;
        _ = self;
        _ = program_id;
        _ = config;
        _ = filters;
        _ = with_context;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getRecentBlockhash(self: *Self, allocator: std.mem.Allocator, commitment: ?t.CommitmentConfig) t.Result(t.RpcResponse(t.RpcBlockhashFeeCalculator)) {
        _ = allocator;
        _ = self;
        _ = commitment;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getRecentPerformanceSamples(self: *Self, allocator: std.mem.Allocator, limit: ?usize) t.Result([]t.RpcPerfSample) {
        _ = allocator;
        _ = self;
        _ = limit;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getRecentPrioritizationFees(self: *Self, allocator: std.mem.Allocator, pubkeys: []t.Pubkey) t.Result([]t.RpcPrioritizationFee) {
        _ = allocator;
        _ = self;
        _ = pubkeys;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getSignaturesForAddress(self: *Self, allocator: std.mem.Allocator, address: t.Pubkey, before: ?t.Signature, until: ?t.Signature, limit: usize, config: t.RpcContextConfig) t.Result([]t.RpcConfirmedTransactionStatusWithSignature) {
        _ = allocator;
        _ = self;
        _ = address;
        _ = before;
        _ = until;
        _ = limit;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getSignatureStatuses(self: *Self, allocator: std.mem.Allocator, signatures: [][]const u8, config: ?t.RpcSignatureStatusConfig) t.Result(t.RpcResponse([]?t.TransactionStatus)) {
        _ = allocator;
        _ = self;
        _ = signatures;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getSlot(self: *Self, allocator: std.mem.Allocator, config: t.RpcContextConfig) t.Result(t.Slot) {
        _ = allocator;
        _ = self;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getSlotLeader(self: *Self, allocator: std.mem.Allocator, config: t.RpcContextConfig) t.Result([]const u8) {
        _ = allocator;
        _ = self;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getSlotLeaders(self: *Self, allocator: std.mem.Allocator, commitment: ?t.CommitmentConfig, start_slot: t.Slot, limit: usize) t.Result([]t.Pubkey) {
        _ = allocator;
        _ = self;
        _ = commitment;
        _ = start_slot;
        _ = limit;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getSnapshotSlot(self: *Self, allocator: std.mem.Allocator) t.Result(t.Slot) {
        _ = allocator;

        _ = self;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getStakeActivation(self: *Self, allocator: std.mem.Allocator, pubkey: t.Pubkey, config: ?t.RpcEpochConfig) t.Result(t.RpcStakeActivation) {
        _ = allocator;
        _ = self;
        _ = pubkey;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getStakeMinimumDelegation(self: *Self, allocator: std.mem.Allocator, config: t.RpcContextConfig) t.Result(t.RpcResponse(u64)) {
        _ = allocator;
        _ = self;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getSupply(self: *Self, allocator: std.mem.Allocator, config: ?t.RpcSupplyConfig) t.Result(t.RpcResponse(t.RpcSupply)) {
        _ = allocator;
        _ = self;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getTokenAccountBalance(self: *Self, allocator: std.mem.Allocator, pubkey: t.Pubkey, commitment: ?t.CommitmentConfig) t.Result(t.RpcResponse(t.UiTokenAmount)) {
        _ = allocator;
        _ = self;
        _ = pubkey;
        _ = commitment;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getTokenAccountsByDelegate(self: *Self, allocator: std.mem.Allocator, delegate: t.Pubkey, token_account_filter: t.TokenAccountsFilter, config: ?t.RpcAccountInfoConfig) t.Result(t.RpcResponse([]t.RpcKeyedAccount)) {
        _ = allocator;
        _ = self;
        _ = delegate;
        _ = token_account_filter;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getTokenAccountsByOwner(self: *Self, allocator: std.mem.Allocator, owner: t.Pubkey, token_account_filter: t.TokenAccountsFilter, config: ?t.RpcAccountInfoConfig) t.Result(t.RpcResponse([]t.RpcKeyedAccount)) {
        _ = allocator;
        _ = self;
        _ = owner;
        _ = token_account_filter;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getTokenLargestAccounts(self: *Self, allocator: std.mem.Allocator, mint: t.Pubkey, commitment: ?t.CommitmentConfig) t.Result(t.RpcResponse([]t.RpcTokenAccountBalance)) {
        _ = allocator;
        _ = self;
        _ = mint;
        _ = commitment;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getTokenSupply(self: *Self, allocator: std.mem.Allocator, mint: t.Pubkey, commitment: t.CommitmentConfig) t.Result(t.RpcResponse(t.UiTokenAmount)) {
        _ = allocator;
        _ = self;
        _ = mint;
        _ = commitment;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getTotalSupply(self: *Self, allocator: std.mem.Allocator, commitment: ?t.CommitmentConfig) t.Result(u64) {
        _ = allocator;
        _ = self;
        _ = commitment;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getTransaction(self: *Self, allocator: std.mem.Allocator, signature: t.Signature, config: t.RpcEncodingConfigWrapper(t.RpcTransactionConfig)) t.Result(?t.EncodedConfirmedTransactionWithStatusMeta) {
        _ = allocator;
        _ = self;
        _ = signature;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getTransactionCount(self: *Self, allocator: std.mem.Allocator, config: t.RpcContextConfig) t.Result(u64) {
        _ = allocator;
        _ = self;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getVersion(self: *Self, allocator: std.mem.Allocator) t.Result(t.RpcVersionInfo) {
        _ = allocator;

        _ = self;

        return .{
            .Ok = t.RpcVersionInfo{
                .@"solana-core" = "",
                .@"feature-set" = 0,
            },
        };
    }

    pub fn getVoteAccounts(self: *Self, allocator: std.mem.Allocator, config: ?t.RpcGetVoteAccountsConfig) t.Result(t.RpcVoteAccountStatus) {
        _ = allocator;
        _ = self;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn isBlockhashValid(self: *Self, allocator: std.mem.Allocator, hash: t.Hash, config: t.RpcContextConfig) t.Result(t.RpcResponse(bool)) {
        _ = allocator;
        _ = self;
        _ = hash;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn minimumLedgerSlot(self: *Self, allocator: std.mem.Allocator) t.Result(t.Slot) {
        _ = allocator;

        _ = self;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn requestAirdrop(self: *Self, allocator: std.mem.Allocator, pubkey: t.Pubkey, lamports: u64, config: ?t.RpcRequestAirdropConfig) t.Result([]const u8) {
        _ = allocator;
        _ = self;
        _ = pubkey;
        _ = lamports;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn sendTransaction(self: *Self, allocator: std.mem.Allocator, data: []const u8, config: ?t.RpcSendTransactionConfig) t.Result([]const u8) {
        _ = allocator;
        _ = self;
        _ = data;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn simulateTransaction(self: *Self, allocator: std.mem.Allocator, data: []const u8, config: ?t.RpcSimulateTransactionConfig) t.Result(t.RpcResponse(t.RpcSimulateTransactionResult)) {
        _ = allocator;
        _ = self;
        _ = data;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }
};

// Statically dispatched, compile-time generics :)
comptime {
    const check: t.RpcServiceImpl(RpcRequestProcessor, t.Result) = .{
        .getAccountInfo = RpcRequestProcessor.getAccountInfo,
        .getBalance = RpcRequestProcessor.getBalance,
        .getBlock = RpcRequestProcessor.getBlock,
        .getBlockCommitment = RpcRequestProcessor.getBlockCommitment,
        .getBlockHeight = RpcRequestProcessor.getBlockHeight,
        .getBlockProduction = RpcRequestProcessor.getBlockProduction,
        .getBlocks = RpcRequestProcessor.getBlocks,
        .getBlocksWithLimit = RpcRequestProcessor.getBlocksWithLimit,
        .getBlockTime = RpcRequestProcessor.getBlockTime,
        .getClusterNodes = RpcRequestProcessor.getClusterNodes,
        .getConfirmedBlock = RpcRequestProcessor.getConfirmedBlock,
        .getConfirmedBlocks = RpcRequestProcessor.getConfirmedBlocks,
        .getConfirmedBlocksWithLimit = RpcRequestProcessor.getConfirmedBlocksWithLimit,
        .getConfirmedSignaturesForAddress2 = RpcRequestProcessor.getConfirmedSignaturesForAddress2,
        .getConfirmedTransaction = RpcRequestProcessor.getConfirmedTransaction,
        .getEpochInfo = RpcRequestProcessor.getEpochInfo,
        .getEpochSchedule = RpcRequestProcessor.getEpochSchedule,
        .getFeeCalculatorForBlockhash = RpcRequestProcessor.getFeeCalculatorForBlockhash,
        .getFeeForMessage = RpcRequestProcessor.getFeeForMessage,
        .getFeeRateGovernor = RpcRequestProcessor.getFeeRateGovernor,
        .getFees = RpcRequestProcessor.getFees,
        .getFirstAvailableBlock = RpcRequestProcessor.getFirstAvailableBlock,
        .getGenesisHash = RpcRequestProcessor.getGenesisHash,
        .getHealth = RpcRequestProcessor.getHealth,
        .getHighestSnapshotSlot = RpcRequestProcessor.getHighestSnapshotSlot,
        .getIdentity = RpcRequestProcessor.getIdentity,
        .getInflationGovernor = RpcRequestProcessor.getInflationGovernor,
        .getInflationRate = RpcRequestProcessor.getInflationRate,
        .getInflationReward = RpcRequestProcessor.getInflationReward,
        .getLargestAccounts = RpcRequestProcessor.getLargestAccounts,
        .getLatestBlockhash = RpcRequestProcessor.getLatestBlockhash,
        .getLeaderSchedule = RpcRequestProcessor.getLeaderSchedule,
        .getMaxRetransmitSlot = RpcRequestProcessor.getMaxRetransmitSlot,
        .getMaxShredInsertSlot = RpcRequestProcessor.getMaxShredInsertSlot,
        .getMinimumBalanceForRentExemption = RpcRequestProcessor.getMinimumBalanceForRentExemption,
        .getMultipleAccounts = RpcRequestProcessor.getMultipleAccounts,
        .getProgramAccounts = RpcRequestProcessor.getProgramAccounts,
        .getRecentBlockhash = RpcRequestProcessor.getRecentBlockhash,
        .getRecentPerformanceSamples = RpcRequestProcessor.getRecentPerformanceSamples,
        .getRecentPrioritizationFees = RpcRequestProcessor.getRecentPrioritizationFees,
        .getSignaturesForAddress = RpcRequestProcessor.getSignaturesForAddress,
        .getSignatureStatuses = RpcRequestProcessor.getSignatureStatuses,
        .getSlot = RpcRequestProcessor.getSlot,
        .getSlotLeader = RpcRequestProcessor.getSlotLeader,
        .getSlotLeaders = RpcRequestProcessor.getSlotLeaders,
        .getSnapshotSlot = RpcRequestProcessor.getSnapshotSlot,
        .getStakeActivation = RpcRequestProcessor.getStakeActivation,
        .getStakeMinimumDelegation = RpcRequestProcessor.getStakeMinimumDelegation,
        .getSupply = RpcRequestProcessor.getSupply,
        .getTokenAccountBalance = RpcRequestProcessor.getTokenAccountBalance,
        .getTokenAccountsByDelegate = RpcRequestProcessor.getTokenAccountsByDelegate,
        .getTokenAccountsByOwner = RpcRequestProcessor.getTokenAccountsByOwner,
        .getTokenLargestAccounts = RpcRequestProcessor.getTokenLargestAccounts,
        .getTokenSupply = RpcRequestProcessor.getTokenSupply,
        .getTotalSupply = RpcRequestProcessor.getTotalSupply,
        .getTransaction = RpcRequestProcessor.getTransaction,
        .getTransactionCount = RpcRequestProcessor.getTransactionCount,
        .getVersion = RpcRequestProcessor.getVersion,
        .getVoteAccounts = RpcRequestProcessor.getVoteAccounts,
        .isBlockhashValid = RpcRequestProcessor.isBlockhashValid,
        .minimumLedgerSlot = RpcRequestProcessor.minimumLedgerSlot,
        .requestAirdrop = RpcRequestProcessor.requestAirdrop,
        .sendTransaction = RpcRequestProcessor.sendTransaction,
        .simulateTransaction = RpcRequestProcessor.simulateTransaction,
    };
    _ = check;
}
