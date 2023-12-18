const std = @import("std");
const t = @import("types.zig");
const GossipService = @import("../gossip/gossip_service.zig").GossipService;
const CrdsTable = @import("../gossip/crds_table.zig").CrdsTable;

pub const RpcServiceProcessor = struct {
    gossip_service: *GossipService,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, gossip_service: *GossipService) Self {
        return Self{
            .gossip_service = gossip_service,
            .allocator = allocator,
        };
    }

    pub fn getAccountInfo(self: *Self, pubkey: t.Pubkey, config: ?t.RpcAccountInfoConfig) t.Result(t.RpcResponse(?t.UiAccount)) {
        _ = self;
        _ = pubkey;
        _ = config;
        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getBalance(self: *Self, pubkey: t.Pubkey, config: t.RpcContextConfig) t.Result(t.RpcResponse(u64)) {
        _ = self;
        _ = pubkey;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getBlock(self: *Self, slot: t.Slot, config: ?t.RpcBlockConfig) t.Result(t.UiConfirmedBlock) {
        _ = self;
        _ = slot;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getBlockCommitment(self: *Self, block: t.Slot) t.Result(t.RpcBlockCommitment) {
        _ = self;
        _ = block;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getBlockHeight(self: *Self, config: t.RpcContextConfig) t.Result(u64) {
        _ = self;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getBlockProduction(self: *Self, config: ?t.RpcBlockProductionConfig) t.Result(t.RpcResponse(t.RpcBlockProduction)) {
        _ = self;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getBlocks(self: *Self, start_slot: t.Slot, end_slot: t.Slot, commitment: ?t.CommitmentConfig) t.Result([]t.Slot) {
        _ = self;
        _ = start_slot;
        _ = end_slot;
        _ = commitment;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getBlocksWithLimit(self: *Self, start_slot: t.Slot, limit: usize, commitment: ?t.CommitmentConfig) t.Result([]t.Slot) {
        _ = self;
        _ = start_slot;
        _ = limit;
        _ = commitment;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getBlockTime(self: *Self, slot: t.Slot) t.Result(?t.UnixTimestamp) {
        _ = self;
        _ = slot;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getClusterNodes(self: *Self) t.Result([]t.RpcContactInfo) {
        var crds_table_rlock = self.gossip_service.crds_table_rw.read();
        defer crds_table_rlock.unlock();
        var crds_table: *const CrdsTable = crds_table_rlock.get();

        var contact_infos = crds_table.getAllContactInfos() catch return .{ .Err = t.Error.Internal };
        var rpc_contact_infos = std.ArrayList(t.RpcContactInfo).initCapacity(self.allocator, contact_infos.items.len) catch return .{ .Err = t.Error.Internal };

        for (contact_infos.items) |contact_info| {
            rpc_contact_infos.appendAssumeCapacity(t.RpcContactInfo{
                .feature_set = null,
                .gossip = contact_info.gossip,
                .pubkey = contact_info.id,
                .pubsub = contact_info.rpc_pubsub,
                .rpc = contact_info.rpc,
                .shred_version = contact_info.shred_version,
                .tpu = contact_info.tpu,
                .tpu_quic = contact_info.tpu_forwards, // TODO: correct value
                .version = null, // TODO: populate
            });
        }
        return .{ .Ok = rpc_contact_infos.items };
    }

    pub fn getConfirmedBlock(self: *Self, slot: t.Slot, config: t.RpcEncodingConfigWrapper(t.RpcConfirmedBlockConfig)) t.Result(?t.UiConfirmedBlock) {
        _ = self;
        _ = slot;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getConfirmedBlocks(self: *Self, start_slot: t.Slot, config: ?t.RpcConfirmedBlocksConfigWrapper, commitment: ?t.CommitmentConfig) t.Result([]t.Slot) {
        _ = self;
        _ = start_slot;
        _ = config;
        _ = commitment;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getConfirmedBlocksWithLimit(self: *Self, start_slot: t.Slot, limit: usize, commitment: ?t.CommitmentConfig) t.Result([]t.Slot) {
        _ = self;
        _ = start_slot;
        _ = limit;
        _ = commitment;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getConfirmedSignaturesForAddress2(self: *Self, address: []const u8, config: ?t.RpcGetConfirmedSignaturesForAddress2Config) t.Result([]t.RpcConfirmedTransactionStatusWithSignature) {
        _ = self;
        _ = address;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getConfirmedTransaction(self: *Self, signature: []const u8, config: ?t.RpcEncodingConfigWrapper(t.RpcConfirmedTransactionConfig)) t.Result(?t.EncodedConfirmedTransactionWithStatusMeta) {
        _ = self;
        _ = signature;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getEpochInfo(self: *Self, config: ?t.RpcContextConfig) t.Result(t.EpochInfo) {
        _ = self;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getEpochSchedule(self: *Self) t.Result(t.EpochSchedule) {
        _ = self;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getFeeCalculatorForBlockhash(self: *Self, blockhash: t.Hash, commitment: ?t.CommitmentConfig) t.Result(t.RpcResponse(?t.RpcFeeCalculator)) {
        _ = self;
        _ = blockhash;
        _ = commitment;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getFeeForMessage(self: *Self, data: []const u8, config: ?t.RpcContextConfig) t.Result(t.RpcResponse(?u64)) {
        _ = self;
        _ = data;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getFeeRateGovernor(self: *Self) t.Result(t.RpcResponse(t.RpcFeeRateGovernor)) {
        _ = self;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getFees(self: *Self, commitment: ?t.CommitmentConfig) t.Result(t.RpcResponse(t.RpcFees)) {
        _ = self;
        _ = commitment;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getFirstAvailableBlock(self: *Self) t.Result(u64) {
        _ = self;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getGenesisHash(self: *Self) t.Result([]const u8) {
        _ = self;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getHealth(self: *Self) t.Result([]const u8) {
        _ = self;

        return .{ .Ok = "ok" };
    }

    pub fn getHighestSnapshotSlot(self: *Self) t.Result(t.RpcSnapshotSlotInfo) {
        _ = self;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getIdentity(self: *Self) t.Result(t.RpcIdentity) {
        var identity: []const u8 = self.gossip_service.my_pubkey.toString(self.allocator) catch @panic("could not toString a Pubkey");
        return .{
            .Ok = t.RpcIdentity{
                .identity = identity,
            },
        };
    }

    pub fn getInflationGovernor(self: *Self, commitment: ?t.CommitmentConfig) t.Result(t.RpcInflationGovernor) {
        _ = self;
        _ = commitment;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getInflationRate(self: *Self) t.Result(t.RpcInflationRate) {
        _ = self;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getInflationReward(self: *Self, addresses: []t.Pubkey, config: ?t.RpcEpochConfig) t.Result([]?t.RpcInflationReward) {
        _ = self;
        _ = addresses;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getLargestAccounts(self: *Self, config: ?t.RpcLargestAccountsConfig) t.Result(t.RpcResponse([]t.RpcAccountBalance)) {
        _ = self;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getLatestBlockhash(self: *Self, config: ?t.RpcContextConfig) t.Result(t.RpcResponse(t.RpcBlockhash)) {
        _ = self;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getLeaderSchedule(self: *Self, options: ?t.RpcLeaderScheduleConfigWrapper, config: ?t.RpcLeaderScheduleConfig) t.Result(?t.RpcLeaderSchedule) {
        _ = self;
        _ = options;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getMaxRetransmitSlot(self: *Self) t.Result(t.Slot) {
        _ = self;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getMaxShredInsertSlot(self: *Self) t.Result(t.Slot) {
        _ = self;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getMinimumBalanceForRentExemption(self: *Self, data_len: usize, commitment_config: ?t.CommitmentConfig) t.Result(u64) {
        _ = self;
        _ = data_len;
        _ = commitment_config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getMultipleAccounts(self: *Self, publeys: []t.Pubkey, config: ?t.RpcAccountInfoConfig) t.Result(t.RpcResponse([]?t.UiAccount)) {
        _ = self;
        _ = publeys;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getProgramAccounts(self: *Self, program_id: t.Pubkey, config: ?t.RpcAccountInfoConfig, filters: []t.AccountFilter, with_context: bool) t.Result(t.OptionalContext([]t.RpcKeyedAccount)) {
        _ = self;
        _ = program_id;
        _ = config;
        _ = filters;
        _ = with_context;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getRecentBlockhash(self: *Self, commitment: ?t.CommitmentConfig) t.Result(t.RpcResponse(t.RpcBlockhashFeeCalculator)) {
        _ = self;
        _ = commitment;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getRecentPerformanceSamples(self: *Self, limit: ?usize) t.Result([]t.RpcPerfSample) {
        _ = self;
        _ = limit;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getRecentPrioritizationFees(self: *Self, pubkeys: []t.Pubkey) t.Result([]t.RpcPrioritizationFee) {
        _ = self;
        _ = pubkeys;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getSignaturesForAddress(self: *Self, address: t.Pubkey, before: ?t.Signature, until: ?t.Signature, limit: usize, config: t.RpcContextConfig) t.Result([]t.RpcConfirmedTransactionStatusWithSignature) {
        _ = self;
        _ = address;
        _ = before;
        _ = until;
        _ = limit;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getSignatureStatuses(self: *Self, signatures: [][]const u8, config: ?t.RpcSignatureStatusConfig) t.Result(t.RpcResponse([]?t.TransactionStatus)) {
        _ = self;
        _ = signatures;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getSlot(self: *Self, config: t.RpcContextConfig) t.Result(t.Slot) {
        _ = self;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getSlotLeader(self: *Self, config: t.RpcContextConfig) t.Result([]const u8) {
        _ = self;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getSlotLeaders(self: *Self, commitment: ?t.CommitmentConfig, start_slot: t.Slot, limit: usize) t.Result([]t.Pubkey) {
        _ = self;
        _ = commitment;
        _ = start_slot;
        _ = limit;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getSnapshotSlot(self: *Self) t.Result(t.Slot) {
        _ = self;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getStakeActivation(self: *Self, pubkey: t.Pubkey, config: ?t.RpcEpochConfig) t.Result(t.RpcStakeActivation) {
        _ = self;
        _ = pubkey;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getStakeMinimumDelegation(self: *Self, config: t.RpcContextConfig) t.Result(t.RpcResponse(u64)) {
        _ = self;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getSupply(self: *Self, config: ?t.RpcSupplyConfig) t.Result(t.RpcResponse(t.RpcSupply)) {
        _ = self;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getTokenAccountBalance(self: *Self, pubkey: t.Pubkey, commitment: ?t.CommitmentConfig) t.Result(t.RpcResponse(t.UiTokenAmount)) {
        _ = self;
        _ = pubkey;
        _ = commitment;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getTokenAccountsByDelegate(self: *Self, delegate: t.Pubkey, token_account_filter: t.TokenAccountsFilter, config: ?t.RpcAccountInfoConfig) t.Result(t.RpcResponse([]t.RpcKeyedAccount)) {
        _ = self;
        _ = delegate;
        _ = token_account_filter;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getTokenAccountsByOwner(self: *Self, owner: t.Pubkey, token_account_filter: t.TokenAccountsFilter, config: ?t.RpcAccountInfoConfig) t.Result(t.RpcResponse([]t.RpcKeyedAccount)) {
        _ = self;
        _ = owner;
        _ = token_account_filter;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getTokenLargestAccounts(self: *Self, mint: t.Pubkey, commitment: ?t.CommitmentConfig) t.Result(t.RpcResponse([]t.RpcTokenAccountBalance)) {
        _ = self;
        _ = mint;
        _ = commitment;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getTokenSupply(self: *Self, mint: t.Pubkey, commitment: t.CommitmentConfig) t.Result(t.RpcResponse(t.UiTokenAmount)) {
        _ = self;
        _ = mint;
        _ = commitment;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getTotalSupply(self: *Self, commitment: ?t.CommitmentConfig) t.Result(u64) {
        _ = self;
        _ = commitment;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getTransaction(self: *Self, signature: t.Signature, config: t.RpcEncodingConfigWrapper(t.RpcTransactionConfig)) t.Result(?t.EncodedConfirmedTransactionWithStatusMeta) {
        _ = self;
        _ = signature;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getTransactionCount(self: *Self, config: t.RpcContextConfig) t.Result(u64) {
        _ = self;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getVersion(self: *Self) t.Result(t.RpcVersionInfo) {
        _ = self;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn getVoteAccounts(self: *Self, config: ?t.RpcGetVoteAccountsConfig) t.Result(t.RpcVoteAccountStatus) {
        _ = self;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn isBlockhashValid(self: *Self, hash: t.Hash, config: t.RpcContextConfig) t.Result(t.RpcResponse(bool)) {
        _ = self;
        _ = hash;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn minimumLedgerSlot(self: *Self) t.Result(t.Slot) {
        _ = self;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn requestAirdrop(self: *Self, pubkey: t.Pubkey, lamports: u64, config: ?t.RpcRequestAirdropConfig) t.Result([]const u8) {
        _ = self;
        _ = pubkey;
        _ = lamports;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn sendTransaction(self: *Self, data: []const u8, config: ?t.RpcSendTransactionConfig) t.Result([]const u8) {
        _ = self;
        _ = data;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }

    pub fn simulateTransaction(self: *Self, data: []const u8, config: ?t.RpcSimulateTransactionConfig) t.Result(t.RpcResponse(t.RpcSimulateTransactionResult)) {
        _ = self;
        _ = data;
        _ = config;

        return .{ .Err = t.Error.Unimplemented };
    }
};

// Statically dispatched, compile-time generics :)
comptime {
    const check: t.RpcServiceImpl(RpcServiceProcessor) = .{
        .getAccountInfo = RpcServiceProcessor.getAccountInfo,
        .getBalance = RpcServiceProcessor.getBalance,
        .getBlock = RpcServiceProcessor.getBlock,
        .getBlockCommitment = RpcServiceProcessor.getBlockCommitment,
        .getBlockHeight = RpcServiceProcessor.getBlockHeight,
        .getBlockProduction = RpcServiceProcessor.getBlockProduction,
        .getBlocks = RpcServiceProcessor.getBlocks,
        .getBlocksWithLimit = RpcServiceProcessor.getBlocksWithLimit,
        .getBlockTime = RpcServiceProcessor.getBlockTime,
        .getClusterNodes = RpcServiceProcessor.getClusterNodes,
        .getConfirmedBlock = RpcServiceProcessor.getConfirmedBlock,
        .getConfirmedBlocks = RpcServiceProcessor.getConfirmedBlocks,
        .getConfirmedBlocksWithLimit = RpcServiceProcessor.getConfirmedBlocksWithLimit,
        .getConfirmedSignaturesForAddress2 = RpcServiceProcessor.getConfirmedSignaturesForAddress2,
        .getConfirmedTransaction = RpcServiceProcessor.getConfirmedTransaction,
        .getEpochInfo = RpcServiceProcessor.getEpochInfo,
        .getEpochSchedule = RpcServiceProcessor.getEpochSchedule,
        .getFeeCalculatorForBlockhash = RpcServiceProcessor.getFeeCalculatorForBlockhash,
        .getFeeForMessage = RpcServiceProcessor.getFeeForMessage,
        .getFeeRateGovernor = RpcServiceProcessor.getFeeRateGovernor,
        .getFees = RpcServiceProcessor.getFees,
        .getFirstAvailableBlock = RpcServiceProcessor.getFirstAvailableBlock,
        .getGenesisHash = RpcServiceProcessor.getGenesisHash,
        .getHealth = RpcServiceProcessor.getHealth,
        .getHighestSnapshotSlot = RpcServiceProcessor.getHighestSnapshotSlot,
        .getIdentity = RpcServiceProcessor.getIdentity,
        .getInflationGovernor = RpcServiceProcessor.getInflationGovernor,
        .getInflationRate = RpcServiceProcessor.getInflationRate,
        .getInflationReward = RpcServiceProcessor.getInflationReward,
        .getLargestAccounts = RpcServiceProcessor.getLargestAccounts,
        .getLatestBlockhash = RpcServiceProcessor.getLatestBlockhash,
        .getLeaderSchedule = RpcServiceProcessor.getLeaderSchedule,
        .getMaxRetransmitSlot = RpcServiceProcessor.getMaxRetransmitSlot,
        .getMaxShredInsertSlot = RpcServiceProcessor.getMaxShredInsertSlot,
        .getMinimumBalanceForRentExemption = RpcServiceProcessor.getMinimumBalanceForRentExemption,
        .getMultipleAccounts = RpcServiceProcessor.getMultipleAccounts,
        .getProgramAccounts = RpcServiceProcessor.getProgramAccounts,
        .getRecentBlockhash = RpcServiceProcessor.getRecentBlockhash,
        .getRecentPerformanceSamples = RpcServiceProcessor.getRecentPerformanceSamples,
        .getRecentPrioritizationFees = RpcServiceProcessor.getRecentPrioritizationFees,
        .getSignaturesForAddress = RpcServiceProcessor.getSignaturesForAddress,
        .getSignatureStatuses = RpcServiceProcessor.getSignatureStatuses,
        .getSlot = RpcServiceProcessor.getSlot,
        .getSlotLeader = RpcServiceProcessor.getSlotLeader,
        .getSlotLeaders = RpcServiceProcessor.getSlotLeaders,
        .getSnapshotSlot = RpcServiceProcessor.getSnapshotSlot,
        .getStakeActivation = RpcServiceProcessor.getStakeActivation,
        .getStakeMinimumDelegation = RpcServiceProcessor.getStakeMinimumDelegation,
        .getSupply = RpcServiceProcessor.getSupply,
        .getTokenAccountBalance = RpcServiceProcessor.getTokenAccountBalance,
        .getTokenAccountsByDelegate = RpcServiceProcessor.getTokenAccountsByDelegate,
        .getTokenAccountsByOwner = RpcServiceProcessor.getTokenAccountsByOwner,
        .getTokenLargestAccounts = RpcServiceProcessor.getTokenLargestAccounts,
        .getTokenSupply = RpcServiceProcessor.getTokenSupply,
        .getTotalSupply = RpcServiceProcessor.getTotalSupply,
        .getTransaction = RpcServiceProcessor.getTransaction,
        .getTransactionCount = RpcServiceProcessor.getTransactionCount,
        .getVersion = RpcServiceProcessor.getVersion,
        .getVoteAccounts = RpcServiceProcessor.getVoteAccounts,
        .isBlockhashValid = RpcServiceProcessor.isBlockhashValid,
        .minimumLedgerSlot = RpcServiceProcessor.minimumLedgerSlot,
        .requestAirdrop = RpcServiceProcessor.requestAirdrop,
        .sendTransaction = RpcServiceProcessor.sendTransaction,
        .simulateTransaction = RpcServiceProcessor.simulateTransaction,
    };
    _ = check;
}
