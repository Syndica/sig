const std = @import("std");
const t = @import("types.zig");
const http = std.http;
const testing = std.testing;
const Parsed = std.json.Parsed;

const RpcClientError = error{
    JsonParseError,
    RequestReadError,
};

pub const RpcClient = struct {
    allocator: std.mem.Allocator,
    client: http.Client,
    uri: std.Uri,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, uri: std.Uri) Self {
        return Self{
            .allocator = allocator,
            .client = http.Client{
                .allocator = allocator,
            },
            .uri = uri,
        };
    }

    pub fn deinit(self: *Self) void {
        self.client.deinit();
    }

    fn call(self: *Self, allocator: std.mem.Allocator, comptime method: []const u8, args: anytype) ClientResult(ExtractResultOkParsedType(method)) {
        var headers = http.Headers.init(allocator);
        headers.append("Content-Type", "application/json; charset=utf-8") catch unreachable;
        headers.append("User-Agent", "sig/0.1") catch unreachable;
        defer headers.deinit();

        var req = self.client.request(http.Method.POST, self.uri, headers, .{}) catch unreachable;
        req.transfer_encoding = .chunked;
        defer req.deinit();
        req.start() catch |err| {
            return .{ .ClientError = .{ .StartError = @errorName(err) } };
        };

        const JsonRpcRequest = t.TypedJsonRpcRequest(@TypeOf(args));

        var out = std.json.stringifyAlloc(allocator, JsonRpcRequest{
            .jsonrpc = "2.0",
            .id = .{ .number = 1 },
            .method = method,
            .params = args,
        }, .{ .emit_null_optional_fields = false }) catch {
            return .{ .ClientError = .OutOfMemory };
        };

        defer allocator.free(out);

        req.writer().writeAll(out) catch {
            return .{ .ClientError = .WriteError };
        };
        req.finish() catch |err| {
            return .{ .ClientError = .{ .FinishError = @errorName(err) } };
        };
        req.wait() catch |err| {
            return .{ .ClientError = .{ .WaitError = @errorName(err) } };
        };

        if (req.response.status != http.Status.ok) {
            return .{ .ClientError = .{ .StatusError = req.response.status } };
        }

        const body = req.reader().readAllAlloc(allocator, 819200) catch |err| {
            return .{ .ClientError = .{ .ReaderError = @errorName(err) } };
        };
        defer allocator.free(body);

        // For now, because we do special deserialization into t.JsonRpcSuccessOrFailureResponse
        // we create arena manually and then set it in Parsed(...) types.
        var arena = allocator.create(std.heap.ArenaAllocator) catch {
            return .{ .ClientError = .OutOfMemory };
        };
        arena.* = std.heap.ArenaAllocator.init(allocator);
        var arena_allocator = arena.allocator();

        var resp = std.json.parseFromSliceLeaky(
            ClientResult(ExtractResultOkParsedType(method)),
            arena_allocator,
            body,
            .{},
        ) catch |err| {
            arena.deinit();
            allocator.destroy(arena);
            return .{ .ClientError = .{ .JsonParseError = @errorName(err) } };
        };

        // Set appropriate arena if Success or RpcError
        if (resp == .Success) {
            resp.Success.arena = arena;
        } else if (resp == .RpcError) {
            resp.RpcError.arena = arena;
        }

        return resp;
    }

    pub fn getAccountInfo(self: *Self, allocator: std.mem.Allocator, pubkey: t.Pubkey, config: ?t.RpcAccountInfoConfig) ClientResult(t.RpcResponse(?t.UiAccount)) {
        return self.call(allocator, "getAccountInfo", .{ pubkey, config });
    }

    pub fn getBalance(self: *Self, allocator: std.mem.Allocator, pubkey: t.Pubkey, config: t.RpcContextConfig) ClientResult(t.RpcResponse(u64)) {
        return self.call(allocator, "getBalance", .{ pubkey, config });
    }

    pub fn getBlock(self: *Self, allocator: std.mem.Allocator, slot: t.Slot, config: ?t.RpcBlockConfig) ClientResult(t.UiConfirmedBlock) {
        return self.call(allocator, "getBlock", .{ slot, config });
    }

    pub fn getBlockCommitment(self: *Self, allocator: std.mem.Allocator, block: t.Slot) ClientResult(t.RpcBlockCommitment) {
        return self.call(allocator, "getBlockCommitment", .{block});
    }

    pub fn getBlockHeight(self: *Self, allocator: std.mem.Allocator, config: t.RpcContextConfig) ClientResult(u64) {
        return self.call(allocator, "getBlockHeight", .{config});
    }

    pub fn getBlockProduction(self: *Self, allocator: std.mem.Allocator, config: ?t.RpcBlockProductionConfig) ClientResult(t.RpcResponse(t.RpcBlockProduction)) {
        return self.call(allocator, "getBlockProduction", .{config});
    }

    pub fn getBlocks(self: *Self, allocator: std.mem.Allocator, start_slot: t.Slot, end_slot: t.Slot, commitment: ?t.CommitmentConfig) ClientResult([]t.Slot) {
        return self.call(allocator, "getBlocks", .{ start_slot, end_slot, commitment });
    }

    pub fn getBlocksWithLimit(self: *Self, allocator: std.mem.Allocator, start_slot: t.Slot, limit: usize, commitment: ?t.CommitmentConfig) ClientResult([]t.Slot) {
        return self.call(allocator, "getBlocksWithLimit", .{ start_slot, limit, commitment });
    }

    pub fn getBlockTime(self: *Self, allocator: std.mem.Allocator, slot: t.Slot) ClientResult(?t.UnixTimestamp) {
        return self.call(allocator, "getBlockTime", .{slot});
    }

    pub fn getClusterNodes(
        self: *Self,
        allocator: std.mem.Allocator,
    ) ClientResult([]t.RpcContactInfo) {
        return self.call(allocator, "getClusterNodes", .{});
    }

    pub fn getConfirmedBlock(self: *Self, allocator: std.mem.Allocator, slot: t.Slot, config: t.RpcEncodingConfigWrapper(t.RpcConfirmedBlockConfig)) ClientResult(?t.UiConfirmedBlock) {
        return self.call(allocator, "getConfirmedBlock", .{ slot, config });
    }

    pub fn getConfirmedBlocks(self: *Self, allocator: std.mem.Allocator, start_slot: t.Slot, config: ?t.RpcConfirmedBlocksConfigWrapper, commitment: ?t.CommitmentConfig) ClientResult([]t.Slot) {
        return self.call(allocator, "getConfirmedBlocks", .{ start_slot, config, commitment });
    }

    pub fn getConfirmedBlocksWithLimit(self: *Self, allocator: std.mem.Allocator, start_slot: t.Slot, limit: usize, commitment: ?t.CommitmentConfig) ClientResult([]t.Slot) {
        return self.call(allocator, "getConfirmedBlocksWithLimit", .{ start_slot, limit, commitment });
    }

    pub fn getConfirmedSignaturesForAddress2(self: *Self, allocator: std.mem.Allocator, address: []const u8, config: ?t.RpcGetConfirmedSignaturesForAddress2Config) ClientResult([]t.RpcConfirmedTransactionStatusWithSignature) {
        return self.call(allocator, "getConfirmedSignaturesForAddress2", .{ address, config });
    }

    pub fn getConfirmedTransaction(self: *Self, allocator: std.mem.Allocator, signature: []const u8, config: ?t.RpcEncodingConfigWrapper(t.RpcConfirmedTransactionConfig)) ClientResult(?t.EncodedConfirmedTransactionWithStatusMeta) {
        return self.call(allocator, "getConfirmedTransaction", .{ signature, config });
    }

    pub fn getEpochInfo(self: *Self, allocator: std.mem.Allocator, config: ?t.RpcContextConfig) ClientResult(t.EpochInfo) {
        return self.call(allocator, "getEpochInfo", .{config});
    }

    pub fn getEpochSchedule(self: *Self, allocator: std.mem.Allocator) ClientResult(t.EpochSchedule) {
        return self.call(allocator, "getEpochSchedule", .{});
    }

    pub fn getFeeCalculatorForBlockhash(self: *Self, allocator: std.mem.Allocator, blockhash: t.Hash, commitment: ?t.CommitmentConfig) ClientResult(t.RpcResponse(?t.RpcFeeCalculator)) {
        return self.call(allocator, "getFeeCalculatorForBlockhash", .{ blockhash, commitment });
    }

    pub fn getFeeForMessage(self: *Self, allocator: std.mem.Allocator, data: []const u8, config: ?t.RpcContextConfig) ClientResult(t.RpcResponse(?u64)) {
        return self.call(allocator, "getFeeForMessage", .{ data, config });
    }

    pub fn getFeeRateGovernor(self: *Self, allocator: std.mem.Allocator) ClientResult(t.RpcResponse(t.RpcFeeRateGovernor)) {
        return self.call(allocator, "getFeeRateGovernor", .{});
    }

    pub fn getFees(self: *Self, allocator: std.mem.Allocator, commitment: ?t.CommitmentConfig) ClientResult(t.RpcResponse(t.RpcFees)) {
        return self.call(allocator, "getFees", .{commitment});
    }

    pub fn getFirstAvailableBlock(self: *Self, allocator: std.mem.Allocator) ClientResult(u64) {
        return self.call(allocator, "getFirstAvailableBlock", .{});
    }

    pub fn getGenesisHash(self: *Self, allocator: std.mem.Allocator) ClientResult([]const u8) {
        return self.call(allocator, "getGenesisHash", .{});
    }

    pub fn getHealth(self: *Self, allocator: std.mem.Allocator) ClientResult([]const u8) {
        return self.call(allocator, "getHealth", .{});
    }

    pub fn getHighestSnapshotSlot(self: *Self, allocator: std.mem.Allocator) ClientResult(t.RpcSnapshotSlotInfo) {
        return self.call(allocator, "getHighestSnapshotSlot", .{});
    }

    pub fn getIdentity(self: *Self, allocator: std.mem.Allocator) ClientResult(t.RpcIdentity) {
        return self.call(allocator, "getIdentity", .{});
    }

    pub fn getInflationGovernor(self: *Self, allocator: std.mem.Allocator, commitment: ?t.CommitmentConfig) ClientResult(t.RpcInflationGovernor) {
        return self.call(allocator, "getInflationGovernor", .{commitment});
    }

    pub fn getInflationRate(self: *Self, allocator: std.mem.Allocator) ClientResult(t.RpcInflationRate) {
        return self.call(allocator, "getInflationRate", .{});
    }

    pub fn getInflationReward(self: *Self, allocator: std.mem.Allocator, addresses: []t.Pubkey, config: ?t.RpcEpochConfig) ClientResult([]?t.RpcInflationReward) {
        return self.call(allocator, "getInflationReward", .{ addresses, config });
    }

    pub fn getLargestAccounts(self: *Self, allocator: std.mem.Allocator, config: ?t.RpcLargestAccountsConfig) ClientResult(t.RpcResponse([]t.RpcAccountBalance)) {
        return self.call(allocator, "getLargestAccounts", .{config});
    }

    pub fn getLatestBlockhash(self: *Self, allocator: std.mem.Allocator, config: ?t.RpcContextConfig) ClientResult(t.RpcResponse(t.RpcBlockhash)) {
        return self.call(allocator, "getLatestBlockhash", .{config});
    }

    pub fn getLeaderSchedule(self: *Self, allocator: std.mem.Allocator, options: ?t.RpcLeaderScheduleConfigWrapper, config: ?t.RpcLeaderScheduleConfig) ClientResult(?t.RpcLeaderSchedule) {
        return self.call(allocator, "getLeaderSchedule", .{ options, config });
    }

    pub fn getMaxRetransmitSlot(self: *Self, allocator: std.mem.Allocator) ClientResult(t.Slot) {
        return self.call(allocator, "getMaxRetransmitSlot", .{});
    }

    pub fn getMaxShredInsertSlot(self: *Self, allocator: std.mem.Allocator) ClientResult(t.Slot) {
        return self.call(allocator, "getMaxShredInsertSlot", .{});
    }

    pub fn getMinimumBalanceForRentExemption(self: *Self, allocator: std.mem.Allocator, data_len: usize, commitment_config: ?t.CommitmentConfig) ClientResult(u64) {
        return self.call(allocator, "getMinimumBalanceForRentExemption", .{ data_len, commitment_config });
    }

    pub fn getMultipleAccounts(self: *Self, allocator: std.mem.Allocator, publeys: []t.Pubkey, config: ?t.RpcAccountInfoConfig) ClientResult(t.RpcResponse([]?t.UiAccount)) {
        return self.call(allocator, "getMultipleAccounts", .{ publeys, config });
    }

    pub fn getProgramAccounts(self: *Self, allocator: std.mem.Allocator, program_id: t.Pubkey, config: ?t.RpcAccountInfoConfig, filters: []t.AccountFilter, with_context: bool) ClientResult(t.OptionalContext([]t.RpcKeyedAccount)) {
        return self.call(allocator, "getProgramAccounts", .{ program_id, config, filters, with_context });
    }

    pub fn getRecentBlockhash(self: *Self, allocator: std.mem.Allocator, commitment: ?t.CommitmentConfig) ClientResult(t.RpcResponse(t.RpcBlockhashFeeCalculator)) {
        return self.call(allocator, "getRecentBlockhash", .{commitment});
    }

    pub fn getRecentPerformanceSamples(self: *Self, allocator: std.mem.Allocator, limit: ?usize) ClientResult([]t.RpcPerfSample) {
        return self.call(allocator, "getRecentPerformanceSamples", .{limit});
    }

    pub fn getRecentPrioritizationFees(self: *Self, allocator: std.mem.Allocator, pubkeys: []t.Pubkey) ClientResult([]t.RpcPrioritizationFee) {
        return self.call(allocator, "getRecentPrioritizationFees", .{pubkeys});
    }

    pub fn getSignaturesForAddress(self: *Self, allocator: std.mem.Allocator, address: t.Pubkey, before: ?t.Signature, until: ?t.Signature, limit: usize, config: t.RpcContextConfig) ClientResult([]t.RpcConfirmedTransactionStatusWithSignature) {
        return self.call(allocator, "getSignaturesForAddress", .{ address, before, until, limit, config });
    }

    pub fn getSignatureStatuses(self: *Self, allocator: std.mem.Allocator, signatures: [][]const u8, config: ?t.RpcSignatureStatusConfig) ClientResult(t.RpcResponse([]?t.TransactionStatus)) {
        return self.call(allocator, "getSignatureStatuses", .{ signatures, config });
    }

    pub fn getSlot(self: *Self, allocator: std.mem.Allocator, config: t.RpcContextConfig) ClientResult(t.Slot) {
        return self.call(allocator, "getSlot", .{config});
    }

    pub fn getSlotLeader(self: *Self, allocator: std.mem.Allocator, config: t.RpcContextConfig) ClientResult([]const u8) {
        return self.call(allocator, "getSlotLeader", .{config});
    }

    pub fn getSlotLeaders(self: *Self, allocator: std.mem.Allocator, commitment: ?t.CommitmentConfig, start_slot: t.Slot, limit: usize) ClientResult([]t.Pubkey) {
        return self.call(allocator, "getSlotLeaders", .{ commitment, start_slot, limit });
    }

    pub fn getSnapshotSlot(self: *Self, allocator: std.mem.Allocator) ClientResult(t.Slot) {
        return self.call(allocator, "getSnapshotSlot", .{});
    }

    pub fn getStakeActivation(self: *Self, allocator: std.mem.Allocator, pubkey: t.Pubkey, config: ?t.RpcEpochConfig) ClientResult(t.RpcStakeActivation) {
        return self.call(allocator, "getStakeActivation", .{ pubkey, config });
    }

    pub fn getStakeMinimumDelegation(self: *Self, allocator: std.mem.Allocator, config: t.RpcContextConfig) ClientResult(t.RpcResponse(u64)) {
        return self.call(allocator, "getStakeMinimumDelegation", .{config});
    }

    pub fn getSupply(self: *Self, allocator: std.mem.Allocator, config: ?t.RpcSupplyConfig) ClientResult(t.RpcResponse(t.RpcSupply)) {
        return self.call(allocator, "getSupply", .{config});
    }

    pub fn getTokenAccountBalance(self: *Self, allocator: std.mem.Allocator, pubkey: t.Pubkey, commitment: ?t.CommitmentConfig) ClientResult(t.RpcResponse(t.UiTokenAmount)) {
        return self.call(allocator, "getTokenAccountBalance", .{ pubkey, commitment });
    }

    pub fn getTokenAccountsByDelegate(self: *Self, allocator: std.mem.Allocator, delegate: t.Pubkey, token_account_filter: t.TokenAccountsFilter, config: ?t.RpcAccountInfoConfig) ClientResult(t.RpcResponse([]t.RpcKeyedAccount)) {
        return self.call(allocator, "getTokenAccountsByDelegate", .{ delegate, token_account_filter, config });
    }

    pub fn getTokenAccountsByOwner(self: *Self, allocator: std.mem.Allocator, owner: t.Pubkey, token_account_filter: t.TokenAccountsFilter, config: ?t.RpcAccountInfoConfig) ClientResult(t.RpcResponse([]t.RpcKeyedAccount)) {
        return self.call(allocator, "getTokenAccountsByOwner", .{ owner, token_account_filter, config });
    }

    pub fn getTokenLargestAccounts(self: *Self, allocator: std.mem.Allocator, mint: t.Pubkey, commitment: ?t.CommitmentConfig) ClientResult(t.RpcResponse([]t.RpcTokenAccountBalance)) {
        return self.call(allocator, "getTokenLargestAccounts", .{ mint, commitment });
    }

    pub fn getTokenSupply(self: *Self, allocator: std.mem.Allocator, mint: t.Pubkey, commitment: t.CommitmentConfig) ClientResult(t.RpcResponse(t.UiTokenAmount)) {
        return self.call(allocator, "getTokenSupply", .{ mint, commitment });
    }

    pub fn getTotalSupply(self: *Self, allocator: std.mem.Allocator, commitment: ?t.CommitmentConfig) ClientResult(u64) {
        return self.call(allocator, "getTotalSupply", .{commitment});
    }

    pub fn getTransaction(self: *Self, allocator: std.mem.Allocator, signature: t.Signature, config: t.RpcEncodingConfigWrapper(t.RpcTransactionConfig)) ClientResult(?t.EncodedConfirmedTransactionWithStatusMeta) {
        return self.call(allocator, "getTransaction", .{ signature, config });
    }

    pub fn getTransactionCount(self: *Self, allocator: std.mem.Allocator, config: t.RpcContextConfig) ClientResult(u64) {
        return self.call(allocator, "getTransactionCount", .{config});
    }

    pub fn getVersion(self: *Self, allocator: std.mem.Allocator) ClientResult(t.RpcVersionInfo) {
        return self.call(allocator, "getVersion", .{});
    }

    pub fn getVoteAccounts(self: *Self, allocator: std.mem.Allocator, config: ?t.RpcGetVoteAccountsConfig) ClientResult(t.RpcVoteAccountStatus) {
        return self.call(allocator, "getVoteAccounts", .{config});
    }

    pub fn isBlockhashValid(self: *Self, allocator: std.mem.Allocator, hash: t.Hash, config: t.RpcContextConfig) ClientResult(t.RpcResponse(bool)) {
        return self.call(allocator, "isBlockhashValid", .{ hash, config });
    }

    pub fn minimumLedgerSlot(self: *Self, allocator: std.mem.Allocator) ClientResult(t.Slot) {
        return self.call(allocator, "minimumLedgerSlot", .{});
    }

    pub fn requestAirdrop(self: *Self, allocator: std.mem.Allocator, pubkey: t.Pubkey, lamports: u64, config: ?t.RpcRequestAirdropConfig) ClientResult([]const u8) {
        return self.call(allocator, "requestAirdrop", .{ pubkey, lamports, config });
    }

    pub fn sendTransaction(self: *Self, allocator: std.mem.Allocator, data: []const u8, config: ?t.RpcSendTransactionConfig) ClientResult([]const u8) {
        return self.call(allocator, "sendTransaction", .{ data, config });
    }

    pub fn simulateTransaction(self: *Self, allocator: std.mem.Allocator, data: []const u8, config: ?t.RpcSimulateTransactionConfig) ClientResult(t.RpcResponse(t.RpcSimulateTransactionResult)) {
        return self.call(allocator, "simulateTransaction", .{ data, config });
    }
};

pub fn ExtractResultOkParsedType(comptime method: []const u8) type {
    for (@typeInfo(t.RpcServiceImpl(RpcClient, ClientResult)).Struct.fields) |field| {
        if (std.mem.eql(u8, field.name, method)) {
            return @typeInfo(@typeInfo(@typeInfo(@typeInfo(field.type).Pointer.child).Fn.return_type.?)
                .Union.fields[0].type).Struct.fields[1].type;
        }
    }
    unreachable;
}

pub const ClientError = union(enum(u8)) {
    StartError: []const u8,
    FinishError: []const u8,
    WaitError: []const u8,
    ReaderError: []const u8,
    JsonParseError: []const u8,
    StatusError: std.http.Status,
    WriteError,
    OutOfMemory,
};

pub fn ClientResult(comptime T: type) type {
    return union(enum(u8)) {
        Success: Parsed(T),
        RpcError: Parsed(t.ErrorObject),
        ClientError: ClientError,

        const Self = @This();

        // NOTE: This is currently leaky and requires (Success|RpcError).Parsed(...).arena to be set manully by caller
        pub fn jsonParse(allocator: std.mem.Allocator, source: anytype, options: std.json.ParseOptions) !Self {
            var value = try std.json.Value.jsonParse(allocator, source, options);
            return try Self.jsonParseFromValue(allocator, value, options);
        }

        // NOTE: This is currently leaky and requires (Success|RpcError).Parsed(...).arena to be set manully by caller
        pub fn jsonParseFromValue(allocator: std.mem.Allocator, source: std.json.Value, options: std.json.ParseOptions) !Self {
            var parsed_response = try std.json.parseFromValue(t.JsonRpcResponse(T), allocator, source, options);
            defer parsed_response.deinit();

            if (parsed_response.value.@"error" != null) {
                return Self{
                    .RpcError = Parsed(t.ErrorObject){
                        // arena will be overriden
                        .arena = parsed_response.arena,
                        .value = parsed_response.value.@"error".?,
                    },
                };
            } else {
                return Self{
                    .Success = Parsed(T){
                        // arena will be overriden
                        .arena = parsed_response.arena,
                        .value = parsed_response.value.result.?,
                    },
                };
            }
        }
    };
}

// Statically dispatched, compile-time generics :)
comptime {
    const check: t.RpcServiceImpl(RpcClient, ClientResult) = .{
        .getAccountInfo = RpcClient.getAccountInfo,
        .getBalance = RpcClient.getBalance,
        .getBlock = RpcClient.getBlock,
        .getBlockCommitment = RpcClient.getBlockCommitment,
        .getBlockHeight = RpcClient.getBlockHeight,
        .getBlockProduction = RpcClient.getBlockProduction,
        .getBlocks = RpcClient.getBlocks,
        .getBlocksWithLimit = RpcClient.getBlocksWithLimit,
        .getBlockTime = RpcClient.getBlockTime,
        .getClusterNodes = RpcClient.getClusterNodes,
        .getConfirmedBlock = RpcClient.getConfirmedBlock,
        .getConfirmedBlocks = RpcClient.getConfirmedBlocks,
        .getConfirmedBlocksWithLimit = RpcClient.getConfirmedBlocksWithLimit,
        .getConfirmedSignaturesForAddress2 = RpcClient.getConfirmedSignaturesForAddress2,
        .getConfirmedTransaction = RpcClient.getConfirmedTransaction,
        .getEpochInfo = RpcClient.getEpochInfo,
        .getEpochSchedule = RpcClient.getEpochSchedule,
        .getFeeCalculatorForBlockhash = RpcClient.getFeeCalculatorForBlockhash,
        .getFeeForMessage = RpcClient.getFeeForMessage,
        .getFeeRateGovernor = RpcClient.getFeeRateGovernor,
        .getFees = RpcClient.getFees,
        .getFirstAvailableBlock = RpcClient.getFirstAvailableBlock,
        .getGenesisHash = RpcClient.getGenesisHash,
        .getHealth = RpcClient.getHealth,
        .getHighestSnapshotSlot = RpcClient.getHighestSnapshotSlot,
        .getIdentity = RpcClient.getIdentity,
        .getInflationGovernor = RpcClient.getInflationGovernor,
        .getInflationRate = RpcClient.getInflationRate,
        .getInflationReward = RpcClient.getInflationReward,
        .getLargestAccounts = RpcClient.getLargestAccounts,
        .getLatestBlockhash = RpcClient.getLatestBlockhash,
        .getLeaderSchedule = RpcClient.getLeaderSchedule,
        .getMaxRetransmitSlot = RpcClient.getMaxRetransmitSlot,
        .getMaxShredInsertSlot = RpcClient.getMaxShredInsertSlot,
        .getMinimumBalanceForRentExemption = RpcClient.getMinimumBalanceForRentExemption,
        .getMultipleAccounts = RpcClient.getMultipleAccounts,
        .getProgramAccounts = RpcClient.getProgramAccounts,
        .getRecentBlockhash = RpcClient.getRecentBlockhash,
        .getRecentPerformanceSamples = RpcClient.getRecentPerformanceSamples,
        .getRecentPrioritizationFees = RpcClient.getRecentPrioritizationFees,
        .getSignaturesForAddress = RpcClient.getSignaturesForAddress,
        .getSignatureStatuses = RpcClient.getSignatureStatuses,
        .getSlot = RpcClient.getSlot,
        .getSlotLeader = RpcClient.getSlotLeader,
        .getSlotLeaders = RpcClient.getSlotLeaders,
        .getSnapshotSlot = RpcClient.getSnapshotSlot,
        .getStakeActivation = RpcClient.getStakeActivation,
        .getStakeMinimumDelegation = RpcClient.getStakeMinimumDelegation,
        .getSupply = RpcClient.getSupply,
        .getTokenAccountBalance = RpcClient.getTokenAccountBalance,
        .getTokenAccountsByDelegate = RpcClient.getTokenAccountsByDelegate,
        .getTokenAccountsByOwner = RpcClient.getTokenAccountsByOwner,
        .getTokenLargestAccounts = RpcClient.getTokenLargestAccounts,
        .getTokenSupply = RpcClient.getTokenSupply,
        .getTotalSupply = RpcClient.getTotalSupply,
        .getTransaction = RpcClient.getTransaction,
        .getTransactionCount = RpcClient.getTransactionCount,
        .getVersion = RpcClient.getVersion,
        .getVoteAccounts = RpcClient.getVoteAccounts,
        .isBlockhashValid = RpcClient.isBlockhashValid,
        .minimumLedgerSlot = RpcClient.minimumLedgerSlot,
        .requestAirdrop = RpcClient.requestAirdrop,
        .sendTransaction = RpcClient.sendTransaction,
        .simulateTransaction = RpcClient.simulateTransaction,
    };
    _ = check;
}

test "rpc.client: makes request successfully" {
    var client = RpcClient.init(testing.allocator, try std.Uri.parse("https://api.mainnet-beta.solana.com/"));
    defer client.deinit();

    switch (client.getAccountInfo(testing.allocator, try t.Pubkey.fromString("CcwHykJRPsTvJrDH6vT9U6VJo2m2hwCAsPAG1mE1qEt6"), null)) {
        .Success => |val| {
            defer val.deinit();
            std.debug.print("result: {any}", .{val.value});
        },
        .RpcError => |err| {
            defer err.deinit();
            std.debug.print("rpc error: {}", .{err.value});
        },
        .ClientError => |err| {
            std.debug.print("client error: {any}", .{err});
        },
    }
}
