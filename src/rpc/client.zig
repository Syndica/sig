const std = @import("std");
const rpc = @import("lib.zig");

const Allocator = std.mem.Allocator;

const MethodAndParams = rpc.methods.MethodAndParams;
const HttpPostFetcher = rpc.http.HttpPostFetcher;
const Response = rpc.response.Response;

pub const FetchRpcError = Allocator.Error || HttpPostFetcher.Error || rpc.response.ParseError;

pub const Client = struct {
    fetcher: HttpPostFetcher,

    pub const Options = HttpPostFetcher.Options;
    pub const Error = FetchRpcError;

    pub fn init(
        allocator: Allocator,
        rpc_url: []const u8,
        options: HttpPostFetcher.Options,
    ) Allocator.Error!Client {
        return .{ .fetcher = try HttpPostFetcher.init(
            allocator,
            rpc_url,
            options,
        ) };
    }

    pub fn deinit(self: *Client) void {
        self.fetcher.deinit();
    }

    /// Call fetchRpc using the contained fetcher and the passed allocator.
    pub fn fetchCustom(
        self: *Client,
        allocator: Allocator,
        id: rpc.request.Id,
        comptime method: MethodAndParams.Tag,
        params: @FieldType(MethodAndParams, @tagName(method)),
    ) Error!Response(@TypeOf(params).Response) {
        const request: rpc.request.Request = .{
            .id = id,
            .method = @unionInit(MethodAndParams, @tagName(method), params),
        };

        const request_json = try std.json.stringifyAlloc(allocator, request, .{});
        defer allocator.free(request_json);

        const response_json = try self.fetcher.fetchWithRetries(allocator, request_json);
        defer allocator.free(response_json);

        return try Response(@TypeOf(params).Response).fromJson(allocator, response_json);
    }

    /// Call fetchRpc using the contained allocator and fetcher.
    pub fn fetch(
        self: *Client,
        id: rpc.request.Id,
        comptime method: MethodAndParams.Tag,
        request: @FieldType(MethodAndParams, @tagName(method)),
    ) Error!Response(@TypeOf(request).Response) {
        return try self.fetchCustom(
            self.fetcher.http_client.allocator,
            id,
            method,
            request,
        );
    }

    ///////////////////////////
    // All remaining functions are helpers for each RPC method, to make call sites less verbose.

    pub fn getAccountInfo(
        self: *Client,
        request: rpc.methods.GetAccountInfo,
    ) Error!Response(rpc.methods.GetAccountInfo.Response) {
        return self.fetch(.null, .getAccountInfo, request);
    }

    pub fn getBalance(
        self: *Client,
        request: rpc.methods.GetBalance,
    ) Error!Response(rpc.methods.GetBalance.Response) {
        return self.fetch(.null, .getBalance, request);
    }

    pub fn getBlock(
        self: *Client,
        request: rpc.methods.GetBlock,
    ) Error!Response(rpc.methods.GetBlock.Response) {
        return self.fetch(.null, .getBlock, request);
    }

    pub fn getBlockCommitment(
        self: *Client,
        request: rpc.methods.GetBlockCommitment,
    ) Error!Response(rpc.methods.GetBlockCommitment.Response) {
        return self.fetch(.null, .getBlockCommitment, request);
    }

    pub fn getBlockHeight(
        self: *Client,
        request: rpc.methods.GetBlockHeight,
    ) Error!Response(rpc.methods.GetBlockHeight.Response) {
        return self.fetch(.null, .getBlockHeight, request);
    }

    pub fn getClusterNodes(
        self: *Client,
        request: rpc.methods.GetClusterNodes,
    ) Error!Response(rpc.methods.GetClusterNodes.Response) {
        return self.fetch(.null, .getClusterNodes, request);
    }

    pub fn getEpochInfo(
        self: *Client,
        request: rpc.methods.GetEpochInfo,
    ) Error!Response(rpc.methods.GetEpochInfo.Response) {
        return self.fetch(.null, .getEpochInfo, request);
    }

    pub fn getEpochSchedule(
        self: *Client,
        request: rpc.methods.GetEpochSchedule,
    ) Error!Response(rpc.methods.GetEpochSchedule.Response) {
        return self.fetch(.null, .getEpochSchedule, request);
    }

    pub fn getGenesisHash(
        self: *Client,
        request: rpc.methods.GetGenesisHash,
    ) Error!Response(rpc.methods.GetGenesisHash.Response) {
        return self.fetch(.null, .getGenesisHash, request);
    }

    pub fn getLatestBlockhash(
        self: *Client,
        request: rpc.methods.GetLatestBlockhash,
    ) Error!Response(rpc.methods.GetLatestBlockhash.Response) {
        return self.fetch(.null, .getLatestBlockhash, request);
    }

    pub fn getLeaderSchedule(
        self: *Client,
        request: rpc.methods.GetLeaderSchedule,
    ) Error!Response(rpc.methods.GetLeaderSchedule.Response) {
        return self.fetch(.null, .getLeaderSchedule, request);
    }

    pub fn getSignatureStatuses(
        self: *Client,
        request: rpc.methods.GetSignatureStatuses,
    ) Error!Response(rpc.methods.GetSignatureStatuses.Response) {
        return self.fetch(.null, .getSignatureStatuses, request);
    }

    pub fn getSlot(
        self: *Client,
        request: rpc.methods.GetSlot,
    ) Error!Response(rpc.methods.GetSlot.Response) {
        return self.fetch(.null, .getSlot, request);
    }

    pub fn getTransaction(
        self: *Client,
        request: rpc.methods.GetTransaction,
    ) Error!Response(rpc.methods.GetTransaction.Response) {
        return self.fetch(.null, .getTransaction, request);
    }

    pub fn getVersion(
        self: *Client,
        request: rpc.methods.GetVersion,
    ) Error!Response(rpc.methods.GetVersion.Response) {
        return self.fetch(.null, .getVersion, request);
    }

    pub fn getVoteAccounts(
        self: *Client,
        request: rpc.methods.GetVoteAccounts,
    ) Error!Response(rpc.methods.GetVoteAccounts.Response) {
        return self.fetch(.null, .getVoteAccounts, request);
    }

    pub fn requestAirdrop(
        self: *Client,
        request: rpc.methods.RequestAirdrop,
    ) Error!Response(rpc.methods.RequestAirdrop.Response) {
        return self.fetch(.null, .requestAirdrop, request);
    }

    pub fn sendTransaction(
        self: *Client,
        request: rpc.methods.SendTransaction,
    ) Error!Response(rpc.methods.SendTransaction.Response) {
        return self.fetch(.null, .sendTransaction, request);
    }
};
