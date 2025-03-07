const std = @import("std");
const sig = @import("../sig.zig");
const rpc = @import("lib.zig");

const Allocator = std.mem.Allocator;

const ClusterType = sig.accounts_db.genesis_config.ClusterType;

const HttpPostFetcher = rpc.http.HttpPostFetcher;
const Response = rpc.response.Response;

const GetAccountInfo = rpc.methods.GetAccountInfo;
const GetBalance = rpc.methods.GetBalance;
const GetBlock = rpc.methods.GetBlock;
const GetBlockCommitment = rpc.methods.GetBlockCommitment;
const GetBlockHeight = rpc.methods.GetBlockHeight;
const GetClusterNodes = rpc.methods.GetClusterNodes;
const GetEpochInfo = rpc.methods.GetEpochInfo;
const GetEpochSchedule = rpc.methods.GetEpochSchedule;
const GetLatestBlockhash = rpc.methods.GetLatestBlockhash;
const GetLeaderSchedule = rpc.methods.GetLeaderSchedule;
const GetSignatureStatuses = rpc.methods.GetSignatureStatuses;
const GetSlot = rpc.methods.GetSlot;
const GetTransaction = rpc.methods.GetTransaction;
const GetVersion = rpc.methods.GetVersion;
const GetVoteAccounts = rpc.methods.GetVoteAccounts;
const RequestAirdrop = rpc.methods.RequestAirdrop;
const SendTransaction = rpc.methods.SendTransaction;

pub const FetchRpcError = Allocator.Error || HttpPostFetcher.Error || rpc.response.ParseError;

/// Send a typed RPC request and await a response.
/// Pass a struct, such as those defined in `rpc.methods`.
/// Returns data allocated with the passed allocator.
pub fn fetchRpc(
    fetcher: *HttpPostFetcher,
    allocator: Allocator,
    request: anytype,
) FetchRpcError!Response(@TypeOf(request)) {
    const request_json = try rpc.request.serialize(allocator, request);
    defer allocator.free(request_json);
    const response_json = try fetcher.fetchWithRetries(allocator, request_json);
    defer allocator.free(response_json);
    return try Response(@TypeOf(request)).fromJson(allocator, response_json);
}

pub const Client = struct {
    fetcher: HttpPostFetcher,

    pub const Options = HttpPostFetcher.Options;
    pub const Error = FetchRpcError;

    pub fn init(
        allocator: Allocator,
        cluster_type: ClusterType,
        options: HttpPostFetcher.Options,
    ) Allocator.Error!Client {
        return .{ .fetcher = try HttpPostFetcher.init(allocator, rpcUrl(cluster_type), options) };
    }

    pub fn deinit(self: *Client) void {
        self.fetcher.deinit();
    }

    /// Call fetchRpc using the contained allocator and fetcher.
    fn fetch(self: *Client, request: anytype) Error!Response(@TypeOf(request)) {
        return try fetchRpc(&self.fetcher, self.fetcher.http_client.allocator, request);
    }

    /// Call fetchRpc using the contained fetcher and the passed allocator.
    pub fn fetchCustom(
        self: *Client,
        allocator: Allocator,
        request: anytype,
    ) Error!Response(@TypeOf(request)) {
        return try fetchRpc(&self.fetcher, allocator, request);
    }

    ///////////////////////////
    // All remaining functions are helpers for each RPC method, to make call sites less verbose.

    pub fn getAccountInfo(self: *Client, request: GetAccountInfo) Error!Response(GetAccountInfo) {
        return self.fetch(request);
    }

    pub fn getBalance(self: *Client, request: GetBalance) Error!Response(GetBalance) {
        return self.fetch(request);
    }

    pub fn getBlock(self: *Client, request: GetBlock) Error!Response(GetBlock) {
        return self.fetch(request);
    }

    pub fn getBlockCommitment(self: *Client, request: GetBlockCommitment) Error!Response(GetBlockCommitment) {
        return self.fetch(request);
    }

    pub fn getBlockHeight(self: *Client, request: GetBlockHeight) Error!Response(GetBlockHeight) {
        return self.fetch(request);
    }

    pub fn getClusterNodes(self: *Client, request: GetClusterNodes) Error!Response(GetClusterNodes) {
        return self.fetch(request);
    }

    pub fn getEpochInfo(self: *Client, request: GetEpochInfo) Error!Response(GetEpochInfo) {
        return self.fetch(request);
    }

    pub fn getEpochSchedule(self: *Client, request: GetEpochSchedule) Error!Response(GetEpochSchedule) {
        return self.fetch(request);
    }

    pub fn getLatestBlockhash(self: *Client, request: GetLatestBlockhash) Error!Response(GetLatestBlockhash) {
        return self.fetch(request);
    }

    pub fn getLeaderSchedule(self: *Client, request: GetLeaderSchedule) Error!Response(GetLeaderSchedule) {
        return self.fetch(request);
    }

    pub fn getSignatureStatuses(self: *Client, request: GetSignatureStatuses) Error!Response(GetSignatureStatuses) {
        return self.fetch(request);
    }

    pub fn getSlot(self: *Client, request: GetSlot) Error!Response(GetSlot) {
        return self.fetch(request);
    }

    pub fn getTransaction(self: *Client, request: GetTransaction) Error!Response(GetTransaction) {
        return self.fetch(request);
    }

    pub fn getVersion(self: *Client, request: GetVersion) Error!Response(GetVersion) {
        return self.fetch(request);
    }

    pub fn getVoteAccounts(self: *Client, request: GetVoteAccounts) Error!Response(GetVoteAccounts) {
        return self.fetch(request);
    }

    pub fn requestAirdrop(self: *Client, request: RequestAirdrop) Error!Response(RequestAirdrop) {
        return self.fetch(request);
    }

    pub fn sendTransaction(self: *Client, request: SendTransaction) Error!Response(SendTransaction) {
        return self.fetch(request);
    }
};

pub fn rpcUrl(cluster_type: ClusterType) []const u8 {
    return switch (cluster_type) {
        .MainnetBeta => "https://api.mainnet-beta.solana.com",
        .Testnet => "https://api.testnet.solana.com",
        .Devnet => "https://api.devnet.solana.com",
        .Custom => |cluster| cluster.url,
        else => "http://localhost:8899",
    };
}
