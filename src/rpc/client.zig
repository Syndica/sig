const std = @import("std");
const sig = @import("../sig.zig");
const rpc = @import("lib.zig");

const Allocator = std.mem.Allocator;

const ClusterType = sig.accounts_db.genesis_config.ClusterType;

const MethodAndParams = rpc.methods.MethodAndParams;
const HttpPostFetcher = rpc.http.HttpPostFetcher;
const Response = rpc.response.Response;

pub const FetchRpcError = Allocator.Error || HttpPostFetcher.Error || rpc.response.ParseError;

/// Send a typed RPC request and await a response.
/// Pass a struct, such as those defined in `rpc.methods`.
/// Returns data allocated with the passed allocator.
pub fn fetchRpc(
    fetcher: *HttpPostFetcher,
    allocator: Allocator,
    id: rpc.request.Id,
    /// The name of the RPC method to use.
    method_name: []const u8,
    /// Should be a request parameter struct defined in `rpc.methods`, but
    /// can be anything serializable; it is up to the caller to supply a
    /// request which is valid and expected by the target RPC server.
    /// Just as is expected of the types in `rpc.methods`, a type decl
    /// of name `Response` is expected, to declare the type of the response.
    ///
    /// NOTE: typically the parameter field is an array, despite being
    /// represented as a record struct in zig code; unless this is for
    /// named parameters, this should likely be a tuple, or otherwise
    /// serialized as an array.
    method_params: anytype,
) FetchRpcError!Response(@TypeOf(method_params).Response) {
    const request_json = try std.json.stringifyAlloc(allocator, .{
        .jsonrpc = "2.0",
        .id = id,
        .method = method_name,
        .params = method_params,
    }, .{});
    defer allocator.free(request_json);

    const response_json = try fetcher.fetchWithRetries(allocator, request_json);
    defer allocator.free(response_json);

    return try Response(@TypeOf(method_params).Response).fromJson(allocator, response_json);
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

    /// Call fetchRpc using the contained fetcher and the passed allocator.
    pub fn fetchCustom(
        self: *Client,
        allocator: Allocator,
        id: rpc.request.Id,
        comptime method: MethodAndParams.Tag,
        // TODO: use this instead of `std.meta.FieldType` to avoid eval branch quota until `@FieldType`'s here.
        request: @typeInfo(MethodAndParams).Union.fields[@intFromEnum(method)].type,
    ) Error!Response(@TypeOf(request).Response) {
        return try fetchRpc(
            &self.fetcher,
            allocator,
            id,
            @tagName(method),
            request,
        );
    }

    /// Call fetchRpc using the contained allocator and fetcher.
    pub fn fetch(
        self: *Client,
        id: rpc.request.Id,
        comptime method: MethodAndParams.Tag,
        // TODO: use this instead of `std.meta.FieldType` to avoid eval branch quota until `@FieldType`'s here.
        request: @typeInfo(MethodAndParams).Union.fields[@intFromEnum(method)].type,
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

pub fn rpcUrl(cluster_type: ClusterType) []const u8 {
    return switch (cluster_type) {
        .MainnetBeta => "https://api.mainnet-beta.solana.com",
        .Testnet => "https://api.testnet.solana.com",
        .Devnet => "https://api.devnet.solana.com",
        .Custom => |cluster| cluster.url,
        else => "http://localhost:8899",
    };
}
