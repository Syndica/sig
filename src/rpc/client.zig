const std = @import("std");
const json = std.json;
const Uri = std.Uri;
const http = std.http;
const jsonrpc = @import("jsonrpc.zig");
const Account = @import("../core/account.zig").Account;
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const types = @import("types.zig");
const Encoding = @import("types.zig").Encoding;
const base64 = @import("std").base64.standard;
const Response = jsonrpc.ResponsePayload;
const testing = std.testing;

const HTTP_ENDPOINT = "https://api.mainnet-beta.solana.com";
const SKIP_RPC_CALLS_TESTING = true; // temp due to std.http.Client leaking

const logger = std.log.scoped(.rpc_client);

pub const Error = error{ InvalidRequest, ResponseNotStatusOk, InvalidHttpEndpoint, InvalidHttpHeaders };

pub const Client = struct {
    http_endpoint: Uri,
    client: http.Client,
    default_http_headers: http.Headers,
    default_commitment: types.Commitment,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub const Configuration = struct {
        http_endpoint: []const u8,
        /// NOTE: expected format is as follows:
        ///
        ///     var headers = [_][2][]const u8{
        ///         .{"x-api-key", "a-secret-api-key-of-yours"},
        ///         .{"x-hello", "world"},
        ///     }
        ///
        http_headers: ?[][2][]const u8 = null,
        commitment: types.Commitment = .Finalized,
    };

    pub fn init(allocator: std.mem.Allocator, config: Configuration) !Self {
        const uri = try std.Uri.parse(config.http_endpoint);
        var client: http.Client = .{ .allocator = allocator };
        var headers = http.Headers.init(allocator);
        try headers.append("Content-Type", "application/json; charset=utf-8");
        try headers.append("User-Agent", "sig/0.1");

        if (config.http_headers) |http_headers| {
            for (http_headers) |header| {
                var name = header[0];
                var value = header[1];
                if (name.len == 0 or value.len == 0) {
                    headers.deinit();
                    return Error.InvalidHttpHeaders;
                }
                try headers.append(name, value);
            }
        }

        return Self{
            .http_endpoint = uri,
            .client = client,
            .default_http_headers = headers,
            .default_commitment = config.commitment,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        var headers = self.default_http_headers;
        headers.deinit();
    }

    fn defaultCommitmentOr(self: *Self, commitment: ?types.Commitment) types.Commitment {
        if (commitment) |cmmt| {
            return cmmt;
        }
        return self.default_commitment;
    }

    fn makeRequestWithJRpcResponse(self: *Self, comptime Result: type, comptime Params: type, method: []const u8, id: []const u8, params: Params) !jsonrpc.Response(Result) {
        logger.debug("invoking rpc method '{s}' with params: {any}", .{ method, params });

        var req = try self.client.request(http.Method.POST, self.http_endpoint, self.default_http_headers, .{});
        req.transfer_encoding = .chunked;
        defer req.deinit();
        try req.start();

        const JrpcRequest = jsonrpc.Request(Params);

        var out = try std.json.stringifyAlloc(self.allocator, JrpcRequest{
            .jsonrpc = "2.0",
            .id = id,
            .method = method,
            .params = params,
        }, .{ .emit_null_optional_fields = false });
        defer self.allocator.free(out);

        logger.debug("request body: {s}", .{out});

        try req.writer().writeAll(out);
        try req.finish();
        logger.debug("request wating..", .{});
        try req.wait();

        if (req.response.status != http.Status.ok) {
            logger.warn("response status not 200: {}", .{req.response.status});
            return Error.ResponseNotStatusOk;
        }

        logger.debug("request reading..", .{});
        const body = try req.reader().readAllAlloc(self.allocator, 819200);
        defer self.allocator.free(body);

        logger.debug("response body: {s}", .{body});
        var resp = try std.json.parseFromSlice(jsonrpc.ResponsePayload(Result), self.allocator, body, .{ .ignore_unknown_fields = true });
        return jsonrpc.Response(Result).init(self.allocator, resp);
    }

    fn makeRequestWithJsonValueResponse(self: *Self, comptime Params: type, method: []const u8, id: []const u8, params: Params) !json.ValueTree {
        logger.debug("invoking rpc method '{s}' with params: {any}", .{ method, params });

        var client = self.client;
        var req = try client.request(http.Method.POST, self.http_endpoint, self.default_http_headers, .{});
        req.transfer_encoding = .chunked;
        defer req.deinit();
        try req.start();

        const JrpcRequest = jsonrpc.Request(Params);

        var out = try std.json.stringifyAlloc(self.allocator, JrpcRequest{
            .jsonrpc = "2.0",
            .id = id,
            .method = method,
            .params = params,
        }, .{ .emit_null_optional_fields = false });
        defer self.allocator.free(out);
        logger.debug("request body: {s}", .{out});

        try req.writer().writeAll(out);
        try req.finish();
        logger.debug("request wating..", .{});
        try req.wait();

        if (req.response.status != http.Status.ok) {
            logger.warn("response status not 200: {}", .{req.response.status});
            return Error.ResponseNotStatusOk;
        }

        logger.debug("request reading..", .{});
        const body = try req.reader().readAllAlloc(self.allocator, 819200);
        defer self.allocator.free(body);

        logger.debug("response body: {s}", .{body});

        var parser = std.json.Parser.init(self.allocator, .alloc_always);
        defer parser.deinit();

        var tree = try parser.parse(body);
        return tree;
    }

    pub fn getSlot(self: *Self) !jsonrpc.Response(i64) {
        return try self.makeRequestWithJRpcResponse(i64, ?u8, "getSlot", "1", null);
    }

    const GetAccountInfoOptions = struct {
        commitment: ?types.Commitment = null,
        encoding: types.Encoding = .Base64,
    };

    pub fn getAccountInfo(self: *Self, pubkey: Pubkey, options: GetAccountInfoOptions) !jsonrpc.Response(types.AccountInfo) {
        var optionsObj = std.StringArrayHashMap(json.Value).init(self.allocator);
        defer optionsObj.deinit();
        try optionsObj.put("encoding", .{ .string = options.encoding.string() });
        try optionsObj.put("commitment", .{ .string = self.defaultCommitmentOr(options.commitment).string() });

        var arrList = std.ArrayList(json.Value).init(self.allocator);
        defer arrList.deinit();

        var str = pubkey.string();

        try arrList.append(.{ .string = str });
        try arrList.append(.{ .object = optionsObj });

        var params = .{ .array = arrList };

        var resp = try self.makeRequestWithJRpcResponse(types.AccountInfo, json.Value, "getAccountInfo", "1", params);
        return resp;
    }

    pub fn getBalance(self: *Self, pubkey: Pubkey) !jsonrpc.Response(types.BalanceInfo) {
        var str = pubkey.string();

        var params: [1][]const u8 = [1][]const u8{str};
        return try self.makeRequestWithJRpcResponse(types.BalanceInfo, [][]const u8, "getBalance", "1", &params);
    }

    pub fn getBlockHeight(self: *Self) !jsonrpc.Response(u64) {
        return try self.makeRequestWithJRpcResponse(u64, ?u8, "getBlockHeight", "1", null);
    }

    const GetBlockOptions = struct {
        commitment: ?types.Commitment = null,
        maxSupportedTransactionVersion: i64 = 0,
        transactionDetails: []const u8 = "full",
        rewards: bool = false,
        /// NOTE: must be json for now
        encoding: types.Encoding = .Json,
    };

    pub fn getBlock(self: *Self, slot: u64, options: GetBlockOptions) !jsonrpc.Response(types.BlockInfo) {
        var optionsObj = std.StringArrayHashMap(json.Value).init(self.allocator);
        defer optionsObj.deinit();
        try optionsObj.put("commitment", .{ .string = self.defaultCommitmentOr(options.commitment).string() });
        try optionsObj.put("encoding", .{ .string = options.encoding.string() });
        try optionsObj.put("maxSupportedTransactionVersion", .{ .integer = options.maxSupportedTransactionVersion });
        try optionsObj.put("transactionDetails", .{ .string = options.transactionDetails });
        try optionsObj.put("rewards", .{ .bool = options.rewards });

        var arrList = std.ArrayList(json.Value).init(self.allocator);
        defer arrList.deinit();
        try arrList.append(.{ .integer = @intCast(slot) });
        try arrList.append(.{ .object = optionsObj });

        var params = .{ .array = arrList };

        return try self.makeRequestWithJRpcResponse(types.BlockInfo, json.Value, "getBlock", "1", params);
    }

    const GetBlockProductionOptions = struct {
        commitment: ?types.Commitment = null,
        identity: ?[]const u8 = null,
        range: ?struct {
            firstSlot: u64,
            lastSlot: ?u64,
        } = null,
    };

    pub fn getBlockProduction(self: *Self, options: GetBlockProductionOptions) !jsonrpc.ResponseAlt(types.BlockProductionInfo) {
        const Result = jsonrpc.ResponsePayload(types.BlockProductionInfo);

        var optionsObj = std.StringArrayHashMap(json.Value).init(self.allocator);
        defer optionsObj.deinit();
        try optionsObj.put("commitment", .{ .string = self.defaultCommitmentOr(options.commitment).string() });
        if (options.identity) |ident| {
            try optionsObj.put("identity", .{ .string = ident });
        }
        if (options.range) |range| {
            var rangeObj = std.StringArrayHashMap(json.Value).init(self.allocator);
            defer rangeObj.deinit();
            try rangeObj.put("firstSlot", .{ .integer = @as(i64, @intCast(range.firstSlot)) });
            if (range.lastSlot) |lastSlot| {
                try rangeObj.put("lastSlot", .{ .integer = @as(i64, @intCast(lastSlot)) });
            }
        }

        var arrList = std.ArrayList(json.Value).init(self.allocator);
        defer arrList.deinit();
        try arrList.append(.{ .object = optionsObj });

        var params = .{ .array = arrList };

        var tree = try self.makeRequestWithJsonValueResponse(json.Value, "getBlockProduction", "1", params);
        var errorObject = tree.root.object.get("error");
        var id = tree.root.object.get("id").?.string;

        var arena = std.heap.ArenaAllocator.init(self.allocator);
        var responseAllocator = arena.allocator();
        if (errorObject) |errObj| {
            return jsonrpc.ResponseAlt(types.BlockProductionInfo).init(arena, Result{ .jsonrpc = "2.0", .id = id, .result = null, .@"error" = jsonrpc.ErrorObject{
                .code = errObj.object.get("code").?.integer,
                .message = errObj.object.get("message").?.string,
            } }, tree);
        }

        var result = tree.root.object.get("result").?;
        var context = result.object.get("context").?;
        var value = result.object.get("value").?;

        var byIdentity = std.StringArrayHashMap([]u64).init(responseAllocator);
        var iter = value.object.get("byIdentity").?.object.iterator();

        while (iter.next()) |entry| {
            var vals = std.ArrayList(u64).init(responseAllocator);
            for (entry.value_ptr.*.array.items) |val| {
                try vals.append(@as(u64, @intCast(val.integer)));
            }
            try byIdentity.put(entry.key_ptr.*, vals.items);
        }

        return jsonrpc.ResponseAlt(types.BlockProductionInfo).init(
            arena,
            Result{ .jsonrpc = "2.0", .id = id, .result = .{ .context = .{
                .apiVersion = context.object.get("apiVersion").?.string,
                .slot = @as(u64, @intCast(context.object.get("slot").?.integer)),
            }, .value = .{ .byIdentity = byIdentity, .range = .{
                .firstSlot = @as(u64, @intCast(value.object.get("range").?.object.get("firstSlot").?.integer)),
                .lastSlot = @as(u64, @intCast(value.object.get("range").?.object.get("firstSlot").?.integer)),
            } } } },
            tree,
        );
    }

    pub fn getBlockCommitment(self: *Self, slot: u64) !jsonrpc.Response(types.BlockCommitment) {
        var params = [1]u64{slot};
        return try self.makeRequestWithJRpcResponse(types.BlockCommitment, []u64, "getBlockCommitment", "1", &params);
    }

    const GetBlocksOptions = struct {
        commitment: ?types.Commitment = null,
    };

    pub fn getBlocks(self: *Self, startSlot: u64, endSlot: ?u64, options: GetBlocksOptions) !jsonrpc.Response([]u64) {
        var optionsObj = std.StringArrayHashMap(json.Value).init(self.allocator);
        defer optionsObj.deinit();
        try optionsObj.put("commitment", .{ .string = self.defaultCommitmentOr(options.commitment).string() });

        var paramsList = std.ArrayList(json.Value).init(self.allocator);
        defer paramsList.deinit();
        try paramsList.append(.{ .integer = @as(i64, @intCast(startSlot)) });
        if (endSlot) |slot| {
            try paramsList.append(.{ .integer = @as(i64, @intCast(slot)) });
        }
        try paramsList.append(.{ .object = optionsObj });
        var params = json.Value{ .array = paramsList };

        return try self.makeRequestWithJRpcResponse([]u64, json.Value, "getBlocks", "1", params);
    }

    pub fn getBlocksWithLimit(self: *Self, startSlot: u64, limit: ?u64, options: GetBlocksOptions) !jsonrpc.Response([]u64) {
        var optionsObj = std.StringArrayHashMap(json.Value).init(self.allocator);
        defer optionsObj.deinit();
        try optionsObj.put("commitment", .{ .string = self.defaultCommitmentOr(options.commitment).string() });

        var paramsList = std.ArrayList(json.Value).init(self.allocator);
        defer paramsList.deinit();
        try paramsList.append(.{ .integer = @as(i64, @intCast(startSlot)) });
        if (limit) |v| {
            try paramsList.append(.{ .integer = @as(i64, @intCast(v)) });
        }
        try paramsList.append(.{ .object = optionsObj });
        var params = json.Value{ .array = paramsList };

        return try self.makeRequestWithJRpcResponse([]u64, json.Value, "getBlocksWithLimit", "1", params);
    }

    pub fn getBlockTime(self: *Self, slot: u64) !jsonrpc.Response(?u64) {
        var params = [1]u64{slot};
        return try self.makeRequestWithJRpcResponse(?u64, []u64, "getBlockTime", "1", &params);
    }

    pub fn getClusterNodes(self: *Self) !jsonrpc.Response([]types.NodeInfo) {
        return try self.makeRequestWithJRpcResponse([]types.NodeInfo, ?u8, "getClusterNodes", "1", null);
    }

    const GetEpochInfoOptions = struct {
        commitment: ?types.Commitment = null,
    };

    pub fn getEpochInfo(self: *Self, options: GetEpochInfoOptions) !jsonrpc.Response(types.EpochInfo) {
        var optionsObj = std.StringArrayHashMap(json.Value).init(self.allocator);
        defer optionsObj.deinit();
        try optionsObj.put("commitment", .{ .string = self.defaultCommitmentOr(options.commitment).string() });

        var paramsList = std.ArrayList(json.Value).init(self.allocator);
        defer paramsList.deinit();
        try paramsList.append(.{ .object = optionsObj });
        var params = json.Value{ .array = paramsList };
        return try self.makeRequestWithJRpcResponse(types.EpochInfo, json.Value, "getEpochInfo", "1", params);
    }

    pub fn getEpochSchedule(self: *Self) !jsonrpc.Response(types.EpochSchedule) {
        return try self.makeRequestWithJRpcResponse(types.EpochSchedule, ?u8, "getEpochSchedule", "1", null);
    }

    const GetFeeForMessageOptions = struct {
        commitment: ?types.Commitment = null,
    };

    pub fn getFeeForMessage(self: *Self, base64EncodedMessage: []const u8, options: GetFeeForMessageOptions) !jsonrpc.Response(types.MessageFeeInfo) {
        var optionsObj = std.StringArrayHashMap(json.Value).init(self.allocator);
        defer optionsObj.deinit();
        try optionsObj.put("commitment", .{ .string = self.defaultCommitmentOr(options.commitment).string() });

        var paramsList = std.ArrayList(json.Value).init(self.allocator);
        defer paramsList.deinit();
        try paramsList.append(.{ .string = base64EncodedMessage });
        try paramsList.append(.{ .object = optionsObj });
        var params = json.Value{ .array = paramsList };
        return try self.makeRequestWithJRpcResponse(types.MessageFeeInfo, json.Value, "getFeeForMessage", "1", params);
    }

    pub fn getFirstAvailableBlock(self: *Self) !jsonrpc.Response(u64) {
        return try self.makeRequestWithJRpcResponse(u64, ?u8, "getFirstAvailableBlock", "1", null);
    }

    pub fn getGenesisHash(self: *Self) !jsonrpc.Response([]const u8) {
        return try self.makeRequestWithJRpcResponse([]const u8, ?u8, "getGenesisHash", "1", null);
    }

    pub fn getHealth(self: *Self) !jsonrpc.Response([]const u8) {
        return try self.makeRequestWithJRpcResponse([]const u8, ?u8, "getHealth", "1", null);
    }

    pub fn getHighestSnapshotSlot(self: *Self) !jsonrpc.Response(types.SnapshotInfo) {
        return try self.makeRequestWithJRpcResponse(types.SnapshotInfo, ?u8, "getHighestSnapshotSlot", "1", null);
    }

    pub fn getIdentity(self: *Self) !jsonrpc.Response(types.IdentityInfo) {
        return try self.makeRequestWithJRpcResponse(types.IdentityInfo, ?u8, "getIdentity", "1", null);
    }

    const GetInflationGovernorOptions = struct {
        commitment: ?types.Commitment = null,
    };

    pub fn getInflationGovernor(self: *Self, options: GetInflationGovernorOptions) !jsonrpc.Response(types.InfaltionInfo) {
        var optionsObj = std.StringArrayHashMap(json.Value).init(self.allocator);
        defer optionsObj.deinit();
        try optionsObj.put("commitment", .{ .string = self.defaultCommitmentOr(options.commitment).string() });

        var paramsList = std.ArrayList(json.Value).init(self.allocator);
        defer paramsList.deinit();
        try paramsList.append(.{ .object = optionsObj });
        var params = json.Value{ .array = paramsList };
        return try self.makeRequestWithJRpcResponse(types.InfaltionInfo, json.Value, "getInflationGovernor", "1", params);
    }

    pub fn getInflationRate(self: *Self) !jsonrpc.Response(types.InflationRateInfo) {
        return try self.makeRequestWithJRpcResponse(types.InflationRateInfo, ?u8, "getInflationRate", "1", null);
    }

    const GetInflationRewardOptions = struct {
        commitment: ?types.Commitment = null,
        epoch: ?u64 = null,
        minContextSlot: ?u64 = null,
    };

    pub fn getInflationReward(self: *Self, pubkeys: []Pubkey, options: GetInflationRewardOptions) !jsonrpc.Response([]?types.InflationReward) {
        var optionsObj = std.StringArrayHashMap(json.Value).init(self.allocator);
        defer optionsObj.deinit();
        try optionsObj.put("commitment", .{ .string = self.defaultCommitmentOr(options.commitment).string() });
        if (options.epoch) |epoch| {
            try optionsObj.put("epoch", .{ .integer = @as(i64, @intCast(epoch)) });
        }
        if (options.minContextSlot) |minContextSlot| {
            try optionsObj.put("minContextSlot", .{ .integer = @as(i64, @intCast(minContextSlot)) });
        }

        var paramsList = std.ArrayList(json.Value).init(self.allocator);
        defer paramsList.deinit();
        var accountsList = std.ArrayList(json.Value).init(self.allocator);
        defer accountsList.deinit();
        for (pubkeys) |pubkey| {
            var str = pubkey.string();

            try accountsList.append(.{ .string = str });
        }
        try paramsList.append(.{ .array = accountsList });
        try paramsList.append(.{ .object = optionsObj });

        var params = json.Value{ .array = paramsList };

        return try self.makeRequestWithJRpcResponse([]?types.InflationReward, json.Value, "getInflationReward", "1", params);
    }

    const GetLargestAccountsOptions = struct {
        commitment: ?types.Commitment = null,
        filter: ?enum { Circulating, NonCirculating } = null,
    };

    pub fn getLargestAccounts(self: *Self, options: GetLargestAccountsOptions) !jsonrpc.Response(types.LargestAccountsInfo) {
        var optionsObj = std.StringArrayHashMap(json.Value).init(self.allocator);
        defer optionsObj.deinit();
        try optionsObj.put("commitment", .{ .string = self.defaultCommitmentOr(options.commitment).string() });

        if (options.filter) |filter| {
            var filterStr = switch (filter) {
                .Circulating => "circulating",
                .NonCirculating => "nonCirculating",
            };
            try optionsObj.put("filter", .{ .string = filterStr });
        }

        var paramsList = std.ArrayList(json.Value).init(self.allocator);
        defer paramsList.deinit();
        try paramsList.append(.{ .object = optionsObj });
        var params = json.Value{ .array = paramsList };

        return try self.makeRequestWithJRpcResponse(types.LargestAccountsInfo, json.Value, "getLargestAccounts", "1", params);
    }

    const GetLatestBlockhashOptions = struct {
        commitment: ?types.Commitment = null,
        minContextSlot: ?u64 = null,
    };

    pub fn getLatestBlockhash(self: *Self, options: GetLatestBlockhashOptions) !jsonrpc.Response(types.LatestBlockhashInfo) {
        var optionsObj = std.StringArrayHashMap(json.Value).init(self.allocator);
        defer optionsObj.deinit();
        try optionsObj.put("commitment", .{ .string = self.defaultCommitmentOr(options.commitment).string() });

        if (options.minContextSlot) |minContextSlot| {
            try optionsObj.put("minContextSlot", .{ .integer = @as(i64, @intCast(minContextSlot)) });
        }
        var paramsList = std.ArrayList(json.Value).init(self.allocator);
        defer paramsList.deinit();
        try paramsList.append(.{ .object = optionsObj });
        var params = json.Value{ .array = paramsList };

        return try self.makeRequestWithJRpcResponse(types.LatestBlockhashInfo, json.Value, "getLatestBlockhash", "1", params);
    }

    const GetLeaderScheduleOptions = struct {
        commitment: ?types.Commitment = null,
        identity: ?[]const u8 = null,
    };

    pub fn getLeaderSchedule(self: *Self, epoch: ?u64, options: GetLeaderScheduleOptions) !jsonrpc.ResponseAlt(?std.StringArrayHashMap([]u64)) {
        var optionsObj = std.StringArrayHashMap(json.Value).init(self.allocator);
        defer optionsObj.deinit();
        try optionsObj.put("commitment", .{ .string = self.defaultCommitmentOr(options.commitment).string() });
        if (options.identity) |ident| {
            try optionsObj.put("identity", .{ .string = ident });
        }
        var arrList = std.ArrayList(json.Value).init(self.allocator);
        defer arrList.deinit();
        if (epoch) |v| {
            try arrList.append(.{ .integer = @as(i64, @intCast(v)) });
        }
        try arrList.append(.{ .object = optionsObj });
        var params = .{ .array = arrList };

        var tree = try self.makeRequestWithJsonValueResponse(json.Value, "getLeaderSchedule", "1", params);

        var errorObject = tree.root.object.get("error");
        var id = tree.root.object.get("id").?.string;

        var arena = std.heap.ArenaAllocator.init(self.allocator);
        var responseAllocator = arena.allocator();

        if (errorObject) |errObj| {
            return jsonrpc.ResponseAlt(?std.StringArrayHashMap([]u64)).init(
                arena,
                jsonrpc.ResponsePayload(?std.StringArrayHashMap([]u64)){ .jsonrpc = "2.0", .id = id, .result = null, .@"error" = jsonrpc.ErrorObject{
                    .code = errObj.object.get("code").?.integer,
                    .message = errObj.object.get("message").?.string,
                } },
                tree,
            );
        }

        if (tree.root.object.get("result")) |result| {
            if (result == json.Value.null) {
                return jsonrpc.ResponseAlt(?std.StringArrayHashMap([]u64)).init(
                    arena,
                    jsonrpc.ResponsePayload(?std.StringArrayHashMap([]u64)){ .jsonrpc = "2.0", .id = id, .result = null },
                    tree,
                );
            }

            var leaderSchedule = std.StringArrayHashMap([]u64).init(responseAllocator);
            var iter = result.object.iterator();

            while (iter.next()) |entry| {
                var vals = std.ArrayList(u64).init(responseAllocator);
                for (entry.value_ptr.*.array.items) |val| {
                    try vals.append(@as(u64, @intCast(val.integer)));
                }
                try leaderSchedule.put(entry.key_ptr.*, vals.items);
            }

            return jsonrpc.ResponseAlt(?std.StringArrayHashMap([]u64)).init(
                arena,
                jsonrpc.ResponsePayload(?std.StringArrayHashMap([]u64)){ .jsonrpc = "2.0", .id = id, .result = leaderSchedule },
                tree,
            );
        } else {
            return jsonrpc.ResponseAlt(?std.StringArrayHashMap([]u64)).init(
                arena,
                jsonrpc.ResponsePayload(?std.StringArrayHashMap([]u64)){ .jsonrpc = "2.0", .id = id, .result = null },
                tree,
            );
        }
    }

    pub fn getMaxRetransmitSlot(self: *Self) !jsonrpc.Response(u64) {
        return try self.makeRequestWithJRpcResponse(u64, ?u8, "getMaxRetransmitSlot", "1", null);
    }

    pub fn getMaxShredInsertSlot(self: *Self) !jsonrpc.Response(u64) {
        return try self.makeRequestWithJRpcResponse(u64, ?u8, "getMaxShredInsertSlot", "1", null);
    }

    pub fn getMinimumBalanceForRentExemption(self: *Self, size: u64) !jsonrpc.Response(u64) {
        var params = [1]u64{size};
        return try self.makeRequestWithJRpcResponse(u64, []u64, "getMinimumBalanceForRentExemption", "1", &params);
    }

    const GetMultipleAccountsOptions = struct {
        commitment: ?types.Commitment = null,
        encoding: types.Encoding = .Base64,
    };

    pub fn getMultipleAccounts(self: *Self, pubkeys: []Pubkey, options: GetMultipleAccountsOptions) !jsonrpc.Response(types.MultipleAccountsInfo) {
        var optionsObj = std.StringArrayHashMap(json.Value).init(self.allocator);
        defer optionsObj.deinit();
        try optionsObj.put("encoding", .{ .string = options.encoding.string() });
        try optionsObj.put("commitment", .{ .string = self.defaultCommitmentOr(options.commitment).string() });

        var paramsList = std.ArrayList(json.Value).init(self.allocator);
        defer paramsList.deinit();
        var accountsList = std.ArrayList(json.Value).init(self.allocator);
        defer accountsList.deinit();

        for (pubkeys) |pubkey| {
            var str = pubkey.string();

            try accountsList.append(.{ .string = str });
        }
        try paramsList.append(.{ .array = accountsList });
        try paramsList.append(.{ .object = optionsObj });

        var params = .{ .array = paramsList };

        return try self.makeRequestWithJRpcResponse(types.MultipleAccountsInfo, json.Value, "getMultipleAccounts", "1", params);
    }

    pub const DataSlice = struct {
        offset: u64,
        length: u64,
    };

    pub const Filter = struct {
        memcmp: ?struct {
            offset: u64,
            bytes: []const u8,
            // TODO: verify this is the default
            encoding: types.Encoding = .Base58,
        } = null,
        dataSize: ?u64 = null,
    };

    pub const GetProgramAccountsOptions = struct {
        commitment: ?types.Commitment = null,
        /// NOTE: this needs to base64 if want to convert to `core.Account` type
        encoding: types.Encoding = .Base64,
        minContextSlot: ?u64 = null,
        /// NOTE: always true for simplicity
        withContext: bool = true,
        dataSlice: ?DataSlice = null,
        filters: ?[]Filter = null,
    };

    pub fn getProgramAccounts(self: *Self, program: Pubkey, options: GetProgramAccountsOptions) !jsonrpc.Response(types.IdentifiedAccountInfos) {
        var optionsObj = std.StringArrayHashMap(json.Value).init(self.allocator);
        defer optionsObj.deinit();
        try optionsObj.put("encoding", .{ .string = options.encoding.string() });
        try optionsObj.put("commitment", .{ .string = self.defaultCommitmentOr(options.commitment).string() });
        try optionsObj.put("withContext", .{ .bool = true });

        if (options.minContextSlot) |minContextSlot| {
            try optionsObj.put("minContextSlot", .{ .integer = @as(i64, @intCast(minContextSlot)) });
        }

        if (options.dataSlice) |dataSlice| {
            var dataSliceObj = std.StringArrayHashMap(json.Value).init(self.allocator);
            defer dataSliceObj.deinit();
            try dataSliceObj.put("length", .{ .integer = @as(i64, @intCast(dataSlice.length)) });
            try dataSliceObj.put("offset", .{ .integer = @as(i64, @intCast(dataSlice.offset)) });
            try optionsObj.put("dataSlice", .{ .object = dataSliceObj });
        }

        if (options.filters) |filters| {
            var filtersList = std.ArrayList(json.Value).init(self.allocator);
            defer filtersList.deinit();

            for (filters) |filter| {
                var filterObj = std.StringArrayHashMap(json.Value).init(self.allocator);
                defer filterObj.deinit();
                if (filter.memcmp) |memcmp| {
                    var memcmpObj = std.StringArrayHashMap(json.Value).init(self.allocator);
                    defer memcmpObj.deinit();
                    try memcmpObj.put("bytes", .{ .string = memcmp.bytes });
                    try memcmpObj.put("offset", .{ .integer = @as(i64, @intCast(memcmp.offset)) });
                    try memcmpObj.put("encoding", .{ .string = memcmp.encoding.string() });

                    try filterObj.put("memcmp", .{ .object = filterObj });
                } else if (filter.dataSize) |dataSize| {
                    try filterObj.put("dataSize", .{ .integer = @as(i64, @intCast(dataSize)) });
                }

                try filtersList.append(.{ .object = filterObj });
            }

            try optionsObj.put("filters", .{ .array = filtersList });
        }

        var paramsList = std.ArrayList(json.Value).init(self.allocator);
        defer paramsList.deinit();
        var accountsList = std.ArrayList(json.Value).init(self.allocator);
        defer accountsList.deinit();

        var str = program.string();

        try paramsList.append(.{ .string = str });
        try paramsList.append(.{ .object = optionsObj });

        var params = .{ .array = paramsList };

        return try self.makeRequestWithJRpcResponse(types.IdentifiedAccountInfos, json.Value, "getProgramAccounts", "1", params);
    }

    pub fn getRecentPerformanceSamples(self: *Self, limit: ?u64) !jsonrpc.Response([]types.PerformanceSample) {
        var params = [1]?u64{limit};
        return try self.makeRequestWithJRpcResponse([]types.PerformanceSample, []?u64, "getRecentPerformanceSamples", "1", &params);
    }

    pub fn getRecentPrioritizationFees(self: *Self, pubkeys: ?[]Pubkey) !jsonrpc.Response([]types.PrioritizationFeeInfo) {
        var params: ?[][]const u8 = null;

        if (pubkeys) |pks| {
            var accountsList = std.ArrayList([]const u8).init(self.allocator);
            defer accountsList.deinit();

            for (pks) |pubkey| {
                var str = pubkey.string();
                try accountsList.append(str);
            }
            params = accountsList.items[0..];
        }

        return try self.makeRequestWithJRpcResponse([]types.PrioritizationFeeInfo, ?[][]const u8, "getRecentPrioritizationFees", "1", params);
    }

    pub const GetSignaturesForAddressOptions = struct {
        commitment: ?types.Commitment = null,
        minContextSlot: ?u64 = null,
        limit: u32 = 1000,
        before: ?[]const u8 = null,
        until: ?[]const u8 = null,
    };

    pub fn getSignaturesForAddress(self: *Self, pubkey: Pubkey, options: GetSignaturesForAddressOptions) !jsonrpc.Response([]types.SignatureInfo) {
        var optionsObj = std.StringArrayHashMap(json.Value).init(self.allocator);
        defer optionsObj.deinit();
        try optionsObj.put("commitment", .{ .string = self.defaultCommitmentOr(options.commitment).string() });
        try optionsObj.put("limit", .{ .integer = @as(i64, options.limit) });

        if (options.minContextSlot) |minContextSlot| {
            try optionsObj.put("minContextSlot", .{ .integer = @as(i64, @intCast(minContextSlot)) });
        }

        if (options.before) |before| {
            try optionsObj.put("before", .{ .string = before });
        }

        if (options.until) |until| {
            try optionsObj.put("minContextSlot", .{ .string = until });
        }

        var paramsList = std.ArrayList(json.Value).init(self.allocator);
        defer paramsList.deinit();

        var str = pubkey.string();

        try paramsList.append(.{ .string = str });
        try paramsList.append(.{ .object = optionsObj });
        var params = json.Value{ .array = paramsList };
        return try self.makeRequestWithJRpcResponse([]types.SignatureInfo, json.Value, "getSignaturesForAddress", "1", params);
    }

    const GetSignatureStatusesOptions = struct {
        searchTransactionHistory: bool = false,
    };

    pub fn getSignatureStatuses(self: *Self, signatures: [][]const u8, options: GetSignatureStatusesOptions) !jsonrpc.Response(types.SignatureStatusesInfo) {
        var optionsObj = std.StringArrayHashMap(json.Value).init(self.allocator);
        defer optionsObj.deinit();
        try optionsObj.put("searchTransactionHistory", .{ .bool = options.searchTransactionHistory });

        var sigsList = std.ArrayList(json.Value).init(self.allocator);
        defer sigsList.deinit();
        for (signatures) |signature| {
            try sigsList.append(.{ .string = signature });
        }

        var paramsList = std.ArrayList(json.Value).init(self.allocator);
        defer paramsList.deinit();

        try paramsList.append(.{ .array = sigsList });
        try paramsList.append(.{ .object = optionsObj });

        var params = json.Value{ .array = paramsList };
        return try self.makeRequestWithJRpcResponse(types.SignatureStatusesInfo, json.Value, "getSignatureStatuses", "1", params);
    }

    const GetSlotLeaderOptions = struct {
        commitment: ?types.Commitment = null,
        minContextSlot: ?u64 = null,
    };

    pub fn getSlotLeader(self: *Self, options: GetSlotLeaderOptions) !jsonrpc.Response([]const u8) {
        var optionsObj = std.StringArrayHashMap(json.Value).init(self.allocator);
        defer optionsObj.deinit();
        try optionsObj.put("commitment", .{ .string = self.defaultCommitmentOr(options.commitment).string() });
        if (options.minContextSlot) |minContextSlot| {
            try optionsObj.put("minContextSlot", .{ .integer = @as(i64, @intCast(minContextSlot)) });
        }

        var paramsList = std.ArrayList(json.Value).init(self.allocator);
        defer paramsList.deinit();

        try paramsList.append(.{ .object = optionsObj });

        var params = json.Value{ .array = paramsList };
        return try self.makeRequestWithJRpcResponse([]const u8, json.Value, "getSlotLeader", "1", params);
    }

    pub fn getSlotLeaders(self: *Self, startSlot: u64, limit: u64) !jsonrpc.Response([][]const u8) {
        var paramsList = std.ArrayList(json.Value).init(self.allocator);
        defer paramsList.deinit();

        try paramsList.append(.{ .integer = @as(i64, @intCast(startSlot)) });
        try paramsList.append(.{ .integer = @as(i64, @intCast(limit)) });

        var params = json.Value{ .array = paramsList };
        return try self.makeRequestWithJRpcResponse([][]const u8, json.Value, "getSlotLeaders", "1", params);
    }

    pub const GetStakeActivationOptions = struct {
        commitment: ?types.Commitment = null,
        minContextSlot: ?u64 = null,
        epoch: ?u64 = null,
    };

    pub fn getStakeActivation(self: *Self, pubkey: Pubkey, options: GetStakeActivationOptions) !jsonrpc.Response(types.StakeActivation) {
        var optionsObj = std.StringArrayHashMap(json.Value).init(self.allocator);
        defer optionsObj.deinit();
        try optionsObj.put("commitment", .{ .string = self.defaultCommitmentOr(options.commitment).string() });
        if (options.minContextSlot) |minContextSlot| {
            try optionsObj.put("minContextSlot", .{ .integer = @as(i64, @intCast(minContextSlot)) });
        }
        if (options.epoch) |epoch| {
            try optionsObj.put("epoch", .{ .integer = @as(i64, @intCast(epoch)) });
        }

        var paramsList = std.ArrayList(json.Value).init(self.allocator);
        defer paramsList.deinit();

        var str = pubkey.string();

        try paramsList.append(.{ .string = str });
        try paramsList.append(.{ .object = optionsObj });

        var params = json.Value{ .array = paramsList };
        return try self.makeRequestWithJRpcResponse(types.StakeActivation, json.Value, "getStakeActivation", "1", params);
    }

    const GetStakeMinimumDelegationOptions = struct {
        commitment: ?types.Commitment = null,
    };

    pub fn getStakeMinimumDelegation(self: *Self, options: GetStakeMinimumDelegationOptions) !jsonrpc.Response(types.StakeMinimumDelegationInfo) {
        var optionsObj = std.StringArrayHashMap(json.Value).init(self.allocator);
        defer optionsObj.deinit();
        try optionsObj.put("commitment", .{ .string = self.defaultCommitmentOr(options.commitment).string() });

        var paramsList = std.ArrayList(json.Value).init(self.allocator);
        defer paramsList.deinit();
        try paramsList.append(.{ .object = optionsObj });

        var params = json.Value{ .array = paramsList };
        return try self.makeRequestWithJRpcResponse(types.StakeMinimumDelegationInfo, json.Value, "getStakeMinimumDelegation", "1", params);
    }

    const GetSupplyOptions = struct {
        commitment: ?types.Commitment = null,
        excludeNonCirculatingAccountsList: ?bool = null,
    };

    pub fn getSupply(self: *Self, options: GetSupplyOptions) !jsonrpc.Response(types.SupplyInfo) {
        var optionsObj = std.StringArrayHashMap(json.Value).init(self.allocator);
        defer optionsObj.deinit();
        try optionsObj.put("commitment", .{ .string = self.defaultCommitmentOr(options.commitment).string() });
        if (options.excludeNonCirculatingAccountsList) |excludeNonCirculatingAccountsList| {
            try optionsObj.put("excludeNonCirculatingAccountsList", .{ .bool = excludeNonCirculatingAccountsList });
        }

        var paramsList = std.ArrayList(json.Value).init(self.allocator);
        defer paramsList.deinit();
        try paramsList.append(.{ .object = optionsObj });

        var params = json.Value{ .array = paramsList };
        return try self.makeRequestWithJRpcResponse(types.SupplyInfo, json.Value, "getSupply", "1", params);
    }

    const GetTokenAccountBalanceOptions = struct {
        commitment: ?types.Commitment = null,
    };

    pub fn getTokenAccountBalance(self: *Self, pubkey: Pubkey, options: GetTokenAccountBalanceOptions) !jsonrpc.Response(types.TokenAccountBalanceInfo) {
        var optionsObj = std.StringArrayHashMap(json.Value).init(self.allocator);
        defer optionsObj.deinit();
        try optionsObj.put("commitment", .{ .string = self.defaultCommitmentOr(options.commitment).string() });

        var paramsList = std.ArrayList(json.Value).init(self.allocator);
        defer paramsList.deinit();

        var str = pubkey.string();

        try paramsList.append(.{ .string = str });
        try paramsList.append(.{ .object = optionsObj });

        var params = json.Value{ .array = paramsList };
        return try self.makeRequestWithJRpcResponse(types.TokenAccountBalanceInfo, json.Value, "getTokenAccountBalance", "1", params);
    }

    const GetTokenAccountsByDelegateOptions = struct {
        commitment: ?types.Commitment = null,
        encoding: types.Encoding = .Base64,
        minContextSlot: ?u64 = null,
        dataSlice: ?DataSlice = null,
    };

    const MintOrProgramIdParam = struct {
        mint: ?Pubkey = null,
        programId: ?Pubkey = null,
    };

    pub fn getTokenAccountsByDelegate(self: *Self, pubkey: Pubkey, mintOrProgramId: MintOrProgramIdParam, options: GetTokenAccountsByDelegateOptions) !jsonrpc.Response([]types.IdentifiedAccountInfos) {
        var optionsObj = std.StringArrayHashMap(json.Value).init(self.allocator);
        defer optionsObj.deinit();
        try optionsObj.put("commitment", .{ .string = self.defaultCommitmentOr(options.commitment).string() });
        try optionsObj.put("encoding", .{ .string = options.encoding.string() });

        if (options.minContextSlot) |minContextSlot| {
            try optionsObj.put("minContextSlot", .{ .integer = @as(i64, @intCast(minContextSlot)) });
        }

        if (options.dataSlice) |dataSlice| {
            var dataSliceObj = std.StringArrayHashMap(json.Value).init(self.allocator);
            defer dataSliceObj.deinit();
            try dataSliceObj.put("length", .{ .integer = @as(i64, @intCast(dataSlice.length)) });
            try dataSliceObj.put("offset", .{ .integer = @as(i64, @intCast(dataSlice.offset)) });
            try optionsObj.put("dataSlice", .{ .object = dataSliceObj });
        }

        var mintOrPubkeyObj = std.StringArrayHashMap(json.Value).init(self.allocator);
        defer mintOrPubkeyObj.deinit();
        if (mintOrProgramId.mint) |mint| {
            var str = mint.string();

            try mintOrPubkeyObj.put("mint", .{ .string = str });
        } else if (mintOrProgramId.programId) |programId| {
            var str = programId.string();

            try mintOrPubkeyObj.put("programId", .{ .string = str });
        }

        var paramsList = std.ArrayList(json.Value).init(self.allocator);
        defer paramsList.deinit();

        var str = pubkey.string();

        try paramsList.append(.{ .string = str });
        try paramsList.append(.{ .object = mintOrPubkeyObj });
        try paramsList.append(.{ .object = optionsObj });

        var params = json.Value{ .array = paramsList };
        return try self.makeRequestWithJRpcResponse([]types.IdentifiedAccountInfos, json.Value, "getTokenAccountsByDelegate", "1", params);
    }

    const GetTokenAccountsByOwnerOptions = struct {
        commitment: ?types.Commitment = null,
        encoding: types.Encoding = .Base64,
        minContextSlot: ?u64 = null,
        dataSlice: ?DataSlice = null,
    };

    pub fn getTokenAccountsByOwner(self: *Self, pubkey: Pubkey, mintOrProgramId: MintOrProgramIdParam, options: GetTokenAccountsByDelegateOptions) !jsonrpc.Response(types.IdentifiedAccountInfos) {
        var optionsObj = std.StringArrayHashMap(json.Value).init(self.allocator);
        defer optionsObj.deinit();
        try optionsObj.put("commitment", .{ .string = self.defaultCommitmentOr(options.commitment).string() });
        try optionsObj.put("encoding", .{ .string = options.encoding.string() });

        if (options.minContextSlot) |minContextSlot| {
            try optionsObj.put("minContextSlot", .{ .integer = @as(i64, @intCast(minContextSlot)) });
        }

        if (options.dataSlice) |dataSlice| {
            var dataSliceObj = std.StringArrayHashMap(json.Value).init(self.allocator);
            defer dataSliceObj.deinit();
            try dataSliceObj.put("length", .{ .integer = @as(i64, @intCast(dataSlice.length)) });
            try dataSliceObj.put("offset", .{ .integer = @as(i64, @intCast(dataSlice.offset)) });
            try optionsObj.put("dataSlice", .{ .object = dataSliceObj });
        }

        var mintOrPubkeyObj = std.StringArrayHashMap(json.Value).init(self.allocator);
        defer mintOrPubkeyObj.deinit();
        if (mintOrProgramId.mint) |mint| {
            var str = mint.string();

            try mintOrPubkeyObj.put("mint", .{ .string = str });
        } else if (mintOrProgramId.programId) |programId| {
            var str = programId.string();

            try mintOrPubkeyObj.put("programId", .{ .string = str });
        }

        var paramsList = std.ArrayList(json.Value).init(self.allocator);
        defer paramsList.deinit();

        var str = pubkey.string();

        try paramsList.append(.{ .string = str });
        try paramsList.append(.{ .object = mintOrPubkeyObj });
        try paramsList.append(.{ .object = optionsObj });

        var params = json.Value{ .array = paramsList };
        return try self.makeRequestWithJRpcResponse(types.IdentifiedAccountInfos, json.Value, "getTokenAccountsByOwner", "1", params);
    }

    const GetTokenLargestAccountsOptions = struct {
        commitment: ?types.Commitment = null,
    };

    pub fn getTokenLargestAccounts(self: *Self, mint: Pubkey, options: GetTokenLargestAccountsOptions) !jsonrpc.Response(types.TokenAccountBalanceInfos) {
        var optionsObj = std.StringArrayHashMap(json.Value).init(self.allocator);
        defer optionsObj.deinit();
        try optionsObj.put("commitment", .{ .string = self.defaultCommitmentOr(options.commitment).string() });

        var paramsList = std.ArrayList(json.Value).init(self.allocator);
        defer paramsList.deinit();

        var str = mint.string();

        try paramsList.append(.{ .string = str });
        try paramsList.append(.{ .object = optionsObj });

        var params = json.Value{ .array = paramsList };
        return try self.makeRequestWithJRpcResponse(types.TokenAccountBalanceInfos, json.Value, "getTokenLargestAccounts", "1", params);
    }

    const GetTokenSupplyOptions = struct {
        commitment: ?types.Commitment = null,
    };

    pub fn getTokenSupply(self: *Self, mint: Pubkey, options: GetTokenSupplyOptions) !jsonrpc.Response(types.TokenAccountBalanceInfo) {
        var optionsObj = std.StringArrayHashMap(json.Value).init(self.allocator);
        defer optionsObj.deinit();
        try optionsObj.put("commitment", .{ .string = self.defaultCommitmentOr(options.commitment).string() });

        var paramsList = std.ArrayList(json.Value).init(self.allocator);
        defer paramsList.deinit();
        try paramsList.append(.{ .string = mint.string() });
        try paramsList.append(.{ .object = optionsObj });

        var params = json.Value{ .array = paramsList };
        return try self.makeRequestWithJRpcResponse(types.TokenAccountBalanceInfo, json.Value, "getTokenSupply", "1", params);
    }

    const GetTransactionOptions = struct {
        commitment: ?types.Commitment = null,
        maxSupportedTransactionVersion: u8 = 0,
        /// NOTE: must be Json for now
        encoding: types.Encoding = .Json,
    };

    pub fn getTransaction(self: *Self, signature: []const u8, options: GetTransactionOptions) !jsonrpc.Response(types.Transaction) {
        var optionsObj = std.StringArrayHashMap(json.Value).init(self.allocator);
        defer optionsObj.deinit();
        try optionsObj.put("commitment", .{ .string = self.defaultCommitmentOr(options.commitment).string() });
        try optionsObj.put("encoding", .{ .string = options.encoding.string() });
        try optionsObj.put("maxSupportedTransactionVersion", .{ .integer = @as(i64, options.maxSupportedTransactionVersion) });

        var paramsList = std.ArrayList(json.Value).init(self.allocator);
        defer paramsList.deinit();
        try paramsList.append(.{ .string = signature });
        try paramsList.append(.{ .object = optionsObj });

        var params = json.Value{ .array = paramsList };
        return try self.makeRequestWithJRpcResponse(types.Transaction, json.Value, "getTransaction", "1", params);
    }

    const GetTransactionCountOptions = struct {
        commitment: ?types.Commitment = null,
        minContextSlot: ?u64 = null,
    };

    pub fn getTransactionCount(self: *Self, options: GetTransactionCountOptions) !jsonrpc.Response(u64) {
        var optionsObj = std.StringArrayHashMap(json.Value).init(self.allocator);
        defer optionsObj.deinit();
        try optionsObj.put("commitment", .{ .string = self.defaultCommitmentOr(options.commitment).string() });
        if (options.minContextSlot) |minContextSlot| {
            try optionsObj.put("minContextSlot", .{ .integer = @as(i64, @intCast(minContextSlot)) });
        }

        var paramsList = std.ArrayList(json.Value).init(self.allocator);
        defer paramsList.deinit();
        try paramsList.append(.{ .object = optionsObj });

        var params = json.Value{ .array = paramsList };
        return try self.makeRequestWithJRpcResponse(u64, json.Value, "getTransactionCount", "1", params);
    }

    pub fn getVersion(self: *Self) !jsonrpc.Response(types.VersionInfo) {
        return try self.makeRequestWithJRpcResponse(types.VersionInfo, ?u8, "getVersion", "1", null);
    }

    const GetVoteAccountsOptions = struct {
        commitment: ?types.Commitment = null,
        votePubkey: ?Pubkey = null,
        keepUnstakedDelinquents: ?bool = false,
        delinquentSlotDistance: ?u64 = 0,
    };

    pub fn getVoteAccounts(self: *Self, options: GetVoteAccountsOptions) !jsonrpc.Response(types.VoteAccountsInfo) {
        var optionsObj = std.StringArrayHashMap(json.Value).init(self.allocator);
        defer optionsObj.deinit();
        try optionsObj.put("commitment", .{ .string = self.defaultCommitmentOr(options.commitment).string() });
        if (options.votePubkey) |votePubkey| {
            var str = votePubkey.string();
            try optionsObj.put("votePubkey", .{ .string = str });
        }
        if (options.keepUnstakedDelinquents) |keepUnstakedDelinquents| {
            try optionsObj.put("keepUnstakedDelinquents", .{ .bool = keepUnstakedDelinquents });
        }
        if (options.delinquentSlotDistance) |delinquentSlotDistance| {
            try optionsObj.put("delinquentSlotDistance", .{ .integer = @as(i64, @intCast(delinquentSlotDistance)) });
        }

        var paramsList = std.ArrayList(json.Value).init(self.allocator);
        defer paramsList.deinit();
        try paramsList.append(.{ .object = optionsObj });

        var params = json.Value{ .array = paramsList };
        return try self.makeRequestWithJRpcResponse(types.VoteAccountsInfo, json.Value, "getVoteAccounts", "1", params);
    }

    pub const IsBlockhashValidOptions = struct {
        commitment: ?types.Commitment = null,
        minContextSlot: ?u64 = null,
    };

    pub fn isBlockhashValid(self: *Self, blockhash: []const u8, options: IsBlockhashValidOptions) !jsonrpc.Response(types.BlockhashInfo) {
        var optionsObj = std.StringArrayHashMap(json.Value).init(self.allocator);
        defer optionsObj.deinit();
        try optionsObj.put("commitment", .{ .string = self.defaultCommitmentOr(options.commitment).string() });

        if (options.minContextSlot) |minContextSlot| {
            try optionsObj.put("minContextSlot", .{ .integer = @as(i64, @intCast(minContextSlot)) });
        }

        var paramsList = std.ArrayList(json.Value).init(self.allocator);
        defer paramsList.deinit();

        try paramsList.append(.{ .string = blockhash });
        try paramsList.append(.{ .object = optionsObj });

        var params = json.Value{ .array = paramsList };
        return try self.makeRequestWithJRpcResponse(types.BlockhashInfo, json.Value, "isBlockhashValid", "1", params);
    }

    pub fn minimumLedgerSlot(self: *Self) !jsonrpc.Response(u64) {
        return try self.makeRequestWithJRpcResponse(u64, ?u8, "minimumLedgerSlot", "1", null);
    }

    const RequestAirdropOptions = struct {
        commitment: ?types.Commitment = null,
    };

    pub fn requestAirdrop(self: *Self, pubkey: Pubkey, lamports: u64, options: RequestAirdropOptions) !jsonrpc.Response([]const u8) {
        var optionsObj = std.StringArrayHashMap(json.Value).init(self.allocator);
        defer optionsObj.deinit();
        try optionsObj.put("commitment", .{ .string = self.defaultCommitmentOr(options.commitment).string() });

        var paramsList = std.ArrayList(json.Value).init(self.allocator);
        defer paramsList.deinit();

        var str = pubkey.string();

        try paramsList.append(.{ .string = str });
        try paramsList.append(.{ .integer = @as(i64, @intCast(lamports)) });
        try paramsList.append(.{ .object = optionsObj });

        var params = json.Value{ .array = paramsList };
        return try self.makeRequestWithJRpcResponse([]const u8, json.Value, "requestAirdrop", "1", params);
    }

    const SendTransactionOptions = struct {
        preflightCommitment: types.Commitment = .Finalized,
        /// NOTE: must be base64 for now
        encoding: types.Encoding = .Base64,
        skipPreflight: ?bool = null,
        maxRetries: ?u8 = null,
        minContextSlot: ?u64 = null,
    };

    pub fn sendTransaction(self: *Self, payload: []const u8, options: SendTransactionOptions) !jsonrpc.Response([]const u8) {
        var optionsObj = std.StringArrayHashMap(json.Value).init(self.allocator);
        defer optionsObj.deinit();
        try optionsObj.put("preflightCommitment", .{ .string = options.preflightCommitment.string() });
        try optionsObj.put("encoding", .{ .string = options.encoding.string() });

        if (options.skipPreflight) |skipPreflight| {
            try optionsObj.put("skipPreflight", .{ .bool = skipPreflight });
        }

        if (options.maxRetries) |maxRetries| {
            try optionsObj.put("maxRetries", .{ .integer = @as(i64, maxRetries) });
        }

        if (options.minContextSlot) |minContextSlot| {
            try optionsObj.put("minContextSlot", .{ .integer = @as(i64, @intCast(minContextSlot)) });
        }

        var paramsList = std.ArrayList(json.Value).init(self.allocator);
        defer paramsList.deinit();

        try paramsList.append(.{ .string = payload });
        try paramsList.append(.{ .object = optionsObj });

        var params = json.Value{ .array = paramsList };
        return try self.makeRequestWithJRpcResponse([]const u8, json.Value, "sendTransaction", "1", params);
    }

    const SimulateTransactionOptions = struct {
        commitment: ?types.Commitment = null,
        /// NOTE: must be base64 for now
        encoding: types.Encoding = .Base64,
        sigVerify: ?bool = null,
        replaceRecentBlockhash: ?[]const u8 = null,
        minContextSlot: ?u64 = null,
        accounts: ?struct {
            addresses: []Pubkey,
            /// NOTE: must be base64 for now
            encoding: types.Encoding = .Base64,
        } = null,
    };

    pub fn simulateTransaction(self: *Self, payload: []const u8, options: SimulateTransactionOptions) !jsonrpc.Response(types.SimulatedTransactionInfo) {
        var optionsObj = std.StringArrayHashMap(json.Value).init(self.allocator);
        defer optionsObj.deinit();
        try optionsObj.put("commitment", .{ .string = self.defaultCommitmentOr(options.commitment).string() });
        try optionsObj.put("encoding", .{ .string = options.encoding.string() });

        if (options.sigVerify) |sigVerify| {
            try optionsObj.put("sigVerify", .{ .bool = sigVerify });
        }

        if (options.replaceRecentBlockhash) |replaceRecentBlockhash| {
            try optionsObj.put("replaceRecentBlockhash", .{ .string = replaceRecentBlockhash });
        }

        if (options.minContextSlot) |minContextSlot| {
            try optionsObj.put("minContextSlot", .{ .integer = @as(i64, @intCast(minContextSlot)) });
        }

        if (options.accounts) |accounts| {
            var accountsObj = std.StringArrayHashMap(json.Value).init(self.allocator);
            defer accountsObj.deinit();

            var addressesList = std.ArrayList(json.Value).init(self.allocator);
            defer addressesList.deinit();

            for (accounts.addresses) |address| {
                var str = address.string();

                try addressesList.append(.{ .string = str });
            }

            try accountsObj.put("addresses", .{ .array = addressesList });
            try accountsObj.put("encoding", .{ .string = accounts.encoding.string() });

            try optionsObj.put("accounts", .{ .object = accountsObj });
        }

        var paramsList = std.ArrayList(json.Value).init(self.allocator);
        defer paramsList.deinit();

        try paramsList.append(.{ .string = payload });
        try paramsList.append(.{ .object = optionsObj });

        var params = json.Value{ .array = paramsList };
        return try self.makeRequestWithJRpcResponse(types.SimulatedTransactionInfo, json.Value, "simulateTransaction", "1", params);
    }
};

// Tests:

const TestError = error{
    SkipZigTest,
};

test "client should create successfully" {
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();
}

test "client should accept custom headers" {
    var customHeaders = [_][2][]const u8{.{ "Cache-Control", "no-cache" }};
    var client = try Client.init(testing.allocator, .{
        .http_endpoint = HTTP_ENDPOINT,
        .http_headers = &customHeaders,
    });
    defer client.deinit();
}

test "client should not accept bad headers" {
    var customHeaders = [_][2][]const u8{.{ "Cache-Control", "" }};
    try testing.expectError(Error.InvalidHttpHeaders, Client.init(testing.allocator, .{
        .http_endpoint = HTTP_ENDPOINT,
        .http_headers = &customHeaders,
    }));
}

test "pubkey equality works" {
    var pubkey1 = try Pubkey.fromString("4rL4RCWHz3iNCdCaveD8KcHfV9YWGsqSHFPo7X2zBNwa");
    var pubkey1Again = try Pubkey.fromString("4rL4RCWHz3iNCdCaveD8KcHfV9YWGsqSHFPo7X2zBNwa");
    var pubkeyOther = try Pubkey.fromString("Bvg7GuhqwNmV2JVyeZjhAcTPFqPktfmq25VBaZipozda");

    try testing.expect(pubkey1.equals(&pubkey1Again));
    try testing.expect(!pubkey1.equals(&pubkeyOther));
}

test "pubkey randome works" {
    var seed: u64 = @intCast(std.time.milliTimestamp());
    var rand = std.rand.DefaultPrng.init(seed);
    const rng = rand.random();

    var pubkey = Pubkey.random(rng);
    var pubkey_2 = Pubkey.random(rng);
    try testing.expect(!pubkey_2.equals(&pubkey));
}

test "make 'getAccountInfo' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    const pubkey = try Pubkey.fromString("4rL4RCWHz3iNCdCaveD8KcHfV9YWGsqSHFPo7X2zBNwa");

    var resp = try client.getAccountInfo(pubkey, .{ .encoding = .Base64 });
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("Account info: {any}", .{resp.result().value.data});
}

test "make 'getBalance' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    const pubkey = try Pubkey.fromString("4rL4RCWHz3iNCdCaveD8KcHfV9YWGsqSHFPo7X2zBNwa");

    var resp = try client.getBalance(pubkey);
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("balance info: {any}", .{resp.result().value});
}

test "make 'getBlockHeight' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getBlockHeight();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("block height: {any}", .{resp.result()});
}

test "make 'getBlock' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getBlock(500, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("block info: {any}", .{resp.result()});
}

test "make 'getBlockProduction' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    testing.log_level = std.log.Level.debug;
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getBlockProduction(.{ .identity = "1EWZm7aZYxfZHbyiELXtTgN1yT2vU1HF9d8DWswX2Tp" });
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("block production info: {any}", .{resp.result()});
}

test "make 'getBlockCommitment' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getBlockCommitment(400);
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("block commitment info: {any}", .{resp.result()});
}

test "make 'getBlocks' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getBlocks(400, 500, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("blocks: {any}", .{resp.result()});
}

test "make 'getBlocksWithLimit' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getBlocksWithLimit(400, 25, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("blocks: {any}", .{resp.result()});
}

test "make 'getBlockTime' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getBlockTime(163954396);
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("block time: {any}", .{resp.result()});
}

test "make 'getClusterNodes' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getClusterNodes();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("cluster nodes: {any}", .{resp.result()});
}

test "make 'getEpochInfo' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getEpochInfo(.{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("epoch info: {any}", .{resp.result()});
}

test "make 'getEpochSchedule' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getEpochSchedule();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("epoch schedule: {any}", .{resp.result()});
}

test "make 'getFeeForMessage' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getFeeForMessage("AQABAgIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEBAQAA", .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("message fee info: {any}", .{resp.result()});
}

test "make 'getFirstAvailableBlock' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getFirstAvailableBlock();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("first available block: {any}", .{resp.result()});
}

test "make 'getGenesisHash' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getGenesisHash();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("genesis hash: {any}", .{resp.result()});
}

test "make 'getHealth' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getHealth();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("health: {any}", .{resp.result()});
}

test "make 'getHighestSnapshotSlot' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getHighestSnapshotSlot();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("snapshot info: {any}", .{resp.result()});
}

test "make 'getIdentity' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getIdentity();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("indentity info: {any}", .{resp.result()});
}

test "make 'getInflationGovernor' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getInflationGovernor(.{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("inflation info: {any}", .{resp.result()});
}

test "make 'getInflationRate' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getInflationRate();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("inflation rate: {any}", .{resp.result()});
}

test "make 'getInflationReward' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var accounts = [2]Pubkey{
        Pubkey.fromString(
            "6dmNQ5jwLeLk5REvio1JcMshcbvkYMwy26sJ8pbkvStu",
        ) catch unreachable,
        Pubkey.fromString(
            "BGsqMegLpV6n6Ve146sSX2dTjUMj3M92HnU8BbNRMhF2",
        ) catch unreachable,
    };
    var resp = try client.getInflationReward(&accounts, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("inflation reward info: {any}", .{resp.result()});
}

test "make 'getLargestAccounts' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getLargestAccounts(.{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("largest accounts: {any}", .{resp.result()});
}

test "make 'getLatestBlockhash' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getLatestBlockhash(.{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("latest blockhash: {any}", .{resp.result()});
}

test "make 'getLeaderSchedule' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getLeaderSchedule(null, .{ .identity = "GRmtMtAeSL8HgX1p815ATQjaYU4Sk7XCP21i4yoFd3KS" });
    // defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("leader schedule: {any}", .{resp.result()});
}

test "make 'getMaxRetransmitSlot' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getMaxRetransmitSlot();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("max retransmit slot: {any}", .{resp.result()});
}

test "make 'getMaxShredInsertSlot' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getMaxShredInsertSlot();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("max shred insert slot: {any}", .{resp.result()});
}

test "make 'getMinimumBalanceForRentExemption' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getMinimumBalanceForRentExemption(1000);
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("minimum balance: {any}", .{resp.result()});
}

test "make 'getMultipleAccounts' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var accounts2 = [2]Pubkey{
        try Pubkey.fromString(
            "4rL4RCWHz3iNCdCaveD8KcHfV9YWGsqSHFPo7X2zBNwa",
        ),
        try Pubkey.fromString(
            "BGsqMegLpV6n6Ve146sSX2dTjUMj3M92HnU8BbNRMhF2",
        ),
    };
    var resp = try client.getMultipleAccounts(&accounts2, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("multiple accounts: {any}", .{resp.result()});
}

test "make 'getProgramAccounts' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var filters = [1]Client.Filter{.{ .memcmp = .{ .offset = 0, .bytes = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v" } }};
    var resp = try client.getProgramAccounts(
        try Pubkey.fromString("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
        .{ .filters = &filters },
    );
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("program accounts: {any}", .{resp.result()});
}

test "make 'getRecentPerformanceSamples' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getRecentPerformanceSamples(null);
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("recent performance samples: {any}", .{resp.result()});
}

test "make 'getRecentPrioritizationFees' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getRecentPrioritizationFees(null);
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("recent prioritization fees: {any}", .{resp.result()});
}

test "make 'getSignaturesForAddress' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getSignaturesForAddress(try Pubkey.fromString("4rL4RCWHz3iNCdCaveD8KcHfV9YWGsqSHFPo7X2zBNwa"), .{ .limit = 10 });
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("signatures: {any}", .{resp.result()});
}

test "make 'getSignatureStatuses' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var signatures = [2][]const u8{
        "3oK4vMqnRbLhdNVq9Cb81JwHim4QaxvgcNEyA4jTySFFtFtBhJgmLwT3rMFAGakKHE9iMiymVNZsTbnrzNjuxXJc",
        "5fqHdfeY1GbshDFzTdybqDbR3mwj5tkgHEP28dFWFZDcvQkkJUynVWrsfMYip8SsfAaFYTFmRdeC3K1CQRC7Ukkb",
    };
    var resp = try client.getSignatureStatuses(&signatures, .{ .searchTransactionHistory = true });
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("signature statuses: {any}", .{resp.result()});
}

test "make 'getSlotLeader' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getSlotLeader(.{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("slot leader: {any}", .{resp.result()});
}

test "make 'getSlotLeaders' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getSlotLeaders(193536000, 10);
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("slot leaders: {any}", .{resp.result()});
}

test "make 'getStakeActivation' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getStakeActivation(try Pubkey.fromString(
        "CWrKSEDYhj6VHGocZowq2BUncKESqD7rdLTSrsoasTjU",
    ), .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("stake activation: {any}", .{resp.result()});
}

test "make 'getStakeMinimumDelegation' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getStakeMinimumDelegation(.{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("min stake delegation: {any}", .{resp.result()});
}

test "make 'getSupply' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getSupply(.{ .excludeNonCirculatingAccountsList = false });
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("get supply: {any}", .{resp.result()});
}

test "make 'getTokenAccountBalance' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var pubkey = try Pubkey.fromString(
        "6A5NHCj1yF6urc9wZNe6Bcjj4LVszQNj5DwAWG97yzMu",
    );
    var resp = try client.getTokenAccountBalance(pubkey, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("token account balance: {any}", .{resp.result()});
}

test "make 'getTokenAccountsByDelegate' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var programPubkey = try Pubkey.fromString(
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
    );
    var pubkey = try Pubkey.fromString(
        "CTz5UMLQm2SRWHzQnU62Pi4yJqbNGjgRBHqqp6oDHfF7",
    );
    var resp = try client.getTokenAccountsByDelegate(pubkey, .{ .programId = programPubkey }, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("token accounts: {any}", .{resp.result()});
}

test "make 'getTokenAccountsByOwner' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var mintPubkey = try Pubkey.fromString(
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    );
    var pubkey = try Pubkey.fromString(
        "CTz5UMLQm2SRWHzQnU62Pi4yJqbNGjgRBHqqp6oDHfF7",
    );
    var resp = try client.getTokenAccountsByOwner(pubkey, .{ .mint = mintPubkey }, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("token accounts: {any}", .{resp.result()});
}

test "make 'getTokenLargestAccounts' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var mintPubkey = try Pubkey.fromString(
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    );
    var resp = try client.getTokenLargestAccounts(mintPubkey, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("token largest accounts: {any}", .{resp.result()});
}

test "make 'getTokenSupply' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var mintPubkey = try Pubkey.fromString(
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    );
    var resp = try client.getTokenSupply(mintPubkey, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("token supply: {any}", .{resp.result()});
}

test "make 'getTransaction' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var txSig = "5UfDuX7WXY18keiz9mZ6zKkY8JyNuLDFz2QycQcr7skRkgVaNmo6tgFbsePRrX5C6crvycJ2A3txSdGgjPHvPbTZ";
    var resp = try client.getTransaction(txSig, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("transaction: {any}", .{resp.result()});
}

test "make 'getTransactionCount' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getTransactionCount(.{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("transaction count: {any}", .{resp.result()});
}

test "make 'getVersion' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getVersion();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("version: {any}", .{resp.result()});
}

test "make 'getVoteAccounts' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var votePubkey = try Pubkey.fromString(
        "CertusDeBmqN8ZawdkxK5kFGMwBXdudvWHYwtNgNhvLu",
    );
    var resp = try client.getVoteAccounts(.{ .votePubkey = votePubkey });
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("vote accounts: {any}", .{resp.result()});
}

test "make 'isBlockhashValid' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.isBlockhashValid("AaPs8sYJjnDLMMAADYj2fPyDyNzp9to9v4J6c5gevxpX", .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("blockhash valid: {any}", .{resp.result()});
}

test "make 'minimumLedgerSlot' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.minimumLedgerSlot();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("minimum ledger slot: {any}", .{resp.result()});
}

test "make 'requestAirdrop' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var pubkey = try Pubkey.fromString(
        "Bvg7GuhqwNmV2JVyeZjhAcTPFqPktfmq25VBaZipozda",
    );
    var resp = try client.requestAirdrop(pubkey, 10000, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("airdrop result: {any}", .{resp.result()});
}

test "make 'sendTransaction' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.sendTransaction(
        "4hXTCkRzt9WyecNzV1XPgCDfGAZzQKNxLXgynz5QDuWWPSAZBZSHptvWRL3BjCvzUXRdKvHL2b7yGrRQcWyaqsaBCncVG7BFggS8w9snUts67BSh3EqKpXLUm5UMHfD7ZBe9GhARjbNQMLJ1QD3Spr6oMTBU6EhdB4RD8CP2xUxr2u3d6fos36PD98XS6oX8TQjLpsMwncs5DAMiD4nNnR8NBfyghGCWvCVifVwvA8B8TJxE1aiyiv2L429BCWfyzAme5sZW8rDb14NeCQHhZbtNqfXhcp2tAnaAT",
        .{},
    );
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("tx signature: {any}", .{resp.result()});
}

test "make 'simulateTransaction' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try Client.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.simulateTransaction(
        "AdYOLBh+RlElmqIY08YZ4OvkWzmGz5ccQLKOENWccchuSluWO7ZTy6B4x/A/WJAFvSFfUhXEcG/PZajL5EmZBQMBAAEDb3Q4CUF/hTg/MgAsYv45KRoWu+9GafjMndSktv5KzQ3fydC+bF4RL7cMFn8iCnd9sKVJp3K3PwOxVZ3agBBUWAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAjkczsB8wv5yFAgAKUdvb4irHybi2IEEHJcAJrfdhMfgBAgIAAQwCAAAAgJaYAAAAAAA=",
        .{},
    );
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("simulate tx info: {any}", .{resp.result()});
}
