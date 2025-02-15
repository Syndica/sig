const std = @import("std");
const sig = @import("../sig.zig");
const base58 = @import("base58");

const types = sig.rpc.types;

const Slot = sig.core.Slot;
const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;
const Request = sig.rpc.Request;
const Response = sig.rpc.Response;
const Logger = sig.trace.log.Logger;
const ScopedLogger = sig.trace.log.ScopedLogger;
const Transaction = sig.core.Transaction;
const ClusterType = sig.accounts_db.genesis_config.ClusterType;

pub const Client = struct {
    http_endpoint: []const u8,
    http_client: std.http.Client,
    max_retries: usize,
    logger: ScopedLogger(@typeName(Self)),

    const Self = @This();

    pub const Options = struct {
        max_retries: usize = 0,
        logger: Logger = .noop,
    };

    pub fn init(allocator: std.mem.Allocator, cluster_type: ClusterType, options: Options) Client {
        const http_endpoint = switch (cluster_type) {
            .MainnetBeta => "https://api.mainnet-beta.solana.com",
            .Testnet => "https://api.testnet.solana.com",
            .Devnet => "https://api.devnet.solana.com",
            .Development => @panic("cannot initialize RPC client with Development cluster type"),
            .LocalHost => "http://localhost:8899",
            .Custom => |cluster| cluster.url,
        };

        var client: Client = .{
            .http_endpoint = http_endpoint,
            .http_client = std.http.Client{ .allocator = allocator },
            .max_retries = options.max_retries,
            .logger = options.logger.withScope(@typeName(Client)),
        };

        client.logVersion(allocator) catch |err| {
            client.logger.err().logf("Failed to log RPC version: error={any}", .{err});
        };
        return client;
    }

    pub fn deinit(self: *Client) void {
        self.http_client.deinit();
    }

    /// Log the RPC version were connected to
    pub fn logVersion(self: *Client, allocator: std.mem.Allocator) !void {
        const response = try self.getVersion(allocator);
        defer response.deinit();
        const version = try response.result();
        self.logger.info().logf("RPC version: {s}", .{version.@"solana-core"});
    }

    pub const GetAccountInfoConfig = struct {
        commitment: ?types.Commitment = null,
        minContextSlot: ?u64 = null,
        encoding: ?[]const u8 = null,
        dataSlice: ?DataSlice = null,

        const DataSlice = struct {
            offset: usize,
            length: usize,
        };
    };

    pub fn getAccountInfo(self: *Client, allocator: std.mem.Allocator, pubkey: Pubkey, config: GetAccountInfoConfig) !Response(types.AccountInfo) {
        var request = try Request.init(allocator, "getAccountInfo");
        defer request.deinit();
        try request.addParameter(pubkey.base58String().slice());
        try request.addConfig(config);
        return self.sendFetchRequest(allocator, types.AccountInfo, request, .{});
    }

    pub const GetBalanceConfig = struct {
        commitment: ?types.Commitment = null,
        minContextSlot: ?u64 = null,
    };

    pub fn getBalance(self: *Client, allocator: std.mem.Allocator, pubkey: Pubkey, config: GetBalanceConfig) !Response(types.Balance) {
        var request = try Request.init(allocator, "getBalance");
        defer request.deinit();
        try request.addParameter(pubkey.base58String().slice());
        try request.addConfig(config);
        return self.sendFetchRequest(allocator, types.Balance, request, .{});
    }

    pub const GetBlockConfig = struct {
        commitment: ?types.Commitment = null,
        encoding: ?[]const u8 = null,
        transactionDetails: ?[]const u8 = null,
        maxSupportedTransactionVersion: ?u64 = null,
        rewards: ?bool = null,
    };

    pub fn getBlockCommitment(self: *Client, allocator: std.mem.Allocator, block: u64) !Response(types.BlockCommitment) {
        var request = try Request.init(allocator, "getBlockCommitment");
        defer request.deinit();
        try request.addParameter(block);
        return self.sendFetchRequest(allocator, types.BlockCommitment, request, .{});
    }

    pub const GetBlockHeightConfig = struct {
        commitment: ?types.Commitment = null,
        minContextSlot: ?u64 = null,
    };

    pub fn getBlockHeight(self: *Client, allocator: std.mem.Allocator, config: GetBlockHeightConfig) !Response(u64) {
        var request = try Request.init(allocator, "getBlockHeight");
        defer request.deinit();
        try request.addConfig(config);
        return self.sendFetchRequest(allocator, u64, request, .{});
    }

    // TODO: getBlockProduction()
    // TODO: getBlockTime()
    // TODO: getBlocks()
    // TODO: getBlocksWithLimit()

    pub fn getClusterNodes(self: *Client, allocator: std.mem.Allocator) !Response([]const types.RpcContactInfo) {
        var request = try Request.init(allocator, "getClusterNodes");
        defer request.deinit();
        return self.sendFetchRequest(allocator, []const types.RpcContactInfo, request, .{
            .ignore_unknown_fields = true,
        });
    }

    pub const GetEpochInfoConfig = struct {
        commitment: ?types.Commitment = null,
        minContextSlot: ?u64 = null,
    };

    pub fn getEpochInfo(self: *Client, allocator: std.mem.Allocator, config: GetEpochInfoConfig) !Response(types.EpochInfo) {
        var request = try Request.init(allocator, "getEpochInfo");
        defer request.deinit();
        try request.addConfig(config);
        return self.sendFetchRequest(allocator, types.EpochInfo, request, .{});
    }

    pub fn getEpochSchedule(self: *Client, allocator: std.mem.Allocator) !Response(types.EpochSchedule) {
        var request = try Request.init(allocator, "getEpochSchedule");
        defer request.deinit();
        return self.sendFetchRequest(allocator, types.EpochSchedule, request, .{});
    }

    // TODO: getFeeForMessage()
    // TODO: getFirstAvailableBlock()
    // TODO: getGenesisHash()
    // TODO: getHealth()
    // TODO: getHighestSnapshotSlot()
    // TODO: getIdentity()
    // TODO: getInflationGovernor()
    // TODO: getInflationRate()
    // TODO: getInflationReward()
    // TODO: getLargeAccounts()

    pub const GetLatestBlockhashConfig = struct {
        commitment: ?types.Commitment = null,
        minContextSlot: ?Slot = null,
    };

    pub fn getLatestBlockhash(self: *Client, allocator: std.mem.Allocator, config: GetLatestBlockhashConfig) !Response(types.LatestBlockhash) {
        var request = try Request.init(allocator, "getLatestBlockhash");
        defer request.deinit();
        try request.addConfig(config);
        return self.sendFetchRequest(allocator, types.LatestBlockhash, request, .{});
    }

    pub const GetLeaderScheduleConfig = struct {
        commitment: ?types.Commitment = null,
        identity: ?[]const u8 = null,
    };

    /// NOTE: Is there a way in zig to implement your own methods on a type from an external library?
    /// For example I would like to impelement jsonParse for the RPC return type of leader schedule which is:
    /// pub const LeaderSchedule = std.StringArrayHashMap([]const u64);
    /// I could use a wrapper like
    /// pub const LeaderSchedule = struct {
    ///    inner: std.StringArrayHashMap([]const u64),
    ///    pub fn jsonParse(...) !void
    /// }
    /// however, this introduces another layer of indirection.
    /// Not a big deal here but I am curious if there is a way to do this.
    pub fn getLeaderSchedule(
        self: *Client,
        allocator: std.mem.Allocator,
        maybe_slot: ?Slot,
        config: GetLeaderScheduleConfig,
    ) !Response(types.LeaderSchedule) {
        var request = try Request.init(allocator, "getLeaderSchedule");
        defer request.deinit();
        try request.addParameter(maybe_slot);
        try request.addConfig(config);
        const json_response = try self.sendFetchRequest(allocator, std.json.Value, request, .{});

        // Convert the result type from std.json.Value to types.LeaderSchedule
        var type_converted_result: ?types.LeaderSchedule = null;
        if (json_response.parsed.result) |json_value| {
            // The json result should always be an object
            const json_object = switch (json_value) {
                .object => |obj| obj,
                else => return error.LeaderScheduleResultIsNotAnObject,
            };

            // Convert the json object to the LeaderSchedule type
            type_converted_result = types.LeaderSchedule.init(json_response.arena.allocator());
            for (json_object.keys(), json_object.values()) |key, value| {
                const slots = try json_response.arena.allocator().alloc(u64, value.array.items.len);
                for (value.array.items, 0..) |slot, i| {
                    slots[i] = @intCast(slot.integer);
                }
                try type_converted_result.?.put(key, slots);
            }
        }

        // Return the response with the type converted result
        return .{
            .arena = json_response.arena,
            .bytes = json_response.bytes,
            .parsed = .{
                .id = json_response.parsed.id,
                .jsonrpc = json_response.parsed.jsonrpc,
                .result = type_converted_result,
                .@"error" = json_response.parsed.@"error",
            },
            .parse_options = json_response.parse_options,
        };
    }

    // TODO: getMaxRetransmitSlot()
    // TODO: getMaxShredInsertSlot()
    // TODO: getMinimumBalanceForRentExemption()
    // TODO: getMultipleAccounts()
    // TODO: getProgramAccounts()
    // TODO: getRecentPerformanceSamples()
    // TODO: getRecentPrioritizationFees()

    pub const GetSignatureStatusesConfig = struct {
        searchTransactionHistory: ?bool = null,
    };

    pub fn getSignatureStatuses(
        self: *Client,
        allocator: std.mem.Allocator,
        signatures: []const Signature,
        config: GetSignatureStatusesConfig,
    ) !Response(types.SignatureStatuses) {
        var request = try Request.init(allocator, "getSignatureStatuses");
        defer request.deinit();
        try request.addParameter(signatures);
        try request.addConfig(config);
        return self.sendFetchRequest(allocator, types.SignatureStatuses, request, .{ .ignore_unknown_fields = true });
    }

    // TODO: getSignaturesForAddress()

    pub const GetSlotConfig = struct {
        commitment: ?types.Commitment = null,
        minContextSlot: ?Slot = null,
    };

    pub fn getSlot(self: *Client, allocator: std.mem.Allocator, config: GetSlotConfig) !Response(Slot) {
        var request = try Request.init(allocator, "getSlot");
        defer request.deinit();
        try request.addConfig(config);
        return self.sendFetchRequest(allocator, Slot, request, .{});
    }

    pub const RequestAirdropOptions = struct {
        commitment: ?types.Commitment = null,
    };

    pub fn requestAirDrop(
        self: *Client,
        allocator: std.mem.Allocator,
        pubkey: Pubkey,
        lamports: u64,
        config: RequestAirdropOptions,
    ) !Response(types.Signature) {
        var request = try Request.init(allocator, "requestAirdrop");
        defer request.deinit();
        try request.addParameter(pubkey.base58String().slice());
        try request.addParameter(lamports);
        try request.addConfig(config);
        return self.sendFetchRequest(allocator, types.Signature, request, .{});
    }

    // TODO: getSlotLeader()
    // TODO: getSlotLeaders()
    // TODO: getStakeActivation()
    // TODO: getStakeMinimumDelegation()
    // TODO: getSupply()
    // TODO: getTokenAccountBalance()
    // TODO: getTokenAccountsByDelegate()
    // TODO: getTockenAccountsByOwner()
    // TODO: getTokenLargestAccounts()
    // TODO: getTokenSupply()
    // TODO: getTransaction()
    // TODO: getTransactionCount()
    // TODO: getVoteAccounts()
    // TODO: isBlockhashValid()
    // TODO: minimumLedgerSlot()
    // TODO: simulateTransaction()

    const SendTransactionConfig = struct {};

    pub fn sendTransaction(
        self: *Client,
        allocator: std.mem.Allocator,
        transaction: Transaction,
        config: SendTransactionConfig,
    ) !Response(types.Signature) {
        var request = try Request.init(allocator, "sendTransaction");
        defer request.deinit();

        var buffer: [sig.net.PACKET_DATA_SIZE]u8 = undefined;
        const written = try sig.bincode.writeToSlice(&buffer, transaction, .{});

        const endec = base58.Table.BITCOIN;
        var encoded_buffer: [base58.encodedMaxSize(buffer.len)]u8 = undefined;
        const length = endec.encode(&encoded_buffer, written);
        const encoded = encoded_buffer[0..length];

        try request.addParameter(encoded);
        try request.addConfig(config);

        return self.sendFetchRequest(allocator, types.Signature, request, .{});
    }

    pub fn getVersion(self: *Client, allocator: std.mem.Allocator) !Response(types.RpcVersionInfo) {
        var request = try Request.init(allocator, "getVersion");
        defer request.deinit();
        return self.sendFetchRequest(allocator, types.RpcVersionInfo, request, .{});
    }

    const GetVoteAccountsConfig = struct {
        commitment: ?types.Commitment = null,
        votePubkey: ?Pubkey = null,
        keepUnstakedDelinquents: ?bool = null,
        delinquintSlotDistance: ?u64 = null,
    };

    pub fn getVoteAccounts(
        self: *Client,
        allocator: std.mem.Allocator,
        config: GetVoteAccountsConfig,
    ) !Response(types.GetVoteAccountsResponse) {
        var request = try Request.init(allocator, "getVoteAccounts");
        defer request.deinit();
        try request.addConfig(config);

        return self.sendFetchRequest(allocator, types.GetVoteAccountsResponse, request, .{});
    }

    /// Sends a JSON-RPC request to the HTTP endpoint and parses the response.
    /// If the request fails, it will be retried up to `max_retries` times, restarting the HTTP client
    /// if necessary. If the response fails to parse, an error will be returned.
    fn sendFetchRequest(
        self: *Client,
        allocator: std.mem.Allocator,
        comptime T: type,
        request: Request,
        response_parse_options: std.json.ParseOptions,
    ) !Response(T) {
        var response = try Response(T).init(allocator, response_parse_options);
        errdefer response.deinit();

        const payload = try request.toJsonString(allocator);
        defer allocator.free(payload);

        for (0..self.max_retries + 1) |curr_retries| {
            const result = self.fetchRequest(payload, &response.bytes) catch |fetch_error| {
                self.logger.warn().logf("HTTP client error, attempting reinitialisation: error={any}", .{fetch_error});
                if (curr_retries == self.max_retries) return fetch_error;
                response.bytes.clearRetainingCapacity();
                self.restartHttpClient();
                continue;
            };

            if (result.status != .ok) {
                self.logger.warn().logf("HTTP request failed ({d}/{d}): {}", .{ curr_retries, self.max_retries, result.status });
                if (curr_retries == self.max_retries) return error.HttpRequestFailed;
                response.bytes.clearRetainingCapacity();
                continue;
            }

            break;
        }

        response.parse() catch |err| {
            self.logger.err().logf("Failed to parse response: error={} request_payload={s} response={s}", .{ err, payload, response.bytes.items });
            return err;
        };

        return response;
    }

    fn fetchRequest(
        self: *Client,
        request_payload: []const u8,
        response_payload: *std.ArrayList(u8),
    ) !std.http.Client.FetchResult {
        return self.http_client.fetch(.{
            .location = .{ .url = self.http_endpoint },
            .method = .POST,
            .headers = .{
                .content_type = .{
                    .override = "application/json",
                },
                .user_agent = .{
                    .override = "sig/0.1",
                },
            },
            .payload = request_payload,
            .response_storage = .{ .dynamic = response_payload },
            .max_append_size = 100 * 1024 * 1024,
        });
    }

    fn restartHttpClient(self: *Client) void {
        self.http_client.deinit();
        self.http_client = std.http.Client{ .allocator = self.http_client.allocator };
    }
};

test "getAccountInfo: null value" {
    if (true) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    // random pubkey that should not exist
    const pubkey = try Pubkey.parseBase58String("Bkd9xbHF7JgwXmEib6uU3y582WaPWWiasPxzMesiBwWn");
    const response = try client.getAccountInfo(allocator, pubkey, .{});
    defer response.deinit();
    const x = try response.result();

    try std.testing.expectEqual(null, x.value);
}

test "getAccountInfo" {
    if (true) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    const pubkey = try Pubkey.parseBase58String("Bkd9xbHF7JgwXmEib6uU3y582WaPWWiasPxzMesiBwWm");
    const response = try client.getAccountInfo(allocator, pubkey, .{});
    defer response.deinit();
    _ = try response.result();
}

test "getBalance" {
    if (true) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    const pubkey = try Pubkey.parseBase58String("Bkd9xbHF7JgwXmEib6uU3y582WaPWWiasPxzMesiBwWm");
    const response = try client.getBalance(allocator, pubkey, .{});
    defer response.deinit();
    _ = try response.result();
}

test "getBlockHeight" {
    if (true) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    const response = try client.getBlockHeight(allocator, .{});
    defer response.deinit();
    _ = try response.result();
}

test "getBlockCommitment" {
    if (true) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    const slot_response = try client.getSlot(allocator, .{ .commitment = .finalized });
    defer slot_response.deinit();
    const response = try client.getBlockCommitment(allocator, slot_response.parsed.result.?);
    defer response.deinit();
    _ = try response.result();
}

test "getEpochInfo" {
    if (true) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    const response = try client.getEpochInfo(allocator, .{});
    defer response.deinit();
    _ = try response.result();
}

test "getEpochSchedule" {
    if (true) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    const response = try client.getEpochSchedule(allocator);
    defer response.deinit();
    _ = try response.result();
}

// TODO: test getFeeForMessage()
// TODO: test getFirstAvailableBlock()
// TODO: test getGenesisHash()
// TODO: test getHealth()
// TODO: test getHighestSnapshotSlot()
// TODO: test getIdentity()
// TODO: test getInflationGovernor()
// TODO: test getInflationRate()
// TODO: test getInflationReward()
// TODO: test getLargeAccounts()

test "getLatestBlockhash" {
    if (true) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    const response = try client.getLatestBlockhash(allocator, .{});
    defer response.deinit();
    _ = try response.result();
}

test "getLeaderSchedule" {
    if (true) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    const response = try client.getLeaderSchedule(allocator, null, .{});
    defer response.deinit();
    _ = try response.result();
}

// TODO: test getMaxRetransmitSlot()
// TODO: test getMaxShredInsertSlot()
// TODO: test getMinimumBalanceForRentExemption()
// TODO: test getMultipleAccounts()
// TODO: test getProgramAccounts()
// TODO: test getRecentPerformanceSamples()
// TODO: test getRecentPrioritizationFees()

test "getSignatureStatuses" {
    if (true) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    var signatures = try allocator.alloc(Signature, 2);
    defer allocator.free(signatures);
    signatures[0] = try Signature.parseBase58String(
        "56H13bd79hzZa67gMACJYsKxb5MdfqHhe3ceEKHuBEa7hgjMgAA4Daivx68gBFUa92pxMnhCunngcP3dpVnvczGp",
    );
    signatures[1] = try Signature.parseBase58String(
        "4K6Gjut37p3ajRtsN2s6q1Miywit8VyP7bAYLfVSkripdNJkF3bL6BWG7dauzZGMr3jfsuFaPR91k2NuuCc7EqAz",
    );
    const response = try client.getSignatureStatuses(allocator, signatures, .{});
    defer response.deinit();
    _ = try response.result();
}

// TODO: test getSignaturesForAddress()

test "getSlot" {
    if (true) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    const response = try client.getSlot(allocator, .{});
    defer response.deinit();
    _ = try response.result();
}

// TODO: test getSlotLeader()
// TODO: test getSlotLeaders()
// TODO: test getStakeActivation()
// TODO: test getStakeMinimumDelegation()
// TODO: test getSupply()
// TODO: test getTokenAccountBalance()
// TODO: test getTokenAccountsByDelegate()
// TODO: test getTockenAccountsByOwner()
// TODO: test getTokenLargestAccounts()
// TODO: test getTokenSupply()
// TODO: test getTransaction()
// TODO: test getTransactionCount()
// TODO: test getVoteAccounts()
// TODO: test isBlockhashValid()
// TODO: test minimumLedgerSlot()
// TODO: test requestAirdrop()
// TODO: test sendTransaction()
// TODO: test simulateTransaction()

test "getVersion" {
    if (true) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    const response = try client.getVersion(allocator);
    defer response.deinit();
    _ = try response.result();
}

test "getVoteAccounts response parses correctly" {
    const response_json =
        \\{
        \\  "jsonrpc": "2.0",
        \\  "result": {
        \\    "current": [
        \\      {
        \\        "commission": 0,
        \\        "epochVoteAccount": true,
        \\        "epochCredits": [
        \\          [1, 64, 0],
        \\          [2, 192, 64]
        \\        ],
        \\        "nodePubkey": "B97CCUW3AEZFGy6uUg6zUdnNYvnVq5VG8PUtb2HayTDD",
        \\        "lastVote": 147,
        \\        "activatedStake": 42,
        \\        "votePubkey": "3ZT31jkAGhUaw8jsy4bTknwBMP8i4Eueh52By4zXcsVw",
        \\        "rootSlot": 100
        \\      }
        \\    ],
        \\    "delinquent": []
        \\  },
        \\  "id": 1
        \\}
    ;

    var response = try Response(types.GetVoteAccountsResponse).init(std.testing.allocator, .{});
    try response.bytes.appendSlice(response_json);
    defer response.deinit();
    try response.parse();
    const actual = try response.result();
    const expected = types.GetVoteAccountsResponse{
        .current = &.{.{
            .commission = 0,
            .epochVoteAccount = true,
            .epochCredits = &.{ .{ 1, 64, 0 }, .{ 2, 192, 64 } },
            .nodePubkey = try Pubkey.parseBase58String(
                "B97CCUW3AEZFGy6uUg6zUdnNYvnVq5VG8PUtb2HayTDD",
            ),
            .lastVote = 147,
            .activatedStake = 42,
            .votePubkey = try Pubkey.parseBase58String(
                "3ZT31jkAGhUaw8jsy4bTknwBMP8i4Eueh52By4zXcsVw",
            ),
            .rootSlot = 100,
        }},
        .delinquent = &.{},
    };
    try std.testing.expect(sig.utils.types.eql(expected, actual));
}
