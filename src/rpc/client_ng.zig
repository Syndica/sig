const std = @import("std");
const sig = @import("../sig.zig");
const rpc = @import("lib.zig");

const types = sig.rpc.types;

const Allocator = std.mem.Allocator;

const Slot = sig.core.Slot;
const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;
const Request = sig.rpc.Request;
const Response = sig.rpc.Response;
const Logger = sig.trace.log.Logger;

pub const Client = struct {
    allocator: Allocator,
    http_endpoint: []const u8,
    http_client: std.http.Client,
    max_retries: usize,
    logger: Logger,

    pub const Options = struct {
        max_retries: usize = 0,
        logger: Logger = .noop,
    };

    pub fn init(allocator: Allocator, cluster_type: types.ClusterType, options: Options) Client {
        const http_endpoint = switch (cluster_type) {
            .MainnetBeta => "https://api.mainnet-beta.solana.com",
            .Testnet => "https://api.testnet.solana.com",
            .Devnet => "https://api.devnet.solana.com",
            .LocalHost => "http://localhost:8899",
            .Custom => |cluster| cluster.url,
        };
        return .{
            .allocator = allocator,
            .http_endpoint = http_endpoint,
            .http_client = std.http.Client{ .allocator = allocator },
            .max_retries = options.max_retries,
            .logger = options.logger,
        };
    }

    pub fn deinit(self: *Client) void {
        self.http_client.deinit();
    }

    pub fn send(self: *Client, request: anytype) !@TypeOf(request).Response {
        rpc.convert.serializeRequestAlloc(self.allocator, request: anytype)
        self.allocator;

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

test "getAccountInfo" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    const pubkey = try Pubkey.fromString("Bkd9xbHF7JgwXmEib6uU3y582WaPWWiasPxzMesiBwWm");
    const response = try client.getAccountInfo(allocator, pubkey, .{});
    defer response.deinit();
    _ = try response.result();
}

test "getBalance" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    const pubkey = try Pubkey.fromString("Bkd9xbHF7JgwXmEib6uU3y582WaPWWiasPxzMesiBwWm");
    const response = try client.getBalance(allocator, pubkey, .{});
    defer response.deinit();
    _ = try response.result();
}

test "getBlockHeight" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    const response = try client.getBlockHeight(allocator, .{});
    defer response.deinit();
    _ = try response.result();
}

test "getBlockCommitment" {
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
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    const response = try client.getEpochInfo(allocator, .{});
    defer response.deinit();
    _ = try response.result();
}

// TODO: test getEpochSchedule()
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
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    const response = try client.getLatestBlockhash(allocator, .{});
    defer response.deinit();
    _ = try response.result();
}

test "getLeaderSchedule" {
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
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    var signatures = try allocator.alloc(Signature, 2);
    defer allocator.free(signatures);
    signatures[0] = try Signature.fromString(
        "56H13bd79hzZa67gMACJYsKxb5MdfqHhe3ceEKHuBEa7hgjMgAA4Daivx68gBFUa92pxMnhCunngcP3dpVnvczGp",
    );
    signatures[1] = try Signature.fromString(
        "4K6Gjut37p3ajRtsN2s6q1Miywit8VyP7bAYLfVSkripdNJkF3bL6BWG7dauzZGMr3jfsuFaPR91k2NuuCc7EqAz",
    );
    const response = try client.getSignatureStatuses(allocator, signatures, .{});
    defer response.deinit();
    _ = try response.result();
}

// TODO: test getSignaturesForAddress()

test "getSlot" {
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
// TODO: test getVersion()
// TODO: test getVoteAccounts()
// TODO: test isBlockhashValid()
// TODO: test minimumLedgerSlot()
// TODO: test requestAirdrop()
// TODO: test sendTransaction()
// TODO: test simulateTransaction()
