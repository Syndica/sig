const std = @import("std");
const base58 = @import("base58-zig");
const sig = @import("../sig.zig");
const rpc = @import("lib.zig");

const types = rpc.types;
const methods = rpc.methods;

const Allocator = std.mem.Allocator;

const ClusterType = sig.accounts_db.genesis_config.ClusterType;
const ErrorReturn = sig.utils.types.ErrorReturn;
const Logger = sig.trace.log.Logger;
const ScopedLogger = sig.trace.log.ScopedLogger;

const Response = rpc.response.Response;

pub const Client = struct {
    fetcher: HttpFetcher,

    pub const Options = HttpFetcher.Options;

    pub fn init(
        allocator: Allocator,
        cluster_type: ClusterType,
        options: HttpFetcher.Options,
    ) Allocator.Error!Client {
        return .{ .fetcher = try HttpFetcher.init(allocator, rpcUrl(cluster_type), options) };
    }

    pub fn deinit(self: *Client) void {
        self.fetcher.deinit();
    }

    /// Send a typed RPC request and await a response.
    /// Pass a struct, such as those defined in `rpc.methods`.
    /// Returns data allocated with the contained allocator.
    pub fn fetch(self: *Client, request: anytype) !Response(@TypeOf(request)) {
        return try fetchRpc(
            self.fetcher.http_client.allocator,
            &self.fetcher,
            HttpFetcher.fetchWithRetries,
            request,
        );
    }

    /// Send a typed RPC request and await a response.
    /// Pass a struct, such as those defined in `rpc.methods`.
    /// Returns data allocated with the passed allocator.
    pub fn fetchAlloc(
        self: *Client,
        allocator: Allocator,
        request: anytype,
    ) !Response(@TypeOf(request)) {
        return try fetchRpc(allocator, &self.fetcher, HttpFetcher.fetchWithRetries, request);
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

/// Fetch the response for an RPC request with an arbitrary fetcher implementation.
pub fn fetchRpc(
    allocator: Allocator,
    fetcher: anytype,
    fetchFn: fn (@TypeOf(fetcher), Allocator, []const u8) @TypeOf(fetcher.*).Error![]const u8,
    /// Instance of a struct defined in `rpc.methods`
    request: anytype,
) !Response(@TypeOf(request)) {
    const request_json = try rpc.request.serialize(allocator, request);
    defer allocator.free(request_json);
    const response_json = try fetchFn(fetcher, allocator, request_json);
    defer allocator.free(response_json);
    return try Response(@TypeOf(request)).init(allocator, response_json);
}

pub const HttpFetcher = struct {
    http_client: std.http.Client,
    base_url: []const u8,
    logger: Logger,
    max_retries: usize,

    pub const Options = struct {
        max_retries: usize = 0,
        logger: Logger = .noop,
    };

    const Self = @This();

    pub const Error = error{HttpRequestFailed} ||
        ErrorReturn(std.http.Client.fetch) || Allocator.Error;

    pub fn init(allocator: Allocator, base_url: []const u8, options: Options) Allocator.Error!Self {
        return .{
            .base_url = try allocator.dupe(u8, base_url),
            .http_client = std.http.Client{ .allocator = allocator },
            .logger = options.logger,
            .max_retries = options.max_retries,
        };
    }

    pub fn deinit(self: *HttpFetcher) void {
        self.http_client.allocator.free(self.base_url);
        self.http_client.deinit();
    }

    /// Sends a JSON-RPC request to the HTTP endpoint and parses the response.
    /// If the request fails, it will be retried up to `max_retries` times,
    /// If the response fails to parse, an error will be returned.
    pub fn fetchWithRetries(
        self: *Self,
        allocator: std.mem.Allocator,
        request: []const u8,
    ) Error![]const u8 {
        var response = std.ArrayList(u8).init(allocator);
        errdefer response.deinit();

        var last_error: ?Error = null;

        for (0..self.max_retries + 1) |curr_retries| {
            const result = self.fetchOnce(request, &response) catch |fetch_error| {
                last_error = fetch_error;
                self.logger.warn().logf(
                    "HTTP client error, attempting reinitialisation: error={any}",
                    .{fetch_error},
                );
                response.clearRetainingCapacity();
                self.restartHttpClient();
                continue;
            };

            if (result.status != .ok) {
                last_error = error.HttpRequestFailed;
                self.logger.warn().logf(
                    "HTTP request failed ({d}/{d}): {}",
                    .{ curr_retries, self.max_retries, result.status },
                );
                response.clearRetainingCapacity();
                continue;
            }

            return try response.toOwnedSlice();
        }

        return last_error.?;
    }

    pub fn fetchOnce(
        self: *Self,
        request_payload: []const u8,
        response_payload: *std.ArrayList(u8),
    ) ErrorReturn(std.http.Client.fetch)!std.http.Client.FetchResult {
        return self.http_client.fetch(.{
            .location = .{ .url = self.base_url },
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

    fn restartHttpClient(self: *Self) void {
        self.http_client.deinit();
        self.http_client = std.http.Client{ .allocator = self.http_client.allocator };
    }
};
