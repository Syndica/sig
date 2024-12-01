const std = @import("std");
const sig = @import("../sig.zig");
const rpc = @import("lib.zig");

const types = sig.rpc.types;

const Allocator = std.mem.Allocator;

const Slot = sig.core.Slot;
const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;
const Logger = sig.trace.log.Logger;

const Response = rpc.convert.Response;

pub const RpcClient = struct {
    allocator: Allocator,
    fetcher: HttpFetcher,

    pub const Options = HttpFetcher.Options;

    pub fn init(
        allocator: Allocator,
        cluster_type: types.ClusterType,
        options: HttpFetcher.Options,
    ) RpcClient {
        const http_endpoint = switch (cluster_type) {
            .MainnetBeta => "https://api.mainnet-beta.solana.com",
            .Testnet => "https://api.testnet.solana.com",
            .Devnet => "https://api.devnet.solana.com",
            .LocalHost => "http://localhost:8899",
            .Custom => |cluster| cluster.url, // TODO lifetime
        };

        return .{
            .allocator = allocator,
            .fetcher = .{
                .http_endpoint = http_endpoint,
                .http_client = std.http.Client{ .allocator = allocator },
                .logger = options.logger,
                .max_retries = options.max_retries,
            },
        };
    }

    pub fn deinit(self: RpcClient) void {
        _ = self; // autofix
    }

    pub fn fetch(
        self: *RpcClient,
        allocator: Allocator,
        /// Instance of a struct defined in `rpc.methods`
        request: anytype,
    ) !Response(@TypeOf(request)) {
        const request_json = try rpc.convert.serializeRequest(allocator, request);
        const response_json = try self.fetcher.fetchWithRetries(allocator, request_json);
        defer allocator.free(response_json);
        return try rpc.convert.deserializeResponse(allocator, @TypeOf(request), response_json);
    }
};

pub const HttpFetcher = struct {
    http_client: std.http.Client,
    http_endpoint: []const u8,
    logger: Logger,
    max_retries: usize,

    pub const Options = struct {
        max_retries: usize = 0,
        logger: Logger = .noop,
    };

    const Self = @This();

    pub const Error = error{HttpRequestFailed} ||
        ErrorReturn(std.http.Client.fetch) || Allocator.Error;

    /// Sends a JSON-RPC request to the HTTP endpoint and parses the response.
    /// If the request fails, it will be retried up to `max_retries` times,
    /// If the response fails to parse, an error will be returned.
    pub fn fetchWithRetries(
        self: *Self,
        allocator: std.mem.Allocator,
        request: []const u8,
    ) Error![]const u8 {
        std.debug.print("HTTP request {s}\n", .{request});
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

            std.debug.print("HTTP response {s}\n", .{response.items});

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

    fn restartHttpClient(self: *Self) void {
        self.http_client.deinit();
        self.http_client = std.http.Client{ .allocator = self.http_client.allocator };
    }
};

pub fn ErrorReturn(function: anytype) type {
    return @typeInfo(@typeInfo(@TypeOf(function)).Fn.return_type.?).ErrorUnion.error_set;
}
