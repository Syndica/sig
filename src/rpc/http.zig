const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;

const ErrorReturn = sig.utils.types.ErrorReturn;
const Logger = sig.trace.log.Logger("rpc.http");

/// Sends HTTP POST requests with content type of application/json and awaits a
/// response. Offers a retry mechanism to handle failures.
///
/// Not safe to use in multiple threads since the http client may be restarted
/// by fetchWithRetries.
pub const HttpPostFetcher = struct {
    http_client: std.http.Client,
    base_url: []const u8,
    logger: Logger,
    max_retries: usize,

    pub const Options = struct {
        max_retries: usize = 0,
        logger: Logger = .noop,
    };

    pub const Error = error{HttpRequestFailed} ||
        ErrorReturn(std.http.Client.fetch) || Allocator.Error;

    pub fn init(
        allocator: Allocator,
        base_url: []const u8,
        options: Options,
    ) Allocator.Error!HttpPostFetcher {
        return .{
            .base_url = try allocator.dupe(u8, base_url),
            .http_client = std.http.Client{ .allocator = allocator },
            .logger = options.logger,
            .max_retries = options.max_retries,
        };
    }

    pub fn deinit(self: *HttpPostFetcher) void {
        self.http_client.allocator.free(self.base_url);
        self.http_client.deinit();
    }

    /// Sends a JSON-RPC request to the HTTP endpoint and parses the response.
    /// If the request fails, it will be retried up to `max_retries` times,
    /// If the response fails to parse, an error will be returned.
    pub fn fetchWithRetries(
        self: *HttpPostFetcher,
        allocator: std.mem.Allocator,
        request: []const u8,
    ) Error![]const u8 {
        var response = std.array_list.Managed(u8).init(allocator);
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
        self: *HttpPostFetcher,
        request_payload: []const u8,
        response_payload: *std.array_list.Managed(u8),
    ) ErrorReturn(std.http.Client.fetch)!std.http.Client.FetchResult {
        var buf: [1024]u8 = undefined;
        var writer = response_payload.writer().adaptToNewApi(&buf);

        const result = try self.http_client.fetch(.{
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
            .response_writer = &writer.new_interface,
        });

        try writer.new_interface.flush();
        return result;
    }

    fn restartHttpClient(self: *HttpPostFetcher) void {
        const allocator = self.http_client.allocator;
        self.http_client.deinit();
        self.http_client = std.http.Client{ .allocator = allocator };
    }
};
