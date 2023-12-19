//! Basic HTTP adapter for prometheus using the http server in std.

const std = @import("std");

const Registry = @import("registry.zig").Registry;
const default_buckets = @import("histogram.zig").default_buckets;
const Logger = @import("../trace/log.zig").Logger;
const Level = @import("../trace/level.zig").Level;

pub fn servePrometheus(
    allocator: std.mem.Allocator,
    registry: *Registry(.{}),
    listen_addr: std.net.Address,
    logger: Logger,
) !void {
    var server = std.http.Server.init(allocator, .{});
    defer server.deinit();
    try server.listen(listen_addr);

    outer: while (true) {
        var response = try server.accept(.{ .allocator = allocator });
        defer response.deinit();

        while (response.reset() != .closing) {
            response.wait() catch |err| switch (err) {
                error.HttpHeadersInvalid => continue :outer,
                error.EndOfStream => continue,
                else => return err,
            };
            handleRequest(allocator, &response, registry, logger) catch |e| {
                logger.errf("prometheus http: Failed to handle request. {}", .{e});
            };
        }
    }
}

fn handleRequest(
    allocator: std.mem.Allocator,
    response: *std.http.Server.Response,
    registry: *Registry(.{}),
    logger: Logger,
) !void {
    logger.debugf("prometheus http: {s} {s} {s}\n", .{
        @tagName(response.request.method),
        @tagName(response.request.version),
        response.request.target,
    });

    if (response.request.method == .GET and
        std.mem.startsWith(u8, response.request.target, "/metrics"))
    {
        response.transfer_encoding = .chunked;
        try response.headers.append("content-type", "text/plain");
        try response.do();
        try registry.write(allocator, response.writer());
        try response.finish();
    } else {
        response.status = .not_found;
        try response.do();
        try response.finish();
    }
}

/// Runs a test prometheus endpoint with dummy data.
pub fn main() !void {
    const a = std.heap.page_allocator;
    var registry = try Registry(.{}).init(a);
    _ = try std.Thread.spawn(
        .{},
        struct {
            fn run(r: *Registry(.{})) !void {
                var secs_counter = try r.getOrCreateCounter("seconds_since_start");
                var gauge = try r.getOrCreateGauge("seconds_hand", u64);
                var hist = try r.getOrCreateHistogram("hist", &default_buckets);
                while (true) {
                    std.time.sleep(1_000_000_000);
                    secs_counter.inc();
                    gauge.set(@as(u64, @intCast(std.time.timestamp())) % @as(u64, 60));
                    hist.observe(1.1);
                    hist.observe(0.02);
                }
            }
        }.run,
        .{registry},
    );
    const logger = Logger.init(a, Level.debug);
    try servePrometheus(
        a,
        registry,
        try std.net.Address.parseIp4("0.0.0.0", 1234),
        logger,
    );
}
