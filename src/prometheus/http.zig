//! Basic HTTP adapter for prometheus using the http server in std.

const std = @import("std");
const Registry = @import("registry.zig").Registry;

// TODO: log with correct logger

pub fn servePrometheus(
    allocator: std.mem.Allocator,
    registry: *Registry(.{}),
    listen_addr: std.net.Address,
) !void {
    var server = std.http.Server.init(allocator, .{});
    defer server.deinit();
    try server.listen(listen_addr);

    outer: while (true) {
        var response = try server.accept(.{
            .allocator = allocator,
        });
        defer response.deinit();

        while (response.reset() != .closing) {
            response.wait() catch |err| switch (err) {
                error.HttpHeadersInvalid => continue :outer,
                error.EndOfStream => continue,
                else => return err,
            };
            handleRequest(allocator, &response, registry) catch |e| {
                std.debug.print("Failed while handling prometheus http request. {}", .{e});
            };
        }
    }
}

fn handleRequest(
    allocator: std.mem.Allocator,
    response: *std.http.Server.Response,
    registry: *Registry(.{}),
) !void {
    std.debug.print("{s} {s} {s}\n", .{
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
