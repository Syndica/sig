const builtin = @import("builtin");
const std = @import("std");

const Registry = @import("registry.zig").Registry;
const globalRegistry = @import("registry.zig").globalRegistry;
const DEFAULT_BUCKETS = @import("histogram.zig").DEFAULT_BUCKETS;

/// Initializes the global registry. Returns error if registry was already initialized.
/// Spawns a thread to serve the metrics over http on the given port.
pub fn spawnMetrics(
    gpa_allocator: std.mem.Allocator,
    port: u16,
) !std.Thread {
    const registry = globalRegistry();
    return std.Thread.spawn(.{}, servePrometheus, .{ gpa_allocator, registry, port });
}

pub fn servePrometheus(
    allocator: std.mem.Allocator,
    registry: *Registry(.{}),
    port: u16,
) !void {
    const our_ip = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, port);
    var tcp = try our_ip.listen(.{
        .force_nonblocking = true,
        .reuse_address = true,
    });
    defer tcp.deinit();

    while (true) {
        const conn = tcp.accept() catch |err| switch (err) {
            error.WouldBlock => continue,
            else => |e| return e,
        };

        // TODO: unify this with the code for the RPC server
        if (comptime builtin.target.isDarwin()) set_flags: {
            const FlagsInt = @typeInfo(std.posix.O).Struct.backing_integer.?;
            var flags_int: FlagsInt =
                @intCast(try std.posix.fcntl(conn.stream.handle, std.posix.F.GETFL, 0));
            const flags: *std.posix.O =
                std.mem.bytesAsValue(std.posix.O, std.mem.asBytes(&flags_int));
            if (flags.NONBLOCK == false and flags.CLOEXEC == true) break :set_flags;
            flags.NONBLOCK = false;
            flags.CLOEXEC = true;
            _ = try std.posix.fcntl(conn.stream.handle, std.posix.F.SETFL, flags_int);
        }

        var read_buffer: [4096]u8 = undefined;
        var http_server = std.http.Server.init(conn, &read_buffer);
        var request = http_server.receiveHead() catch continue;

        if (request.head.method != .GET or
            !std.mem.eql(u8, request.head.target, "/metrics") //
        ) {
            try request.respond("", .{
                .version = .@"HTTP/1.0",
                .status = .not_found,
                .keep_alive = false,
            });
            continue;
        }

        var send_buffer: [4096]u8 = undefined;
        var response = request.respondStreaming(.{
            .send_buffer = &send_buffer,
            .respond_options = .{
                .version = .@"HTTP/1.0",
                .status = .ok,
                .keep_alive = true,
            },
        });
        try registry.write(allocator, response.writer());
        try response.end();
    }
}

/// Runs a test prometheus endpoint with dummy data.
pub fn main() !void {
    const alloc = std.heap.c_allocator;

    _ = try std.Thread.spawn(
        .{},
        struct {
            fn run() !void {
                const reg = globalRegistry();
                var secs_counter = try reg.getOrCreateCounter("seconds_since_start");
                var gauge = try reg.getOrCreateGauge("seconds_hand", u64);
                var hist = try reg.getOrCreateHistogram("hist", &DEFAULT_BUCKETS);
                while (true) {
                    std.time.sleep(1_000_000_000);
                    secs_counter.inc();
                    gauge.set(@as(u64, @intCast(std.time.timestamp())) % @as(u64, 60));
                    hist.observe(1.1);
                    hist.observe(0.02);
                }
            }
        }.run,
        .{},
    );
    try servePrometheus(
        alloc,
        globalRegistry(),
        12345,
    );
}
