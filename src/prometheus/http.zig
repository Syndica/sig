const std = @import("std");
const httpz = @import("httpz");

const Registry = @import("registry.zig").Registry;
const globalRegistry = @import("registry.zig").globalRegistry;
const DEFAULT_BUCKETS = @import("histogram.zig").DEFAULT_BUCKETS;

pub fn servePrometheus(
    allocator: std.mem.Allocator,
    registry: *Registry(.{}),
    port: u16,
) !void {
    const endpoint = MetricsEndpoint{
        .allocator = allocator,
        .registry = registry,
    };
    var server = try httpz.Server(*const MetricsEndpoint).init(
        allocator,
        .{ .port = port, .address = "0.0.0.0" },
        &endpoint,
    );
    var router = try server.router(.{});
    router.get("/metrics", getMetrics, .{});
    return server.listen();
}

const MetricsEndpoint = struct {
    allocator: std.mem.Allocator,
    registry: *Registry(.{}),
};

/// Initializes the global registry. Returns error if registry was already initialized.
/// Spawns a thread to serve the metrics over http on the given port.
pub fn spawnMetrics(gpa_allocator: std.mem.Allocator, port: u16) !std.Thread {
    const registry = globalRegistry();
    return std.Thread.spawn(.{}, servePrometheus, .{ gpa_allocator, registry, port });
}

pub fn getMetrics(
    self: *const MetricsEndpoint,
    _: *httpz.Request,
    response: *httpz.Response,
) !void {
    response.content_type = .TEXT; // expected by prometheus
    try self.registry.write(self.allocator, response.writer());
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
                    std.Thread.sleep(1_000_000_000);
                    secs_counter.inc();
                    gauge.set(@as(u64, @intCast(std.time.timestamp())) % @as(u64, 60));
                    hist.observe(1.1);
                    hist.observe(0.02);
                }
            }
        }.run,
        .{},
    );

    try servePrometheus(alloc, globalRegistry(), 12345);
}
