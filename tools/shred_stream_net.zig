//! Streams raw shreds from an Agave ledger to a UDP target.

const std = @import("std");
const lib = @import("lib");

const tel = lib.telemetry;
const Logger = tel.Logger("main");
const PacketRing = lib.net.Pair.PacketRing;

const shred_stream = @import("shred_stream");

const printHelp = shred_stream.printHelp;
const run = shred_stream.run;
const netThreadMain = shred_stream.netThreadMain;

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    const argv = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, argv);

    var stderr_buf: [4096]u8 = undefined;
    var stderr_writer = std.fs.File.stderr().writer(&stderr_buf);
    defer stderr_writer.interface.flush() catch {};
    const stderr = &stderr_writer.interface;
    const logger: Logger = .{ .sink = .{ .writer = stderr } };
    const args = argv[1..];

    var inputs: shred_stream.Inputs = try .init(gpa, logger, args);
    defer inputs.deinit(gpa);

    const target_str = inputs.config.target orelse {
        std.debug.print("missing required argument: --target <ip:port>\n", .{});
        try printHelp(stderr);
        return error.InvalidArguments;
    };
    const target = try std.net.Address.parseIpAndPort(target_str);

    const sockfd = try std.posix.socket(
        target.any.family,
        std.posix.SOCK.DGRAM | std.posix.SOCK.CLOEXEC,
        std.posix.IPPROTO.UDP,
    );
    defer std.posix.close(sockfd);

    // Ring is ~20 MB (Packet is ~1.2 KB * 16384 slots); allocate on heap.
    const ring = try gpa.create(PacketRing);
    defer gpa.destroy(ring);
    ring.init();

    var producer_done: std.atomic.Value(bool) = .init(false);
    var net_stop: std.atomic.Value(bool) = .init(false);
    var net_failed: std.atomic.Value(bool) = .init(false);
    var send_errors: std.atomic.Value(u64) = .init(0);
    var packets_sent: std.atomic.Value(u64) = .init(0);
    var payload_bytes_sent: std.atomic.Value(u64) = .init(0);

    var writer_iter = ring.get(.writer);

    const net_thread = try std.Thread.spawn(.{}, netThreadMain, .{
        ring,
        &producer_done,
        &net_stop,
        &net_failed,
        &send_errors,
        &packets_sent,
        &payload_bytes_sent,
        sockfd,
        target,
    });

    var joined = false;
    errdefer if (!joined) {
        producer_done.store(true, .release);
        net_stop.store(true, .release);
        net_thread.join();
    };

    const service_result = run(gpa, logger, &writer_iter, inputs);

    producer_done.store(true, .release);
    net_thread.join();
    joined = true;

    try service_result;
    if (net_failed.load(.monotonic)) return error.NetThreadFailed;

    std.debug.print(
        "net_thread: udp_sent_packets={d} udp_sent_payload_bytes={d} udp_send_errors={d}\n",
        .{
            packets_sent.load(.monotonic),
            payload_bytes_sent.load(.monotonic),
            send_errors.load(.monotonic),
        },
    );
}
