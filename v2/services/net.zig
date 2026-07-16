//! This services gives other services access to UDP sockets, sharing a pair of ringbuffers for
//! sending and receiving packets.

const std = @import("std");
const start = @import("start_service");
const lib = @import("lib");
const services = @import("services");
const Pair = lib.net.Pair;
const tel = lib.telemetry;

comptime {
    _ = start;
}

pub const name = .net;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadOnly = services.net.ReadOnly;
pub const ReadWrite = services.net.ReadWrite;

pub fn serviceMain(
    runner: lib.runner.Connection,
    _: ReadOnly,
    rw: ReadWrite,
) !noreturn {
    const logger = rw.tel.acquireLogger(@tagName(name), "main");

    const metric_appender = rw.tel.metricAppender();
    const metrics = metric_appender.appendFields(Metrics, .{
        .prefix = @tagName(name),
        .fields = .{
            .recv_packet_latency = .{ .layout = .{
                .schema = 2,
                .min_ns = 512,
                .octaves = 12,
            } },
            .send_packet_latency = .{ .layout = .{
                .schema = 2,
                .min_ns = 512,
                .octaves = 12,
            } },
        },
    });
    rw.tel.signalReady();

    try mainInner(
        runner,
        logger,
        metrics,
        &.{ rw.gossip_pair, rw.shred_pair },
    );
}

const Metrics = struct {
    recv_packet_latency: tel.LatencyHistogram,
    send_packet_latency: tel.LatencyHistogram,
};

const MAX_SOCKETS = 10;

/// `ports` is the list of ports it'll listen on.
fn mainInner(
    runner: lib.runner.Connection,
    logger: tel.Logger("main"),
    metrics: Metrics,
    pairs: []const *Pair,
) !noreturn {
    _ = runner;
    std.debug.assert(pairs.len <= MAX_SOCKETS);

    var sockets: [MAX_SOCKETS]std.posix.fd_t = undefined;
    var sockets_len: usize = 0;

    for (pairs, 0..) |pair, i| {
        errdefer for (sockets[0..i]) |socket| std.posix.close(socket);
        const socket = try std.posix.socket(
            std.posix.AF.INET,
            std.posix.SOCK.DGRAM | std.posix.SOCK.NONBLOCK | std.posix.SOCK.CLOEXEC,
            std.posix.IPPROTO.UDP,
        );
        errdefer std.posix.close(socket);

        logger.info().logf("binding 0.0.0.0:{}", .{pair.port});

        const local: std.net.Address = .initIp4(.{ 0, 0, 0, 0 }, pair.port);
        try std.posix.bind(socket, &local.any, local.getOsSockLen());

        sockets[sockets_len] = socket;
        sockets_len += 1;
    }

    var timer: lib.time.Timer = .start();
    while (true) {
        // send
        for (pairs, sockets[0..sockets_len]) |pair, sock| {
            var it = pair.send.get(.reader);
            defer it.markUsed();

            // TODO: use std.os.linux.sendmmsg
            while (it.next()) |p| {
                timer.reset();
                const bytes = try std.posix.sendto(
                    sock,
                    p.data[0..p.len],
                    std.posix.MSG.NOSIGNAL,
                    &p.addr.any,
                    p.addr.getOsSockLen(),
                );
                std.debug.assert(bytes == p.len);
                metrics.send_packet_latency.observe(timer.read());
            }
        }

        // recv
        for (pairs, sockets[0..sockets_len]) |pair, sock| {
            var it = pair.recv.get(.writer);
            defer it.markUsed();

            // TODO: use std.os.linux.recvmmsg
            while (it.peek()) |ptr| {
                timer.reset();
                var addr_len: std.posix.socklen_t = @sizeOf(std.net.Address);
                ptr.len = @intCast(std.posix.recvfrom(
                    sock,
                    &ptr.data,
                    0,
                    &ptr.addr.any,
                    &addr_len,
                ) catch |err| switch (err) {
                    error.WouldBlock => break,
                    else => |e| return e,
                });
                _ = it.next();
                metrics.recv_packet_latency.observe(timer.read());
            }
        }
    }
}
