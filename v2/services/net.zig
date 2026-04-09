//! This services gives other services access to UDP sockets, sharing a pair of ringbuffers for
//! sending and receiving packets.

const std = @import("std");
const start = @import("start");
const lib = @import("lib");
const Pair = lib.net.Pair;
const tel = lib.telemetry;

comptime {
    _ = start;
}

pub const name = .net;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadOnly = struct {};

pub const ReadWrite = struct {
    gossip_pair: *Pair,
    shred_pair: *Pair,
    tel: *tel.Region,
};

pub fn serviceMain(_: ReadOnly, rw: ReadWrite) !noreturn {
    const logger = rw.tel.acquireLogger(@tagName(name), "main");

    const metric_appender = rw.tel.metricAppender();
    const metrics = metric_appender.appendFields(Metrics, .{});
    rw.tel.signalReady();

    try mainInner(
        logger,
        metrics,
        &.{ rw.gossip_pair, rw.shred_pair },
    );
}

const Metrics = struct {
    recv_packets: tel.Counter,
    send_packets: tel.Counter,
};

const MAX_SOCKETS = 10;

/// `ports` is the list of ports it'll listen on.
fn mainInner(
    logger: tel.Logger("main"),
    metrics: Metrics,
    pairs: []const *Pair,
) !noreturn {
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

    while (true) {
        // send
        for (pairs, sockets[0..sockets_len]) |pair, sock| {
            var packet_reader = pair.send.get(.reader);
            defer packet_reader.markUsed();

            // TODO: buffer up std.os.linux.sendmmsg across multiple pairs
            while (packet_reader.peek()) |p| {
                const sent = std.posix.sendto(
                    sock,
                    p.data[0..p.size],
                    0,
                    &p.addr.any,
                    p.addr.getOsSockLen(),
                ) catch |e| switch (e) {
                    error.WouldBlock => break,
                    else => |err| return err,
                };
                std.debug.assert(sent == p.size);
                _ = packet_reader.next();
                metrics.send_packets.increment(1);
            }
        }

        // recv
        for (pairs, sockets[0..sockets_len]) |pair, sock| {
            var packet_writer = pair.recv.get(.writer);
            defer packet_writer.markUsed();

            // TODO: buffer std.os.linux.recvmmsg across multiple pairs.
            while (packet_writer.peek()) |p| {
                var addr_len: std.posix.socklen_t = @sizeOf(std.net.Address);
                p.size = @intCast(std.posix.recvfrom(
                    sock,
                    &p.data,
                    0,
                    &p.addr.any,
                    &addr_len,
                ) catch |e| switch (e) {
                    error.WouldBlock => break,
                    else => |err| return err,
                });
                _ = packet_writer.next();
                metrics.recv_packets.increment(1);
            }
        }
    }
}
