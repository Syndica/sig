//! This services gives other services access to UDP sockets, sharing a pair of ringbuffers for
//! sending and receiving packets.

const std = @import("std");
const start = @import("start");
const common = @import("common");
const Pair = common.net.Pair;
const obs = common.observability;

comptime {
    _ = start;
}

pub const name = .net;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadOnly = struct {};

pub const ReadWrite = struct {
    pair: *Pair,
    obs: obs.Regions,
};

pub fn serviceMain(_: ReadOnly, rw: ReadWrite) !noreturn {
    const logger = rw.obs.acquireLogger(@tagName(name), "main");

    const metric_appender = rw.obs.metricAppender();
    _ = metric_appender;

    rw.obs.signalReady();

    try mainInner(logger, &.{rw.pair});
}

const MAX_SOCKETS = 10;

/// `ports` is the list of ports it'll listen on.
fn mainInner(
    logger: obs.Logger("main"),
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
            var slice = pair.send.getReadable() catch continue;
            const flags = std.posix.MSG.NOSIGNAL;
            var counter: u32 = 0;
            inline for (.{ slice.first(), slice.second() }) |packets| {
                for (packets) |p| {
                    const bytes = try std.posix.sendto(
                        sock,
                        p.data[0..p.size],
                        flags,
                        &p.addr.any,
                        p.addr.getOsSockLen(),
                    );
                    std.debug.assert(bytes == p.size);
                    counter += 1;
                }
            }
            slice.markUsed(counter);
        }

        // recv
        for (pairs, sockets[0..sockets_len]) |pair, sock| {
            var slice = pair.recv.getWritable() catch continue;
            const ptr = slice.get(0);
            ptr.size = @intCast(std.posix.recvfrom(
                sock,
                &ptr.data,
                0,
                null,
                null,
            ) catch |err| switch (err) {
                error.WouldBlock => continue,
                else => |e| return e,
            });
            slice.markUsed(1);
        }
    }
}
