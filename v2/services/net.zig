//! This services gives other services access to UDP sockets, sharing a pair of ringbuffers for
//! sending and receiving packets.

const std = @import("std");
const start = @import("start");
const lib = @import("lib");
const Pair = lib.net.Pair;

comptime {
    _ = start;
}

pub const name = .net;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadWrite = struct {
    gossip_pair: *Pair,
    shred_pair: *Pair,
};

pub fn serviceMain(rw: ReadWrite) !noreturn {
    try mainInner(&.{ rw.gossip_pair, rw.shred_pair });
}

const MAX_SOCKETS = 10;

/// `ports` is the list of ports it'll listen on.
fn mainInner(pairs: []const *Pair) !noreturn {
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

        std.log.info("binding 0.0.0.0:{}", .{pair.port});

        const local: std.net.Address = .initIp4(.{ 0, 0, 0, 0 }, pair.port);
        try std.posix.bind(socket, &local.any, local.getOsSockLen());

        sockets[sockets_len] = socket;
        sockets_len += 1;
    }

    while (true) {
        // send
        for (pairs, sockets[0..sockets_len]) |pair, sock| {
            var it = pair.send.get(.reader);
            defer it.markUsed();

            // TODO: use std.os.linux.sendmmsg
            while (it.next()) |p| {
                const bytes = try std.posix.sendto(
                    sock,
                    p.data[0..p.size],
                    std.posix.MSG.NOSIGNAL,
                    &p.addr.any,
                    p.addr.getOsSockLen(),
                );
                std.debug.assert(bytes == p.size);
            }
        }

        // recv
        for (pairs, sockets[0..sockets_len]) |pair, sock| {
            var it = pair.recv.get(.writer);
            defer it.markUsed();

            // TODO: use std.os.linux.recvmmsg
            while (it.peek()) |ptr| {
                var addr_len: std.posix.socklen_t = @sizeOf(std.net.Address);
                ptr.size = @intCast(std.posix.recvfrom(
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
            }
        }
    }
}
