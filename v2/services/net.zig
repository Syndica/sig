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
            var packet_reader = pair.send.get(.reader);
            defer packet_reader.markUsed();

            // TODO: buffer up std.os.linux.sendmmsg across multiple pairs
            while (packet_reader.peek()) |p| {
                const bytes = std.posix.sendmsg(
                    sock,
                    &.{
                        .name = &p.addr.any,
                        .namelen = p.addr.getOsSockLen(),
                        .iov = &.{ .{ .base = &p.data, .len = p.size } },
                        .iovlen = 1,
                        .control = null,
                        .controllen = 0,
                        .flags = 0,
                    },
                    std.posix.MSG.NOSIGNAL,
                ) catch |e| switch (e) {
                    error.WouldBlock => break,
                    else => |err| return err,
                };
                std.debug.assert(bytes == p.size);
                _ = packet_reader.next();
            }
        }

        // recv
        for (pairs, sockets[0..sockets_len]) |pair, sock| {
            var packet_writer = pair.recv.get(.writer);
            defer packet_writer.markUsed();

            // TODO: buffer std.os.linux.recvmmsg across multiple pairs.
            while (packet_writer.peek()) |p| {
                var iovecs: [1]std.posix.iovec = .{ .{ .base = &p.data, .len = p.data.len } };
                var msg_hdr: std.posix.system.msghdr = .{
                    .name = &p.addr.any,
                    .namelen = @sizeOf(std.net.Address),
                    .iov = &iovecs,
                    .iovlen = iovecs.len,
                    .control = null,
                    .controllen = 0,
                    .flags = 0,
                };
                // stdlib doesn't seem to have a nice wrapper for this
                const rc = std.posix.system.recvmsg(
                    sock,
                    &msg_hdr,
                    std.posix.MSG.NOSIGNAL,
                );
                switch (std.posix.errno(rc)) {
                    .SUCCESS => p.size = @intCast(rc),
                    .INTR => continue, // try again
                    .AGAIN => break,
                    .BADF => unreachable, // invalid sock fd (never invalidated)
                    .CONNREFUSED => unreachable, // invalid connection (a datagram socket)
                    .FAULT => unreachable, // invalid packet/msghdr/iov ptr (valid buffers)
                    .INVAL => unreachable, // invalid argument somewhere (?)
                    .NOMEM => return error.OutOfMemory,
                    else => |errno| {
                        std.log.err("recvmsg() = {}", .{errno});
                        return error.Unexpected;
                    },
                }
                _ = packet_writer.next();
            }
        }
    }
}
