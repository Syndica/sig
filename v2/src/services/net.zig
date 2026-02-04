const std = @import("std");
const start = @import("start");
const common = @import("common");
const Pair = common.net.Pair;

comptime {
    _ = start;
}

pub const name: []const u8 = "net";
pub const _start = {};
pub const panic = start.panic;

pub const ReadWrite = struct {
    ping: *Pair,
};

pub fn main(_: *std.io.Writer, rw: ReadWrite) !noreturn {
    rw.ping.init(8000);

    try tile(&.{rw.ping});
}

const MAX_SOCKETS = 10;

/// `ports` is the list of ports it'll listen on.
fn tile(pairs: []const *Pair) !noreturn {
    std.debug.assert(pairs.len <= MAX_SOCKETS);

    var sockets: [MAX_SOCKETS]std.posix.fd_t = undefined;
    var sockets_len: usize = 0;

    for (pairs, 0..) |pair, i| {
        errdefer for (sockets[0..i]) |socket| std.posix.close(socket);
        const socket = try std.posix.socket(
            std.posix.AF.INET,
            std.posix.SOCK.DGRAM | std.posix.SOCK.NONBLOCK,
            0,
        );
        errdefer std.posix.close(socket);

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
            const ptr = slice.one();
            var dummy: u32 = 0;
            ptr.size = @intCast(std.posix.recvfrom(
                sock,
                &ptr.data,
                0,
                &ptr.addr.any,
                &dummy,
            ) catch |err| switch (err) {
                error.WouldBlock => continue,
                else => |e| return e,
            });
            slice.markUsed(1);
        }
    }
}
