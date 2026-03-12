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

pub const ReadWrite = struct {
    pair: *Pair,

    obs_startup: *obs.Startup,
    obs_log_streams: []obs.log.MessageStream,
    obs_id_mem: []u8,
    obs_gauges: []std.atomic.Value(u64),
    obs_histogram_data: []u64,
};

pub fn serviceMain(rw: ReadWrite) !noreturn {
    const obs_log_stream = &rw.obs_log_streams[rw.obs_startup.log_streams.fetchAdd(1, .release)];
    obs_log_stream.name.init(@tagName(name));

    const metric_appender: obs.MetricAppender = .{
        .id_mem = rw.obs_id_mem,
        .id_mem_end = &rw.obs_startup.id_mem_end,

        .gauges = rw.obs_gauges,
        .gauges_end = &rw.obs_startup.gauges_end,

        .histogram_data = rw.obs_histogram_data,
        .histogram_data_end = &rw.obs_startup.histogram_data_end,
    };
    _ = metric_appender;

    rw.obs_startup.signalReady();

    try mainInner(
        .{
            .sink = .{ .ring = &obs_log_stream.ring },
            .max_level = rw.obs_startup.max_log_level,
        },
        &.{rw.pair},
    );
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
