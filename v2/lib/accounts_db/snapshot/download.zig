const std = @import("std");

pub const Config = struct {
    min_timeout_ns: u64,
    min_warmup_ns: u64,
    min_speed_bytes: u64,
    min_lockin_percent: f64,
};

pub fn downloadSnapshot(
    snapshot_dir: std.fs.Dir,
    path: []const u8,
    addr: std.net.Address,
    config: Config,
) !std.fs.File {
    const snapshot_file = try snapshot_dir.createFile(path, .{ .truncate = true });
    errdefer {
        snapshot_file.close();
        snapshot_dir.deleteFile(path) catch {};
    }

    const socket = try std.posix.socket(addr.any.family, std.posix.SOCK.STREAM, 0);
    defer std.posix.close(socket);

    // Set timeout for all operations (connect, read, write)
    var tv = std.posix.timeval{ .sec = 1, .usec = 0 };
    try std.posix.setsockopt(
        socket,
        std.posix.SOL.SOCKET,
        std.posix.SO.RCVTIMEO,
        std.mem.asBytes(&tv),
    );
    try std.posix.setsockopt(
        socket,
        std.posix.SOL.SOCKET,
        std.posix.SO.SNDTIMEO,
        std.mem.asBytes(&tv),
    );

    try std.posix.connect(socket, &addr.any, addr.getOsSockLen());

    // Write http request.
    var io_buf: [4096]u8 = undefined;
    const req_buf =
        try std.fmt.bufPrint(&io_buf, "GET /{s} HTTP/1.1\r\nHost: {f}\r\n\r\n", .{ path, addr });

    var n: u64 = 0;
    while (n < req_buf.len) // use sendto() explicitly to avoid writeAll calling write()
        n += try std.posix.sendto(socket, req_buf[n..], 0, null, 0);

    // Read http response
    n = 0;
    const headers_end = while (true) break std.mem.indexOf(u8, io_buf[0..n], "\r\n\r\n") orelse {
        if (n == io_buf.len) return error.HttpResponseTooLarge;
        n += try std.posix.recvfrom(socket, io_buf[n..], 0, null, null);
        continue;
    };

    var headers = std.mem.splitSequence(u8, io_buf[0..headers_end], "\r\n");
    const extra_body = io_buf[headers_end + 4 .. n];

    // parse header from response
    const status: []u8 = @constCast(headers.next() orelse return error.MissingHttpStatus);
    for (status) |*c| c.* = std.ascii.toLower(c.*);
    if (!std.mem.eql(u8, status, "http/1.1 200 ok")) return error.InvalidHttpResponse;

    const content_length = while (headers.next()) |header| {
        const sep = std.mem.indexOfAny(u8, header, ": ") orelse return error.InvalidHttpHeader;
        const key: []u8, const val = .{ @constCast(header[0..sep]), header[sep + 2 ..] };
        for (key) |*c| c.* = std.ascii.toLower(c.*);
        if (std.mem.eql(u8, key, "content-length")) {
            break std.fmt.parseInt(u64, val, 10) catch return error.InvalidHttpContentLength;
        }
    } else return error.MissingHttpContentLength;

    if (content_length > 512 * 1024 * 1024 * 1024) return error.SnapshotTooBig;
    std.log.debug(" fetching {B:.2} snapshot file", .{content_length});
    try std.posix.ftruncate(snapshot_file.handle, content_length);

    // write any body data read into io_buf
    var offset: u64 = 0;
    while (offset < extra_body.len)
        offset += try std.posix.pwrite(snapshot_file.handle, extra_body[offset..], offset);

    // Start transfering over from socket -> pipe -> file
    const pipe_buf_size = 64 * 1024; // TODO: get it directly from the pipe
    const pipe = try std.posix.pipe2(.{ .CLOEXEC = true }); // for direct socket -> pipe -> file
    defer {
        std.posix.close(pipe[0]);
        std.posix.close(pipe[1]);
    }

    tv = .{
        .sec = @intCast(config.min_timeout_ns / std.time.ns_per_s),
        .usec = @intCast((config.min_timeout_ns % std.time.ns_per_s) / std.time.ns_per_us),
    };
    try std.posix.setsockopt(
        socket,
        std.posix.SOL.SOCKET,
        std.posix.SO.RCVTIMEO,
        std.mem.asBytes(&tv),
    );

    const Period = struct { timestamp: std.time.Instant, transferred: usize };
    var total: Period = .{ .timestamp = try .now(), .transferred = 0 };
    var per_sec: Period = .{ .timestamp = total.timestamp, .transferred = 0 };

    var past_warmup = false;
    var past_lockin = false;

    var in: usize = 0;
    var out: usize = 0;
    while (in < content_length) {
        const now = try std.time.Instant.now();
        const since_per_sec = now.since(per_sec.timestamp);
        // if (since_per_sec >= config.min_timeout_ns) return error.TimedOut;

        const may_partial_move = (content_length - in) > pipe_buf_size;
        n = try splice(socket, pipe[1], content_length - in, may_partial_move);
        in += if (n > 0) n else return error.EndOfStream;

        const will_move_more = in < content_length;
        out += try splice(pipe[0], snapshot_file.handle, in - out, will_move_more);

        total.transferred += n;
        per_sec.transferred += n;

        const over_warmup_period = now.since(total.timestamp) >= config.min_warmup_ns;
        const crossed_warmup_period = over_warmup_period and !past_warmup;
        past_warmup = over_warmup_period;

        if (since_per_sec >= std.time.ns_per_s or crossed_warmup_period) {
            const elapsed_secs = @as(f64, @floatFromInt(since_per_sec)) / std.time.ns_per_s;
            const bytes_per_sec: u64 =
                @intFromFloat(@as(f64, @floatFromInt(per_sec.transferred)) / elapsed_secs);
            const total_progress = (@as(f64, @floatFromInt(total.transferred)) * 100.0) /
                @as(f64, @floatFromInt(content_length));

            per_sec.transferred = 0;
            per_sec.timestamp = now;

            const over_lockin_percent = (total_progress / 100.0) >= config.min_lockin_percent;
            const crossed_lockin_percent = over_lockin_percent and !past_lockin;
            past_lockin = over_lockin_percent;

            std.log.debug(" download speed: {B:.2}/s {d:.1}% ({B:.2}/{B:.2}) {s}", .{
                bytes_per_sec,
                total_progress,
                total.transferred,
                content_length,
                if (crossed_lockin_percent) "(locked in)" else "",
            });

            // rate limit
            const too_slow = bytes_per_sec < config.min_speed_bytes;
            if (too_slow and past_warmup and !past_lockin) {
                return error.TooSlow;
            }
        }
    }

    // finish up any bytes still left in the pipe
    while (out < in) {
        const may_partial_move = (in - out) > pipe_buf_size;
        out += try splice(pipe[0], snapshot_file.handle, in - out, may_partial_move);
    }

    std.log.debug(" commiting snapshot file to disk..", .{});
    try snapshot_file.sync();
    return snapshot_file;
}

fn splice(from: std.posix.fd_t, to: std.posix.fd_t, n: usize, hint_has_more: bool) !usize {
    const SPLICE_F_MOVE: u32 = 1;
    // const SPLICE_F_NONBLOCK: u32 = 2;
    const SPLICE_F_MORE: u32 = 4;

    const flags = SPLICE_F_MOVE |
        (SPLICE_F_MORE * @intFromBool(hint_has_more));

    const rc = std.os.linux.syscall6(.splice, @intCast(from), 0, @intCast(to), 0, n, flags);
    switch (std.posix.errno(rc)) {
        .SUCCESS => return rc,
        .AGAIN => return error.WouldBlock,
        .BADF => return error.BadFile, // one side stopped supporting read/write
        .INVAL => unreachable, // bad arg somewhere
        .NOMEM => return error.OutOfMemory,
        .SPIPE => unreachable, // if the offsets were null over pipes (they're both 0)
        else => |err| return std.posix.unexpectedErrno(err),
    }
}
