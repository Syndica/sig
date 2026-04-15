const std = @import("std");
const lib = @import("../../lib.zig");

const tel = lib.telemetry;
const SlotAndHash = lib.solana.SlotAndHash;

pub const Config = struct {
    min_timeout_ns: u64,
    min_warmup_ns: u64,
    min_speed_bytes: u64,
    min_lockin_percent: f64,
};

pub fn downloadSnapshot(
    logger: tel.Logger("downloadSnapshot"),
    snapshot_dir: std.fs.Dir,
    slot_hash: SlotAndHash,
    addr: std.net.Address,
    config: Config,
) !std.fs.File {
    const TMP_FILE_EXT = ".part";

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dl_path = try std.fmt.bufPrint(
        &path_buf,
        "snapshot-{d}-{f}.tar.zst" ++ TMP_FILE_EXT,
        .{ slot_hash.slot, slot_hash.hash },
    );
    const ready_path = dl_path[0 .. dl_path.len - TMP_FILE_EXT.len];

    // download the file into dl_path
    const snapshot_file = try snapshot_dir.createFile(dl_path, .{ .truncate = true });
    downloadToFile(.from(logger), snapshot_file, ready_path, addr, config) catch |err| {
        snapshot_file.close();
        try snapshot_dir.deleteFile(dl_path);
        return err;
    };

    // move the file from dl_path to ready_path
    snapshot_file.close();
    try snapshot_dir.rename(dl_path, ready_path);
    return try snapshot_dir.openFile(ready_path, .{ .mode = .read_only });
}

fn downloadToFile(
    logger: tel.Logger("downloadSnapshot"),
    snapshot_file: std.fs.File,
    path: []const u8,
    addr: std.net.Address,
    config: Config,
) !void {
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
            break std.fmt.parseInt(usize, val, 10) catch return error.InvalidHttpContentLength;
        }
    } else return error.MissingHttpContentLength;

    if (content_length > 512 * 1024 * 1024 * 1024) { // 512 GB reasonable cap against storage DoS
        return error.SnapshotTooBig;
    }

    // TODO: should be trace() instead when per-service filtering is implemented.
    logger.debug().logf(" fetching {B:.2} snapshot file", .{content_length});
    try std.posix.ftruncate(snapshot_file.handle, content_length);

    // write any body data read into io_buf
    try snapshot_file.writeAll(extra_body);

    // Start transfering over from socket -> pipe -> file
    const pipe = try std.posix.pipe2(.{ .CLOEXEC = true }); // for direct socket -> pipe -> file
    defer {
        std.posix.close(pipe[0]);
        std.posix.close(pipe[1]);
    }

    const MaxPipeSize = struct {
        var global_size: std.atomic.Value(usize) = .init(0);

        fn get() !usize {
            var max_size = global_size.load(.monotonic);
            if (max_size > 0) return max_size;

            const proc_fs = try std.fs.openFileAbsolute(
                "/proc/sys/fs/pipe-max-size",
                .{ .mode = .read_only },
            );
            defer proc_fs.close();

            var size_buf: [16]u8 = undefined;
            const size_len = try proc_fs.readAll(&size_buf);

            max_size = @max(
                std.heap.page_size_min,
                try std.fmt.parseInt(usize, size_buf[0..size_len -| 1], 10),
            );
            global_size.store(max_size, .monotonic);
            return max_size;
        }
    };

    const F_SETPIPE_SZ = 1031;
    var pipe_buf_size = try MaxPipeSize.get(); // larger pipe size to speed up downloads
    pipe_buf_size = try std.posix.fcntl(pipe[1], F_SETPIPE_SZ, pipe_buf_size);

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

    var timer = try std.time.Timer.start();
    var last_elapsed = timer.read();
    var total_downloaded: usize = 0;

    var past_warmup = false;
    var past_lockin = false;

    var in: usize = extra_body.len;
    var out: usize = 0;
    while (in < content_length) {
        const may_partial_move = (content_length - in) > pipe_buf_size;
        n = try splice(socket, pipe[1], content_length - in, .{
            .MOVE = true,
            .MORE = may_partial_move,
        });
        in += if (n > 0) n else return error.EndOfStream;

        const total_elapsed = timer.read();
        const current_elapsed = total_elapsed - last_elapsed;
        total_downloaded += n;

        const will_move_more = in < content_length;
        out += splice(pipe[0], snapshot_file.handle, in - out, .{
            .MOVE = true,
            .MORE = will_move_more,
            .NONBLOCK = true,
        }) catch |e| switch (e) {
            error.WouldBlock => 0,
            else => |err| return err,
        };

        const over_warmup_period = total_elapsed >= config.min_warmup_ns;
        const crossed_warmup_period = over_warmup_period and !past_warmup;
        past_warmup = over_warmup_period;

        if (current_elapsed >= std.time.ns_per_s or crossed_warmup_period) {
            last_elapsed = total_elapsed;

            const total_elapsed_secs = @as(f64, @floatFromInt(total_elapsed)) / std.time.ns_per_s;
            const bytes_per_sec: u64 =
                @intFromFloat(@as(f64, @floatFromInt(total_downloaded)) / total_elapsed_secs);
            const total_progress = (@as(f64, @floatFromInt(total_downloaded)) * 100.0) /
                @as(f64, @floatFromInt(content_length));

            const over_lockin_percent = (total_progress / 100.0) >= config.min_lockin_percent;
            const crossed_lockin_percent = over_lockin_percent and !past_lockin;
            past_lockin = over_lockin_percent;

            // TODO: should be trace() instead when per-service filtering is implemented.
            logger.info().logf(" download speed: {B:.2}/s {d:.1}% ({B:.2}/{B:.3}) {s}", .{
                bytes_per_sec,
                total_progress,
                total_downloaded,
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
        out += try splice(pipe[0], snapshot_file.handle, in - out, .{
            .MOVE = true,
            .MORE = may_partial_move,
        });
    }

    // TODO: should be debug() instead when per-service filtering is implemented.
    logger.info().logf(" commiting snapshot file to disk..", .{});
    try snapshot_file.sync();
}

const SPLICE_F = packed struct(u8) {
    MOVE: bool = false,
    NONBLOCK: bool = false,
    MORE: bool = false,
    _: u5 = 0,
};

fn splice(from: std.posix.fd_t, to: std.posix.fd_t, n: usize, flags: SPLICE_F) !usize {
    const raw_flags: u8 = @bitCast(flags);
    const rc = std.os.linux.syscall6(.splice, @intCast(from), 0, @intCast(to), 0, n, raw_flags);
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
