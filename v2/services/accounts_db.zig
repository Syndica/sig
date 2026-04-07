//! Runs a node instance of the gossip protocol, passing around cluster information from the network
//! to other validator services.

const std = @import("std");
const start = @import("start");
const lib = @import("lib");

comptime {
    _ = start;
}

const Slot = lib.solana.Slot;
const Hash = lib.solana.Hash;

pub const name = .accounts_db;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadWrite = struct {
    snapshot_queue: *lib.accounts_db.SnapshotQueue,
};

pub const ReadOnly = struct {
    config: *const lib.accounts_db.Config,
};

pub fn serviceMain(ro: ReadOnly, rw: ReadWrite) !noreturn {
    const folder = ro.config.folder_path[0..ro.config.folder_path_len];
    std.log.info("AccountsDB started in ./{s}", .{folder});

    var snapshot_dir = try std.fs.cwd().openDir(folder, .{ .iterate = true });
    defer snapshot_dir.close();

    var snapshot_addr_reader = rw.snapshot_queue.incoming.get(.reader);
    const snapshot_file = try findOrDownloadSnapshot(snapshot_dir, &snapshot_addr_reader, .{
        .min_download_timeout_ns = 5 * std.time.ns_per_s,
        .min_download_warmup_ns = ro.config.min_snapshot_download_warmup_ms * 1_000_000,
        .min_download_speed_bytes = ro.config.min_snapshot_download_speed_mb * 1_000_000,
    });
    defer snapshot_file.close();

    while (true) std.atomic.spinLoopHint();
}

fn findOrDownloadSnapshot(
    snapshot_dir: std.fs.Dir,
    snapshot_addr_reader: *lib.accounts_db.SnapshotQueue.Incoming.Iterator(.reader),
    dl_config: Downloader.Config,
) !std.fs.File {
    var it = snapshot_dir.iterate();
    while (try it.next()) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.startsWith(u8, entry.name, "snapshot-")) continue;
        if (!std.mem.endsWith(u8, entry.name, ".tar.zst")) continue;

        const path = entry.name["snapshot-".len .. entry.name.len - ".tar.zst".len];
        const split = std.mem.indexOfScalar(u8, path, '-') orelse continue;
        _ = std.fmt.parseInt(Slot, path[0..split], 10) catch continue;
        _ = Hash.parseRuntime(path[split + 1 ..]) catch continue;

        std.log.info("Found existing snapshot: {s}", .{entry.name});
        return try snapshot_dir.openFile(entry.name, .{ .mode = .read_only });
    }

    var path_buf: [512]u8 = undefined;
    std.log.debug("Waiting for snapshot from gossip...", .{});
    while (true) {
        const e = snapshot_addr_reader.next() orelse continue;
        const addr = e.rpc_address;
        const path = try std.fmt.bufPrint(
            &path_buf,
            "snapshot-{d}-{f}.tar.zst",
            .{ e.slot_hash.slot, e.slot_hash.hash },
        );
        snapshot_addr_reader.markUsed();

        return downloadSnapshot(snapshot_dir, path, addr, dl_config) catch |err| {
            // if (@errorReturnTrace()) |t| std.debug.dumpStackTrace(t.*);
            std.log.err("snapshot download from {f} failed: {}", .{ addr, err });
            continue;
        };
    }
}

fn downloadSnapshot(
    snapshot_dir: std.fs.Dir,
    path: []const u8,
    addr: std.net.Address,
    dl_config: Downloader.Config,
) !std.fs.File {
    std.log.debug("Downloading snapshot from http://{f}/{s} ...", .{ addr, path });

    const snapshot_file = try snapshot_dir.createFile(path, .{ .truncate = true });
    errdefer {
        snapshot_file.close();
        snapshot_dir.deleteFile(path) catch {};
    }

    const socket = try std.posix.socket(addr.any.family, std.posix.SOCK.STREAM, 0);
    defer std.posix.close(socket);

    // Set timeout for all operations (connect, read, write)
    const tv = comptime std.mem.asBytes(&std.posix.timeval{ .sec = 1, .usec = 0 });
    try std.posix.setsockopt(socket, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, tv);
    try std.posix.setsockopt(socket, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, tv);
    try std.posix.connect(socket, &addr.any, addr.getOsSockLen());

    // Write http request.
    var io_buf: [4096]u8 = undefined;
    const req_buf =
        try std.fmt.bufPrint(&io_buf, "GET /{s} HTTP/1.1\r\nHost: {f}\r\n\r\n", .{ path, addr });

    var n: u64 = 0;
    while (n < req_buf.len) n += try std.posix.sendto(socket, req_buf[n..], 0, null, 0);

    // Read http response
    @memset(req_buf, 0);
    const header_end = while (true) break std.mem.indexOf(u8, io_buf[0..n], "\r\n\r\n") orelse {
        if (n == io_buf.len) return error.HttpResponseTooLarge;
        n += try std.posix.recvfrom(socket, io_buf[n..], 0, null, null);
        continue;
    };
    var extra_body = io_buf[0..n][header_end + 4 ..];

    // parse header from response
    var headers = std.mem.tokenizeAny(u8, io_buf[0..header_end], "\r\n");
    const status: []u8 = @constCast(headers.next() orelse return error.MissingHttpStatus);
    for (status) |*c| c.* = std.ascii.toLower(c.*);

    // Seems to fail & return error, even when it prints to the valid status. UB?
    // if (!std.mem.eql(u8, status, "http/1.1 200 ok")) return error.InvalidHttpResponse;

    const content_length = while (headers.next()) |header| {
        const hdr: []u8 = @constCast(header);
        const sep = std.mem.indexOfAny(u8, hdr, ": ") orelse return error.InvalidHttpHeader;
        const key, const val = .{ hdr[0..sep], hdr[sep + 2 ..] };
        for (key) |*c| c.* = std.ascii.toLower(c.*);
        for (val) |*c| c.* = std.ascii.toLower(c.*);
        if (std.mem.eql(u8, key, "content-length")) {
            break std.fmt.parseInt(u64, val, 10) catch return error.InvalidHttpContentLength;
        }
    } else return error.MissingHttpContentLength;

    var downloader = try Downloader.init(dl_config, content_length);
    defer downloader.deinit();

    // write to file extra that was read into io_buf
    var file_offset: usize = 0;
    while (file_offset < extra_body.len) {
        file_offset +=
            try std.posix.pwrite(snapshot_file.handle, extra_body[file_offset..], file_offset);
    }

    // send remaining bytes directly to file
    try downloader.transfer(socket, snapshot_file.handle, content_length -| file_offset, false);

    std.log.debug(" fsync()...", .{});
    try snapshot_file.sync();
    std.log.info("Downloaded snapshot {s}", .{path});
    return snapshot_file;
}

const Downloader = struct {
    config: Config,
    pipe: [2]std.posix.fd_t, // for transfering directly from socket -> file
    started: ?std.time.Instant,
    timestamp: std.time.Instant,
    transferred: usize = 0,
    total: usize,
    total_transfered: usize = 0,

    const Config = struct {
        min_download_timeout_ns: u64,
        min_download_warmup_ns: u64,
        min_download_speed_bytes: u64,
    };

    fn init(config: Config, total: usize) !Downloader {
        const started: std.time.Instant = try .now();
        return .{
            .config = config,
            .started = started,
            .timestamp = started,
            .total = total,
            .pipe = try std.posix.pipe2(.{ .CLOEXEC = true }),
        };
    }

    fn deinit(self: *const Downloader) void {
        std.posix.close(self.pipe[0]);
        std.posix.close(self.pipe[1]);
    }

    fn transfer(
        self: *Downloader,
        from: std.posix.fd_t,
        to: std.posix.fd_t,
        bytes: usize,
        hint_has_more: bool,
    ) !void {
        if (bytes == 0) return;

        var in: usize = 0;
        var out: usize = 0;
        while (in < bytes) {
            const now = try std.time.Instant.now();
            const elapsed_ns = now.since(self.timestamp);
            if (elapsed_ns >= self.config.min_download_timeout_ns) return error.TimedOut;

            const n = splice(from, self.pipe[1], bytes - in, hint_has_more) catch |e| switch (e) {
                error.WouldBlock => continue,
                else => |err| return err,
            };
            in += if (n > 0) n else return error.EndOfStream;

            const hit_warmup = blk: {
                const started = self.started orelse break :blk false;
                if (now.since(started) < self.config.min_download_warmup_ns) break :blk false;
                self.started = null;
                break :blk true;
            };

            self.transferred += n;
            if (elapsed_ns >= std.time.ns_per_s or hit_warmup) {
                const elapsed_secs = @as(f64, @floatFromInt(elapsed_ns)) / std.time.ns_per_s;
                const bytes_per_sec: u64 =
                    @intFromFloat(@as(f64, @floatFromInt(self.transferred)) / elapsed_secs);

                self.total_transfered += self.transferred;
                self.timestamp = now;
                self.transferred = 0;

                const progress = (@as(f64, @floatFromInt(self.total_transfered)) * 100.0) /
                    @as(f64, @floatFromInt(self.total));
                std.log.debug(" download speed: {B:.2}/s {d:.1}% ({}/{})", .{
                    bytes_per_sec,
                    progress,
                    self.total_transfered,
                    self.total,
                });

                if (bytes_per_sec < self.config.min_download_speed_bytes) {
                    return error.TooSlow;
                }
            }

            const will_pipe_more = hint_has_more or (in < bytes);
            out += splice(self.pipe[0], to, bytes - out, will_pipe_more) catch |e| switch (e) {
                error.WouldBlock => continue,
                else => |err| return err,
            };
        }

        // Flush remaining of what's left in pipe to file.
        while (out < bytes) {
            const n = try splice(self.pipe[0], to, bytes - out, hint_has_more);
            std.log.debug("out remain: {}", .{n});
            out += n;
        }
    }

    fn splice(from: std.posix.fd_t, to: std.posix.fd_t, n: usize, hint_has_more: bool) !usize {
        const SPLICE_F_MOVE: u32 = 1;
        const SPLICE_F_NONBLOCK: u32 = 2;
        const SPLICE_F_MORE: u32 = 4;

        const flags = SPLICE_F_MOVE | SPLICE_F_NONBLOCK |
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
};
