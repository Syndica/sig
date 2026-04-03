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
    snapshot_queue: *lib.gossip.SnapshotQueue,
};

pub const ReadOnly = struct {
    config: *const lib.accounts_db.Config,
};

var scratch_memory: [1 * 1024 * 1024]u8 = undefined;

pub fn serviceMain(ro: ReadOnly, rw: ReadWrite) !noreturn {
    const folder = ro.config.folder_path[0..ro.config.folder_path_len];
    std.log.info("AccountsDB started in ./{s}", .{folder});

    var snapshot_dir = try std.fs.cwd().openDir(folder, .{ .iterate = true });
    defer snapshot_dir.close();

    var fba = std.heap.FixedBufferAllocator.init(&scratch_memory);
    var snapshot_addr_reader = rw.snapshot_queue.incoming.get(.reader);
    const snapshot_file = try findOrDownloadSnapshot(
        &fba,
        snapshot_dir,
        &snapshot_addr_reader,
        ro.config.min_snapshot_download_warmup_ns,
        ro.config.min_snapshot_download_speed_mb,
    );
    defer snapshot_file.close();

    while (true) std.atomic.spinLoopHint();
}

fn findOrDownloadSnapshot(
    fba: *std.heap.FixedBufferAllocator,
    snapshot_dir: std.fs.Dir,
    snapshot_addr_reader: *lib.gossip.SnapshotQueue.Incoming.Iterator(.reader),
    min_download_warmup_ns: u64,
    min_download_speed_mb: u64,
) !std.fs.File {
    var it = snapshot_dir.iterate();
    while (try it.next()) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.startsWith(u8, entry.name, "snapshot-")) continue;
        if (!std.mem.endsWith(u8, entry.name, ".tar.zst")) continue;

        const path = entry.name["snapshot-".len .. entry.name.len - ".tar.zst".len];
        const split = std.mem.indexOfScalar(u8, path, '-') orelse continue;
        _ = std.fmt.parseInt(Slot, path[0..split], 10) catch continue;
        _ = Hash.parseRuntime(path[split + 1..]) catch continue;

        std.log.info("Found existing snapshot: {s}", .{entry.name});
        return try snapshot_dir.openFile(entry.name, .{ .mode = .read_only });
    }

    var url_buf: [512]u8 = undefined;
    var path_buf: [512]u8 = undefined;
    std.log.debug("Waiting for snapshot from gossip...", .{});
    while (true) {
        const entry = snapshot_addr_reader.next() orelse continue;
        const path = try std.fmt.bufPrint(&path_buf, "snapshot-{d}-{f}.tar.zst", .{ entry.slot, entry.hash });
        const url = try std.fmt.bufPrint(&url_buf, "http://{f}/{s}", .{entry.rpc_address, path});
        snapshot_addr_reader.markUsed();

        std.log.debug("Downloading snapshot from {s}...", .{url});

        var client: std.http.Client = .{ .allocator = fba.allocator() };
        defer {
            client.deinit();
            fba.reset();
        }

        const write_buf = try fba.allocator().alloc(u8, 4096);

        var snapshot_file = try snapshot_dir.createFile(path, .{});
        var writer: RateLimitedFileWriter = .{
            .file_writer = snapshot_file.writerStreaming(write_buf),
            .warmup_period_ns = min_download_warmup_ns,
            .min_bytes_per_sec = min_download_speed_mb * (1 * 1024 * 1024),
            .timestamp = std.time.Instant.now() catch unreachable,
        };

        const maybe_error_msg = blk: {
            const res = client.fetch(.{
                .location = .{ .url = url },
                .method = .GET,
                .response_writer = &writer.interface,
            }) catch |err| {
                if (@errorReturnTrace()) |t| std.debug.dumpStackTrace(t.*);
                if (err == error.WriteFailed) {
                    if (writer.err) |e| break :blk @errorName(e);
                    if (writer.file_writer.err) |e| break :blk @errorName(e);
                }
                break :blk @errorName(err);
            };
            break :blk switch (res.status) {
                .ok => null,
                else => res.status.phrase() orelse "failed http request",
            };
        };

        if (maybe_error_msg) |err_msg| {
            std.log.err("Failed to download snapshot {s}: {s}", .{url, err_msg});
            snapshot_file.close();
            try snapshot_dir.deleteFile(path);
            continue;
        }

        std.log.info("Downloaded snapshot {s} from gossip", .{path});
        return snapshot_file;
    }
}

const RateLimitedFileWriter = struct {
    file_writer: std.fs.File.Writer,
    warmup_period_ns: u64,
    min_bytes_per_sec: u64,
    timestamp: std.time.Instant,
    interface: std.Io.Writer = .{
        .buffer = &.{},
        .end = 0,
        .vtable = &.{
            .drain = Self.drain,
            .sendFile = Self.sendFile,
        },
    },
    err: ?Error = null,
    transferred: usize = 0,
    warmup_elapsed: u64 = 0,

    const Self = @This();
    const Error = error{TooSlow};

    fn checkTransfer(self: *Self, n: usize) Error!void {
        self.transferred += n;

        const now = std.time.Instant.now() catch unreachable;
        const elapsed = now.since(self.timestamp);

        std.log.debug("transferred={} n={} elapsed={D}", .{self.transferred, n, elapsed});

        if (elapsed >= std.time.ns_per_s or self.warmup_elapsed + elapsed >= self.warmup_period_ns) {
            const secs = @as(f64, @floatFromInt(elapsed)) / std.time.ns_per_s;
            const bytes_per_sec: u64 = @intFromFloat(@as(f64, @floatFromInt(self.transferred)) / secs);
            std.log.debug("  snapshot download speed: {B}/s", .{bytes_per_sec});

            self.transferred = 0;
            self.timestamp = now;
            self.warmup_elapsed += elapsed;

            if (bytes_per_sec < self.min_bytes_per_sec) {
                return error.TooSlow;
            }
        }
    }

    fn drain(
        writer: *std.Io.Writer,
        data: []const []const u8,
        splat: usize,
    ) std.Io.Writer.Error!usize {
        const self: *Self = @fieldParentPtr("interface", writer);
        const w = &self.file_writer.interface;
        const n = try w.vtable.drain(w, data, splat);
        self.checkTransfer(n) catch |e| {
            self.err = e;
            return error.WriteFailed;
        };
        return n;
    }

    fn sendFile(
        writer: *std.Io.Writer,
        reader: *std.fs.File.Reader,
        limit: std.Io.Limit,
    ) std.Io.Writer.FileError!usize {
        const self: *Self = @fieldParentPtr("interface", writer);
        const w = &self.file_writer.interface;
        const n = try w.vtable.sendFile(w, reader, limit);
        self.checkTransfer(n) catch |e| {
            self.err = e;
            return error.WriteFailed;
        };
        return n;
    }
};