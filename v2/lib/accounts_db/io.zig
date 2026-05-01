const std = @import("std");
const lib = @import("../lib.zig");
const tracy = @import("tracy");

const tel = lib.telemetry;

pub const page_size = 64 * 1024;
const sector_align = 4 * 1024;

pub fn openDirect(dir: std.fs.Dir, path: []const u8, mode: enum { rw, read_only }) !std.fs.File {
    return .{ .handle = try std.posix.openat(
        dir.fd,
        path,
        .{
            .ACCMODE = if (mode == .rw) .RDWR else .RDONLY,
            .CREAT = mode == .rw,
            .NOATIME = true,
            .CLOEXEC = true,
            .DIRECT = true,
        },
        0o777,
    ) };
}

pub fn FileWriter(buffer_size: comptime_int) type {
    const Page = u32;
    const Wrote = std.math.IntFittingRange(0, page_size + 1);
    const Index = std.meta.Int(.unsigned, 64 - 32 - @bitSizeOf(Wrote));

    const UserData = packed struct(u64) {
        disk_page: Page,
        bytes_written: Wrote,
        page_idx: Index,
    };

    const num_pages = @divExact(buffer_size, page_size);
    std.debug.assert(num_pages <= std.math.maxInt(Index) + 1);

    return struct {
        ring: std.os.linux.IoUring,
        file: std.fs.File,
        tail: u64,
        inflight: u32,
        writing: [num_pages]bool,
        pages: [num_pages]extern struct { bytes: [page_size]u8 align(sector_align) },

        const Self = @This();

        pub fn init(self: *Self, file: std.fs.File) !void {
            self.ring = try .init(num_pages, std.os.linux.IORING_SETUP_SQPOLL);
            errdefer self.ring.deinit();

            self.file = file;
            self.tail = 0;
            self.inflight = 0;
            @memset(&self.writing, false);
        }

        pub fn deinit(self: *Self) void {
            self.ring.deinit();
        }

        pub fn getSlice(self: *Self, logger: tel.Logger("FileWriter")) ![]u8 {
            const t = self.tail % buffer_size;
            const idx = t / page_size;
            const used = t % page_size;

            if (self.ring.cq_ready() > 0) {
                try self.poll(logger, false);
            }

            if (self.writing[idx]) {
                @branchHint(.unlikely);

                const zone = tracy.Zone.init(@src(), .{ .name = "FileWriter.poll" });
                defer zone.deinit();

                // TODO: record time stalled
                while (self.writing[idx])
                    try self.poll(logger, true);
            }

            return self.pages[idx].bytes[used..];
        }

        pub fn advance(self: *Self, n: usize) !void {
            std.debug.assert(n <= page_size);

            const old_tail = self.tail;
            self.tail += n;

            const old_idx = (old_tail % buffer_size) / page_size;
            const new_idx = (self.tail % buffer_size) / page_size;
            if (old_idx != new_idx) {
                try self.submit(.{
                    .disk_page = @intCast(old_tail / page_size),
                    .bytes_written = 0,
                    .page_idx = @intCast(old_idx),
                });
            }
        }

        fn submit(self: *Self, user_data: UserData) !void {
            const zone = tracy.Zone.init(@src(), .{ .name = "FileReader.submit" });
            defer zone.deinit();

            std.debug.assert(!self.writing[user_data.page_idx]);
            self.writing[user_data.page_idx] = true;
            self.inflight += 1;

            const sqe: *std.os.linux.io_uring_sqe =
                while (true) break self.ring.get_sqe() catch |err| switch (err) {
                    error.SubmissionQueueFull => {
                        _ = try self.ring.submit();
                        continue;
                    },
                };
            sqe.prep_write(
                self.file.handle,
                self.pages[user_data.page_idx].bytes[user_data.bytes_written..],
                (@as(u64, user_data.disk_page) * page_size) + user_data.bytes_written,
            );
            sqe.user_data = @bitCast(user_data);
            _ = try self.ring.submit(); // SQPOLL should be cheap to submit
        }

        fn poll(self: *Self, logger: tel.Logger("FileWriter"), block: bool) !void {
            var cqes: [num_pages]std.os.linux.io_uring_cqe = undefined;
            const n = try self.ring.copy_cqes(&cqes, @intFromBool(block));
            for (cqes[0..n]) |*cqe| {
                var user_data: UserData = @bitCast(cqe.user_data);
                if (cqe.err() != .SUCCESS) {
                    logger.err().logf("pwrite(fd={}, ptr={*}, offset={} len={}) = {}", .{
                        self.file.handle,
                        self.pages[user_data.page_idx].bytes[user_data.bytes_written..].ptr,
                        @as(u64, user_data.disk_page) * page_size + user_data.bytes_written,
                        page_size - user_data.bytes_written,
                        cqe.err(),
                    });
                    return error.WriteFailed;
                }

                std.debug.assert(self.writing[user_data.page_idx]);
                self.writing[user_data.page_idx] = false;
                self.inflight -= 1;

                user_data.bytes_written += @intCast(cqe.res);
                if (user_data.bytes_written < page_size) {
                    try self.submit(user_data);
                }
            }
        }

        pub fn sync(self: *Self, logger: tel.Logger("FileWriter")) !void {
            const zone = tracy.Zone.init(@src(), .{ .name = "FileReader.sync" });
            defer zone.deinit();

            while (self.inflight > 0) {
                try self.poll(logger, true);
            }

            try self.file.sync();
        }
    };
}

pub fn FileReader(buffer_size: comptime_int) type {
    const Page = u32;
    const Read = std.math.IntFittingRange(0, page_size + 1);
    const Index = std.meta.Int(.unsigned, 64 - 32 - @bitSizeOf(Read));

    const UserData = packed struct(u64) {
        disk_page: Page,
        bytes_read: Read,
        page_idx: Index,
    };

    const num_pages = @divExact(buffer_size, page_size);
    std.debug.assert(num_pages <= std.math.maxInt(Index) + 1);

    return struct {
        ring: std.os.linux.IoUring,
        file: std.fs.File,
        head: u64,
        tail: u64,
        meta: [num_pages]packed struct(u32) { ready: bool, len: u31 },
        pages: [num_pages]extern struct { bytes: [page_size]u8 align(sector_align) },

        const Self = @This();

        pub fn init(self: *Self, file: std.fs.File) !void {
            self.ring = try .init(num_pages, std.os.linux.IORING_SETUP_SQPOLL);
            errdefer self.ring.deinit();

            self.file = file;
            self.head = 0;
            self.tail = 0;
            @memset(&self.meta, .{ .ready = false, .len = 0 });

            for (0..num_pages) |_| try self.enqueue();
        }

        pub fn deinit(self: *Self) void {
            self.ring.deinit();
        }

        pub fn enqueue(self: *Self) !void {
            const reads_queued = self.tail - self.head;
            std.debug.assert(reads_queued < buffer_size);

            const disk_page: u32 = @intCast(@divExact(self.tail, page_size));
            const page_idx: u8 = @intCast((self.tail % buffer_size) / page_size);
            self.tail += page_size;

            try self.submit(.{ .disk_page = disk_page, .bytes_read = 0, .page_idx = page_idx });
        }

        fn submit(self: *Self, user_data: UserData) !void {
            const zone = tracy.Zone.init(@src(), .{ .name = "FileReader.submit" });
            defer zone.deinit();

            const meta = self.meta[user_data.page_idx];
            std.debug.assert(!meta.ready and meta.len == 0);

            const sqe: *std.os.linux.io_uring_sqe =
                while (true) break self.ring.get_sqe() catch |err| switch (err) {
                    error.SubmissionQueueFull => {
                        _ = try self.ring.submit();
                        continue;
                    },
                };
            sqe.prep_read(
                self.file.handle,
                self.pages[user_data.page_idx].bytes[user_data.bytes_read..],
                (@as(u64, user_data.disk_page) * page_size) + user_data.bytes_read,
            );
            sqe.user_data = @bitCast(user_data);
            _ = try self.ring.submit(); // SQPOLL should be cheap to submit
        }

        pub fn getSlice(self: *Self, logger: tel.Logger("FileReader")) ![]u8 {
            const h = self.head % buffer_size;
            const idx = h / page_size;
            const used = h % page_size;

            const meta = &self.meta[idx];
            if (!meta.ready) {
                @branchHint(.unlikely);

                const zone = tracy.Zone.init(@src(), .{ .name = "FileReader.poll" });
                defer zone.deinit();

                var cqes: [num_pages]std.os.linux.io_uring_cqe = undefined;
                while (!meta.ready) {
                    const n = try self.ring.copy_cqes(&cqes, 1);
                    for (cqes[0..n]) |*cqe| {
                        var user_data: UserData = @bitCast(cqe.user_data);
                        if (cqe.err() != .SUCCESS) {
                            logger.err().logf("pread(fd={}, ptr={*}, offset={}, len={}) = {}", .{
                                self.file.handle,
                                self.pages[user_data.page_idx].bytes[user_data.bytes_read..].ptr,
                                @as(u64, user_data.disk_page) * page_size + user_data.bytes_read,
                                page_size - user_data.bytes_read,
                                cqe.err(),
                            });
                            return error.ReadFailed;
                        }

                        const eof = cqe.res == 0;
                        user_data.bytes_read += @intCast(cqe.res);
                        if (user_data.bytes_read == page_size or eof) {
                            self.meta[user_data.page_idx] =
                                .{ .ready = true, .len = user_data.bytes_read };
                        } else {
                            try self.submit(user_data);
                        }
                    }
                }
            }

            return self.pages[idx].bytes[used..meta.len];
        }

        pub fn advance(self: *Self, n: usize) !void {
            std.debug.assert(n <= page_size);

            const old_head = self.head;
            self.head += n;

            const old_idx = (old_head % buffer_size) / page_size;
            const new_idx = (self.head % buffer_size) / page_size;
            if (old_idx != new_idx) {
                self.meta[old_idx] = .{ .ready = false, .len = 0 };
                try self.enqueue();
            }
        }
    };
}
