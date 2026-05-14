const std = @import("std");
const tracy = @import("tracy");

pub const FileWriter = struct {
    // observable fields
    file: std.fs.File,
    offset: u64,
    io_inflight: u32,

    ring: std.os.linux.IoUring,
    write_pos: u64,
    writing_bitmask: [num_words]u64,
    write_buf: [buffer_size]u8 align(sector_align),

    pub const page_size = 64 * 1024; // imperically good IOP size for disk IO
    pub const sector_align = 4096; // for O_DIRECT

    const buffer_size = 16 * 1024 * 1024;
    const num_pages = @divExact(buffer_size, page_size);
    const num_words = @divExact(num_pages, 64);

    const PageIndex = std.math.IntFittingRange(0, num_pages);
    const UserData = packed struct(u64) {
        disk_page: u32,
        page_idx: PageIndex,
        wrote: std.meta.Int(.unsigned, 64 - 32 - @bitSizeOf(PageIndex)),
    };

    pub fn init(self: *FileWriter, dir: std.fs.Dir, path: []const u8) !void {
        self.file = .{ .handle = try std.posix.openat(
            dir.fd,
            path,
            .{ .ACCMODE = .RDWR, .CREAT = true, .NOATIME = true, .CLOEXEC = true, .DIRECT = true },
            0o777,
        ) };
        errdefer self.file.close();

        self.offset = 0;
        self.io_inflight = 0;

        self.ring = try .init(num_pages, std.os.linux.IORING_SETUP_SQPOLL);
        errdefer self.ring.deinit();

        self.write_pos = 0;
        @memset(&self.writing_bitmask, 0);
    }

    pub fn deinit(self: *FileWriter) void {
        self.ring.deinit();
        self.file.close();
    }

    pub fn flush(self: *FileWriter) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "FileWriter.flush" });
        defer zone.deinit();

        // wait for all writes to complete
        while (self.io_inflight > 0)
            try self.poll();

        // make sure the writes made it to disk
        {
            const sync_zone = tracy.Zone.init(@src(), .{ .name = "FileWriter.fsync" });
            defer sync_zone.deinit();

            try std.posix.fsync(self.file.handle);
        }
    }

    pub fn writableSlice(self: *FileWriter) ![]u8 {
        const pos = self.write_pos % buffer_size;
        const page_idx = pos / page_size;
        const page_used = pos % page_size;

        // If we wrap around, wait for this page to stop being written to disk (io stall)
        const mask = @as(u64, 1) << @intCast(page_idx % 64);
        if (self.writing_bitmask[page_idx / 64] & mask > 0) {
            @branchHint(.unlikely);

            std.debug.assert(page_used == 0);
            std.debug.assert(self.io_inflight > 0);

            const zone = tracy.Zone.init(@src(), .{ .name = "FileWriter.stall" });
            defer zone.deinit();

            while (self.writing_bitmask[page_idx / 64] & mask > 0) {
                try self.poll();
            }
        }

        return self.write_buf[@as(u64, page_idx) * page_size..][page_used..page_size];
    }

    pub fn advance(self: *FileWriter, n: usize) !void {
        const pos = self.write_pos % buffer_size;
        const page_idx = pos / page_size;
        const page_used = pos % page_size;
        std.debug.assert(n <= page_size - page_used);

        self.write_pos += n;

        // when a page gets filled up, submit it to be written at the file offset
        const new_page_idx = (self.write_pos % buffer_size) / page_size;
        if (page_idx != new_page_idx) {
            std.debug.assert(new_page_idx == (page_idx + 1) % num_pages);

            const disk_page = @divExact(self.offset, page_size);
            self.offset += page_size;

            try self.submit(.{
                .disk_page = @intCast(disk_page),
                .page_idx = @intCast(page_idx),
                .wrote = 0,
            });
        }
    }

    fn submit(self: *FileWriter, user_data: UserData) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "FileWriter.submit" });
        defer zone.deinit();

        self.io_inflight += 1;
        std.debug.assert(self.io_inflight <= num_pages);

        const mask = @as(u64, 1) << @intCast(user_data.page_idx % 64);
        std.debug.assert(self.writing_bitmask[user_data.page_idx / 64] & mask == 0);
        self.writing_bitmask[user_data.page_idx / 64] |= mask;

        const sqe = while (true) break self.ring.get_sqe() catch |e| switch (e) {
            error.SubmissionQueueFull => {
                _ = try self.ring.submit();
                continue;
            },
        };
        sqe.prep_write(
            self.file.handle,
            self.write_buf[@as(u64, user_data.page_idx) * page_size..][user_data.wrote..page_size],
            @as(u64, user_data.disk_page) * page_size + user_data.wrote,
        );
        sqe.user_data = @bitCast(user_data);

        // when SQPOLL enabled, submit the SQE immediately so that it starts writing in background.
        // SQPOLL makes this cheap, as the kernel thread reaping SQEs is running in the background.
        if (self.ring.flags & std.os.linux.IORING_SETUP_SQPOLL > 0) {
            _ = try self.ring.submit();
        }
    }

    fn poll(self: *FileWriter) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "FileWriter.poll" });
        defer zone.deinit();

        var cqes: [num_pages]std.os.linux.io_uring_cqe = undefined;
        const n = try self.ring.copy_cqes(&cqes, 1);
        for (cqes[0..n]) |*cqe| {
            self.io_inflight -= 1;

            const wrote: u32 = switch (cqe.err()) {
                .SUCCESS => @intCast(cqe.res),
                .INTR => 0,
                .BADF => return error.InvalidFile, // should not be closed
                .SPIPE => return error.InvalidFile, // should not be a pipe/socket/fifo
                .AGAIN => return error.InvalidFile, // disk files dont support O_NONBLOCK
                .INVAL => return error.BadWriteArg,
                .NOSPC, .FBIG, .DQUOT => return error.OutOfStorage,
                .IO => return error.WriteFailed,
                .FAULT => unreachable, // invalid buffer
                else => |e| std.debug.panic("pwrite={}", .{e}),
            };

            var user_data: UserData = @bitCast(cqe.user_data);

            const mask = @as(u64, 1) << @intCast(user_data.page_idx % 64);
            std.debug.assert(self.writing_bitmask[user_data.page_idx / 64] & mask > 0);
            self.writing_bitmask[user_data.page_idx / 64] &= ~mask;

            user_data.wrote += @intCast(wrote);
            if (user_data.wrote < page_size) { // handle partial write
                try self.submit(user_data);
            }
        }
    }
};