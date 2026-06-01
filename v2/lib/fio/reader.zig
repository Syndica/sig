const std = @import("std");
const tracy = @import("tracy");
const lib = @import("../lib.zig");

const tel = lib.telemetry;
const sector_size = lib.fio.sector_size;

pub fn FileReader(
    comptime config: struct {
        buffer_size: usize, // max inflight data being read from disk
        block_size: usize, // data chunk  size submitted to disk to be read
    },
) type {
    return struct {
        // publically observable fields
        file: std.fs.File,
        offset: u64,

        io_transferred: u64, // total bytes read from disk.
        io_inflight: u32, // current inflight blocks being read to disk.
        io_stalled: u64, // total time spent stalled waiting for disk.

        ring: std.os.linux.IoUring,
        read_pos: u64,
        read_offset: u64,
        block_states: [num_blocks]BlockState,
        buffer: [buffer_size]u8 align(sector_size),

        const Self = @This();
        const BlockState = packed struct(u32) {
            status: enum(u2) { idle, reading, ready },
            len: u30,
        };

        pub const buffer_size = config.buffer_size;
        pub const block_size = config.block_size;

        comptime {
            std.debug.assert(block_size >= sector_size);
            std.debug.assert(block_size % sector_size == 0);
        }

        const num_blocks = @divExact(buffer_size, block_size);
        const BlockIndex = std.math.IntFittingRange(0, num_blocks);

        const RingUserData = packed struct(u64) {
            disk_block: u32, // offset = self.disk_block * block_size + self.read
            block_idx: BlockIndex, // < num_blocks
            read: std.meta.Int(.unsigned, 64 - 32 - @bitSizeOf(BlockIndex)), // <= block_size
        };

        pub fn init(self: *Self, file: std.fs.File) !void {
            self.file = file;
            self.offset = 0;

            self.io_transferred = 0;
            self.io_inflight = 0;
            self.io_stalled = 0;

            self.ring = try .init(num_blocks, std.os.linux.IORING_SETUP_SQPOLL);
            errdefer self.ring.deinit();

            self.read_pos = 0;
            self.read_offset = 0;
            @memset(&self.block_states, .{ .status = .idle, .len = 0 });

            // start reading in blocks
            for (0..num_blocks) |block_idx| {
                try self.submitNext(@intCast(block_idx));
            }
        }

        pub fn deinit(self: *const Self) void {
            var ring = self.ring; // stdlib IoUring needs mut self for deinit()
            ring.deinit();
        }

        /// Get the current file offset that a getBuffer() would read from
        pub fn getOffset(self: *const Self) u64 {
            const pos = self.read_pos % buffer_size;
            const block_used = pos % block_size;
            return self.offset + block_used;
        }

        /// Get a writable slice .len <= block_size
        pub fn getBuffer(self: *Self, logger: tel.Logger("FileReader.getBuffer")) ![]const u8 {
            const pos = self.read_pos % buffer_size;
            const block_idx = pos / block_size;
            const block_used = pos % block_size;

            // Block is currently being read into (IO stalled)
            const block_state = &self.block_states[block_idx];
            if (block_state.status != .ready) {
                @branchHint(.unlikely);

                const zone = tracy.Zone.init(@src(), .{ .name = "FileReader.stalled" });
                defer zone.deinit();

                // cant have partially advanced() on stalled blk
                std.debug.assert(block_used == 0);

                const stall_start = std.time.Instant.now() catch unreachable;
                defer self.io_stalled +=
                    (std.time.Instant.now() catch unreachable).since(stall_start);

                while (block_state.status != .ready) {
                    std.debug.assert(self.io_inflight > 0); // it's being read, right?
                    std.debug.assert(block_state.status == .reading);

                    try self.poll(.from(logger));
                }
            }

            // clamp by block_state.len instead of block_size, in case of smaller read (EOF).
            return self.buffer[@as(u64, block_idx) * block_size ..][block_used..block_state.len];
        }

        // Mark n bytes (from a previous `.getBuffer()` call) as read.
        pub fn advance(self: *Self, n: usize) !void {
            const pos = self.read_pos % buffer_size;
            const block_idx = pos / block_size;
            const block_used = pos % block_size;

            const readable = block_size - block_used;
            std.debug.assert(n <= readable);

            const block_state = &self.block_states[block_idx];
            std.debug.assert(block_state.status == .ready);

            self.read_pos += n;
            if (n == readable) { // finishing reading from the block. reuse it for the next read
                @branchHint(.unlikely);

                self.offset += block_size;

                block_state.status = .idle;
                try self.submitNext(@intCast(block_idx));
            }
        }

        // Waits for any pending IO to finish
        pub fn sync(self: *Self, logger: tel.Logger("FileReader.sync")) !void {
            const zone = tracy.Zone.init(@src(), .{ .name = "FileReader.sync" });
            defer zone.deinit();

            while (self.io_inflight > 0) {
                try self.poll(.from(logger));
            }
        }

        fn submitNext(self: *Self, block_idx: BlockIndex) !void {
            const disk_block = @divExact(self.read_offset, block_size);
            self.read_offset += block_size;

            try self.submit(.{
                .disk_block = @intCast(disk_block),
                .block_idx = @intCast(block_idx),
                .read = 0,
            });
        }

        fn submit(self: *Self, data: RingUserData) !void {
            const zone = tracy.Zone.init(@src(), .{ .name = "FileReader.submit" });
            defer zone.deinit();

            const block_state = &self.block_states[data.block_idx];
            std.debug.assert(block_state.status == .idle);
            block_state.status = .reading;

            std.debug.assert(self.io_inflight < num_blocks);
            self.io_inflight += 1;

            const sqe = while (true) break self.ring.get_sqe() catch |err| switch (err) {
                error.SubmissionQueueFull => {
                    _ = try self.ring.submit();
                    continue;
                },
            };
            const block_offset = @as(u64, data.block_idx) * block_size + data.read;
            const block_len = block_size - data.read;
            sqe.prep_read(
                self.file.handle,
                self.buffer[block_offset..][0..block_len],
                @as(u64, data.disk_block) * block_size + data.read,
            );
            sqe.user_data = @bitCast(data);
            _ = try self.ring.submit(); // SQPOLL makes this fast if done frequently enough
        }

        fn poll(self: *Self, logger: tel.Logger("FileReader.poll")) !void {
            const zone = tracy.Zone.init(@src(), .{ .name = "FileReader.poll" });
            defer zone.deinit();

            var cqes: [num_blocks]std.os.linux.io_uring_cqe = blk: {
                @setRuntimeSafety(false);
                break :blk undefined; // avoid needless memset
            };
            const n = try self.ring.copy_cqes(&cqes, 0); // dont wait: non-blocking poll is fastest
            for (cqes[0..n]) |*cqe| {
                var data: RingUserData = @bitCast(cqe.user_data);
                if (cqe.err() != .SUCCESS) {
                    logger.err().logf("pread(fd={} ptr={*}, len={}, offset={}) = {}", .{
                        self.file.handle,
                        self.buffer[@as(u64, data.block_idx) * block_size + data.read ..].ptr,
                        block_size - data.read,
                        @as(u64, data.disk_block) * block_size + data.read,
                        cqe.err(),
                    });
                    return error.ReadFailed;
                }

                std.debug.assert(self.io_inflight > 0);
                self.io_inflight -= 1;

                const block_state = &self.block_states[data.block_idx];
                std.debug.assert(block_state.status == .reading);
                block_state.status = .idle;

                const n_read: u32 = @intCast(cqe.res);
                self.io_transferred += n_read;

                data.read += @intCast(n_read);
                std.debug.assert(data.read <= block_size);

                if (data.read == block_size or n_read == 0) { // finished or EOF
                    block_state.* = .{ .status = .ready, .len = @intCast(data.read) };
                } else { // partial read
                    try self.submit(data);
                }
            }
        }
    };
}
