const std = @import("std");
const tracy = @import("tracy");
const lib = @import("../lib.zig");

const tel = lib.telemetry;
const sector_size = lib.fio.sector_size;

pub fn FileWriter(
    comptime config: struct {
        buffer_size: usize, // max inflight data being written to disk
        block_size: usize, // data chunks submitted to disk to be written
    },
) type {
    return struct {
        // publically observable fields
        file: std.fs.File,
        offset: u64,

        io_transferred: u64, // total bytes written to disk.
        io_inflight: u32, // current inflight blocks being written to disk.
        io_stalled: u64, // total time spent stalled waiting for disk.

        ring: std.os.linux.IoUring,
        write_pos: u64,
        writing_mask: [@divExact(num_blocks, 64)]u64,
        buffer: [buffer_size]u8 align(sector_size),

        const Self = @This();

        pub const buffer_size = config.buffer_size;
        pub const block_size = config.block_size;

        comptime {
            std.debug.assert(block_size >= sector_size);
            std.debug.assert(block_size % sector_size == 0);
        }

        const num_blocks = @divExact(buffer_size, block_size);
        const BlockIndex = std.math.IntFittingRange(0, num_blocks);

        const RingUserData = packed struct(u64) {
            disk_block: u32, // offset = self.disk_block * block_size + self.written
            block_idx: BlockIndex, // < num_blocks
            written: std.meta.Int(.unsigned, 64 - 32 - @bitSizeOf(BlockIndex)), // <= block_size
        };

        pub fn init(self: *Self, file: std.fs.File) !void {
            self.file = file;
            self.offset = 0;

            self.io_transferred = 0;
            self.io_inflight = 0;
            self.io_stalled = 0;

            self.ring = try .init(num_blocks, std.os.linux.IORING_SETUP_SQPOLL);
            errdefer self.ring.deinit();

            self.write_pos = 0;
            @memset(&self.writing_mask, 0);
        }

        pub fn deinit(self: *const Self) void {
            var ring = self.ring; // stdlib IoUring needs mut self for deinit()
            ring.deinit();
        }

        /// Get the current file offset that a getBuffer() would write to.
        pub fn getOffset(self: *const Self) u64 {
            const pos = self.write_pos % buffer_size;
            const block_used = pos % block_size;
            return self.offset + block_used;
        }

        /// Set the next file offset an advance() call will write to.
        /// NOTE: this rounds down the offset to a block_size boundary.
        pub fn setOffset(self: *Self, new_offset: u64) void {
            self.offset = std.mem.alignBackward(u64, new_offset, block_size);
        }

        /// Get a writable slice .len <= block_size
        pub fn getBuffer(self: *Self, logger: tel.Logger("FileWriter.getBuffer")) ![]u8 {
            const pos = self.write_pos % buffer_size;
            const block_idx = pos / block_size;
            const block_used = pos % block_size;

            // We wrapped around & all blocks are currently being written out (IO stalled)
            if (self.isBlockWriting(block_idx)) {
                @branchHint(.unlikely);

                const zone = tracy.Zone.init(@src(), .{ .name = "FileWriter.stalled" });
                defer zone.deinit();

                // cant have partially advanced() on stalled blk
                std.debug.assert(block_used == 0);

                const stall_start = std.time.Instant.now() catch unreachable;
                defer self.io_stalled +=
                    (std.time.Instant.now() catch unreachable).since(stall_start);

                while (self.isBlockWriting(block_idx)) {
                    std.debug.assert(self.io_inflight > 0); // it's being written, right?
                    try self.poll(.from(logger));
                }
            }

            return self.buffer[@as(u64, block_idx) * block_size ..][block_used..block_size];
        }

        fn isBlockWriting(self: *const Self, block_idx: usize) bool {
            std.debug.assert(block_idx < num_blocks);
            return (self.writing_mask[block_idx / 64] >> @intCast(block_idx % 64)) & 1 > 0;
        }

        // Mark n bytes (from a previous `.getBuffer()` call) as written.
        pub fn advance(self: *Self, n: usize) !void {
            const pos = self.write_pos % buffer_size;
            const block_idx = pos / block_size;
            const block_used = pos % block_size;

            const writable = block_size - block_used;
            std.debug.assert(n <= writable);
            std.debug.assert(!self.isBlockWriting(block_idx));

            self.write_pos += n;
            if (n == writable) { // completed the block
                @branchHint(.unlikely);

                const disk_block = @divExact(self.offset, block_size);
                self.offset += block_size;

                try self.submit(.{
                    .disk_block = @intCast(disk_block),
                    .block_idx = @intCast(block_idx),
                    .written = 0,
                });
            }
        }

        // Waits for any pending IO to finish
        pub fn sync(self: *Self, logger: tel.Logger("FileWriter.sync")) !void {
            const zone = tracy.Zone.init(@src(), .{ .name = "FileWriter.sync" });
            defer zone.deinit();

            while (self.io_inflight > 0) {
                try self.poll(.from(logger));
            }
        }

        fn submit(self: *Self, data: RingUserData) !void {
            const zone = tracy.Zone.init(@src(), .{ .name = "FileWriter.submit" });
            defer zone.deinit();

            const mask = @as(u64, 1) << @intCast(data.block_idx % 64);
            std.debug.assert(self.writing_mask[data.block_idx / 64] & mask == 0);
            self.writing_mask[data.block_idx / 64] |= mask;

            std.debug.assert(self.io_inflight < num_blocks);
            self.io_inflight += 1;

            const sqe = while (true) break self.ring.get_sqe() catch |err| switch (err) {
                error.SubmissionQueueFull => {
                    _ = try self.ring.submit();
                    continue;
                },
            };
            const block_offset = @as(u64, data.block_idx) * block_size + data.written;
            const block_len = block_size - data.written;
            sqe.prep_write(
                self.file.handle,
                self.buffer[block_offset..][0..block_len],
                @as(u64, data.disk_block) * block_size + data.written,
            );
            sqe.user_data = @bitCast(data);
            _ = try self.ring.submit(); // SQPOLL makes this fast if done frequently enough
        }

        fn poll(self: *Self, logger: tel.Logger("FileWriter.poll")) !void {
            const zone = tracy.Zone.init(@src(), .{ .name = "FileWriter.poll" });
            defer zone.deinit();

            // Avoid needless memset(0xAA) in safe modes.
            var cqes = lib.util.initUndefUnchecked([num_blocks]std.os.linux.io_uring_cqe);

            const n = try self.ring.copy_cqes(&cqes, 0); // dont wait: non-blocking poll is fastest
            for (cqes[0..n]) |*cqe| {
                var data: RingUserData = @bitCast(cqe.user_data);
                if (cqe.err() != .SUCCESS) {
                    logger.err().logf("pwrite(fd={} ptr={*}, len={}, offset={}) = {}", .{
                        self.file.handle,
                        self.buffer[@as(u64, data.block_idx) * block_size + data.written ..].ptr,
                        block_size - data.written,
                        @as(u64, data.disk_block) * block_size + data.written,
                        cqe.err(),
                    });
                    return error.WriteFailed;
                }

                std.debug.assert(self.io_inflight > 0);
                self.io_inflight -= 1;

                const mask = @as(u64, 1) << @intCast(data.block_idx % 64);
                std.debug.assert(self.writing_mask[data.block_idx / 64] & mask > 0);
                self.writing_mask[data.block_idx / 64] &= ~mask;

                const n_wrote: u32 = @intCast(cqe.res);
                self.io_transferred += n_wrote;

                data.written += @intCast(n_wrote);
                std.debug.assert(data.written <= block_size);
                if (data.written < block_size) try self.submit(data); // partial write
            }
        }
    };
}
