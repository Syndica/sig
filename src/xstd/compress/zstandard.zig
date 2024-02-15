const std = @import("std");
const Allocator = std.mem.Allocator;
const RingBuffer = std.RingBuffer;

const types = @import("zstandard/types.zig");
pub const frame = types.frame;
pub const compressed_block = types.compressed_block;

pub const decompress = @import("zstandard/decompress.zig");

const printTimeEstimate = @import("../../core/accounts_db.zig").printTimeEstimate;
const ThreadPool = @import("../../sync/thread_pool.zig").ThreadPool;
const Task = ThreadPool.Task;
const Batch = ThreadPool.Batch;

pub const DecompressStreamOptions = struct {
    verify_checksum: bool = true,
    window_size_max: usize = 1 << 23, // 8MiB default maximum window size
};

pub const BlockContext = struct {
    literal_fse_buffer: []types.compressed_block.Table.Fse,
    match_fse_buffer: []types.compressed_block.Table.Fse,
    offset_fse_buffer: []types.compressed_block.Table.Fse,
    literals_buffer: []u8,
    sequence_buffer: []u8,
    buffer: RingBuffer,
    decode_state: decompress.block.DecodeState,
    frame_context: decompress.FrameContext,
    allocator: std.mem.Allocator,

    pub fn init(
        allocator: std.mem.Allocator,
        frame_context: decompress.FrameContext,
        window_size_max: usize,
    ) !BlockContext {
        const literal_fse_buffer = try allocator.alloc(
            types.compressed_block.Table.Fse,
            types.compressed_block.table_size_max.literal,
        );
        errdefer allocator.free(literal_fse_buffer);

        const match_fse_buffer = try allocator.alloc(
            types.compressed_block.Table.Fse,
            types.compressed_block.table_size_max.match,
        );
        errdefer allocator.free(match_fse_buffer);

        const offset_fse_buffer = try allocator.alloc(
            types.compressed_block.Table.Fse,
            types.compressed_block.table_size_max.offset,
        );
        errdefer allocator.free(offset_fse_buffer);

        const decode_state = decompress.block.DecodeState.init(
            literal_fse_buffer,
            match_fse_buffer,
            offset_fse_buffer,
        );
        const buffer = try RingBuffer.init(allocator, frame_context.window_size);

        const literals_data = try allocator.alloc(u8, window_size_max);
        errdefer allocator.free(literals_data);

        const sequence_data = try allocator.alloc(u8, window_size_max);
        errdefer allocator.free(sequence_data);

        return .{
            .literal_fse_buffer = literal_fse_buffer,
            .match_fse_buffer = match_fse_buffer,
            .offset_fse_buffer = offset_fse_buffer,
            .literals_buffer = literals_data,
            .sequence_buffer = sequence_data,
            .decode_state = decode_state,
            .buffer = buffer,
            .frame_context = frame_context,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *BlockContext) void {
        self.allocator.free(self.literal_fse_buffer);
        self.allocator.free(self.match_fse_buffer);
        self.allocator.free(self.offset_fse_buffer);
        self.allocator.free(self.literals_buffer);
        self.allocator.free(self.sequence_buffer);
        self.buffer.deinit(self.allocator);
    }
};

const ZstdTask = struct {
    task: Task,
    frame_context: decompress.FrameContext,
    source_buf: []u8,
    options: DecompressStreamOptions,
    block_context: ?BlockContext = null,
    done: std.atomic.Atomic(bool) = std.atomic.Atomic(bool).init(true),

    pub fn deinit(self: *ZstdTask) void {
        if (self.block_context) |*block_context| {
            block_context.deinit();
        }
    }

    pub fn callback(task: *Task) void {
        _callback(task) catch |err| {
            std.debug.print("zstd task error: {s}\n", .{@errorName(err)});
            unreachable;
        };
    }

    pub fn _callback(task: *Task) !void {
        var self = @fieldParentPtr(@This(), "task", task);
        std.debug.assert(!self.done.load(std.atomic.Ordering.Acquire));
        defer self.done.store(true, std.atomic.Ordering.Release);

        var fbs = std.io.fixedBufferStream(self.source_buf);
        var reader = fbs.reader();

        var n_blocks: usize = 0;
        block_loop: while (true) {
            const header_bytes = reader.readBytesNoEof(3) catch
                return error.MalformedFrame;

            const block_header = decompress.block.decodeBlockHeader(&header_bytes);
            const block_size = block_header.block_size;
            if (block_size == 0) continue;

            decompress.block.decodeBlockReader(
                &self.block_context.?.buffer, // this holds the result
                reader,
                block_header,
                &self.block_context.?.decode_state,
                self.block_context.?.frame_context.block_size_max,
                self.block_context.?.literals_buffer,
                self.block_context.?.sequence_buffer,
            ) catch return error.MalformedBlock;

            n_blocks += 1;

            if (block_header.last_block) {
                if (self.frame_context.has_checksum) {
                    try reader.skipBytes(4, .{});
                }
                break :block_loop;
            }
        }
    }
};

pub const Decompressor = struct {
    const Self = @This();

    allocator: Allocator,
    source_buf: []u8,
    pos: usize = 0,

    const options: DecompressStreamOptions = .{};

    fn readFrameContext(reader: anytype) !?decompress.FrameContext {
        switch (try decompress.decodeFrameHeader(reader)) {
            .skippable => |header| {
                try reader.skipBytes(header.frame_size, .{});
                return null;
            },
            .zstandard => |header| {
                const frame_context = context: {
                    break :context try decompress.FrameContext.init(
                        header,
                        options.window_size_max,
                        options.verify_checksum,
                    );
                };
                return frame_context;
            },
        }
    }

    pub fn read(self: *Self) ![]u8 {
        // count number of blocks
        var fbs = std.io.FixedBufferStream([]u8){ .buffer = self.source_buf, .pos = 0 };
        var source_reader = fbs.reader();

        // mainnet: 101_384 (for incremental) 1_532_423 (for full)
        var total_n_blocks: usize = 0;
        // note: this is usually 1 for a snapshot
        var total_n_frames: usize = 0;

        var frame_read_lens = std.ArrayList(usize).init(self.allocator);
        defer frame_read_lens.deinit();

        const initial_count = self.source_buf.len;
        var total_output_memory: usize = 0;
        counting_loop: while (true) {
            // read the frame context (can parallelize this)
            var frame_context: ?decompress.FrameContext = null;
            while (frame_context == null) {
                frame_context = readFrameContext(source_reader) catch |err| switch (err) {
                    error.DictionaryIdFlagUnsupported => return error.DictionaryIdFlagUnsupported,
                    error.EndOfStream => if (source_reader.context.pos == initial_count) {
                        break :counting_loop;
                    } else {
                        return error.MalformedFrame;
                    },
                    else => return error.MalformedFrame,
                } orelse continue;
            }
            total_n_frames += 1;
            total_output_memory += frame_context.?.window_size;

            // read the corresponding blocks
            var frame_read_len: usize = 0;
            while (true) {
                const header_bytes = source_reader.readBytesNoEof(3) catch
                    return error.MalformedFrame;

                const block_header = decompress.block.decodeBlockHeader(&header_bytes);
                const block_size = block_header.block_size;
                if (block_size == 0) continue;

                var read_size: usize = switch (block_header.block_type) {
                    .raw => block_size,
                    .rle => 1,
                    .compressed => block_size,
                    .reserved => {
                        return error.MalformedBlock;
                    },
                };
                frame_read_len += read_size + 3;

                source_reader.skipBytes(read_size, .{}) catch {
                    return error.MalformedFrame;
                };
                total_n_blocks += 1;

                if (block_header.last_block) {
                    if (frame_context.?.has_checksum) {
                        source_reader.skipBytes(4, .{}) catch {
                            return error.MalformedFrame;
                        };
                    }
                    break;
                }
            }
            try frame_read_lens.append(frame_read_len);

            const frame_alloc_size = frame_context.?.window_size;
            std.debug.assert(frame_read_len <= frame_alloc_size);
        }

        const N_THREADS: usize = @min(2, total_n_frames);
        var thread_pool = ThreadPool.init(.{
            .max_threads = @intCast(N_THREADS),
        });
        defer {
            thread_pool.shutdown();
            thread_pool.deinit();
        }

        var tasks = try self.allocator.alloc(ZstdTask, N_THREADS);
        defer {
            for (tasks) |*task| {
                task.deinit();
            }
            self.allocator.free(tasks);
        }

        for (tasks) |*task| {
            task.* = ZstdTask{
                .task = .{ .callback = ZstdTask.callback },
                .options = options,
                .frame_context = undefined,
                .source_buf = undefined,
            };
        }
        var task_i: usize = 0;

        // reset the reader
        fbs.pos = 0;

        var output = try self.allocator.alloc(u8, total_output_memory);
        errdefer self.allocator.free(output);
        var output_pos: usize = 0;

        var frame_index: usize = 0;
        var timer = try std.time.Timer.start();
        decompression_loop: while (true) {
            // read the frame context
            var frame_context: ?decompress.FrameContext = null;
            while (frame_context == null) {
                frame_context = readFrameContext(source_reader) catch |err| switch (err) {
                    error.DictionaryIdFlagUnsupported => return error.DictionaryIdFlagUnsupported,
                    error.EndOfStream => if (source_reader.context.pos == initial_count) {
                        break :decompression_loop;
                    } else {
                        return error.MalformedFrame;
                    },
                    else => return error.MalformedFrame,
                } orelse continue;
            }

            // find a free task
            var task_ptr = &tasks[task_i];
            while (!task_ptr.done.load(std.atomic.Ordering.Acquire)) {
                // TODO: fix this while the order is still correct
            }
            task_i = (task_i + 1) % N_THREADS;

            // copy output to buffer
            if (task_ptr.block_context) |*block_context| {
                while (block_context.buffer.read()) |x| {
                    output[output_pos] = x;
                    output_pos += 1;
                }
                block_context.deinit();
                task_ptr.block_context = null;
            }
            task_ptr.frame_context = frame_context.?;
            task_ptr.block_context = try BlockContext.init(
                self.allocator,
                frame_context.?,
                options.window_size_max,
            );

            const start_index = source_reader.context.pos;
            const end_index = start_index + frame_read_lens.items[frame_index];
            defer source_reader.context.pos = end_index;
            task_ptr.source_buf = self.source_buf[start_index..end_index];

            task_ptr.done.store(false, std.atomic.Ordering.Release);
            frame_index += 1;

            const batch = Batch.from(&task_ptr.task);
            thread_pool.schedule(batch);

            printTimeEstimate(
                &timer,
                frame_read_lens.items.len,
                frame_index,
                "decompressing",
                null,
            );
        }

        // wait for all tasks (still need them ordered)
        for (0..tasks.len) |_| {
            var task = &tasks[task_i];
            defer task_i = (task_i + 1) % N_THREADS;
            while (!task.done.load(std.atomic.Ordering.Acquire)) {
                // wait
            }

            if (task.block_context) |*block_context| {
                while (block_context.buffer.read()) |x| {
                    output[output_pos] = x;
                    output_pos += 1;
                }
                block_context.deinit();
                task.block_context = null;
            }
        }

        if (!self.allocator.resize(output, output_pos)) {
            var new_output = try self.allocator.alloc(u8, output_pos);
            @memcpy(output, output[0..output_pos]);
            self.allocator.free(output);
            output = new_output;
        } else {
            output.len = output_pos;
        }

        return output;
    }
};

test "xstd.compress.zstandard: test decompression" {
    const filepath = "test_data/incremental-snapshot-10-25-GXgKvm3NMAPgGdv2verVaNXmKTHQgfy2TAxLVEfAvdCS.tar.zst";
    var file = try std.fs.cwd().openFile(filepath, .{});
    defer file.close();

    const file_stat = try file.stat();
    const file_size: u64 = @intCast(file_stat.size);
    var memory = try std.os.mmap(
        null,
        file_size,
        std.os.PROT.READ,
        std.os.MAP.SHARED,
        file.handle,
        0,
    );

    const allocator = std.testing.allocator;

    var d = Decompressor{ .allocator = allocator, .source_buf = memory };
    const result = try d.read();
    defer allocator.free(result);

    var fbs = std.io.fixedBufferStream(memory);
    var stream = std.compress.zstd.decompressStream(allocator, fbs.reader());
    var std_result = try stream.reader().readAllAlloc(allocator, std.math.maxInt(usize));
    defer allocator.free(std_result);

    try std.testing.expectEqualSlices(u8, std_result, result);
}
