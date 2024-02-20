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
    // TODO: shouldnt need a ring buffer here (just a slice should do)
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
    start_index: usize = 0,
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
    n_threads: usize = 1, // default single threaded

    const options: DecompressStreamOptions = .{};

    fn readFrameContext(r: anytype) !?decompress.FrameContext {
        switch (try decompress.decodeFrameHeader(r)) {
            .skippable => |header| {
                try r.skipBytes(header.frame_size, .{});
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

    pub const ZstdInfo = struct {
        n_frames: usize,
        total_output_size: usize,
        min_buffer_size: usize,
    };

    /// need to collect
    /// the number of frames (how many parallel works we need)
    /// the total output size decompressed (so we know how much memory to allocate)
    pub fn getInfo(source_buf: []u8) !ZstdInfo {
        var fbs = std.io.FixedBufferStream([]u8){ .buffer = source_buf, .pos = 0 };
        var reader = fbs.reader();

        var total_n_frames: usize = 0;
        var min_buffer_size: usize = 0;
        var total_output_memory: usize = 0;

        counting_loop: while (true) {
            // read the frame context (can parallelize this)
            var frame_context: ?decompress.FrameContext = null;
            while (frame_context == null) {
                frame_context = readFrameContext(reader) catch |err| switch (err) {
                    error.DictionaryIdFlagUnsupported => return error.DictionaryIdFlagUnsupported,
                    error.EndOfStream => if (reader.context.pos == source_buf.len) {
                        break :counting_loop;
                    } else {
                        return error.MalformedFrame;
                    },
                    else => return error.MalformedFrame,
                } orelse continue;
            }
            total_n_frames += 1;
            total_output_memory += frame_context.?.window_size;
            min_buffer_size = @max(min_buffer_size, frame_context.?.window_size);

            while (true) {
                const header_bytes = reader.readBytesNoEof(3) catch
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
                reader.skipBytes(read_size, .{}) catch {
                    return error.MalformedFrame;
                };
                if (block_header.last_block) {
                    if (frame_context.?.has_checksum) {
                        reader.skipBytes(4, .{}) catch {
                            return error.MalformedFrame;
                        };
                    }
                    break;
                }
            }
        }

        return .{
            .n_frames = total_n_frames,
            .total_output_size = total_output_memory,
            .min_buffer_size = min_buffer_size,
        };
    }

    pub fn read(self: *Self, output: *MuxRingBuffer) !usize {
        // TODO: support anytype output and add comptime to ensure fcns exist
        if (self.pos == self.source_buf.len) {
            return 0;
        }

        // count number of blocks
        var fbs = std.io.FixedBufferStream([]u8){ .buffer = self.source_buf, .pos = self.pos };
        var reader = fbs.reader();

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
                frame_context = readFrameContext(reader) catch |err| switch (err) {
                    error.EndOfStream => if (reader.context.pos == initial_count) {
                        break :counting_loop;
                    } else {
                        return error.MalformedFrame;
                    },
                    else => return err,
                } orelse continue;
            }
            total_n_frames += 1;
            total_output_memory += frame_context.?.window_size;

            // read the corresponding blocks
            var frame_read_len: usize = 0;
            while (true) {
                const header_bytes = reader.readBytesNoEof(3) catch
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

                reader.skipBytes(read_size, .{}) catch {
                    return error.MalformedFrame;
                };
                total_n_blocks += 1;

                if (block_header.last_block) {
                    if (frame_context.?.has_checksum) {
                        reader.skipBytes(4, .{}) catch {
                            return error.MalformedFrame;
                        };
                    }
                    break;
                }
            }
            try frame_read_lens.append(frame_read_len);
        }
        std.debug.print("n_frames: {}\n", .{total_n_frames});

        const n_threads_bounded: usize = @min(self.n_threads, total_n_frames);
        var thread_pool = ThreadPool.init(.{
            .max_threads = @intCast(n_threads_bounded),
        });
        defer {
            thread_pool.shutdown();
            thread_pool.deinit();
        }

        var tasks = try self.allocator.alloc(ZstdTask, n_threads_bounded);
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

        var last_valid_pos: ?usize = null;
        var output_pos: usize = 0;
        var frame_index: usize = 0;
        var timer = try std.time.Timer.start();
        decompression_loop: while (true) {
            // read the frame context
            var frame_context: ?decompress.FrameContext = null;
            while (frame_context == null) {
                frame_context = readFrameContext(reader) catch |err| switch (err) {
                    error.DictionaryIdFlagUnsupported => return error.DictionaryIdFlagUnsupported,
                    error.EndOfStream => if (reader.context.pos == initial_count) {
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
            task_i = (task_i + 1) % n_threads_bounded;

            // copy output to buffer
            if (task_ptr.block_context) |*block_context| {
                const len = block_context.buffer.len();
                // TODO: support mid block decompression
                if (output_pos + len > output.freeSpace()) {
                    block_context.deinit();
                    task_ptr.block_context = null;
                    last_valid_pos = task_ptr.start_index; // restart from here on the next run
                    break :decompression_loop;
                }

                // TODO: pulling out the RingBuffer should make this a lot faster
                {
                    output.mux.lock();
                    defer output.mux.unlock();

                    while (block_context.buffer.read()) |x| {
                        output.inner.writeAssumeCapacity(x);
                        output_pos += 1;
                    }
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

            const start_index = reader.context.pos;
            const end_index = start_index + frame_read_lens.items[frame_index];
            task_ptr.start_index = start_index;
            defer reader.context.pos = end_index;

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
        var ran_out_of_memory = last_valid_pos != null;

        for (0..tasks.len) |_| {
            var task = &tasks[task_i];
            defer task_i = (task_i + 1) % n_threads_bounded;
            while (!task.done.load(std.atomic.Ordering.Acquire)) {
                // wait
            }

            if (task.block_context) |*block_context| {
                if (ran_out_of_memory) {
                    block_context.deinit();
                    task.block_context = null;
                    continue;
                } else {
                    const len = block_context.buffer.len();
                    if (output_pos + len > output.freeSpace()) {
                        block_context.deinit();
                        task.block_context = null;

                        last_valid_pos = task.start_index;
                        ran_out_of_memory = true;
                        continue;
                    }
                }

                {
                    output.mux.lock();
                    defer output.mux.unlock();

                    while (block_context.buffer.read()) |x| {
                        output.inner.writeAssumeCapacity(x);
                        output_pos += 1;
                    }
                }
                block_context.deinit();
                task.block_context = null;
            }
        }

        if (last_valid_pos) |pos| {
            self.pos = pos;
        } else {
            self.pos = reader.context.pos;
        }

        return output_pos;
    }
};

pub const MuxRingBuffer = struct {
    inner: std.RingBuffer,
    allocator: std.mem.Allocator,
    is_done: bool = false,
    mux: std.Thread.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator, inner_capacity: usize) !@This() {
        return @This(){
            .inner = try std.RingBuffer.init(allocator, inner_capacity),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *@This()) void {
        self.inner.deinit(self.allocator);
    }

    pub fn capacity(self: *@This()) usize {
        return self.inner.data.len;
    }

    /// amount of space to write to
    pub fn freeSpace(self: *@This()) usize {
        self.mux.lock();
        defer self.mux.unlock();

        const free = self.inner.data.len - self.inner.len();
        return free;
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

    var fbs = std.io.fixedBufferStream(memory);
    var stream = std.compress.zstd.decompressStream(allocator, fbs.reader());
    var std_result = try stream.reader().readAllAlloc(allocator, std.math.maxInt(usize));
    defer allocator.free(std_result);

    var d = Decompressor{ .allocator = allocator, .source_buf = memory, .n_threads = 1 };
    var buf = try allocator.create(MuxRingBuffer);
    buf.* = try MuxRingBuffer.init(allocator, std_result.len);
    defer {
        buf.deinit();
        allocator.destroy(buf);
    }

    _ = try d.read(buf);

    try std.testing.expectEqualSlices(u8, std_result, buf.inner.data);
}
