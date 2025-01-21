const std = @import("std");
const sig = @import("../sig.zig");
const builtin = @import("builtin");

const FileId = sig.accounts_db.accounts_file.FileId;
const bincode = sig.bincode;

/// arbitrarily chosen, I believe >95% of accounts will be <= 512 bytes
pub const FRAME_SIZE = 512;
const INVALID_FRAME = std.math.maxInt(FrameIndex);
pub const Frame = [FRAME_SIZE]u8;
/// we can get away with a 32-bit index
const FrameIndex = u32;
const FileOffset = u32;
const FrameOffset = u10; // 0..=FRAME_SIZE

comptime {
    // assert our FRAME_SIZE fits in FrameOffset
    const offset: FrameOffset = FRAME_SIZE;
    _ = offset;
}

const LinuxIoMode = enum {
    Blocking,
    IoUring,
};
const linux_io_mode: LinuxIoMode = .IoUring;

const use_io_uring = builtin.os.tag == .linux and linux_io_mode == .IoUring;

const io_uring_entries = 128;

threadlocal var maybe_io_uring: if (use_io_uring) ?std.os.linux.IoUring else void = null;
fn io_uring() !*std.os.linux.IoUring {
    return if (maybe_io_uring) |*io_ur|
        io_ur
    else io_ur: {
        maybe_io_uring = try std.os.linux.IoUring.init(
            io_uring_entries,
            0,
        );
        // TODO: to deinit reliably we could hook thread exit? Not sure if we even need to.
        break :io_ur &(maybe_io_uring.?);
    };
}

const FileIdFileOffset = packed struct(u64) {
    file_id: FileId,

    /// offset in the file from which the frame begin
    /// always a multiple of FRAME_SIZE
    file_offset: FileOffset,

    const INVALID: FileIdFileOffset = .{
        .file_id = FileId.fromInt(std.math.maxInt(FileId.Int)),
        // disambiguate from 0xAAAA / will trigger asserts as it's not even.
        .file_offset = 0xBAAD,
    };
};

fn readError() type {
    var ErrorSet = error{
        InvalidArgument,
        OutOfMemory,
        InvalidKey,
        CannotResetAlive,
        CannotOverwriteAliveInfo,
        OffsetsOutOfBounds,
    };

    if (use_io_uring) {
        const extra_fns = &.{
            std.os.linux.IoUring.read,
            std.os.linux.IoUring.submit_and_wait,
            std.os.linux.IoUring.copy_cqes,
            std.os.linux.IoUring.init,
        };
        inline for (extra_fns) |func| {
            const FnErrorSet = @typeInfo(
                @typeInfo(@TypeOf(func)).Fn.return_type.?,
            ).ErrorUnion.error_set;
            ErrorSet = ErrorSet || FnErrorSet;
        }
    }

    ErrorSet = ErrorSet || std.posix.PReadError;

    return ErrorSet;
}

/// Used for obtaining cached reads.
///
/// Design details:
/// Holds a large number of fixed-size "frames".
/// Frames have an associated reference counter, but this is for tracking open
/// handles - frames may outlive the associated rc. Frames are considered dead
/// when are evicted (which may only happen with 0 open handles).
/// A frame is always alive when it can be found in frame_map; a frame is always
/// dead when it is in free_list.
/// A frame dies when its index is evicted from HierarchicalFifo (inside of
/// evictUnusedFrame).
pub const BufferPool = struct {
    /// indices of all free frames
    /// free frames have a refcount of 0 *and* have been evicted
    free_list: AtomicStack(FrameIndex),

    /// uniquely identifies a frame
    /// for finding your wanted index
    /// TODO: a concurrent hashmap would be more appropriate
    frame_map_rw: sig.sync.RwMux(FrameMap),

    frames: []Frame,
    frames_metadata: FramesMetadata,

    /// used for eviction to free less popular (rc=0) frames first
    eviction_lfu: HierarchicalFIFO,

    pub const FrameMap = std.AutoHashMapUnmanaged(FileIdFileOffset, FrameIndex);
    pub const ReadError = readError();

    pub fn init(
        init_allocator: std.mem.Allocator,
        num_frames: u32,
    ) !BufferPool {
        if (num_frames == 0 or num_frames == 1) return error.InvalidArgument;

        const frames = try init_allocator.alloc(Frame, num_frames);
        errdefer init_allocator.free(frames);

        var frames_metadata = try FramesMetadata.init(init_allocator, num_frames);
        errdefer frames_metadata.deinit(init_allocator);

        var free_list = try AtomicStack(FrameIndex).init(init_allocator, num_frames);
        errdefer free_list.deinit(init_allocator);
        for (0..num_frames) |i| free_list.appendAssumeCapacity(@intCast(i));

        var frame_map: FrameMap = .{};
        try frame_map.ensureTotalCapacity(init_allocator, num_frames);
        errdefer frame_map.deinit(init_allocator);

        const frame_map_rw = sig.sync.RwMux(FrameMap).init(frame_map);

        return .{
            .frames = frames,
            .frames_metadata = frames_metadata,
            .free_list = free_list,
            .frame_map_rw = frame_map_rw,
            .eviction_lfu = try HierarchicalFIFO.init(init_allocator, num_frames / 10, num_frames),
        };
    }

    pub fn deinit(
        self: *BufferPool,
        init_allocator: std.mem.Allocator,
    ) void {
        init_allocator.free(self.frames);
        self.frames_metadata.deinit(init_allocator);
        self.free_list.deinit(init_allocator);
        self.eviction_lfu.deinit(init_allocator);
        const frame_map, var frame_map_lg = self.frame_map_rw.writeWithLock();
        frame_map.deinit(init_allocator);
        frame_map_lg.unlock();
    }

    pub fn read(
        self: *BufferPool,
        /// used for temp allocations, and the returned .indices slice
        allocator: std.mem.Allocator,
        file: std.fs.File,
        file_id: FileId,
        /// inclusive
        file_offset_start: FileOffset,
        /// exclusive
        file_offset_end: FileOffset,
    ) ReadError!ReadHandle {
        const handle = try if (use_io_uring)
            self.readIoUringSubmitAndWait(
                allocator,
                file,
                file_id,
                file_offset_start,
                file_offset_end,
            )
        else
            self.readBlocking(
                allocator,
                file,
                file_id,
                file_offset_start,
                file_offset_end,
            );

        return handle;
    }

    pub fn computeNumberofFrameIndices(
        /// inclusive
        file_offset_start: FileOffset,
        /// exclusive
        file_offset_end: FileOffset,
    ) error{InvalidArgument}!u32 {
        if (file_offset_start > file_offset_end) return error.InvalidArgument;
        if (file_offset_start == file_offset_end) return 0;

        const starting_frame = file_offset_start / FRAME_SIZE;
        const ending_frame = (file_offset_end - 1) / FRAME_SIZE;

        return ending_frame - starting_frame + 1;
    }

    /// allocates the required amount of indices, sets them all to
    /// INVALID_FRAME, overwriting with a valid frame where one is found.
    /// INVALID_FRAME indicates that there is no frame in the BufferPool for the
    /// given file_id and range.
    fn computeFrameIndices(
        self: *BufferPool,
        file_id: FileId,
        allocator: std.mem.Allocator,
        /// inclusive
        file_offset_start: FileOffset,
        /// exclusive
        file_offset_end: FileOffset,
    ) error{ InvalidArgument, OffsetsOutOfBounds, OutOfMemory }![]FrameIndex {
        const n_indices = try computeNumberofFrameIndices(file_offset_start, file_offset_end);

        if (n_indices > self.frames.len) return error.OffsetsOutOfBounds;

        const frame_indices = try allocator.alloc(FrameIndex, n_indices);
        for (frame_indices) |*f_idx| f_idx.* = INVALID_FRAME;

        // lookup frame mappings
        for (0.., frame_indices) |i, *f_idx| {
            const file_offset: FileOffset = @intCast(
                (i * FRAME_SIZE) + (file_offset_start - file_offset_start % FRAME_SIZE),
            );

            const key: FileIdFileOffset = .{
                .file_id = file_id,
                .file_offset = file_offset,
            };

            const maybe_frame_idx = blk: {
                const frame_map, var frame_map_lg = self.frame_map_rw.readWithLock();
                defer frame_map_lg.unlock();
                break :blk frame_map.get(key);
            };

            if (maybe_frame_idx) |frame_idx| f_idx.* = frame_idx;
        }

        return frame_indices;
    }

    /// On a "new" frame (i.e. freshly read into), set all of its associated metadata
    fn overwriteDeadFrameInfo(
        self: *BufferPool,
        f_idx: FrameIndex,
        file_id: FileId,
        frame_aligned_file_offset: FileOffset,
        size: FrameOffset,
    ) error{CannotOverwriteAliveInfo}!void {
        try self.overwriteDeadFrameInfoNoSize(f_idx, file_id, frame_aligned_file_offset);
        self.frames_metadata.size[f_idx].store(size, .release);
    }

    /// Useful if you don't currently know the size.
    /// make sure to set the size later (!)
    fn overwriteDeadFrameInfoNoSize(
        self: *BufferPool,
        f_idx: FrameIndex,
        file_id: FileId,
        frame_aligned_file_offset: FileOffset,
    ) error{CannotOverwriteAliveInfo}!void {
        std.debug.assert(frame_aligned_file_offset % FRAME_SIZE == 0);

        if (self.frames_metadata.rc[f_idx].isAlive()) {
            // not-found indices should always have 0 active readers
            return error.CannotOverwriteAliveInfo;
        }

        self.frames_metadata.freqSetToZero(f_idx);
        self.frames_metadata.in_queue[f_idx].store(.none, .release);
        self.frames_metadata.rc[f_idx].reset();

        self.frames_metadata.key[f_idx].store(@bitCast(FileIdFileOffset{
            .file_id = file_id,
            .file_offset = frame_aligned_file_offset,
        }), .release);

        const key: FileIdFileOffset = .{
            .file_id = file_id,
            .file_offset = frame_aligned_file_offset,
        };

        {
            const frame_map, var frame_map_lg = self.frame_map_rw.writeWithLock();
            defer frame_map_lg.unlock();
            frame_map.putAssumeCapacityNoClobber(key, f_idx);
        }
    }

    /// Frames with an associated rc of 0 are up for eviction, and which frames
    /// are evicted first is up to the LFU.
    fn evictUnusedFrame(self: *BufferPool) error{CannotResetAlive}!void {
        const evicted = self.eviction_lfu.evict(self.frames_metadata);
        self.free_list.appendAssumeCapacity(evicted);

        const did_remove = blk: {
            const frame_map, var frame_map_lg = self.frame_map_rw.writeWithLock();
            defer frame_map_lg.unlock();
            break :blk frame_map.remove(
                @bitCast(self.frames_metadata.key[evicted].load(.acquire)),
            );
        };
        if (!did_remove) {
            std.debug.panic(
                "evicted a frame that did not exist in frame_map, frame: {}\n",
                .{evicted},
            );
        }
        @memset(&self.frames[evicted], 0xAA);
        try self.frames_metadata.resetFrame(evicted);
    }

    fn readIoUringSubmitAndWait(
        self: *BufferPool,
        /// used for temp allocations, and the returned .indices slice
        allocator: std.mem.Allocator,
        file: std.fs.File,
        file_id: FileId,
        /// inclusive
        file_offset_start: FileOffset,
        /// exclusive
        file_offset_end: FileOffset,
    ) ReadError!ReadHandle {
        if (!use_io_uring) @compileError("io_uring disabled");

        const threadlocal_io_uring = try io_uring();

        const frame_indices = try self.computeFrameIndices(
            file_id,
            allocator,
            file_offset_start,
            file_offset_end,
        );
        errdefer allocator.free(frame_indices);

        // update found frames in the LFU (we don't want to evict these in the next loop)
        for (0.., frame_indices) |i, f_idx| {
            if (f_idx == INVALID_FRAME) continue;

            errdefer {
                // Failed insert? Roll back acquired frames rcs
                for (frame_indices[0..i]) |alive_frame_idx| {
                    if (alive_frame_idx != INVALID_FRAME)
                        _ = self.frames_metadata.rc[alive_frame_idx].release();
                }
            }

            try self.eviction_lfu.insert(self.frames_metadata, f_idx);
            if (!self.frames_metadata.rc[f_idx].acquire()) {
                // frame has no handles, but memory is still valid
                self.frames_metadata.rc[f_idx].reset();
            }
        }

        // fill in invalid frames with file data, replacing invalid frames with
        // fresh ones.
        var queued_reads: u32 = 0;
        for (0.., frame_indices) |i, *f_idx| {
            if (f_idx.* != INVALID_FRAME) continue;
            // INVALID_FRAME => not found, read fresh and populate

            const frame_aligned_file_offset: FileOffset = @intCast((i * FRAME_SIZE) +
                (file_offset_start - file_offset_start % FRAME_SIZE));
            std.debug.assert(frame_aligned_file_offset % FRAME_SIZE == 0);

            f_idx.* = blk: while (true) {
                if (self.free_list.popOrNull()) |free_idx| {
                    break :blk free_idx;
                } else {
                    try self.evictUnusedFrame();
                }
            };

            errdefer {
                // Filling this frame failed, releasing rcs of previously filled frames
                for (frame_indices[0..i]) |alive_frame_idx| {
                    std.debug.assert(alive_frame_idx != INVALID_FRAME); // impossible
                    _ = self.frames_metadata.rc[alive_frame_idx].release();
                }
            }

            if (threadlocal_io_uring.read(
                f_idx.*,
                file.handle,
                .{ .buffer = &self.frames[f_idx.*] },
                frame_aligned_file_offset,
            )) |_| {
                queued_reads += 1;
            } else |err| switch (err) {
                error.SubmissionQueueFull => {
                    // if the queue is full, let's submit our previous reads early, and then queue
                    // our read again.
                    try performReads(
                        self.frames_metadata,
                        allocator,
                        threadlocal_io_uring,
                        file,
                        queued_reads,
                    );
                    _ = try threadlocal_io_uring.read(
                        f_idx.*,
                        file.handle,
                        .{ .buffer = &self.frames[f_idx.*] },
                        frame_aligned_file_offset,
                    );
                    queued_reads = 1;
                },
                else => |e| return e,
            }

            try self.overwriteDeadFrameInfoNoSize(f_idx.*, file_id, frame_aligned_file_offset);
            try self.eviction_lfu.insert(self.frames_metadata, f_idx.*);
        }

        errdefer {
            for (frame_indices) |alive_frame_idx| {
                std.debug.assert(alive_frame_idx != INVALID_FRAME); // impossible
                _ = self.frames_metadata.rc[alive_frame_idx].release();
            }
        }

        // Wait for our file reads to complete, filling the read length into the metadata as we go.
        // (This read length will almost always be FRAME_SIZE, however it will likely be less than
        // that at the end of the file)
        if (queued_reads > 0) {
            try performReads(self.frames_metadata, allocator, threadlocal_io_uring, file, queued_reads);
        }

        return ReadHandle.initCached(
            self,
            frame_indices,
            @intCast(file_offset_start % FRAME_SIZE),
            @intCast(((file_offset_end - 1) % FRAME_SIZE) + 1),
        );
    }

    fn performReads(
        frames_metadata: FramesMetadata,
        allocator: std.mem.Allocator,
        threadlocal_io_uring: *std.os.linux.IoUring,
        file: std.fs.File,
        n_reads: u32,
    ) !void {
        const n_submitted = try threadlocal_io_uring.submit_and_wait(n_reads);
        std.debug.assert(n_submitted == n_reads); // did somethng else submit an event?

        // would be nice to get rid of this alloc
        const cqes = try allocator.alloc(std.os.linux.io_uring_cqe, n_submitted);
        defer allocator.free(cqes);

        // check our completions in order to set the frame's size;
        // we need to wait for completion to get the bytes read
        const cqe_count = try threadlocal_io_uring.copy_cqes(cqes, n_submitted);
        std.debug.assert(cqe_count == n_submitted); // why did we not receive them all?
        for (0.., cqes) |i, cqe| {
            if (cqe.err() != .SUCCESS) {
                std.debug.panic("cqe: {}, err: {}, i: {}, file: {}", .{
                    cqe,
                    cqe.err(),
                    i,
                    file,
                });
            }
            const f_idx = cqe.user_data;
            const bytes_read: FrameOffset = @intCast(cqe.res);
            std.debug.assert(bytes_read <= FRAME_SIZE);

            frames_metadata.size[f_idx].store(bytes_read, .release);
        }
    }

    fn readBlocking(
        self: *BufferPool,
        /// used for temp allocations, and the returned .indices slice
        allocator: std.mem.Allocator,
        file: std.fs.File,
        file_id: FileId,
        /// inclusive
        file_offset_start: FileOffset,
        /// exclusive
        file_offset_end: FileOffset,
    ) ReadError!ReadHandle {
        const frame_indices = try self.computeFrameIndices(
            file_id,
            allocator,
            file_offset_start,
            file_offset_end,
        );
        errdefer allocator.free(frame_indices);

        // update found frames in the LFU (we don't want to evict these in the next loop)
        for (0.., frame_indices) |i, f_idx| {
            if (f_idx == INVALID_FRAME) continue;

            errdefer {
                // Failed insert? Roll back acquired frames rcs
                for (frame_indices[0..i]) |alive_frame_idx| {
                    if (alive_frame_idx != INVALID_FRAME)
                        _ = self.frames_metadata.rc[alive_frame_idx].release();
                }
            }

            try self.eviction_lfu.insert(self.frames_metadata, f_idx);
            if (!self.frames_metadata.rc[f_idx].acquire()) {
                // frame has no handles, but memory is still valid
                self.frames_metadata.rc[f_idx].reset();
            }
        }

        // fill in invalid frames with file data, replacing invalid frames with
        // fresh ones.
        for (0.., frame_indices) |i, *f_idx| {
            if (f_idx.* != INVALID_FRAME) continue;
            // INVALID_FRAME => not found, read fresh and populate

            const frame_aligned_file_offset: FileOffset = @intCast((i * FRAME_SIZE) +
                (file_offset_start - file_offset_start % FRAME_SIZE));
            std.debug.assert(frame_aligned_file_offset % FRAME_SIZE == 0);

            f_idx.* = blk: while (true) {
                if (self.free_list.popOrNull()) |free_idx| {
                    break :blk free_idx;
                } else {
                    try self.evictUnusedFrame();
                }
            };

            errdefer {
                // Filling this frame failed, releasing rcs of previously filled frames
                for (frame_indices[0..i]) |alive_frame_idx| {
                    std.debug.assert(alive_frame_idx != INVALID_FRAME); // impossible
                    _ = self.frames_metadata.rc[alive_frame_idx].release();
                }
            }

            const bytes_read = try file.pread(&self.frames[f_idx.*], frame_aligned_file_offset);
            try self.overwriteDeadFrameInfo(
                f_idx.*,
                file_id,
                frame_aligned_file_offset,
                @intCast(bytes_read),
            );
            try self.eviction_lfu.insert(self.frames_metadata, f_idx.*);
        }

        return ReadHandle.initCached(
            self,
            frame_indices,
            @intCast(file_offset_start % FRAME_SIZE),
            @intCast(((file_offset_end - 1) % FRAME_SIZE) + 1),
        );
    }
};

pub const FramesMetadata = struct {
    pub const InQueue = enum(u8) { none, small, main, ghost }; // u8 required for extern usage

    /// ref count for the frame. For frames that are currently being used elsewhere.
    rc: []sig.sync.ReferenceCounter,

    /// effectively the inverse of BufferPool.FrameMap, used in order to
    /// evict keys by their value
    /// This is really a FileIdFileOffset.
    /// TODO: Zig 0.14 (#20590) seems to let us to do atomics on packed structs directly.
    key: []std.atomic.Value(u64),

    /// frequency for the HierarchicalFIFO
    /// Yes, really, only 0, 1, 2, 3.
    /// Atomic - do not access directly.
    freq: []u2,

    /// which HierarchicalFIFO queue this frame exists in
    in_queue: []std.atomic.Value(InQueue),

    /// 0..=512
    /// This is really a FrameOffset, but I've upped it to a u16 to appease std.atomic
    size: []std.atomic.Value(u16),

    fn init(allocator: std.mem.Allocator, num_frames: usize) !FramesMetadata {
        const rc = try allocator.alloc(sig.sync.ReferenceCounter, num_frames);
        errdefer allocator.free(rc);
        @memset(rc, .{ .state = .{ .raw = 0 } });

        const key = try allocator.alloc(std.atomic.Value(u64), num_frames);
        errdefer allocator.free(key);
        @memset(
            key,
            std.atomic.Value(u64).init(@bitCast(FileIdFileOffset{
                .file_id = FileId.fromInt(0),
                .file_offset = 0,
            })),
        );

        const freq = try allocator.alloc(u2, num_frames);
        errdefer allocator.free(freq);
        @memset(freq, 0);

        const in_queue = try allocator.alloc(std.atomic.Value(InQueue), num_frames);
        errdefer allocator.free(in_queue);
        @memset(in_queue, std.atomic.Value(InQueue).init(.none));

        const size = try allocator.alloc(std.atomic.Value(u16), num_frames);
        errdefer allocator.free(size);
        @memset(size, std.atomic.Value(u16).init(0));

        return .{
            .rc = rc,
            .key = key,
            .freq = freq,
            .in_queue = in_queue,
            .size = size,
        };
    }

    fn deinit(self: *FramesMetadata, allocator: std.mem.Allocator) void {
        // NOTE: this check itself is racy, but should never happen
        for (0.., self.rc) |i, *rc| {
            if (rc.isAlive()) {
                std.debug.panic("BufferPool deinitialised with alive handle: {}\n", .{i});
            }
        }
        allocator.free(self.rc);
        allocator.free(self.key);
        allocator.free(self.freq);
        allocator.free(self.in_queue);
        allocator.free(self.size);
        self.* = undefined;
    }

    // to be called on the eviction of a frame
    // should never be called on a frame with rc>0
    // TODO: this should *all* be atomic (!)
    fn resetFrame(self: FramesMetadata, index: FrameIndex) error{CannotResetAlive}!void {
        if (self.rc[index].isAlive()) return error.CannotResetAlive;

        self.freqSetToZero(index);
        self.in_queue[index].store(.none, .release);
        self.size[index].store(0, .release);
        self.key[index].store(@bitCast(FileIdFileOffset.INVALID), .release);
    }

    fn freqIncrement(self: FramesMetadata, index: FrameIndex) void {
        const old_freq = @atomicRmw(u2, &self.freq[index], .Add, 1, .acquire);
        if (old_freq == 0) {
            // we overflowed (3->0), set back to max
            @atomicStore(u2, &self.freq[index], 3, .release);
        }
    }

    fn freqDecrement(self: FramesMetadata, index: FrameIndex) void {
        const old_freq = @atomicRmw(u2, &self.freq[index], .Add, 1, .acquire);
        if (old_freq == 3) {
            // we overflowed (0->3), set back to min
            @atomicStore(u2, &self.freq[index], 0, .release);
        }
    }

    fn freqIsZero(self: FramesMetadata, index: FrameIndex) bool {
        const freq = @atomicLoad(u2, &self.freq[index], .acquire);
        return freq == 0;
    }

    fn freqSetToOne(self: FramesMetadata, index: FrameIndex) void {
        @atomicStore(u2, &self.freq[index], 1, .release);
    }

    fn freqSetToZero(self: FramesMetadata, index: FrameIndex) void {
        @atomicStore(u2, &self.freq[index], 0, .release);
    }
};

/// This cache is S3-FIFO inspired, with some important modifications to reads
/// and eviction. This cache:
/// 1) Does not store any values itself.
/// 2) Never "forgets" any key that is inserted, meaning it stays inside the
///    cache until eviction is called.
/// 3) Maintains that main.cap and ghost.cap equal num_frames.
/// 4) Asserts that its main and ghost queues never get full.
/// 5) Does not allow duplicates, except when a ghost key is read again, leading
///    to it pushed to main with a frequency of 1. The key remains in ghost,
///    which is ignored when popped.
/// 6) Checks frame refcounts upon eviction attempt, and will push alive frame
///    indices back into the main queue (freq=1).
/// 7) Asserts that it will always return a value upon eviction. Calling
///    eviction when no free frames can be made available is illegal behaviour.
pub const HierarchicalFIFO = struct {
    pub const Key = FrameIndex;
    pub const Metadata = FramesMetadata;
    pub const Fifo = AtomicLinearFifo(FrameIndex);

    small: Fifo,
    main: Fifo, // probably-alive items
    ghost: Fifo, // probably-dead items

    pub fn init(
        allocator: std.mem.Allocator,
        small_size: u32,
        num_frames: u32,
    ) error{ InvalidArgument, OutOfMemory }!HierarchicalFIFO {
        if (small_size > num_frames) return error.InvalidArgument;

        const small_buf = try allocator.alloc(FrameIndex, small_size);
        errdefer allocator.free(small_buf);

        const main_buf = try allocator.alloc(FrameIndex, num_frames);
        errdefer allocator.free(main_buf);

        const ghost_buf = try allocator.alloc(FrameIndex, num_frames);
        errdefer allocator.free(ghost_buf);

        return .{
            .small = Fifo.init(small_buf),
            .main = Fifo.init(main_buf),
            .ghost = Fifo.init(ghost_buf),
        };
    }

    pub fn deinit(self: *HierarchicalFIFO, allocator: std.mem.Allocator) void {
        allocator.free(self.small.buf);
        allocator.free(self.main.buf);
        allocator.free(self.ghost.buf);
        self.* = undefined;
    }

    pub fn numFrames(self: *HierarchicalFIFO) u32 {
        return @intCast(self.main.buf.len);
    }

    pub fn insert(
        self: *HierarchicalFIFO,
        metadata: Metadata,
        key: Key,
    ) error{InvalidKey}!void {
        if (key == INVALID_FRAME) return error.InvalidKey;

        switch (metadata.in_queue[key].load(.acquire)) {
            .main, .small => {
                metadata.freqIncrement(key);
            },
            .ghost => {
                std.debug.assert(metadata.freqIsZero(key));
                metadata.freqSetToOne(key);
                // Add key to main too - important to note that the key *still*
                // exists within ghost, but from now on we'll ignore that entry.
                self.main.writeItemAssumeCapacity(key);
                metadata.in_queue[key].store(.main, .release);
            },
            .none => {
                if (self.small.writableLengthIsZero()) {
                    const popped_small = self.small.readItem().?;

                    if (metadata.freqIsZero(popped_small)) {
                        self.ghost.writeItemAssumeCapacity(popped_small);
                        metadata.in_queue[popped_small].store(.ghost, .release);
                    } else {
                        self.main.writeItemAssumeCapacity(popped_small);
                        metadata.in_queue[popped_small].store(.main, .release);
                    }
                }
                self.small.writeItemAssumeCapacity(key);
                metadata.in_queue[key].store(.small, .release);
            },
        }
    }

    /// To be called when freelist is empty.
    /// This does not return an optional, as the caller *requires* a key to be
    /// evicted. Not being able to return a key means illegal internal state in
    /// the BufferPool.
    pub fn evict(self: *HierarchicalFIFO, metadata: Metadata) Key {
        var alive_eviction_attempts: usize = 0;

        const dead_key: Key = while (true) {
            var maybe_evicted: ?Key = null;

            if (maybe_evicted == null) maybe_evicted = self.evictGhost(metadata);

            // if we keep failing to evict a dead key, start alternating between
            // evicting from main and small. This saves us from the rare case
            // that every key in main is alive. In normal conditions, main
            // should be evicted from first.
            if (alive_eviction_attempts < 10 or alive_eviction_attempts % 2 == 0) {
                if (maybe_evicted == null) maybe_evicted = self.evictSmallOrMain(metadata, .main);
                if (maybe_evicted == null) maybe_evicted = self.evictSmallOrMain(metadata, .small);
            } else {
                if (maybe_evicted == null) maybe_evicted = self.evictSmallOrMain(metadata, .small);
                if (maybe_evicted == null) maybe_evicted = self.evictSmallOrMain(metadata, .main);
            }

            // NOTE: This panic is effectively unreachable - an empty cache
            // shouldn't be possible by (mis)using the public API of BufferPool,
            // except by touching the .eviction_lfu field (which you should
            // never do).
            const evicted = maybe_evicted orelse
                @panic("unable to evict: cache empty"); // see above comment

            // alive evicted keys are reinserted, we try again
            if (metadata.rc[evicted].isAlive()) {
                metadata.freqSetToOne(evicted);
                self.main.writeItemAssumeCapacity(evicted);
                metadata.in_queue[evicted].store(.main, .release);
                alive_eviction_attempts += 1;
                continue;
            }

            // key is definitely dead
            metadata.in_queue[evicted].store(.none, .release);
            break evicted;
        };

        return dead_key;
    }

    fn evictGhost(self: *HierarchicalFIFO, metadata: Metadata) ?Key {
        const evicted: ?Key = while (self.ghost.readItem()) |ghost_key| {
            switch (metadata.in_queue[ghost_key].load(.acquire)) {
                .ghost => {
                    break ghost_key;
                },
                .main => {
                    // This key has moved from ghost to main, we will just pop
                    // and ignore it.
                },
                .none => {
                    // This key moved from ghost to main, and then was evicted
                    // from main. However, because ghost is always evicted from
                    // before main, this should not be possible.
                    unreachable;
                },
                .small => unreachable,
            }
        } else null;

        return evicted;
    }

    fn evictSmallOrMain(
        self: *HierarchicalFIFO,
        metadata: Metadata,
        comptime target_queue: enum { small, main },
    ) ?Key {
        const queue = switch (target_queue) {
            .small => &self.small,
            .main => &self.main,
        };

        const evicted: ?Key = while (queue.readItem()) |popped_key| {
            switch (target_queue) {
                .small => if (metadata.in_queue[popped_key].load(.acquire) != .small) unreachable,
                .main => if (metadata.in_queue[popped_key].load(.acquire) != .main) unreachable,
            }

            if (metadata.freqIsZero(popped_key)) {
                break popped_key;
            } else {
                metadata.freqDecrement(popped_key);
                queue.writeItemAssumeCapacity(popped_key);
            }
        } else null;

        return evicted;
    }
};

/// slice-like datatype
/// view over one or more buffers owned by the BufferPool
pub const ReadHandle = union(enum) {
    /// Data owned by BufferPool, returned by .read() - do not construct this yourself (!)
    cached: CachedRead,
    /// Data allocated elsewhere, not owned or created by BufferPool.
    allocated_read: AllocatedRead,
    /// Data owned by parent ReadHandle
    sub_read: SubRead,

    const CachedRead = struct {
        buffer_pool: *BufferPool,
        frame_indices: []const FrameIndex,
        /// inclusive, the offset into the first frame
        first_frame_start_offset: FrameOffset,
        /// exclusive, the offset into the last frame
        last_frame_end_offset: FrameOffset,
    };

    const AllocatedRead = struct {
        slice: []u8,
        /// owned => ReadHandle.deinit() will free the slice
        owned: bool,
    };

    const SubRead = packed struct(u128) {
        parent: *ReadHandle,
        // offset into the parent's read
        start: u32,
        end: u32,
    };

    pub const @"!bincode-config" = bincode.FieldConfig(ReadHandle){
        .deserializer = bincodeDeserialize,
        .serializer = bincodeSerialize,
        .free = bincodeFree,
    };

    /// Only called by the BufferPool
    fn initCached(
        buffer_pool: *BufferPool,
        frame_indices: []const FrameIndex,
        first_frame_start_offset: FrameOffset,
        last_frame_end_offset: FrameOffset,
    ) ReadHandle {
        return .{
            .cached = .{
                .buffer_pool = buffer_pool,
                .frame_indices = frame_indices,
                .first_frame_start_offset = first_frame_start_offset,
                .last_frame_end_offset = last_frame_end_offset,
            },
        };
    }

    /// External to the BufferPool, data will be freed upon .deinit
    pub fn initAllocatedOwned(data: []u8) ReadHandle {
        return ReadHandle{
            .allocated_read = .{ .slice = data, .owned = true },
        };
    }

    /// External to the BufferPool
    pub fn initAllocated(data: []u8) ReadHandle {
        return ReadHandle{
            .allocated_read = .{ .slice = data, .owned = false },
        };
    }

    pub fn deinit(self: ReadHandle, allocator: std.mem.Allocator) void {
        switch (self) {
            .cached => |cached| {
                for (cached.frame_indices) |frame_index| {
                    std.debug.assert(frame_index != INVALID_FRAME);

                    if (cached.buffer_pool.frames_metadata.rc[frame_index].release()) {
                        // notably, the frame remains in memory, and its hashmap entry
                        // remains valid.
                    }
                }
                allocator.free(cached.frame_indices);
            },
            .sub_read => |_| {},
            .allocated_read => |allocated_read| {
                if (allocated_read.owned) allocator.free(allocated_read.slice);
            },
        }
    }

    pub fn iterator(self: *const ReadHandle) Iterator {
        return .{ .read_handle = self, .start = 0, .end = self.len() };
    }

    /// Copies entire read into specified buffer. Must be correct length.
    pub fn readAll(self: ReadHandle, buf: []u8) error{InvalidArgument}!void {
        try self.read(0, self.len(), buf);
    }

    pub fn readAllAllocate(self: ReadHandle, allocator: std.mem.Allocator) ![]u8 {
        return self.readAllocate(allocator, 0, self.len());
    }

    /// Copies entire read into specified buffer. Must be correct length.
    pub fn read(
        self: *const ReadHandle,
        start: FileOffset,
        end: FileOffset,
        buf: []u8,
    ) error{InvalidArgument}!void {
        const range_len = end - start;
        if (buf.len != range_len) return error.InvalidArgument;

        switch (self.*) {
            .allocated_read => |*a| return @memcpy(buf, a.slice[start..end]),
            .sub_read => |*sb| return sb.parent.read(sb.start + start, sb.start + end, buf),
            .cached => {},
        }

        var iter = try self.iteratorRanged(start, end);

        var bytes_copied: u32 = 0;
        while (iter.nextFrame()) |frame_slice| {
            const copy_len = @min(frame_slice.len, buf.len - bytes_copied);
            @memcpy(
                buf[bytes_copied..][0..copy_len],
                frame_slice[0..copy_len],
            );
            bytes_copied += @intCast(copy_len);
        }
    }

    pub fn readAllocate(
        self: ReadHandle,
        allocator: std.mem.Allocator,
        start: FileOffset,
        end: FileOffset,
    ) ![]u8 {
        const buf = try allocator.alloc(u8, end - start);
        self.read(start, end, buf) catch unreachable; // invalid account?
        return buf;
    }

    pub fn len(self: ReadHandle) u32 {
        return switch (self) {
            .sub_read => |sr| sr.end - sr.start,
            .cached => |cached| {
                if (cached.frame_indices.len == 0) return 0;
                return (@as(u32, @intCast(cached.frame_indices.len)) - 1) *
                    FRAME_SIZE +
                    cached.last_frame_end_offset - cached.first_frame_start_offset;
            },
            .allocated_read => |allocated| @intCast(allocated.slice.len),
        };
    }

    pub fn iteratorRanged(self: *const ReadHandle, start: FileOffset, end: FileOffset) !Iterator {
        if (start > end or end > self.len()) return error.InvalidArgument;
        return .{ .read_handle = self, .start = start, .end = end };
    }

    pub fn dupeAllocatedOwned(self: ReadHandle, allocator: std.mem.Allocator) !ReadHandle {
        const data_copy = try self.readAllAllocate(allocator);
        return initAllocatedOwned(data_copy);
    }

    pub fn slice(self: *ReadHandle, start: usize, end: usize) ReadHandle {
        return .{ .sub_read = .{
            .end = end,
            .start = start,
            .self = self,
        } };
    }

    /// testing purposes only
    pub fn expectEqual(expected: ReadHandle, actual: ReadHandle) !void {
        if (!builtin.is_test) @compileError("ReadHandle.expectEqual is for testing purposes only");
        const expected_buf = try expected.readAllocate(std.testing.allocator, 0, expected.len());
        defer std.testing.allocator.free(expected_buf);
        const actual_buf = try actual.readAllocate(std.testing.allocator, 0, actual.len());
        defer std.testing.allocator.free(actual_buf);
        try std.testing.expectEqualSlices(u8, expected_buf, actual_buf);
    }

    pub fn eql(h1: ReadHandle, h2: ReadHandle) bool {
        if (std.meta.eql(h1, h2)) return true;
        if (h1.len() != h2.len()) return false;

        var h1_iter = h1.iterator();
        var h2_iter = h2.iterator();

        while (h1_iter.nextByte()) |h1_byte| {
            const h2_byte = h2_iter.nextByte().?;
            if (h1_byte != h2_byte) return false;
        }

        return true;
    }

    pub fn eqlSlice(self: ReadHandle, data: []const u8) bool {
        if (self.len() != data.len) return false;

        var iter = self.iterator();
        var i: u32 = 0;
        while (iter.nextFrame()) |frame_slice| : (i += frame_slice.len) {
            if (!std.mem.eql(u8, frame_slice, data[i..frame_slice.len])) return false;
        }

        return true;
    }

    pub const Iterator = struct {
        read_handle: *const ReadHandle,
        bytes_read: FileOffset = 0,
        start: FileOffset,
        end: FileOffset,

        pub const Reader = std.io.GenericReader(*Iterator, error{}, Iterator.readBytes);

        pub fn reader(self: *Iterator) Reader {
            return .{ .context = self };
        }

        pub fn len(self: Iterator) FileOffset {
            return self.end - self.start;
        }

        pub fn bytesRemaining(self: Iterator) FileOffset {
            return self.len() - self.bytes_read;
        }

        pub fn readBytes(self: *Iterator, buffer: []u8) error{}!usize {
            if (self.bytes_read == self.end) return 0;

            const read_len = @min(self.bytesRemaining(), buffer.len);

            self.read_handle.read(
                self.start + self.bytes_read,
                self.start + self.bytes_read + read_len,
                buffer[0..read_len],
            ) catch unreachable;
            self.bytes_read += @intCast(read_len);
            return read_len;
        }

        pub fn nextByte(self: *Iterator) ?u8 {
            var buf: u8 = undefined;
            const buf_len = self.readBytes((&buf)[0..1]) catch unreachable;
            if (buf_len > 1) unreachable;
            if (buf_len == 0) return null;
            return buf;
        }

        /// Does not copy, reads buffers of up to FRAME_SIZE at a time.
        pub fn nextFrame(self: *Iterator) ?[]const u8 {
            if (self.bytesRemaining() == 0) return null;

            const first_frame_offset: FrameIndex = switch (self.read_handle.*) {
                .cached => |*cached| cached.first_frame_start_offset,
                else => 0,
            };

            // an index we can use with the bufferpool directly
            const read_offset: FileOffset = self.start + first_frame_offset + self.bytes_read;

            const frame_buf = switch (self.read_handle.*) {
                .cached => |*cached| buf: {
                    const current_frame: FrameIndex = read_offset / FRAME_SIZE;

                    const frame_start: FrameOffset = @intCast(read_offset % FRAME_SIZE);
                    const frame_end: FrameOffset = if (current_frame == cached.frame_indices.len - 1)
                        cached.last_frame_end_offset
                    else
                        FRAME_SIZE;

                    const end_idx = @min(frame_end, frame_start + self.bytesRemaining());

                    const buf = cached.buffer_pool.frames[
                        cached.frame_indices[current_frame]
                    ][frame_start..end_idx];

                    break :buf buf;
                },
                .allocated_read => |*external| buf: {
                    const end_idx = @min(read_offset + FRAME_SIZE, read_offset + self.bytesRemaining());
                    break :buf external.slice[read_offset..end_idx];
                },
                .sub_read => @panic("unimpl"),
            };

            if (frame_buf.len == 0) unreachable; // guarded against by the bytes_read check
            if (self.bytes_read > self.len()) unreachable; // we've gone too far

            self.bytes_read += @intCast(frame_buf.len);
            return frame_buf;
        }
    };

    fn bincodeSerialize(writer: anytype, read_handle: anytype, params: bincode.Params) anyerror!void {
        // we want to serialise it as if it's a slice
        try bincode.write(writer, @as(u64, read_handle.len()), params);

        var iter = read_handle.iterator();
        while (iter.nextFrame()) |frame| {
            try writer.writeAll(frame);
        }
    }

    fn bincodeDeserialize(
        alloc: std.mem.Allocator,
        reader: anytype,
        params: bincode.Params,
    ) anyerror!ReadHandle {
        const data = try bincode.read(alloc, []u8, reader, params);
        return ReadHandle.initAllocatedOwned(data);
    }

    fn bincodeFree(allocator: std.mem.Allocator, read_handle: anytype) void {
        read_handle.deinit(allocator);
    }
};

/// Used for atomic appends + pops; No guarantees for elements.
/// Methods follow that of ArrayListUnmanaged
pub fn AtomicStack(T: type) type {
    return struct {
        const Self = @This();

        buf: [*]T,
        len: std.atomic.Value(usize),
        cap: usize, // fixed

        fn init(allocator: std.mem.Allocator, cap: usize) !Self {
            const buf = try allocator.alloc(T, cap);
            return .{
                .buf = buf.ptr,
                .len = .{ .raw = 0 },
                .cap = cap,
            };
        }

        fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            allocator.free(self.buf[0..self.cap]);
            self.* = undefined;
        }

        // add new item to the end of buf, incrementing self.len atomically
        fn appendAssumeCapacity(self: *Self, item: T) void {
            const prev_len = self.len.load(.acquire);
            std.debug.assert(prev_len < self.cap);
            self.buf[prev_len] = item;
            _ = self.len.fetchAdd(1, .release);
        }

        // return item at end of buf, decrementing self.len atomically
        fn popOrNull(self: *Self) ?T {
            const prev_len = self.len.fetchSub(1, .acquire);
            if (prev_len == 0) {
                _ = self.len.fetchAdd(1, .release);
                return null;
            }
            return self.buf[prev_len - 1];
        }
    };
}

/// An std.fifo.LinearFifo-like type with atomics and a minimal API.
pub fn AtomicLinearFifo(T: type) type {
    return struct {
        const Self = @This();

        buf: []T,
        head: std.atomic.Value(usize),
        tail: std.atomic.Value(usize) align(64), // align to avoid false share

        pub fn init(buf: []T) Self {
            return .{
                .buf = buf,
                .head = std.atomic.Value(usize).init(0),
                .tail = std.atomic.Value(usize).init(0),
            };
        }

        pub fn writeItemAssumeCapacity(self: *Self, item: T) void {
            const tail = self.tail.fetchAdd(1, .monotonic) % self.buf.len;
            self.buf[tail] = item;
        }

        pub fn readItem(self: *Self) ?T {
            const current_head = self.head.load(.acquire);
            const current_tail = self.tail.load(.acquire);

            if (current_head == current_tail) return null;

            const item = self.buf[current_head % self.buf.len];
            self.head.store(current_head + 1, .release);
            return item;
        }

        pub fn writableLengthIsZero(self: *Self) bool {
            const current_head = self.head.load(.acquire);
            const current_tail = self.tail.load(.acquire);
            return (current_tail - current_head) >= self.buf.len;
        }
    };
}

test "BufferPool indicesRequired" {
    const TestCase = struct {
        start: FileOffset,
        end: FileOffset,
        expected: u32,
    };
    const F_SIZE = FRAME_SIZE;

    const cases = [_]TestCase{
        .{ .start = 0, .end = 1, .expected = 1 },
        .{ .start = 1, .end = 1, .expected = 0 },
        .{ .start = 0, .end = F_SIZE, .expected = 1 },
        .{ .start = F_SIZE / 2, .end = (F_SIZE * 3) / 2, .expected = 2 },
        .{ .start = F_SIZE, .end = F_SIZE * 2, .expected = 1 },
    };

    for (0.., cases) |i, case| {
        errdefer std.debug.print("failed on case(i={}): {}", .{ i, case });
        try std.testing.expectEqual(
            case.expected,
            BufferPool.computeNumberofFrameIndices(case.start, case.end),
        );
    }
}

test "BufferPool init deinit" {
    const allocator = std.testing.allocator;

    for (0.., &[_]u32{
        2,     3,     4,     8,
        16,    32,    256,   4096,
        16384, 16385, 24576, 32767,
        32768, 49152, 65535, 65536,
    }) |i, frame_count| {
        errdefer std.debug.print("failed on case(i={}): {}", .{ i, frame_count });
        var bp = try BufferPool.init(allocator, frame_count);
        bp.deinit(allocator);
    }
}

test "BufferPool readBlocking" {
    const allocator = std.testing.allocator;

    const file = try std.fs.cwd().openFile("data/test-data/test_account_file", .{});
    defer file.close();
    const file_id = FileId.fromInt(1);

    var bp = try BufferPool.init(allocator, 2048); // 2048 frames = 1MiB
    defer bp.deinit(allocator);

    var read = try bp.readBlocking(allocator, file, file_id, 0, 1000);
    defer read.deinit(allocator);
}

test "BufferPool readIoUringSubmitAndWait" {
    if (!use_io_uring) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    const file = try std.fs.cwd().openFile("data/test-data/test_account_file", .{});
    defer file.close();
    const file_id = FileId.fromInt(1);

    var bp = try BufferPool.init(allocator, 2048); // 2048 frames = 1MiB
    defer bp.deinit(allocator);

    var read = try bp.readIoUringSubmitAndWait(allocator, file, file_id, 0, 1000);
    defer read.deinit(allocator);
}

test "BufferPool basic usage" {
    const allocator = std.testing.allocator;

    const file = try std.fs.cwd().openFile("data/test-data/test_account_file", .{});
    defer file.close();
    const file_id = FileId.fromInt(1);

    var bp = try BufferPool.init(allocator, 2048); // 2048 frames = 1MiB @ FRAME_SIZE=512
    defer bp.deinit(allocator);

    var fba_buf: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&fba_buf);

    const read = try bp.read(fba.allocator(), file, file_id, 0, 1000);
    defer read.deinit(fba.allocator());

    try std.testing.expectEqual(
        try std.math.divCeil(usize, 1000, FRAME_SIZE),
        read.cached.frame_indices.len,
    );
    for (read.cached.frame_indices) |f_idx| try std.testing.expect(f_idx != INVALID_FRAME);

    {
        var iter1 = read.iterator();
        const reader_data = try iter1.reader().readAllAlloc(fba.allocator(), 1000);
        defer fba.allocator().free(reader_data);
        try std.testing.expectEqual(1000, reader_data.len);

        var iter2 = read.iterator();

        const iter_data = try fba.allocator().alloc(u8, 1000);
        defer fba.allocator().free(iter_data);

        var bytes_read: usize = 0;
        while (iter2.nextByte()) |byte| : (bytes_read += 1) {
            iter_data[bytes_read] = byte;
        }
        try std.testing.expectEqual(1000, bytes_read);
        try std.testing.expectEqualSlices(u8, reader_data, iter_data);
    }
}

test "BufferPool allocation sizes" {
    var gpa = std.heap.GeneralPurposeAllocator(.{
        .enable_memory_limit = true,
    }){};
    const allocator = gpa.allocator();

    const frame_count = 2048; // 2048 frames = 1MiB cached

    var bp = try BufferPool.init(allocator, frame_count);
    defer bp.deinit(allocator);

    // We expect all allocations to be a multiple of the frame size in length
    // except for the s3_fifo queues, which are split to be ~90% and ~10% of that
    // length.
    var total_requested_bytes = gpa.total_requested_bytes;
    total_requested_bytes -= bp.eviction_lfu.ghost.buf.len * @sizeOf(FrameIndex);
    total_requested_bytes -= bp.eviction_lfu.main.buf.len * @sizeOf(FrameIndex);
    total_requested_bytes -= bp.eviction_lfu.small.buf.len * @sizeOf(FrameIndex);
    total_requested_bytes -= @sizeOf(usize) * 3; // hashmap header

    try std.testing.expect(total_requested_bytes % frame_count == 0);

    // metadata should be small!
    // As of writing, all metadata (excluding eviction_lfu, including frame_map)
    // is 50 bytes or ~9% of memory usage at a frame size of 512, or 50MB for a
    // million frames.
    try std.testing.expect((total_requested_bytes / frame_count) - FRAME_SIZE <= 64);
}

test "BufferPool filesize > frame_size * num_frames" {
    const allocator = std.testing.allocator;

    const file = try std.fs.cwd().openFile("data/test-data/test_account_file", .{});
    defer file.close();
    const file_id = FileId.fromInt(1);

    const num_frames = 200;

    const file_size = (try file.stat()).size;
    if (file_size < FRAME_SIZE * num_frames) @panic("file too small for valid test");

    var bp = try BufferPool.init(std.heap.page_allocator, num_frames);
    defer bp.deinit(std.heap.page_allocator);

    // can't read buffer larger than total size of the buffer pool
    const read_whole = bp.read(allocator, file, file_id, 0, @intCast(file_size - 1));
    try std.testing.expectEqual(error.OffsetsOutOfBounds, read_whole);

    // file_size > total buffers size => we evict as we go
    var offset: u32 = 0;
    while (offset < file_size) : (offset += FRAME_SIZE) {
        // when we've already filled every frame, we evict as we go
        // => free list should be empty
        if (offset >= FRAME_SIZE * num_frames) {
            try std.testing.expectEqual(0, bp.free_list.len.raw);
        } else {
            try std.testing.expect(bp.free_list.len.raw > 0);
        }

        const read_frame = try bp.read(
            allocator,
            file,
            file_id,
            offset,
            offset + FRAME_SIZE,
        );

        try std.testing.expectEqual(1, read_frame.cached.frame_indices.len);

        const frame: []const u8 = bp.frames[
            read_frame.cached.frame_indices[0]
        ][0..bp.frames_metadata.size[
            read_frame.cached.frame_indices[0]
        ].load(.unordered)];

        var frame2: [FRAME_SIZE]u8 = undefined;
        const bytes_read = try file.preadAll(&frame2, offset);
        try std.testing.expectEqualSlices(u8, frame2[0..bytes_read], frame);
        read_frame.deinit(allocator);
    }
}

test "BufferPool random read" {
    const allocator = std.testing.allocator;

    const file = try std.fs.cwd().openFile("data/test-data/test_account_file", .{});
    defer file.close();
    const file_id = FileId.fromInt(1);

    const num_frames = 200;

    var bp = try BufferPool.init(allocator, num_frames);
    defer bp.deinit(allocator);

    const file_size: u32 = @intCast((try file.stat()).size);

    var prng = std.Random.DefaultPrng.init(5083);

    var reads: usize = 0;
    while (reads < 5000) : (reads += 1) {
        var gpa = std.heap.GeneralPurposeAllocator(.{
            .safety = true,
        }){};
        defer _ = gpa.deinit();

        const range_start = prng.random().intRangeAtMost(u32, 0, file_size);
        const range_end = prng.random().intRangeAtMost(
            u32,
            range_start,
            @min(file_size, range_start + num_frames * FRAME_SIZE),
        );

        errdefer std.debug.print(
            "failed on case(reads={}): file[{}..{}]\n",
            .{ reads, range_start, range_end },
        );

        if (try BufferPool.computeNumberofFrameIndices(range_start, range_end) > num_frames) {
            continue;
        }

        var read = try bp.read(gpa.allocator(), file, file_id, range_start, range_end);
        defer read.deinit(gpa.allocator());

        // check for equality with other impl
        if (use_io_uring) {
            var read2 = try bp.readBlocking(
                gpa.allocator(),
                file,
                file_id,
                range_start,
                range_end,
            );
            defer read2.deinit(gpa.allocator());

            try std.testing.expectEqual(
                read.cached.first_frame_start_offset,
                read2.cached.first_frame_start_offset,
            );
            try std.testing.expectEqual(
                read.cached.last_frame_end_offset,
                read2.cached.last_frame_end_offset,
            );
            try std.testing.expectEqualSlices(
                u32,
                read.cached.frame_indices,
                read2.cached.frame_indices,
            );
        }

        errdefer std.debug.print("failed with read: {}\n", .{read});

        var total_bytes_read: u32 = 0;
        for (read.cached.frame_indices) |f_idx| {
            total_bytes_read += bp.frames_metadata.size[f_idx].load(.unordered);
        }
        const read_data_bp_iter = try allocator.alloc(u8, read.len());
        defer allocator.free(read_data_bp_iter);
        {
            var iter = read.iterator();
            var start_offset: u32 = 0;
            while (iter.nextFrame()) |frame_slice| {
                @memcpy(
                    read_data_bp_iter[start_offset..][0..frame_slice.len],
                    frame_slice,
                );
                start_offset += @intCast(frame_slice.len);
            }

            try std.testing.expectEqual(read.len(), iter.bytes_read);
        }

        var iter = read.iterator();
        const read_data_bp_reader = try iter.reader().readAllAlloc(
            allocator,
            num_frames * FRAME_SIZE,
        );
        defer allocator.free(read_data_bp_reader);

        const read_data_bp_readall = try allocator.alloc(u8, read.len());
        defer allocator.free(read_data_bp_readall);
        try read.readAll(read_data_bp_readall);

        const read_data_expected = try allocator.alloc(u8, range_end - range_start);
        defer allocator.free(read_data_expected);
        const preaded_bytes = try file.preadAll(read_data_expected, range_start);

        // read via iterator
        try std.testing.expectEqualSlices(u8, read_data_expected, read_data_bp_iter);
        try std.testing.expectEqual(preaded_bytes, read_data_bp_iter.len);

        // read via reader
        try std.testing.expectEqualSlices(u8, read_data_expected, read_data_bp_reader);
        try std.testing.expectEqual(preaded_bytes, read_data_bp_reader.len);

        // read via .readAll()
        try std.testing.expectEqualSlices(u8, read_data_expected, read_data_bp_readall);
        try std.testing.expectEqual(preaded_bytes, read_data_bp_readall.len);
    }
}

test "ReadHandle bincode" {
    const allocator = std.testing.allocator;

    const file = try std.fs.cwd().openFile("data/test-data/test_account_file", .{});
    defer file.close();
    const file_id = FileId.fromInt(1);

    const num_frames = 400;

    var bp = try BufferPool.init(allocator, num_frames);
    defer bp.deinit(allocator);

    const file_size: u32 = @intCast((try file.stat()).size);

    const read = try bp.read(allocator, file, file_id, 0, file_size);
    defer read.deinit(allocator);

    const read_data = try read.readAllAllocate(allocator);
    defer allocator.free(read_data);

    {
        var serialised_from_slice = std.ArrayList(u8).init(allocator);
        defer serialised_from_slice.deinit();

        try bincode.write(serialised_from_slice.writer(), read_data, .{});

        const deserialised_from_slice = try bincode.readFromSlice(
            allocator,
            ReadHandle,
            serialised_from_slice.items,
            .{},
        );
        defer deserialised_from_slice.deinit(allocator);

        try std.testing.expectEqualSlices(
            u8,
            read_data,
            deserialised_from_slice.allocated_read.slice,
        );
    }

    {
        var serialised_from_handle = std.ArrayList(u8).init(allocator);
        defer serialised_from_handle.deinit();

        try bincode.write(serialised_from_handle.writer(), read, .{});

        const deserialised_from_handle = try bincode.readFromSlice(
            allocator,
            ReadHandle,
            serialised_from_handle.items,
            .{},
        );
        defer deserialised_from_handle.deinit(allocator);

        try std.testing.expectEqualSlices(
            u8,
            read_data,
            deserialised_from_handle.allocated_read.slice,
        );
    }
}

test AtomicStack {
    const allocator = std.testing.allocator;
    var stack = try AtomicStack(usize).init(allocator, 100);
    defer stack.deinit(allocator);

    for (0..100) |i| stack.appendAssumeCapacity(i);

    var i: usize = 100;
    while (i > 0) {
        i -= 1;
        try std.testing.expectEqual(i, stack.popOrNull());
    }
}
