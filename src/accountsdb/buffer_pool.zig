const std = @import("std");
const sig = @import("../sig.zig");
const builtin = @import("builtin");

const FileId = sig.accounts_db.accounts_file.FileId;

/// arbitrarily chosen, I believe >95% of accounts will be <= 512 bytes
const FRAME_SIZE = 512;
const INVALID_FRAME = std.math.maxInt(FrameIndex);
const Frame = [FRAME_SIZE]u8;
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

const FileIdFileOffset = packed struct(u64) {
    const INVALID: FileIdFileOffset = .{
        .file_id = FileId.fromInt(std.math.maxInt(FileId.Int)),
        // disambiguate from 0xAAAA / will trigger asserts as it's not even.
        .file_offset = 0xBAAD,
    };

    file_id: FileId,

    /// offset in the file from which the frame begin
    /// always a multiple of FRAME_SIZE
    file_offset: FileOffset,
};

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
    pub const FrameMap = std.AutoHashMapUnmanaged(FileIdFileOffset, FrameIndex);

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

    /// NOTE: we might want this to be a threadlocal for best performance? I don't think this field is threadsafe
    io_uring: if (use_io_uring) std.os.linux.IoUring else void,

    pub fn init(
        init_allocator: std.mem.Allocator,
        num_frames: u32,
    ) !BufferPool {
        if (num_frames == 0 or num_frames == 1) return error.InvalidArgument;

        const frames = try init_allocator.alignedAlloc(Frame, std.mem.page_size, num_frames);
        errdefer init_allocator.free(frames);

        var frames_metadata = try FramesMetadata.init(init_allocator, num_frames);
        errdefer frames_metadata.deinit(init_allocator);

        var free_list = try AtomicStack(FrameIndex).init(init_allocator, num_frames);
        errdefer free_list.deinit(init_allocator);
        for (0..num_frames) |i| free_list.appendAssumeCapacity(@intCast(i));

        var io_uring = if (use_io_uring) blk: {
            // NOTE: this is pretty much a guess, maybe worth tweaking?
            // think this is a bit on the high end, libxev uses 256
            const io_uring_entries = 4096;

            break :blk try std.os.linux.IoUring.init(
                io_uring_entries,
                0,
            );
        } else {};
        errdefer if (use_io_uring) io_uring.deinit();

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
            .io_uring = io_uring,
        };
    }

    pub fn deinit(self: *BufferPool, init_allocator: std.mem.Allocator) void {
        init_allocator.free(self.frames);
        self.frames_metadata.deinit(init_allocator);
        if (use_io_uring) self.io_uring.deinit();
        self.free_list.deinit(init_allocator);
        self.eviction_lfu.deinit(init_allocator);
        const frame_map, var frame_map_lg = self.frame_map_rw.writeWithLock();
        frame_map.deinit(init_allocator);
        frame_map_lg.unlock();
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
    /// TODO: atomics
    fn overwriteDeadFrameInfo(
        self: *BufferPool,
        f_idx: FrameIndex,
        file_id: FileId,
        frame_aligned_file_offset: FileOffset,
        size: FrameOffset,
    ) error{CannotOverwriteAliveInfo}!void {
        try self.overwriteDeadFrameInfoNoSize(f_idx, file_id, frame_aligned_file_offset);
        self.frames_metadata.size[f_idx] = size;
    }

    /// Useful if you don't currently know the size.
    /// make sure to set the size later (!)
    /// TODO: atomics
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

        self.frames_metadata.freq[f_idx] = 0;
        self.frames_metadata.in_queue[f_idx] = .none;
        self.frames_metadata.rc[f_idx].reset();

        self.frames_metadata.key[f_idx] = .{
            .file_id = file_id,
            .file_offset = frame_aligned_file_offset,
        };

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
            break :blk frame_map.remove(self.frames_metadata.key[evicted]);
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
    ) !CachedRead {
        return if (use_io_uring)
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
    ) !CachedRead {
        if (builtin.os.tag != .linux)
            @compileError("io_uring only available on linux - unsupported target");

        const frame_indices = try self.computeFrameIndices(
            file_id,
            allocator,
            file_offset_start,
            file_offset_end,
        );
        errdefer allocator.free(frame_indices);

        // update found frames in the LFU (we don't want to evict these in the next loop)
        var n_invalid_indices: u32 = 0;
        for (frame_indices) |f_idx| {
            if (f_idx == INVALID_FRAME) {
                n_invalid_indices += 1;
                continue;
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

            _ = try self.io_uring.read(
                f_idx.*,
                file.handle,
                .{ .buffer = &self.frames[f_idx.*] },
                frame_aligned_file_offset,
            );
            try self.overwriteDeadFrameInfoNoSize(f_idx.*, file_id, frame_aligned_file_offset);
            try self.eviction_lfu.insert(self.frames_metadata, f_idx.*);
        }

        // Wait for our file reads to complete, filling the read length into the metadata as we go.
        // (This read length will almost always be FRAME_SIZE, however it will likely be less than
        // that at the end of the file)
        if (n_invalid_indices > 0) {
            const n_submitted = try self.io_uring.submit_and_wait(n_invalid_indices);
            std.debug.assert(n_submitted == n_invalid_indices); // did smthng else submit an event?

            // would be nice to get rid of this alloc
            const cqes = try allocator.alloc(std.os.linux.io_uring_cqe, n_submitted);
            defer allocator.free(cqes);

            // check our completions in order to set the frame's size;
            // we need to wait for completion to get the bytes read
            const cqe_count = try self.io_uring.copy_cqes(cqes, n_submitted);
            std.debug.assert(cqe_count == n_submitted); // why did we not receive them all?
            for (0.., cqes) |i, cqe| {
                if (cqe.err() != .SUCCESS) {
                    std.debug.panic("cqe err: {}, i: {}", .{ cqe, i });
                }
                const f_idx = cqe.user_data;
                const bytes_read: FrameOffset = @intCast(cqe.res);
                std.debug.assert(bytes_read <= FRAME_SIZE);

                // TODO: atomics
                self.frames_metadata.size[f_idx] = bytes_read;
            }
        }

        return CachedRead{
            .buffer_pool = self,
            .frame_indices = frame_indices,
            .first_frame_start_offset = @intCast(file_offset_start % FRAME_SIZE),
            .last_frame_end_offset = @intCast(((file_offset_end - 1) % FRAME_SIZE) + 1),
        };
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
    ) (error{
        InvalidArgument,
        OutOfMemory,
        InvalidKey,
        CannotResetAlive,
        CannotOverwriteAliveInfo,
        OffsetsOutOfBounds,
    } || std.posix.PReadError)!CachedRead {
        const frame_indices = try self.computeFrameIndices(
            file_id,
            allocator,
            file_offset_start,
            file_offset_end,
        );
        errdefer allocator.free(frame_indices);

        // update found frames in the LFU (we don't want to evict these in the next loop)
        for (frame_indices) |f_idx| {
            if (f_idx == INVALID_FRAME) continue;
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

            const bytes_read = try file.pread(&self.frames[f_idx.*], frame_aligned_file_offset);
            try self.overwriteDeadFrameInfo(
                f_idx.*,
                file_id,
                frame_aligned_file_offset,
                @intCast(bytes_read),
            );
        }

        return CachedRead{
            .buffer_pool = self,
            .frame_indices = frame_indices,
            .first_frame_start_offset = @intCast(file_offset_start % FRAME_SIZE),
            .last_frame_end_offset = @intCast(((file_offset_end - 1) % FRAME_SIZE) + 1),
        };
    }
};

/// TODO: atomics on all index accesses
pub const FramesMetadata = struct {
    pub const InQueue = enum(u2) { none, small, main, ghost };

    /// ref count for the frame. For frames that are currently being used elsewhere.
    rc: []sig.sync.ReferenceCounter,

    /// effectively the inverse of BufferPool.FrameMap, used in order to
    /// evict keys by their value
    key: []FileIdFileOffset,

    /// frequency for the S3_FIFO
    /// Yes, really, only 0, 1, 2, 3.
    freq: []u2,

    /// which S3_FIFO queue this frame exists in
    in_queue: []InQueue,

    /// 0..=512
    size: []FrameOffset,

    fn init(allocator: std.mem.Allocator, num_frames: usize) !FramesMetadata {
        const rc = try allocator.alignedAlloc(
            sig.sync.ReferenceCounter,
            std.mem.page_size,
            num_frames,
        );
        errdefer allocator.free(rc);
        @memset(rc, .{ .state = .{ .raw = 0 } });

        const key = try allocator.alignedAlloc(FileIdFileOffset, std.mem.page_size, num_frames);
        errdefer allocator.free(key);
        @memset(key, .{ .file_id = FileId.fromInt(0), .file_offset = 0 });

        const freq = try allocator.alignedAlloc(u2, std.mem.page_size, num_frames);
        errdefer allocator.free(freq);
        @memset(freq, 0);

        const in_queue = try allocator.alignedAlloc(InQueue, std.mem.page_size, num_frames);
        errdefer allocator.free(in_queue);
        @memset(in_queue, .none);

        const size = try allocator.alignedAlloc(FrameOffset, std.mem.page_size, num_frames);
        errdefer allocator.free(size);
        @memset(size, 0);

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
        for (self.rc) |*rc| {
            if (rc.isAlive()) {
                @panic("BufferPool deinitialised with alive handles");
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
        self.freq[index] = 0;
        self.in_queue[index] = .none;
        self.size[index] = 0;
        self.key[index] = FileIdFileOffset.INVALID;
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
    pub const Fifo = std.fifo.LinearFifo(FrameIndex, .Slice); // TODO: atomics

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

        switch (metadata.in_queue[key]) {
            .main, .small => {
                metadata.freq[key] +|= 1;
            },
            .ghost => {
                std.debug.assert(metadata.freq[key] == 0);
                metadata.freq[key] = 1;
                // Add key to main too - important to note that the key *still*
                // exists within ghost, but from now on we'll ignore that entry.
                self.main.writeItemAssumeCapacity(key);
                metadata.in_queue[key] = .main;
            },
            .none => {
                if (self.small.writableLength() == 0) {
                    const popped_small = self.small.readItem().?;

                    if (metadata.freq[popped_small] == 0) {
                        self.ghost.writeItemAssumeCapacity(popped_small);
                        metadata.in_queue[popped_small] = .ghost;
                    } else {
                        self.main.writeItemAssumeCapacity(popped_small);
                        metadata.in_queue[popped_small] = .main;
                    }
                }
                self.small.writeItemAssumeCapacity(key);
                metadata.in_queue[key] = .small;
            },
        }
    }

    /// To be called when freelist is empty.
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

            const evicted = maybe_evicted orelse
                @panic("unable to evict: cache empty");

            // alive evicted keys are reinserted, we try again
            if (metadata.rc[evicted].isAlive()) {
                metadata.freq[evicted] = 1;
                self.main.writeItemAssumeCapacity(evicted);
                metadata.in_queue[evicted] = .main;
                alive_eviction_attempts += 1;
                continue;
            }

            // key is definitely dead
            metadata.in_queue[evicted] = .none;
            break evicted;
        };

        return dead_key;
    }

    fn evictGhost(self: *HierarchicalFIFO, metadata: Metadata) ?Key {
        const evicted: ?Key = while (self.ghost.readItem()) |ghost_key| {
            switch (metadata.in_queue[ghost_key]) {
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
                .small => if (metadata.in_queue[popped_key] != .small) unreachable,
                .main => if (metadata.in_queue[popped_key] != .main) unreachable,
            }

            if (metadata.freq[popped_key] == 0) {
                break popped_key;
            } else {
                metadata.freq[popped_key] -|= 1;
                queue.writeItemAssumeCapacity(popped_key);
            }
        } else null;

        return evicted;
    }
};

/// slice-like datatype
/// view over one or more buffers owned by the BufferPool
pub const CachedRead = struct {
    buffer_pool: *BufferPool,
    frame_indices: []const FrameIndex,
    /// inclusive, the offset into the first frame
    first_frame_start_offset: FrameOffset,
    /// exclusive, the offset into the last frame
    last_frame_end_offset: FrameOffset,

    pub const Iterator = struct {
        cached_read: *const CachedRead,
        bytes_read: u32 = 0,

        const Reader = std.io.GenericReader(*Iterator, error{}, readBytes);

        pub fn next(self: *Iterator) ?u8 {
            if (self.bytes_read == self.cached_read.len()) {
                return null;
            }
            defer self.bytes_read += 1;
            return self.cached_read.readByte(self.bytes_read);
        }

        pub fn reset(self: *Iterator) void {
            self.bytes_read = 0;
        }

        pub fn readBytes(self: *Iterator, buffer: []u8) error{}!usize {
            var i: u32 = 0;
            while (i < buffer.len) : (i += 1) {
                buffer[i] = self.next() orelse break;
            }
            return i;
        }

        pub fn reader(self: *Iterator) Reader {
            return .{ .context = self };
        }
    };

    pub fn readByte(self: CachedRead, index: usize) u8 {
        std.debug.assert(self.frame_indices.len != 0);
        std.debug.assert(index < self.len());
        const offset = index + self.first_frame_start_offset;
        std.debug.assert(offset >= self.first_frame_start_offset);

        return self.buffer_pool.frames[
            self.frame_indices[offset / FRAME_SIZE]
        ][offset % FRAME_SIZE];
    }

    /// Copies entire read into specified buffer. Must be correct length.
    pub fn readAll(
        self: CachedRead,
        buf: []u8,
    ) error{InvalidArgument}!void {
        if (buf.len != self.len()) return error.InvalidArgument;
        var bytes_copied: usize = 0;

        for (0.., self.frame_indices) |i, f_idx| {
            const is_first_frame: u2 = @intFromBool(i == 0);
            const is_last_frame: u2 = @intFromBool(i == self.frame_indices.len - 1);

            switch (is_first_frame << 1 | is_last_frame) {
                0b00 => { // !first, !last (middle frame)
                    const read_len = FRAME_SIZE;
                    @memcpy(
                        buf[bytes_copied..][0..read_len],
                        &self.buffer_pool.frames[f_idx],
                    );
                    bytes_copied += read_len;
                },
                0b10 => { // first, !last (first frame)
                    std.debug.assert(i == 0);
                    const read_len = FRAME_SIZE - self.first_frame_start_offset;
                    @memcpy(
                        buf[0..read_len],
                        self.buffer_pool.frames[f_idx][self.first_frame_start_offset..],
                    );
                    bytes_copied += read_len;
                },
                0b01 => { // !first, last (last frame)
                    const read_len = self.last_frame_end_offset;
                    @memcpy(
                        buf[bytes_copied..][0..read_len],
                        self.buffer_pool.frames[f_idx][0..read_len],
                    );
                    bytes_copied += read_len;
                    std.debug.assert(bytes_copied == self.len());
                },
                0b11 => { // first, last (only frame)
                    std.debug.assert(self.frame_indices.len == 1);
                    const readable_len = self.len();
                    @memcpy(
                        buf[0..readable_len],
                        self.buffer_pool.frames[
                            f_idx
                        ][self.first_frame_start_offset..self.last_frame_end_offset],
                    );
                    bytes_copied += self.len();
                },
            }
        }
    }

    pub fn iterator(self: *const CachedRead) Iterator {
        return .{ .cached_read = self };
    }

    pub fn len(self: CachedRead) u32 {
        if (self.frame_indices.len == 0) return 0;
        return (@as(u32, @intCast(self.frame_indices.len)) - 1) *
            FRAME_SIZE + self.last_frame_end_offset - self.first_frame_start_offset;
    }

    pub fn deinit(self: CachedRead, allocator: std.mem.Allocator) void {
        for (self.frame_indices) |frame_index| {
            std.debug.assert(frame_index != INVALID_FRAME);

            if (self.buffer_pool.frames_metadata.rc[frame_index].release()) {
                // notably, the frame remains in memory, and its hashmap entry
                // remains valid.
            }
        }
        allocator.free(self.frame_indices);
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
    if (builtin.os.tag != .linux) return error.SkipZigTest;

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

    var bp = try BufferPool.init(allocator, 2048); // 2048 frames = 1MiB
    defer bp.deinit(allocator);

    var fba_buf: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&fba_buf);

    const read = try bp.read(fba.allocator(), file, file_id, 0, 1000);
    defer read.deinit(fba.allocator());

    try std.testing.expectEqual(2, read.frame_indices.len);
    for (read.frame_indices) |f_idx| try std.testing.expect(f_idx != INVALID_FRAME);

    {
        var iter1 = read.iterator();
        const reader_data = try iter1.reader().readAllAlloc(fba.allocator(), 1000);
        defer fba.allocator().free(reader_data);
        try std.testing.expectEqual(1000, reader_data.len);

        var iter2 = read.iterator();

        const iter_data = try fba.allocator().alloc(u8, 1000);
        defer fba.allocator().free(iter_data);

        var bytes_read: usize = 0;
        while (iter2.next()) |byte| : (bytes_read += 1) {
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
    try std.testing.expect((total_requested_bytes / frame_count) - 512 <= 64);
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

        try std.testing.expectEqual(1, read_frame.frame_indices.len);

        const frame: []const u8 = bp.frames[
            read_frame.frame_indices[0]
        ][0..bp.frames_metadata.size[
            read_frame.frame_indices[0]
        ]];

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

            try std.testing.expect(
                read.first_frame_start_offset == read2.first_frame_start_offset,
            );
            try std.testing.expect(read.last_frame_end_offset == read2.last_frame_end_offset);
            try std.testing.expectEqualSlices(u32, read.frame_indices, read2.frame_indices);
        }

        var total_bytes_read: u32 = 0;
        for (read.frame_indices) |f_idx| total_bytes_read += bp.frames_metadata.size[f_idx];
        const read_data_bp_iter = try allocator.alloc(u8, read.len());
        defer allocator.free(read_data_bp_iter);
        {
            var i: u32 = 0;
            var iter = read.iterator();
            while (iter.next()) |b| : (i += 1) read_data_bp_iter[i] = b;
            if (i != read.len()) unreachable;
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
