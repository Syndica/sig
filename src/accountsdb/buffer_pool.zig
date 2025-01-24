const std = @import("std");
const sig = @import("../sig.zig");
const builtin = @import("builtin");

const IoUring = std.os.linux.IoUring;

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

// TODO: ideally we should be able to select this with a cli flag. (#509)
const use_io_uring = builtin.os.tag == .linux and linux_io_mode == .IoUring;

const io_uring_entries = 128;

fn io_uring() !*IoUring {
    // We use one io_uring instance per-thread internally for fast thread-safe usage.

    // From https://github.com/axboe/liburing/wiki/io_uring-and-networking-in-2023:
    // > Not sharing a ring between threads is the recommended way to use rings in general, as it
    // > avoids any unnecessary synchronization. Available since 6.1.

    const threadlocals = struct {
        threadlocal var io_uring: ?IoUring = null;
    };

    _ = threadlocals.io_uring orelse {
        threadlocals.io_uring = try IoUring.init(
            io_uring_entries,
            // Causes an error if we try to init with more entries than the kernel supports - it
            // would be bad if the kernel gave us fewer than we expect to have.
            std.os.linux.IORING_SETUP_CLAMP,
        );
    };

    return &(threadlocals.io_uring.?);
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
            IoUring.read,
            IoUring.submit_and_wait,
            IoUring.copy_cqes,
            IoUring.init,
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
    frames: []Frame,
    manager: Manager,

    pub const ReadError = readError();
    pub const Manager = FrameManager;

    pub fn init(
        allocator: std.mem.Allocator,
        num_frames: u32,
    ) !BufferPool {
        if (num_frames == 0 or num_frames == 1) return error.InvalidArgument;

        const frames = try allocator.alloc(Frame, num_frames);
        errdefer allocator.free(frames);

        const manager = try FrameManager.init(allocator, num_frames);
        errdefer manager.deinit(allocator);

        return .{
            .frames = frames,
            .manager = manager,
        };
    }

    pub fn deinit(
        self: *BufferPool,
        allocator: std.mem.Allocator,
    ) void {
        allocator.free(self.frames);
        self.manager.deinit(allocator);
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
        const frame_indices = try self.manager.getIndices(
            allocator,
            file_id,
            file_offset_start,
            file_offset_end,
        );
        errdefer allocator.free(frame_indices);

        // fill in invalid frames with file data, replacing invalid frames with
        // fresh ones.
        for (0.., frame_indices) |i, *f_idx| {
            if (f_idx.* != INVALID_FRAME) continue;
            // INVALID_FRAME => not found, read fresh and populate

            const frame_aligned_file_offset: FileOffset = @intCast((i * FRAME_SIZE) +
                (file_offset_start - file_offset_start % FRAME_SIZE));
            std.debug.assert(frame_aligned_file_offset % FRAME_SIZE == 0);

            f_idx.* = self.manager.getUnused(self.frames);

            errdefer {
                // Filling this frame failed, releasing rcs of previously filled frames
                for (frame_indices[0..i]) |alive_frame_idx| {
                    self.manager.deinitFrame(alive_frame_idx);
                }
            }

            const bytes_read = try file.pread(&self.frames[f_idx.*], frame_aligned_file_offset);
            self.manager.resetNewFrame(
                f_idx.*,
                file_id,
                frame_aligned_file_offset,
                @intCast(bytes_read),
            );
        }

        return ReadHandle.initCached(
            self,
            frame_indices,
            @intCast(file_offset_start % FRAME_SIZE),
            @intCast(((file_offset_end - 1) % FRAME_SIZE) + 1),
        );
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

        const frame_indices = try self.manager.getIndices(
            allocator,
            file_id,
            file_offset_start,
            file_offset_end,
        );
        errdefer allocator.free(frame_indices);

        // fill in invalid frames with file data, replacing invalid frames with
        // fresh ones.
        var queued_reads: u32 = 0;
        for (0.., frame_indices) |i, *f_idx| {
            if (f_idx.* != INVALID_FRAME) continue;
            // INVALID_FRAME => not found, read fresh and populate

            const frame_aligned_file_offset: FileOffset = @intCast((i * FRAME_SIZE) +
                (file_offset_start - file_offset_start % FRAME_SIZE));
            std.debug.assert(frame_aligned_file_offset % FRAME_SIZE == 0);

            f_idx.* = self.manager.getUnused(self.frames);

            errdefer {
                // Filling this frame failed, releasing rcs of previously filled frames
                for (frame_indices[0..i]) |alive_frame_idx| {
                    self.manager.deinitFrame(alive_frame_idx);
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
                    try IouringSubmitAndWaitReads(
                        &self.manager,
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

            self.manager.resetNewFrameNoSize(
                f_idx.*,
                file_id,
                frame_aligned_file_offset,
            );
        }

        errdefer {
            for (frame_indices) |alive_frame_idx| {
                self.manager.deinitFrame(alive_frame_idx);
            }
        }

        if (queued_reads > 0) {
            try IouringSubmitAndWaitReads(&self.manager, threadlocal_io_uring, file, queued_reads);
        }

        return ReadHandle.initCached(
            self,
            frame_indices,
            @intCast(file_offset_start % FRAME_SIZE),
            @intCast(((file_offset_end - 1) % FRAME_SIZE) + 1),
        );
    }

    // Wait for our file reads to complete, filling the read length into the metadata as we go.
    fn IouringSubmitAndWaitReads(
        manager: *Manager,
        threadlocal_io_uring: *IoUring,
        file: std.fs.File,
        n_reads: u32,
    ) !void {
        const n_submitted = try threadlocal_io_uring.submit_and_wait(n_reads);
        std.debug.assert(n_submitted == n_reads); // did somethng else submit an event?

        var cqe_buf: [io_uring_entries]std.os.linux.io_uring_cqe = undefined;

        // check our completions in order to set the frame's size;
        // we need to wait for completion to get the bytes read
        const cqe_count = try threadlocal_io_uring.copy_cqes(&cqe_buf, n_submitted);
        std.debug.assert(cqe_count == n_submitted); // why did we not receive them all?

        for (0.., cqe_buf[0..n_submitted]) |i, cqe| {
            if (cqe.err() != .SUCCESS) {
                std.debug.panicExtra(
                    null,
                    @returnAddress(),
                    "cqe: {}, err: {}, i: {}, file: {}",
                    .{ cqe, cqe.err(), i, file },
                );
            }
            const f_idx: FrameIndex = @intCast(cqe.user_data);
            const bytes_read: FrameOffset = @intCast(cqe.res);
            std.debug.assert(bytes_read <= FRAME_SIZE);

            manager.setNewFrameSize(f_idx, bytes_read);
        }
    }
};

/// Keeps track of all of the data and lifetimes associated with frames.
const FrameManager = struct {
    /// This field allows you to quickly get the first unused frames after initialisation. Once its
    /// value exceeds num_frames - 1, this means there are no more never-used frames (and we will
    /// start evicting from the lfu)
    free_idx: std.atomic.Value(u64),

    /// Uniquely identifies a frame from its file_id and offset.
    /// Used for looking up valid frames.
    /// TODO: Using a concurrent hashmap may be a large performance improvement.
    frame_map_rw: sig.sync.RwMux(Map),

    /// Stores internally-used per-frame data.
    metadata: Metadata,

    /// Evicts unused frames for reuse.
    eviction_lfu: sig.sync.RwMux(HierarchicalFIFO),

    pub const Metadata = FrameMetadata;
    pub const Map = std.AutoHashMapUnmanaged(FileIdFileOffset, FrameIndex);

    pub fn init(allocator: std.mem.Allocator, num_frames: u32) error{OutOfMemory}!FrameManager {
        var metadata = try Metadata.init(allocator, num_frames);
        errdefer metadata.deinit(allocator);

        var frame_map: Map = .{};
        try frame_map.ensureTotalCapacity(allocator, num_frames * 2);
        errdefer frame_map.deinit(allocator);
        const frame_map_rw = sig.sync.RwMux(Map).init(frame_map);

        const eviction_lfu = HierarchicalFIFO.init(
            allocator,
            num_frames / 10,
            num_frames,
        ) catch |err| switch (err) {
            error.InvalidArgument => unreachable,
            error.OutOfMemory => return error.OutOfMemory,
        };
        errdefer eviction_lfu.deinit(allocator);

        return .{
            .free_idx = std.atomic.Value(u64).init(0),
            .frame_map_rw = frame_map_rw,
            .metadata = metadata,
            .eviction_lfu = sig.sync.RwMux(HierarchicalFIFO).init(eviction_lfu),
        };
    }

    pub fn deinit(self: *FrameManager, allocator: std.mem.Allocator) void {
        self.metadata.deinit(allocator);

        const eviction_lfu, var eviction_lfu_lg = self.eviction_lfu.writeWithLock();
        eviction_lfu.deinit(allocator);
        eviction_lfu_lg.unlock();

        const frame_map, var frame_map_lg = self.frame_map_rw.writeWithLock();
        frame_map.deinit(allocator);
        frame_map_lg.unlock();
    }

    // Creates a buffer of frame indices. Each frame index may either be an INVALID_FRAME, or a
    // frame index pointing to valid data. In both cases, the frame is marked as alive - take care
    // to mark
    pub fn getIndices(
        self: *FrameManager,
        allocator: std.mem.Allocator,
        file_id: FileId,
        file_offset_start: FileOffset,
        file_offset_end: FileOffset,
    ) error{ InvalidArgument, OffsetsOutOfBounds, OutOfMemory }![]FrameIndex {
        const n_indices = try BufferPool.computeNumberofFrameIndices(
            file_offset_start,
            file_offset_end,
        );
        if (n_indices > self.metadata.rc.len) return error.OffsetsOutOfBounds;

        const frame_indices = try allocator.alloc(FrameIndex, n_indices);
        errdefer allocator.free(frame_indices);
        @memset(frame_indices, INVALID_FRAME);

        // lookup frame mappings
        {
            const frame_map, var frame_map_lg = self.frame_map_rw.readWithLock();
            defer frame_map_lg.unlock();

            for (0.., frame_indices) |i, *f_idx| {
                const file_offset: FileOffset = @intCast(
                    (i * FRAME_SIZE) + (file_offset_start - file_offset_start % FRAME_SIZE),
                );

                const key: FileIdFileOffset = .{
                    .file_id = file_id,
                    .file_offset = file_offset,
                };

                if (frame_map.get(key)) |frame_idx| f_idx.* = frame_idx;
            }
        }

        for (frame_indices) |f_idx| {
            if (f_idx == INVALID_FRAME) continue;
            self.reuse(f_idx);
        }

        return frame_indices;
    }

    /// Frames with an associated rc of 0 are up for eviction, and which frames
    /// are evicted first is up to the LFU.
    fn getUnused(self: *FrameManager, frames: []Frame) FrameIndex {
        const prev_free_idx = self.free_idx.fetchAdd(1, .monotonic);
        if (prev_free_idx < self.metadata.rc.len) return @intCast(prev_free_idx);

        const evicted, const evicted_key = blk: {
            const eviction_lfu, var eviction_lfu_lg = self.eviction_lfu.writeWithLock();
            defer eviction_lfu_lg.unlock();

            const evicted = eviction_lfu.evict(self.metadata);
            const evicted_key = self.metadata.key[evicted].load(.acquire);

            // not actually necessary, but makes issues more visible
            self.metadata.key[evicted].store(@bitCast(FileIdFileOffset.INVALID), .release);
            self.metadata.size[evicted].store(0xAAAA, .release);

            break :blk .{ evicted, evicted_key };
        };

        const did_remove = blk: {
            const frame_map, var frame_map_lg = self.frame_map_rw.writeWithLock();
            defer frame_map_lg.unlock();
            break :blk frame_map.remove(@bitCast(evicted_key));
        };

        // Thread safety: thread safety issues seem to all go away if I hold the eviction_lfu_lg up
        // until here. But we shouldn't need to do this?

        if (!did_remove) {
            std.debug.panicExtra(
                null,
                @returnAddress(),
                "evicted a frame that did not exist in frame_map, frame: {}\n",
                .{evicted},
            );
        }
        @memset(&frames[evicted], 0xAA);
        return evicted;
    }

    /// Used upon a valid frame. Frame's rc may be alive or dead.
    fn reuse(self: *FrameManager, f_idx: FrameIndex) void {
        self.insertLfu(f_idx);

        if (!self.metadata.rc[f_idx].acquire()) {
            // frame has no handles, but memory is still valid
            self.metadata.rc[f_idx].reset();
        }
    }

    /// Must be used on an alive frame.
    fn reuseAlive(self: *FrameManager, f_idx: FrameIndex) void {
        self.insertLfu(f_idx);

        if (!self.metadata.rc[f_idx].acquire()) {
            std.debug.panicExtra(
                null,
                @returnAddress(),
                "attempted to reuse dead frame: {}",
                .{f_idx},
            );
        }
    }

    fn deinitFrame(self: *FrameManager, f_idx: FrameIndex) void {
        std.debug.assert(f_idx != INVALID_FRAME);

        // We deliberately do not clean up upon deinit - the frame's data and map entry remain valid
        // for a later read to use.
        _ = self.metadata.rc[f_idx].release();
    }

    /// To be used on newly evicted dead frames, which are being written into.
    fn resetNewFrame(
        self: *FrameManager,
        f_idx: FrameIndex,
        file_id: FileId,
        frame_aligned_file_offset: FileOffset,
        size: FrameOffset,
    ) void {
        resetNewFrameNoSize(
            self,
            f_idx,
            file_id,
            frame_aligned_file_offset,
        );
        self.metadata.size[f_idx].store(size, .release);
    }

    /// Only to be called soon after .resetNewFrameNoSize.
    fn setNewFrameSize(
        self: *FrameManager,
        f_idx: FrameIndex,
        size: FrameOffset,
    ) void {
        self.metadata.size[f_idx].store(size, .release);
    }

    /// Must be followed up with a call to .setNewFrameSize when the size is known.
    fn resetNewFrameNoSize(
        self: *FrameManager,
        f_idx: FrameIndex,
        file_id: FileId,
        frame_aligned_file_offset: FileOffset,
    ) void {
        std.debug.assert(frame_aligned_file_offset % FRAME_SIZE == 0);

        if (self.metadata.rc[f_idx].isAlive()) {
            std.debug.panicExtra(
                null,
                @returnAddress(),
                "attempted to reset frame with active ReadHandles: {}\n",
                .{f_idx},
            );
        }

        const map_key: FileIdFileOffset = .{
            .file_id = file_id,
            .file_offset = frame_aligned_file_offset,
        };

        {
            // Thread safety: Lock eviction_lfu, as it directly accesses many of these metadata
            // fields.
            _, var eviction_lfu_lg = self.eviction_lfu.writeWithLock();
            defer eviction_lfu_lg.unlock();

            self.metadata.freqSetToZero(f_idx);
            self.metadata.in_queue[f_idx].store(.none, .release);
            self.metadata.rc[f_idx].reset(); // Thread safety: is .reset() correct?
            self.metadata.key[f_idx].store(@bitCast(map_key), .release);
            self.metadata.size[f_idx].store(0xAAAA, .release);
        }

        {
            const frame_map, var frame_map_lg = self.frame_map_rw.writeWithLock();
            defer frame_map_lg.unlock();

            // Thread safety: it is possible for an ordering of inserts and removes to cause this
            // frame_map to not always be at a consistent size, despite a single thread always
            // removing one entry before adding one.
            frame_map.putAssumeCapacityNoClobber(map_key, f_idx);
        }

        self.insertLfu(f_idx);
    }

    fn insertLfu(self: *FrameManager, f_idx: FrameIndex) void {
        const eviction_lfu, var eviction_lfu_lg = self.eviction_lfu.writeWithLock();
        defer eviction_lfu_lg.unlock();
        eviction_lfu.insert(self.metadata, f_idx) catch |err| switch (err) {
            error.InvalidKey => std.debug.panicExtra(
                null,
                @returnAddress(),
                "Attempted to use invalid key: {}\n",
                .{f_idx},
            ),
        };
    }
};

const FrameMetadata = struct {
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

    fn init(allocator: std.mem.Allocator, num_frames: usize) !FrameMetadata {
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

    fn deinit(self: *FrameMetadata, allocator: std.mem.Allocator) void {
        // NOTE: this check itself is racy, but should never happen
        for (0.., self.rc) |i, *rc| {
            if (rc.isAlive()) {
                std.debug.panicExtra(
                    null,
                    @returnAddress(),
                    "BufferPool deinitialised with alive handle: {}\n",
                    .{i},
                );
            }
        }
        allocator.free(self.rc);
        allocator.free(self.key);
        allocator.free(self.freq);
        allocator.free(self.in_queue);
        allocator.free(self.size);
        self.* = undefined;
    }

    fn freqIncrement(self: FrameMetadata, index: FrameIndex) void {
        const old_freq = @atomicRmw(u2, &self.freq[index], .Add, 1, .acquire);
        if (old_freq == 0) {
            // we overflowed (3->0), set back to max
            @atomicStore(u2, &self.freq[index], 3, .release);
        }
    }

    fn freqDecrement(self: FrameMetadata, index: FrameIndex) void {
        const old_freq = @atomicRmw(u2, &self.freq[index], .Sub, 1, .acquire);
        if (old_freq == 3) {
            // we overflowed (0->3), set back to min
            @atomicStore(u2, &self.freq[index], 0, .release);
        }
    }

    fn freqIsZero(self: FrameMetadata, index: FrameIndex) bool {
        const freq = @atomicLoad(u2, &self.freq[index], .acquire);
        return freq == 0;
    }

    fn freqSetToOne(self: FrameMetadata, index: FrameIndex) void {
        @atomicStore(u2, &self.freq[index], 1, .release);
    }

    fn freqSetToZero(self: FrameMetadata, index: FrameIndex) void {
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
    pub const Metadata = FrameMetadata;
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
    owned_allocation: []const u8,
    /// Data allocated elsewhere, not owned or created by BufferPool.
    unowned_allocation: []const u8,
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

    const SubRead = packed struct(u128) {
        parent: *const ReadHandle,
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
    pub fn initAllocatedOwned(data: []const u8) ReadHandle {
        return ReadHandle{ .owned_allocation = data };
    }

    /// External to the BufferPool
    pub fn initAllocated(data: []const u8) ReadHandle {
        return ReadHandle{ .unowned_allocation = data };
    }

    pub fn deinit(self: ReadHandle, allocator: std.mem.Allocator) void {
        switch (self) {
            .cached => |cached| {
                for (cached.frame_indices) |frame_index| {
                    cached.buffer_pool.manager.deinitFrame(frame_index);
                }
                allocator.free(cached.frame_indices);
            },
            .sub_read => |_| {},
            .unowned_allocation => |_| {},
            .owned_allocation => |owned_allocation| {
                allocator.free(owned_allocation);
            },
        }
    }

    pub fn iterator(self: *const ReadHandle) Iterator {
        return .{ .read_handle = self, .start = 0, .end = self.len() };
    }

    /// Copies all data into specified buffer. Buf.len === self.len()
    pub fn readAll(self: ReadHandle, buf: []u8) void {
        std.debug.assert(buf.len == self.len());
        self.read(0, buf);
    }

    pub fn readAllAllocate(self: ReadHandle, allocator: std.mem.Allocator) ![]u8 {
        return self.readAllocate(allocator, 0, self.len());
    }

    /// Copies data into specified buffer.
    pub fn read(
        self: *const ReadHandle,
        start: FileOffset,
        buf: []u8,
    ) void {
        const end: FileOffset = @intCast(start + buf.len);

        switch (self.*) {
            .owned_allocation, .unowned_allocation => |data| return @memcpy(buf, data[start..end]),
            .sub_read => |*sb| return sb.parent.read(sb.start + start, buf),
            .cached => {},
        }

        var bytes_copied: u32 = 0;
        var iter = self.iteratorRanged(start, end);
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
        self.read(start, buf);
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
            .owned_allocation, .unowned_allocation => |data| @intCast(data.len),
        };
    }

    pub fn iteratorRanged(self: *const ReadHandle, start: FileOffset, end: FileOffset) Iterator {
        std.debug.assert(self.len() >= end);
        std.debug.assert(end >= start);

        return .{ .read_handle = self, .start = start, .end = end };
    }

    pub fn dupeAllocatedOwned(self: ReadHandle, allocator: std.mem.Allocator) !ReadHandle {
        const data_copy = try self.readAllAllocate(allocator);
        return initAllocatedOwned(data_copy);
    }

    pub fn duplicateCached(self: ReadHandle, allocator: std.mem.Allocator) !ReadHandle {
        switch (self) {
            .cached => |*cached| {
                const indices = try allocator.dupe(FrameIndex, cached.frame_indices);
                for (indices) |f_idx| {
                    cached.buffer_pool.manager.reuseAlive(f_idx);
                }
                return ReadHandle.initCached(
                    cached.buffer_pool,
                    indices,
                    cached.first_frame_start_offset,
                    cached.last_frame_end_offset,
                );
            },
            else => unreachable, // duplicateCached called with non-cached ReadHandle
        }
    }

    pub fn slice(self: *const ReadHandle, start: usize, end: usize) ReadHandle {
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
        while (iter.nextFrame()) |frame_slice| : (i += @intCast(frame_slice.len)) {
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

            self.read_handle.read(self.start + self.bytes_read, buffer[0..read_len]);
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
                    const frame_end: FrameOffset = if (current_frame ==
                        cached.frame_indices.len - 1)
                        cached.last_frame_end_offset
                    else
                        FRAME_SIZE;

                    const end_idx = @min(frame_end, frame_start + self.bytesRemaining());

                    const buf = cached.buffer_pool.frames[
                        cached.frame_indices[current_frame]
                    ][frame_start..end_idx];

                    break :buf buf;
                },
                .owned_allocation, .unowned_allocation => |external| buf: {
                    const end_idx = @min(
                        read_offset + FRAME_SIZE,
                        read_offset + self.bytesRemaining(),
                    );
                    break :buf external[read_offset..end_idx];
                },
                .sub_read => @panic("unimpl"),
            };

            if (frame_buf.len == 0) unreachable; // guarded against by the bytes_read check
            if (self.bytes_read > self.len()) unreachable; // we've gone too far

            self.bytes_read += @intCast(frame_buf.len);
            return frame_buf;
        }
    };

    fn bincodeSerialize(
        writer: anytype,
        read_handle: anytype,
        params: bincode.Params,
    ) anyerror!void {
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
    total_requested_bytes -= bp.manager.eviction_lfu.readField("ghost").buf.len *
        @sizeOf(FrameIndex);
    total_requested_bytes -= bp.manager.eviction_lfu.readField("main").buf.len *
        @sizeOf(FrameIndex);
    total_requested_bytes -= bp.manager.eviction_lfu.readField("small").buf.len *
        @sizeOf(FrameIndex);
    total_requested_bytes -= @sizeOf(usize) * 3; // hashmap header

    try std.testing.expect(total_requested_bytes % frame_count == 0);

    // metadata should be small!
    // As of writing, all metadata (excluding eviction_lfu, including frame_map)
    // is 50 bytes or ~9% of memory usage at a frame size of 512, or 50MB for a
    // million frames.
    try std.testing.expect((total_requested_bytes / frame_count) - FRAME_SIZE <= 80);
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
        ][0..bp.manager.metadata.size[
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
            total_bytes_read += bp.manager.metadata.size[f_idx].load(.unordered);
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
        read.readAll(read_data_bp_readall);

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
            deserialised_from_slice.owned_allocation,
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
            deserialised_from_handle.owned_allocation,
        );
    }
}
