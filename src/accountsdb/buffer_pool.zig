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
const FrameIndex = u31;
const FileOffset = u32;
const FrameOffset = u10; // 0..=FRAME_SIZE

comptime {
    // assert our FRAME_SIZE fits in FrameOffset
    const offset: FrameOffset = FRAME_SIZE;
    _ = offset;
}

const FrameRef = packed struct(u32) {
    f_idx: FrameIndex,
    hit: bool,
    const INIT = FrameRef{
        .f_idx = INVALID_FRAME,
        .hit = false,
    };
};

const Rc = std.atomic.Value(u32);

const LinuxIoMode = enum {
    Blocking,
    IoUring,
};
const linux_io_mode: LinuxIoMode = .Blocking;

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

const IoUringError = err: {
    var Error = error{};
    const fns = &.{ IoUring.read, IoUring.submit_and_wait, IoUring.copy_cqes, IoUring.init };
    for (fns) |func| {
        Error = Error || @typeInfo(
            @typeInfo(@TypeOf(func)).Fn.return_type.?,
        ).ErrorUnion.error_set;
    }

    break :err Error;
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
    frames: []Frame,
    manager: Manager,

    pub const ReadBlockingError = FrameManager.GetError || std.posix.PReadError;
    pub const ReadIoUringError = FrameManager.GetError || IoUringError;
    pub const ReadError = if (use_io_uring) ReadIoUringError else ReadBlockingError;
    pub const Manager = FrameManager;

    pub fn init(
        allocator: std.mem.Allocator,
        num_frames: u32,
    ) !BufferPool {
        if (num_frames == 0 or num_frames == 1) return error.InvalidArgument;

        // Alignment of frames is good for read performance (and necessary if we want to use O_DIRECT.)
        const frames = try allocator.alignedAlloc(Frame, 4096, num_frames);
        errdefer allocator.free(frames);

        var manager = try FrameManager.init(allocator, num_frames);
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
    ) ReadBlockingError!ReadHandle {
        const frame_refs = try self.manager.getAllIndices(
            allocator,
            file_id,
            file_offset_start,
            file_offset_end,
        );
        errdefer allocator.free(frame_refs);
        errdefer self.manager.getAllIndicesRollback(frame_refs);

        // read into unpopulated frames
        for (0.., frame_refs) |i, *frame_ref| {
            const contains_valid_data = self.manager
                .contains_valid_data[frame_ref.f_idx].load(.acquire);
            if (contains_valid_data) continue;

            const frame_aligned_file_offset: FileOffset = @intCast((i * FRAME_SIZE) +
                (file_offset_start - file_offset_start % FRAME_SIZE));
            std.debug.assert(frame_aligned_file_offset % FRAME_SIZE == 0);

            const bytes_read = try file.preadAll(
                &self.frames[frame_ref.f_idx],
                frame_aligned_file_offset,
            );
            std.debug.assert(bytes_read <= FRAME_SIZE);
            self.manager.contains_valid_data[frame_ref.f_idx].store(true, .seq_cst);
        }

        return ReadHandle.initCached(
            self,
            frame_refs,
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
            self.readIoUring(
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

    fn readIoUring(
        self: *BufferPool,
        /// used for temp allocations, and the returned .indices slice
        allocator: std.mem.Allocator,
        file: std.fs.File,
        file_id: FileId,
        /// inclusive
        file_offset_start: FileOffset,
        /// exclusive
        file_offset_end: FileOffset,
    ) ReadIoUringError!ReadHandle {
        if (!use_io_uring) @compileError("io_uring disabled");
        const threadlocal_io_uring = try io_uring();

        const frame_refs = try self.manager.getAllIndices(
            allocator,
            file_id,
            file_offset_start,
            file_offset_end,
        );
        errdefer allocator.free(frame_refs);
        errdefer self.manager.getAllIndicesRollback(frame_refs);

        var i: u32 = 0;
        var n_read: u32 = 0;
        while (i < frame_refs.len or n_read < frame_refs.len) {
            var queue_full = false;

            if (i < frame_refs.len) {
                const frame_ref = &frame_refs[i];

                const populated = self.manager.contains_valid_data[frame_ref.f_idx].load(.acquire);
                if (populated) {
                    n_read += 1;
                    i += 1;
                    continue;
                }

                const frame_aligned_file_offset: FileOffset = @intCast((i * FRAME_SIZE) +
                    (file_offset_start - file_offset_start % FRAME_SIZE));
                std.debug.assert(frame_aligned_file_offset % FRAME_SIZE == 0);

                _ = threadlocal_io_uring.read(
                    frame_ref.f_idx,
                    file.handle,
                    .{ .buffer = &self.frames[frame_ref.f_idx] },
                    frame_aligned_file_offset,
                ) catch |err| switch (err) {
                    error.SubmissionQueueFull => {
                        queue_full = true;
                    },
                    else => return err,
                };

                if (!queue_full) {
                    i += 1;
                    continue;
                }
            }

            if (queue_full or i >= frame_refs.len) {
                // Submit without blocking
                const n_submitted = try threadlocal_io_uring.submit();
                std.debug.assert(n_submitted <= io_uring_entries);
                if (queue_full) std.debug.assert(n_submitted == io_uring_entries);

                // Read whatever is still available
                var cqe_buf: [io_uring_entries]std.os.linux.io_uring_cqe = undefined;
                const n_cqes_copied = try threadlocal_io_uring.copy_cqes(&cqe_buf, 0);
                for (cqe_buf[0..n_cqes_copied]) |cqe| {
                    if (cqe.err() != .SUCCESS) std.debug.panic(
                        "Read failed, cqe: {}, err: {}, i: {}, file: {}",
                        .{ cqe, cqe.err(), i, file },
                    );
                    const bytes_read: FrameOffset = @intCast(cqe.res);
                    std.debug.assert(bytes_read > 0);
                }

                for (frame_refs[n_read..][0..n_cqes_copied]) |*frame_ref| {
                    self.manager.contains_valid_data[frame_ref.f_idx].store(true, .seq_cst);
                }
                n_read += n_cqes_copied;
            }
        }

        return ReadHandle.initCached(
            self,
            frame_refs,
            @intCast(file_offset_start % FRAME_SIZE),
            @intCast(((file_offset_end - 1) % FRAME_SIZE) + 1),
        );
    }
};

/// Keeps track of all of the data and lifetimes associated with frames.
const FrameManager = struct {
    /// Uniquely identifies a frame from its file_id and offset.
    /// Used for looking up valid frames.
    frame_map_rw: sig.sync.RwMux(Map),

    /// Evicts unused frames for reuse.
    eviction_lfu: sig.sync.RwMux(HierarchicalFIFO),

    /// Per-frame refcounts. Used to track what frames still have handles associated with them.
    rc: []Rc,

    contains_valid_data: []std.atomic.Value(bool),

    pub const Map = std.AutoHashMapUnmanaged(FileIdFileOffset, FrameIndex);

    const GetError = error{ InvalidArgument, OffsetsOutOfBounds, OutOfMemory };

    pub fn init(allocator: std.mem.Allocator, num_frames: u32) error{OutOfMemory}!FrameManager {
        std.debug.assert(num_frames > 0);

        var frame_map: Map = .{};
        try frame_map.ensureTotalCapacity(allocator, num_frames * 2);
        errdefer frame_map.deinit(allocator);

        var eviction_lfu = HierarchicalFIFO.init(
            allocator,
            @max(num_frames / 10, 1),
            num_frames,
        ) catch |err| switch (err) {
            error.InvalidArgument => unreachable,
            error.OutOfMemory => return error.OutOfMemory,
        };
        errdefer eviction_lfu.deinit(allocator);

        for (0..num_frames) |i| {
            const f_idx: FrameIndex = @intCast(i);
            // initially populate so that we can start evicting
            eviction_lfu.insert(f_idx);

            const bad_key = FileIdFileOffset{
                .file_id = FileId.fromInt(std.math.maxInt(u32)),
                .file_offset = f_idx * 2 + 1, // always odd => always invalid
            };

            frame_map.putAssumeCapacityNoClobber(bad_key, f_idx);
            eviction_lfu.key[f_idx] = bad_key;
        }

        const rc = try allocator.alloc(Rc, num_frames);
        errdefer allocator.free(rc);
        @memset(rc, .{ .raw = 0 });

        const contains_valid_data = try allocator.alloc(std.atomic.Value(bool), num_frames);
        errdefer allocator.free(contains_valid_data);
        @memset(contains_valid_data, std.atomic.Value(bool).init(false));

        return .{
            .frame_map_rw = sig.sync.RwMux(Map).init(frame_map),
            .eviction_lfu = sig.sync.RwMux(HierarchicalFIFO).init(eviction_lfu),
            .rc = rc,
            .contains_valid_data = contains_valid_data,
        };
    }

    pub fn deinit(self: *FrameManager, allocator: std.mem.Allocator) void {
        const eviction_lfu, var eviction_lfu_lg = self.eviction_lfu.writeWithLock();
        eviction_lfu.deinit(allocator);
        eviction_lfu_lg.unlock();

        const frame_map, var frame_map_lg = self.frame_map_rw.writeWithLock();
        frame_map.deinit(allocator);
        frame_map_lg.unlock();

        for (0.., self.rc) |i, *rc| {
            if (rc.load(.seq_cst) > 0) {
                std.debug.panicExtra(
                    null,
                    @returnAddress(),
                    "BufferPool deinitialised with alive handle: {}\n",
                    .{i},
                );
            }
        }
        allocator.free(self.rc);
        allocator.free(self.contains_valid_data);
    }

    fn numFrames(self: *const FrameManager) u32 {
        return @intCast(self.rc.len);
    }

    fn getAllIndices(
        self: *FrameManager,
        allocator: std.mem.Allocator,
        file_id: FileId,
        file_offset_start: FileOffset,
        file_offset_end: FileOffset,
    ) GetError![]FrameRef {
        const n_indices = try BufferPool.computeNumberofFrameIndices(
            file_offset_start,
            file_offset_end,
        );
        if (n_indices > self.numFrames()) return error.OffsetsOutOfBounds;

        const frame_refs = try allocator.alloc(FrameRef, n_indices);
        @memset(frame_refs, FrameRef.INIT);

        if (n_indices == 0) return &.{};

        errdefer comptime unreachable; // We don't error after this point

        // lookup frame mappings
        var n_hits: u32 = 0;
        {
            const frame_map, var frame_map_lg = self.frame_map_rw.readWithLock();
            defer frame_map_lg.unlock();

            for (0.., frame_refs) |i, *frame_ref| {
                const file_offset: FileOffset = @intCast(
                    (i * FRAME_SIZE) + (file_offset_start - file_offset_start % FRAME_SIZE),
                );

                const key: FileIdFileOffset = .{
                    .file_id = file_id,
                    .file_offset = file_offset,
                };

                const cache_hit_f_idx = frame_map.get(key) orelse continue;
                n_hits += 1;
                frame_ref.hit = true;
                frame_ref.f_idx = cache_hit_f_idx;
                _ = self.rc[frame_ref.f_idx].fetchAdd(1, .seq_cst);
            }
        }

        if (n_hits < frame_refs.len) {
            const frame_map, var frame_map_lg = self.frame_map_rw.writeWithLock();
            defer frame_map_lg.unlock();

            const eviction_lfu, var eviction_lfu_lg = self.eviction_lfu.writeWithLock();
            defer eviction_lfu_lg.unlock();

            for (0.., frame_refs) |i, *frame_ref| {
                if (frame_ref.hit) {
                    std.debug.assert(frame_ref.f_idx != INVALID_FRAME);
                    continue;
                }
                std.debug.assert(frame_ref.f_idx == INVALID_FRAME); // missed frame with valid idx?

                const file_offset: FileOffset = @intCast(
                    (i * FRAME_SIZE) + (file_offset_start - file_offset_start % FRAME_SIZE),
                );

                const key: FileIdFileOffset = .{
                    .file_id = file_id,
                    .file_offset = file_offset,
                };

                // Couldve been added between readLock() and us. If so, just ref it.
                // If not, upsert to value-index that we'll get from eviction below.
                const entry = frame_map.getOrPutAssumeCapacity(key);
                if (entry.found_existing) {
                    frame_ref.f_idx = entry.value_ptr.*;
                    _ = self.rc[frame_ref.f_idx].fetchAdd(1, .seq_cst);
                    continue;
                }

                const evicted_f_idx = eviction_lfu.evict(self.rc);

                const evicted_key = eviction_lfu.key[evicted_f_idx];

                frame_ref.f_idx = evicted_f_idx;
                self.rc[frame_ref.f_idx].store(1, .seq_cst);
                self.contains_valid_data[frame_ref.f_idx].store(false, .seq_cst);

                eviction_lfu.insert(frame_ref.f_idx);

                entry.value_ptr.* = frame_ref.f_idx;
                eviction_lfu.key[frame_ref.f_idx] = key;

                std.debug.assert(!std.meta.eql(evicted_key, key)); // inserted key we just evicted

                const removed = frame_map.remove(evicted_key);
                std.debug.assert(removed); // evicted key was not in map
            }
        }

        for (frame_refs) |frame_ref| std.debug.assert(frame_ref.f_idx != INVALID_FRAME);

        return frame_refs;
    }

    /// To be called on read failure. This should be extremely rare.
    fn getAllIndicesRollback(self: *FrameManager, frame_refs: []FrameRef) void {
        @setCold(true);

        // rollback rcs
        for (frame_refs) |f_ref| _ = self.rc[f_ref.f_idx].fetchSub(1, .seq_cst);

        // re-insert evicted indices
        {
            const eviction_lfu, var eviction_lfu_lg = self.eviction_lfu.writeWithLock();
            defer eviction_lfu_lg.unlock();

            for (frame_refs) |f_ref| {
                if (f_ref.hit == false) eviction_lfu.insert(f_ref.f_idx);
            }
        }
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
    pub const Fifo = std.fifo.LinearFifo(FrameIndex, .Slice);

    pub const InQueue = enum(u8) { none, small, main, ghost }; // u8 required for extern usage

    small: Fifo,
    main: Fifo, // probably-alive items
    ghost: Fifo, // probably-dead items

    /// Effectively the inverse of FrameManager.Map, used in order to remove Map entries by their
    /// value when their key is evicted.
    key: []FileIdFileOffset,

    /// Frequency for the HierarchicalFIFO entries.
    /// Yes, really, only 0, 1, 2, 3.
    freq: []u2,

    /// Which queue each frame exists in.
    in_queue: []InQueue,

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

        const key = try allocator.alloc(FileIdFileOffset, num_frames);
        errdefer allocator.free(key);
        @memset(key, .{ .file_id = FileId.fromInt(0), .file_offset = 0 });

        const freq = try allocator.alloc(u2, num_frames);
        errdefer allocator.free(freq);
        @memset(freq, 0);

        const in_queue = try allocator.alloc(InQueue, num_frames);
        errdefer allocator.free(in_queue);
        @memset(in_queue, .none);

        return .{
            .small = Fifo.init(small_buf),
            .main = Fifo.init(main_buf),
            .ghost = Fifo.init(ghost_buf),
            .key = key,
            .freq = freq,
            .in_queue = in_queue,
        };
    }

    pub fn deinit(self: *HierarchicalFIFO, allocator: std.mem.Allocator) void {
        allocator.free(self.small.buf);
        allocator.free(self.main.buf);
        allocator.free(self.ghost.buf);

        allocator.free(self.key);
        allocator.free(self.freq);
        allocator.free(self.in_queue);

        self.* = undefined;
    }

    pub fn numFrames(self: *HierarchicalFIFO) u32 {
        return @intCast(self.main.buf.len);
    }

    pub fn insert(self: *HierarchicalFIFO, key: Key) void {
        switch (self.in_queue[key]) {
            .main, .small => {
                self.freq[key] +|= 1;
            },
            .ghost => {
                std.debug.assert(self.freq[key] == 0);
                self.freq[key] = 1;
                // Add key to main too - important to note that the key *still*
                // exists within ghost, but from now on we'll ignore that entry.
                self.main.writeItemAssumeCapacity(key);
                self.in_queue[key] = .main;
            },
            .none => {
                if (self.small.writableLength() == 0) {
                    const popped_small = self.small.readItem().?;

                    if (self.freq[popped_small] == 0) {
                        self.ghost.writeItemAssumeCapacity(popped_small);
                        self.in_queue[popped_small] = .ghost;
                    } else {
                        self.main.writeItemAssumeCapacity(popped_small);
                        self.in_queue[popped_small] = .main;
                    }
                }
                self.small.writeItemAssumeCapacity(key);
                self.in_queue[key] = .small;
            },
        }
    }

    /// To be called when freelist is empty.
    /// This does not return an optional, as the caller *requires* a key to be
    /// evicted. Not being able to return a key means illegal internal state in
    /// the BufferPool.
    pub fn evict(self: *HierarchicalFIFO, rc: []Rc) Key {
        var alive_eviction_attempts: usize = 0;

        const dead_key: Key = while (true) {
            var maybe_evicted: ?Key = null;

            if (maybe_evicted == null) maybe_evicted = self.evictGhost();

            // if we keep failing to evict a dead key, start alternating between
            // evicting from main and small. This saves us from the rare case
            // that every key in main is alive. In normal conditions, main
            // should be evicted from first.
            if (alive_eviction_attempts < 10 or alive_eviction_attempts % 2 == 0) {
                if (maybe_evicted == null) maybe_evicted = self.evictSmallOrMain(.main);
                if (maybe_evicted == null) maybe_evicted = self.evictSmallOrMain(.small);
            } else {
                if (maybe_evicted == null) maybe_evicted = self.evictSmallOrMain(.small);
                if (maybe_evicted == null) maybe_evicted = self.evictSmallOrMain(.main);
            }

            // NOTE: This panic is effectively unreachable - an empty cache
            // shouldn't be possible by (mis)using the public API of BufferPool,
            // except by touching the .eviction_lfu field (which you should
            // never do).
            const evicted = maybe_evicted orelse
                @panic("unable to evict: cache empty"); // see above comment

            // alive evicted keys are reinserted, we try again
            if (rc[evicted].load(.seq_cst) > 0) {
                self.freq[evicted] = 1;
                self.main.writeItemAssumeCapacity(evicted);
                self.in_queue[evicted] = .main;
                alive_eviction_attempts += 1;
                continue;
            }

            // key is definitely dead
            self.in_queue[evicted] = .none;
            break evicted;
        };

        return dead_key;
    }

    fn evictGhost(self: *HierarchicalFIFO) ?Key {
        const evicted: ?Key = while (self.ghost.readItem()) |ghost_key| {
            switch (self.in_queue[ghost_key]) {
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
        comptime target_queue: enum { small, main },
    ) ?Key {
        const queue = switch (target_queue) {
            .small => &self.small,
            .main => &self.main,
        };

        const evicted: ?Key = while (queue.readItem()) |popped_key| {
            switch (target_queue) {
                .small => if (self.in_queue[popped_key] != .small) unreachable,
                .main => if (self.in_queue[popped_key] != .main) unreachable,
            }

            if (self.freq[popped_key] == 0) {
                break popped_key;
            } else {
                self.freq[popped_key] -= 1;
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

    /// Data allocated elsewhere, not owned or created by BufferPool. BufferPool will deallocate.
    owned_allocation: []const u8,
    /// Data allocated elsewhere, not owned or created by BufferPool.
    unowned_allocation: []const u8,
    /// Data owned by parent ReadHandle
    sub_read: SubRead,
    /// Used in place of a read, in callsites where it is not actually needed. Provides .len().
    unread: Unread,

    const CachedRead = struct {
        buffer_pool: *BufferPool,
        frame_refs: []FrameRef,
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

    const Unread = struct {
        len: u32,
    };

    pub const @"!bincode-config" = bincode.FieldConfig(ReadHandle){
        .deserializer = bincodeDeserialize,
        .serializer = bincodeSerialize,
        .free = bincodeFree,
    };

    /// Only called by the BufferPool
    fn initCached(
        buffer_pool: *BufferPool,
        frame_refs: []FrameRef,
        first_frame_start_offset: FrameOffset,
        last_frame_end_offset: FrameOffset,
    ) ReadHandle {
        return .{
            .cached = .{
                .buffer_pool = buffer_pool,
                .frame_refs = frame_refs,
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

    pub fn initUnread(length: u32) ReadHandle {
        return .{ .unread = .{ .len = length } };
    }

    pub fn deinit(self: ReadHandle, allocator: std.mem.Allocator) void {
        switch (self) {
            .cached => |*cached| {
                for (cached.frame_refs) |frame_ref| {
                    std.debug.assert(frame_ref.f_idx != INVALID_FRAME);
                    const prev_rc = cached.buffer_pool.manager.rc[
                        frame_ref.f_idx
                    ].fetchSub(1, .seq_cst);
                    std.debug.assert(prev_rc != 0); // deinit of dead frame
                }

                allocator.free(cached.frame_refs);
            },
            .owned_allocation => |owned_allocation| {
                allocator.free(owned_allocation);
            },
            .sub_read,
            .unowned_allocation,
            .unread,
            => {},
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
            .unread => unreachable,
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
                if (cached.frame_refs.len == 0) return 0;
                return (@as(u32, @intCast(cached.frame_refs.len)) - 1) *
                    FRAME_SIZE +
                    cached.last_frame_end_offset - cached.first_frame_start_offset;
            },
            .unread => |unread| unread.len,
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
                const refs = try allocator.dupe(FrameRef, cached.frame_refs);
                for (refs) |ref| {
                    const prev_rc = cached.buffer_pool.manager.rc[ref.f_idx].fetchAdd(1, .seq_cst);
                    std.debug.assert(prev_rc > 0); // duplicated ReadHandle with dead frame
                }
                return ReadHandle.initCached(
                    cached.buffer_pool,
                    refs,
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
                    const current_frame: FrameIndex = @intCast(read_offset / FRAME_SIZE);

                    const frame_start: FrameOffset = @intCast(read_offset % FRAME_SIZE);
                    const frame_end: FrameOffset = if (current_frame ==
                        cached.frame_refs.len - 1)
                        cached.last_frame_end_offset
                    else
                        FRAME_SIZE;

                    const end_idx = @min(frame_end, frame_start + self.bytesRemaining());

                    const buf = cached.buffer_pool.frames[
                        cached.frame_refs[current_frame].f_idx
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
                .unread => unreachable,
                .sub_read => @panic("unimplemented"),
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

    var read = try bp.readIoUring(allocator, file, file_id, 0, 1000);
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
        read.cached.frame_refs.len,
    );
    for (read.cached.frame_refs) |frame_ref|
        try std.testing.expect(frame_ref.f_idx != INVALID_FRAME);

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

        try std.testing.expectEqual(1, read_frame.cached.frame_refs.len);

        const frame: []const u8 = &bp.frames[
            read_frame.cached.frame_refs[0].f_idx
        ];

        var frame2: [FRAME_SIZE]u8 = undefined;
        const bytes_read = try file.preadAll(&frame2, offset);
        try std.testing.expectEqualSlices(u8, frame2[0..bytes_read], frame[0..bytes_read]);
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
                FrameRef,
                read.cached.frame_refs,
                read2.cached.frame_refs,
            );
        }

        errdefer std.debug.print("failed with read: {}\n", .{read});

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
