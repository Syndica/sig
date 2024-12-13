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
    const offset: FrameOffset = FRAME_SIZE;
    _ = offset;
}

const FileIdFileOffset = struct {
    const INVALID: FileIdFileOffset = .{
        .file_id = FileId.fromInt(std.math.maxInt(FileId.Int)),
        // disambiguate from 0xAAAA / will trigger asserts as it's not even.
        .file_offset = 0xBAAD,
    };

    file_id: FileId,

    /// offset in the file from which the frame begin
    /// always a multiple of FRAME_SIZE
    file_offset: FileOffset,
    comptime {
        if (@sizeOf(FileIdFileOffset) != @sizeOf(u64)) unreachable;
    }
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

    /// indexes of all free frames
    /// free frames have a refcount of 0 *and* have been evicted
    free_list: AtomicStack(FrameIndex),

    /// uniquely identifies a frame
    /// for finding your wanted index
    // TODO: thread safety?
    frame_map: FrameMap,

    frames: []Frame,
    frames_metadata: FramesMetadata,

    /// used for eviction to free less popular (rc=0) frames first
    eviction_lfu: HierarchicalFIFO,

    /// NOTE: we might want this to be a threadlocal for best performance? I don't think this field is threadsafe
    io_uring: if (builtin.os.tag == .linux) std.os.linux.IoUring else void,

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

        var io_uring = if (builtin.os.tag == .linux) blk: {
            // NOTE: this is pretty much a guess, maybe worth tweaking?
            // think this is a bit on the high end, libxev uses 256
            const io_uring_entries = 4096;

            break :blk try std.os.linux.IoUring.init(
                io_uring_entries,
                0,
            );
        } else {};
        errdefer if (builtin.os.tag == .linux) io_uring.deinit();

        var frame_map: FrameMap = .{};
        try frame_map.ensureTotalCapacity(init_allocator, num_frames);
        errdefer frame_map.deinit(init_allocator);

        return .{
            .frames = frames,
            .frames_metadata = frames_metadata,
            .free_list = free_list,
            .frame_map = frame_map,
            .eviction_lfu = try HierarchicalFIFO.init(init_allocator, num_frames / 10, num_frames),
            .io_uring = io_uring,
        };
    }

    pub fn deinit(self: *BufferPool, init_allocator: std.mem.Allocator) void {
        init_allocator.free(self.frames);
        self.frames_metadata.deinit(init_allocator);
        if (builtin.os.tag == .linux) {
            self.io_uring.deinit();
        }
        self.free_list.deinit(init_allocator);
        self.eviction_lfu.deinit(init_allocator);
        self.frame_map.deinit(init_allocator);
    }

    pub fn indicesRequired(
        /// inclusive
        range_start: FileOffset,
        /// exclusive
        range_end: FileOffset,
    ) u32 {
        if (range_start > range_end) unreachable;
        if (range_start == range_end) return 0;

        const starting_frame = range_start / FRAME_SIZE;
        const ending_frame = (range_end - 1) / FRAME_SIZE;

        return ending_frame - starting_frame + 1;
    }

    /// allocates the required amount of indices, sets them all to
    /// INVALID_FRAME, overwriting with a valid frame where one is found.
    /// INVALID_FRAME indicates that there is no frame in the BufferPool for the
    /// given file_id and range.
    fn makeindices(
        self: *BufferPool,
        file_id: FileId,
        allocator: std.mem.Allocator,
        /// inclusive
        range_start: FileOffset,
        /// exclusive
        range_end: FileOffset,
    ) ![]FrameIndex {
        const n_indices = indicesRequired(range_start, range_end);

        if (n_indices > self.frames.len) return error.InvalidArgument;

        const indices = try allocator.alloc(FrameIndex, n_indices);
        for (indices) |*idx| idx.* = INVALID_FRAME;

        // lookup frame mappings
        for (0.., indices) |i, *idx| {
            const file_offset: FileOffset = @intCast(
                (i * FRAME_SIZE) + (range_start - range_start % FRAME_SIZE),
            );

            const key: FileIdFileOffset = .{
                .file_id = file_id,
                .file_offset = file_offset,
            };

            const maybe_frame_idx = self.frame_map.get(key);

            if (maybe_frame_idx) |frame_idx| idx.* = frame_idx;
        }

        return indices;
    }

    /// On a "new" frame (i.e. freshly read into), set all of its associated metadata
    /// TODO: atomics
    fn populateNew(
        self: *BufferPool,
        idx: FrameIndex,
        file_id: FileId,
        file_offset: FileOffset,
        size: FrameOffset,
    ) void {
        self.populateNewNoSize(idx, file_id, file_offset);
        self.frames_metadata.size[idx] = size;
    }

    /// Useful if you don't currently know the size.
    /// make sure to set the size later (!)
    /// TODO: atomics
    fn populateNewNoSize(
        self: *BufferPool,
        idx: FrameIndex,
        file_id: FileId,
        file_offset: FileOffset,
    ) void {
        self.frames_metadata.freq[idx] = 0;
        self.frames_metadata.in_queue[idx] = .none;

        if (self.frames_metadata.rc[idx].isAlive()) {
            unreachable; // not-found indices should always have 0 active readers
        }
        self.frames_metadata.rc[idx].reset();

        self.frames_metadata.key[idx] = .{
            .file_id = file_id,
            .file_offset = file_offset,
        };

        const key: FileIdFileOffset = .{
            .file_id = file_id,
            .file_offset = file_offset,
        };

        self.frame_map.putAssumeCapacityNoClobber(key, idx);
    }

    /// Frames with an associated rc of 0 are up for eviction, and which frames
    /// are evicted first is up to the LFU.
    fn evictUnusedFrame(self: *BufferPool) void {
        const evicted = self.eviction_lfu.evict(self.frames_metadata);
        self.free_list.appendAssumeCapacity(evicted);
        const did_remove = self.frame_map.remove(self.frames_metadata.key[evicted]);
        if (!did_remove) {
            std.debug.panic(
                "evicted a frame that did not exist in frame_map, frame: {}\n",
                .{evicted},
            );
        }
        @memset(&self.frames[evicted], 0xAA);
        self.frames_metadata.resetFrame(evicted);
    }

    pub fn read(
        self: *BufferPool,
        /// used for temp allocations, and the returned .indices slice
        allocator: std.mem.Allocator,
        file: std.fs.File,
        file_id: FileId,
        /// inclusive
        range_start: FileOffset,
        /// exclusive
        range_end: FileOffset,
    ) !CachedRead {
        return switch (builtin.os.tag) {
            .linux => self.readIoUringSubmitAndWait(
                allocator,
                file,
                file_id,
                range_start,
                range_end,
            ),
            else => self.readBlocking(
                allocator,
                file,
                file_id,
                range_start,
                range_end,
            ),
        };
    }

    fn readIoUringSubmitAndWait(
        self: *BufferPool,
        /// used for temp allocations, and the returned .indices slice
        allocator: std.mem.Allocator,
        file: std.fs.File,
        file_id: FileId,
        /// inclusive
        range_start: FileOffset,
        /// exclusive
        range_end: FileOffset,
    ) !CachedRead {
        if (builtin.os.tag != .linux)
            @compileError("io_uring only available on linux - unsupported target");

        const indices = try self.makeindices(file_id, allocator, range_start, range_end);
        errdefer allocator.free(indices);

        var n_invalid: u32 = 0;
        for (indices) |idx| {
            if (idx == INVALID_FRAME) {
                n_invalid += 1;
            } else {
                // we don't want to evict these in the next loop

                self.eviction_lfu.insert(self.frames_metadata, idx);
                if (!self.frames_metadata.rc[idx].acquire()) {
                    // frame has no handles, but memory is still valid
                    self.frames_metadata.rc[idx].reset(); // dumb
                }
            }
        }

        var sent_reads: u32 = 0;
        for (0.., indices) |i, *idx| {
            if (idx.* != INVALID_FRAME) continue;
            // INVALID_FRAME => not found, read fresh and populate

            const file_offset: FileOffset = @intCast((i * FRAME_SIZE) +
                (range_start - range_start % FRAME_SIZE));
            if (file_offset % FRAME_SIZE != 0) unreachable;

            idx.* = blk: while (true) {
                if (self.free_list.popOrNull()) |free_idx| {
                    break :blk free_idx;
                } else {
                    self.evictUnusedFrame();
                }
            };

            _ = try self.io_uring.read(
                idx.*,
                file.handle,
                .{ .buffer = &self.frames[idx.*] },
                file_offset,
            );
            sent_reads += 1;
            self.populateNewNoSize(idx.*, file_id, file_offset);
            self.eviction_lfu.insert(self.frames_metadata, idx.*);
        }
        if (sent_reads != n_invalid) unreachable;

        if (sent_reads > 0) {
            const n_submitted = try self.io_uring.submit_and_wait(sent_reads);
            if (n_submitted != sent_reads) unreachable; // did something else submit an event?

            // would be nice to get rid of this alloc
            const cqes = try allocator.alloc(std.os.linux.io_uring_cqe, n_submitted);
            defer allocator.free(cqes);

            // check our completions in order to set the frame's size;
            // we need to wait for completion to get the bytes read
            const cqe_count = try self.io_uring.copy_cqes(cqes, n_submitted);
            if (cqe_count != n_submitted) unreachable; // why did we not receive them all?
            for (0.., cqes) |i, cqe| {
                if (cqe.err() != .SUCCESS) {
                    std.debug.panic("cqe err: {}, i: {}", .{ cqe, i });
                }
                const idx = cqe.user_data;
                const bytes_read: FrameOffset = @intCast(cqe.res);
                if (bytes_read > FRAME_SIZE) unreachable;

                // TODO: atomics
                self.frames_metadata.size[idx] = bytes_read;
            }
        }

        return CachedRead{
            .bp = self,
            .indices = indices,
            .start_offset = @intCast(range_start % FRAME_SIZE),
            .end_offset = @intCast(((range_end - 1) % FRAME_SIZE) + 1),
        };
    }

    fn readBlocking(
        self: *BufferPool,
        /// used for temp allocations, and the returned .indices slice
        allocator: std.mem.Allocator,
        file: std.fs.File,
        file_id: FileId,
        /// inclusive
        range_start: FileOffset,
        /// exclusive
        range_end: FileOffset,
    ) !CachedRead {
        const indices = try self.makeindices(file_id, allocator, range_start, range_end);
        errdefer allocator.free(indices);

        var n_invalid: u32 = 0;
        for (indices) |idx| {
            if (idx == INVALID_FRAME) {
                n_invalid += 1;
            } else {
                // we don't want to evict these in the next loop
                self.eviction_lfu.insert(self.frames_metadata, idx);
                if (!self.frames_metadata.rc[idx].acquire()) {
                    // frame has no handles, but memory is still valid
                    self.frames_metadata.rc[idx].reset(); // dumb
                }
            }
        }

        // fill in invalid frames with file data, replacing invalid frames with
        // fresh ones.
        for (0.., indices) |i, *idx| {
            if (idx.* != INVALID_FRAME) continue;
            // INVALID_FRAME => not found, read fresh and populate

            const file_offset: FileOffset = @intCast((i * FRAME_SIZE) +
                (range_start - range_start % FRAME_SIZE));
            if (file_offset % FRAME_SIZE != 0) unreachable;

            if (idx.* != INVALID_FRAME) continue;
            idx.* = blk: while (true) {
                if (self.free_list.popOrNull()) |free_idx| {
                    break :blk free_idx;
                } else {
                    self.evictUnusedFrame();
                }
            };

            const bytes_read = try file.pread(&self.frames[idx.*], file_offset);
            if (bytes_read > FRAME_SIZE) unreachable;
            self.populateNew(idx.*, file_id, file_offset, @intCast(bytes_read));
        }

        return CachedRead{
            .bp = self,
            .indices = indices,
            .start_offset = @intCast(range_start % FRAME_SIZE),
            .end_offset = @intCast(((range_end - 1) % FRAME_SIZE) + 1),
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
    /// Wonder if it would be faster to pack this.
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
    fn resetFrame(self: FramesMetadata, index: FrameIndex) void {
        if (self.rc[index].isAlive()) unreachable;
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

    pub fn init(allocator: std.mem.Allocator, small_size: u32, num_frames: u32) !HierarchicalFIFO {
        if (small_size > num_frames) unreachable;
        return .{
            .small = Fifo.init(try allocator.alloc(FrameIndex, small_size)),
            .main = Fifo.init(try allocator.alloc(FrameIndex, num_frames)),
            .ghost = Fifo.init(try allocator.alloc(FrameIndex, num_frames)),
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

    pub fn insert(self: *HierarchicalFIFO, metadata: Metadata, key: Key) void {
        if (key == INVALID_FRAME) unreachable;

        switch (metadata.in_queue[key]) {
            .main, .small => {
                metadata.freq[key] +|= 1;
            },
            .ghost => {
                if (metadata.freq[key] != 0) unreachable;
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
                if (maybe_evicted == null) maybe_evicted = self.evictMain(metadata);
                if (maybe_evicted == null) maybe_evicted = self.evictSmall(metadata);
            } else {
                if (maybe_evicted == null) maybe_evicted = self.evictSmall(metadata);
                if (maybe_evicted == null) maybe_evicted = self.evictMain(metadata);
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

    fn evictMain(self: *HierarchicalFIFO, metadata: Metadata) ?Key {
        const evicted: ?Key = while (self.main.readItem()) |main_key| {
            if (metadata.in_queue[main_key] != .main) unreachable;

            if (metadata.freq[main_key] == 0) {
                break main_key;
            } else {
                metadata.freq[main_key] -|= 1;
                self.main.writeItemAssumeCapacity(main_key);
            }
        } else null;

        return evicted;
    }

    fn evictSmall(self: *HierarchicalFIFO, metadata: Metadata) ?Key {
        const evicted: ?Key = while (self.small.readItem()) |small_key| {
            if (metadata.in_queue[small_key] != .small) unreachable;

            if (metadata.freq[small_key] == 0) {
                break small_key;
            } else {
                metadata.freq[small_key] -|= 1;
                self.small.writeItemAssumeCapacity(small_key);
            }
        } else null;

        return evicted;
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
            if (prev_len >= self.cap) unreachable;
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
            BufferPool.indicesRequired(case.start, case.end),
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

    try std.testing.expectEqual(2, read.indices.len);
    for (read.indices) |idx| try std.testing.expect(idx != INVALID_FRAME);

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
    try std.testing.expectEqual(error.InvalidArgument, read_whole);

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

        try std.testing.expectEqual(1, read_frame.indices.len);

        const frame: []const u8 = bp.frames[
            read_frame.indices[0]
        ][0..bp.frames_metadata.size[
            read_frame.indices[0]
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
        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        defer _ = gpa.deinit();

        const range_start = prng.random().intRangeAtMost(u32, 0, file_size);
        const range_end = prng.random().intRangeAtMost(
            u32,
            range_start,
            @min(file_size, range_start + num_frames * FRAME_SIZE),
        );

        if (BufferPool.indicesRequired(range_start, range_end) > num_frames) {
            continue;
        }

        var read = try bp.read(gpa.allocator(), file, file_id, range_start, range_end);
        defer read.deinit(gpa.allocator());

        if (builtin.os.tag == .linux) {
            var read2 = try bp.readBlocking(
                gpa.allocator(),
                file,
                file_id,
                range_start,
                range_end,
            );
            defer read2.deinit(gpa.allocator());

            try std.testing.expect(read.start_offset == read2.start_offset);
            try std.testing.expect(read.end_offset == read2.end_offset);
            try std.testing.expectEqualSlices(u32, read.indices, read2.indices);
        }

        var total_bytes_read: u32 = 0;
        for (read.indices) |idx| total_bytes_read += bp.frames_metadata.size[idx];
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

        const read_data_expected = try allocator.alloc(u8, range_end - range_start);
        defer allocator.free(read_data_expected);
        const preaded_bytes = try file.preadAll(read_data_expected, range_start);

        try std.testing.expectEqualSlices(u8, read_data_expected, read_data_bp_iter);
        try std.testing.expectEqual(preaded_bytes, read_data_bp_iter.len);

        try std.testing.expectEqualSlices(u8, read_data_expected, read_data_bp_reader);
        try std.testing.expectEqual(preaded_bytes, read_data_bp_reader.len);
    }
}

/// slice-like datatype
/// view over one or more buffers owned by the BufferPool
pub const CachedRead = struct {
    bp: *BufferPool,
    indices: []const FrameIndex,
    /// inclusive, the offset into the first frame
    start_offset: FrameOffset,
    /// exclusive, the offset into the last frame
    end_offset: FrameOffset,

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

    pub fn readByte(self: CachedRead, idx: usize) u8 {
        if (self.indices.len == 0) unreachable;
        if (idx > self.len()) unreachable;
        const offset = idx + self.start_offset;
        if (offset < self.start_offset) unreachable;

        return self.bp.frames[self.indices[offset / FRAME_SIZE]][offset % FRAME_SIZE];
    }

    pub fn iterator(self: *const CachedRead) Iterator {
        return .{ .cached_read = self };
    }

    pub fn len(self: CachedRead) u32 {
        if (self.indices.len == 0) return 0;
        return (@as(u32, @intCast(self.indices.len)) - 1) *
            FRAME_SIZE + self.end_offset - self.start_offset;
    }

    pub fn deinit(self: CachedRead, allocator: std.mem.Allocator) void {
        for (self.indices) |frame_index| {
            if (frame_index == INVALID_FRAME) unreachable;

            if (self.bp.frames_metadata.rc[frame_index].release()) {
                // notably, the frame remains in memory, and its hashmap entry
                // remains valid.
            }
        }
        allocator.free(self.indices);
    }
};
