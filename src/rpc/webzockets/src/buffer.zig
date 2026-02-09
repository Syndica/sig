//! Shared buffer pool for WebSocket connections.
//!
//! Provides a growable pool of fixed-size buffers for use as read buffers
//! when messages exceed the per-connection embedded buffer. Pre-allocate
//! buffers with preheat() to avoid allocations in the common case.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// Growable buffer pool with runtime-configurable buffer size.
/// Uses an intrusive free list (like std.heap.MemoryPool) for efficient reuse.
/// Thread-safe for shared use across connections.
///
/// Pool grows beyond preheat size as needed. Use preheat to pre-allocate
/// buffers for expected concurrent usage, avoiding allocations in the
/// common case.
pub const BufferPool = struct {
    /// Size of each buffer in this pool.
    buffer_size: usize,

    /// Arena for growing allocations (never shrinks until deinit).
    arena: std.heap.ArenaAllocator,

    /// Head of the intrusive free list (null if no free buffers).
    free_list: ?*FreeNode,

    /// Mutex for thread-safe access.
    mutex: std.Thread.Mutex,

    /// Intrusive free list node stored at the start of free buffers.
    const FreeNode = struct {
        next: ?*FreeNode,
    };

    /// Minimum buffer size to hold the free list node pointer.
    pub const min_buffer_size = @sizeOf(FreeNode);

    /// Initialize pool with a given buffer size.
    /// Buffer size must be at least min_buffer_size (size of pointer).
    pub fn init(allocator: Allocator, buffer_size: usize) BufferPool {
        std.debug.assert(buffer_size >= min_buffer_size);
        return .{
            .buffer_size = buffer_size,
            .arena = std.heap.ArenaAllocator.init(allocator),
            .free_list = null,
            .mutex = .{},
        };
    }

    /// Release all pool memory.
    pub fn deinit(self: *BufferPool) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.arena.deinit();
        self.free_list = null;
    }

    /// Preheat the pool by pre-allocating buffers.
    /// This allows up to `count` active allocations before the pool needs to grow.
    /// If called after the pool has already been used, it will add `count` new
    /// buffers to the free list.
    pub fn preheat(self: *BufferPool, count: usize) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (0..count) |_| {
            const buf = try self.arena.allocator().alloc(u8, self.buffer_size);
            const node: *FreeNode = @ptrCast(@alignCast(buf.ptr));
            node.* = .{ .next = self.free_list };
            self.free_list = node;
        }
    }

    /// Acquire a buffer from the pool.
    /// Returns from free list if available, otherwise allocates from arena.
    /// Returns null only on allocation failure.
    pub fn acquire(self: *BufferPool) ?[]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.free_list) |node| {
            // Pop from free list
            self.free_list = node.next;
            const ptr: [*]u8 = @ptrCast(node);
            return ptr[0..self.buffer_size];
        }

        // Grow the pool
        return self.arena.allocator().alloc(u8, self.buffer_size) catch null;
    }

    /// Release a buffer back to the pool.
    /// The buffer is added to the free list for reuse.
    pub fn release(self: *BufferPool, buf: []u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Push onto free list (store next pointer at start of buffer)
        const node: *FreeNode = @ptrCast(@alignCast(buf.ptr));
        node.* = .{ .next = self.free_list };
        self.free_list = node;
    }

    /// The size of buffers in this pool.
    pub fn bufferSize(self: *const BufferPool) usize {
        return self.buffer_size;
    }
};

const testing = std.testing;

test "BufferPool: acquire and release" {
    var pool = BufferPool.init(testing.allocator, 64);
    defer pool.deinit();
    try pool.preheat(2);

    const buf1 = pool.acquire();
    try testing.expect(buf1 != null);
    try testing.expectEqual(@as(usize, 64), buf1.?.len);

    const buf2 = pool.acquire();
    try testing.expect(buf2 != null);
    try testing.expect(buf1.?.ptr != buf2.?.ptr);

    pool.release(buf1.?);
    pool.release(buf2.?);
}

test "BufferPool: grows beyond preheat size" {
    var pool = BufferPool.init(testing.allocator, 64);
    defer pool.deinit();
    try pool.preheat(1);

    const buf1 = pool.acquire();
    try testing.expect(buf1 != null);

    // Pool grows beyond preheat size
    const buf2 = pool.acquire();
    try testing.expect(buf2 != null);
    try testing.expect(buf1.?.ptr != buf2.?.ptr);

    pool.release(buf1.?);
    pool.release(buf2.?);
}

test "BufferPool: reuses released buffers" {
    var pool = BufferPool.init(testing.allocator, 64);
    defer pool.deinit();
    try pool.preheat(1);

    const buf1 = pool.acquire();
    try testing.expect(buf1 != null);
    const ptr1 = buf1.?.ptr;

    pool.release(buf1.?);

    // Should get the same buffer back
    const buf2 = pool.acquire();
    try testing.expect(buf2 != null);
    try testing.expectEqual(ptr1, buf2.?.ptr);

    pool.release(buf2.?);
}

test "BufferPool: bufferSize returns configured size" {
    var pool = BufferPool.init(testing.allocator, 128);
    defer pool.deinit();

    try testing.expectEqual(@as(usize, 128), pool.bufferSize());
}
