const std = @import("std");

/// Fixed capacity pool whose header and item storage are laid out in one contiguous buffer.
/// Intended for shared memory because every stored reference is an ItemId index. No process
/// address is stored in the pool. Pointers returned by create() are computed from the current
/// process mapping and are only valid in that process.
///
/// NOTE: this is not an atomic pool. The same thread is expected to create and destroy all nodes.
///
/// Free slots store item ids in the same memory as items, so Item must be large and aligned
/// enough to hold an optional item id.
///
/// create() allocates one Item and returns *Item. createId() returns the slot index, which can
/// be stored in shared memory and converted to a pointer in each process.
///
/// ```zig
/// const IntPool = SharedPool(u64, 4);
///
/// // This storage would typically be a shared memory mapping. Stack storage used here
/// // for simplicity.
/// var storage: [IntPool.size()]u8 align(@alignOf(IntPool)) = undefined;
/// const pool: *IntPool = @ptrCast(&storage);
/// pool.init();
///
/// const item_id = try pool.createId();
/// item_id.ptr(pool).* = 42;
///
/// pool.destroyId(item_id);
/// ```
///
pub fn SharedPool(Item: type, cap: usize) type {
    // bits required for the power-of-two integer needed to store capacity+1 items
    const int_bits = @max(
        8,
        try std.math.ceilPowerOfTwo(
            usize,
            std.math.log2_int_ceil(usize, cap + 2),
        ),
    );
    const IdInt: type = @Type(.{ .int = .{ .bits = int_bits, .signedness = .unsigned } });

    return extern struct {
        free_list: ItemId.Optional,

        // This is effectively a [capacity]Node, however Zig doesn't let us make structs over 4GiB,
        // which some pools may be.
        // We're not using a pointer as we want the header field(s) to be in the same buffer as the
        // pool items.
        // This should normally only be accessed via .buf().
        _buf: void align(@alignOf(Node)),

        const PoolSelf = @This();
        pub const capacity = cap;

        // We know when next_free is active when we walk the free_list
        const Node = extern union {
            next_free: ItemId.Optional align(@alignOf(Item)),
            item: Item,
        };

        comptime {
            if (@sizeOf(Node) != @sizeOf(Item)) unreachable;
            if (@alignOf(Node) != @alignOf(Item)) unreachable;
        }

        pub const ItemId = enum(IdInt) {
            _,

            comptime {
                std.debug.assert(capacity < std.math.maxInt(IdInt));
                _ = PoolSelf;
            }

            pub fn index(self: ItemId) IdInt {
                return @intFromEnum(self);
            }

            pub fn fromInt(int: IdInt) ItemId {
                return @enumFromInt(int);
            }

            pub fn ptr(self: ItemId, pool: *PoolSelf) *Item {
                return pool.indexToPtr(self);
            }

            pub fn constPtr(self: ItemId, pool: *const PoolSelf) *const Item {
                return pool.indexToConstPtr(self);
            }

            pub const Optional = enum(IdInt) {
                null = std.math.maxInt(IdInt),
                _,

                pub fn init(non_optional: ItemId) Optional {
                    return @enumFromInt(@intFromEnum(non_optional));
                }

                pub fn opt(self: Optional) ?ItemId {
                    if (self == .null) return null;
                    return @enumFromInt(@intFromEnum(self));
                }

                pub fn ptr(self: Optional, pool: *PoolSelf) ?*Item {
                    if (self == .null) return null;
                    const id: ItemId = @enumFromInt(@intFromEnum(self));
                    return id.ptr(pool);
                }

                pub fn constPtr(self: Optional, pool: *const PoolSelf) ?*const Item {
                    if (self == .null) return null;
                    const id: ItemId = @enumFromInt(@intFromEnum(self));
                    return id.constPtr(pool);
                }
            };
        };

        pub fn size() usize {
            return @offsetOf(PoolSelf, "_buf") + capacity * @sizeOf(Item);
        }

        /// Only use this if you're certain that it's the only way
        pub fn buf(pool: *PoolSelf) []Node {
            const base: [*]Node = @ptrCast(&pool._buf);
            return base[0..capacity];
        }

        pub fn constBuf(pool: *const PoolSelf) []const Node {
            const base: [*]const Node = @ptrCast(&pool._buf);
            return base[0..capacity];
        }

        pub fn init(pool: *PoolSelf) void {
            const nodes: []Node = pool.buf();

            // place all nodes in the free list
            // (0) -> (1) -> ... ->(buf.len - 1) -> (null)
            for (nodes[0 .. nodes.len - 1], 0..) |*node, i| {
                node.* = .{ .next_free = @enumFromInt(i + 1) };
            }
            nodes[nodes.len - 1] = .{ .next_free = .null };

            pool.free_list = @enumFromInt(0);
        }

        // take head off free_list
        pub fn create(self: *PoolSelf) !*Item {
            const head = self.free_list.opt() orelse return error.OutOfSpace;

            const new_node: *Node = &self.buf()[head.index()];
            self.free_list = new_node.next_free;
            return @ptrCast(new_node);
        }

        pub fn createId(self: *PoolSelf) !ItemId {
            const item = try self.create();
            return self.ptrToIndex(item);
        }

        // place item as head of free_list
        pub fn destroy(self: *PoolSelf, item: *Item) void {
            item.* = undefined;
            const node: *Node = @ptrCast(item);
            const id = self.ptrToIndex(item);

            node.* = .{ .next_free = self.free_list };
            self.free_list = .init(id);
        }

        pub fn destroyId(self: *PoolSelf, item_id: ItemId) void {
            const item: *Item = @ptrCast(&self.buf()[item_id.index()]);
            self.destroy(item);
        }

        pub fn indexToPtr(self: *PoolSelf, item_id: ItemId) *Item {
            return @ptrCast(&self.buf()[item_id.index()]);
        }

        pub fn indexToConstPtr(self: *const PoolSelf, item_id: ItemId) *const Item {
            return @ptrCast(&self.constBuf()[item_id.index()]);
        }

        pub fn ptrToIndex(self: *PoolSelf, item: *Item) ItemId {
            const node: [*]const Node = @ptrCast(item);
            const base: [*]const Node = self.buf().ptr;

            {
                // range check
                const item_addr: usize = @intFromPtr(item);
                std.debug.assert(item_addr >= @intFromPtr(self.buf().ptr));
                std.debug.assert(item_addr < @intFromPtr(self.buf().ptr + capacity));
            }

            return @enumFromInt(node - base);
        }
    };
}

/// Runtime sized in process pool backed by a caller provided Item buffer.
/// Unlike SharedPool, this struct stores a pointer to the backing buffer. That pointer is valid
/// only in the process that created the pool, so this type should not be embedded in shared memory.
///
/// NOTE: this pool is not atomic, but is designed such that it could be made atomic easily.
///
/// Free slots store item ids in the same memory as items, so Item must be large and aligned
/// enough to hold an optional item id.
///
/// create() allocates one Item and returns *Item. createId() returns the slot index, which can be
/// converted back to a pointer while using the same Pool value.
///
/// ```zig
/// const U64Pool = Pool(u64, u16);
///
/// var items: [4]u64 = undefined;
/// var pool = U64Pool.init(items[0..]);
///
/// const item = try pool.create();
/// item.* = 42;
///
/// const item_id = pool.ptrToIndex(item);
/// item_id.ptr(&pool).* = 43;
///
/// pool.destroyId(item_id);
/// ```
///
pub fn Pool(Item: type, IdInt: type) type {
    switch (IdInt) {
        u8, u16, u32, u64 => {},
        else => @compileError("Unexpected integer type"),
    }

    return extern struct {
        free_list: ItemId.Optional,
        len: IdInt,
        buf: [*]Node,

        const PoolSelf = @This();

        // We know when next_free is active when we walk the free_list
        const Node = extern union { next_free: ItemId.Optional, item: Item };

        comptime {
            if (@sizeOf(Item) < @sizeOf(ItemId)) unreachable;
            if (@alignOf(Item) < @alignOf(ItemId)) unreachable;
            if (@sizeOf(Node) != @sizeOf(Item)) unreachable;
            if (@alignOf(Node) != @alignOf(Item)) unreachable;
        }

        pub const ItemId = enum(IdInt) {
            _,

            comptime {
                _ = PoolSelf;
            }

            pub fn index(self: ItemId) IdInt {
                return @intFromEnum(self);
            }

            pub fn fromInt(int: IdInt) ItemId {
                return @enumFromInt(int);
            }

            pub fn ptr(self: ItemId, pool: *PoolSelf) *Item {
                return pool.indexToPtr(self);
            }

            pub fn constPtr(self: ItemId, pool: *const PoolSelf) *const Item {
                return pool.indexToPtr(self);
            }

            pub const Optional = enum(IdInt) {
                null = std.math.maxInt(IdInt),
                _,

                pub fn init(non_optional: ItemId) Optional {
                    return @enumFromInt(@intFromEnum(non_optional));
                }

                pub fn opt(self: Optional) ?ItemId {
                    if (self == .null) return null;
                    return @enumFromInt(@intFromEnum(self));
                }

                pub fn ptr(self: Optional, pool: *PoolSelf) ?*Item {
                    if (self == .null) return null;
                    const id: ItemId = @enumFromInt(@intFromEnum(self));
                    return id.ptr(pool);
                }

                pub fn constPtr(self: Optional, pool: *const PoolSelf) ?*const Item {
                    if (self == .null) return null;
                    const id: ItemId = @enumFromInt(@intFromEnum(self));
                    return id.constPtr(pool);
                }
            };
        };

        pub fn init(item_buf: []Item) PoolSelf {
            std.debug.assert(item_buf.len < std.math.maxInt(IdInt));

            const buf: []Node = @ptrCast(item_buf);

            // place all nodes in the free list
            // (0) -> (1) -> ... ->(buf.len - 1) -> (null)
            for (buf[0 .. buf.len - 1], 0..) |*node, i| {
                node.* = .{ .next_free = @enumFromInt(i + 1) };
            }
            buf[buf.len - 1] = .{ .next_free = .null };

            return .{
                .free_list = @enumFromInt(0),
                .len = @intCast(buf.len),
                .buf = buf.ptr,
            };
        }

        /// Rebuilds the free list in place, returning every item to the pool
        /// without freeing or reallocating the backing buffer. The buffer
        /// contents are clobbered.
        pub fn reset(self: *PoolSelf) void {
            const item_buf: []Item = @ptrCast(self.buf[0..self.len]);
            self.* = init(item_buf);
        }

        // take head off free_list
        pub fn create(self: *PoolSelf) !*Item {
            const head = self.free_list.opt() orelse return error.OutOfSpace;

            const new_node: *Node = &self.buf[head.index()];
            self.free_list = new_node.next_free;

            return @ptrCast(new_node);
        }

        pub fn createId(self: *PoolSelf) !ItemId {
            const item = try self.create();
            return self.ptrToIndex(item);
        }

        // place item as head of free_list
        pub fn destroy(self: *PoolSelf, item: *Item) void {
            item.* = undefined;

            const node: *Node = @ptrCast(item);
            node.* = .{ .next_free = self.free_list };
            self.free_list = .init(self.ptrToIndex(item));
        }

        pub fn destroyId(self: *PoolSelf, item_id: ItemId) void {
            const item: *Item = @ptrCast(&self.buf[item_id.index()]);
            self.destroy(item);
        }

        pub fn indexToPtr(self: *const PoolSelf, item_id: ItemId) *Item {
            return @ptrCast(&self.buf[item_id.index()]);
        }

        pub fn ptrToIndex(self: *const PoolSelf, item: *Item) ItemId {
            const node: [*]const Node = @ptrCast(item);
            const base: [*]const Node = self.buf;

            {
                // range check
                const item_addr: usize = @intFromPtr(item);
                std.debug.assert(item_addr >= @intFromPtr(self.buf));
                std.debug.assert(item_addr < @intFromPtr(self.buf + self.len));
            }

            return @enumFromInt(node - base);
        }
    };
}

test "pool create + destroy" {
    const capacity = 2048;
    const allocator = std.testing.allocator;

    const P = Pool(i64, u16);

    const pool_buf = try allocator.alloc(i64, capacity);
    defer allocator.free(pool_buf);

    var pool: P = .init(pool_buf);

    for (0..capacity + 1) |i| {
        if (i == capacity) {
            try std.testing.expectError(error.OutOfSpace, pool.create());
            continue;
        }

        const x: *i64 = try pool.create();
        x.* = -(@as(i64, @intCast(i)) * 2);
    }

    for (0..capacity) |i| {
        const node = &pool.buf[i];
        const x: *i64 = @ptrCast(node);
        std.debug.assert(x.* == -(@as(i64, @intCast(i)) * 2));
        pool.destroy(@ptrCast(&pool.buf[i]));
    }

    for (0..capacity + 1) |i| {
        if (i == capacity) {
            try std.testing.expectError(error.OutOfSpace, pool.create());
            continue;
        }

        const x: *i64 = try pool.create();
        x.* = -(@as(i64, @intCast(i)) * 2);
    }
}

test "pool create + destroy out of order" {
    const allocator = std.testing.allocator;

    const P = Pool(i64, u64);

    const pool_buf = try allocator.alloc(i64, 3);
    defer allocator.free(pool_buf);

    var pool: P = .init(pool_buf);

    const a = try pool.create();
    const b = try pool.create();
    const c = try pool.create();

    a.* = 0;
    b.* = 10;
    c.* = 30;

    pool.destroy(b);
    pool.destroy(a);

    const x = try pool.create();
    const y = try pool.create();

    try std.testing.expectEqual(a, x);
    try std.testing.expectEqual(b, y);
}
