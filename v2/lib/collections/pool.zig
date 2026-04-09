const std = @import("std");

/// A mem pool of []Item
/// Asserts Item to have an alignment and size >= IdInt
/// NOTE: this pool is not atomic, but is designed such that it could be made atomic easily
pub fn Pool(Item: type, IdInt: type) type {
    switch (IdInt) {
        u8, u16, u32, u64 => {},
        else => @compileError("Unexpected integer type"),
    }

    return extern struct {
        free_list: ItemId,
        len: IdInt,
        buf: [*]Node,

        const PoolSelf = @This();

        // We know when next_free is active when we walk the free_list
        const Node = extern union { next_free: ItemId, item: Item };

        comptime {
            if (@sizeOf(Item) < @sizeOf(ItemId)) unreachable;
            if (@alignOf(Item) < @alignOf(ItemId)) unreachable;
            if (@sizeOf(Node) != @sizeOf(Item)) unreachable;
            if (@alignOf(Node) != @alignOf(Item)) unreachable;
        }

        pub const ItemId = enum(IdInt) {
            null = std.math.maxInt(IdInt),
            _,

            const IdSelf = @This();

            comptime {
                _ = PoolSelf;
            }

            pub fn index(self: IdSelf) ?IdInt {
                if (self == .null) return null;
                return @intFromEnum(self);
            }

            pub fn fromInt(int: IdInt) IdSelf {
                return @enumFromInt(int);
            }
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

        // take head off free_list
        pub fn create(self: *PoolSelf) !*Item {
            if (self.free_list == .null) return error.OutOfSpace;

            const new_node: *Node = &self.buf[self.free_list.index().?];
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
            self.free_list = self.ptrToIndex(item);
        }

        pub fn destroyId(self: *PoolSelf, item_id: ItemId) void {
            std.debug.assert(item_id != .null);
            const item: *Item = @ptrCast(&self.buf[item_id.index().?]);
            self.destroy(item);
        }

        pub fn indexToPtr(self: *const PoolSelf, item_id: ItemId) *Item {
            std.debug.assert(item_id != .null);
            return @ptrCast(&self.buf[item_id.index().?]);
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
