const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;

/// Thread safe Window that stores a single copy of data that is shared with
/// readers as a pointer to the underlying data inside the Window.
///
/// - this struct owns the data and is responsible for freeing it
/// - the lifetime of returned pointer exceeds every read operation of that pointer,
///   even if another thread evicts it from the Window, as long as `release` is used properly.
pub fn SharedPointerWindow(
    T: type,
    deinitItem_: anytype,
    DeinitContext: type,
) type {
    const Window = sig.utils.collections.Window;
    const Rc = sig.sync.Rc;
    const deinitItem = normalizeDeinitFunction(T, DeinitContext, deinitItem_);

    return struct {
        allocator: Allocator,
        window: Window(Rc(T)),
        center: std.atomic.Value(usize),
        lock: std.Thread.RwLock = .{},
        deinit_context: DeinitContext,
        discard_buf: std.atomic.Value(?[*]?Rc(T)),

        const Self = @This();

        pub fn init(
            allocator: Allocator,
            len: usize,
            start: usize,
            deinit_context: DeinitContext,
        ) !Self {
            return .{
                .allocator = allocator,
                .window = try Window(Rc(T)).init(allocator, len, start),
                .deinit_context = deinit_context,
                .center = std.atomic.Value(usize).init(start),
                .discard_buf = std.atomic.Value(?[*]?Rc(T)).init(null),
            };
        }

        pub fn deinit(self: Self) void {
            for (self.window.state) |maybe_item| if (maybe_item) |item| {
                self.releaseItem(item);
            };
            self.window.deinit(self.allocator);
            if (self.discard_buf.load(.monotonic)) |buf| {
                self.allocator.free(buf[0..self.window.state.len]);
            }
        }

        pub fn put(self: *Self, index: usize, value: T) !void {
            const ptr = try Rc(T).create(self.allocator);
            errdefer ptr.deinit(self.allocator);
            ptr.payload().* = value;

            const item_to_release = blk: {
                self.lock.lock();
                defer self.lock.unlock();
                break :blk try self.window.put(index, ptr);
            };

            if (item_to_release) |old| {
                self.releaseItem(old);
            }
        }

        /// call `release` when you're done with the pointer
        pub fn get(self: *Self, index: usize) ?*const T {
            self.lock.lockShared();
            defer self.lock.unlockShared();

            if (self.window.get(index)) |element| {
                return element.acquire().payload();
            } else {
                return null;
            }
        }

        /// call `release` when you're done with the pointer
        pub fn contains(self: *Self, index: usize) bool {
            self.lock.lockShared();
            defer self.lock.unlockShared();

            return self.window.contains(index);
        }

        pub fn realign(self: *Self, new_center: usize) !void {
            if (new_center == self.center.load(.monotonic)) return;
            const discard_buf = try self.acquireDiscardBuf();
            defer self.releaseDiscardBuf(discard_buf);

            const items_to_release = blk: {
                self.lock.lock();
                defer self.lock.unlock();

                self.center.store(new_center, .monotonic);
                break :blk self.window.realignGet(new_center, discard_buf);
            };

            for (items_to_release) |maybe_item| {
                if (maybe_item) |item| {
                    self.releaseItem(item);
                }
            }
        }

        pub fn release(self: *Self, ptr: *const T) void {
            self.releaseItem(Rc(T).fromPayload(ptr));
        }

        fn releaseItem(self: *const Self, item: Rc(T)) void {
            if (item.release()) |bytes_to_free| {
                deinitItem(item.payload(), self.deinit_context);
                self.allocator.free(bytes_to_free);
            }
        }

        fn acquireDiscardBuf(self: *Self) ![]?Rc(T) {
            return if (self.discard_buf.swap(null, .acquire)) |buf|
                buf[0..self.window.state.len]
            else
                try self.allocator.alloc(?Rc(T), self.window.state.len);
        }

        fn releaseDiscardBuf(self: *Self, buf: []?Rc(T)) void {
            if (self.discard_buf.swap(buf.ptr, .release)) |extra_buf| {
                self.allocator.free(extra_buf[0..self.window.state.len]);
            }
        }
    };
}

/// Thread safe hashmap that stores a single copy of data that is shared with
/// readers as a pointer to the underlying data inside the map.
///
/// - this struct owns the data and is responsible for freeing it
/// - the lifetime of returned pointer exceeds every read operation of that
///   pointer, even if another thread evicts it from the Window, as long as
///   `release` is used properly.
///
/// TODO: Consolidate this with SharedPointerWindow, since the logic is exactly
/// the same. But do not to make things more complex. I see two potential
/// approaches:
/// 1. Create an entirely generic struct that allows you to specify the generic
///    container type that's contained within as a parameter. This would replace
///    both of these structs.
/// 2. Create a lean and unopinionated struct that manages the lifetimes logic
///    without actually containing anything, and compose it within these
///    pre-existing specialized structs to reduce the duplicated logic.
///
/// I like the idea of #2 since #1 may result in some confusing abstractions.
/// But #2 say not even be viable since wrapping may be necessary for
/// correctness.
pub fn SharedPointerMap(
    K: type,
    V: type,
    deinitItem_: anytype,
    DeinitContext: type,
) type {
    const Rc = sig.sync.Rc;
    const deinitItem = normalizeDeinitFunction(V, DeinitContext, deinitItem_);

    return struct {
        map: std.ArrayHashMapUnmanaged(K, Rc(V)),
        lock: std.Thread.RwLock = .{},
        deinit_context: DeinitContext,
        discard_buf: std.atomic.Value(?[*]?Rc(V)),

        const Self = @This();

        pub fn init(deinit_context: DeinitContext) !Self {
            return .{
                .map = .{},
                .deinit_context = deinit_context,
                .discard_buf = std.atomic.Value(?[*]?Rc(V)).init(null),
            };
        }

        pub fn deinit(self: Self, allocator: Allocator) void {
            for (self.map.state) |maybe_item| if (maybe_item) |item| {
                self.releaseItem(item);
            };
            self.map.deinit(allocator);
            if (self.discard_buf.load(.monotonic)) |buf| {
                allocator.free(buf[0..self.map.state.len]);
            }
        }

        pub fn put(self: *Self, allocator: Allocator, key: K, value: V) !void {
            const ptr = try Rc(V).create(allocator);
            errdefer ptr.deinit(allocator);
            ptr.payload().* = value;

            const item_to_release = blk: {
                self.lock.lock();
                defer self.lock.unlock();
                break :blk try self.map.put(key, ptr);
            };

            if (item_to_release) |old| {
                self.releaseItem(old);
            }
        }

        /// call `release` when you're done with the pointer
        pub fn get(self: *Self, key: K) ?*const V {
            self.lock.lockShared();
            defer self.lock.unlockShared();

            if (self.map.get(key)) |element| {
                return element.acquire().payload();
            } else {
                return null;
            }
        }

        /// call `release` when you're done with the pointer
        pub fn contains(self: *Self, key: K) bool {
            self.lock.lockShared();
            defer self.lock.unlockShared();

            return self.map.contains(key);
        }

        pub fn release(self: *Self, ptr: *const V) void {
            self.releaseItem(Rc(V).fromPayload(ptr));
        }

        fn releaseItem(self: *const Self, allocator: Allocator, item: Rc(V)) void {
            if (item.release()) |bytes_to_free| {
                deinitItem(item.payload(), self.deinit_context);
                allocator.free(bytes_to_free);
            }
        }
    };
}

pub fn SharedPointerMap2(
    K: type,
    V: type,
    deinitItem_: anytype,
    DeinitContext: type,
) type {
    const Rc = sig.sync.Rc;
    const deinitItem = normalizeDeinitFunction(V, DeinitContext, deinitItem_);

    return struct {
        map: std.ArrayHashMapUnmanaged(K, Rc(V)),
        ptr_mgr: SharedPointerManager(V, deinitItem_, DeinitContext),

        const Self = @This();

        pub fn init(deinit_context: DeinitContext) !Self {
            return .{
                .map = .{},
                .deinit_context = deinit_context,
                .discard_buf = std.atomic.Value(?[*]?Rc(V)).init(null),
            };
        }

        pub fn deinit(self: Self, allocator: Allocator) void {
            for (self.map.state) |maybe_item| if (maybe_item) |item| {
                self.releaseItem(item);
            };
            self.map.deinit(allocator);
            if (self.discard_buf.load(.monotonic)) |buf| {
                allocator.free(buf[0..self.map.state.len]);
            }
        }

        pub fn put(self: *Self, allocator: Allocator, key: K, value: V) !void {
            const ptr = try Rc(V).create(allocator);
            errdefer ptr.deinit(allocator);
            ptr.payload().* = value;

            const item_to_release = blk: {
                self.lock.lock();
                defer self.lock.unlock();
                break :blk try self.map.put(key, ptr);
            };

            if (item_to_release) |old| {
                self.releaseItem(old);
            }
        }

        /// call `release` when you're done with the pointer
        pub fn get(self: *Self, key: K) ?*const V {
            self.lock.lockShared();
            defer self.lock.unlockShared();

            if (self.map.get(key)) |element| {
                return element.acquire().payload();
            } else {
                return null;
            }
        }

        /// call `release` when you're done with the pointer
        pub fn contains(self: *Self, key: K) bool {
            self.lock.lockShared();
            defer self.lock.unlockShared();

            return self.map.contains(key);
        }

        pub fn release(self: *Self, ptr: *const V) void {
            self.releaseItem(Rc(V).fromPayload(ptr));
        }

        fn releaseItem(self: *const Self, allocator: Allocator, item: Rc(V)) void {
            if (item.release()) |bytes_to_free| {
                deinitItem(item.payload(), self.deinit_context);
                allocator.free(bytes_to_free);
            }
        }
    };
}

pub fn SharedPointerManager(
    V: type,
    deinitItem_: anytype,
    DeinitContext: type,
) type {
    const Rc = sig.sync.Rc;
    const deinitItem = normalizeDeinitFunction(V, DeinitContext, deinitItem_);

    return struct {
        lock: std.Thread.RwLock = .{},
        deinit_context: DeinitContext,
        discard_buf: std.atomic.Value(?[*]?Rc(V)),

        const Self = @This();

        pub fn init(deinit_context: DeinitContext) !Self {
            return .{
                .map = .{},
                .deinit_context = deinit_context,
                .discard_buf = std.atomic.Value(?[*]?Rc(V)).init(null),
            };
        }

        pub fn deinit(self: Self, allocator: Allocator) void {
            for (self.map.state) |maybe_item| if (maybe_item) |item| {
                self.releaseItem(item);
            };
            self.map.deinit(allocator);
            if (self.discard_buf.load(.monotonic)) |buf| {
                allocator.free(buf[0..self.map.state.len]);
            }
        }

        pub fn startPut(self: *Self, allocator: Allocator, value: V) !*V {
            _ = self; // autofix
            const ptr = try Rc(V).create(allocator);
            errdefer ptr.deinit(allocator);
            ptr.payload().* = value;
            return ptr.payload().*;
        }

        pub fn finishPut(self: *Self, allocator: Allocator, item_to_release: ?*V) void {
            self.lock.lockShared(); // TODO: need??
            defer self.lock.unlockShared();
            if (item_to_release) |old| {
                self.releaseItem(allocator, old);
            }
        }

        pub fn startRead(self: *Self) void {
            _ = self; // autofix
        }
        pub fn readUnlock(self: *Self) void {
            _ = self; // autofix
        }

        pub fn deleteLock(self: *Self) void {
            _ = self; // autofix
        }
        pub fn deleteUnlock(self: *Self) void {
            _ = self; // autofix
        }

        // /// call `release` when you're done with the pointer
        // pub fn get(self: *Self, key: K) ?*const V {
        //     self.lock.lockShared();
        //     defer self.lock.unlockShared();

        //     if (self.map.get(key)) |element| {
        //         return element.acquire().payload();
        //     } else {
        //         return null;
        //     }
        // }

        // /// call `release` when you're done with the pointer
        // pub fn contains(self: *Self, key: K) bool {
        //     self.lock.lockShared();
        //     defer self.lock.unlockShared();

        //     return self.map.contains(key);
        // }

        pub fn release(self: *Self, ptr: *const V) void {
            self.releaseItem(Rc(V).fromPayload(ptr));
        }

        fn releaseItem(self: *const Self, allocator: Allocator, item: Rc(V)) void {
            self.lock.lock();
            defer self.lock.unlock();
            if (item.release()) |bytes_to_free| {
                deinitItem(item.payload(), self.deinit_context);
                allocator.free(bytes_to_free);
            }
        }
    };
}

pub fn normalizeDeinitFunction(
    V: type,
    DeinitContext: type,
    deinitFn: anytype,
) fn (*V, DeinitContext) void {
    return switch (@TypeOf(deinitFn)) {
        fn (*V, DeinitContext) void => deinitFn,

        fn (V, DeinitContext) void => struct {
            fn f(v: *V, ctx: DeinitContext) void {
                deinitFn(v.*, ctx);
            }
        }.f,

        fn (V) void => struct {
            fn f(v: *V, _: DeinitContext) void {
                V.deinit(v.*);
            }
        }.f,

        fn (*V) void => struct {
            fn f(v: *V, _: DeinitContext) void {
                V.deinit(v);
            }
        }.f,

        else => if (DeinitContext == Allocator and
            @TypeOf(deinitFn) == @TypeOf(Allocator.free) and deinitFn == Allocator.free)
            struct {
                fn free(v: *V, allocator: Allocator) void {
                    allocator.free(v.*);
                }
            }.free
        else
            @compileError("unsupported deinit function type"),
    };
}

test "SharedPointerWindow frees memory" {
    const allocator = std.testing.allocator;
    var window = try SharedPointerWindow([]u8, Allocator.free, Allocator)
        .init(allocator, 3, 1, allocator);
    defer window.deinit();
    const first = try allocator.alloc(u8, 1);
    try window.put(0, first);
    const second = try allocator.alloc(u8, 1);
    try window.put(0, second);
    const third = try allocator.alloc(u8, 1);
    try window.put(1, third);
    const fourth = try allocator.alloc(u8, 1);
    try window.put(2, fourth);
}
