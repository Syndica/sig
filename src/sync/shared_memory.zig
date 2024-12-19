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
        discard_buf: []?Rc(T),

        const Self = @This();

        pub fn init(
            allocator: Allocator,
            len: usize,
            start: usize,
            deinit_context: DeinitContext,
        ) !Self {
            const discard_buf = try allocator.alloc(?Rc(T), len);
            return .{
                .allocator = allocator,
                .window = try Window(Rc(T)).init(allocator, len, start),
                .deinit_context = deinit_context,
                .center = std.atomic.Value(usize).init(start),
                .discard_buf = discard_buf,
            };
        }

        pub fn deinit(self: Self) void {
            for (self.window.state) |maybe_item| if (maybe_item) |item| {
                self.releaseItem(item);
            };
            self.window.deinit();
        }

        pub fn put(self: *Self, index: usize, value: T) !void {
            const ptr = try Rc(T).create(self.allocator);
            ptr.payload().* = value;

            const item_to_release = blk: {
                self.lock.lock();
                defer self.lock.unlock();
                break :blk self.window.put(index, ptr) catch null;
            };

            if (item_to_release) |old| {
                self.releaseItem(old);
            }
        }

        /// call `release` when you're done with the pointer
        pub fn get(self: *Self, index: usize) ?*const T {
            self.lock.lockShared();
            defer self.lock.lockShared();

            if (self.window.get(index)) |element| {
                return element.acquire().payload();
            } else {
                return null;
            }
        }

        /// call `release` when you're done with the pointer
        pub fn contains(self: *Self, index: usize) bool {
            self.lock.lockShared();
            defer self.lock.lockShared();

            return self.window.contains(index);
        }

        pub fn realign(self: *Self, new_center: usize) void {
            if (new_center == self.center.load(.monotonic)) return;

            const items_to_release = blk: {
                self.lock.lock();
                defer self.lock.lock();

                self.center.store(new_center, .monotonic);
                break :blk self.window.realignGet(new_center, self.discard_buf);
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

        else => @compileError("unsupported deinit function type"),
    };
}
