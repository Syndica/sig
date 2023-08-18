const std = @import("std");
const Mutex = std.Thread.Mutex;
const RwLock = std.Thread.RwLock;
const assert = std.debug.assert;
const testing = std.testing;

/// Mux is a `Mutex` wrapper which enforces proper access to a protected value which is moved to heap.
pub fn Mux(comptime T: type) type {
    return struct {
        /// Do not use! Private field.
        inner: *Inner,
        allocator: std.mem.Allocator,

        const Self = @This();

        /// `init` will initialize self with `val`
        pub fn init(allocator: std.mem.Allocator, val: T) error{OutOfMemory}!Self {
            var inner = try allocator.create(Inner);
            inner.* = .{
                .m = Mutex{},
                .v = val,
            };
            return Self{
                .inner = inner,
                .allocator = allocator,
            };
        }

        pub fn deinit(self: *Self) void {
            self.allocator.destroy(self.inner);
        }

        const Inner = struct {
            m: Mutex,
            v: T,
        };

        /// LockGuard represents a currently held lock on `Mux(T)`. It is not thread-safe.
        pub const LockGuard = struct {
            /// Do not use! Private field.
            inner: *Inner,
            /// Do not use! Private field.
            valid: bool,

            /// get func returns `T`
            pub fn get(self: *LockGuard) *const T {
                assert(self.valid == true);
                return &self.inner.v;
            }

            /// `ptr` func returns a `*T` (usually to modify `T`)
            pub fn ptr(self: *LockGuard) *T {
                assert(self.valid == true);
                return &self.inner.v;
            }

            /// `set` sets the val in place of current `T`
            pub fn set(self: *LockGuard, val: T) void {
                assert(self.valid == true);
                self.inner.v = val;
            }

            /// value can only be called on slices
            pub fn value(self: *LockGuard) T {
                comptime {
                    switch (@typeInfo(T)) {
                        .Pointer => |*info| {
                            if (info.size != .Slice) {
                                @compileError("must be slice to call slice");
                            }
                        },
                        else => {
                            @compileError("must be slice to call slice");
                        },
                    }
                }
                return self.inner.v;
            }

            /// `unlock` releases the held `Mutex` lock and invalidates this `LockGuard`
            pub fn unlock(self: *LockGuard) void {
                assert(self.valid == true);
                self.inner.m.unlock();
                self.valid = false;
            }

            /// `unlockAfter` releases the held `Mutex` lock and invalidates this `LockGuard`
            /// after calling `func` function
            pub fn unlockAfter(self: *LockGuard, comptime func: fn (*T) void) void {
                assert(self.valid == true);
                func(self.ptr());
                self.inner.m.unlock();
                self.valid = false;
            }
        };

        /// `lock` returns a `LockGuard` after acquiring `Mutex` lock
        pub fn lock(self: *Self) LockGuard {
            self.inner.m.lock();
            return LockGuard{
                .inner = self.inner,
                .valid = true,
            };
        }
    };
}

/// RwMux is a `RwLock` wrapper which enforces proper access to a protected value which is moved to heap.
pub fn RwMux(comptime T: type) type {
    return struct {
        /// Do not use! Private field.
        inner: *Inner,
        allocator: std.mem.Allocator,

        const Self = @This();

        const Inner = struct {
            r: RwLock,
            v: T,
        };

        /// `init` will initialize self with `val` and moves it to the heap
        pub fn init(allocator: std.mem.Allocator, val: T) error{OutOfMemory}!Self {
            var inner = try allocator.create(Inner);
            inner.* = .{
                .r = RwLock{},
                .v = val,
            };
            return Self{
                .inner = inner,
                .allocator = allocator,
            };
        }

        pub fn deinit(self: *Self) void {
            self.allocator.destroy(self.inner);
        }

        /// RLockGuard represents a currently held read lock on `RwMux(T)`. It is not thread-safe.
        pub const RLockGuard = struct {
            /// Do not use! Private field.
            inner: *Inner,
            /// Do not use! Private field.
            valid: bool,

            /// get func returns `*const T`
            pub fn get(self: *RLockGuard) *const T {
                assert(self.valid == true);
                return &self.inner.v;
            }

            /// value can only be called on slices
            pub fn value(self: *RLockGuard) T {
                comptime {
                    switch (@typeInfo(T)) {
                        .Pointer => |*info| {
                            if (info.size != .Slice) {
                                @compileError("must be slice to call slice");
                            }
                        },
                        else => {
                            @compileError("must be slice to call slice");
                        },
                    }
                }
                return self.inner.v;
            }

            /// `unlock` releases the held read lock and invalidates this `WLockGuard`
            pub fn unlock(self: *RLockGuard) void {
                self.valid = false;
                self.inner.r.unlockShared();
            }

            /// `unlockAfter` releases the held read lock and invalidates this `RLockGuard`
            /// after calling `func` function
            pub fn unlockAfter(self: *RLockGuard, comptime func: fn (*const T) void) void {
                assert(self.valid == true);
                func(self.get());
                self.valid = false;
                self.inner.m.unlockShared();
            }
        };

        /// WLockGuard represents a currently held write lock on `RwMux(T)`. It is not thread-safe.
        pub const WLockGuard = struct {
            /// Do not use! Private field.
            inner: *Inner,
            /// Do not use! Private field.
            valid: bool,

            /// get func returns `*const T`
            pub fn get(self: *WLockGuard) *const T {
                assert(self.valid == true);
                return &self.inner.v;
            }

            /// `ptr` func returns a `*T` (usually to modify `T`)
            pub fn ptr(self: *WLockGuard) *T {
                assert(self.valid == true);
                return &self.inner.v;
            }

            /// value can only be called on slices
            pub fn value(self: *WLockGuard) T {
                comptime {
                    switch (@typeInfo(T)) {
                        .Pointer => |*info| {
                            if (info.size != .Slice) {
                                @compileError("must be slice to call slice");
                            }
                        },
                        else => {
                            @compileError("must be slice to call slice");
                        },
                    }
                }
                return self.inner.v;
            }

            /// `set` sets the val in place of current `T`
            pub fn set(self: *WLockGuard, val: T) void {
                assert(self.valid == true);
                self.inner.v = val;
            }

            /// `unlock` releases the held write lock and invalidates this `WLockGuard`
            pub fn unlock(self: *WLockGuard) void {
                self.valid = false;
                self.inner.r.unlock();
            }

            /// `unlockAfter` releases the held write lock and invalidates this `WLockGuard`
            /// after calling `func` function
            pub fn unlockAfter(self: *WLockGuard, comptime func: fn (*T) void) void {
                assert(self.valid == true);
                func(self.ptr());
                self.valid = false;
                self.inner.r.unlock();
            }
        };

        /// `write` returns a `LockGuard` after acquiring `Mutex` lock
        pub fn write(self: *Self) WLockGuard {
            self.inner.r.lock();
            return WLockGuard{
                .inner = self.inner,
                .valid = true,
            };
        }

        /// `read` returns a `LockGuard` after acquiring `Mutex` lock
        pub fn read(self: *Self) RLockGuard {
            self.inner.r.lockShared();
            return RLockGuard{
                .inner = self.inner,
                .valid = true,
            };
        }
    };
}

const Counter = struct {
    current: usize,
};

fn modifyCounter(v: *Counter) void {
    v.current = 1;
}

test "sync.mux: Cluster info example" {
    var cluster_info = try RwMux(Counter).init(testing.allocator, .{ .current = 3 });
    defer cluster_info.deinit();
    var r_cluster_info = cluster_info.read();
    defer r_cluster_info.unlock();

    var curr = r_cluster_info.get().current;

    std.log.info("{any}", .{curr});
}

test "sync.mux: Mux works" {
    var m = try Mux(Counter).init(testing.allocator, .{ .current = 0 });
    defer m.deinit();

    var locked_counter = m.lock();
    try testing.expectEqual(Counter{ .current = 0 }, locked_counter.get().*);
    locked_counter.unlockAfter(modifyCounter);

    var locked_counter_again = m.lock();
    try testing.expectEqual(Counter{ .current = 1 }, locked_counter_again.get().*);
    locked_counter_again.unlock();

    var usize_mux = try Mux(usize).init(testing.allocator, 0);
    defer usize_mux.deinit();

    var locked_usize_mux = usize_mux.lock();
    defer locked_usize_mux.unlock();
    locked_usize_mux.ptr().* = 4;
    try testing.expectEqual(@as(usize, 4), locked_usize_mux.get().*);
}

test "sync.mux: RwMux works" {
    var m = try RwMux(Counter).init(testing.allocator, .{ .current = 0 });
    defer m.deinit();

    var locked_counter = m.write();
    try testing.expectEqual(Counter{ .current = 0 }, locked_counter.get().*);
    locked_counter.unlockAfter(modifyCounter);

    var r_locked_counter = m.read();
    try testing.expectEqual(Counter{ .current = 1 }, r_locked_counter.get().*);
    r_locked_counter.unlock();

    var usize_mux = try RwMux(usize).init(testing.allocator, 0);
    defer usize_mux.deinit();

    var locked_usize_mux = usize_mux.write();
    defer locked_usize_mux.unlock();
    locked_usize_mux.ptr().* = 4;
    try testing.expectEqual(@as(usize, 4), locked_usize_mux.get().*);
}

test "sync.mux: slice test" {
    var items = [_]u8{ 0, 45, 53, 44, 33 };

    var mux = try Mux([]u8).init(testing.allocator, &items);
    defer mux.deinit();
    var locked = mux.lock();
    locked.value()[0] = 1;

    try testing.expectEqualSlices(u8, &[_]u8{ 1, 45, 53, 44, 33 }, locked.get().*);
}
