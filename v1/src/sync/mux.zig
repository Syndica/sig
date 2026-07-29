const sig = @import("../sig.zig");
const std = @import("std");
const builtin = @import("builtin");

const Mutex = std.Thread.Mutex;
const RwLock = sig.sync.RwLock;

const assert = std.debug.assert;
const testing = std.testing;

const containsPointer = sig.utils.types.containsPointer;

/// Mux is a `Mutex` wrapper which enforces proper access to a protected value.
pub fn Mux(comptime T: type) type {
    return struct {
        /// Do not use! Private field.
        private: Inner,

        const Self = @This();

        /// `init` will initialize self with `val`
        pub fn init(val: T) Self {
            return Self{
                .private = .{
                    .m = Mutex{},
                    .v = val,
                },
            };
        }

        const Inner = struct {
            m: Mutex,
            v: T,
        };

        /// LockGuard represents a currently held lock on `Mux(T)`. It is not thread-safe.
        pub const LockGuard = struct {
            /// Do not use! Private field.
            private: *Inner,
            /// Do not use! Private field.
            valid: bool,

            /// get func returns `Const(T)`
            pub fn get(self: *LockGuard) Const(T) {
                assert(self.valid == true);
                switch (@typeInfo(T)) {
                    // if value is a pointer, we will return pointer itself
                    .pointer => |_| {
                        return self.private.v;
                    },
                    else => {
                        return &self.private.v;
                    },
                }
            }

            /// `mut` func returns a `Mutable(T)`
            pub fn mut(self: *LockGuard) Mutable(T) {
                assert(self.valid == true);
                switch (@typeInfo(T)) {
                    // if value is a pointer, we will return pointer itself
                    .pointer => |_| {
                        return self.private.v;
                    },
                    else => {
                        return &self.private.v;
                    },
                }
            }

            /// `replace` sets the val in place of current `T`
            pub fn replace(self: *LockGuard, val: T) void {
                assert(self.valid == true);
                self.private.v = val;
            }

            /// `unlock` releases the held `Mutex` lock and invalidates this `LockGuard`
            pub fn unlock(self: *LockGuard) void {
                assert(self.valid == true);
                if (builtin.mode == .Debug) self.valid = false;

                self.private.m.unlock();
            }

            /// `unlockAfter` releases the held `Mutex` lock and invalidates this `LockGuard`
            /// after calling `func` function
            pub fn unlockAfter(self: *LockGuard, comptime func: fn (Mutable(T)) void) void {
                assert(self.valid == true);
                func(self.mut());
                if (builtin.mode == .Debug) self.valid = false;
                self.private.m.unlock();
            }

            /// `condition` will call `wait` on the `cond` that was passed with self
            pub fn condition(self: *LockGuard, cond: *std.Thread.Condition) void {
                assert(self.valid == true);
                cond.wait(&self.private.m);
            }
        };

        pub fn readWithLock(self: *Self) struct { Const(T), LockGuard } {
            var lock_guard = self.lock();
            const t = lock_guard.get();
            return .{ t, lock_guard };
        }

        pub fn writeWithLock(self: *Self) struct { Mutable(T), LockGuard } {
            var lock_guard = self.lock();
            const t = lock_guard.mut();
            return .{ t, lock_guard };
        }

        pub fn set(self: *Self, item: T) void {
            self.private.m.lock();
            defer self.private.m.unlock();
            self.private.v = item;
        }

        /// `lock` returns a `LockGuard` after acquiring `Mutex` lock
        pub fn lock(self: *Self) LockGuard {
            self.private.m.lock();
            return LockGuard{
                .private = &self.private,
                .valid = true,
            };
        }

        /// `tryLock` returns a `LockGuard` after acquiring `Mutex` lock if its able to otherwise
        /// it returns `null`.
        pub fn tryLock(self: *Self) ?LockGuard {
            if (!self.private.m.tryLock()) return null;
            return LockGuard{
                .private = &self.private,
                .valid = true,
            };
        }

        /// Acquires the lock just long enough to shallow copy the item, and
        /// returns the copy.
        pub fn readCopy(self: *Self) T {
            self.private.m.lock();
            defer self.private.m.unlock();
            return self.private.v;
        }
    };
}

/// RwMux is a `RwLock` wrapper which enforces proper access to a protected value which is moved to heap.
pub fn RwMux(comptime T: type) type {
    return struct {
        /// Do not use! Private field.
        private: Inner,

        const Self = @This();

        const Inner = struct {
            r: RwLock,
            v: T,
        };

        /// `init` will initialize self with `val` and moves it to the heap
        pub fn init(val: T) Self {
            return Self{
                .private = .{
                    .r = RwLock{},
                    .v = val,
                },
            };
        }

        /// RLockGuard represents a currently held read lock on `RwMux(T)`. It is not thread-safe.
        pub const RLockGuard = struct {
            /// Do not use! Private field.
            private: *Inner,
            /// Do not use! Private field.
            valid: bool,

            /// get func returns a `Const(T)`
            pub fn get(self: *const RLockGuard) Const(T) {
                assert(self.valid == true);
                switch (@typeInfo(T)) {
                    // if value is a pointer, we will return pointer itself instead of `*const *T`
                    .pointer => |_| {
                        return self.private.v;
                    },
                    else => {
                        return &self.private.v;
                    },
                }
            }

            /// `unlock` releases the held read lock and invalidates this `RLockGuard`
            pub fn unlock(self: *RLockGuard) void {
                assert(self.valid == true);
                if (builtin.mode == .Debug) self.valid = false;
                self.private.r.unlockShared();
            }

            /// `unlockAfter` releases the held read lock and invalidates this `RLockGuard`
            /// after calling `func` function
            pub fn unlockAfter(self: *RLockGuard, comptime func: fn (Const(T)) void) void {
                assert(self.valid == true);
                func(self.get());
                if (builtin.mode == .Debug) self.valid = false;
                self.private.m.unlockShared();
            }
        };

        /// WLockGuard represents a currently held write lock on `RwMux(T)`. It is not thread-safe.
        pub const WLockGuard = struct {
            /// Do not use! Private field.
            private: *Inner,
            /// Do not use! Private field.
            valid: bool,

            /// `get` func returns `Const(T)`
            pub fn get(self: *WLockGuard) Const(T) {
                assert(self.valid == true);
                switch (@typeInfo(T)) {
                    // if value is a pointer, we will return pointer itself instead of `*const *T`
                    .pointer => |_| {
                        return self.private.v;
                    },
                    else => {
                        return &self.private.v;
                    },
                }
            }

            /// `mut` func returns a `Mutable(T)`
            pub fn mut(self: *WLockGuard) Mutable(T) {
                assert(self.valid == true);
                switch (@typeInfo(T)) {
                    // if value is a pointer, we will return pointer itself instead of `*const *T`
                    .pointer => |_| {
                        return self.private.v;
                    },
                    else => {
                        return &self.private.v;
                    },
                }
            }

            /// `replace` sets the val in place of current `T`
            pub fn replace(self: *WLockGuard, val: T) void {
                assert(self.valid == true);
                self.private.v = val;
            }

            /// `unlock` releases the held write lock and invalidates this `WLockGuard`
            pub fn unlock(self: *WLockGuard) void {
                self.valid = false;
                self.private.r.unlock();
            }

            /// `unlockAfter` releases the held write lock and invalidates this `WLockGuard`
            /// after calling `func` function
            pub fn unlockAfter(self: *WLockGuard, comptime func: fn (Mutable(T)) void) void {
                assert(self.valid == true);
                func(self.mut());
                if (builtin.mode == .Debug) self.valid = false;
                self.private.r.unlock();
            }
        };

        /// `write` returns a `WLockGuard` after acquiring a `write` lock
        pub fn write(self: *Self) WLockGuard {
            self.private.r.lock();
            return WLockGuard{
                .private = &self.private,
                .valid = true,
            };
        }

        /// `write` returns a `WLockGuard` after acquiring a `write` lock
        pub fn tryWrite(self: *Self) ?WLockGuard {
            if (!self.private.r.tryLock()) return null;
            return WLockGuard{
                .private = &self.private,
                .valid = true,
            };
        }

        pub fn set(self: *Self, item: T) void {
            self.private.r.lock();
            defer self.private.r.unlock();
            self.private.v = item;
        }

        /// `read` returns a `RLockGuard` after acquiring a `read` lock
        pub fn read(self: *Self) RLockGuard {
            self.private.r.lockShared();
            return RLockGuard{
                .private = &self.private,
                .valid = true,
            };
        }

        /// `tryRead` returns a `RLockGuard` after acquiring a `read` lock
        pub fn tryRead(self: *Self) ?RLockGuard {
            if (!self.private.r.tryLockShared()) return null;
            return .{
                .private = &self.private,
                .valid = true,
            };
        }

        pub fn readWithLock(self: *Self) struct { Const(T), RLockGuard } {
            var lock_guard = self.read();
            const t = lock_guard.get();
            return .{ t, lock_guard };
        }

        /// Acquires the lock just long enough to shallow copy the item, and
        /// returns the copy.
        pub fn readCopy(self: *Self) T {
            comptime if (containsPointer(.mut, T) orelse true) {
                @compileError("reading a mutable pointer after unlocking would bypass the lock");
            };
            self.private.r.lockShared();
            defer self.private.r.unlockShared();
            return self.private.v;
        }

        pub fn writeWithLock(self: *Self) struct { Mutable(T), WLockGuard } {
            var lock_guard = self.write();
            const t = lock_guard.mut();
            return .{ t, lock_guard };
        }

        pub fn readField(
            self: *Self,
            comptime field: []const u8,
        ) @TypeOf(@field(self.private.v, field)) {
            self.private.r.lockShared();
            const value = @field(self.private.v, field);
            self.private.r.unlockShared();
            return value;
        }

        // directly unlocks the lock guard. note: 99% of the time you should
        // not use this method except in cases where you need to pass around
        // rw_lock guards and unlock them later.
        pub fn unlock(self: *Self) void {
            self.private.r.unlock();
        }

        // directly unlocks the shared lock guard. note: 99% of the time you should
        // not use this method except in cases where you need to pass around
        // rw_lock guards and unlock them later.
        pub fn unlockShared(self: *Self) void {
            self.private.r.unlockShared();
        }
    };
}

/// `Const` type is a const pointer adapter for different types as explained below:
///
/// - T is a non-pointer type (example: bool): `Const` is a `*const bool`
/// - T is a non-pointer type (example: [100]u8): `Const` is a `*const [100]u8`
/// - T is a pointer to One type (example: *usize): `Const` is `*const usize`
/// - T is a pointer to Slice type (example: []Packet): `Const` is a `[]const Packet`
///
/// ### Assertions:
///
/// ```
///     assert(Const(*usize)  ==  *const usize)
///     assert(Const(usize)   ==  *const usize)
///     assert(Const(*[]u8)   ==  *const []u8)
///     assert(Const([]u8)    ==  []const u8)
///     assert(Const(*Packet) ==  *const Packet)
///     assert(Const(Packet)  ==  *const Packet)
///     assert(Const([100]u8)  ==  *const [100]u8)
///     assert(Const(*[100]u8)  ==  *const [100]u8)
/// ```
///
/// This is used in conjuction with `toConst` function and is a way to
/// avoid `@TypeOf()` return type.
pub fn Const(comptime T: type) type {
    return switch (@typeInfo(T)) {
        .pointer => |info| blk: {
            if (info.size == .c) @compileError("C pointers not supported");
            var new_info = info;
            new_info.is_const = true;
            break :blk @Type(.{ .pointer = new_info });
        },
        else => *const T,
    };
}

/// `Mutable` type is a pointer adapter for different types as explained below:
///
/// - T is a non-pointer type (example: bool): `Mutable` is a `*bool`
/// - T is a non-pointer type (example: [100]u8): `Mutable` is a `*[100]u8`
/// - T is a pointer to One type (example: *usize): `Mutable` is `*usize`
/// - T is a pointer to Slice type (example: []Packet): `Mutable` is a `[]Packet`
///
/// ### Assertions:
///
/// ```
///     assert(Mutable(*usize)      ==  *usize)
///     assert(Mutable(usize)       ==  *usize)
///     assert(Mutable(*[]u8)       ==  *[]u8)
///     assert(Mutable([]u8)        ==  []u8)
///     assert(Mutable(*Packet)     ==  *Packet)
///     assert(Mutable(Packet)      ==  *Packet)
///     assert(Mutable([100]u8)     ==  *[100]u8)
///     assert(Mutable(*[100]u8)    ==  *[100]u8)
/// ```
///
/// This is used as return type of `mut` function and is a way to
/// avoid `@TypeOf()` return type or block statements.
pub fn Mutable(comptime T: type) type {
    return switch (@typeInfo(T)) {
        .pointer => T,
        else => *T,
    };
}

pub fn deinitMux(mux: anytype) void {
    var v, var lg = mux.writeWithLock();
    defer lg.unlock();
    v.deinit();
}

test "sync.mux: Const is correct" {
    const Packet = struct {
        buffer: [100]u8 = [_]u8{0} ** 100,
    };

    assert(*const usize == Const(*usize));
    assert(*const usize == Const(usize));
    assert(*const []u8 == Const(*[]u8));
    assert([]const u8 == Const([]u8));
    assert(*const Packet == Const(*Packet));
    assert(*const Packet == Const(Packet));
    assert(*const [100]u32 == Const([100]u32));
    assert(*const [100]u32 == Const(*[100]u32));
}

test "sync.mux: Mux handles slices properly" {
    var arr = [3]u8{ 0, 1, 2 };
    var slice = Mux([]u8).init(&arr);

    var slice_locked = slice.lock();
    defer slice_locked.unlock();

    slice_locked.mut()[1] = 2;
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 2, 2 }, slice_locked.get());
}

test "sync.mux: Mutable is correct" {
    const Packet = struct {
        buffer: [100]u8 = [_]u8{0} ** 100,
    };

    assert(*usize == Mutable(*usize));
    assert(*usize == Mutable(usize));
    assert(*[]u8 == Mutable(*[]u8));
    assert([]u8 == Mutable([]u8));
    assert(*Packet == Mutable(*Packet));
    assert(*Packet == Mutable(Packet));
    assert(*[100]u32 == Mutable([100]u32));
    assert(*[100]u32 == Mutable(*[100]u32));

    var bool_1 = true;
    assert(@TypeOf(&bool_1) == Mutable(bool));
    var usize_1: usize = 3;
    assert(@TypeOf(&usize_1) == Mutable(usize));
    var arr: [4]u8 = [4]u8{ 1, 2, 3, 4 };
    assert(@TypeOf(&arr) == Mutable([4]u8));
    const slice: []u8 = arr[0..];
    assert(@TypeOf(slice) == Mutable([]u8));
}

const Counter = struct {
    current: usize,
};

fn modifyCounter(v: *Counter) void {
    v.current = 1;
}

test "sync.mux: Cluster info example" {
    var cluster_info = RwMux(Counter).init(.{ .current = 3 });
    var r_cluster_info = cluster_info.read();
    defer r_cluster_info.unlock();

    const curr = r_cluster_info.get().current;
    _ = curr;
}

test "sync.mux: Mux works" {
    var m = Mux(Counter).init(.{ .current = 0 });

    var locked_counter = m.lock();
    try testing.expectEqual(Counter{ .current = 0 }, locked_counter.get().*);
    var v = locked_counter.mut();
    v.current = 4;
    locked_counter.unlockAfter(modifyCounter);

    var locked_counter_again = m.lock();
    try testing.expectEqual(Counter{ .current = 1 }, locked_counter_again.get().*);
    locked_counter_again.unlock();

    var usize_mux = Mux(usize).init(0);
    var locked_usize_mux = usize_mux.lock();
    defer locked_usize_mux.unlock();
    locked_usize_mux.mut().* = 4;
    try testing.expectEqual(@as(usize, 4), locked_usize_mux.get().*);
    locked_usize_mux.replace(5);
    try testing.expectEqual(@as(usize, 5), locked_usize_mux.get().*);
}

test "sync.mux: RwMux works" {
    var counter = RwMux(Counter).init(.{ .current = 0 });

    var locked_counter = counter.write();
    try testing.expectEqual(Counter{ .current = 0 }, locked_counter.get().*);
    locked_counter.unlockAfter(modifyCounter);

    var r_locked_counter = counter.read();
    try testing.expectEqual(Counter{ .current = 1 }, r_locked_counter.get().*);
    r_locked_counter.unlock();

    var usize_mux = RwMux(usize).init(0);

    var locked_usize_mux = usize_mux.write();
    defer locked_usize_mux.unlock();
    locked_usize_mux.mut().* = 4;
    try testing.expectEqual(@as(usize, 4), locked_usize_mux.get().*);
}

test "sync.mux: slice test" {
    var items = [_]u8{ 0, 45, 53, 44, 33 };

    var mux = Mux([]u8).init(&items);
    var locked = mux.lock();
    locked.mut()[0] = 1;

    try testing.expectEqualSlices(u8, &[_]u8{ 1, 45, 53, 44, 33 }, locked.get());
}

test "sync.mux: RwMux works with slices" {
    var items = [_]u8{ 0, 45, 53, 44, 33 };

    var mux = RwMux([]u8).init(&items);

    var locked = mux.write();
    defer locked.unlock();
    var got = locked.mut();
    got[0] = 1;

    try testing.expectEqualSlices(u8, &[_]u8{ 1, 45, 53, 44, 33 }, locked.get());
}
