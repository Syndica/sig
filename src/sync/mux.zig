const std = @import("std");
const Mutex = std.Thread.Mutex;
const assert = std.debug.assert;
const testing = std.testing;

/// Mux is a `Mutex` wrapper which enforces proper access to a protected value.
pub fn Mux(comptime T: type) type {
    return struct {
        /// Do not use! Private field.
        inner: Inner,

        const Self = @This();

        /// `init` will initialize self with `val`
        pub fn init(val: T) Self {
            return Self{
                .inner = .{
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
            inner: *Inner,
            /// Do not use! Private field.
            valid: bool,

            /// get func returns `T`
            pub fn get(self: *LockGuard) T {
                assert(self.valid == true);
                return self.inner.v;
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
                .inner = &self.inner,
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

test "sync.mux: works" {
    var m = Mux(Counter).init(.{ .current = 0 });

    var locked_counter = m.lock();
    try testing.expectEqual(Counter{ .current = 0 }, locked_counter.get());
    locked_counter.unlockAfter(modifyCounter);

    var locked_counter_again = m.lock();
    try testing.expectEqual(Counter{ .current = 1 }, locked_counter_again.get());
    locked_counter_again.unlock();

    var usize_mux = Mux(usize).init(0);

    var locked_usize_mux = usize_mux.lock();
    defer locked_usize_mux.unlock();
    locked_usize_mux.ptr().* = 4;
    try testing.expectEqual(@as(usize, 4), locked_usize_mux.get());
}
