const std = @import("std");

/// Thread-safe data structure that can only be written to once.
/// WARNING: This does not make the inner type thread-safe.
///
/// All fields are private. Direct access leads to undefined behavior.
///
/// 1. When this struct is initialized, the contained type is missing.
/// 2. Call one of the init methods to initialize the contained type.
/// 3. After initialization:
///    - get methods will return the initialized value.
///    - value may not be re-initialized.
pub fn OnceCell(comptime T: type) type {
    return struct {
        value: T = undefined,
        started: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
        finished: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

        const Self = @This();

        pub fn init() Self {
            return .{};
        }

        /// Initializes the inner value and returns pointer to it.
        /// Returns error if it was already initialized.
        /// Blocks while other threads are in the process of initialization.
        pub fn initialize(self: *Self, initLogic: anytype, init_args: anytype) error{AlreadyInitialized}!*T {
            if (!self.acquire()) return error.AlreadyInitialized;
            self.value = @call(.auto, initLogic, init_args);
            self.finished.store(true, .release);
            return &self.value;
        }

        /// Tries to initialize the inner value and returns pointer to it, or return error if it fails.
        /// Returns error if it was already initialized.
        /// Blocks while other threads are in the process of initialization.
        pub fn tryInit(self: *Self, initLogic: anytype, init_args: anytype) !*T {
            if (!self.acquire()) return error.AlreadyInitialized;
            errdefer self.started.store(false, .release);
            self.value = try @call(.auto, initLogic, init_args);
            self.finished.store(true, .release);
            return &self.value;
        }

        /// Returns pointer to inner value if already initialized.
        /// Otherwise initializes the value and returns it.
        /// Blocks while other threads are in the process of initialization.
        pub fn getOrInit(self: *Self, initLogic: anytype, init_args: anytype) *T {
            if (self.acquire()) {
                self.value = @call(.auto, initLogic, init_args);
                self.finished.store(true, .release);
            }
            return &self.value;
        }

        /// Returns pointer to inner value if already initialized.
        /// Otherwise tries to initialize the value and returns it, or return error if it fails.
        /// Blocks while other threads are in the process of initialization.
        pub fn getOrTryInit(self: *Self, initLogic: anytype, init_args: anytype) !*T {
            if (self.acquire()) {
                errdefer self.started.store(false, .release);
                self.value = try @call(.auto, initLogic, init_args);
                self.finished.store(true, .release);
            }
            return &self.value;
        }

        /// Tries to acquire the write lock.
        /// returns:
        /// - true if write lock is acquired.
        /// - false if write lock is not acquirable because a write was already completed.
        /// - waits if another thread has a write in progress. if the other thread fails, this may acquire the lock.
        fn acquire(self: *Self) bool {
            while (self.started.cmpxchgWeak(false, true, .acquire, .monotonic)) |_| {
                if (self.finished.load(.acquire)) {
                    return false;
                }
            }
            return true;
        }

        /// Returns the value if initialized.
        /// Returns error if not initialized.
        /// Blocks while other threads are in the process of initialization.
        pub fn get(self: *Self) error{NotInitialized}!*T {
            if (self.finished.load(.acquire)) {
                return &self.value;
            }
            while (self.started.load(.monotonic)) {
                if (self.finished.load(.acquire)) {
                    return &self.value;
                }
            }
            return error.NotInitialized;
        }
    };
}

test "sync.once_cell: init returns correctly" {
    var oc = OnceCell(u64).init();
    const x = try oc.initialize(returns(10), .{});
    try std.testing.expect(10 == x.*);
}

test "sync.once_cell: cannot get uninitialized" {
    var oc = OnceCell(u64).init();
    if (oc.get()) |_| {
        try std.testing.expect(false);
    } else |_| {}
}

test "sync.once_cell: can get initialized" {
    var oc = OnceCell(u64).init();
    _ = try oc.initialize(returns(10), .{});
    const x = try oc.get();
    try std.testing.expect(10 == x.*);
}

test "sync.once_cell: tryInit returns error on failure" {
    var oc = OnceCell(u64).init();
    const err = oc.tryInit(returnErr, .{});
    try std.testing.expectError(error.TestErr, err);
}

test "sync.once_cell: tryInit works on success" {
    var oc = OnceCell(u64).init();
    const x1 = try oc.tryInit(returnNotErr(10), .{});
    const x2 = try oc.get();
    try std.testing.expect(10 == x1.*);
    try std.testing.expect(10 == x2.*);
}

test "sync.once_cell: tryInit returns error if initialized" {
    var oc = OnceCell(u64).init();
    const x1 = try oc.tryInit(returnNotErr(10), .{});
    const err = oc.tryInit(returnNotErr(11), .{});
    const x2 = try oc.get();
    try std.testing.expect(10 == x1.*);
    try std.testing.expectError(error.AlreadyInitialized, err);
    try std.testing.expect(10 == x2.*);
}

test "sync.once_cell: getOrInit can initialize when needed" {
    var oc = OnceCell(u64).init();
    const x1 = oc.getOrInit(returns(10), .{});
    const x2 = try oc.get();
    try std.testing.expect(10 == x1.*);
    try std.testing.expect(10 == x2.*);
}

test "sync.once_cell: getOrInit uses already initialized value" {
    var oc = OnceCell(u64).init();
    const x1 = oc.getOrInit(returns(10), .{});
    const x2 = oc.getOrInit(returns(11), .{});
    try std.testing.expect(10 == x1.*);
    try std.testing.expect(10 == x2.*);
}

test "sync.once_cell: getOrTryInit returns error on failure" {
    var oc = OnceCell(u64).init();
    const err = oc.getOrTryInit(returnErr, .{});
    try std.testing.expectError(error.TestErr, err);
}

test "sync.once_cell: getOrTryInit works on success" {
    var oc = OnceCell(u64).init();
    const x1 = try oc.getOrTryInit(returnNotErr(10), .{});
    const x2 = try oc.get();
    try std.testing.expect(10 == x1.*);
    try std.testing.expect(10 == x2.*);
}

test "sync.once_cell: getOrTryInit uses already initialized value" {
    var oc = OnceCell(u64).init();
    const x1 = try oc.getOrTryInit(returnNotErr(10), .{});
    const x2 = try oc.getOrTryInit(returnNotErr(11), .{});
    try std.testing.expect(10 == x1.*);
    try std.testing.expect(10 == x2.*);
}

fn returns(comptime x: u64) fn () u64 {
    return struct {
        fn get() u64 {
            return x;
        }
    }.get;
}

fn returnNotErr(comptime x: u64) fn () error{}!u64 {
    return struct {
        fn get() !u64 {
            return x;
        }
    }.get;
}

fn returnErr() !u64 {
    return error.TestErr;
}
