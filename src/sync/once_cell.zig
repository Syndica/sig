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
        started: std.atomic.Atomic(bool) = std.atomic.Atomic(bool).init(false),
        finished: std.atomic.Atomic(bool) = std.atomic.Atomic(bool).init(false),

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
            self.finished.store(true, .Release);
            return &self.value;
        }

        /// Tries to initialize the inner value and returns pointer to it, or return error if it fails.
        /// Returns error if it was already initialized.
        /// Blocks while other threads are in the process of initialization.
        pub fn tryInitialize(self: *Self, initLogic: anytype, init_args: anytype) !*T {
            if (!self.acquire()) return error.AlreadyInitialized;
            errdefer self.started.store(false, .Release);
            self.value = try @call(.auto, initLogic, init_args);
            self.finished.store(true, .Release);
            return &self.value;
        }

        /// Returns pointer to inner value if already initialized.
        /// Otherwise initializes the value and returns it.
        /// Blocks while other threads are in the process of initialization.
        pub fn getOrInit(self: *Self, initLogic: anytype, init_args: anytype) *T {
            if (self.acquire()) {
                self.value = @call(.auto, initLogic, init_args);
                self.finished.store(true, .Release);
            }
            return &self.value;
        }

        /// Returns pointer to inner value if already initialized.
        /// Otherwise tries to initialize the value and returns it, or return error if it fails.
        /// Blocks while other threads are in the process of initialization.
        pub fn getOrTryInit(self: *Self, initLogic: anytype, init_args: anytype) !*T {
            if (self.acquire()) {
                errdefer self.started.store(false, .Release);
                self.value = try @call(.auto, initLogic, init_args);
                self.finished.store(true, .Release);
            }
            return &self.value;
        }

        /// Tries to acquire the write lock.
        /// returns:
        /// - true if write lock is acquired.
        /// - false if write lock is not acquirable because a write was already completed.
        /// - waits if another thread has a write in progress. if the other thread fails, this may acquire the lock.
        fn acquire(self: *Self) bool {
            while (self.started.compareAndSwap(false, true, .Acquire, .Monotonic)) |_| {
                if (self.finished.load(.Acquire)) {
                    return false;
                }
            }
            return true;
        }

        /// Returns the value if initialized.
        /// Returns error if not initialized.
        /// Blocks while other threads are in the process of initialization.
        pub fn get(self: *Self) error{NotInitialized}!*T {
            if (self.finished.load(.Acquire)) {
                return &self.value;
            }
            while (self.started.load(.Monotonic)) {
                if (self.finished.load(.Acquire)) {
                    return &self.value;
                }
            }
            return error.NotInitialized;
        }
    };
}
