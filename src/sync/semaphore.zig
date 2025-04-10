const std = @import("std");

/// comparison with std.Thread.Semaphore:
/// - offers a non-blocking alternative to `wait`
/// - uses a futex instead of mutex + condition
pub const Semaphore = struct {
    permits: std.atomic.Value(u32),

    pub fn init(initial: u32) Semaphore {
        return .{ .permits = std.atomic.Value(u32).init(initial) };
    }

    pub fn wait(self: *Semaphore) void {
        var deadline = std.Thread.Futex.Deadline.init(null);
        while (true) {
            if (self.tryAcquire()) return;
            deadline.wait(&self.permits, 0) catch unreachable;
        }
    }

    pub fn timedWait(self: *Semaphore, timeout: u64) error{Timeout}!void {
        var deadline = std.Thread.Futex.Deadline.init(timeout);
        while (true) {
            if (self.tryAcquire()) return;
            try deadline.wait(&self.permits, 0);
        }
    }

    /// non-blocking alternative to wait
    pub fn tryAcquire(self: *Semaphore) bool {
        var permits = self.permits.load(.monotonic);
        while (permits != 0) {
            if (self.permits.cmpxchgWeak(permits, permits - 1, .acquire, .monotonic)) |update| {
                permits = update;
                std.atomic.spinLoopHint();
            } else {
                if (permits > 1) std.Thread.Futex.wake(&self.permits, 1);
                return true;
            }
        }
        return false;
    }

    pub fn post(self: *Semaphore) void {
        _ = self.permits.fetchAdd(1, .release);
        std.Thread.Futex.wake(&self.permits, 1);
    }
};
