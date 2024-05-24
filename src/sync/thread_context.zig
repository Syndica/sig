const std = @import("std");
const parker = @import("parker.zig");
const OperationId = @import("waker.zig").OperationId;
const TempSlot = @import("bounded.zig").TempSlot;
const Backoff = @import("backoff.zig").Backoff;
const Parker = parker.Parker;
const Atomic = std.atomic.Value;

threadlocal var thread_local_context: ThreadLocalContext = .{
    .state = Atomic(usize).init(0),
    .parker = undefined,
    .id = undefined,
};

pub fn getThreadLocalContext() *ThreadLocalContext {
    return &thread_local_context;
}

/// `ThreadLocalContext` holds thread specfic information such as what
/// it's current state is, parker and it's id.
///
/// **NOTE:** Whenever it's acquired it's important to remember to call `reset()`
/// so that it can be properly (re)initialized.
pub const ThreadLocalContext = struct {
    /// Selected operation.
    state: Atomic(usize),
    /// Thread handle.
    parker: *Parker,
    /// Thread id.
    id: std.Thread.Id,

    const Self = @This();

    /// tries to update internal `state` from `.waiting` to `new_state` returning current state
    /// if comparison failed (or state isn't `.waiting`), meaning it failed to update the state successfully.
    /// If successful, returns `null`.
    pub inline fn tryUpdateFromWaitingStateTo(self: *Self, new_state: ThreadState) ?ThreadState {
        return ThreadState.fromUsize(self.state.cmpxchgStrong(
            ThreadState.toUsize(.waiting),
            new_state.toUsize(),
            .acq_rel,
            .acquire,
        ) orelse return null);
    }

    pub fn reset(self: *Self) void {
        self.parker = parker.getThreadLocal();
        self.id = std.Thread.getCurrentId();
        self.state.store(ThreadState.toUsize(.waiting), .release);
    }

    pub fn waitUntil(self: *Self, timeout: ?std.time.Instant) ThreadState {
        var backoff = Backoff.init();

        while (true) {
            const state = ThreadState.fromUsize(self.state.load(.acquire));
            if (state != .waiting) return state;

            if (backoff.isCompleted())
                break
            else
                backoff.snooze();
        }

        // park the thread as we are waiting longer
        while (true) {
            const state = ThreadState.fromUsize(self.state.load(.acquire));
            if (state != .waiting) return state;

            if (timeout) |end| {
                const now = std.time.Instant.now() catch unreachable;

                if (now.timestamp.tv_sec < end.timestamp.tv_sec and now.timestamp.tv_nsec < end.timestamp.tv_nsec)
                    self.parker.parkTimeout(timespecDifferenceInNs(end, now))
                else
                    return self.tryUpdateFromWaitingStateTo(.aborted) orelse .aborted;
            } else self.parker.park();
        }
    }
};

fn timespecDifferenceInNs(a: std.time.Instant, b: std.time.Instant) u64 {
    const sec_diff = a.timestamp.tv_sec - b.timestamp.tv_sec;
    const nsec_diff = a.timestamp.tv_nsec - b.timestamp.tv_nsec;
    const total_nsec = sec_diff * std.time.ns_per_s + nsec_diff;
    return @intCast(total_nsec);
}

pub const ThreadState = union(enum(u8)) {
    /// Still waiting for an operation.
    waiting,
    /// The attempt to block the current thread has been aborted.
    aborted,
    /// An operation became ready because a channel is disconnected.
    disconnected,
    /// An operation became ready because a message can be sent or received.
    operation: OperationId,

    const Self = @This();

    pub fn fromUsize(val: usize) Self {
        return switch (val) {
            0 => .waiting,
            1 => .aborted,
            2 => .disconnected,
            else => .{ .operation = val },
        };
    }

    pub fn toUsize(self: Self) usize {
        return switch (self) {
            .waiting => 0,
            .aborted => 1,
            .disconnected => 2,
            .operation => |op| op,
        };
    }
};

test "thread state conversion to/from usize" {
    var token = TempSlot(u64).uninitialized();

    var state = ThreadState{ .operation = token.toOperationId() };
    const as_usize = state.toUsize();
    const other_state = ThreadState.fromUsize(as_usize);

    try std.testing.expectEqual(state, other_state);
    try std.testing.expectEqual(&token, TempSlot(u64).fromOperationId(other_state.operation));
}
