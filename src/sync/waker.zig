const std = @import("std");
const Parker = @import("parker.zig").Parker;
const Token = @import("bounded.zig").TempSlot;
const thread_context = @import("thread_context.zig");
const ThreadLocalContext = thread_context.ThreadLocalContext;
const ThreadState = thread_context.ThreadState;
const ArrayList = std.ArrayList;
const Atomic = std.atomic.Value;
const Mutex = std.Thread.Mutex;

pub const Waker = struct {
    allocator: std.mem.Allocator,
    sleepers: ArrayList(SleepingOperation),
    is_empty: Atomic(bool),
    mutex: Mutex,

    const Self = @This();

    pub inline fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .sleepers = ArrayList(SleepingOperation).init(allocator),
            .is_empty = Atomic(bool).init(true),
            .mutex = .{},
        };
    }

    pub inline fn deinit(self: *Self) void {
        self.sleepers.deinit();
    }

    pub inline fn registerOperation(self: *Self, operation_id: OperationId, context: *ThreadLocalContext) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.sleepers.append(.{
            .operation_id = operation_id,
            .thread_context = context,
        }) catch @panic("could not append sleeper: OutOfMemory!");

        self.is_empty.store(
            false,
            .SeqCst,
        );
    }

    pub inline fn unregisterOperation(self: *Self, operation_id: OperationId) ?SleepingOperation {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (0.., self.sleepers.items) |i, entry| {
            if (entry.operation_id == operation_id) {

                // if there's only a single item, then after this swapRemove, we'll be empty
                self.is_empty.store(
                    self.sleepers.items.len == 1,
                    .SeqCst,
                );

                return self.sleepers.swapRemove(i);
            }
        }

        self.is_empty.store(
            self.sleepers.items.len == 0,
            .SeqCst,
        );
        return null;
    }

    /// NOTE: This assumes we've already acquired the self.mutex lock
    inline fn tryAwakeSleeper(self: *Self) ?SleepingOperation {
        const this_thread_id = std.Thread.getCurrentId();

        for (0.., self.sleepers.items) |i, sleeper| {
            // for each sleeping operation, try and find one that:
            //
            // 1. doesn't have this thread id (different thread than the caller)
            //                  AND
            // 2. can update its thread context's state successfully (it's currently in the .waiting state)
            //
            // If found: unpark the thread, remove and return it
            if (sleeper.thread_context.id != this_thread_id and
                sleeper.thread_context.tryUpdateFromWaitingStateTo(.{ .operation = sleeper.operation_id }) == null)
            {
                // awaken the thread
                sleeper.thread_context.parker.unpark();
                return self.sleepers.orderedRemove(i);
            }
        }

        return null;
    }

    pub inline fn disconnectAll(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.sleepers.items) |sleeper| {
            // for each sleeping operation, try and update state to disconnected
            if (sleeper.thread_context.tryUpdateFromWaitingStateTo(.disconnected) == null) {
                // if updated, awaken the thread so it can exit op
                sleeper.thread_context.parker.unpark();
            }
        }
    }

    pub inline fn notify(self: *Self) void {
        if (!self.is_empty.load(.SeqCst)) {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (!self.is_empty.load(.SeqCst)) {
                _ = self.tryAwakeSleeper();
                self.is_empty.store(
                    self.sleepers.items.len == 0,
                    .SeqCst,
                );
            }
        }
    }
};

const SleepingOperation = struct {
    /// A unique operation identifier that's pending completion post sleeping.
    /// We use this to remove this sleeper in the case we need to abort/channel
    /// is disconnected.
    operation_id: OperationId,
    /// Context associated with the thread owning this operation. Used for parking/unparking.
    thread_context: *ThreadLocalContext,
};

/// A unique identifier of a `Token` which will be used in some channel operation.
/// We use a `usize` because the `ThreadState` enum is updated atomically in
/// `ThreadLocalContext.state` by casting the pointer to the `Token` as a `usize`.
pub const OperationId = usize;
