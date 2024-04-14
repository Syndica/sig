const std = @import("std");
const builtin = @import("builtin");
const Atomic = std.atomic.Atomic;
const c = std.os.system;
const CLOCK_MONOTONIC = c.CLOCK.MONOTONIC;
const CLOCK_REALTIME = c.CLOCK.REALTIME;

pub const Parker = struct {
    state: Atomic(usize),
    lock: c.pthread_mutex_t,
    cond: c.pthread_cond_t,

    const Self = @This();

    const State = enum {
        empty,
        parked,
        notified,
    };

    const SUCCESS = c.E.SUCCESS;

    pub fn init() Self {
        var self = Self{
            .state = Atomic(usize).init(@intFromEnum(State.empty)),
            .lock = c.PTHREAD_MUTEX_INITIALIZER,
            .cond = undefined,
        };

        switch (builtin.os.tag) {
            .linux => {
                var attr = c.pthread_condattr_t{};
                assertEq(c.pthread_condattr_init(&attr), SUCCESS);
                assertEq(c.pthread_condattr_setclock(&attr, CLOCK_MONOTONIC), SUCCESS);
                assertEq(c.pthread_cond_init(&self.cond, &attr), SUCCESS);
                assertEq(c.pthread_condattr_destroy(&attr), SUCCESS);
            },
            .macos => {
                self.cond = c.PTHREAD_COND_INITIALIZER;
            },
            else => {
                @compileError("only linux or macos supported for thread parking");
            },
        }

        return self;
    }

    pub fn deinit(self: *Self) void {
        assertEq(c.pthread_cond_destroy(&self.cond), SUCCESS);
        assertEq(c.pthread_mutex_destroy(&self.lock), SUCCESS);
    }

    pub fn park(self: *Self) void {
        // if we were previously notified, we return early
        if (self.state.compareAndSwap(
            @intFromEnum(State.notified),
            @intFromEnum(State.empty),
            .SeqCst,
            .SeqCst,
        ) == null) {
            return;
        }

        assertEq(c.pthread_mutex_lock(&self.lock), SUCCESS);

        if (self.state.compareAndSwap(
            @intFromEnum(State.empty),
            @intFromEnum(State.parked),
            .SeqCst,
            .SeqCst,
        )) |other| {
            var other_state: State = @enumFromInt(other);
            switch (other_state) {
                .notified => {
                    // We must read here, even though we know it will be `NOTIFIED`.
                    // This is because `unpark` may have been called again since we read
                    // `NOTIFIED` in the `compare_exchange` above. We must perform an
                    // acquire operation that synchronizes with that `unpark` to observe
                    // any writes it made before the call to unpark. To do that we must
                    // read from the write it made to `state`.
                    var old: State = @enumFromInt(self.state.swap(@intFromEnum(State.empty), .SeqCst));
                    assertEq(c.pthread_mutex_unlock(&self.lock), SUCCESS);
                    assertEq(old, State.notified);
                    return;
                },
                else => {
                    assertEq(c.pthread_mutex_unlock(&self.lock), SUCCESS);
                    @panic("inconsistent park state");
                },
            }
        }

        while (true) {
            assertEq(c.pthread_cond_wait(&self.cond, &self.lock), SUCCESS);

            if (self.state.compareAndSwap(
                @intFromEnum(State.notified),
                @intFromEnum(State.empty),
                .SeqCst,
                .SeqCst,
            )) |_| {
                continue; // spurious wakeup, go back to sleep
            }
            break;
        }

        assertEq(c.pthread_mutex_unlock(&self.lock), SUCCESS);
    }

    pub fn parkTimeout(self: *Self, duration_ns: u64) void {
        // Like `park` above we have a fast path for an already-notified thread, and
        // afterwards we start coordinating for a sleep.
        // return quickly.
        if (self.state.compareAndSwap(
            @intFromEnum(State.notified),
            @intFromEnum(State.empty),
            .SeqCst,
            .SeqCst,
        ) == null) {
            return;
        }

        assertEq(c.pthread_mutex_lock(&self.lock), SUCCESS);

        if (self.state.compareAndSwap(
            @intFromEnum(State.empty),
            @intFromEnum(State.parked),
            .SeqCst,
            .SeqCst,
        )) |other| {
            var other_state: State = @enumFromInt(other);
            switch (other_state) {
                .notified => {
                    // We must read here, even though we know it will be `NOTIFIED`.
                    // This is because `unpark` may have been called again since we read
                    // `NOTIFIED` in the `compare_exchange` above. We must perform an
                    // acquire operation that synchronizes with that `unpark` to observe
                    // any writes it made before the call to unpark. To do that we must
                    // read from the write it made to `state`.
                    var old: State = @enumFromInt(self.state.swap(@intFromEnum(State.empty), .SeqCst));
                    assertEq(c.pthread_mutex_unlock(&self.lock), SUCCESS);
                    assertEq(old, State.notified);
                },
                else => {
                    assertEq(c.pthread_mutex_unlock(&self.lock), SUCCESS);
                    @panic("inconsistent park state");
                },
            }
        }

        var now = std.os.timespec{
            .tv_sec = 0,
            .tv_nsec = 0,
        };

        if (builtin.os.tag == .macos) {
            std.os.clock_gettime(@intCast(CLOCK_REALTIME), &now) catch unreachable;
        } else if (builtin.os.tag == .linux) {
            std.os.clock_gettime(@intCast(CLOCK_MONOTONIC), &now) catch unreachable;
        } else {
            @compileError("only macos or linux supported!");
        }

        var secs: u64 = duration_ns / std.time.ns_per_s;
        var nsecs: u64 = duration_ns % std.time.ns_per_s;

        // add duration to now
        now.tv_sec +|= @intCast(secs);
        now.tv_nsec +|= @intCast(nsecs);
        var out = c.pthread_cond_timedwait(&self.cond, &self.lock, &now);
        std.debug.assert((out == SUCCESS) or (out == c.E.TIMEDOUT));

        switch (@as(State, @enumFromInt(self.state.swap(@intFromEnum(State.empty), .SeqCst)))) {
            .notified, .parked => assertEq(c.pthread_mutex_unlock(&self.lock), SUCCESS),
            else => {
                assertEq(c.pthread_mutex_unlock(&self.lock), SUCCESS);
                @panic("inconsistent park timeout state");
            },
        }
    }

    pub fn unpark(self: *Self) void {
        switch (@as(State, @enumFromInt(self.state.swap(@intFromEnum(State.notified), .SeqCst)))) {
            .empty, .notified => return,
            .parked => {},
        }

        // in the case of a spurious wake up, we need to do the following:
        assertEq(c.pthread_mutex_lock(&self.lock), SUCCESS);
        assertEq(c.pthread_mutex_unlock(&self.lock), SUCCESS);
        assertEq(c.pthread_cond_signal(&self.cond), SUCCESS);
    }
};

threadlocal var thread_local_parker: Parker = Parker.init();
pub fn getThreadLocal() *Parker {
    return &thread_local_parker;
}

pub fn assertEq(left: anytype, right: @TypeOf(left)) void {
    std.debug.assert(left == right);
}

fn testParkedThread(parker: *Parker) void {
    std.debug.print("attempting to park parkedThread\n", .{});
    parker.park();
    std.debug.print("successfully unparked in parkedThread\n", .{});
}

fn testParkedTimedThread(parker: *Parker) void {
    std.debug.print("attempting to park parkedThread\n", .{});
    parker.parkTimeout(std.time.ns_per_s * 1);
    std.debug.print("successfully unparked in parkedThread\n", .{});
}

pub fn testUnparkingThread(parker: *Parker) void {
    std.debug.print("attempting to unpark parkedThread\n", .{});
    parker.unpark();
}

test "parker untimed" {
    std.debug.print("Parking test (no timeout):\n", .{});
    var now = try std.time.Instant.now();
    var parker = Parker.init();

    var parked_handle = try std.Thread.spawn(.{}, testParkedThread, .{&parker});
    var unparker_handle = try std.Thread.spawn(.{}, testUnparkingThread, .{&parker});

    parked_handle.join();
    unparker_handle.join();

    var new_now = try std.time.Instant.now();
    std.debug.print("took: {any} nsecs\n", .{new_now.since(now)});
}

test "parker timed" {
    std.debug.print("Parking test (1 second timeout):\n", .{});
    var now = try std.time.Instant.now();

    var parker = Parker.init();

    var parked_handle = try std.Thread.spawn(.{}, testParkedTimedThread, .{&parker});

    parked_handle.join();

    var new_now = try std.time.Instant.now();
    std.debug.print("took: {} secs\n", .{new_now.since(now) / std.time.ns_per_s});
}

fn testParkerIsDifferentPerThread(out_ptr: *u64) void {
    var parker = getThreadLocal();
    out_ptr.* = @intFromPtr(parker);
}

test "parker should remain per-thread" {
    var parker = getThreadLocal();
    var out_ptr: usize = undefined;
    var other_thread_handle = try std.Thread.spawn(.{}, testParkerIsDifferentPerThread, .{&out_ptr});

    other_thread_handle.join();

    try std.testing.expect(out_ptr != @intFromPtr(parker));
    try std.testing.expect(@intFromPtr(getThreadLocal()) == @intFromPtr(parker));
}
