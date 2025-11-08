const std = @import("std");
const sig = @import("../sig.zig");
const tracy = @import("tracy");

const Allocator = std.mem.Allocator;
const ThreadPool = @import("../sync/thread_pool.zig").ThreadPool;

const assert = std.debug.assert;

pub const TaskParams = struct {
    start_index: usize,
    end_index: usize,
    thread_id: usize,
};

fn chunkSizeAndThreadCount(data_len: usize, max_n_threads: usize) struct { usize, usize } {
    var n_threads = max_n_threads;
    var chunk_size = data_len / n_threads;
    if (chunk_size == 0) {
        // default to one thread for all the data
        n_threads = 1;
        chunk_size = data_len;
    }
    return .{ chunk_size, n_threads };
}

/// Returns after the duration completes or exit signal is set, indicating which
/// was the cause of the return.
pub fn sleep(
    duration: sig.time.Duration,
    exit: struct {
        signal: ?*const std.atomic.Value(bool) = null,
        poll_interval: sig.time.Duration = .fromMillis(10),
    },
) enum { time, signal } {
    if (exit.signal == null) {
        std.Thread.sleep(duration.asNanos());
        return .time;
    }

    const signal = exit.signal.?;
    const num_intervals = duration.asNanos() / exit.poll_interval.asNanos();
    const remainder_nanos = duration.asNanos() % exit.poll_interval.asNanos();
    for (0..num_intervals) |_| {
        if (signal.load(.monotonic)) return .signal;
        std.Thread.sleep(exit.poll_interval.asNanos());
    }
    if (signal.load(.monotonic)) return .signal;
    std.Thread.sleep(remainder_nanos);

    return .time;
}

pub fn SpawnThreadTasksParams(comptime TaskFn: type) type {
    return struct {
        data_len: usize,
        max_threads: usize,
        params: Params,

        pub const Params = std.meta.ArgsTuple(@Type(.{ .@"fn" = blk: {
            var info = @typeInfo(TaskFn).@"fn";
            info.params = info.params[0 .. info.params.len - 1];
            break :blk info;
        } }));
    };
}

/// this function spawns a number of threads to run the same task function.
pub fn spawnThreadTasks(
    allocator: Allocator,
    comptime taskFn: anytype,
    config: SpawnThreadTasksParams(@TypeOf(taskFn)),
) !void {
    const chunk_size, const n_threads =
        chunkSizeAndThreadCount(config.data_len, config.max_threads);

    const S = struct {
        task_params: TaskParams,
        fcn_params: @TypeOf(config).Params,

        fn run(self: *const @This()) @typeInfo(@TypeOf(taskFn)).@"fn".return_type.? {
            return @call(.auto, taskFn, self.fcn_params ++ .{self.task_params});
        }
    };

    var thread_pool = try HomogeneousThreadPool(S).init(allocator, @intCast(n_threads));
    defer thread_pool.deinit(allocator);

    var start_index: usize = 0;
    for (0..n_threads) |thread_id| {
        const end_index = if (thread_id == n_threads - 1)
            config.data_len
        else
            (start_index + chunk_size);
        try thread_pool.schedule(allocator, .{
            .task_params = .{
                .start_index = start_index,
                .end_index = end_index,
                .thread_id = thread_id,
            },
            .fcn_params = config.params,
        });

        start_index = end_index;
    }

    try thread_pool.joinFallible();
}

/// Wrapper for ThreadPool to run many tasks of the same type.
///
/// TaskType should have a method `run (*TaskType) void`
///
/// This struct should only be used in a single thread. All the interactions
/// with the child threads are safe, but it's not safe to call this struct's
/// methods from multiple threads.
pub fn HomogeneousThreadPool(comptime TaskType: type) type {
    return struct {
        pool: union(enum) {
            owned: *ThreadPool,
            borrowed: *ThreadPool,
        },

        tasks: std.SegmentedList(TaskNode, 0) = .{},
        free_list: std.atomic.Value(?*TaskNode) = .init(null),
        local_free_list: ?*TaskNode = null,

        task_error: ?TaskError = null,
        join_event: std.Thread.ResetEvent = .{},
        state: std.atomic.Value(packed struct(u32) {
            waiting: bool = false,
            has_error: bool = false,
            pending: u30 = 0,
        }) = .init(.{}),

        const Self = @This();
        const zone_prefix = "HomogeneousThreadPool(" ++ @typeName(TaskType) ++ ")";

        pub const Task = TaskType;
        pub const TaskResult = @typeInfo(@TypeOf(TaskType.run)).@"fn".return_type.?;
        pub const TaskError = @typeInfo(TaskResult).error_union.error_set;

        const TaskNode = struct {
            next: ?*TaskNode = null,
            pool_task: ThreadPool.Task = .{ .callback = run },
            homogeneous_pool: *Self,
            typed_task: TaskType,

            fn run(pool_task: *ThreadPool.Task) void {
                const zone = tracy.Zone.init(@src(), .{ .name = zone_prefix ++ ".run()" });
                defer zone.deinit();

                const self: *TaskNode = @alignCast(@fieldParentPtr("pool_task", pool_task));
                self.homogeneous_pool.completeTask(
                    self,
                    if (self.typed_task.run()) |_| @as(?TaskError, null) else |err| err,
                );
            }
        };

        pub fn init(allocator: Allocator, num_threads: u32) !Self {
            const pool = try allocator.create(ThreadPool);
            pool.* = ThreadPool.init(.{ .max_threads = num_threads });
            return .{ .pool = .{ .owned = pool } };
        }

        pub fn initBorrowed(pool: *ThreadPool) Self {
            return .{ .pool = .{ .borrowed = pool } };
        }

        /// join before calling this
        pub fn deinit(self: *const Self, allocator: Allocator) void {
            if (self.state.load(.monotonic).pending > 0) {
                @panic("did not join before deiniting thread pool");
            }

            if (self.pool == .owned) {
                self.pool.owned.shutdown();
                self.pool.owned.deinit();
                allocator.destroy(self.pool.owned);
            }

            var mut_tasks = self.tasks;
            mut_tasks.deinit(allocator);
        }

        pub fn getThreadPool(self: Self) *ThreadPool {
            switch (self.pool) {
                inline else => |pool| return pool,
            }
        }

        pub fn schedule(self: *Self, allocator: Allocator, typed_task: TaskType) !void {
            const node = blk: {
                if (self.local_free_list orelse self.free_list.swap(null, .acquire)) |node| {
                    self.local_free_list = node.next;
                    break :blk node;
                }
                break :blk try self.tasks.addOne(allocator);
            };

            node.* = .{
                .homogeneous_pool = self,
                .typed_task = typed_task,
            };

            _ = self.state.fetchAdd(.{ .pending = 1 }, .monotonic);
            self.getThreadPool().schedule(.from(&node.pool_task));
        }

        fn completeTask(self: *Self, node: *TaskNode, err: ?TaskError) void {
            if (err) |e| {
                @branchHint(.unlikely);
                if (!self.state.fetchOr(.{ .has_error = true }, .monotonic).has_error) {
                    self.task_error = e;
                }
            }

            var top = self.free_list.load(.monotonic);
            while (true) {
                node.next = top;
                top = self.free_list.cmpxchgWeak(top, node, .release, .monotonic) orelse break;
            }

            const state = self.state.fetchSub(.{ .pending = 1 }, .release);
            if (state.waiting and state.pending == 1) {
                self.join_event.set();
            }
        }

        // If there are tasks running, returns .pending.
        // If all tasks completed, return done if all success or err if one failed.
        pub fn pollFallible(self: *Self) union(enum) { pending, done, err: TaskError } {
            const state = self.state.load(.acquire);
            assert(!state.waiting);
            if (state.pending > 0) {
                return .pending;
            }

            self.consumeErrorAndReset() catch |e| return .{ .err = e };
            return .done;
        }

        // Wait for all tasks to complete. If one of the tasks failed, returns its error.
        pub fn joinFallible(self: *Self) TaskError!void {
            const zone = tracy.Zone.init(@src(), .{ .name = zone_prefix ++ ".join()" });
            defer zone.deinit();

            const state = self.state.fetchAdd(.{ .waiting = true }, .acquire);
            assert(!state.waiting);
            if (state.pending > 0) {
                self.join_event.wait();
            }

            return self.consumeErrorAndReset();
        }

        fn consumeErrorAndReset(self: *Self) TaskError!void {
            const state = self.state.swap(.{}, .acquire);
            assert(state.pending == 0);
            self.join_event.reset();

            self.free_list = .init(null);
            self.local_free_list = null;
            self.tasks.clearRetainingCapacity();

            defer self.task_error = null;
            if (self.task_error) |err| return err;
        }
    };
}

fn testSpawnThreadTasks(
    values: []const u64,
    sums: []u64,
    task: TaskParams,
) !void {
    assert(@import("builtin").is_test);
    var sum: u64 = 0;
    for (task.start_index..task.end_index) |i| {
        sum += values[i];
    }
    sums[task.thread_id] = sum;
}

test spawnThreadTasks {
    const n_threads = 4;
    const allocator = std.testing.allocator;

    const sums = try allocator.alloc(u64, n_threads);
    defer allocator.free(sums);

    try spawnThreadTasks(
        std.testing.allocator,
        testSpawnThreadTasks,
        .{
            .data_len = 10,
            .max_threads = n_threads,
            .params = .{
                &[_]u64{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 },
                sums,
            },
        },
    );

    var total_sum: u64 = 0;
    for (sums) |sum| {
        total_sum += sum;
    }
    try std.testing.expectEqual(55, total_sum);
}

test "typed thread pool" {
    const allocator = std.testing.allocator;
    const AdditionTask = struct {
        a: u64,

        var global_sum: std.atomic.Value(u64) = .init(0);

        pub fn run(self: *const @This()) !void {
            if (self.a == 0) return error.Zero;
            _ = global_sum.fetchAdd(self.a, .monotonic);
        }
    };

    var pool = try HomogeneousThreadPool(AdditionTask).init(allocator, 2);
    defer pool.deinit(allocator);

    // normal tasks
    try pool.schedule(allocator, .{ .a = 1 });
    try pool.schedule(allocator, .{ .a = 2 });
    try pool.schedule(allocator, .{ .a = 3 }); // more tasks than pool size.
    switch (pool.pollFallible()) {
        .pending, .done => {}, // ok
        .err => unreachable, // .a != 0 in any task
    }

    try pool.joinFallible();
    try std.testing.expectEqual(AdditionTask.global_sum.load(.monotonic), 1 + 2 + 3);
    try std.testing.expect(pool.pollFallible() == .done);

    // failing tasks
    try pool.schedule(allocator, .{ .a = 0 });
    try std.testing.expectError(error.Zero, pool.joinFallible());
    try std.testing.expectEqual(AdditionTask.global_sum.load(.monotonic), 1 + 2 + 3); // no change
    try std.testing.expect(pool.pollFallible() == .done); // joinFallible() consumed error

    // mixing succesful tasks with failing tasks
    for ([_]usize{ 1, 2, 10 }) |num_failing| {
        const start = AdditionTask.global_sum.load(.monotonic);

        for (0..50) |_| try pool.schedule(allocator, .{ .a = 2 });
        for (0..num_failing) |_| try pool.schedule(allocator, .{ .a = 0 });
        for (0..50) |_| try pool.schedule(allocator, .{ .a = 2 });

        switch (pool.pollFallible()) {
            .pending => try std.testing.expectError(error.Zero, pool.joinFallible()),
            .err => |e| try std.testing.expectEqual(error.Zero, e),
            .done => unreachable,
        }

        const end = start + (50 * 2) + (50 * 2);
        try std.testing.expectEqual(AdditionTask.global_sum.load(.monotonic), end);
    }
}

test sleep {
    var timer = sig.time.Timer.start();
    try std.testing.expectEqual(.time, sleep(.fromMillis(12), .{}));
    try std.testing.expect(timer.lap().gt(.fromMillis(11)));

    var exit = std.atomic.Value(bool).init(false);
    try std.testing.expectEqual(.time, sleep(.fromMillis(12), .{ .signal = &exit }));
    try std.testing.expect(timer.lap().gt(.fromMillis(11)));

    exit.store(true, .monotonic);
    try std.testing.expectEqual(.signal, sleep(.fromMillis(12), .{ .signal = &exit }));
    try std.testing.expect(timer.lap().lt(.fromMillis(11)));
}
