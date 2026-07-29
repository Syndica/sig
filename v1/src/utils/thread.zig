const std = @import("std");
const tracy = @import("tracy");
const sig = @import("../sig.zig");

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

        fn run(self: @This()) @typeInfo(@TypeOf(taskFn)).@"fn".return_type.? {
            return @call(.auto, taskFn, self.fcn_params ++ .{self.task_params});
        }
    };

    const thread_pool = try ScopedThreadPool(S.run).init(allocator, n_threads);
    defer thread_pool.deinit(allocator);

    var start_index: usize = 0;
    for (0..n_threads) |thread_id| {
        const end_index = if (thread_id == n_threads - 1)
            config.data_len
        else
            (start_index + chunk_size);
        try thread_pool.schedule(allocator, .{.{
            .task_params = .{
                .start_index = start_index,
                .end_index = end_index,
                .thread_id = thread_id,
            },
            .fcn_params = config.params,
        }});

        start_index = end_index;
    }

    try thread_pool.join();
}

/// A thread pool wrapper for a function.
/// TODO: investigate all uses of this and replace them with direct ThreadPool.zig usage.
pub fn ScopedThreadPool(comptime func: anytype) type {
    const Args = std.meta.ArgsTuple(@TypeOf(func));
    const ReturnType = @typeInfo(@TypeOf(func)).@"fn".return_type.?;
    const Error = switch (@typeInfo(ReturnType)) {
        .error_union => |e| e.error_set,
        else => error{},
    };

    return struct {
        // task dispatch/sync
        thread_pool: ThreadPool,
        wait_group: std.Thread.WaitGroup = .{},

        // task allocation
        scoped_tasks: std.SegmentedList(ScopedTask, 0) = .{},
        free_list: ?*ScopedTask = null,
        incoming_free_list: std.atomic.Value(?*ScopedTask) = .init(null),

        // error tracking
        has_error: std.atomic.Value(bool) = .init(false),
        set_error: Error = undefined,

        borrowed: bool,

        const Self = @This();
        const ScopedTask = struct {
            pool_task: ThreadPool.Task = .{ .callback = run },
            next: ?*ScopedTask = null,
            pool: *Self,
            args: Args,

            fn run(pool_task: *ThreadPool.Task) void {
                const zone = tracy.Zone.init(@src(), .{ .name = "ScopedTask.run" });
                defer zone.deinit();

                const self: *ScopedTask = @alignCast(@fieldParentPtr("pool_task", pool_task));
                switch (@typeInfo(ReturnType)) {
                    .error_union => @call(.auto, func, self.args) catch |e| {
                        if (!self.pool.has_error.swap(true, .monotonic))
                            self.pool.set_error = e;
                    },
                    else => @call(.auto, func, self.args),
                }

                // Read out *WaitGroup from self as, after pushing to free list, task may be reused.
                const wg = &self.pool.wait_group;
                defer wg.finish();

                const free_list = &self.pool.incoming_free_list;
                var top = free_list.load(.monotonic);
                while (true) {
                    self.next = top;
                    top = free_list.cmpxchgWeak(top, self, .release, .monotonic) orelse break;
                }
            }
        };

        pub fn init(allocator: Allocator, max_threads: usize) !*Self {
            const self = try allocator.create(Self);
            self.* = .{
                .thread_pool = .init(.{ .max_threads = @intCast(max_threads) }),
                .borrowed = false,
            };
            return self;
        }

        pub fn deinit(self: *Self, allocator: Allocator) void {
            self.wait_group.wait();
            self.scoped_tasks.deinit(allocator);
            if (!self.borrowed) {
                self.thread_pool.shutdown();
                self.thread_pool.deinit();
            }
            allocator.destroy(self);
        }

        /// Spawn a task to the function using the given args.
        /// Must be called by the single init/deinit thread.
        pub fn schedule(self: *Self, allocator: Allocator, args: Args) !void {
            const free_task = self.free_list orelse self.incoming_free_list.swap(null, .acquire);
            if (free_task) |task| self.free_list = task.next;

            const task = free_task orelse try self.scoped_tasks.addOne(allocator);
            task.* = .{ .args = args, .pool = self };

            self.wait_group.start();
            self.thread_pool.schedule(.from(&task.pool_task));
        }

        /// Wait for all previously scheduled tasks to finish. If any of the scheduled tasks fails,
        /// this consumes their error and returns it. The pool remains usable after.
        /// Must be called by the single init/deinit thread.
        pub fn join(self: *Self) Error!void {
            self.wait_group.wait();
            self.wait_group = .{};

            self.scoped_tasks.clearRetainingCapacity();
            self.incoming_free_list = .init(null);
            self.free_list = null;

            if (self.has_error.load(.monotonic)) {
                self.has_error.store(false, .monotonic);
                return self.set_error;
            }
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
        var global: std.atomic.Value(u64) = .init(0);

        pub fn inc(value: u64) void {
            _ = global.fetchAdd(value, .monotonic);
        }
    };

    const pool = try ScopedThreadPool(AdditionTask.inc).init(allocator, 3);
    defer pool.deinit(allocator);

    try pool.schedule(allocator, .{1});
    try pool.schedule(allocator, .{2});
    try pool.schedule(allocator, .{3});
    try pool.join();
    try std.testing.expectEqual(6, AdditionTask.global.load(.monotonic));

    try pool.schedule(allocator, .{4});
    try pool.join();
    try std.testing.expectEqual(10, AdditionTask.global.load(.monotonic));
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
