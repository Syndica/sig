const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;
const Condition = std.Thread.Condition;
const Mutex = std.Thread.Mutex;
const ResetEvent = std.Thread.ResetEvent;
const Rc = sig.sync.Rc;
const Semaphore = sig.sync.Semaphore;

const ThreadPool = @import("../sync/thread_pool.zig").ThreadPool;
const Batch = ThreadPool.Batch;

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

pub fn SpawnThreadTasksParams(comptime TaskFn: type) type {
    return struct {
        data_len: usize,
        max_threads: usize,
        params: Params,

        pub const Params = std.meta.ArgsTuple(@Type(.{ .Fn = blk: {
            var info = @typeInfo(TaskFn).Fn;
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
    const chunk_size, const n_threads = chunkSizeAndThreadCount(config.data_len, config.max_threads);

    const S = struct {
        task_params: TaskParams,
        fcn_params: @TypeOf(config).Params,

        fn run(self: *const @This()) @typeInfo(@TypeOf(taskFn)).Fn.return_type.? {
            return @call(.auto, taskFn, self.fcn_params ++ .{self.task_params});
        }
    };

    var pool = ThreadPool.init(.{ .max_threads = @intCast(n_threads) });
    var scheduler = try HomogeneousTaskScheduler(S).init(allocator, &pool, @intCast(n_threads));
    defer scheduler.deinit(allocator);

    var start_index: usize = 0;
    for (0..n_threads) |thread_id| {
        const end_index = if (thread_id == n_threads - 1) config.data_len else (start_index + chunk_size);
        scheduler.scheduleNow(allocator, .{
            .task_params = .{
                .start_index = start_index,
                .end_index = end_index,
                .thread_id = thread_id,
            },
            .fcn_params = config.params,
        });

        start_index = end_index;
    }

    try scheduler.joinFallible(allocator);
}

/// Run and monitor many tasks of the same type that in a thread pool.
///
/// TaskType must have a method `run (*TaskType) anytype`
///
/// Using this in multiple threads concurrently has undefined behavior.
pub fn HomogeneousTaskScheduler(comptime TaskType: type) type {
    // the task's return type
    const TaskResult = @typeInfo(@TypeOf(TaskType.run)).Fn.return_type.?;

    // compatibility layer between user-defined TaskType and ThreadPool's Task type,
    const TaskAdapter = struct {
        allocator: Allocator,
        /// logic to pass to underlying thread pool
        pool_task: ThreadPool.Task = .{ .callback = TaskAdapter.run },

        /// available if the task is done
        semaphore: Semaphore,

        scheduler_semaphore: Rc(Semaphore),

        /// The task's inputs and state.
        /// TaskType.run is the task's logic, which uses the data in this struct.
        typed_task: TaskType,

        /// the return value of the task
        /// - points to undefined data until the task is complete
        /// - memory address may become invalid after task is joined, if caller decides to deinit results
        result: TaskResult,

        ref_count: sig.sync.ReferenceCounter,

        const TaskAdapter = @This();

        fn run(pool_task: *ThreadPool.Task) void {
            var self: *TaskAdapter = @fieldParentPtr("pool_task", pool_task);

            self.result = self.typed_task.run();

            // signal completion
            self.semaphore.post();
            self.scheduler_semaphore.payload().post();

            self.deinit();
        }

        /// blocks until the task is complete.
        /// tasks can only be joined once.
        fn join(self: *TaskAdapter) void {
            self.semaphore.wait();
        }

        fn deinit(self: *TaskAdapter) void {
            if (self.ref_count.release()) {
                self.scheduler_semaphore.deinit(self.allocator);
                self.allocator.destroy(self);
            }
        }
    };

    return struct {
        /// not owned by this struct
        pool: *ThreadPool,
        tasks: std.ArrayListUnmanaged(*TaskAdapter),
        semaphore: Rc(Semaphore),
        max_tasks: usize,

        pub const Task = TaskType;

        const Self = @This();

        pub fn init(allocator: Allocator, pool: *ThreadPool, max_tasks: u64) !Self {
            var tasks = try std.ArrayListUnmanaged(*TaskAdapter).initCapacity(allocator, max_tasks);
            errdefer tasks.deinit(allocator);

            const sema = try Rc(Semaphore).create(allocator);
            sema.payload().* = Semaphore.init(0);

            return .{
                .pool = pool,
                .tasks = tasks,
                .max_tasks = max_tasks,
                .semaphore = sema,
            };
        }

        pub fn deinit(self: *Self, allocator: Allocator) void {
            for (self.tasks.items) |task| task.join();
            self.tasks.deinit(allocator);
        }

        pub const ScheduleResult = union(enum) {
            /// task was scheduled successfully, and it did not replace another task.
            success,
            /// the task was scheduled successfully, and it replaced another
            /// task, since max_tasks have already been scheduled. the returned
            /// TaskResult is the result of that other task finished, which this
            /// one has replaced.
            replaced_completed: TaskResult,
            would_block,
        };

        /// returns when the task has been scheduled. waits if necessary.
        pub fn schedule(
            self: *Self,
            allocator: Allocator,
            typed_task: TaskType,
        ) Allocator.Error!?TaskResult {
            return switch (try self.scheduleImpl(allocator, typed_task, true)) {
                .success => null,
                .would_block => unreachable,
                .replaced_completed => |result| result,
            };
        }

        /// schedule immediately. undefined behavior if max_tasks have already been scheduled.
        pub fn scheduleNow(
            self: *Self,
            allocator: Allocator,
            typed_task: TaskType,
        ) Allocator.Error!void {
            std.debug.assert(.success == try self.scheduleImpl(allocator, typed_task, false));
        }

        fn scheduleImpl(
            self: *Self,
            allocator: Allocator,
            typed_task: TaskType,
            /// if all tasks are occupied and unfinished, should we wait until
            /// one is free, or return error.WouldBlock?
            block: bool,
        ) Allocator.Error!ScheduleResult {
            var ret: ScheduleResult = .success;

            if (self.tasks.items.len < self.max_tasks) {
                const task = try self.tasks.addOne(allocator);
                task.* = try allocator.create(TaskAdapter);
                task.*.* = .{
                    .allocator = allocator,
                    .semaphore = Semaphore.init(0),
                    .scheduler_semaphore = self.semaphore,
                    .typed_task = typed_task,
                    .result = undefined,
                    .ref_count = .{},
                };
                std.debug.assert(task.*.ref_count.acquire());
                self.pool.schedule(Batch.from(&task.*.pool_task));
            } else {
                // identify that a task is available to be replaced
                if (block) {
                    self.semaphore.payload().wait();
                } else if (!self.semaphore.payload().tryAcquire()) {
                    return .would_block;
                }

                // recycle the finished task
                for (self.tasks.items) |task| {
                    if (task.semaphore.tryAcquire()) {
                        ret = .{ .replaced_completed = task.result };
                        task.typed_task = typed_task;
                        task.result = undefined;
                        self.pool.schedule(Batch.from(&task.pool_task));
                        break;
                    }
                } else unreachable;
            }

            return ret;
        }

        /// blocks until all tasks are complete.
        ///
        /// returns a list of results for all tasks whose results have not been
        /// returned by `schedule`
        pub fn join(
            self: *Self,
            allocator: Allocator,
        ) std.mem.Allocator.Error!std.ArrayListUnmanaged(TaskResult) {
            const results = try std.ArrayListUnmanaged(TaskResult)
                .initCapacity(allocator, self.tasks.items.len);
            for (self.tasks.items) |task| {
                task.join();
                results.appendAssumeCapacity(task.result);
                task.deinit(allocator);
            }
        }

        /// Like join, but it returns an error if any tasks failed, and
        /// otherwise discards task output.
        ///
        /// NOTE: this will return the first error encountered which may be
        /// inconsistent between runs.
        pub fn joinFallible(self: *Self, allocator: Allocator) !void {
            var results = try self.join(allocator);
            for (results.items) |result| try result;
            results.deinit(allocator);
        }
    };
}

fn testSpawnThreadTasks(
    values: []const u64,
    sums: []u64,
    task: TaskParams,
) !void {
    std.debug.assert(@import("builtin").is_test);
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
    const AdditionTask = struct {
        a: u64,
        b: u64,
        pub fn run(self: *const @This()) u64 {
            return self.a + self.b;
        }
    };

    var pool = ThreadPool.init(.{ .max_threads = 3 });
    defer pool.shutdown();
    var scheduler = try HomogeneousTaskScheduler(AdditionTask)
        .init(std.testing.allocator, &pool, 2);
    defer scheduler.deinit(std.testing.allocator);

    try std.testing.expectEqual(
        .success,
        scheduler.schedule(std.testing.allocator, .{ .a = 1, .b = 1 }),
    );
    std.time.sleep(std.time.ns_per_ms);
    try std.testing.expectEqual(
        .success,
        scheduler.schedule(std.testing.allocator, .{ .a = 1, .b = 2 }),
    );
    const next = scheduler.schedule(std.testing.allocator, .{ .a = 1, .b = 4 });
    try std.testing.expectEqual(
        HomogeneousTaskScheduler(AdditionTask).ScheduleResult{ .replaced_completed = 2 },
        next,
    );

    var results = try scheduler.join(std.testing.allocator);
    defer results.deinit(std.testing.allocator);

    try std.testing.expect(2 == results.items.len);
    try std.testing.expect(5 == results.items[0]);
    try std.testing.expect(3 == results.items[1]);
}
