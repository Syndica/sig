const std = @import("std");

const Allocator = std.mem.Allocator;
const Condition = std.Thread.Condition;
const Mutex = std.Thread.Mutex;

const ThreadPool = @import("../sync/thread_pool.zig").ThreadPool;
const Batch = ThreadPool.Batch;

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

    var thread_pool = try HomogeneousThreadPool(S).init(
        allocator,
        @intCast(n_threads),
        @intCast(n_threads),
    );
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
///
/// TODO: Support the max tasks constraint without blocking the current thread.
/// This will require changes the underlying ThreadPool implementation.
pub fn HomogeneousThreadPool(comptime TaskType: type) type {
    // the task's return type
    const TaskResult = @typeInfo(@TypeOf(TaskType.run)).@"fn".return_type.?;

    // compatibility layer between user-defined TaskType and ThreadPool's Task type,
    const TaskAdapter = struct {
        /// logic to pass to underlying thread pool
        pool_task: ThreadPool.Task = .{ .callback = Self.run },

        /// whether the task has completed.
        /// do not touch without locking the mutex.
        done: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
        /// locks done to avoid infinite wait on the condition
        /// due to a potential race condition.
        done_lock: Mutex = .{},
        /// broadcasts to joiners when done becomes true
        done_notifier: Condition = .{},

        /// The task's inputs and state.
        /// TaskType.run is the task's logic, which uses the data in this struct.
        typed_task: TaskType,

        /// the return value of the task
        /// - points to undefined data until the task is complete
        /// - memory address may become invalid after task is joined, if caller
        ///   decides to deinit results
        result: TaskResult = undefined,

        /// It was already incremented when this task was scheduled, and it
        /// needs to be decremented when this task is completed.
        num_running_tasks: *std.atomic.Value(usize),

        const Self = @This();

        fn run(pool_task: *ThreadPool.Task) void {
            var self: *Self = @fieldParentPtr("pool_task", pool_task);

            self.result = self.typed_task.run();

            // signal completion
            assert(0 != self.num_running_tasks.fetchSub(1, .acq_rel));
            self.done_lock.lock();
            self.done.store(true, .release);
            self.done_notifier.broadcast();
            self.done_lock.unlock();
        }

        /// blocks until the task is complete.
        fn join(self: *Self) void {
            self.done_lock.lock();
            while (!self.done.load(.acquire)) self.done_notifier.wait(&self.done_lock);
            self.done_lock.unlock();
        }
    };

    return struct {
        pool_allocator: ?Allocator,
        task_pool: std.heap.MemoryPool(TaskAdapter),
        pool: *ThreadPool,
        tasks: std.ArrayListUnmanaged(*TaskAdapter) = .{},
        num_running_tasks: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
        max_concurrent_tasks: ?usize,

        pub const Task = TaskType;
        pub const TaskError = @typeInfo(TaskResult).error_union.error_set;

        const Self = @This();

        pub fn init(
            allocator: Allocator,
            num_threads: u32,
            max_concurrent_tasks: ?usize,
        ) !Self {
            const pool = try allocator.create(ThreadPool);
            pool.* = ThreadPool.init(.{ .max_threads = num_threads });

            return .{
                .pool_allocator = allocator,
                .task_pool = std.heap.MemoryPool(TaskAdapter).init(allocator),
                .pool = pool,
                .max_concurrent_tasks = max_concurrent_tasks,
            };
        }

        pub fn initBorrowed(
            allocator: Allocator,
            pool: *ThreadPool,
            max_concurrent_tasks: ?usize,
        ) !Self {
            return .{
                .pool_allocator = null,
                .task_pool = std.heap.MemoryPool(TaskAdapter).init(allocator),
                .pool = pool,
                .max_concurrent_tasks = max_concurrent_tasks,
            };
        }

        /// join before calling this
        pub fn deinit(const_self: Self, schedule_allocator: Allocator) void {
            var self = const_self;
            if (self.pool_allocator) |pool_allocator| {
                self.pool.shutdown();
                self.pool.deinit();
                pool_allocator.destroy(self.pool);
            }
            assert(0 == self.tasks.items.len);
            self.tasks.deinit(schedule_allocator);
            assert(self.task_pool.reset(.free_all));
        }

        /// Blocks until the task is scheduled. It will be immediate unless
        /// you've already scheduled max_concurrent_tasks and none have
        /// finished.
        pub fn schedule(
            self: *Self,
            allocator: Allocator,
            typed_task: TaskType,
        ) !void {
            while (true) {
                if (try self.trySchedule(allocator, typed_task)) return;
                try std.Thread.yield();
            }
        }

        /// Attempt to schedule the task and return whether the task was
        /// scheduled.
        ///
        /// Returns false if max_concurrent_tasks were already
        /// scheduled, and they're all still running.
        ///
        /// Never returns false if max_concurrent_tasks == null
        pub fn trySchedule(
            self: *Self,
            allocator: Allocator,
            typed_task: TaskType,
        ) Allocator.Error!bool {
            if (self.max_concurrent_tasks) |max| {
                const running = self.num_running_tasks.load(.monotonic);
                assert(running <= max);
                if (running == max) {
                    return false;
                }
                assert(max >= self.num_running_tasks.fetchAdd(1, .monotonic));
            } else {
                _ = self.num_running_tasks.fetchAdd(1, .monotonic);
            }

            const task = try self.task_pool.create();
            errdefer self.task_pool.destroy(task);
            task.* = .{ .typed_task = typed_task, .num_running_tasks = &self.num_running_tasks };

            try self.tasks.append(allocator, task);

            self.pool.schedule(Batch.from(&task.pool_task));
            return true;
        }

        /// Checks if all tasks are complete.
        /// Returns a result indicating the outcome:
        /// - done: all succeeded.
        /// - pending: some are still running.
        /// - err: all completed, and at least one failed.
        pub fn pollFallible(self: *Self) union(enum) { done, pending, err: TaskError } {
            for (self.tasks.items) |task| {
                if (!task.done.load(.acquire)) {
                    return .pending;
                }
            }
            return if (self.joinFallible()) |_| .done else |err| .{ .err = err };
        }

        /// Blocks until all tasks are complete.
        /// Returns a list of all return values.
        pub fn join(self: *Self, allocator: Allocator) Allocator.Error![]TaskResult {
            for (self.tasks.items) |task| task.join();

            const results = try allocator.alloc(TaskResult, self.tasks.items.len);
            errdefer allocator.free(results);

            for (self.tasks.items, 0..) |task, i| {
                results[i] = task.result;
            }

            assert(self.task_pool.reset(.retain_capacity));
            self.tasks.clearRetainingCapacity();

            return results;
        }

        /// Like join, but it returns an error if any tasks failed, and otherwise discards task output.
        /// This will return the first error encountered which may be inconsistent between runs.
        pub fn joinFallible(self: *Self) !void {
            defer {
                assert(self.task_pool.reset(.retain_capacity));
                self.tasks.clearRetainingCapacity();
            }

            for (self.tasks.items) |task| task.join();
            for (self.tasks.items) |task| _ = try task.result;
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
    const AdditionTask = struct {
        a: u64,
        b: u64,
        pub fn run(self: *const @This()) u64 {
            return self.a + self.b;
        }
    };

    var pool = try HomogeneousThreadPool(AdditionTask).init(
        std.testing.allocator,
        2,
        3,
    );
    defer pool.deinit(std.testing.allocator);
    try pool.schedule(std.testing.allocator, .{ .a = 1, .b = 1 });
    try pool.schedule(std.testing.allocator, .{ .a = 1, .b = 2 });
    try pool.schedule(std.testing.allocator, .{ .a = 1, .b = 4 });

    const results = try pool.join(std.testing.allocator);
    defer std.testing.allocator.free(results);

    try std.testing.expect(3 == results.len);
    try std.testing.expect(2 == results[0]);
    try std.testing.expect(3 == results[1]);
    try std.testing.expect(5 == results[2]);
}
