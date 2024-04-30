const std = @import("std");

const Allocator = std.mem.Allocator;
const Condition = std.Thread.Condition;
const Mutex = std.Thread.Mutex;

const ThreadPool = @import("../sync/thread_pool.zig").ThreadPool;
const Batch = ThreadPool.Batch;

/// Spawns tasks and returns a list of threads
/// task function should take {params} ++ {start_index, end_index, thread_id}
pub fn spawnThreadTasks(
    allocator: std.mem.Allocator,
    f: anytype,
    params: anytype,
    data_len: usize,
    max_n_threads: usize,
) !std.ArrayList(std.Thread) {
    var chunk_size = data_len / max_n_threads;
    var n_threads = max_n_threads;
    if (chunk_size == 0) {
        n_threads = 1;
        chunk_size = data_len;
    }

    var handles = try std.ArrayList(std.Thread).initCapacity(allocator, n_threads);

    var start_index: usize = 0;
    var end_index: usize = 0;
    for (0..n_threads) |thread_id| {
        if (thread_id == (n_threads - 1)) {
            end_index = data_len;
        } else {
            end_index = start_index + chunk_size;
        }
        const handle = try std.Thread.spawn(.{}, f, params ++ .{ start_index, end_index, thread_id });
        handles.appendAssumeCapacity(handle);

        start_index = end_index;
    }

    return handles;
}

pub fn ThreadPoolTask(
    comptime EntryType: type,
) type {
    return struct {
        task: ThreadPool.Task,
        entry: EntryType,
        done: std.atomic.Value(bool) = std.atomic.Value(bool).init(true),

        const Self = @This();

        pub fn init(allocator: std.mem.Allocator, capacity: usize) ![]Self {
            const tasks = try allocator.alloc(Self, capacity);
            for (tasks) |*t| {
                t.* = .{
                    .entry = undefined,
                    .task = .{ .callback = Self.callback },
                };
            }
            return tasks;
        }

        fn callback(task: *ThreadPool.Task) void {
            var self: *Self = @fieldParentPtr("task", task);
            std.debug.assert(!self.done.load(.acquire));
            defer {
                self.done.store(true, .release);
            }
            self.entry.callback() catch |err| {
                std.debug.print("{s} error: {}\n", .{ @typeName(EntryType), err });
                return;
            };
        }

        pub fn queue(thread_pool: *ThreadPool, tasks: []Self, entry: EntryType) void {
            var task_i: usize = 0;
            var task_ptr = &tasks[task_i];
            while (!task_ptr.done.load(.acquire)) {
                task_i = (task_i + 1) % tasks.len;
                task_ptr = &tasks[task_i];
            }
            task_ptr.done.store(false, .release);
            task_ptr.entry = entry;

            const batch = Batch.from(&task_ptr.task);
            thread_pool.schedule(batch);
        }
    };
}

/// Wrapper for ThreadPool to run many tasks of the same type.
///
/// TaskType should have a method `run (*TaskType) void`
///
/// TODO: this should be able to work with a pre-existing thread pool.
/// Ideally this could also impose its own constraint of concurrent tasks of its own,
/// without having to spawn extra threads to monitor those threads, and without
/// blocking callers. not sure if possible, but try to balance those values.
pub fn HomogeneousThreadPool(comptime TaskType: type) type {
    // the task's return type
    const TaskResult = @typeInfo(@TypeOf(TaskType.run)).Fn.return_type.?;

    // compatibility layer between user-defined TaskType and ThreadPool's Task type,
    const TaskAdapter = struct {
        /// logic to pass to underlying thread pool
        pool_task: ThreadPool.Task = .{ .callback = Self.run },

        /// whether the task has completed.
        /// do not touch without locking the mutex.
        done: bool = false,
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
        /// - memory address may become invalid after task is joined, if caller decides to deinit results
        result: *TaskResult,

        const Self = @This();

        fn run(pool_task: *ThreadPool.Task) void {
            var self: *Self = @fieldParentPtr("pool_task", pool_task);

            self.result.* = self.typed_task.run();

            // signal completion
            self.done_lock.lock();
            self.done = true;
            self.done_notifier.broadcast();
            self.done_lock.unlock();
        }

        /// blocks until the task is complete.
        fn join(self: *Self) void {
            self.done_lock.lock();
            while (!self.done) self.done_notifier.wait(&self.done_lock);
            self.done_lock.unlock();
        }
    };

    return struct {
        allocator: std.mem.Allocator,
        pool: ThreadPool,
        tasks: std.ArrayList(TaskAdapter),
        results: std.ArrayList(TaskResult),

        pub const Task = TaskType;

        const Self = @This();

        pub fn init(allocator: std.mem.Allocator, num_threads: u32) Self {
            return .{
                .allocator = allocator,
                .pool = ThreadPool.init(.{ .max_threads = num_threads }),
                .tasks = std.ArrayList(TaskAdapter).init(allocator),
                .results = std.ArrayList(TaskResult).init(allocator),
            };
        }

        pub fn deinit(self: *Self) void {
            self.pool.shutdown();
            self.tasks.deinit();
            self.results.deinit();
            self.pool.deinit();
        }

        pub fn schedule(self: *Self, typed_task: TaskType) Allocator.Error!void {
            const result = try self.results.addOne();
            var task = try self.tasks.addOne();
            task.* = .{ .typed_task = typed_task, .result = result };
            self.pool.schedule(Batch.from(&task.pool_task));
        }

        /// blocks until all tasks are complete
        /// returns a list of any results for tasks that did not have a pointer provided
        pub fn join(self: *Self) std.ArrayList(TaskResult) {
            for (self.tasks.items) |*task| task.join();
            const results = self.results;
            self.results = std.ArrayList(TaskResult).init(self.allocator);
            self.tasks.clearRetainingCapacity();
            return results;
        }

        /// Like join, but it returns an error if any tasks failed, and otherwise discards task output.
        pub fn joinFallible(self: *Self) !void {
            for (self.join().items) |result| try result;
        }
    };
}

test "typed thread pool" {
    const AdditionTask = struct {
        a: u64,
        b: u64,
        pub fn run(self: *const @This()) u64 {
            return self.a + self.b;
        }
    };

    var pool = HomogeneousThreadPool(AdditionTask).init(std.testing.allocator, 2);
    defer pool.deinit();
    try pool.schedule(.{ .a = 1, .b = 1 });
    try pool.schedule(.{ .a = 1, .b = 2 });
    try pool.schedule(.{ .a = 1, .b = 4 });

    const results = pool.join();
    defer results.deinit();

    try std.testing.expect(3 == results.items.len);
    try std.testing.expect(2 == results.items[0]);
    try std.testing.expect(3 == results.items[1]);
    try std.testing.expect(5 == results.items[2]);
}
