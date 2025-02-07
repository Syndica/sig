const std = @import("std");

const Condition = std.Thread.Condition;
const Mutex = std.Thread.Mutex;

const ThreadPool = @import("../sync/thread_pool.zig").ThreadPool;
const Batch = ThreadPool.Batch;

pub fn IntrusiveMPSC(comptime Node: type) type {
    return struct {
        const Self = @This();

        head: std.atomic.Value(?*Node) = std.atomic.Value(?*Node).init(null),
        tail: std.atomic.Value(?*Node) = std.atomic.Value(?*Node).init(null),

        /// Push a node to the MPSC list (safe to call from multiple threads).
        /// Returns true if this pushed to an empty MPSC.
        pub fn push(self: *Self, node: *Node) bool {
            // Push the node to the end of the list with a swap.
            node.next = null;
            const old_tail = self.tail.swap(node, .acq_rel);

            // Link the previous tail node to the one we just pushed. No tail means we're the first
            // so it links to `self.head` instead (which should be null).
            const link = if (old_tail) |prev| &prev.next else &self.head.raw;
            @atomicStore(?*Node, link, node, .release);

            // Return if the tail was empty (first to push).
            return old_tail == null;
        }

        pub fn pop(self: *Self) ?*Node {
            // Get current head ptr (is null when empty).
            const head = self.head.load(.acquire) orelse return null;

            // Check if theres a next node, if so then it means tail doesnt point to it so it can be
            // consumed and returned. Just make sure to set the next as the new head below.
            const next = @atomicLoad(?*Node, &head.next, .acquire) orelse blk: {
                // There's no next node. This might be the last. If so, have to steal it from the
                // tail to make sure no one else can access it. Before doing so the head must be
                // set to null, as on a successful steal a subsequent push will set the head.
                self.head.store(null, .monotonic);
                _ = self.tail.cmpxchgStrong(head, null, .acq_rel, .acquire) orelse return head;

                // A new node was pushed or the thread which pushed hasn't set this node.next yet.
                // Wait for it to do so (spinning should be fine here as this window is only between
                // the `swap()` and the `store()` above).
                while (true) : (std.atomic.spinLoopHint()) {
                    break :blk @atomicLoad(?*Node, &head.next, .acquire) orelse continue;
                }
            };

            self.head.store(next, .monotonic);
            return head;
        }

        /// Returns true if the MPSC is empty (safe to call from multiple threads).
        pub fn isEmpty(self: *const Self) bool {
            return self.head.load(.seq_cst) == null;
        }
    };
}

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
    allocator: std.mem.Allocator,
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

    var thread_pool = try HomogeneousThreadPool(S).init(
        allocator,
        @intCast(n_threads),
        n_threads,
    );
    defer thread_pool.deinit();

    var start_index: usize = 0;
    for (0..n_threads) |thread_id| {
        const end_index = if (thread_id == n_threads - 1) config.data_len else (start_index + chunk_size);
        thread_pool.schedule(.{
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

pub fn ThreadPoolTask(comptime Entry: type) type {
    return struct {
        task: ThreadPool.Task,
        entry: Entry,
        available: std.atomic.Value(bool) = std.atomic.Value(bool).init(true),
        result: CallbackError!void = {},
        const Self = @This();

        const CallbackError = blk: {
            const CallbackFn = @TypeOf(Entry.callback);
            const CallbackResult = @typeInfo(CallbackFn).Fn.return_type.?;
            break :blk switch (@typeInfo(CallbackResult)) {
                .ErrorUnion => |info| info.error_set,
                else => error{},
            };
        };

        pub fn init(allocator: std.mem.Allocator, task_count: usize) ![]Self {
            const tasks = try allocator.alloc(Self, task_count);
            @memset(tasks, .{
                .entry = undefined,
                .task = .{ .callback = Self.callback },
            });
            return tasks;
        }

        fn callback(task: *ThreadPool.Task) void {
            const self: *Self = @fieldParentPtr("task", task);
            self.result = undefined;

            std.debug.assert(!self.available.load(.acquire));
            defer self.available.store(true, .release);

            self.result = self.entry.callback();
        }

        /// Waits for any of the tasks in the slice to become available. Once one does,
        /// it is atomically set to be unavailable, and its index is returned.
        pub fn awaitAndAcquireFirstAvailableTask(tasks: []Self, start_index: usize) usize {
            var task_index = start_index;
            while (tasks[task_index].available.cmpxchgWeak(true, false, .acquire, .monotonic) != null) {
                task_index = (task_index + 1) % tasks.len;
            }
            return task_index;
        }

        pub fn blockUntilCompletion(task: *Self) void {
            while (!task.available.load(.acquire)) {
                std.atomic.spinLoopHint();
            }
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

        pub fn init(
            allocator: std.mem.Allocator,
            num_threads: u32,
            num_tasks: u64,
        ) !Self {
            return .{
                .allocator = allocator,
                .pool = ThreadPool.init(.{ .max_threads = num_threads }),
                .tasks = try std.ArrayList(TaskAdapter).initCapacity(allocator, num_tasks),
                .results = try std.ArrayList(TaskResult).initCapacity(allocator, num_tasks),
            };
        }

        pub fn deinit(self: *Self) void {
            self.pool.shutdown();
            self.tasks.deinit();
            self.results.deinit();
            self.pool.deinit();
        }

        pub fn schedule(self: *Self, typed_task: TaskType) void {
            // NOTE: this breaks other pre-scheduled tasks on re-allocs so we dont
            // allow re-allocations
            const result = self.results.addOneAssumeCapacity();
            var task = self.tasks.addOneAssumeCapacity();
            task.* = .{ .typed_task = typed_task, .result = result };
            self.pool.schedule(Batch.from(&task.pool_task));
        }

        /// blocks until all tasks are complete
        /// returns a list of any results for tasks that did not have a pointer provided
        /// NOTE: if this fails then the result field is left in a bad state in which case the
        /// thread pool should be discarded/reset
        pub fn join(self: *Self) std.mem.Allocator.Error!std.ArrayList(TaskResult) {
            for (self.tasks.items) |*task| task.join();
            const results = self.results;
            self.results = try std.ArrayList(TaskResult).initCapacity(self.allocator, self.tasks.capacity);
            self.tasks.clearRetainingCapacity();
            return results;
        }

        /// Like join, but it returns an error if any tasks failed, and otherwise discards task output.
        /// NOTE: this will return the first error encountered which may be inconsistent between runs.
        pub fn joinFallible(self: *Self) !void {
            const results = try self.join();
            for (results.items) |result| try result;
            results.deinit();
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

    var pool = try HomogeneousThreadPool(AdditionTask).init(
        std.testing.allocator,
        2,
        3,
    );
    defer pool.deinit();
    pool.schedule(.{ .a = 1, .b = 1 });
    pool.schedule(.{ .a = 1, .b = 2 });
    pool.schedule(.{ .a = 1, .b = 4 });

    const results = try pool.join();
    defer results.deinit();

    try std.testing.expect(3 == results.items.len);
    try std.testing.expect(2 == results.items[0]);
    try std.testing.expect(3 == results.items[1]);
    try std.testing.expect(5 == results.items[2]);
}
