const std = @import("std");

const ThreadPool = @import("../sync/thread_pool.zig").ThreadPool;
const Task = ThreadPool.Task;
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
        task: Task,
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

        fn callback(task: *Task) void {
            var self: Self = @fieldParentPtr("task", task);
            std.debug.assert(!self.done.load(std.atomic.Ordering.Acquire));
            defer {
                self.done.store(true, std.atomic.Ordering.release);
            }
            self.entry.callback() catch |err| {
                std.debug.print("{s} error: {}\n", .{ @typeName(EntryType), err });
                return;
            };
        }

        pub fn queue(thread_pool: *ThreadPool, tasks: []Self, entry: EntryType) void {
            var task_i: usize = 0;
            var task_ptr = &tasks[task_i];
            while (!task_ptr.done.load(std.atomic.Ordering.Acquire)) {
                task_i = (task_i + 1) % tasks.len;
                task_ptr = &tasks[task_i];
            }
            task_ptr.done.store(false, std.atomic.Ordering.release);
            task_ptr.entry = entry;

            const batch = Batch.from(&task_ptr.task);
            thread_pool.schedule(batch);
        }
    };
}
