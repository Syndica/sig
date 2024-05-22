const std = @import("std");

const ThreadPool = @import("../sync/thread_pool.zig").ThreadPool;
const Task = ThreadPool.Task;
const Batch = ThreadPool.Batch;

/// Spawns tasks and outputs the list of handles for the spawned threads.
/// Task function should accept `params ++ .{ start_index, end_index, thread_id }` as its parameter tuple.
pub fn spawnThreadTasks(
    /// This list is cleared, and then filled with the handles for the spawned task threads.
    /// On successful call, all threads were appropriately spawned.
    handles: *std.ArrayList(std.Thread),
    comptime taskFn: anytype,
    params: anytype,
    data_len: usize,
    max_n_threads: usize,
) (std.mem.Allocator.Error || std.Thread.SpawnError)!void {
    const chunk_size, const n_threads = blk: {
        var chunk_size = data_len / max_n_threads;
        var n_threads = max_n_threads;
        if (chunk_size == 0) {
            n_threads = 1;
            chunk_size = data_len;
        }
        break :blk .{ chunk_size, n_threads };
    };

    handles.clearRetainingCapacity();
    try handles.ensureTotalCapacityPrecise(n_threads);

    var start_index: usize = 0;
    for (0..n_threads) |thread_id| {
        const end_index = if (thread_id == n_threads - 1) data_len else (start_index + chunk_size);
        // NOTE(trevor): instead of just `try`ing, we could fill an optional diagnostic struct
        //               which inform the caller how much coverage over `data_len` was achieved,
        //               so that they could handle its coverage themselves instead of just having
        //               to kill all the successfully spawned threads.
        const handle = try std.Thread.spawn(.{}, taskFn, params ++ .{ start_index, end_index, thread_id });
        handles.appendAssumeCapacity(handle);
        start_index = end_index;
    }
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
