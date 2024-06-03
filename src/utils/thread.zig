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

pub fn ThreadPoolTask(comptime Entry: type) type {
    return struct {
        task: Task,
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

        fn callback(task: *Task) void {
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
            while (tasks[task_index].available.cmpxchgWeak(true, false, .release, .acquire) != null) {
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
