const std = @import("std");
const sig = @import("sig");
const xev = @import("xev");
const types = @import("types.zig");
const protocol = @import("protocol.zig");

const ThreadPool = sig.sync.ThreadPool;
const Channel = sig.sync.Channel;

/// Serialization task wrapper for the thread pool.
/// TODO(perf): we just heap allocate these for simplicity.
/// Right now that means IO thread allocates, thread pool threads deallocate,
/// but we could optimize with a pool.
const SerializeTask = struct {
    task: ThreadPool.Task,
    job: types.SerializeJob,
    /// Channel to send the result back to the IO loop thread.
    commit_channel: *Channel(types.CommitMsg),
    /// Async handle to wake the IO loop of commit messages ready to process.
    loop_async: *xev.Async,
    /// Atomic flag to avoid redundant waking of IO thread: only notify if not already pending.
    notify_pending: *std.atomic.Value(bool),
    allocator: std.mem.Allocator,

    fn deinit(self: *SerializeTask) void {
        self.job.event_data.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    fn execute(task: *ThreadPool.Task) void {
        const self: *SerializeTask = @alignCast(@fieldParentPtr("task", task));
        defer self.deinit();

        const start_ns = std.time.nanoTimestamp();

        const result: types.CommitResult = if (protocol.serializeNotification(
            self.allocator,
            self.job.sub_id,
            self.job.event_data,
            self.job.encoding,
            self.job.sub_method,
        )) |p|
            .{ .payload = p }
        else |err|
            .{ .serialize_error = err };

        const end_ns = std.time.nanoTimestamp();
        const serialize_ns_i = end_ns - start_ns;
        const serialize_ns: u64 = if (serialize_ns_i > 0)
            @intCast(serialize_ns_i)
        else
            0;
        const pipeline_ns_i = end_ns - self.job.submitted_ns;
        const pipeline_latency_ns: u64 = if (pipeline_ns_i > 0)
            @intCast(pipeline_ns_i)
        else
            0;
        const payload_bytes: u64 = switch (result) {
            .payload => |p| @intCast(p.payload().len),
            .serialize_error => 0,
        };

        const commit_msg = types.CommitMsg{
            .sub_id = self.job.sub_id,
            .index = self.job.index,
            .result = result,
            .serialize_ns = serialize_ns,
            .pipeline_latency_ns = pipeline_latency_ns,
            .payload_bytes = payload_bytes,
        };

        self.commit_channel.send(commit_msg) catch {
            result.deinit(self.allocator);
            return;
        };

        const already_pending = self.notify_pending.swap(true, .release);
        if (!already_pending) {
            self.loop_async.notify() catch {
                _ = self.notify_pending.swap(false, .release);
            };
        }
    }
};

/// Submit a serialization job to the thread pool.
pub fn submitSerializeJob(
    pool: *ThreadPool,
    allocator: std.mem.Allocator,
    job: types.SerializeJob,
    commit_channel: *Channel(types.CommitMsg),
    loop_async: *xev.Async,
    notify_pending: *std.atomic.Value(bool),
) !void {
    const t = try allocator.create(SerializeTask);
    t.* = .{
        .task = .{ .callback = SerializeTask.execute },
        .job = job,
        .commit_channel = commit_channel,
        .loop_async = loop_async,
        .notify_pending = notify_pending,
        .allocator = allocator,
    };
    // TODO(perf): could maybe be batched.
    pool.schedule(.{ .head = &t.task, .tail = &t.task, .len = 1 });
}
