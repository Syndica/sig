const std = @import("std");
const xev = @import("xev");
const sig = @import("sig");

const log = std.log.scoped(.jrpc_ws_runtime);

const types = @import("types.zig");
const methods = @import("methods.zig");
const sub_map_mod = @import("sub_map.zig");
const serialize_mod = @import("serialize.zig");
const metrics_mod = @import("metrics.zig");
const NotifQueue = @import("NotifQueue.zig");

const Channel = sig.sync.Channel;
const ThreadPool = sig.sync.ThreadPool;
const NotifPayload = sig.sync.RcSlice(u8);
/// Type to track alignment of RcSlice bytes for allocator free
pub const ReleasedPayloadBytes = @TypeOf((@as(NotifPayload, undefined)).release().?);

/// Shared runtime context passed to all handlers and the loop thread.
///
/// For shutdown you must continue running the RuntimeContext loop and ThreadPool until inflight_jobs
/// drops to 0, then you can stop the loop and deint the context and threadpool.
pub const RuntimeContext = struct {
    allocator: std.mem.Allocator,
    /// Subscription map: matches subscriptions and events to subscription queues.
    sub_map: *sub_map_mod.RPCSubMap,
    /// Queue for receiving events from producers (account updates, etc).
    inbound_event_queue: *Channel(types.EventMsg),
    /// Queue for receiving commit messages from serialization workers.
    commit_queue: *Channel(types.CommitMsg),
    /// Async handle for waking the loop thread to drain queues.
    loop_async: *xev.Async,
    async_completion: xev.Completion = .{},
    /// Thread pool for running serialization jobs.
    serialization_pool: *ThreadPool,
    /// Metrics counters for monitoring and benchmarking.
    metrics: *metrics_mod.Metrics,
    /// Maximum batch size in bytes for notifications received by clients before ensuring TCP flush.
    max_batch_bytes: u64,
    loop: *xev.Loop,
    /// True when an async wake has been requested but not yet observed by the loop thread.
    /// Used to coalesce multiple wake requests into a single wakeup event on the loop.
    notify_pending: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// Set to false to stop async wakeups, which in turn stops draining queues.
    running: bool = true,
    /// Queues that have newly committed notifications this drain cycle.
    /// Built during commit processing; drained immediately after.
    pending_wake_queues: std.ArrayList(*NotifQueue) = .{},
    /// Number of serialization jobs submitted but not yet committed.
    /// Incremented on job submit, decremented on commit receive.
    /// Used during shutdown to wait for all in-flight work to complete.
    inflight_jobs: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    /// Optional queue for off-loop payload allocator free work.
    payload_free_queue: ?*Channel(ReleasedPayloadBytes) = null,

    /// Free resources owned directly by RuntimeContext.
    /// IMPORTANT: shutdown the websocket server and wait for inflight_jobs to settle to 0 before calling deinit.
    pub fn deinit(self: *RuntimeContext) void {
        const inflight_jobs = self.inflight_jobs.load(.acquire);
        if (inflight_jobs != 0) {
            log.err(
                "deinit called with inflight_jobs = {}, wait for it to settle to 0 first",
                .{inflight_jobs},
            );
        }
        self.pending_wake_queues.deinit(self.allocator);
    }

    /// Request an async wake on the loop, coalescing duplicate wakeups.
    pub fn requestWakeup(self: *RuntimeContext) void {
        const already_pending = self.notify_pending.swap(true, .release);
        if (!already_pending) {
            self.loop_async.notify() catch |err| {
                log.err("loop async notify failed: {}", .{err});
                _ = self.notify_pending.swap(false, .release);
            };
        }
    }

    pub fn armAsyncWait(self: *RuntimeContext) void {
        self.loop_async.wait(self.loop, &self.async_completion, RuntimeContext, self, onAsyncWakeup);
    }

    fn onAsyncWakeup(
        self_opt: ?*RuntimeContext,
        _: *xev.Loop,
        _: *xev.Completion,
        result: xev.Async.WaitError!void,
    ) xev.CallbackAction {
        result catch |e| {
            log.err("async wait error: {}", .{e});
            return .disarm;
        };

        const self = self_opt orelse return .disarm;
        _ = self.notify_pending.swap(false, .acquire);
        self.drainInboundEvents();
        self.drainCommitQueue();

        if (self.running) {
            self.armAsyncWait();
        }
        return .disarm;
    }

    /// Drain all pending inbound events from producers.
    fn drainInboundEvents(self: *RuntimeContext) void {
        while (self.inbound_event_queue.tryReceive()) |event_msg| {
            self.metrics.events_received += 1;

            switch (event_msg.event_data) {
                .account => |account_data| {
                    defer account_data.rc.release(self.allocator);
                    for (self.sub_map.entries.items) |entry| {
                        self.submitAccountDerivedJobs(entry, account_data);
                    }
                },
                else => {
                    for (self.sub_map.entries.items) |entry| {
                        if (entry.key.method == event_msg.method) {
                            self.submitJobForEntry(
                                entry,
                                event_msg.event_data,
                                .base64,
                                entry.key.method,
                            );
                        }
                    }
                },
            }
        }

        self.metrics.inbound_drain_calls += 1;
    }

    fn submitAccountDerivedJobs(
        self: *RuntimeContext,
        entry: sub_map_mod.MapEntry,
        account_data: types.AccountEventData,
    ) void {
        const awp = account_data.rc.get();
        switch (entry.key.method) {
            .account => {
                if (awp.pubkey.equals(&entry.key.params.account.pubkey)) {
                    self.submitJobForEntry(entry, .{
                        .account = .{ .rc = account_data.rc.acquire(), .slot = account_data.slot },
                    }, entry.key.params.account.encoding, .account);
                }
            },
            .program => {
                if (awp.account.owner.equals(&entry.key.params.program.program_id)) {
                    self.submitJobForEntry(entry, .{
                        .account = .{ .rc = account_data.rc.acquire(), .slot = account_data.slot },
                    }, entry.key.params.program.encoding, .program);
                }
            },
            else => {},
        }
    }

    fn submitJobForEntry(
        self: *RuntimeContext,
        entry: sub_map_mod.MapEntry,
        event_data: types.EventData,
        encoding: methods.Encoding,
        sub_method: types.SubMethod,
    ) void {
        const q = entry.queue;
        if (q.subscriberCount() == 0) {
            event_data.deinit(self.allocator);
            return;
        }

        const idx: ?u64 = switch (q.commit_path) {
            .reserved => q.reserveUncommitted(),
            .direct => null,
        };
        q.inflight_sers += 1;

        const job = types.SerializeJob{
            .sub_id = entry.sub_id,
            .index = idx,
            .event_data = event_data,
            .encoding = encoding,
            .sub_method = sub_method,
            .submitted_ns = std.time.nanoTimestamp(),
        };

        serialize_mod.submitSerializeJob(
            self.serialization_pool,
            self.allocator,
            job,
            self.commit_queue,
            self.loop_async,
            &self.notify_pending,
        ) catch {
            event_data.deinit(self.allocator);
            q.inflight_sers -= 1;
            if (idx) |i| {
                q.cancelReservation(i);
            }
            self.maybeRemoveIdleQueue(entry.sub_id, q);
            return;
        };
        _ = self.inflight_jobs.fetchAdd(1, .monotonic);
        self.metrics.serialize_tasks_allocated += 1;
    }

    /// Drain all pending commit messages from serialization workers.
    fn drainCommitQueue(self: *RuntimeContext) void {
        // TODO: this is draining *all* pending, this could overwhelm queue capacity
        // before clients have a chance to consume. I don't think there's really a way
        // around it, the clients must keep up with the commit rate or messages will be
        // missed. I think what could be done is have large queue size (4096?) to absorb
        // bursts and give clients time to consume but kick/eject clients that are consistently
        // not keeping pace to avoid retaining too may payloads due to full queues.
        while (self.commit_queue.tryReceive()) |msg| {
            self.handleCommitMsg(msg);
        }

        self.wakePendingQueueSubscribers();

        self.metrics.commit_drain_calls += 1;
    }

    fn handleCommitMsg(self: *RuntimeContext, msg: types.CommitMsg) void {
        _ = self.inflight_jobs.fetchSub(1, .monotonic);
        self.metrics.serialize_jobs += 1;
        self.metrics.serialize_ns += msg.serialize_ns;
        self.metrics.serialize_pipeline_ns += msg.pipeline_latency_ns;
        self.metrics.serialize_payload_bytes += msg.payload_bytes;

        const entry = self.sub_map.getById(msg.sub_id) orelse {
            switch (msg.result) {
                .payload => |p| releasePayload(self, p),
                .serialize_error => {},
            }
            // this should never happen: queues are not removed until all in-flight jobs finish
            log.err("orphan commit message: sub_id not found in sub_map (invariant violation)", .{});
            return;
        };

        const q = entry.queue;
        defer {
            q.inflight_sers -= 1;
            self.maybeRemoveIdleQueue(msg.sub_id, q);
        }

        switch (msg.result) {
            .serialize_error => {
                self.metrics.serialize_errors += 1;
            },
            .payload => |p| {
                if (q.subscriberCount() == 0) {
                    releasePayload(self, p);
                    return;
                }

                const newly_committed = q.commitSerialized(msg.index, p) catch {
                    releasePayload(self, p);
                    log.err("commitSerialized failed: queue commit-path/index mismatch" ++
                        " or invalid reserved state (invariant violation)", .{});
                    return;
                };

                if (newly_committed > 0) {
                    self.metrics.notifications_committed += @intCast(newly_committed);
                    self.markQueueForWaking(q);
                }
            },
        }
    }

    fn markQueueForWaking(self: *RuntimeContext, q: *NotifQueue) void {
        if (!q.wake_pending) {
            self.pending_wake_queues.append(self.allocator, q) catch {
                log.warn("pending_wake_queues append failed: OOM; wake skipped for this cycle", .{});
                return;
            };
            q.wake_pending = true;
        }
    }

    fn wakePendingQueueSubscribers(self: *RuntimeContext) void {
        for (self.pending_wake_queues.items) |q| {
            q.wake_pending = false;
            for (q.subscribers.items) |h| {
                h.sendNext();
            }
        }
        self.pending_wake_queues.clearRetainingCapacity();
    }

    pub fn maybeRemoveIdleQueue(self: *RuntimeContext, sub_id: types.SubId, q: *NotifQueue) void {
        if (q.subscriberCount() == 0 and q.inflight_sers == 0) {
            self.sub_map.removeById(sub_id);
        }
    }
};

/// Release a refcounted notification payload, freeing the backing
/// allocation when the last reference is dropped. Kept as a helper
/// to make it easy to to add payload memory metrics or send to another
/// thread for freeing if desired.
pub fn releasePayload(ctx: *RuntimeContext, payload: NotifPayload) void {
    if (payload.release()) |bytes| {
        if (ctx.payload_free_queue) |payload_free_queue| {
            payload_free_queue.send(bytes) catch {
                freePayloadBytes(ctx, bytes);
            };
        } else {
            freePayloadBytes(ctx, bytes);
        }
    }
}

fn freePayloadBytes(ctx: *RuntimeContext, bytes: ReleasedPayloadBytes) void {
    const start_ns = std.time.nanoTimestamp();
    ctx.allocator.free(bytes);
    const end_ns = std.time.nanoTimestamp();

    _ = ctx.metrics.payloads_freed.fetchAdd(1, .monotonic);
    if (end_ns > start_ns) {
        _ = ctx.metrics.payload_free_wall_ns.fetchAdd(@intCast(end_ns - start_ns), .monotonic);
    }
}
