//! Shared runtime context passed to all handlers and the loop thread.

const std = @import("std");
const xev = @import("xev");
const sig = @import("../../sig.zig");

const types = @import("types.zig");
const methods = @import("methods.zig");
const protocol = @import("protocol.zig");
const sub_map_mod = @import("sub_map.zig");
const metrics_mod = @import("metrics.zig");
const NotifQueue = @import("NotifQueue.zig");
const SlotStateCache = @import("SlotStateCache.zig");

const Channel = sig.sync.Channel;
const ThreadPool = sig.sync.ThreadPool;
const Slot = sig.core.Slot;
const Logger = sig.trace.Logger("rpc.jrpc_websockets.runtime");
const NotifPayload = sig.sync.RcSlice(u8);
/// Type to track alignment of RcSlice bytes for allocator free
pub const ReleasedPayloadBytes = @TypeOf((@as(NotifPayload, undefined)).release().?);
pub const SlotReadContext = types.SlotReadContext;

const RuntimeContext = @This();

allocator: std.mem.Allocator,
logger: Logger,
/// Subscription map: matches subscriptions and events to subscription queues.
sub_map: *sub_map_mod.RPCSubMap,
/// Read-only dependencies for websocket slot-state bookkeeping.
slot_read_ctx: SlotReadContext,
/// Runtime-owned slot-state bookkeeping.
slot_state_cache: SlotStateCache,
/// Queue for receiving events from producers (account updates, lifecycle events, etc).
inbound_event_queue: *Channel(types.InboundEvent),
/// Queue for receiving commit messages from serialization workers.
commit_queue: *Channel(types.CommitMsg),
/// Async handle for waking the loop thread to drain queues.
loop_async: *xev.Async,
async_completion: xev.Completion = .{},
/// Thread pool for runtime background tasks.
threadpool: *ThreadPool,
/// Metrics counters for monitoring and benchmarking.
metrics: *metrics_mod.Metrics,
/// Maximum batch size in bytes for notifications received by clients before ensuring TCP flush.
max_batch_bytes: u64,
loop: *xev.Loop,
/// True when an async wake has been requested but not yet observed by the loop thread.
/// Used to coalesce multiple wake requests into a single wakeup event on the loop.
notify_pending: *std.atomic.Value(bool),
/// Set to false to stop async wakeups, which in turn stops draining queues.
running: bool = true,
/// Queues that have newly committed notifications this drain cycle.
/// Built during commit processing; drained immediately after.
pending_wake_queues: std.ArrayList(*NotifQueue) = .{},
/// Waitgroup to track submitted threadpool tasks that must finish before shutdown can complete.
threadpool_wg: std.Thread.WaitGroup,
/// Optional callback run on the loop thread whenever the async wake fires.
/// Used by integrations to drain additional loop-thread-only queues.
wakeup_hook: ?WakeupHook = null,

pub const WakeupHook = struct {
    ptr: *anyopaque,
    onWake: *const fn (*anyopaque) void,

    fn call(self: WakeupHook) void {
        self.onWake(self.ptr);
    }
};

pub const Dependencies = struct {
    allocator: std.mem.Allocator,
    logger: Logger,
    sub_map: *sub_map_mod.RPCSubMap,
    slot_read_ctx: SlotReadContext,
    event_sink: *types.EventSink,
    commit_queue: *Channel(types.CommitMsg),
    threadpool: *ThreadPool,
    metrics: *metrics_mod.Metrics,
    max_batch_bytes: u64,
    loop: *xev.Loop,
    wakeup_hook: ?WakeupHook = null,
};

pub fn init(deps: Dependencies) RuntimeContext {
    const runtime: RuntimeContext = .{
        .allocator = deps.allocator,
        .logger = .from(deps.logger),
        .sub_map = deps.sub_map,
        .slot_read_ctx = deps.slot_read_ctx,
        .slot_state_cache = .init(deps.slot_read_ctx, .from(deps.logger)),
        .inbound_event_queue = &deps.event_sink.channel,
        .commit_queue = deps.commit_queue,
        .loop_async = &deps.event_sink.loop_async,
        .threadpool = deps.threadpool,
        .metrics = deps.metrics,
        .max_batch_bytes = deps.max_batch_bytes,
        .loop = deps.loop,
        .notify_pending = &deps.event_sink.notify_pending,
        .threadpool_wg = .{},
        .wakeup_hook = deps.wakeup_hook,
    };
    return runtime;
}

/// Get or create a subscription entry for the given key.
pub fn getOrCreateSubscription(
    self: *RuntimeContext,
    key: *const types.SubReqKey,
) !sub_map_mod.GetOrCreateResult {
    const result = try self.sub_map.getOrCreate(key);
    if (result.created) {
        switch (result.entry.key.method) {
            .account => self.initializeAccountSubscriptionEntry(result.entry),
            else => {},
        }
    }
    return result;
}

const SerializeTask = struct {
    runtime: *RuntimeContext,
    task: ThreadPool.Task,
    job: types.SerializeJob,

    fn execute(threadpool_task: *ThreadPool.Task) void {
        const serialize_task: *SerializeTask = @alignCast(@fieldParentPtr("task", threadpool_task));
        const runtime = serialize_task.runtime;
        defer runtime.threadpool_wg.finish();
        defer serialize_task.deinit();

        const job = serialize_task.job;
        var serialize_timer = std.time.Timer.start() catch unreachable;

        const result: types.CommitResult = if (protocol.serializeNotification(
            runtime.allocator,
            job.sub_id,
            job.job_type,
        )) |p|
            .{ .payload = p }
        else |err|
            .{ .serialize_error = err };

        const serialize_ns = serialize_timer.read();
        const completed_at = std.time.Instant.now() catch unreachable;
        const pipeline_latency_ns = completed_at.since(job.submitted_at);
        const payload_bytes: u64 = switch (result) {
            .payload => |p| @intCast(p.payload().len),
            .serialize_error => 0,
        };

        const commit_msg = types.CommitMsg{
            .sub_id = job.sub_id,
            .index = job.index,
            .result = result,
            .is_final = job.is_final,
            .serialize_ns = serialize_ns,
            .pipeline_latency_ns = pipeline_latency_ns,
            .payload_bytes = payload_bytes,
        };

        runtime.commit_queue.send(commit_msg) catch {
            result.deinit(runtime.allocator);
            return;
        };

        const already_pending = runtime.notify_pending.swap(true, .release);
        if (!already_pending) {
            runtime.loop_async.notify() catch {
                _ = runtime.notify_pending.swap(false, .release);
            };
        }
    }

    fn deinit(self: *SerializeTask) void {
        self.job.deinit(self.runtime.allocator);
        self.runtime.allocator.destroy(self);
    }
};

const FreePayloadTask = struct {
    runtime: *RuntimeContext,
    task: ThreadPool.Task,
    bytes: ReleasedPayloadBytes,

    fn execute(threadpool_task: *ThreadPool.Task) void {
        const free_task: *FreePayloadTask = @alignCast(@fieldParentPtr("task", threadpool_task));
        const runtime = free_task.runtime;
        defer runtime.threadpool_wg.finish();
        defer free_task.deinit();

        freePayloadBytes(runtime, free_task.bytes);
    }

    fn deinit(self: *FreePayloadTask) void {
        self.runtime.allocator.destroy(self);
    }
};

/// Drain runtime-owned work queues and wait for runtime-submitted threadpool tasks to finish.
///
/// IMPORTANT: callers must shutdown the websocket server and stop sending messages to the
/// inbound event channel before calling `shutdown()`.
pub fn shutdown(self: *RuntimeContext, timeout_ms: u64) error{Timeout}!void {
    self.drainCommitQueue();
    try self.waitForThreadpoolTasks(timeout_ms);

    if (self.metrics.inflight_jobs != 0) {
        self.logger.warn().logf(
            "shutdown completed with inflight_jobs metric = {}; " ++
                "metric may be stale after worker send failures",
            .{self.metrics.inflight_jobs},
        );
    }
}

pub fn deinit(self: *RuntimeContext) void {
    self.slot_state_cache.deinit(self.allocator);
    self.pending_wake_queues.deinit(self.allocator);
}

fn waitForThreadpoolTasks(self: *RuntimeContext, timeout_ms: u64) error{Timeout}!void {
    var timer = std.time.Timer.start() catch unreachable;
    const timeout_ns = timeout_ms * std.time.ns_per_ms;

    while (!self.threadpool_wg.isDone()) {
        const elapsed_ns = timer.read();
        if (elapsed_ns >= timeout_ns) {
            return error.Timeout;
        }

        const remaining_ns = timeout_ns - elapsed_ns;
        std.Thread.sleep(@min(remaining_ns, 100 * std.time.ns_per_us));
    }
}

/// Request an async wake on the loop, coalescing duplicate wakeups.
pub fn requestWakeup(self: *RuntimeContext) void {
    const already_pending = self.notify_pending.swap(true, .release);
    if (!already_pending) {
        self.loop_async.notify() catch |err| {
            self.logger.err().logf("loop async notify failed: {}", .{err});
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
    const self = self_opt orelse return .disarm;
    result catch |e| {
        self.logger.err().logf("async wait error: {}", .{e});
        return .disarm;
    };

    _ = self.notify_pending.swap(false, .acquire);
    if (self.wakeup_hook) |wakeup_hook| {
        wakeup_hook.call();
    }
    self.drainInboundEvents();
    self.drainCommitQueue();

    if (self.running) {
        self.armAsyncWait();
    }
    return .disarm;
}

fn appendSerializeTask(
    self: *RuntimeContext,
    job: types.SerializeJob,
    task_batch: *ThreadPool.Batch,
) !void {
    // TODO(perf): we could pool these task structs to avoid allocator churn,
    // but notably this is quite fast when benchmarked due to same-size allocations.
    const serialize_task = try self.allocator.create(SerializeTask);
    serialize_task.* = .{
        .runtime = self,
        .task = .{ .callback = SerializeTask.execute },
        .job = job,
    };
    task_batch.push(.from(&serialize_task.task));
}

fn submitPayloadFree(self: *RuntimeContext, bytes: ReleasedPayloadBytes) !void {
    // TODO(perf): we could pool these task structs to avoid allocator churn,
    // but notably this is quite fast when benchmarked due to same-size allocations.
    const free_task = try self.allocator.create(FreePayloadTask);
    free_task.* = .{
        .runtime = self,
        .task = .{ .callback = FreePayloadTask.execute },
        .bytes = bytes,
    };
    self.threadpool_wg.start();
    self.threadpool.schedule(.{
        .head = &free_task.task,
        .tail = &free_task.task,
        .len = 1,
    });
}

/// Drain all pending inbound events from producers.
fn drainInboundEvents(self: *RuntimeContext) void {
    var task_batch = ThreadPool.Batch{};
    defer {
        if (task_batch.len > 0) {
            self.threadpool_wg.startMany(task_batch.len);
            self.threadpool.schedule(task_batch);
        }
    }

    while (self.inbound_event_queue.tryReceive()) |event| {
        self.metrics.events_received += 1;
        self.handleInboundEvent(event, &task_batch);
    }

    self.metrics.inbound_drain_calls += 1;
}

fn handleInboundEvent(
    self: *RuntimeContext,
    event: types.InboundEvent,
    task_batch: *ThreadPool.Batch,
) void {
    // TODO: review how ownership should flow in Zig for this situation,
    // .slot_frozen and .logs cases take ownership of the inner data
    var e = event;
    defer e.deinit(self.inbound_event_queue.allocator);

    switch (e) {
        .logs => |*log_data| {
            // NOTE: logs events only populate the slot cache; publication happens on later
            // slot transitions. Replay may send multiple log batches for the same slot before
            // `.slot_frozen`, and the cache accumulates them until the slot is published.
            self.slot_state_cache.onLogsEvent(self.allocator, log_data) catch |err| {
                self.logger.err().logf(
                    "failed to cache logs event for slot {}: {}",
                    .{ log_data.slot, err },
                );
            };
        },
        .received_signatures => |data| {
            self.handleReceivedSignaturesEvent(data, task_batch);
        },
        .slot_frozen => |*slot_data| {
            const transition = self.slot_state_cache.onSlotFrozen(
                self.allocator,
                slot_data,
            ) catch |err| {
                self.logger.err().logf(
                    "failed to cache frozen slot {}: {}",
                    .{ slot_data.slot, err },
                );
                return;
            };
            const slot_event_kind: SlotEventKind = .{ .slot_frozen = .{
                .slot = slot_data.slot,
                .parent = slot_data.parent,
                .root = slot_data.root,
            } };
            self.handleSlotTransition(slot_event_kind, slot_data.slot, transition, task_batch);
        },
        .slot_rooted => |rooted_slot| {
            const transition = self.slot_state_cache.onSlotRooted(
                self.allocator,
                rooted_slot,
            ) catch |err| {
                self.logger.err().logf(
                    "failed to mark rooted slot {}: {}",
                    .{ rooted_slot, err },
                );
                return;
            };
            const slot_event_kind: SlotEventKind = .{ .slot_rooted = .{ .root = rooted_slot } };
            self.handleSlotTransition(
                slot_event_kind,
                rooted_slot,
                transition,
                task_batch,
            );
        },
        .slot_confirmed => |confirmed_slot| {
            const transition = self.slot_state_cache.onSlotConfirmed(
                self.allocator,
                confirmed_slot,
            ) catch |err| {
                self.logger.err().logf(
                    "failed to mark confirmed slot {}: {}",
                    .{ confirmed_slot, err },
                );
                return;
            };
            self.handleSlotTransition(.slot_confirmed, confirmed_slot, transition, task_batch);
        },
        .tip_changed => |new_tip| {
            const transition = self.slot_state_cache.onTipChanged(self.slot_read_ctx, new_tip);
            self.handleSlotTransition(.tip_changed, new_tip, transition, task_batch);
        },
    }
}

fn handleReceivedSignaturesEvent(
    self: *RuntimeContext,
    data: types.ReceivedSignaturesEvent,
    task_batch: *ThreadPool.Batch,
) void {
    for (self.sub_map.entries.items) |entry| {
        if (entry.key.method != .signature) {
            continue;
        }
        if (!entry.key.params.signature.enableReceivedNotification) {
            continue;
        }
        if (entry.queue.finalNotificationIndex() != null) {
            // already sent/queued final notification, no more notifications need to be sent
            // for this subscription
            continue;
        }

        for (data.signatures) |signature| {
            if (!signature.eql(&entry.key.params.signature.sig_value)) {
                continue;
            }

            _ = self.enqueueJobForEntry(entry, .{ .signature = .{
                .slot = data.slot,
                .value = .received,
            } }, false, task_batch);
            break;
        }
    }
}

const SlotEventKind = union(enum) {
    slot_frozen: types.SlotEventData,
    slot_confirmed,
    slot_rooted: types.RootEventData,
    tip_changed,
};

/// Lazily collects the unpublished frozen ancestor chain for a confirmed slot and
/// iterates it oldest-first so slot-derived notifications preserve slot order.
const PublishableConfirmedSlots = struct {
    runtime: *RuntimeContext,
    trigger_slot: Slot,
    slots: ?std.ArrayList(SlotStateCache.AncestorItem) = null,
    attempted: bool = false,

    fn init(runtime: *RuntimeContext, trigger_slot: Slot) PublishableConfirmedSlots {
        return .{ .runtime = runtime, .trigger_slot = trigger_slot };
    }

    fn deinit(self: *PublishableConfirmedSlots) void {
        if (self.slots) |*slots| {
            slots.deinit(self.runtime.allocator);
        }
    }

    fn iterator(self: *PublishableConfirmedSlots) ?Iterator {
        const slots = self.ensure() orelse return null;
        return .{ .slots = slots, .index = slots.len };
    }

    fn ensure(self: *PublishableConfirmedSlots) ?[]SlotStateCache.AncestorItem {
        if (self.attempted) {
            return if (self.slots) |*slots| slots.items else null;
        }
        self.attempted = true;
        self.slots = self.runtime.slot_state_cache.collectPublishableConfirmedSlots(
            self.runtime.allocator,
            self.trigger_slot,
        ) catch |err| {
            self.runtime.logger.err().logf(
                "failed to collect publishable confirmed slots from {}: {}",
                .{ self.trigger_slot, err },
            );
            return null;
        };
        return self.slots.?.items;
    }

    const Iterator = struct {
        slots: []SlotStateCache.AncestorItem,
        index: usize,

        fn next(self: *Iterator) ?SlotStateCache.AncestorItem {
            if (self.index == 0) {
                return null;
            }
            self.index -= 1;
            return self.slots[self.index];
        }
    };
};

fn handleSlotTransition(
    self: *RuntimeContext,
    event_kind: SlotEventKind,
    slot: Slot,
    transition: SlotStateCache.Transition,
    task_batch: *ThreadPool.Batch,
) void {
    var publishable_confirmed_slots = PublishableConfirmedSlots.init(self, slot);
    defer publishable_confirmed_slots.deinit();

    // TODO(perf): this is basically just brute-force iteration to find matches, and it's
    // running on the IO loop thread, so this won't scale.
    for (self.sub_map.entries.items) |*entry| {
        switch (entry.key.method) {
            .slot => {
                // TODO: slotSubscribe should be emitted at "bank created" rather than frozen.
                const slot_event = switch (event_kind) {
                    .slot_frozen => |slot_event| slot_event,
                    else => continue,
                };
                if (transition.publishable_slot == null) {
                    // TODO: for now just avoid publishing duplicates if replay over same slot
                    continue;
                }
                _ = self.enqueueJobForEntry(entry.*, .{ .slot = slot_event }, false, task_batch);
            },
            .root => {
                const root_event = switch (event_kind) {
                    .slot_rooted => |root_event| root_event,
                    else => continue,
                };
                _ = self.enqueueJobForEntry(entry.*, .{ .root = root_event }, false, task_batch);
            },
            .logs => {
                const commitment = entry.key.params.logs.commitment;
                if (!transitionMatchesCommitment(transition.notify_commitments, commitment)) {
                    continue;
                }
                switch (commitment) {
                    .confirmed => {
                        var confirmed_slots =
                            publishable_confirmed_slots.iterator() orelse continue;
                        while (confirmed_slots.next()) |confirmed_slot| {
                            self.publishLogsSubscriptionForEntry(
                                entry,
                                confirmed_slot.cached_slot,
                                confirmed_slot.slot,
                                task_batch,
                            );
                        }
                    },
                    .processed, .finalized => {
                        const publishable_slot = transition.publishable_slot orelse continue;
                        self.publishLogsSubscriptionForEntry(
                            entry,
                            publishable_slot,
                            slot,
                            task_batch,
                        );
                    },
                }
            },
            .program => {
                const commitment = entry.key.params.program.commitment;
                if (!transitionMatchesCommitment(transition.notify_commitments, commitment)) {
                    continue;
                }
                switch (commitment) {
                    .confirmed => {
                        var confirmed_slots =
                            publishable_confirmed_slots.iterator() orelse continue;
                        while (confirmed_slots.next()) |confirmed_slot| {
                            self.publishProgramSubscriptionForEntry(
                                entry,
                                confirmed_slot.cached_slot,
                                confirmed_slot.slot,
                                task_batch,
                            );
                        }
                    },
                    .processed, .finalized => {
                        const publishable_slot = transition.publishable_slot orelse continue;
                        self.publishProgramSubscriptionForEntry(
                            entry,
                            publishable_slot,
                            slot,
                            task_batch,
                        );
                    },
                }
            },
            .signature => {
                self.maybeEnqueueFinalSignatureNotification(entry, transition, task_batch);
            },
            .account => {
                // TODO(perf): we follow Agave's reevaluate approach, and actually
                //  here we do it for every processed slot. Could just use
                //  .tip_changed for processed commitment or, via tracked forks, avoid
                //  reevaluating if it's already in slot cache state.
                if (!transitionMatchesCommitment(
                    transition.notify_commitments,
                    entry.key.params.account.commitment,
                )) {
                    continue;
                }
                self.enqueueAccountReevaluation(entry, slot, task_batch);
            },
        }
    }

    if (transition.evict_through) |evict_through| {
        self.slot_state_cache.evictFinalizedThrough(self.allocator, evict_through);
    }
}

fn transitionMatchesCommitment(
    commitments: SlotStateCache.NotificationCommitments,
    commitment: methods.Commitment,
) bool {
    return switch (commitment) {
        .processed => commitments.processed,
        .confirmed => commitments.confirmed,
        .finalized => commitments.finalized,
    };
}

fn maybeEnqueueFinalSignatureNotification(
    self: *RuntimeContext,
    entry: *sub_map_mod.MapEntry,
    transition: SlotStateCache.Transition,
    task_batch: *ThreadPool.Batch,
) void {
    const params = entry.key.params.signature;
    if (!transitionMatchesCommitment(transition.notify_commitments, params.commitment)) {
        return;
    }
    const q = entry.queue;
    if (q.finalNotificationIndex() != null) {
        return;
    }
    if (q.subscriberCount() == 0) {
        self.logger.err().logf(
            "zero-subscriber queue remained in sub_map during signature final enqueue: sub_id={}",
            .{entry.sub_id},
        );
        return;
    }

    const commitment_slot = self.slot_read_ctx.slot_tracker.commitments.get(params.commitment);
    const slot_ref = self.slot_read_ctx.slot_tracker.get(commitment_slot) orelse return;
    defer slot_ref.release();

    // TODO(perf): similar to accountSubscribe this reevaluation lookup should not be on the
    // IO loop thread
    var status = self.slot_read_ctx.status_cache.getForkAnyBlockhash(
        self.allocator,
        &params.sig_value.toBytes(),
        &slot_ref.constants().ancestors,
    ) catch |err| {
        self.logger.err().logf(
            "failed to evaluate signature subscription for slot {}: {}",
            .{ commitment_slot, err },
        );
        return;
    } orelse return;
    // Always reserved for signatureSubscribe, ensures we publish in runtime received order
    // across shred received and final notification
    std.debug.assert(q.commit_path == .reserved);
    const idx = q.reserveFinalUncommitted() catch {
        status.deinit(self.allocator);
        return;
    };

    const job = types.SerializeJob{
        .sub_id = entry.sub_id,
        .index = idx,
        .job_type = .{ .signature = .{
            .slot = commitment_slot,
            .value = .{ .final = .{ .err = status.maybe_err } },
        } },
        .is_final = true,
        .submitted_at = std.time.Instant.now() catch unreachable,
    };

    self.appendSerializeTask(job, task_batch) catch {
        job.deinit(self.allocator);
        q.cancelReservation(idx);
        return;
    };
    self.metrics.inflight_jobs += 1;
    self.metrics.serialize_tasks_allocated += 1;
}

/// Initialize last notified modified slot for an account subscription entry, this matches
/// Agave's approach such that last modified is set but no replay notification is emitted.
fn initializeAccountSubscriptionEntry(
    self: *RuntimeContext,
    entry: *sub_map_mod.MapEntry,
) void {
    const params = entry.key.params.account;
    const slot = self.slot_read_ctx.slot_tracker.commitments.get(switch (params.commitment) {
        .processed => .processed,
        .confirmed => .confirmed,
        .finalized => .finalized,
    });
    const slot_ref = self.slot_read_ctx.slot_tracker.get(slot) orelse {
        entry.last_notified_modified_slot = 0;
        return;
    };
    defer slot_ref.release();

    // TODO(perf): similar to reevaluation on slot transition, we don't want to do this on the
    // IO loop thread, we'd want this to be done on another thread.
    const slot_reader = self.slot_read_ctx.account_reader.forSlot(&slot_ref.constants().ancestors);
    const latest = slot_reader.getWithModifiedSlot(self.allocator, params.pubkey) catch |err| {
        self.logger.err().logf(
            "failed to initialize account subscription baseline for slot {}: {}",
            .{ slot, err },
        );
        entry.last_notified_modified_slot = 0;
        return;
    } orelse {
        entry.last_notified_modified_slot = 0;
        return;
    };
    defer latest.account.deinit(self.allocator);

    entry.last_notified_modified_slot = latest.modified_slot;
}

/// accountSubscribe follows what is currently done in Agave:
/// reevaluate the current state of the account for the slot based on commitment level.
///
/// TODO(perf): this is pretty expensive to do for every account subscription on every slot,
/// in theory we could track fork state (slot state cache) to avoid reevaluating unless an
/// actual fork occurs, and even when a fork occurs we may already have the account in the
/// slot state cache.
fn enqueueAccountReevaluation(
    self: *RuntimeContext,
    entry: *sub_map_mod.MapEntry,
    commitment_slot: Slot,
    task_batch: *ThreadPool.Batch,
) void {
    const slot_ref = self.slot_read_ctx.slot_tracker.get(commitment_slot) orelse return;
    defer slot_ref.release();

    const ancestors = &slot_ref.constants().ancestors;
    const slot_reader = self.slot_read_ctx.account_reader.forSlot(ancestors);
    const latest = slot_reader.getWithModifiedSlot(
        self.allocator,
        entry.key.params.account.pubkey,
    ) catch |err| {
        self.logger.err().logf(
            "failed to read account subscription state for slot {}: {}",
            .{ commitment_slot, err },
        );
        return;
    } orelse return;

    var account = latest.account;
    const modified_slot = latest.modified_slot;

    // Commitment may advance without this account changing; dedupe by the slot that last
    // modified the visible version instead of by the commitment slot we are evaluating.
    if (modified_slot == entry.last_notified_modified_slot) {
        account.deinit(self.allocator);
        return;
    }
    errdefer account.deinit(self.allocator);

    if (account.lamports == 0) {
        // Missing/deleted accounts are still delivered as an explicit zero-lamport payload.
        // This is to match Agave.
        account.deinit(self.allocator);
        account = deletedAccountPlaceholder();
    }

    const enqueued = self.enqueueJobForEntry(entry.*, .{
        .account = .{
            .data = .{
                .account = .{
                    .pubkey = entry.key.params.account.pubkey,
                    .account = account,
                },
                .slot = commitment_slot,
            },
            .encoding = entry.key.params.account.encoding,
            .data_slice = entry.key.params.account.data_slice,
            .read_ctx = self.slot_read_ctx,
        },
    }, false, task_batch);
    if (!enqueued) {
        return;
    }
    // Assume delivery once the serialization job is accepted. Technically serialization could fail
    // in which case notification is dropped regardless so it doesn't matter much, e.g.:
    // Update last modified -> serialization fail -> never deliver
    // vs.
    // Serialization fail -> never update last modified -> never deliver
    entry.last_notified_modified_slot = modified_slot;
}

fn deletedAccountPlaceholder() sig.core.Account {
    return .{
        .lamports = 0,
        .data = sig.accounts_db.buffer_pool.AccountDataHandle.initEmpty(0),
        .owner = sig.core.Pubkey.ZEROES,
        .executable = false,
        .rent_epoch = 0,
    };
}

fn publishLogsSubscriptionForEntry(
    self: *RuntimeContext,
    entry: *sub_map_mod.MapEntry,
    cached_slot: *const SlotStateCache.CachedSlot,
    slot: Slot,
    task_batch: *ThreadPool.Batch,
) void {
    const logs_filter = entry.key.params.logs.filter;
    var log_entries = cached_slot.logEntriesIterator();
    while (log_entries.next()) |log_event| {
        if (!logsEventMatchesFilter(logs_filter, log_event)) {
            continue;
        }

        // TODO(perf): clone has to allocate; ideally we would use the cached log event as is
        // and keep the arena alive until outstanding events are returned from serialization.
        const notification_data = log_event.toOwnedNotificationData(
            self.allocator,
            slot,
        ) catch |err| {
            self.logger.err().logf(
                "failed to clone logs subscription payload for slot {}: {}",
                .{ slot, err },
            );
            continue;
        };

        _ = self.enqueueJobForEntry(entry.*, .{ .logs = notification_data }, false, task_batch);
    }
}

fn logsEventMatchesFilter(
    filter: methods.LogsFilter,
    log_event: *const types.TransactionLogsEntry,
) bool {
    return switch (filter) {
        .all => !log_event.is_vote,
        .allWithVotes => true,
        .mentions => |mentions_filter| blk: {
            const target_pubkey = mentions_filter.mentions[0];
            for (log_event.mentioned_pubkeys) |pubkey| {
                if (pubkey.equals(&target_pubkey)) {
                    break :blk true;
                }
            }
            break :blk false;
        },
    };
}

/// programSubscribe publishes from the cached modified accounts for one slot once that slot
// becomes visible at the requested commitment.
fn publishProgramSubscriptionForEntry(
    self: *RuntimeContext,
    entry: *sub_map_mod.MapEntry,
    cached_slot: *const SlotStateCache.CachedSlot,
    slot: Slot,
    task_batch: *ThreadPool.Batch,
) void {
    const program_params = entry.key.params.program;
    // Check owner before touching account data so unrelated modified accounts stay cheap.
    for (cached_slot.modified_accounts.accounts) |modified_account| {
        if (!modified_account.account.owner.equals(&program_params.program_id)) {
            continue;
        }
        const matches_filters = self.programAccountMatchesFilters(
            &modified_account.account,
            program_params.filters,
        ) catch |err| {
            self.logger.err().logf(
                "failed to evaluate program subscription filters for slot {}: {}",
                .{ slot, err },
            );
            continue;
        };
        if (!matches_filters) {
            continue;
        }

        // TODO(perf): clone has to allocate; ideally we would use the cached Account as is
        // and keep the arena alive until outstanding events are returned from serialization.
        const cloned_account = modified_account.account.cloneOwned(self.allocator) catch |err| {
            self.logger.err().logf(
                "failed to clone program subscription payload: {}",
                .{err},
            );
            continue;
        };
        _ = self.enqueueJobForEntry(entry.*, .{
            .program = .{
                .data = .{
                    .account = .{
                        .pubkey = modified_account.pubkey,
                        .account = cloned_account,
                    },
                    .slot = slot,
                },
                .encoding = program_params.encoding,
                .data_slice = program_params.data_slice,
                .read_ctx = self.slot_read_ctx,
            },
        }, false, task_batch);
    }
}

fn programAccountMatchesFilters(
    self: *RuntimeContext,
    account: *const sig.core.Account,
    filters: ?[]const methods.ProgramSubscribe.Filter,
) !bool {
    const program_filters = filters orelse return true;
    // Some filters need the full account bytes; load them lazily once and reuse them.
    var account_data: ?[]u8 = null;
    defer if (account_data) |bytes| {
        self.allocator.free(bytes);
    };

    for (program_filters) |filter| {
        switch (filter) {
            .dataSize => |data_size| {
                const expected_size = std.math.cast(usize, data_size) orelse return false;
                if (account.data.len() != expected_size) {
                    return false;
                }
            },
            .memcmp => |memcmp_filter| {
                const bytes = if (account_data) |cached_bytes|
                    cached_bytes
                else blk: {
                    account_data = try account.data.readAllAllocate(self.allocator);
                    break :blk account_data.?;
                };
                if (memcmp_filter.offset > bytes.len) {
                    return false;
                }
                const remaining_len = bytes.len - memcmp_filter.offset;
                if (memcmp_filter.bytes.len > remaining_len) {
                    return false;
                }
                if (!std.mem.eql(
                    u8,
                    bytes[memcmp_filter.offset..][0..memcmp_filter.bytes.len],
                    memcmp_filter.bytes,
                )) {
                    return false;
                }
            },
            .tokenAccountState => {
                const bytes = if (account_data) |cached_bytes|
                    cached_bytes
                else blk: {
                    account_data = try account.data.readAllAllocate(self.allocator);
                    break :blk account_data.?;
                };
                if (!sig.rpc.account_codec.parse_token.isValidTokenAccountData(bytes)) {
                    return false;
                }
            },
        }
    }
    return true;
}

fn enqueueJobForEntry(
    self: *RuntimeContext,
    entry: sub_map_mod.MapEntry,
    job_type: types.SerializeJob.JobType,
    is_final: bool,
    task_batch: *ThreadPool.Batch,
) bool {
    const q = entry.queue;
    if (q.subscriberCount() == 0) {
        self.logger.err().logf(
            "zero-subscriber queue remained in sub_map during enqueue: sub_id={}",
            .{entry.sub_id},
        );
        job_type.deinit(self.allocator);
        return false;
    }

    const idx: ?u64 = switch (q.commit_path) {
        // Note: if threadpool fails to send back a response then the reserved position will
        // never be committed which is not ideal, but if notifications keep getting pushed then
        // eventually it will roll off the end of the queue ring buffer. More importantly nothing
        // undefined/illegal happens.
        .reserved => q.reserveUncommitted() catch {
            job_type.deinit(self.allocator);
            return false;
        },
        .direct => null,
    };

    const job = types.SerializeJob{
        .sub_id = entry.sub_id,
        .index = idx,
        .job_type = job_type,
        .is_final = is_final,
        .submitted_at = std.time.Instant.now() catch unreachable,
    };

    self.appendSerializeTask(job, task_batch) catch {
        job.deinit(self.allocator);
        if (idx) |i| {
            q.cancelReservation(i);
        }
        return false;
    };
    self.metrics.inflight_jobs += 1;
    self.metrics.serialize_tasks_allocated += 1;
    return true;
}

/// Drain all pending commit messages from serialization workers.
fn drainCommitQueue(self: *RuntimeContext) void {
    // TODO: this is draining *all* pending, this could overwhelm queue capacity
    // before clients have a chance to consume. I don't think there's really a way
    // around it, the clients must keep up with the commit rate or messages will be
    // missed. I think what could be done is have a large queue size (4096?) to absorb
    // bursts and give clients time to consume, but kick/eject clients that are consistently
    // not keeping pace to avoid retaining too many payloads due to full queues.
    while (self.commit_queue.tryReceive()) |msg| {
        self.handleCommitMsg(msg);
    }

    self.wakePendingQueueSubscribers();

    self.metrics.commit_drain_calls += 1;
}

fn handleCommitMsg(self: *RuntimeContext, msg: types.CommitMsg) void {
    self.metrics.inflight_jobs -= 1;
    self.metrics.serialize_jobs += 1;
    self.metrics.serialize_ns += msg.serialize_ns;
    self.metrics.serialize_pipeline_ns += msg.pipeline_latency_ns;
    self.metrics.serialize_payload_bytes += msg.payload_bytes;

    const entry = self.sub_map.getById(msg.sub_id) orelse {
        switch (msg.result) {
            .payload => |p| {
                // We can be here if queue was removed due to all clients disconnecting while
                // serialization was in-flight
                releasePayload(self, p);
            },
            .serialize_error => {
                self.metrics.serialize_errors += 1;
            },
        }
        return;
    };

    const q = entry.queue;
    switch (msg.result) {
        .serialize_error => {
            self.metrics.serialize_errors += 1;
            if (msg.is_final and msg.index != null) {
                q.cancelReservation(msg.index.?);
            }
        },
        .payload => |p| {
            if (q.subscriberCount() == 0) {
                self.logger.err().logf(
                    "zero-subscriber queue remained in sub_map during commit: sub_id={}",
                    .{msg.sub_id},
                );
                if (msg.is_final and msg.index != null) {
                    q.cancelReservation(msg.index.?);
                }
                releasePayload(self, p);
                return;
            }

            const newly_committed = q.commitSerialized(msg.index, p, msg.is_final) catch {
                releasePayload(self, p);
                self.logger.err().log(
                    "commitSerialized failed: queue commit-path/index mismatch" ++
                        " or invalid reserved state (invariant violation)",
                );
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
            // Best-effort only under OOM. There is no reliable local recovery here beyond a
            // later runtime wake successfully queuing this subscriber wake pass.
            self.logger.warn().log(
                "pending_wake_queues append failed: OOM; wake skipped for this cycle",
            );
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
    if (q.subscriberCount() == 0) {
        self.sub_map.removeById(sub_id);
    }
}

/// Release a refcounted notification payload, freeing the backing
/// allocation when the last reference is dropped.
pub fn releasePayload(ctx: *RuntimeContext, payload: NotifPayload) void {
    if (payload.release()) |bytes| {
        ctx.submitPayloadFree(bytes) catch {
            freePayloadBytes(ctx, bytes);
        };
    }
}

fn freePayloadBytes(ctx: *RuntimeContext, bytes: ReleasedPayloadBytes) void {
    var free_timer = std.time.Timer.start() catch unreachable;
    ctx.allocator.free(bytes);
    const elapsed_ns = free_timer.read();

    _ = ctx.metrics.payloads_freed.fetchAdd(1, .monotonic);
    _ = ctx.metrics.payload_free_wall_ns.fetchAdd(elapsed_ns, .monotonic);
}

test "releasePayload frees payloads on the threadpool" {
    const CountingAllocator = struct {
        backing: std.mem.Allocator,
        free_calls: std.atomic.Value(u32) = .init(0),

        fn allocator(self: *@This()) std.mem.Allocator {
            return .{
                .ptr = @ptrCast(self),
                .vtable = &.{
                    .alloc = alloc,
                    .resize = resize,
                    .remap = remap,
                    .free = free,
                },
            };
        }

        fn alloc(
            ctx: *anyopaque,
            len: usize,
            alignment: std.mem.Alignment,
            ret_addr: usize,
        ) ?[*]u8 {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            return self.backing.rawAlloc(len, alignment, ret_addr);
        }

        fn resize(
            ctx: *anyopaque,
            memory: []u8,
            alignment: std.mem.Alignment,
            new_len: usize,
            ret_addr: usize,
        ) bool {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            return self.backing.rawResize(memory, alignment, new_len, ret_addr);
        }

        fn remap(
            ctx: *anyopaque,
            memory: []u8,
            alignment: std.mem.Alignment,
            new_len: usize,
            ret_addr: usize,
        ) ?[*]u8 {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            return self.backing.rawRemap(memory, alignment, new_len, ret_addr);
        }

        fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            _ = self.free_calls.fetchAdd(1, .monotonic);
            self.backing.rawFree(memory, alignment, ret_addr);
        }
    };

    var allocator_state = CountingAllocator{ .backing = std.testing.allocator };
    const allocator = allocator_state.allocator();

    var commit_queue = try Channel(types.CommitMsg).init(allocator);
    defer commit_queue.deinit();

    var xev_pool = xev.ThreadPool.init(.{});
    defer {
        xev_pool.shutdown();
        xev_pool.deinit();
    }

    var loop = try xev.Loop.init(.{ .thread_pool = &xev_pool });
    defer loop.deinit();

    var threadpool = ThreadPool.init(.{ .max_threads = 1 });
    defer {
        threadpool.shutdown();
        threadpool.deinit();
    }

    var sub_map = sub_map_mod.RPCSubMap.init(allocator, 8);
    defer sub_map.deinit();

    var slot_tracker = try sig.replay.trackers.SlotTracker.initEmpty(allocator, 0);
    defer slot_tracker.deinit(allocator);

    var event_sink = try types.EventSink.create(allocator);
    defer event_sink.destroy();

    var status_cache: sig.core.StatusCache = .DEFAULT;
    defer status_cache.deinit(allocator);

    var metrics = metrics_mod.Metrics{};
    const slot_read_ctx: SlotReadContext = .{
        .slot_tracker = &slot_tracker,
        .account_reader = .noop,
        .status_cache = &status_cache,
    };
    var runtime = RuntimeContext.init(.{
        .allocator = allocator,
        .logger = .FOR_TESTS,
        .sub_map = &sub_map,
        .slot_read_ctx = slot_read_ctx,
        .event_sink = event_sink,
        .commit_queue = &commit_queue,
        .threadpool = &threadpool,
        .metrics = &metrics,
        .max_batch_bytes = 64 * 1024,
        .loop = &loop,
    });
    defer runtime.deinit();

    const payload = try NotifPayload.alloc(allocator, 16);
    @memset(payload.payload(), 0xAB);
    releasePayload(&runtime, payload);

    try runtime.waitForThreadpoolTasks(5 * std.time.ms_per_s);

    try std.testing.expectEqual(1, metrics.payloads_freed.load(.acquire));
    try std.testing.expect(allocator_state.free_calls.load(.acquire) > 0);
}

test "shutdown times out while runtime tasks remain unfinished" {
    const allocator = std.testing.allocator;

    var commit_queue = try Channel(types.CommitMsg).init(allocator);
    defer commit_queue.deinit();

    var xev_pool = xev.ThreadPool.init(.{});
    defer {
        xev_pool.shutdown();
        xev_pool.deinit();
    }

    var loop = try xev.Loop.init(.{ .thread_pool = &xev_pool });
    defer loop.deinit();

    var threadpool = ThreadPool.init(.{ .max_threads = 1 });
    defer {
        threadpool.shutdown();
        threadpool.deinit();
    }

    var sub_map = sub_map_mod.RPCSubMap.init(allocator, 8);
    defer sub_map.deinit();

    var slot_tracker = try sig.replay.trackers.SlotTracker.initEmpty(allocator, 0);
    defer slot_tracker.deinit(allocator);

    var event_sink = try types.EventSink.create(allocator);
    defer event_sink.destroy();

    var status_cache: sig.core.StatusCache = .DEFAULT;
    defer status_cache.deinit(allocator);

    var metrics = metrics_mod.Metrics{};
    const slot_read_ctx: SlotReadContext = .{
        .slot_tracker = &slot_tracker,
        .account_reader = .noop,
        .status_cache = &status_cache,
    };
    var runtime = RuntimeContext.init(.{
        .allocator = allocator,
        .logger = .FOR_TESTS,
        .sub_map = &sub_map,
        .slot_read_ctx = slot_read_ctx,
        .event_sink = event_sink,
        .commit_queue = &commit_queue,
        .threadpool = &threadpool,
        .metrics = &metrics,
        .max_batch_bytes = 64 * 1024,
        .loop = &loop,
    });
    defer runtime.deinit();

    runtime.threadpool_wg.start();
    // balance the start on test failure
    errdefer runtime.threadpool_wg.finish();

    try std.testing.expectError(error.Timeout, runtime.shutdown(1));

    runtime.threadpool_wg.finish();
    try runtime.shutdown(5 * std.time.ms_per_s);
}

test "handleCommitMsg drops payload for removed queue" {
    const allocator = std.testing.allocator;

    var commit_queue = try Channel(types.CommitMsg).init(allocator);
    defer commit_queue.deinit();

    var xev_pool = xev.ThreadPool.init(.{});
    defer {
        xev_pool.shutdown();
        xev_pool.deinit();
    }

    var loop = try xev.Loop.init(.{ .thread_pool = &xev_pool });
    defer loop.deinit();

    var threadpool = ThreadPool.init(.{ .max_threads = 1 });
    defer {
        threadpool.shutdown();
        threadpool.deinit();
    }

    var sub_map = sub_map_mod.RPCSubMap.init(allocator, 8);
    defer sub_map.deinit();

    var slot_tracker = try sig.replay.trackers.SlotTracker.initEmpty(allocator, 0);
    defer slot_tracker.deinit(allocator);

    var event_sink = try types.EventSink.create(allocator);
    defer event_sink.destroy();

    var status_cache: sig.core.StatusCache = .DEFAULT;
    defer status_cache.deinit(allocator);

    var metrics = metrics_mod.Metrics{};
    const slot_read_ctx: SlotReadContext = .{
        .slot_tracker = &slot_tracker,
        .account_reader = .noop,
        .status_cache = &status_cache,
    };
    var runtime = RuntimeContext.init(.{
        .allocator = allocator,
        .logger = .FOR_TESTS,
        .sub_map = &sub_map,
        .slot_read_ctx = slot_read_ctx,
        .event_sink = event_sink,
        .commit_queue = &commit_queue,
        .threadpool = &threadpool,
        .metrics = &metrics,
        .max_batch_bytes = 64 * 1024,
        .loop = &loop,
    });
    defer runtime.deinit();

    const key = types.SubReqKey.slotKey();
    const result = try sub_map.getOrCreate(&key);

    var subscriber: @import("handler.zig").JRPCHandler = undefined;
    try result.queue.addSubscriber(&subscriber);
    const idx = try result.queue.reserveUncommitted();
    result.queue.removeSubscriber(&subscriber, result.queue.head + 1);
    runtime.maybeRemoveIdleQueue(result.sub_id, result.queue);
    try std.testing.expect(sub_map.getById(result.sub_id) == null);

    const payload = try NotifPayload.alloc(allocator, 4);
    @memcpy(payload.payload(), "late");

    metrics.inflight_jobs = 1;
    runtime.handleCommitMsg(.{
        .sub_id = result.sub_id,
        .index = idx,
        .result = .{ .payload = payload },
        .payload_bytes = payload.payload().len,
    });
    try runtime.waitForThreadpoolTasks(5 * std.time.ms_per_s);

    try std.testing.expectEqual(1, metrics.serialize_jobs);
    try std.testing.expectEqual(0, metrics.notifications_committed);
    try std.testing.expectEqual(1, metrics.payloads_freed.load(.acquire));
    try std.testing.expect(sub_map.getById(result.sub_id) == null);
}

test "handleCommitMsg ignores serialize error for removed queue" {
    const allocator = std.testing.allocator;

    var commit_queue = try Channel(types.CommitMsg).init(allocator);
    defer commit_queue.deinit();

    var xev_pool = xev.ThreadPool.init(.{});
    defer {
        xev_pool.shutdown();
        xev_pool.deinit();
    }

    var loop = try xev.Loop.init(.{ .thread_pool = &xev_pool });
    defer loop.deinit();

    var threadpool = ThreadPool.init(.{ .max_threads = 1 });
    defer {
        threadpool.shutdown();
        threadpool.deinit();
    }

    var sub_map = sub_map_mod.RPCSubMap.init(allocator, 8);
    defer sub_map.deinit();

    var slot_tracker = try sig.replay.trackers.SlotTracker.initEmpty(allocator, 0);
    defer slot_tracker.deinit(allocator);

    var event_sink = try types.EventSink.create(allocator);
    defer event_sink.destroy();

    var status_cache: sig.core.StatusCache = .DEFAULT;
    defer status_cache.deinit(allocator);

    var metrics = metrics_mod.Metrics{};
    const slot_read_ctx: SlotReadContext = .{
        .slot_tracker = &slot_tracker,
        .account_reader = .noop,
        .status_cache = &status_cache,
    };
    var runtime = RuntimeContext.init(.{
        .allocator = allocator,
        .logger = .FOR_TESTS,
        .sub_map = &sub_map,
        .slot_read_ctx = slot_read_ctx,
        .event_sink = event_sink,
        .commit_queue = &commit_queue,
        .threadpool = &threadpool,
        .metrics = &metrics,
        .max_batch_bytes = 64 * 1024,
        .loop = &loop,
    });
    defer runtime.deinit();

    const key = types.SubReqKey.slotKey();
    const result = try sub_map.getOrCreate(&key);

    var subscriber: @import("handler.zig").JRPCHandler = undefined;
    try result.queue.addSubscriber(&subscriber);
    const idx = try result.queue.reserveUncommitted();
    result.queue.removeSubscriber(&subscriber, result.queue.head + 1);
    runtime.maybeRemoveIdleQueue(result.sub_id, result.queue);
    try std.testing.expect(sub_map.getById(result.sub_id) == null);

    metrics.inflight_jobs = 1;
    runtime.handleCommitMsg(.{
        .sub_id = result.sub_id,
        .index = idx,
        .result = .{ .serialize_error = error.TestCommitFailure },
    });

    try std.testing.expectEqual(1, metrics.serialize_jobs);
    try std.testing.expectEqual(1, metrics.serialize_errors);
    try std.testing.expect(sub_map.getById(result.sub_id) == null);
}

test "handleReceivedSignaturesEvent skips received notifications once final is queued" {
    const allocator = std.testing.allocator;

    var commit_queue = try Channel(types.CommitMsg).init(allocator);
    defer commit_queue.deinit();

    var xev_pool = xev.ThreadPool.init(.{});
    defer {
        xev_pool.shutdown();
        xev_pool.deinit();
    }

    var loop = try xev.Loop.init(.{ .thread_pool = &xev_pool });
    defer loop.deinit();

    var threadpool = ThreadPool.init(.{ .max_threads = 1 });
    defer {
        threadpool.shutdown();
        threadpool.deinit();
    }

    var sub_map = sub_map_mod.RPCSubMap.init(allocator, 8);
    defer sub_map.deinit();

    var slot_tracker = try sig.replay.trackers.SlotTracker.initEmpty(allocator, 0);
    defer slot_tracker.deinit(allocator);

    var event_sink = try types.EventSink.create(allocator);
    defer event_sink.destroy();

    var status_cache: sig.core.StatusCache = .DEFAULT;
    defer status_cache.deinit(allocator);

    var metrics = metrics_mod.Metrics{};
    const slot_read_ctx: SlotReadContext = .{
        .slot_tracker = &slot_tracker,
        .account_reader = .noop,
        .status_cache = &status_cache,
    };
    var runtime = RuntimeContext.init(.{
        .allocator = allocator,
        .logger = .FOR_TESTS,
        .sub_map = &sub_map,
        .slot_read_ctx = slot_read_ctx,
        .event_sink = event_sink,
        .commit_queue = &commit_queue,
        .threadpool = &threadpool,
        .metrics = &metrics,
        .max_batch_bytes = 64 * 1024,
        .loop = &loop,
    });
    defer runtime.deinit();

    const signature = sig.core.Signature.ZEROES;
    const key: types.SubReqKey = .{
        .method = .signature,
        .params = .{ .signature = .{
            .sig_value = signature,
            .commitment = .processed,
            .enableReceivedNotification = true,
        } },
    };
    const result = try sub_map.getOrCreate(&key);

    var subscriber: @import("handler.zig").JRPCHandler = undefined;
    try result.queue.addSubscriber(&subscriber);
    _ = try result.queue.reserveFinalUncommitted();

    const next_reserve_before = result.queue.next_reserve;
    var task_batch = ThreadPool.Batch{};
    runtime.handleReceivedSignaturesEvent(.{
        .slot = 99,
        .signatures = &.{signature},
    }, &task_batch);

    try std.testing.expectEqual(0, task_batch.len);
    try std.testing.expectEqual(next_reserve_before, result.queue.next_reserve);
    try std.testing.expectEqual(0, metrics.inflight_jobs);
}
