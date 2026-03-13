//! Shared runtime context passed to all handlers and the loop thread.
//!
//! For shutdown you must continue running the RuntimeContext loop and ThreadPool until inflight_jobs
//! drops to 0, then you can stop the loop and deint the context and threadpool.

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
/// Thread pool for running serialization jobs.
serialization_pool: *ThreadPool,
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
/// Number of serialization jobs submitted but not yet committed.
/// Incremented on job submit, decremented on commit receive.
/// Used during shutdown to wait for all in-flight work to complete.
inflight_jobs: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
/// Optional queue for off-loop payload allocator free work.
payload_free_queue: ?*Channel(ReleasedPayloadBytes) = null,
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
    serialization_pool: *ThreadPool,
    metrics: *metrics_mod.Metrics,
    max_batch_bytes: u64,
    loop: *xev.Loop,
    payload_free_queue: ?*Channel(ReleasedPayloadBytes) = null,
    wakeup_hook: ?WakeupHook = null,
};

pub fn init(deps: Dependencies) RuntimeContext {
    return .{
        .allocator = deps.allocator,
        .logger = .from(deps.logger),
        .sub_map = deps.sub_map,
        .slot_read_ctx = deps.slot_read_ctx,
        .slot_state_cache = .init(deps.slot_read_ctx, .from(deps.logger)),
        .inbound_event_queue = &deps.event_sink.channel,
        .commit_queue = deps.commit_queue,
        .loop_async = &deps.event_sink.loop_async,
        .serialization_pool = deps.serialization_pool,
        .metrics = deps.metrics,
        .max_batch_bytes = deps.max_batch_bytes,
        .loop = deps.loop,
        .notify_pending = &deps.event_sink.notify_pending,
        .payload_free_queue = deps.payload_free_queue,
        .wakeup_hook = deps.wakeup_hook,
    };
}

const SerializeTask = struct {
    runtime: *RuntimeContext,
    task: ThreadPool.Task,
    job: types.SerializeJob,

    fn deinit(self: *SerializeTask) void {
        self.job.event_data.deinit(self.runtime.allocator);
        self.runtime.allocator.destroy(self);
    }
};

/// Free resources owned directly by RuntimeContext.
/// IMPORTANT: shutdown the websocket server and wait for inflight_jobs to settle to 0 before calling deinit.
pub fn deinit(self: *RuntimeContext) void {
    const inflight_jobs = self.inflight_jobs.load(.acquire);
    if (inflight_jobs != 0) {
        self.logger.err().logf(
            "deinit called with inflight_jobs = {}, wait for it to settle to 0 first",
            .{inflight_jobs},
        );
    }
    self.slot_state_cache.deinit(self.allocator);
    self.pending_wake_queues.deinit(self.allocator);
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

fn executeSerializeTask(task: *ThreadPool.Task) void {
    const serialize_task: *SerializeTask = @alignCast(@fieldParentPtr("task", task));
    defer serialize_task.deinit();

    const runtime = serialize_task.runtime;
    const job = serialize_task.job;
    var serialize_timer = std.time.Timer.start() catch unreachable;

    const result: types.CommitResult = if (protocol.serializeNotification(
        runtime.allocator,
        job.sub_id,
        job.event_data,
        job.encoding,
        job.data_slice,
        job.read_ctx,
        job.sub_method,
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

fn submitSerialize(self: *RuntimeContext, job: types.SerializeJob) !void {
    const serialize_task = try self.allocator.create(SerializeTask);
    serialize_task.* = .{
        .runtime = self,
        .task = .{ .callback = RuntimeContext.executeSerializeTask },
        .job = job,
    };
    // TODO(perf): could maybe be batched.
    self.serialization_pool.schedule(.{
        .head = &serialize_task.task,
        .tail = &serialize_task.task,
        .len = 1,
    });
}

/// Drain all pending inbound events from producers.
fn drainInboundEvents(self: *RuntimeContext) void {
    while (self.inbound_event_queue.tryReceive()) |event| {
        self.metrics.events_received += 1;
        self.handleInboundEvent(event);
    }

    self.metrics.inbound_drain_calls += 1;
}

fn handleInboundEvent(self: *RuntimeContext, event: types.InboundEvent) void {
    // TODO: review how ownership should flow in Zig for this situation,
    // .slot_frozen case effectively takes ownership of the accounts data
    var e = event;
    defer e.deinit(self.inbound_event_queue.allocator);

    switch (e) {
        .logs => |logs_data| {
            // TODO: actual logs events and logsSubscribe (this placeholder)
            self.submitMethodMatchedJobs(.logs, .{ .logs = logs_data }, .base64);
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
            self.handleSlotTransition(slot_event_kind, slot_data.slot, transition);
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
            self.handleSlotTransition(.slot_confirmed, confirmed_slot, transition);
        },
        .tip_changed => |new_tip| {
            const transition = self.slot_state_cache.onTipChanged(self.slot_read_ctx, new_tip);
            self.handleSlotTransition(.tip_changed, new_tip, transition);
        },
    }
}

const SlotEventKind = union(enum) {
    slot_frozen: types.SlotEventData,
    slot_confirmed,
    slot_rooted: types.RootEventData,
    // TODO: this case is currently unused.
    tip_changed,
};

fn handleSlotTransition(
    self: *RuntimeContext,
    event_kind: SlotEventKind,
    slot: Slot,
    transition: SlotStateCache.Transition,
) void {
    // Track confirmed program slots for publishing confirmed commitment notifications
    var publishable_confirmed_slots: ?std.ArrayList(SlotStateCache.AncestorItem) = null;
    defer if (publishable_confirmed_slots) |*slots| {
        slots.deinit(self.allocator);
    };

    // TODO(perf): this is basically just brute force iterate and find matches and it's
    // running on the IO loop thread, so this wont scale.
    for (self.sub_map.entries.items) |*entry| {
        switch (entry.key.method) {
            .slot => {
                const slot_event = switch (event_kind) {
                    .slot_frozen => |slot_event| slot_event,
                    else => continue,
                };
                if (transition.cached_slot == null) {
                    continue;
                }
                _ = self.submitJobForEntry(entry.*, .{ .slot = slot_event }, .base64, .slot);
            },
            .root => {
                const root_event = switch (event_kind) {
                    .slot_rooted => |root_event| root_event,
                    else => continue,
                };
                if (transition.evict_through == null) {
                    continue;
                }
                _ = self.submitJobForEntry(entry.*, .{ .root = root_event }, .base64, .root);
            },
            .program => {
                if (event_kind == .tip_changed) {
                    continue;
                }
                const commitment = entry.key.params.program.commitment;
                if (!transitionMatchesCommitment(transition.commitments, commitment)) {
                    continue;
                }
                switch (commitment) {
                    .confirmed => {
                        if (publishable_confirmed_slots == null) {
                            publishable_confirmed_slots = self.slot_state_cache
                                .collectPublishableConfirmedSlots(
                                self.allocator,
                                slot,
                            ) catch |err| {
                                self.logger.err().logf(
                                    "failed to collect confirmed program slots from {}: {}",
                                    .{ slot, err },
                                );
                                continue;
                            };
                        }
                        const slots = publishable_confirmed_slots.?.items;
                        var index = slots.len;
                        while (index > 0) {
                            index -= 1;
                            const confirmed_slot = slots[index];
                            self.publishProgramSubscriptionForEntry(
                                entry,
                                confirmed_slot.cached_slot,
                                confirmed_slot.slot,
                            );
                        }
                    },
                    .processed, .finalized => {
                        const cached_slot = transition.cached_slot orelse continue;
                        self.publishProgramSubscriptionForEntry(entry, cached_slot, slot);
                    },
                }
            },
            .account => {
                // TODO(perf): we follow Agave's reevaluate approach and actaully
                //  here we do it for every slot processed. Actually could just use
                //  .tip_changed for processed commitment or via tracked forks avoid
                //  reevaluating if it's already in slot cache state.
                if (!transitionMatchesCommitment(
                    transition.commitments,
                    entry.key.params.account.commitment,
                )) {
                    continue;
                }
                self.submitAccountReevaluation(entry, slot);
            },
            else => {},
        }
    }

    if (transition.evict_through) |evict_through| {
        self.slot_state_cache.evictFinalizedThrough(evict_through);
    }
}

fn transitionMatchesCommitment(
    commitments: SlotStateCache.CommitmentMask,
    commitment: methods.Commitment,
) bool {
    return switch (commitment) {
        .processed => commitments.processed,
        .confirmed => commitments.confirmed,
        .finalized => commitments.finalized,
    };
}

/// accountSubscribe follows what is currently done in Agave:
/// reevaluate the current state of the account for the slot based on commitment level.
///
/// TODO(perf): this is pretty expensive to do for every account subscription on every slot,
/// in theory we could track fork state (slot state cache) to avoid reevaluating unless an
/// actual fork occurs, and even when a fork occurs we may already have the account in the
/// slot state cache.
fn submitAccountReevaluation(
    self: *RuntimeContext,
    entry: *sub_map_mod.MapEntry,
    commitment_slot: Slot,
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
    if (entry.last_notified_modified_slot) |last_modified_slot| {
        if (modified_slot == last_modified_slot) {
            account.deinit(self.allocator);
            return;
        }
    }
    errdefer account.deinit(self.allocator);

    if (account.lamports == 0) {
        // Missing/deleted accounts are still delivered as an explicit zero-lamport payload.
        // This is to match Agave.
        account.deinit(self.allocator);
        account = deletedAccountPlaceholder();
    }

    const rc = types.RcAccountWithPubkey.init(
        self.allocator,
        entry.key.params.account.pubkey,
        account,
    ) catch |err| {
        self.logger.err().logf("failed to clone account subscription payload: {}", .{err});
        return;
    };
    errdefer rc.release(self.allocator);

    const submitted = self.submitJobForEntry(entry.*, .{
        .account = .{ .rc = rc, .slot = commitment_slot },
    }, entry.key.params.account.encoding, .account);
    if (!submitted) {
        return;
    }
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

// Used for methods whose inbound event is already the final notification payload.
fn submitMethodMatchedJobs(
    self: *RuntimeContext,
    method: types.SubMethod,
    event_data: types.EventData,
    encoding: methods.AccountEncoding,
) void {
    var submitted = false;
    for (self.sub_map.entries.items) |entry| {
        if (entry.key.method == method) {
            submitted = self.submitJobForEntry(entry, event_data, encoding, method) or submitted;
        }
    }
    if (!submitted) {
        event_data.deinit(self.allocator);
    }
}

/// programSubscribe publishes from the cached modified accounts for one slot once that slot
// becomes visible at the requested commitment.
fn publishProgramSubscriptionForEntry(
    self: *RuntimeContext,
    entry: *sub_map_mod.MapEntry,
    cached_slot: *const SlotStateCache.CachedSlot,
    slot: Slot,
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

        // TODO(perf): clone has to allocate and then we also end up allocating again
        // for the RcAccountWithPubkey, ideally we would just use the Account as is and keep
        // the arena alive until outstanding events are returned from serialization.
        const cloned_account = modified_account.account.cloneOwned(self.allocator) catch |err| {
            self.logger.err().logf(
                "failed to clone program subscription payload: {}",
                .{err},
            );
            continue;
        };
        errdefer cloned_account.deinit(self.allocator);

        const rc = types.RcAccountWithPubkey.init(
            self.allocator,
            modified_account.pubkey,
            cloned_account,
        ) catch |err| {
            self.logger.err().logf(
                "failed to clone program subscription payload: {}",
                .{err},
            );
            continue;
        };
        _ = self.submitJobForEntry(entry.*, .{
            .account = .{ .rc = rc, .slot = slot },
        }, program_params.encoding, .program);
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

fn submitJobForEntry(
    self: *RuntimeContext,
    entry: sub_map_mod.MapEntry,
    event_data: types.EventData,
    encoding: methods.AccountEncoding,
    sub_method: types.SubMethod,
) bool {
    const q = entry.queue;
    if (q.subscriberCount() == 0) {
        event_data.deinit(self.allocator);
        return false;
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
        // Account/program rendering depends on subscription-local presentation options.
        .encoding = encoding,
        .data_slice = switch (entry.key.params) {
            .account => |params| params.data_slice,
            .program => |params| params.data_slice,
            else => null,
        },
        .read_ctx = switch (sub_method) {
            .account, .program => self.slot_read_ctx,
            else => null,
        },
        .sub_method = sub_method,
        .submitted_at = std.time.Instant.now() catch unreachable,
    };

    self.submitSerialize(job) catch {
        event_data.deinit(self.allocator);
        q.inflight_sers -= 1;
        if (idx) |i| {
            q.cancelReservation(i);
        }
        self.maybeRemoveIdleQueue(entry.sub_id, q);
        return false;
    };
    _ = self.inflight_jobs.fetchAdd(1, .monotonic);
    self.metrics.serialize_tasks_allocated += 1;
    return true;
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
        self.logger.err().log(
            "orphan commit message: sub_id not found in sub_map (invariant violation)",
        );
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
    if (q.subscriberCount() == 0 and q.inflight_sers == 0) {
        self.sub_map.removeById(sub_id);
    }
}

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
    var free_timer = std.time.Timer.start() catch unreachable;
    ctx.allocator.free(bytes);
    const elapsed_ns = free_timer.read();

    _ = ctx.metrics.payloads_freed.fetchAdd(1, .monotonic);
    _ = ctx.metrics.payload_free_wall_ns.fetchAdd(elapsed_ns, .monotonic);
}
