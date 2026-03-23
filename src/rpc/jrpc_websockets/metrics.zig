const std = @import("std");

// TODO: use actual metrics patterns for Sig.

/// Runtime metrics counters for the JRPC WebSocket broadcast server.
pub const Metrics = struct {
    // ── Connection Lifecycle ──────────────────────────────────────────

    /// Total connections opened.
    connections_opened: u64 = 0,
    /// Total connections closed.
    connections_closed: u64 = 0,

    // ── Subscription Management ────────────────────────────────────────

    /// Total subscribe requests.
    subscribe_requests: u64 = 0,
    /// Total unsubscribe requests.
    unsubscribe_requests: u64 = 0,
    /// Current number of distinct subscription keys/queues in sub_map.
    sub_map_keys_current: u64 = 0,
    /// Maximum observed number of distinct subscription keys/queues in sub_map.
    sub_map_keys_max: u64 = 0,

    // ── Inbound Event Processing ───────────────────────────────────────

    /// Total events received from producers.
    events_received: u64 = 0,
    /// Number of inbound drain invocations.
    inbound_drain_calls: u64 = 0,

    // ── Serialization Pipeline ─────────────────────────────────────────

    /// Total serialization jobs processed by loop thread.
    serialize_jobs: u64 = 0,
    /// Total serialization worker time (ns).
    serialize_ns: u64 = 0,
    /// Total enqueue->serialize-complete latency (ns).
    serialize_pipeline_ns: u64 = 0,
    /// Total serialized payload bytes produced by workers.
    serialize_payload_bytes: u64 = 0,
    /// Total heap allocations of serialization tasks.
    serialize_tasks_allocated: u64 = 0,
    /// Serialization errors from worker threads.
    serialize_errors: u64 = 0,

    // ── Commit Pipeline ────────────────────────────────────────────────

    /// Total notifications committed.
    notifications_committed: u64 = 0,
    /// Number of commit drain invocations.
    commit_drain_calls: u64 = 0,

    // ── Outbound Send Path ─────────────────────────────────────────────

    /// Total notifications sent to clients.
    notifications_sent: u64 = 0,
    /// Total bytes in notifications accepted for sending.
    notifications_sent_bytes: u64 = 0,
    /// Total bytes in JSON-RPC responses accepted for sending.
    responses_sent_bytes: u64 = 0,
    /// Notifications skipped due to subscriber lag (IndexOverwritten).
    skipped_notifications: u64 = 0,
    /// Send errors (unexpected errors, not WriteBusy/InvalidState).
    send_errors: u64 = 0,
    /// Total payload buffers freed (last Rc reference released).
    payloads_freed: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    /// Total wall time spent freeing payload buffers (ns).
    payload_free_wall_ns: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    pub fn log(self: *const Metrics, inflight_jobs: u64) void {
        const payloads_freed = self.payloads_freed.load(.acquire);
        const payload_free_wall_ns = self.payload_free_wall_ns.load(.acquire);

        const metrics_log = std.log.scoped(.jrpc_ws_metrics);

        metrics_log.info(
            "events={d} committed={d} sent={d} " ++
                "sent_bytes={d} resp_bytes={d} skipped={d} " ++
                "ser_jobs={d} ser_ns={d} pipeline_ns={d} ser_bytes={d} " ++
                "ser_tasks_alloc={d} inflight_jobs={d} " ++
                "ser_err={d} send_err={d} " ++
                "payloads_freed={d} payload_free_ns={d} " ++
                "in_drains={d} commit_drains={d} " ++
                "subs={d} unsubs={d} " ++
                "conns_open={d} conns_close={d} " ++
                "sub_keys={d} sub_keys_max={d}",
            .{
                self.events_received,
                self.notifications_committed,
                self.notifications_sent,
                self.notifications_sent_bytes,
                self.responses_sent_bytes,
                self.skipped_notifications,
                self.serialize_jobs,
                self.serialize_ns,
                self.serialize_pipeline_ns,
                self.serialize_payload_bytes,
                self.serialize_tasks_allocated,
                inflight_jobs,
                self.serialize_errors,
                self.send_errors,
                payloads_freed,
                payload_free_wall_ns,
                self.inbound_drain_calls,
                self.commit_drain_calls,
                self.subscribe_requests,
                self.unsubscribe_requests,
                self.connections_opened,
                self.connections_closed,
                self.sub_map_keys_current,
                self.sub_map_keys_max,
            },
        );
    }

    pub fn reset(self: *Metrics) void {
        self.* = .{};
    }
};
