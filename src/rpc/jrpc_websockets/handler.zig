const std = @import("std");
const ws = @import("webzockets");
const sig = @import("sig");

const types = @import("types.zig");
const protocol = @import("protocol.zig");
const NotifQueue = @import("NotifQueue.zig");
const runtime_mod = @import("runtime.zig");
const ws_request = @import("ws_request.zig");

const NotifPayload = sig.sync.RcSlice(u8);
const SubId = types.SubId;
const SubReqKey = types.SubReqKey;
const Id = sig.rpc.request.Id;
const WsRequest = ws_request.WsRequest;

const ErrorCode = protocol.ErrorCode;

/// Per-subscription state: tracks next read position in a queue.
pub const SubState = struct {
    sub_id: SubId,
    queue: *NotifQueue,
    next_index: u64,
};

/// JRPC WebSocket handler: one instance per connection.
/// Implements the webzockets Handler interface.
///
/// Notes:
/// - This handler must only be accessed from the libxev loop thread.
/// - Peer requests are processed serially, and are not queued to avoid
///   need for queue/allocating requests.
/// - Notifications are ref-counted and received from NotifQueues, responses
///   are serialized on demand and owned by the handler (`response_buf`).
pub const JRPCHandler = struct {
    /// WebSocket connection, null when not connected.
    conn: ?*Conn,
    /// Unordered list of active subscriptions for this connection.
    active_subs: std.ArrayList(SubState),
    send_state: SendState,
    ctx: *Context,
    allocator: std.mem.Allocator,
    parse_arena_state: std.heap.ArenaAllocator,

    pub const Context = runtime_mod.RuntimeContext;

    /// Send state machine, events are triggered by methods, false/null returned
    /// for invalid transitions (indicates bug). We log error and reset to safe
    /// state instead of panicking to minimize blast radius.
    const SendState = struct {
        write_state: WriteState,
        /// Buffer for serializing responses, reused for every response.
        /// `response_buf.items` is the slice to send.
        response_buf: std.ArrayList(u8),
        /// Reusable buffer for batching notification payloads. Multiple
        /// pre-framed notification payloads are copied here and sent as
        /// a single `sendRaw` call. Payloads are released immediately
        /// after copying, so no ref-counted state is held in flight.
        notif_batch_buf: std.ArrayList(u8),

        const WriteState = enum {
            idle,
            response_pending,
            response_inflight,
            notif_inflight,
            notif_inflight_response_pending,
        };

        const WriteCompleteKind = enum {
            response,
            notif,
        };

        fn init() SendState {
            return .{
                .write_state = .idle,
                .response_buf = .{},
                .notif_batch_buf = .{},
            };
        }

        fn deinit(self: *SendState, allocator: std.mem.Allocator) void {
            self.write_state = .idle;
            self.response_buf.deinit(allocator);
            self.notif_batch_buf.deinit(allocator);
        }

        /// Event: response is ready to be sent
        fn onResponseReady(self: *SendState) bool {
            switch (self.write_state) {
                .idle => {
                    self.write_state = .response_pending;
                    return true;
                },
                .notif_inflight => {
                    self.write_state = .notif_inflight_response_pending;
                    return true;
                },
                .response_pending,
                .response_inflight,
                .notif_inflight_response_pending,
                => return false,
            }
        }

        /// Event: send was accepted for response payload
        fn onResponseSendAccepted(self: *SendState) bool {
            if (self.write_state != .response_pending) {
                return false;
            }
            self.write_state = .response_inflight;
            return true;
        }

        /// Event: send was accepted for notification batch
        fn onNotifSendAccepted(self: *SendState) bool {
            if (self.write_state != .idle) {
                return false;
            }
            self.write_state = .notif_inflight;
            return true;
        }

        /// Event: a send write has completed
        fn onWriteComplete(self: *SendState) ?WriteCompleteKind {
            switch (self.write_state) {
                .response_inflight => {
                    self.write_state = .idle;
                    return .response;
                },
                .notif_inflight => {
                    self.write_state = .idle;
                    return .notif;
                },
                .notif_inflight_response_pending => {
                    self.write_state = .response_pending;
                    return .notif;
                },
                .idle, .response_pending => return null,
            }
        }
    };

    const log = std.log.scoped(.jrpc_ws_handler);

    pub const WebSocketServer = ws.Server(JRPCHandler, 4096);
    pub const Conn = WebSocketServer.Conn;

    pub fn init(
        _: ws.http.Request,
        context: *Context,
    ) !JRPCHandler {
        return .{
            .conn = null,
            .active_subs = .{},
            .send_state = SendState.init(),
            .ctx = context,
            .allocator = context.allocator,
            .parse_arena_state = std.heap.ArenaAllocator.init(context.allocator),
        };
    }

    pub fn onHandshakeFailed(self: *JRPCHandler) void {
        log.debug("websocket handshake failed", .{});
        self.active_subs.deinit(self.allocator);
        self.send_state.deinit(self.allocator);
        self.parse_arena_state.deinit();
    }

    pub fn onOpen(self: *JRPCHandler, conn: *Conn) void {
        self.conn = conn;
        self.ctx.metrics.connections_opened += 1;
    }

    pub fn onMessage(
        self: *JRPCHandler,
        conn: *Conn,
        message: ws.Message,
    ) void {
        if (self.conn == null) {
            log.debug("onMessage ignored without active connection", .{});
            return;
        }

        conn.pauseReads();

        const text = switch (message.type) {
            .text => message.data,
            else => {
                log.debug("non-text frame rejected", .{});
                self.sendErrorResponse(
                    .null,
                    ErrorCode.invalid_request,
                    "text frames only",
                );
                return;
            },
        };

        // NOTE: parse arena is not used outside this scope, we always just reset and reuse here
        _ = self.parse_arena_state.reset(.retain_capacity);
        const parse_arena = self.parse_arena_state.allocator();

        // Parse request as jsonrpc
        const request_dyn = std.json.parseFromSliceLeaky(
            WsRequest.Dynamic,
            parse_arena,
            text,
            .{},
        ) catch |err| {
            log.debug("failed to parse request as jrpc: {}", .{err});
            self.sendErrorResponse(.null, ErrorCode.parse_error, "parse error");
            return;
        };

        // Convert jsonrpc request into strongly-typed request struct
        var parse_diag = WsRequest.Dynamic.ParseDiagnostic.INIT;
        const request = request_dyn.parse(parse_arena, .{}, &parse_diag) catch |err| {
            log.debug("failed to parse request body: {}", .{err});
            self.handleRequestParseError(err, parse_diag.err.id orelse .null);
            return;
        };
        const id = request.id;

        // Reject unstable methods (currently not implemented).
        switch (request.method) {
            .blockSubscribe,
            .blockUnsubscribe,
            .slotsUpdatesSubscribe,
            .slotsUpdatesUnsubscribe,
            .voteSubscribe,
            .voteUnsubscribe,
            => {
                self.sendErrorResponse(
                    id,
                    ErrorCode.method_not_found,
                    "method not implemented",
                );
                return;
            },
            else => {},
        }

        if (SubReqKey.fromMethod(&request.method)) |key| {
            self.handleSubscribe(id, &key);
            return;
        }

        switch (request.method) {
            inline .accountUnsubscribe,
            .logsUnsubscribe,
            .programUnsubscribe,
            .rootUnsubscribe,
            .signatureUnsubscribe,
            .slotUnsubscribe,
            => |unsub| {
                self.handleUnsubscribe(id, unsub.sub_id);
            },
            else => {
                log.err("bug: unhandled branch for method: {}", .{request.method});
                self.sendInternalError(id);
                return;
            },
        }
    }

    fn handleRequestParseError(
        self: *JRPCHandler,
        err: (std.mem.Allocator.Error || WsRequest.Dynamic.ParseError),
        id: Id,
    ) void {
        switch (err) {
            error.OutOfMemory => {
                log.warn("request parse failed: out of memory", .{});
                self.sendInternalError(id);
            },
            error.InvalidMethod => {
                log.debug("request parse failed: unsupported method", .{});
                self.sendErrorResponse(
                    id,
                    ErrorCode.method_not_found,
                    "unsupported method",
                );
            },
            error.InvalidParams,
            error.ParamsLengthMismatch,
            => {
                log.debug("request parse failed: invalid params", .{});
                self.sendErrorResponse(
                    id,
                    ErrorCode.invalid_params,
                    "invalid params",
                );
            },
            error.MissingJsonRpcVersion,
            error.MissingMethod,
            error.MissingParams,
            error.InvalidJsonRpcVersion,
            => {
                log.debug("request parse failed: invalid request", .{});
                self.sendErrorResponse(
                    id,
                    ErrorCode.invalid_request,
                    "invalid request",
                );
            },
        }
    }

    fn handleSubscribe(
        self: *JRPCHandler,
        request_id: Id,
        key: *const SubReqKey,
    ) void {
        self.ctx.metrics.subscribe_requests += 1;

        const result = self.ctx.sub_map.getOrCreate(key) catch |err| {
            log.warn("subscribe getOrCreate failed: {}", .{err});
            self.sendInternalError(request_id);
            return;
        };

        // Duplicate check: same sub_id means same SubReqKey
        // already active.
        for (self.active_subs.items) |s| {
            if (s.sub_id == result.sub_id) {
                log.debug("duplicate subscription request for sub_id={d}", .{result.sub_id});
                self.sendErrorResponse(
                    request_id,
                    ErrorCode.invalid_params,
                    "duplicate subscription",
                );
                return;
            }
        }

        const q = result.queue;

        q.addSubscriber(self) catch |err| {
            log.warn("subscribe addSubscriber failed: {}", .{err});
            self.sendInternalError(request_id);
            return;
        };

        // Future-only delivery: start at head + 1.
        self.active_subs.append(self.allocator, .{
            .sub_id = result.sub_id,
            .queue = q,
            .next_index = q.head + 1,
        }) catch |err| {
            log.warn("subscribe active_subs append failed: {}", .{err});
            q.removeSubscriber(self, q.head + 1);
            self.sendInternalError(request_id);
            return;
        };

        protocol.serializeSubscribeResponse(
            &self.send_state.response_buf,
            self.allocator,
            request_id,
            result.sub_id,
        ) catch {
            log.warn("failed to serialize subscribe response", .{});
            return;
        };
        self.responseReadyAndSend();
    }

    fn handleUnsubscribe(
        self: *JRPCHandler,
        request_id: Id,
        sub_id: SubId,
    ) void {
        self.ctx.metrics.unsubscribe_requests += 1;

        const idx = self.findActiveSubIndex(sub_id) orelse {
            log.debug("unsubscribe for unknown sub_id={d}", .{sub_id});
            self.sendErrorResponse(
                request_id,
                ErrorCode.invalid_params,
                "subscription not found",
            );
            return;
        };

        const sub = self.active_subs.swapRemove(idx);
        const q = sub.queue;
        q.removeSubscriber(self, sub.next_index);

        self.ctx.maybeRemoveIdleQueue(sub.sub_id, q);

        protocol.serializeUnsubscribeResponse(
            &self.send_state.response_buf,
            self.allocator,
            request_id,
        ) catch {
            log.warn("failed to serialize unsubscribe response", .{});
            return;
        };
        self.responseReadyAndSend();
    }

    pub fn sendNext(self: *JRPCHandler) void {
        if (self.conn == null) {
            return;
        }

        switch (self.send_state.write_state) {
            .response_inflight, .notif_inflight, .notif_inflight_response_pending => {
                return;
            },
            .response_pending => {
                // if a response is pending, send it before notifications.
                if (self.trySendPayload(self.send_state.response_buf.items)) {
                    if (!self.send_state.onResponseSendAccepted()) {
                        self.safeResetSendState("response send accepted in invalid state");
                    } else {
                        self.ctx.metrics.responses_sent_bytes +=
                            @intCast(self.send_state.response_buf.items.len);
                    }
                }
                return;
            },
            .idle => {},
        }

        // TODO(perf): we need to set TCP_NODELAY on the TCP socket and add a short flush interval
        // using an xev timer to ensure low latency without crippling throughput.

        // Batch available notifications into one send. Cap batch size to avoid blocking the event
        // loop when a single handler has a large backlog of pending notifications.
        self.send_state.notif_batch_buf.clearRetainingCapacity();
        var batch_count: u64 = 0;
        var batch_bytes: u64 = 0;

        var start_idx: usize = 0;
        var first_pick = true;
        while (first_pick or batch_bytes < self.ctx.max_batch_bytes) {
            first_pick = false;
            const pick = self.pickNextNotification(start_idx) orelse break;
            start_idx = pick.sub_idx;
            const payload_slice = pick.payload.payload();
            // TODO(perf): this could copy payloads that are larger than max batch size bytes,
            // but just having everything go through batch for simplicity. Without vectored writes
            // it's difficult to optimize as you cannot uphold all 3 desired properties:
            // 1. Don’t copy oversized payloads.
            // 2. Preserve per-queue order.
            // 3. Keep batches full.
            self.send_state.notif_batch_buf.appendSlice(self.allocator, payload_slice) catch {
                runtime_mod.releasePayload(self.ctx, pick.payload);
                break;
            };
            self.active_subs.items[pick.sub_idx].next_index += 1;
            batch_count += 1;
            batch_bytes += @intCast(payload_slice.len);
            runtime_mod.releasePayload(self.ctx, pick.payload);
        }

        if (batch_count == 0) {
            return;
        }

        if (!self.trySendPayload(self.send_state.notif_batch_buf.items)) {
            // can happen if client disconnecting
            return;
        }

        if (!self.send_state.onNotifSendAccepted()) {
            self.safeResetSendState("notification send accepted in invalid state");
            return;
        }
        self.ctx.metrics.notifications_sent += batch_count;
        self.ctx.metrics.notifications_sent_bytes += batch_bytes;
    }

    const NotifPick = struct {
        payload: NotifPayload,
        sub_idx: usize,
    };

    fn pickNextNotification(self: *JRPCHandler, start_idx: usize) ?NotifPick {
        for (self.active_subs.items[start_idx..], start_idx..) |*s, idx| {
            if (self.tryGetFromSubState(s, idx)) |pick| {
                return pick;
            }
        }
        return null;
    }

    fn tryGetFromSubState(self: *JRPCHandler, s: *SubState, idx: usize) ?NotifPick {
        const q = s.queue;
        const maybe_payload = q.get(s.next_index) catch |err| switch (err) {
            error.IndexOverwritten, error.IndexSkipped => blk: {
                const new_tail = q.tail;
                const next_after_current = s.next_index + 1;
                const recovery_index = @max(new_tail, next_after_current);
                const skip = recovery_index - s.next_index;
                log.debug("notification index unavailable; skipping {d} entries", .{skip});
                self.ctx.metrics.skipped_notifications += skip;
                s.next_index = recovery_index;
                break :blk q.get(s.next_index) catch |retry_err| {
                    log.debug("notification retry get failed: {}", .{retry_err});
                    return null;
                };
            },
        };
        const payload = maybe_payload orelse return null;
        return .{ .payload = payload, .sub_idx = idx };
    }

    fn findActiveSubIndex(
        self: *JRPCHandler,
        sub_id: SubId,
    ) ?usize {
        for (self.active_subs.items, 0..) |s, i| {
            if (s.sub_id == sub_id) {
                return i;
            }
        }
        return null;
    }

    fn safeResetSendState(self: *JRPCHandler, comptime reason: []const u8) void {
        log.err("invalid send state: {s}; resetting", .{reason});
        self.send_state.write_state = .idle;
        if (self.conn) |conn| {
            conn.resumeReads();
        }
    }

    fn trySendPayload(
        self: *JRPCHandler,
        data: []const u8,
    ) bool {
        const connection = self.conn orelse return false;
        connection.sendRaw(data) catch |err| {
            switch (err) {
                error.InvalidState => {
                    log.debug("sendRaw failed: InvalidState", .{});
                    return false;
                },
                error.WriteBusy => {
                    log.debug("sendRaw failed: WriteBusy", .{});
                    return false;
                },
            }
        };
        return true;
    }

    pub fn onWriteComplete(self: *JRPCHandler, conn: *Conn) void {
        const completed = self.send_state.onWriteComplete() orelse {
            self.safeResetSendState("onWriteComplete in invalid state");
            self.sendNext();
            return;
        };

        switch (completed) {
            .response => {
                conn.resumeReads();
            },
            .notif => {},
        }

        self.sendNext();
    }

    pub fn onClose(self: *JRPCHandler, _: *Conn) void {
        self.conn = null;
        self.ctx.metrics.connections_closed += 1;

        for (self.active_subs.items) |s| {
            const q = s.queue;
            q.removeSubscriber(self, s.next_index);
            self.ctx.maybeRemoveIdleQueue(s.sub_id, q);
        }
        self.active_subs.deinit(self.allocator);
        self.send_state.deinit(self.allocator);
        self.parse_arena_state.deinit();
    }

    fn responseReadyAndSend(self: *JRPCHandler) void {
        if (!self.send_state.onResponseReady()) {
            log.err("dropping response: send state already has pending/inflight response", .{});
            return;
        }
        self.sendNext();
    }

    fn sendInternalError(self: *JRPCHandler, id: Id) void {
        self.sendErrorResponse(
            id,
            ErrorCode.internal_error,
            "internal error",
        );
    }

    fn sendErrorResponse(
        self: *JRPCHandler,
        id: Id,
        code: i32,
        message: []const u8,
    ) void {
        protocol.serializeErrorResponse(
            &self.send_state.response_buf,
            self.allocator,
            id,
            code,
            message,
        ) catch {
            log.warn("failed to serialize error response", .{});
            return;
        };
        self.responseReadyAndSend();
    }
};
