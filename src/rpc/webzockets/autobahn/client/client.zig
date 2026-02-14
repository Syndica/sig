const std = @import("std");
const xev = @import("xev");
const ws = @import("webzockets_lib");

pub const std_options: std.Options = .{
    .log_level = .info,
};

const log = std.log.scoped(.autobahn_client);

/// Embedded read buffer size per connection.
const read_buf_size: usize = 4096;

/// Maximum reassembled message size — Autobahn sends up to ~16MB.
const max_message_size: usize = 20 * 1024 * 1024;

const AutobahnClient = ws.Client(AutobahnClientHandler, read_buf_size);

/// Execution phase for a single fuzzingserver connection.
const Phase = enum {
    get_case_count,
    run_case,
    update_reports,
    update_reports_periodic,
};

/// Orchestrates sequential Autobahn case execution and report updates.
const AutobahnRunner = struct {
    loop: *xev.Loop,
    allocator: std.mem.Allocator,
    current_case: usize,
    total_cases: usize,
    conn: AutobahnClient.Conn,
    client: AutobahnClient,
    handler: AutobahnClientHandler,
    phase: Phase,
    path_buf: [256]u8 = undefined,
    csprng: ws.ClientMaskPRNG,
    retry_count: usize = 0,
    retry_timer: xev.Timer = .{},
    retry_timer_completion: xev.Completion = undefined,

    const max_retries = 20;
    const retry_delay_ms = 3000;

    fn init(allocator: std.mem.Allocator, loop: *xev.Loop) AutobahnRunner {
        var seed: [ws.ClientMaskPRNG.secret_seed_length]u8 = undefined;
        std.crypto.random.bytes(&seed);
        return .{
            .loop = loop,
            .allocator = allocator,
            .current_case = 1,
            .total_cases = 0,
            .conn = undefined,
            .client = undefined,
            .handler = undefined,
            .phase = .get_case_count,
            .csprng = ws.ClientMaskPRNG.init(seed),
        };
    }

    fn retryTimerCallback(
        self_opt: ?*AutobahnRunner,
        _: *xev.Loop,
        _: *xev.Completion,
        r: xev.Timer.RunError!void,
    ) xev.CallbackAction {
        r catch {
            log.err("retry timer failed", .{});
            return .disarm;
        };
        const self = self_opt.?;
        self.getCaseCount() catch |err| {
            log.err("getCaseCount failed: {}", .{err});
        };
        return .disarm;
    }

    fn deinit(_: *AutobahnRunner) void {}

    /// First step: connect to /getCaseCount to discover how many cases there are.
    fn getCaseCount(self: *AutobahnRunner) !void {
        log.debug("getCaseCount: connecting to /getCaseCount", .{});
        self.phase = .get_case_count;
        self.handler = .{ .runner = self };
        self.client = AutobahnClient.init(
            self.allocator,
            self.loop,
            &self.handler,
            &self.conn,
            &self.csprng,
            .{
                .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 9001),
                .path = "/getCaseCount",
                .max_message_size = max_message_size,
            },
        );
        try self.client.connect();
        log.debug("getCaseCount: connect submitted to loop", .{});
    }

    /// Start the next test case, or trigger report generation when done.
    fn startNextCase(self: *AutobahnRunner) !void {
        if (self.current_case > self.total_cases) {
            // All cases done — connect to updateReports and finish
            log.info("All {d} cases complete, generating report...", .{self.total_cases});
            try self.connectUpdateReports(false);
            return;
        }

        const case_num = self.current_case;
        self.current_case += 1;

        log.info("Running case {d}/{d}", .{ case_num, self.total_cases });

        // Build path: /runCase?case=N&agent=webzockets
        const path = std.fmt.bufPrint(
            &self.path_buf,
            "/runCase?case={d}&agent=webzockets",
            .{case_num},
        ) catch {
            log.debug("startNextCase: ERROR — failed to format path for case {d}", .{case_num});
            return;
        };

        self.phase = .run_case;
        self.handler = .{ .runner = self };
        self.client = AutobahnClient.init(
            self.allocator,
            self.loop,
            &self.handler,
            &self.conn,
            &self.csprng,
            .{
                .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 9001),
                .path = path,
                .max_message_size = max_message_size,
            },
        );
        try self.client.connect();
    }

    /// Connect to /updateReports to tell the fuzzingserver to generate HTML.
    fn connectUpdateReports(self: *AutobahnRunner, periodic: bool) !void {
        log.debug("connectUpdateReports: periodic={}", .{periodic});
        self.phase = if (periodic) .update_reports_periodic else .update_reports;
        self.handler = .{ .runner = self };
        self.client = AutobahnClient.init(
            self.allocator,
            self.loop,
            &self.handler,
            &self.conn,
            &self.csprng,
            .{
                .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 9001),
                .path = "/updateReports?agent=webzockets",
                .max_message_size = max_message_size,
            },
        );
        try self.client.connect();
    }

    /// Called from handler when a connection's socket is fully closed.
    /// It is safe to overwrite `self.client` here because xev captures all
    /// completion state before invoking callbacks, and no code in the return
    /// path accesses the old client after this function returns.
    fn onConnectionDone(self: *AutobahnRunner) void {
        const was_opened = self.handler.opened;
        log.debug("onConnectionDone: phase={s}, opened={}", .{ @tagName(self.phase), was_opened });
        // conn.deinit() releases buffers back to the pool.
        if (was_opened) {
            self.conn.deinit();
        }

        // Retry getCaseCount if it failed (server may not be fully ready yet).
        if (self.phase == .get_case_count and self.total_cases == 0) {
            self.retry_count += 1;
            if (self.retry_count > max_retries) {
                log.err("getCaseCount failed after {d} retries, giving up.", .{max_retries});
                return;
            }
            if (!was_opened) {
                log.warn("WebSocket handshake to /getCaseCount failed, " ++
                    "retrying in {d}s ({d}/{d})...", .{
                    retry_delay_ms / 1000,
                    self.retry_count,
                    max_retries,
                });
            } else {
                log.warn("Got 0 cases from fuzzingserver, " ++
                    "retrying in {d}s ({d}/{d})...", .{
                    retry_delay_ms / 1000,
                    self.retry_count,
                    max_retries,
                });
            }
            // Schedule retry via xev timer
            self.retry_timer = xev.Timer.init() catch {
                log.err("failed to create retry timer", .{});
                return;
            };
            self.retry_timer_completion = .{};
            self.retry_timer.run(
                self.loop,
                &self.retry_timer_completion,
                retry_delay_ms,
                AutobahnRunner,
                self,
                retryTimerCallback,
            );
            return;
        }

        if (self.phase == .get_case_count) {
            log.info("Fuzzingserver reports {d} test cases", .{self.total_cases});
        }

        // Proceed to next step.
        const next_res = switch (self.phase) {
            .get_case_count => self.startNextCase(),
            .run_case => if (self.current_case > 1 and (self.current_case - 1) % 10 == 0)
                self.connectUpdateReports(true)
            else
                self.startNextCase(),
            .update_reports_periodic => self.startNextCase(),
            .update_reports => {
                log.info("Report generation complete.", .{});
                return;
            },
        };

        next_res catch |err| {
            log.err("failed to start next step: {}", .{err});
        };
    }
};

/// Echo handler used for individual Autobahn test-case connections.
const AutobahnClientHandler = struct {
    const PendingMessage = struct {
        data: []u8,
        is_text: bool,
        next: ?*PendingMessage = null,
    };

    runner: *AutobahnRunner,
    opened: bool = false,

    /// Message currently in-flight; freed in onWriteComplete/onClose.
    sent_data: ?[]u8 = null,
    /// Pending outbound messages while a write is in flight.
    queue_head: ?*PendingMessage = null,
    /// Tail pointer for O(1) queue append.
    queue_tail: ?*PendingMessage = null,

    pub fn onOpen(self: *AutobahnClientHandler, conn: *AutobahnClient.Conn) void {
        self.opened = true;
        log.debug("handler.onOpen: phase={s}", .{@tagName(self.runner.phase)});
        if (self.runner.phase == .update_reports or self.runner.phase == .update_reports_periodic) {
            // For updateReports, just close immediately after connection opens
            log.debug("handler.onOpen: updateReports — closing immediately", .{});
            conn.close(.normal, "");
        }
    }

    /// Explicitly handle pings so every ping gets its own pong response.
    /// Without this, the library's auto-pong uses "latest wins" semantics,
    /// which is spec-compliant but fails Autobahn test 2.10 (expects a
    /// pong for each of 10 rapidly sent pings).
    pub fn onPing(_: *AutobahnClientHandler, conn: *AutobahnClient.Conn, data: []const u8) void {
        conn.sendPong(data) catch |err| {
            log.err("sendPong failed: {}", .{err});
        };
    }

    pub fn onMessage(
        self: *AutobahnClientHandler,
        conn: *AutobahnClient.Conn,
        message: ws.Message,
    ) void {
        log.debug("handler.onMessage: phase={s}, type={s}, len={d}", .{
            @tagName(self.runner.phase),
            @tagName(message.type),
            message.data.len,
        });

        switch (self.runner.phase) {
            .get_case_count => {
                // Server sends case count as a text message
                if (message.type == .text) {
                    const trimmed = std.mem.trim(u8, message.data, &[_]u8{ ' ', '\t', '\r', '\n' });
                    log.debug("handler.onMessage: getCaseCount body=\"{s}\"", .{trimmed});
                    self.runner.total_cases = std.fmt.parseInt(usize, trimmed, 10) catch 0;
                    log.debug("handler.onMessage: parsed total_cases={d}", .{
                        self.runner.total_cases,
                    });
                }
            },
            .run_case => {
                switch (message.type) {
                    .text => {
                        if (!std.unicode.utf8ValidateSlice(message.data)) {
                            conn.close(.invalid_payload, "Invalid UTF-8");
                            return;
                        }
                        self.enqueue(conn, message.data, true);
                    },
                    .binary => self.enqueue(conn, message.data, false),
                    else => {},
                }
            },
            else => {},
        }
    }

    fn enqueue(
        self: *AutobahnClientHandler,
        conn: *AutobahnClient.Conn,
        data: []const u8,
        is_text: bool,
    ) void {
        const allocator = self.runner.allocator;
        const copy = allocator.dupe(u8, data) catch return;
        const msg = allocator.create(PendingMessage) catch {
            allocator.free(copy);
            return;
        };
        msg.* = .{
            .data = copy,
            .is_text = is_text,
        };
        // Append to tail
        if (self.queue_tail) |tail| {
            tail.next = msg;
        } else {
            self.queue_head = msg;
        }
        self.queue_tail = msg;
        self.drainQueue(conn);
    }

    fn drainQueue(self: *AutobahnClientHandler, conn: *AutobahnClient.Conn) void {
        while (self.queue_head) |msg| {
            if (self.sent_data != null) return; // write in flight
            // Pop from head
            self.queue_head = msg.next;
            if (self.queue_head == null) self.queue_tail = null;

            if (msg.is_text) {
                conn.sendText(msg.data) catch {
                    self.runner.allocator.free(msg.data);
                    self.runner.allocator.destroy(msg);
                    continue;
                };
            } else {
                conn.sendBinary(msg.data) catch {
                    self.runner.allocator.free(msg.data);
                    self.runner.allocator.destroy(msg);
                    continue;
                };
            }
            self.sent_data = msg.data;
            self.runner.allocator.destroy(msg);
            return;
        }
    }

    pub fn onWriteComplete(self: *AutobahnClientHandler, conn: *AutobahnClient.Conn) void {
        log.debug("handler.onWriteComplete: phase={s}", .{@tagName(self.runner.phase)});
        if (self.sent_data) |data| {
            self.runner.allocator.free(data);
            self.sent_data = null;
        }
        self.drainQueue(conn);
    }

    pub fn onClose(self: *AutobahnClientHandler, _: *AutobahnClient.Conn) void {
        log.debug("handler.onClose: phase={s}", .{@tagName(self.runner.phase)});
        const allocator = self.runner.allocator;
        if (self.sent_data) |data| {
            allocator.free(data);
            self.sent_data = null;
        }
        while (self.queue_head) |msg| {
            self.queue_head = msg.next;
            allocator.free(msg.data);
            allocator.destroy(msg);
        }
        self.queue_tail = null;
    }

    pub fn onSocketClose(self: *AutobahnClientHandler) void {
        log.debug("handler.onSocketClose: phase={s}", .{@tagName(self.runner.phase)});
        self.runner.onConnectionDone();
    }
};

fn run(allocator: std.mem.Allocator) !void {
    // Wait for Docker fuzzingserver to start
    log.info("Waiting for fuzzingserver on port 9001...", .{});
    const max_retries = 60;
    var attempt: usize = 0;
    while (attempt < max_retries) : (attempt += 1) {
        // Try connecting to see if the server is up
        const stream = std.net.tcpConnectToHost(allocator, "127.0.0.1", 9001) catch {
            log.warn("attempt {d}/{d} — not ready, retrying in 3s...", .{
                attempt + 1,
                max_retries,
            });
            std.time.sleep(3 * std.time.ns_per_s);
            continue;
        };
        stream.close();
        break;
    }
    if (attempt == max_retries) {
        log.err("fuzzingserver did not become ready after {d} attempts.", .{max_retries});
        return error.ServerNotReady;
    }
    log.info("Fuzzingserver is up.", .{});

    // Init event loop
    var thread_pool = xev.ThreadPool.init(.{});
    defer thread_pool.deinit();
    defer thread_pool.shutdown();

    var loop = try xev.Loop.init(.{ .thread_pool = &thread_pool });
    defer loop.deinit();

    // Init runner — first connection will be getCaseCount
    var runner = AutobahnRunner.init(allocator, &loop);
    defer runner.deinit();
    try runner.getCaseCount();

    log.debug("main: entering loop.run(.until_done)", .{});

    // Run until all cases are done
    try loop.run(.until_done);

    log.info("Autobahn client test run complete.", .{});
    log.info("Check autobahn/client/reports/index.html for results.", .{});
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    run(allocator) catch |err| {
        if (gpa.deinit() == .leak) {
            log.err("GPA detected memory leaks while exiting with error: {}", .{err});
        }
        return err;
    };

    if (gpa.deinit() == .leak) {
        return error.MemoryLeakDetected;
    }
}
