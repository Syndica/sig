const std = @import("std");
const ws = @import("webzockets_lib");

const frame = ws.frame;
const mask_mod = ws.mask;
const http = ws.http;
const Opcode = ws.Opcode;
const Message = ws.Message;

/// Blocking, frame-level WebSocket client for testing close handshake behavior
/// against the webzockets server. Connects via TCP, performs HTTP upgrade, then
/// provides frame-level send/receive with client masking.
pub const RawClient = struct {
    stream: std.net.Stream,
    allocator: std.mem.Allocator,
    read_buf: []u8,
    read_pos: usize, // start of unconsumed data
    read_end: usize, // end of valid data in read_buf

    pub const default_read_buf_size: usize = 4096;

    pub const ConnectOpts = struct {
        read_buf_size: usize = default_read_buf_size,
        read_timeout_ms: u32 = 2000,
    };

    // ====================================================================
    // Connect + Lifecycle
    // ====================================================================

    /// Blocking connect and WebSocket handshake to 127.0.0.1:port.
    /// Uses default 4096-byte read buffer.
    pub fn connect(allocator: std.mem.Allocator, port: u16) !RawClient {
        return connectEx(allocator, port, .{});
    }

    /// Blocking connect with configurable options (e.g. larger read buffer
    /// for tests that receive large echoed messages).
    pub fn connectEx(allocator: std.mem.Allocator, port: u16, opts: ConnectOpts) !RawClient {
        const address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, port);
        const stream = try std.net.tcpConnectToAddress(address);
        errdefer stream.close();

        // Set SO_RCVTIMEO for blocking reads (defaults to 2s) to reduce scheduler-jitter flakes.
        const timeout = std.posix.timeval{
            .sec = @intCast(opts.read_timeout_ms / 1000),
            .usec = @intCast((opts.read_timeout_ms % 1000) * 1000),
        };
        try std.posix.setsockopt(
            stream.handle,
            std.posix.SOL.SOCKET,
            std.posix.SO.RCVTIMEO,
            std.mem.asBytes(&timeout),
        );

        // Generate WebSocket key and build upgrade request
        var key_buf: [24]u8 = undefined;
        var raw_key: [16]u8 = undefined;
        std.crypto.random.bytes(&raw_key);
        const key = http.encodeKey(&key_buf, &raw_key);

        var request_buf: [512]u8 = undefined;
        const request = try http.writeRequest(&request_buf, address, "/", key);
        try stream.writeAll(request);

        // Allocate read buffer
        const read_buf = try allocator.alloc(u8, opts.read_buf_size);
        errdefer allocator.free(read_buf);

        // Blocking read loop until handshake response is complete
        var total_read: usize = 0;
        var head_parser: http.HeadParser = .{};

        while (true) {
            if (total_read >= read_buf.len) return error.HandshakeResponseTooLarge;
            const n = try stream.read(read_buf[total_read..]);
            if (n == 0) return error.ConnectionClosed;
            const old_pos = total_read;
            total_read += n;

            // Feed only new bytes to the incremental head parser.
            const consumed = head_parser.feed(read_buf[old_pos..total_read]);
            if (head_parser.state != .finished) continue;

            // Headers complete — header_len is total bytes consumed across all feeds.
            const header_len = old_pos + consumed;

            http.validateResponse(read_buf[0..header_len], key) catch
                return error.HandshakeFailed;
            return RawClient{
                .stream = stream,
                .allocator = allocator,
                .read_buf = read_buf,
                .read_pos = header_len,
                .read_end = total_read,
            };
        }
    }

    /// Close the underlying TCP connection and free the read buffer.
    pub fn deinit(self: *RawClient) void {
        self.stream.close();
        self.allocator.free(self.read_buf);
    }

    // ====================================================================
    // Frame-level send
    // ====================================================================

    /// Options for fine-grained frame control in `writeFrameEx`.
    pub const FrameOpts = struct {
        fin: bool = true,
        mask: bool = true,
        rsv1: bool = false,
        rsv2: bool = false,
        rsv3: bool = false,
    };

    /// Send a single WebSocket frame with full control over header bits.
    /// `opcode` is a raw u4, allowing reserved/invalid opcodes for protocol tests.
    /// When `opts.mask` is true (default), payload is masked in-place — caller
    /// must pass mutable `[]u8`. When false, payload is sent as-is.
    pub fn writeFrameEx(self: *RawClient, opcode: u4, payload: []u8, opts: FrameOpts) !void {
        var header_buf: [14]u8 = undefined;
        var header_len: usize = 0;

        // Byte 0: FIN, RSV1-3, opcode
        var byte0: u8 = 0;
        if (opts.fin) byte0 |= 0x80;
        if (opts.rsv1) byte0 |= 0x40;
        if (opts.rsv2) byte0 |= 0x20;
        if (opts.rsv3) byte0 |= 0x10;
        byte0 |= @as(u8, opcode);
        header_buf[0] = byte0;

        // Byte 1+: MASK bit, payload length
        const mask_bit: u8 = if (opts.mask) 0x80 else 0x00;
        if (payload.len <= 125) {
            header_buf[1] = mask_bit | @as(u8, @truncate(payload.len));
            header_len = 2;
        } else if (payload.len <= 65535) {
            header_buf[1] = mask_bit | 126;
            std.mem.writeInt(u16, header_buf[2..4], @intCast(payload.len), .big);
            header_len = 4;
        } else {
            header_buf[1] = mask_bit | 127;
            std.mem.writeInt(u64, header_buf[2..10], payload.len, .big);
            header_len = 10;
        }

        // Mask key (only when masking)
        if (opts.mask) {
            var mask_key: [4]u8 = undefined;
            std.crypto.random.bytes(&mask_key);
            @memcpy(header_buf[header_len..][0..4], &mask_key);
            header_len += 4;

            // Mask payload in-place
            mask_mod.mask(mask_key, payload);
        }

        // Write header then payload
        try self.stream.writeAll(header_buf[0..header_len]);
        try self.stream.writeAll(payload);
    }

    /// Send a single well-formed WebSocket frame with client masking (FIN=1).
    /// Payload is masked in-place — caller must pass mutable `[]u8`.
    pub fn writeFrame(self: *RawClient, opcode: Opcode, payload: []u8) !void {
        try self.writeFrameEx(@intFromEnum(opcode), payload, .{});
    }

    // ====================================================================
    // Frame-level receive
    // ====================================================================

    pub const ReadResult = union(enum) {
        message: Message,
        timeout,
        closed,
    };

    /// Blocking read of a single WebSocket frame with explicit timeout/close status.
    /// Returned Message.data is heap-allocated; free via `done()`.
    pub fn readResult(self: *RawClient) !ReadResult {
        while (true) {
            const available = self.read_buf[self.read_pos..self.read_end];

            // Try to parse a header from available data
            const header = frame.parseHeader(available) catch |err| switch (err) {
                error.InsufficientData => {
                    switch (try self.fillBufferResult()) {
                        .ok => continue,
                        .timeout => return .timeout,
                        .closed => return .closed,
                    }
                },
                else => return err,
            };

            // Check if we have the full frame (header + payload)
            const payload_len = @as(usize, @intCast(header.payload_len));
            const total_frame_len = @as(usize, @intCast(header.totalLen()));
            if (available.len < total_frame_len) {
                switch (try self.fillBufferResult()) {
                    .ok => continue,
                    .timeout => return .timeout,
                    .closed => return .closed,
                }
            }

            // Validate frame
            try header.validate();
            try header.validateClientBound();

            // Extract payload
            const payload_start = self.read_pos + header.header_len;
            const payload_end = payload_start + payload_len;
            const payload = self.read_buf[payload_start..payload_end];

            // Map opcode to message type
            const msg_type: Message.Type = switch (header.opcode) {
                .text => .text,
                .binary => .binary,
                .close => .close,
                .ping => .ping,
                .pong => .pong,
                .continuation => .text, // shouldn't happen in tests
            };

            // Dupe payload (caller-owned)
            const data = try self.allocator.dupe(u8, payload);

            // Advance past consumed frame
            self.read_pos += total_frame_len;

            // Compact: shift remaining bytes to front
            if (self.read_pos > 0) {
                const remaining = self.read_end - self.read_pos;
                if (remaining > 0) {
                    const src = self.read_buf[self.read_pos..self.read_end];
                    std.mem.copyForwards(u8, self.read_buf[0..remaining], src);
                }
                self.read_end = remaining;
                self.read_pos = 0;
            }

            return .{ .message = Message{ .type = msg_type, .data = data } };
        }
    }

    /// Free the heap-allocated data from a received Message.
    pub fn done(self: *RawClient, msg: Message) void {
        self.allocator.free(msg.data);
    }

    // ====================================================================
    // Sugar methods
    // ====================================================================

    /// Send a text frame.
    pub fn write(self: *RawClient, data: []u8) !void {
        try self.writeFrame(.text, data);
    }

    pub const CloseOpts = struct {
        code: u16,
        reason: []const u8 = "",
    };

    /// Send a close frame with status code and optional reason.
    /// Reason is truncated to 123 bytes (control frame payload max 125, minus 2 for code).
    pub fn close(self: *RawClient, opts: CloseOpts) !void {
        var buf: [125]u8 = undefined;
        std.mem.writeInt(u16, buf[0..2], opts.code, .big);
        const reason_len = @min(opts.reason.len, 123);
        if (reason_len > 0) {
            @memcpy(buf[2..][0..reason_len], opts.reason[0..reason_len]);
        }
        try self.writeFrame(.close, buf[0 .. 2 + reason_len]);
    }

    /// Polls `readResult()` until any frame arrives or `deadline_ms` elapses.
    /// Returns an owned message that must be freed via `done()`.
    pub fn waitForMessage(self: *RawClient, deadline_ms: u64) !Message {
        var timer = try std.time.Timer.start();
        const deadline_ns = deadline_ms * std.time.ns_per_ms;

        while (timer.read() < deadline_ns) {
            switch (try self.readResult()) {
                .timeout => continue,
                .closed => return error.NoResponse,
                .message => |msg| return msg,
            }
        }
        return error.NoResponse;
    }

    /// Polls until a frame of `expected_type` arrives or `deadline_ms` elapses.
    /// Fails if a different frame type is received first.
    pub fn waitForMessageType(
        self: *RawClient,
        expected_type: Message.Type,
        deadline_ms: u64,
    ) !Message {
        const msg = try self.waitForMessage(deadline_ms);
        if (msg.type != expected_type) {
            self.done(msg);
            return error.UnexpectedData;
        }
        return msg;
    }

    /// Polls `readResult()` until a close frame arrives or `deadline_ms` elapses.
    /// Returns an owned message that must be freed via `done()`.
    pub fn waitForCloseFrame(self: *RawClient, deadline_ms: u64) !Message {
        return self.waitForMessageType(.close, deadline_ms);
    }

    /// Polls `readResult()` until peer disconnect or `deadline_ms` elapses.
    /// Fails if any frame is received before disconnect.
    pub fn waitForClosedNoData(self: *RawClient, deadline_ms: u64) !void {
        var timer = try std.time.Timer.start();
        const deadline_ns = deadline_ms * std.time.ns_per_ms;

        while (timer.read() < deadline_ns) {
            switch (try self.readResult()) {
                .closed => return,
                .timeout => continue,
                .message => |msg| {
                    self.done(msg);
                    return error.UnexpectedData;
                },
            }
        }
        return error.ExpectedDisconnect;
    }

    // ====================================================================
    // Internal
    // ====================================================================

    const FillResult = enum { ok, timeout, closed };

    /// Try to read more data into the buffer.
    fn fillBufferResult(self: *RawClient) !FillResult {
        if (self.read_end >= self.read_buf.len) {
            // Compact first if possible
            if (self.read_pos > 0) {
                const remaining = self.read_end - self.read_pos;
                if (remaining > 0) {
                    const src = self.read_buf[self.read_pos..self.read_end];
                    std.mem.copyForwards(u8, self.read_buf[0..remaining], src);
                }
                self.read_end = remaining;
                self.read_pos = 0;
            } else {
                return error.BufferFull;
            }
        }

        const n = self.stream.read(self.read_buf[self.read_end..]) catch |err| switch (err) {
            error.WouldBlock => return .timeout,
            else => return err,
        };
        if (n == 0) return .closed;
        self.read_end += n;
        return .ok;
    }
};
