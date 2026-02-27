const std = @import("std");

/// Whether this endpoint acts as a WebSocket client or server.
/// Affects frame validation (mask requirements) and header construction.
pub const Role = enum { client, server };

/// WebSocket frame opcodes per RFC 6455 Section 5.2.
pub const Opcode = enum(u4) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    // 0x3-0x7 reserved for non-control frames
    close = 0x8,
    ping = 0x9,
    pong = 0xA,
    // 0xB-0xF reserved for control frames

    /// Returns true for control opcodes (close, ping, pong).
    /// Control frames have opcodes where the high bit of the 4-bit field is set (>= 0x8).
    pub fn isControl(self: Opcode) bool {
        return @intFromEnum(self) >= 0x8;
    }
};

/// High-level message type delivered to user callbacks.
pub const Message = struct {
    type: Type,
    data: []const u8,

    pub const Type = enum {
        text,
        binary,
        close,
        ping,
        pong,
    };
};

/// Per-connection state machine states (WebSocket protocol phase only).
pub const ConnectionState = enum {
    open,
    closing,
    closed,
};

/// Handshake state machine states.
pub const HandshakeState = enum {
    reading,
    writing,
    completed,
    failed,
};

/// WebSocket close status codes per RFC 6455 Section 7.4.1.
pub const CloseCode = enum(u16) {
    normal = 1000,
    going_away = 1001,
    protocol_error = 1002,
    unsupported_data = 1003,
    // 1004 reserved
    no_status = 1005,
    abnormal = 1006,
    invalid_payload = 1007,
    policy_violation = 1008,
    message_too_big = 1009,
    mandatory_extension = 1010,
    internal_error = 1011,
    // 1015 reserved (TLS handshake failure)

    /// Returns true if the code is valid for use in a close frame sent on the wire.
    /// Codes 1005, 1006, and 1015 are designated for use in APIs/logs only, never sent.
    pub fn isValidForWire(self: CloseCode) bool {
        const code = @intFromEnum(self);
        return code != 1005 and code != 1006;
    }

    /// Validates a raw u16 close code per RFC 6455 Section 7.4.
    /// Valid ranges: 1000-1003, 1007-1011, 3000-4999.
    pub fn isValidCode(code: u16) bool {
        if (code < 1000) return false;
        if (code == 1004 or code == 1005 or code == 1006) return false;
        if (code >= 1012 and code <= 2999) return false;
        if (code >= 5000) return false;
        return true;
    }

    /// Returns the close code as a 2-byte big-endian value, ready to use as a
    /// close frame payload on the wire.
    pub fn payloadBytes(self: CloseCode) [2]u8 {
        var payload: [2]u8 = undefined;
        std.mem.writeInt(u16, &payload, @intFromEnum(self), .big);
        return payload;
    }
};

/// Errors that can occur during WebSocket handshake.
pub const HandshakeError = error{
    InvalidMethod,
    InvalidHttpVersion,
    MissingUpgradeHeader,
    MissingConnectionHeader,
    MissingWebSocketKey,
    MissingWebSocketVersion,
    UnsupportedWebSocketVersion,
    MalformedRequest,
    MalformedResponse,
    InvalidStatusCode,
    MissingAcceptHeader,
    InvalidAcceptKey,
};

/// Errors that can occur on a WebSocket connection.
pub const ConnectionError = error{
    ConnectionClosed,
    InvalidState,
    InvalidCloseCode,
    MessageTooBig,
    UnexpectedContinuation,
    NestedFragment,
    WriteError,
    ReadError,
    WriteBusy,
    QueueFull,
    ControlFrameTooBig,
};

/// Result of validating a close frame payload.
pub const ClosePayloadValidation = union(enum) {
    /// The original payload is well-formed and can be echoed back as-is.
    valid_payload: []const u8,
    /// The payload was invalid; send this code in the close response instead.
    close_code: CloseCode,
};

/// Validate a close frame payload per RFC 6455 Section 7.4.
/// Returns the original payload (if valid) or a CloseCode to send in response.
///
/// Invalid cases:
/// - Payload of 1 byte (must be 0 or >=2)
/// - Close code outside valid ranges (see `CloseCode.isValidCode`)
/// - Reason text (bytes 2+) contains invalid UTF-8
pub fn validateClosePayload(payload: []const u8) ClosePayloadValidation {
    // Empty payload is valid (no status code)
    if (payload.len == 0) return .{ .valid_payload = payload };

    // 1 byte is invalid — code requires 2 bytes
    if (payload.len == 1) {
        return .{ .close_code = .protocol_error };
    }

    // Extract and validate the close code
    const code = std.mem.readInt(u16, payload[0..2], .big);
    if (!CloseCode.isValidCode(code)) {
        return .{ .close_code = .protocol_error };
    }

    // Validate UTF-8 in reason text (if present)
    if (payload.len > 2) {
        const reason = payload[2..];
        if (!std.unicode.utf8ValidateSlice(reason)) {
            return .{ .close_code = .invalid_payload };
        }
    }

    // Valid — echo the original payload
    return .{ .valid_payload = payload };
}

/// Wrapper around `std.Random.DefaultCsprng` used by WebSocket clients for
/// mask-key and handshake-key generation. Provides only the `fill()` method
/// needed by the library, decoupling the public API from the concrete CSPRNG type.
///
/// Not thread-safe — use only from the `loop.run()` thread and do not share
/// across loops/threads. The pointer must remain stable for the lifetime of
/// any `ClientConnection` using it.
pub const ClientMaskPRNG = struct {
    inner: std.Random.DefaultCsprng,

    /// Seed length required by the underlying CSPRNG. Callers should fill a
    /// `[secret_seed_length]u8` buffer with cryptographically-random bytes
    /// (e.g. `std.posix.getrandom` or `std.crypto.random.bytes`) before
    /// passing it to `init`.
    pub const secret_seed_length = std.Random.DefaultCsprng.secret_seed_length;

    /// Initialize from a seed. The seed must be cryptographically random
    /// (e.g., from `std.crypto.random.bytes`).
    pub fn init(seed: [secret_seed_length]u8) ClientMaskPRNG {
        return .{ .inner = std.Random.DefaultCsprng.init(seed) };
    }

    /// Fill a buffer with cryptographically-strong random bytes.
    pub fn fill(self: *ClientMaskPRNG, buf: []u8) void {
        self.inner.fill(buf);
    }
};

const testing = std.testing;

test "Opcode: isControl returns true for control frames" {
    try testing.expect(Opcode.close.isControl());
    try testing.expect(Opcode.ping.isControl());
    try testing.expect(Opcode.pong.isControl());
}

test "Opcode: isControl returns false for data frames" {
    try testing.expect(!Opcode.continuation.isControl());
    try testing.expect(!Opcode.text.isControl());
    try testing.expect(!Opcode.binary.isControl());
}

test "Opcode: enum values match RFC 6455" {
    try testing.expectEqual(@as(u4, 0x0), @intFromEnum(Opcode.continuation));
    try testing.expectEqual(@as(u4, 0x1), @intFromEnum(Opcode.text));
    try testing.expectEqual(@as(u4, 0x2), @intFromEnum(Opcode.binary));
    try testing.expectEqual(@as(u4, 0x8), @intFromEnum(Opcode.close));
    try testing.expectEqual(@as(u4, 0x9), @intFromEnum(Opcode.ping));
    try testing.expectEqual(@as(u4, 0xA), @intFromEnum(Opcode.pong));
}

test "CloseCode: standard codes have correct values" {
    try testing.expectEqual(@as(u16, 1000), @intFromEnum(CloseCode.normal));
    try testing.expectEqual(@as(u16, 1001), @intFromEnum(CloseCode.going_away));
    try testing.expectEqual(@as(u16, 1002), @intFromEnum(CloseCode.protocol_error));
    try testing.expectEqual(@as(u16, 1003), @intFromEnum(CloseCode.unsupported_data));
    try testing.expectEqual(@as(u16, 1005), @intFromEnum(CloseCode.no_status));
    try testing.expectEqual(@as(u16, 1006), @intFromEnum(CloseCode.abnormal));
    try testing.expectEqual(@as(u16, 1007), @intFromEnum(CloseCode.invalid_payload));
    try testing.expectEqual(@as(u16, 1008), @intFromEnum(CloseCode.policy_violation));
    try testing.expectEqual(@as(u16, 1009), @intFromEnum(CloseCode.message_too_big));
    try testing.expectEqual(@as(u16, 1010), @intFromEnum(CloseCode.mandatory_extension));
    try testing.expectEqual(@as(u16, 1011), @intFromEnum(CloseCode.internal_error));
}

test "CloseCode: isValidForWire rejects API-only codes" {
    try testing.expect(!CloseCode.no_status.isValidForWire());
    try testing.expect(!CloseCode.abnormal.isValidForWire());
    try testing.expect(CloseCode.normal.isValidForWire());
    try testing.expect(CloseCode.protocol_error.isValidForWire());
}

test "CloseCode: isValidCode validates raw codes" {
    // Valid standard codes
    try testing.expect(CloseCode.isValidCode(1000));
    try testing.expect(CloseCode.isValidCode(1001));
    try testing.expect(CloseCode.isValidCode(1002));
    try testing.expect(CloseCode.isValidCode(1003));
    try testing.expect(CloseCode.isValidCode(1007));
    try testing.expect(CloseCode.isValidCode(1011));

    // Invalid: reserved or out of range
    try testing.expect(!CloseCode.isValidCode(0));
    try testing.expect(!CloseCode.isValidCode(999));
    try testing.expect(!CloseCode.isValidCode(1004));
    try testing.expect(!CloseCode.isValidCode(1005));
    try testing.expect(!CloseCode.isValidCode(1006));
    try testing.expect(!CloseCode.isValidCode(1012));
    try testing.expect(!CloseCode.isValidCode(2999));
    try testing.expect(!CloseCode.isValidCode(5000));

    // Valid registered and private ranges
    try testing.expect(CloseCode.isValidCode(3000));
    try testing.expect(CloseCode.isValidCode(3999));
    try testing.expect(CloseCode.isValidCode(4000));
    try testing.expect(CloseCode.isValidCode(4999));
}

test "CloseCode: payloadBytes encodes as big-endian" {
    try testing.expectEqual([2]u8{ 0x03, 0xE8 }, CloseCode.normal.payloadBytes()); // 1000
    try testing.expectEqual([2]u8{ 0x03, 0xEA }, CloseCode.protocol_error.payloadBytes()); // 1002
    try testing.expectEqual([2]u8{ 0x03, 0xF1 }, CloseCode.message_too_big.payloadBytes()); // 1009
}
