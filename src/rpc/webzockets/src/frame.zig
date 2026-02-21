const std = @import("std");

const types = @import("types.zig");
const mask_mod = @import("mask.zig");

const Opcode = types.Opcode;

/// Errors that can occur during frame parsing or validation.
pub const FrameError = error{
    InsufficientData,
    InvalidOpcode,
    ReservedFlags,
    FragmentedControlFrame,
    OversizedControlFrame,
    MaskRequired,
    MaskForbidden,
    PayloadTooLarge,
};

/// Parsed WebSocket frame header.
/// Represents the decoded header fields from the wire format without the payload.
pub const FrameHeader = struct {
    fin: bool,
    rsv1: bool,
    rsv2: bool,
    rsv3: bool,
    opcode: Opcode,
    masked: bool,
    payload_len: u64,
    mask_key: [4]u8,
    /// Total byte length of the header on the wire (2-14 bytes).
    header_len: u8,

    /// Returns total frame length on the wire (header bytes + payload bytes).
    pub fn totalLen(self: FrameHeader) u64 {
        return @as(u64, self.header_len) + self.payload_len;
    }

    /// Unmasks the payload in-place using the mask key from the header.
    /// No-op if the frame is not masked.
    pub fn unmaskPayload(self: FrameHeader, payload: []u8) void {
        if (self.masked) {
            mask_mod.mask(self.mask_key, payload);
        }
    }

    /// Validates the frame header per RFC 6455 requirements.
    ///
    /// Checks:
    /// - RSV bits must all be zero (compression not yet supported) -> `ReservedFlags`
    /// - Control frames (opcode >= 0x8) payload must be <= 125 bytes -> `OversizedControlFrame`
    /// - Control frames must have FIN set -> `FragmentedControlFrame`
    pub fn validate(self: FrameHeader) FrameError!void {
        // RSV bits must be zero (no extensions negotiated)
        if (self.rsv1 or self.rsv2 or self.rsv3) {
            return FrameError.ReservedFlags;
        }

        // Control frame checks
        if (self.opcode.isControl()) {
            if (self.payload_len > 125) {
                return FrameError.OversizedControlFrame;
            }
            if (!self.fin) {
                return FrameError.FragmentedControlFrame;
            }
        }
    }

    /// Validates that the frame is properly masked for client-to-server transmission.
    /// Per RFC 6455 Section 5.1, all client-to-server frames MUST be masked.
    pub fn validateServerBound(self: FrameHeader) FrameError!void {
        if (!self.masked) {
            return FrameError.MaskRequired;
        }
    }

    /// Validates that the frame is not masked, as required for server-to-client transmission.
    /// Per RFC 6455 Section 5.1, server-to-client frames MUST NOT be masked.
    pub fn validateClientBound(self: FrameHeader) FrameError!void {
        if (self.masked) {
            return FrameError.MaskForbidden;
        }
    }
};

/// Parse a WebSocket frame header from raw bytes per RFC 6455 Section 5.2.
///
/// Returns the decoded `FrameHeader` with all fields populated including the
/// computed `header_len` (total bytes consumed by the header on the wire).
///
/// Returns `FrameError.InsufficientData` if `data` does not contain enough
/// bytes to fully decode the header.
/// Returns `FrameError.InvalidOpcode` if the opcode is a reserved value.
pub fn parseHeader(data: []const u8) FrameError!FrameHeader {
    if (data.len < 2) return FrameError.InsufficientData;

    const byte0 = data[0];
    const byte1 = data[1];

    // byte0: [FIN | RSV1 | RSV2 | RSV3 | OP3 | OP2 | OP1 | OP0]
    const fin = (byte0 & 0x80) != 0;
    const rsv1 = (byte0 & 0x40) != 0;
    const rsv2 = (byte0 & 0x20) != 0;
    const rsv3 = (byte0 & 0x10) != 0;
    const raw_opcode: u4 = @truncate(byte0); // low 4 bits
    const opcode = std.meta.intToEnum(Opcode, raw_opcode) catch return FrameError.InvalidOpcode;

    // byte1: [MASK | LEN6 | LEN5 | LEN4 | LEN3 | LEN2 | LEN1 | LEN0]
    const masked = (byte1 & 0x80) != 0;
    const len7: u7 = @truncate(byte1); // low 7 bits

    // Calculate header length and decode payload length
    var header_len: u8 = 2;
    var payload_len: u64 = undefined;

    if (len7 <= 125) {
        payload_len = len7;
    } else if (len7 == 126) {
        header_len += 2;
        if (data.len < header_len) return FrameError.InsufficientData;
        payload_len = std.mem.readInt(u16, data[2..4], .big);
        // NOTE: RFC 6455 requires minimal encoding (e.g. payload_len > 125 here).
        // We are currently permissive and allow non-minimal encodings.
    } else {
        // len7 == 127
        header_len += 8;
        if (data.len < header_len) return FrameError.InsufficientData;
        payload_len = std.mem.readInt(u64, data[2..10], .big);
        // NOTE: RFC 6455 requires the most significant bit to be 0 and minimal
        // encoding (payload_len > 65535). We are currently permissive.
    }

    var mask_key: [4]u8 = .{ 0, 0, 0, 0 };
    if (masked) {
        const mask_start = header_len;
        header_len += 4;
        if (data.len < header_len) return FrameError.InsufficientData;
        @memcpy(&mask_key, data[mask_start..][0..4]);
    }

    return FrameHeader{
        .fin = fin,
        .rsv1 = rsv1,
        .rsv2 = rsv2,
        .rsv3 = rsv3,
        .opcode = opcode,
        .masked = masked,
        .payload_len = payload_len,
        .mask_key = mask_key,
        .header_len = header_len,
    };
}

/// Writes a server-to-client frame header into `buf`.
///
/// Server frames are always unmasked with FIN=1. Sets RSV1 if `compressed` is true.
/// Returns the slice of `buf` that was written (2, 4, or 10 bytes).
///
/// The caller must ensure `buf` is at least 10 bytes long.
pub fn writeFrameHeader(
    buf: []u8,
    opcode: Opcode,
    payload_len: u64,
    compressed: bool,
) []u8 {
    std.debug.assert(buf.len >= 10);
    return writeHeader(buf, opcode, payload_len, compressed, null);
}

/// Writes a client-to-server (masked) frame header into `buf`.
///
/// Client frames always have MASK=1 and FIN=1. Sets RSV1 if `compressed` is true.
/// Returns the slice of `buf` that was written (6, 8, or 14 bytes).
///
/// The caller must ensure `buf` is at least 14 bytes long.
pub fn writeClientFrameHeader(
    buf: []u8,
    opcode: Opcode,
    payload_len: u64,
    mask_key: [4]u8,
    compressed: bool,
) []u8 {
    std.debug.assert(buf.len >= 14);
    return writeHeader(buf, opcode, payload_len, compressed, mask_key);
}

/// Writes a WebSocket frame header into `buf`. When `mask_key` is non-null,
/// the MASK bit is set and the 4-byte key is appended after the length bytes.
/// Always sets FIN=1. Sets RSV1 when `compressed` is true and opcode is not a control frame.
fn writeHeader(
    buf: []u8,
    opcode: Opcode,
    payload_len: u64,
    compressed: bool,
    mask_key: ?[4]u8,
) []u8 {
    // Byte 0: FIN=1, RSV bits, opcode
    var byte0: u8 = 0x80; // FIN bit set
    if (compressed and !opcode.isControl()) byte0 |= 0x40; // RSV1 bit
    byte0 |= @intFromEnum(opcode);
    buf[0] = byte0;

    // Byte 1+: MASK flag, payload length
    const mask_bit: u8 = if (mask_key != null) 0x80 else 0;

    const len_end: usize = blk: {
        if (payload_len <= 125) {
            buf[1] = mask_bit | @as(u8, @truncate(payload_len));
            break :blk 2;
        } else if (payload_len <= 65535) {
            buf[1] = mask_bit | 126;
            std.mem.writeInt(u16, buf[2..4], @truncate(payload_len), .big);
            break :blk 4;
        } else {
            buf[1] = mask_bit | 127;
            std.mem.writeInt(u64, buf[2..10], payload_len, .big);
            break :blk 10;
        }
    };

    // Append mask key if present
    if (mask_key) |key| {
        @memcpy(buf[len_end..][0..4], &key);
        return buf[0 .. len_end + 4];
    }

    return buf[0..len_end];
}

const testing = std.testing;

test "parseHeader: 7-bit payload length (unmasked)" {
    // FIN=1, opcode=text(1), MASK=0, len=5
    const data = [_]u8{ 0x81, 0x05 } ++ [_]u8{ 'H', 'e', 'l', 'l', 'o' };
    const header = try parseHeader(&data);

    try testing.expect(header.fin);
    try testing.expect(!header.rsv1);
    try testing.expect(!header.rsv2);
    try testing.expect(!header.rsv3);
    try testing.expectEqual(Opcode.text, header.opcode);
    try testing.expect(!header.masked);
    try testing.expectEqual(@as(u64, 5), header.payload_len);
    try testing.expectEqual(@as(u8, 2), header.header_len);
}

test "parseHeader: 7-bit payload length (masked)" {
    // FIN=1, opcode=text(1), MASK=1, len=5, mask key=0x37FA213D
    const data = [_]u8{ 0x81, 0x85, 0x37, 0xFA, 0x21, 0x3D, 0x7F, 0x9F, 0x4D, 0x51, 0x58 };
    const header = try parseHeader(&data);

    try testing.expect(header.fin);
    try testing.expectEqual(Opcode.text, header.opcode);
    try testing.expect(header.masked);
    try testing.expectEqual(@as(u64, 5), header.payload_len);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x37, 0xFA, 0x21, 0x3D }, &header.mask_key);
    try testing.expectEqual(@as(u8, 6), header.header_len);
}

test "parseHeader: 16-bit payload length" {
    // FIN=1, opcode=binary(2), MASK=0, len=256 (126 + 2-byte BE)
    var data: [4]u8 = undefined;
    data[0] = 0x82; // FIN=1, binary
    data[1] = 126; // 16-bit extended length
    std.mem.writeInt(u16, data[2..4], 256, .big);

    const header = try parseHeader(&data);

    try testing.expect(header.fin);
    try testing.expectEqual(Opcode.binary, header.opcode);
    try testing.expect(!header.masked);
    try testing.expectEqual(@as(u64, 256), header.payload_len);
    try testing.expectEqual(@as(u8, 4), header.header_len);
}

test "parseHeader: 16-bit payload length (masked)" {
    // FIN=1, opcode=text(1), MASK=1, len=300
    var data: [8]u8 = undefined;
    data[0] = 0x81; // FIN=1, text
    data[1] = 0xFE; // MASK=1, 126 -> 16-bit extended length
    std.mem.writeInt(u16, data[2..4], 300, .big);
    data[4] = 0xAA;
    data[5] = 0xBB;
    data[6] = 0xCC;
    data[7] = 0xDD;

    const header = try parseHeader(&data);

    try testing.expect(header.fin);
    try testing.expectEqual(Opcode.text, header.opcode);
    try testing.expect(header.masked);
    try testing.expectEqual(@as(u64, 300), header.payload_len);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xBB, 0xCC, 0xDD }, &header.mask_key);
    try testing.expectEqual(@as(u8, 8), header.header_len);
}

test "parseHeader: 64-bit payload length" {
    // FIN=1, opcode=binary(2), MASK=0, len=70000 (127 + 8-byte BE)
    var data: [10]u8 = undefined;
    data[0] = 0x82; // FIN=1, binary
    data[1] = 127; // 64-bit extended length
    std.mem.writeInt(u64, data[2..10], 70000, .big);

    const header = try parseHeader(&data);

    try testing.expect(header.fin);
    try testing.expectEqual(Opcode.binary, header.opcode);
    try testing.expect(!header.masked);
    try testing.expectEqual(@as(u64, 70000), header.payload_len);
    try testing.expectEqual(@as(u8, 10), header.header_len);
}

test "parseHeader: 64-bit payload length (masked)" {
    // FIN=1, opcode=binary(2), MASK=1, len=70000
    var data: [14]u8 = undefined;
    data[0] = 0x82; // FIN=1, binary
    data[1] = 0xFF; // MASK=1, 127 -> 64-bit extended length
    std.mem.writeInt(u64, data[2..10], 70000, .big);
    data[10] = 0x11;
    data[11] = 0x22;
    data[12] = 0x33;
    data[13] = 0x44;

    const header = try parseHeader(&data);

    try testing.expect(header.fin);
    try testing.expectEqual(Opcode.binary, header.opcode);
    try testing.expect(header.masked);
    try testing.expectEqual(@as(u64, 70000), header.payload_len);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x11, 0x22, 0x33, 0x44 }, &header.mask_key);
    try testing.expectEqual(@as(u8, 14), header.header_len);
}

test "parseHeader: continuation frame (FIN=0)" {
    // FIN=0, opcode=continuation(0), MASK=0, len=10
    const data = [_]u8{ 0x00, 0x0A };
    const header = try parseHeader(&data);

    try testing.expect(!header.fin);
    try testing.expectEqual(Opcode.continuation, header.opcode);
    try testing.expectEqual(@as(u64, 10), header.payload_len);
}

test "parseHeader: control frames (close, ping, pong)" {
    // Close frame: FIN=1, opcode=0x8, MASK=0, len=2
    const close_data = [_]u8{ 0x88, 0x02 };
    const close_header = try parseHeader(&close_data);
    try testing.expectEqual(Opcode.close, close_header.opcode);
    try testing.expect(close_header.fin);
    try testing.expectEqual(@as(u64, 2), close_header.payload_len);

    // Ping frame: FIN=1, opcode=0x9, MASK=0, len=0
    const ping_data = [_]u8{ 0x89, 0x00 };
    const ping_header = try parseHeader(&ping_data);
    try testing.expectEqual(Opcode.ping, ping_header.opcode);

    // Pong frame: FIN=1, opcode=0xA, MASK=0, len=0
    const pong_data = [_]u8{ 0x8A, 0x00 };
    const pong_header = try parseHeader(&pong_data);
    try testing.expectEqual(Opcode.pong, pong_header.opcode);
}

test "parseHeader: InsufficientData for empty input" {
    const data = [_]u8{};
    try testing.expectError(FrameError.InsufficientData, parseHeader(&data));
}

test "parseHeader: InsufficientData for single byte" {
    const data = [_]u8{0x81};
    try testing.expectError(FrameError.InsufficientData, parseHeader(&data));
}

test "parseHeader: InsufficientData for truncated 16-bit length" {
    // Needs 4 bytes for header but only 3 provided
    const data = [_]u8{ 0x81, 126, 0x01 };
    try testing.expectError(FrameError.InsufficientData, parseHeader(&data));
}

test "parseHeader: InsufficientData for truncated 64-bit length" {
    // Needs 10 bytes for header but only 5 provided
    const data = [_]u8{ 0x81, 127, 0x00, 0x00, 0x00 };
    try testing.expectError(FrameError.InsufficientData, parseHeader(&data));
}

test "parseHeader: InsufficientData for truncated mask key" {
    // FIN=1, text, MASK=1, len=5 but only 2 bytes of mask key
    const data = [_]u8{ 0x81, 0x85, 0x37, 0xFA };
    try testing.expectError(FrameError.InsufficientData, parseHeader(&data));
}

test "parseHeader: InvalidOpcode for reserved non-control opcodes (3-7)" {
    const reserved_opcodes = [_]u8{ 3, 4, 5, 6, 7 };
    for (reserved_opcodes) |op| {
        const data = [_]u8{ 0x80 | op, 0x00 };
        try testing.expectError(FrameError.InvalidOpcode, parseHeader(&data));
    }
}

test "parseHeader: InvalidOpcode for reserved control opcodes (0xB-0xF)" {
    const reserved_opcodes = [_]u8{ 0xB, 0xC, 0xD, 0xE, 0xF };
    for (reserved_opcodes) |op| {
        const data = [_]u8{ 0x80 | op, 0x00 };
        try testing.expectError(FrameError.InvalidOpcode, parseHeader(&data));
    }
}

test "parseHeader: zero payload length" {
    // FIN=1, ping, MASK=0, len=0
    const data = [_]u8{ 0x89, 0x00 };
    const header = try parseHeader(&data);
    try testing.expectEqual(@as(u64, 0), header.payload_len);
    try testing.expectEqual(@as(u8, 2), header.header_len);
}

test "parseHeader: max 7-bit payload length (125)" {
    const data = [_]u8{ 0x81, 125 };
    const header = try parseHeader(&data);
    try testing.expectEqual(@as(u64, 125), header.payload_len);
    try testing.expectEqual(@as(u8, 2), header.header_len);
}

test "FrameHeader.totalLen: basic correctness" {
    const header = FrameHeader{
        .fin = true,
        .rsv1 = false,
        .rsv2 = false,
        .rsv3 = false,
        .opcode = .text,
        .masked = false,
        .payload_len = 100,
        .mask_key = .{ 0, 0, 0, 0 },
        .header_len = 2,
    };
    try testing.expectEqual(@as(u64, 102), header.totalLen());
}

test "FrameHeader.totalLen: with 16-bit length" {
    const header = FrameHeader{
        .fin = true,
        .rsv1 = false,
        .rsv2 = false,
        .rsv3 = false,
        .opcode = .binary,
        .masked = false,
        .payload_len = 1000,
        .mask_key = .{ 0, 0, 0, 0 },
        .header_len = 4,
    };
    try testing.expectEqual(@as(u64, 1004), header.totalLen());
}

test "FrameHeader.totalLen: masked with 64-bit length" {
    const header = FrameHeader{
        .fin = true,
        .rsv1 = false,
        .rsv2 = false,
        .rsv3 = false,
        .opcode = .binary,
        .masked = true,
        .payload_len = 70000,
        .mask_key = .{ 0x11, 0x22, 0x33, 0x44 },
        .header_len = 14,
    };
    try testing.expectEqual(@as(u64, 70014), header.totalLen());
}

test "FrameHeader.unmaskPayload: masks payload when header.masked is true" {
    var payload = [_]u8{ 0x48, 0x65, 0x6c, 0x6c, 0x6f }; // "Hello"
    const header = FrameHeader{
        .fin = true,
        .rsv1 = false,
        .rsv2 = false,
        .rsv3 = false,
        .opcode = .text,
        .masked = true,
        .payload_len = 5,
        .mask_key = .{ 0x37, 0xFA, 0x21, 0x3D },
        .header_len = 6,
    };

    header.unmaskPayload(&payload);
    // "Hello" XOR'd with mask key
    try testing.expectEqualSlices(u8, &[_]u8{ 0x7F, 0x9F, 0x4D, 0x51, 0x58 }, &payload);
}

test "FrameHeader.unmaskPayload: no-op when header.masked is false" {
    const original = [_]u8{ 0x48, 0x65, 0x6c, 0x6c, 0x6f };
    var payload = original;
    const header = FrameHeader{
        .fin = true,
        .rsv1 = false,
        .rsv2 = false,
        .rsv3 = false,
        .opcode = .text,
        .masked = false,
        .payload_len = 5,
        .mask_key = .{ 0x37, 0xFA, 0x21, 0x3D },
        .header_len = 2,
    };

    header.unmaskPayload(&payload);
    try testing.expectEqualSlices(u8, &original, &payload);
}

test "FrameHeader.unmaskPayload: round-trip mask and unmask" {
    const original = "Hello, WebSocket!";
    var payload: [original.len]u8 = undefined;
    @memcpy(&payload, original);

    const header = FrameHeader{
        .fin = true,
        .rsv1 = false,
        .rsv2 = false,
        .rsv3 = false,
        .opcode = .text,
        .masked = true,
        .payload_len = original.len,
        .mask_key = .{ 0xAB, 0xCD, 0xEF, 0x01 },
        .header_len = 6,
    };

    // Mask
    header.unmaskPayload(&payload);
    try testing.expect(!std.mem.eql(u8, &payload, original));
    // Unmask (same operation)
    header.unmaskPayload(&payload);
    try testing.expectEqualSlices(u8, original, &payload);
}

test "FrameHeader.validate: valid data frame passes" {
    const header = FrameHeader{
        .fin = true,
        .rsv1 = false,
        .rsv2 = false,
        .rsv3 = false,
        .opcode = .text,
        .masked = true,
        .payload_len = 100,
        .mask_key = .{ 0, 0, 0, 0 },
        .header_len = 6,
    };
    try header.validate();
}

test "FrameHeader.validate: valid continuation frame (FIN=0) passes" {
    const header = FrameHeader{
        .fin = false,
        .rsv1 = false,
        .rsv2 = false,
        .rsv3 = false,
        .opcode = .continuation,
        .masked = true,
        .payload_len = 50,
        .mask_key = .{ 0, 0, 0, 0 },
        .header_len = 6,
    };
    try header.validate();
}

test "FrameHeader.validate: RSV1 set rejects with ReservedFlags" {
    const header = FrameHeader{
        .fin = true,
        .rsv1 = true,
        .rsv2 = false,
        .rsv3 = false,
        .opcode = .text,
        .masked = true,
        .payload_len = 5,
        .mask_key = .{ 0, 0, 0, 0 },
        .header_len = 6,
    };
    try testing.expectError(FrameError.ReservedFlags, header.validate());
}

test "FrameHeader.validate: RSV2 set rejects with ReservedFlags" {
    const header = FrameHeader{
        .fin = true,
        .rsv1 = false,
        .rsv2 = true,
        .rsv3 = false,
        .opcode = .text,
        .masked = true,
        .payload_len = 5,
        .mask_key = .{ 0, 0, 0, 0 },
        .header_len = 6,
    };
    try testing.expectError(FrameError.ReservedFlags, header.validate());
}

test "FrameHeader.validate: RSV3 set rejects with ReservedFlags" {
    const header = FrameHeader{
        .fin = true,
        .rsv1 = false,
        .rsv2 = false,
        .rsv3 = true,
        .opcode = .text,
        .masked = true,
        .payload_len = 5,
        .mask_key = .{ 0, 0, 0, 0 },
        .header_len = 6,
    };
    try testing.expectError(FrameError.ReservedFlags, header.validate());
}

test "FrameHeader.validate: oversized control frame rejects" {
    const header = FrameHeader{
        .fin = true,
        .rsv1 = false,
        .rsv2 = false,
        .rsv3 = false,
        .opcode = .close,
        .masked = true,
        .payload_len = 126,
        .mask_key = .{ 0, 0, 0, 0 },
        .header_len = 6,
    };
    try testing.expectError(FrameError.OversizedControlFrame, header.validate());
}

test "FrameHeader.validate: control frame at max size (125) passes" {
    const header = FrameHeader{
        .fin = true,
        .rsv1 = false,
        .rsv2 = false,
        .rsv3 = false,
        .opcode = .ping,
        .masked = true,
        .payload_len = 125,
        .mask_key = .{ 0, 0, 0, 0 },
        .header_len = 6,
    };
    try header.validate();
}

test "FrameHeader.validate: fragmented control frame rejects" {
    const header = FrameHeader{
        .fin = false,
        .rsv1 = false,
        .rsv2 = false,
        .rsv3 = false,
        .opcode = .ping,
        .masked = true,
        .payload_len = 5,
        .mask_key = .{ 0, 0, 0, 0 },
        .header_len = 6,
    };
    try testing.expectError(FrameError.FragmentedControlFrame, header.validate());
}

test "FrameHeader.validate: data frame with FIN=0 is allowed" {
    const header = FrameHeader{
        .fin = false,
        .rsv1 = false,
        .rsv2 = false,
        .rsv3 = false,
        .opcode = .text,
        .masked = true,
        .payload_len = 1000,
        .mask_key = .{ 0, 0, 0, 0 },
        .header_len = 6,
    };
    try header.validate();
}

test "FrameHeader.validateServerBound: masked frame passes" {
    const header = FrameHeader{
        .fin = true,
        .rsv1 = false,
        .rsv2 = false,
        .rsv3 = false,
        .opcode = .text,
        .masked = true,
        .payload_len = 5,
        .mask_key = .{ 0x37, 0xFA, 0x21, 0x3D },
        .header_len = 6,
    };
    try header.validateServerBound();
}

test "FrameHeader.validateServerBound: unmasked frame rejects with MaskRequired" {
    const header = FrameHeader{
        .fin = true,
        .rsv1 = false,
        .rsv2 = false,
        .rsv3 = false,
        .opcode = .text,
        .masked = false,
        .payload_len = 5,
        .mask_key = .{ 0, 0, 0, 0 },
        .header_len = 2,
    };
    try testing.expectError(FrameError.MaskRequired, header.validateServerBound());
}

test "writeFrameHeader: 7-bit, 16-bit, and 64-bit payload lengths" {
    var buf: [10]u8 = undefined;

    // 7-bit: payload fits in single length byte
    const r7 = writeFrameHeader(&buf, .text, 5, false);
    try testing.expectEqual(@as(usize, 2), r7.len);
    try testing.expectEqual(@as(u8, 0x81), r7[0]); // FIN=1, text
    try testing.expectEqual(@as(u8, 5), r7[1]); // len=5, MASK=0

    // 16-bit: extended length
    const r16 = writeFrameHeader(&buf, .binary, 300, false);
    try testing.expectEqual(@as(usize, 4), r16.len);
    try testing.expectEqual(@as(u8, 0x82), r16[0]); // FIN=1, binary
    try testing.expectEqual(@as(u8, 126), r16[1]);
    try testing.expectEqual(@as(u16, 300), std.mem.readInt(u16, r16[2..4], .big));

    // 64-bit: extended length
    const r64 = writeFrameHeader(&buf, .binary, 70000, false);
    try testing.expectEqual(@as(usize, 10), r64.len);
    try testing.expectEqual(@as(u8, 0x82), r64[0]); // FIN=1, binary
    try testing.expectEqual(@as(u8, 127), r64[1]);
    try testing.expectEqual(@as(u64, 70000), std.mem.readInt(u64, r64[2..10], .big));
}

test "writeFrameHeader: compressed flag and close opcode" {
    var buf: [10]u8 = undefined;

    const compressed = writeFrameHeader(&buf, .text, 10, true);
    try testing.expectEqual(@as(u8, 0xC1), compressed[0]); // FIN=1, RSV1=1, text

    const close = writeFrameHeader(&buf, .close, 2, false);
    try testing.expectEqual(@as(usize, 2), close.len);
    try testing.expectEqual(@as(u8, 0x88), close[0]); // FIN=1, close
    try testing.expectEqual(@as(u8, 2), close[1]);
}

test "writeFrameHeader: compressed flag ignored for control opcodes" {
    var buf: [10]u8 = undefined;

    // Control frames with compressed=true should NOT have RSV1 bit set
    const close = writeFrameHeader(&buf, .close, 0, true);
    try testing.expectEqual(@as(u8, 0x88), close[0]); // FIN=1, opcode=8 (NOT 0xC8)

    const ping = writeFrameHeader(&buf, .ping, 0, true);
    try testing.expectEqual(@as(u8, 0x89), ping[0]); // FIN=1, opcode=9 (NOT 0xC9)

    // Data frame with compressed=true SHOULD have RSV1 bit set
    const text = writeFrameHeader(&buf, .text, 0, true);
    try testing.expectEqual(@as(u8, 0xC1), text[0]); // FIN=1, RSV1=1, opcode=1
}

test "writeFrameHeader: length tier boundaries (125/126, 65535/65536)" {
    var buf: [10]u8 = undefined;

    // 125 → 7-bit tier (last value in 7-bit range)
    const r125 = writeFrameHeader(&buf, .text, 125, false);
    try testing.expectEqual(@as(usize, 2), r125.len);
    try testing.expectEqual(@as(u8, 125), r125[1]);

    // 126 → 16-bit tier (first value in 16-bit range)
    const r126 = writeFrameHeader(&buf, .text, 126, false);
    try testing.expectEqual(@as(usize, 4), r126.len);
    try testing.expectEqual(@as(u8, 126), r126[1]);
    try testing.expectEqual(@as(u16, 126), std.mem.readInt(u16, r126[2..4], .big));

    // 65535 → 16-bit tier (last value in 16-bit range)
    const r65535 = writeFrameHeader(&buf, .text, 65535, false);
    try testing.expectEqual(@as(usize, 4), r65535.len);
    try testing.expectEqual(@as(u16, 65535), std.mem.readInt(u16, r65535[2..4], .big));

    // 65536 → 64-bit tier (first value in 64-bit range)
    const r65536 = writeFrameHeader(&buf, .text, 65536, false);
    try testing.expectEqual(@as(usize, 10), r65536.len);
    try testing.expectEqual(@as(u8, 127), r65536[1]);
    try testing.expectEqual(@as(u64, 65536), std.mem.readInt(u64, r65536[2..10], .big));
}

test "writeFrameHeader + parseHeader round-trip: all length tiers and compressed" {
    const Case = struct { opcode: Opcode, payload_len: u64, compressed: bool };
    const cases = [_]Case{
        .{ .opcode = .text, .payload_len = 42, .compressed = false },
        .{ .opcode = .binary, .payload_len = 1000, .compressed = false },
        .{ .opcode = .binary, .payload_len = 100000, .compressed = false },
        .{ .opcode = .text, .payload_len = 50, .compressed = true },
    };

    for (cases) |c| {
        var buf: [10]u8 = undefined;
        const written = writeFrameHeader(&buf, c.opcode, c.payload_len, c.compressed);
        const header = try parseHeader(written);

        try testing.expect(header.fin);
        try testing.expectEqual(c.opcode, header.opcode);
        try testing.expect(!header.masked);
        try testing.expectEqual(c.payload_len, header.payload_len);
        try testing.expectEqual(c.compressed, header.rsv1);
        try testing.expectEqual(@as(u8, @intCast(written.len)), header.header_len);
    }
}

// --- validateClientBound tests ---

test "FrameHeader.validateClientBound: unmasked frame passes" {
    const header = FrameHeader{
        .fin = true,
        .rsv1 = false,
        .rsv2 = false,
        .rsv3 = false,
        .opcode = .text,
        .masked = false,
        .payload_len = 5,
        .mask_key = .{ 0, 0, 0, 0 },
        .header_len = 2,
    };
    try header.validateClientBound();
}

test "FrameHeader.validateClientBound: masked frame rejects with MaskForbidden" {
    const header = FrameHeader{
        .fin = true,
        .rsv1 = false,
        .rsv2 = false,
        .rsv3 = false,
        .opcode = .text,
        .masked = true,
        .payload_len = 5,
        .mask_key = .{ 0x37, 0xFA, 0x21, 0x3D },
        .header_len = 6,
    };
    try testing.expectError(FrameError.MaskForbidden, header.validateClientBound());
}

// --- writeClientFrameHeader tests ---

test "writeClientFrameHeader: 7-bit, 16-bit, and 64-bit payload lengths" {
    const mask_key = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
    var buf: [14]u8 = undefined;

    // 7-bit
    const r7 = writeClientFrameHeader(&buf, .text, 5, mask_key, false);
    try testing.expectEqual(@as(usize, 6), r7.len);
    try testing.expectEqual(@as(u8, 0x81), r7[0]); // FIN=1, text
    try testing.expectEqual(@as(u8, 0x85), r7[1]); // MASK=1, len=5
    try testing.expectEqualSlices(u8, &mask_key, r7[2..6]);

    // 16-bit
    const r16 = writeClientFrameHeader(&buf, .binary, 300, mask_key, false);
    try testing.expectEqual(@as(usize, 8), r16.len);
    try testing.expectEqual(@as(u8, 0x82), r16[0]); // FIN=1, binary
    try testing.expectEqual(@as(u8, 0xFE), r16[1]); // MASK=1, 126
    try testing.expectEqual(@as(u16, 300), std.mem.readInt(u16, r16[2..4], .big));
    try testing.expectEqualSlices(u8, &mask_key, r16[4..8]);

    // 64-bit
    const r64 = writeClientFrameHeader(&buf, .binary, 70000, mask_key, false);
    try testing.expectEqual(@as(usize, 14), r64.len);
    try testing.expectEqual(@as(u8, 0x82), r64[0]); // FIN=1, binary
    try testing.expectEqual(@as(u8, 0xFF), r64[1]); // MASK=1, 127
    try testing.expectEqual(@as(u64, 70000), std.mem.readInt(u64, r64[2..10], .big));
    try testing.expectEqualSlices(u8, &mask_key, r64[10..14]);
}

test "writeClientFrameHeader: compressed flag sets RSV1" {
    var buf: [14]u8 = undefined;
    const result = writeClientFrameHeader(&buf, .text, 10, .{ 0x01, 0x02, 0x03, 0x04 }, true);
    try testing.expectEqual(@as(u8, 0xC1), result[0]); // FIN=1, RSV1=1, text
}

test "writeClientFrameHeader + parseHeader round-trip" {
    const mask_key = [_]u8{ 0xAB, 0xCD, 0xEF, 0x01 };
    var buf: [14]u8 = undefined;
    const written = writeClientFrameHeader(&buf, .text, 42, mask_key, false);

    const header = try parseHeader(written);
    try testing.expect(header.fin);
    try testing.expect(!header.rsv1);
    try testing.expectEqual(Opcode.text, header.opcode);
    try testing.expect(header.masked);
    try testing.expectEqual(@as(u64, 42), header.payload_len);
    try testing.expectEqualSlices(u8, &mask_key, &header.mask_key);
    try testing.expectEqual(@as(u8, @intCast(written.len)), header.header_len);
}

// --- Fuzz tests ---

test "fuzz parseHeader: no crash on arbitrary input" {
    const helper = struct {
        fn run(_: void, input: []const u8) anyerror!void {
            // parseHeader must either return a valid header or an error, never crash.
            _ = parseHeader(input) catch return;
        }
    };
    try testing.fuzz({}, helper.run, .{
        .corpus = &[_][]const u8{
            // Minimal valid frames
            &[_]u8{ 0x81, 0x05 }, // text, len=5
            &[_]u8{ 0x88, 0x00 }, // close, len=0
            &[_]u8{ 0x89, 0x00 }, // ping, len=0
            &[_]u8{ 0x8A, 0x00 }, // pong, len=0
            // Masked frame
            &[_]u8{ 0x81, 0x85, 0x37, 0xFA, 0x21, 0x3D },
            // 16-bit length
            &[_]u8{ 0x82, 126, 0x01, 0x00 },
            // 64-bit length
            &[_]u8{ 0x82, 127, 0, 0, 0, 0, 0, 1, 0x11, 0x70 },
            // Reserved opcodes
            &[_]u8{ 0x83, 0x00 },
            &[_]u8{ 0x8F, 0x00 },
            // Empty
            &[_]u8{},
            // Single byte
            &[_]u8{0x81},
        },
    });
}

test "fuzz writeHeader + parseHeader round-trip (server and client)" {
    const helper = struct {
        // Input layout: [0] opcode selector, [1..9] payload_len, [9..13] mask_key, [13] flags
        // flags bit 0 = compressed, flags bit 1 = masked (client frame)
        fn run(_: void, input: []const u8) anyerror!void {
            if (input.len < 14) return;

            const valid_opcodes = [_]Opcode{ .continuation, .text, .binary, .close, .ping, .pong };
            const opcode = valid_opcodes[input[0] % valid_opcodes.len];
            const payload_len = std.mem.readInt(u64, input[1..9], .big);
            const mask_key: [4]u8 = input[9..13].*;
            const compressed = (input[13] & 1) != 0;
            const masked = (input[13] & 2) != 0;

            var buf: [14]u8 = undefined;
            const written = if (masked)
                writeClientFrameHeader(&buf, opcode, payload_len, mask_key, compressed)
            else
                writeFrameHeader(buf[0..10], opcode, payload_len, compressed);

            const header = try parseHeader(written);

            try testing.expect(header.fin);
            try testing.expectEqual(opcode, header.opcode);
            try testing.expectEqual(masked, header.masked);
            try testing.expectEqual(payload_len, header.payload_len);
            try testing.expectEqual(compressed, header.rsv1);
            try testing.expectEqual(@as(u8, @intCast(written.len)), header.header_len);
            if (masked) {
                try testing.expectEqualSlices(u8, &mask_key, &header.mask_key);
            }
        }
    };
    try testing.fuzz({}, helper.run, .{
        .corpus = &[_][]const u8{
            // Server (unmasked): flags bit 1 = 0
            &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0 },
            &[_]u8{ 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0 },
            &[_]u8{ 2, 0, 0, 0, 0, 0, 0, 0, 125, 0, 0, 0, 0, 0 },
            &[_]u8{ 2, 0, 0, 0, 0, 0, 0, 0, 126, 0, 0, 0, 0, 0 },
            &[_]u8{ 2, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0 },
            &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 42, 0, 0, 0, 0, 1 }, // compressed
            // Client (masked): flags bit 1 = 2
            &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 5, 0xAA, 0xBB, 0xCC, 0xDD, 2 },
            &[_]u8{ 1, 0, 0, 0, 0, 0, 0, 1, 0, 0x11, 0x22, 0x33, 0x44, 2 },
            &[_]u8{ 2, 0, 0, 0, 0, 0, 0, 0, 126, 0xDE, 0xAD, 0xBE, 0xEF, 3 }, // masked + compressed
        },
    });
}
