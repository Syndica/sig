const std = @import("std");
const types = @import("types.zig");

const HandshakeError = types.HandshakeError;

pub const HeadParser = std.http.HeadParser;

/// RFC 6455 magic GUID used in Sec-WebSocket-Accept computation.
const websocket_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Parsed HTTP upgrade request.
/// All string fields borrow from the input buffer (no allocations).
pub const Request = struct {
    /// HTTP method — must be "GET".
    method: []const u8,
    /// Request URI path.
    path: []const u8,
    /// Sec-WebSocket-Key header value.
    websocket_key: []const u8,
    /// Host header value (empty slice if absent).
    /// NOTE: permissive to missing Host when parsing despite RFC 6455
    /// and HTTP requiring it (validate in Handler init if you care).
    host: []const u8,
    /// Origin header value (empty slice if absent).
    origin: []const u8,
    /// Sec-WebSocket-Protocol header value (empty slice if absent).
    protocols: []const u8,
    /// Sec-WebSocket-Extensions header value (empty slice if absent).
    extensions: []const u8,
};

/// Tracks which required headers have been seen during parsing.
const FoundRequired = packed struct(u4) {
    upgrade: bool = false,
    connection: bool = false,
    key: bool = false,
    version: bool = false,
};

/// Parses an HTTP WebSocket upgrade request from `buf`.
///
/// `buf` must contain a complete HTTP head as delimited by `HeadParser`.
/// Headers must use `\r\n` line endings; bare-LF lines are not correctly
/// parsed and will likely result in missing-header errors.
///
/// Returns a `HandshakeError` if the request is malformed.
/// On success, returns a `Request` struct with all fields borrowing from `buf`.
pub fn parseRequest(buf: []const u8) HandshakeError!Request {

    // Step 1: Parse the request line.
    var lines = std.mem.splitSequence(u8, buf, "\r\n");
    const request_line = lines.next() orelse return HandshakeError.MalformedRequest;

    // Parse "METHOD PATH HTTP/1.1"
    const method_end = std.mem.indexOf(u8, request_line, " ") orelse
        return HandshakeError.MalformedRequest;
    const method = request_line[0..method_end];

    if (!std.mem.eql(u8, method, "GET")) {
        return HandshakeError.InvalidMethod;
    }

    const after_method = request_line[method_end + 1 ..];
    const path_end = std.mem.indexOf(u8, after_method, " ") orelse
        return HandshakeError.MalformedRequest;
    const path = after_method[0..path_end];

    const version = after_method[path_end + 1 ..];
    if (!std.mem.eql(u8, version, "HTTP/1.1")) {
        return HandshakeError.InvalidHttpVersion;
    }

    // Step 2: Parse headers.
    var found: FoundRequired = .{};
    var version_seen = false;

    var websocket_key: []const u8 = &[_]u8{};
    var host: []const u8 = &[_]u8{};
    var origin: []const u8 = &[_]u8{};
    var protocols: []const u8 = &[_]u8{};
    var extensions: []const u8 = &[_]u8{};

    while (lines.next()) |line| {
        if (line.len == 0) break;
        const colon_pos = std.mem.indexOf(u8, line, ":") orelse continue;
        const header_name = line[0..colon_pos];
        const header_value = std.mem.trim(u8, line[colon_pos + 1 ..], " \t");

        if (std.ascii.eqlIgnoreCase(header_name, "Upgrade")) {
            if (headerContainsToken(header_value, "websocket")) {
                found.upgrade = true;
            }
        } else if (std.ascii.eqlIgnoreCase(header_name, "Connection")) {
            if (headerContainsToken(header_value, "upgrade")) {
                found.connection = true;
            }
        } else if (std.ascii.eqlIgnoreCase(header_name, "Sec-WebSocket-Key")) {
            websocket_key = header_value;
            found.key = true;
        } else if (std.ascii.eqlIgnoreCase(header_name, "Sec-WebSocket-Version")) {
            version_seen = true;
            if (std.mem.eql(u8, header_value, "13")) {
                found.version = true;
            }
        } else if (std.ascii.eqlIgnoreCase(header_name, "Host")) {
            host = header_value;
        } else if (std.ascii.eqlIgnoreCase(header_name, "Origin")) {
            origin = header_value;
        } else if (std.ascii.eqlIgnoreCase(header_name, "Sec-WebSocket-Protocol")) {
            protocols = header_value;
        } else if (std.ascii.eqlIgnoreCase(header_name, "Sec-WebSocket-Extensions")) {
            extensions = header_value;
        }
    }

    // Step 3: Check all required headers were found.
    if (!found.upgrade) return HandshakeError.MissingUpgradeHeader;
    if (!found.connection) return HandshakeError.MissingConnectionHeader;
    if (!found.key) return HandshakeError.MissingWebSocketKey;
    if (!found.version) {
        if (version_seen) {
            return HandshakeError.UnsupportedWebSocketVersion;
        }
        return HandshakeError.MissingWebSocketVersion;
    }

    return Request{
        .method = method,
        .path = path,
        .websocket_key = websocket_key,
        .host = host,
        .origin = origin,
        .protocols = protocols,
        .extensions = extensions,
    };
}

/// Computes the Sec-WebSocket-Accept value per RFC 6455 Section 4.2.2.
///
/// Concatenates `client_key` with the magic GUID, computes SHA-1, and base64-encodes
/// the result into `accept_buf`. Returns the valid slice of `accept_buf`.
pub fn computeAcceptKey(accept_buf: *[28]u8, client_key: []const u8) []const u8 {
    var hasher = std.crypto.hash.Sha1.init(.{});
    hasher.update(client_key);
    hasher.update(websocket_guid);
    const digest = hasher.finalResult();

    const encoded = std.base64.standard.Encoder.encode(accept_buf, &digest);
    return encoded;
}

/// Error set for writeResponse.
pub const WriteError = error{
    BufferTooSmall,
};

/// Writes the HTTP 101 Switching Protocols response into `buf`.
///
/// Returns the slice of `buf` that was written, or `error.BufferTooSmall` if the
/// buffer is not large enough to hold the complete response.
pub fn writeResponse(buf: []u8, client_key: []const u8) WriteError![]const u8 {
    var accept_buf: [28]u8 = undefined;
    const accept_key = computeAcceptKey(&accept_buf, client_key);

    const prefix = "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: ";
    const suffix = "\r\n\r\n";

    const total_len = prefix.len + accept_key.len + suffix.len;
    if (buf.len < total_len) return WriteError.BufferTooSmall;

    @memcpy(buf[0..prefix.len], prefix);
    @memcpy(buf[prefix.len .. prefix.len + accept_key.len], accept_key);
    @memcpy(buf[prefix.len + accept_key.len .. total_len], suffix);

    return buf[0..total_len];
}

/// Base64-encode a 16-byte raw key into `key_buf`.
/// Returns the 24-byte encoded slice.
pub fn encodeKey(key_buf: *[24]u8, raw: *const [16]u8) []const u8 {
    return std.base64.standard.Encoder.encode(key_buf, raw);
}

/// Write an HTTP GET upgrade request into `buf`.
/// Returns the slice of `buf` that was written, or error if the buffer is too small.
pub fn writeRequest(
    buf: []u8,
    address: std.net.Address,
    path: []const u8,
    key: []const u8,
) ![]const u8 {
    var fbs = std.io.fixedBufferStream(buf);
    const w = fbs.writer();
    w.print("GET {s} HTTP/1.1\r\n", .{path}) catch return error.BufferTooSmall;
    w.print("Host: {f}\r\n", .{address}) catch return error.BufferTooSmall;
    w.writeAll("Upgrade: websocket\r\n") catch return error.BufferTooSmall;
    w.writeAll("Connection: Upgrade\r\n") catch return error.BufferTooSmall;
    w.print("Sec-WebSocket-Key: {s}\r\n", .{key}) catch return error.BufferTooSmall;
    w.writeAll("Sec-WebSocket-Version: 13\r\n") catch return error.BufferTooSmall;
    w.writeAll("\r\n") catch return error.BufferTooSmall;
    return buf[0..fbs.pos];
}

/// Validates an HTTP 101 Switching Protocols response.
///
/// `buf` must contain a complete HTTP head as delimited by `HeadParser`.
/// Headers must use `\r\n` line endings; bare-LF lines are not correctly
/// parsed and will likely result in missing-header errors.
///
/// Returns a `HandshakeError` if the response is malformed or invalid.
pub fn validateResponse(buf: []const u8, expected_key: []const u8) HandshakeError!void {
    // Parse status line
    var lines = std.mem.splitSequence(u8, buf, "\r\n");
    const status_line = lines.next() orelse return HandshakeError.MalformedResponse;

    if (!std.mem.startsWith(u8, status_line, "HTTP/1.1 ")) {
        return HandshakeError.MalformedResponse;
    }
    const after_version = status_line["HTTP/1.1 ".len..];
    if (after_version.len < 3) {
        return HandshakeError.MalformedResponse;
    }
    if (!std.mem.eql(u8, after_version[0..3], "101")) {
        return HandshakeError.InvalidStatusCode;
    }

    // Parse headers — track all three required response headers per RFC 6455 §4.2.2.
    var found_upgrade = false;
    var found_connection = false;
    var found_accept = false;

    while (lines.next()) |line| {
        if (line.len == 0) break;
        const colon_pos = std.mem.indexOf(u8, line, ":") orelse continue;
        const header_name = line[0..colon_pos];
        const header_value = std.mem.trim(u8, line[colon_pos + 1 ..], " \t");

        if (std.ascii.eqlIgnoreCase(header_name, "Upgrade")) {
            if (headerContainsToken(header_value, "websocket")) {
                found_upgrade = true;
            }
        } else if (std.ascii.eqlIgnoreCase(header_name, "Connection")) {
            if (headerContainsToken(header_value, "upgrade")) {
                found_connection = true;
            }
        } else if (std.ascii.eqlIgnoreCase(header_name, "Sec-WebSocket-Accept")) {
            var accept_buf: [28]u8 = undefined;
            const expected_accept = computeAcceptKey(&accept_buf, expected_key);
            if (!std.mem.eql(u8, header_value, expected_accept)) {
                return HandshakeError.InvalidAcceptKey;
            }
            found_accept = true;
        }
    }

    if (!found_upgrade) return HandshakeError.MissingUpgradeHeader;
    if (!found_connection) return HandshakeError.MissingConnectionHeader;
    if (!found_accept) return HandshakeError.MissingAcceptHeader;
}

// --- Internal helpers ---

/// Returns true if a comma-separated header value contains the given token
/// (case-insensitive, trims whitespace from value items). E.g. "keep-alive, Upgrade" contains "upgrade".
fn headerContainsToken(value: []const u8, token: []const u8) bool {
    var it = std.mem.splitScalar(u8, value, ',');
    while (it.next()) |item| {
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, item, " \t"), token)) return true;
    }
    return false;
}

const testing = std.testing;

// ===========================================================================
// Tests — Server-side (from handshake.zig)
// ===========================================================================

test "parseRequest: valid full upgrade request" {
    const request_bytes =
        "GET /chat HTTP/1.1\r\n" ++
        "Host: server.example.com\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "\r\n";

    const req = try parseRequest(request_bytes);

    try testing.expectEqualStrings("GET", req.method);
    try testing.expectEqualStrings("/chat", req.path);
    try testing.expectEqualStrings("dGhlIHNhbXBsZSBub25jZQ==", req.websocket_key);
    try testing.expectEqualStrings("server.example.com", req.host);
    try testing.expectEqualStrings("", req.origin);
    try testing.expectEqualStrings("", req.protocols);
    try testing.expectEqualStrings("", req.extensions);
}

test "parseRequest: missing Upgrade header" {
    const request_bytes =
        "GET /chat HTTP/1.1\r\n" ++
        "Host: server.example.com\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "\r\n";

    const result = parseRequest(request_bytes);
    try testing.expectError(HandshakeError.MissingUpgradeHeader, result);
}

test "parseRequest: missing Connection header" {
    const request_bytes =
        "GET /chat HTTP/1.1\r\n" ++
        "Host: server.example.com\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "\r\n";

    const result = parseRequest(request_bytes);
    try testing.expectError(HandshakeError.MissingConnectionHeader, result);
}

test "parseRequest: missing Sec-WebSocket-Key header" {
    const request_bytes =
        "GET /chat HTTP/1.1\r\n" ++
        "Host: server.example.com\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "\r\n";

    const result = parseRequest(request_bytes);
    try testing.expectError(HandshakeError.MissingWebSocketKey, result);
}

test "parseRequest: missing Sec-WebSocket-Version header" {
    const request_bytes =
        "GET /chat HTTP/1.1\r\n" ++
        "Host: server.example.com\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "\r\n";

    const result = parseRequest(request_bytes);
    try testing.expectError(HandshakeError.MissingWebSocketVersion, result);
}

test "parseRequest: wrong HTTP version" {
    const request_bytes =
        "GET /chat HTTP/1.0\r\n" ++
        "Host: server.example.com\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "\r\n";

    const result = parseRequest(request_bytes);
    try testing.expectError(HandshakeError.InvalidHttpVersion, result);
}

test "parseRequest: wrong method" {
    const request_bytes =
        "POST /chat HTTP/1.1\r\n" ++
        "Host: server.example.com\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "\r\n";

    const result = parseRequest(request_bytes);
    try testing.expectError(HandshakeError.InvalidMethod, result);
}

test "parseRequest: wrong WebSocket version" {
    const request_bytes =
        "GET /chat HTTP/1.1\r\n" ++
        "Host: server.example.com\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 8\r\n" ++
        "\r\n";

    const result = parseRequest(request_bytes);
    try testing.expectError(HandshakeError.UnsupportedWebSocketVersion, result);
}

test "parseRequest: optional headers captured" {
    const request_bytes =
        "GET /chat HTTP/1.1\r\n" ++
        "Host: server.example.com\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "Origin: http://example.com\r\n" ++
        "Sec-WebSocket-Protocol: chat, superchat\r\n" ++
        "Sec-WebSocket-Extensions: permessage-deflate\r\n" ++
        "\r\n";

    const req = try parseRequest(request_bytes);

    try testing.expectEqualStrings("http://example.com", req.origin);
    try testing.expectEqualStrings("chat, superchat", req.protocols);
    try testing.expectEqualStrings("permessage-deflate", req.extensions);
}

test "parseRequest: case insensitive headers" {
    const request_bytes =
        "GET /chat HTTP/1.1\r\n" ++
        "host: server.example.com\r\n" ++
        "upgrade: WebSocket\r\n" ++
        "connection: UPGRADE\r\n" ++
        "sec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "sec-websocket-version: 13\r\n" ++
        "\r\n";

    const req = try parseRequest(request_bytes);

    try testing.expectEqualStrings("GET", req.method);
    try testing.expectEqualStrings("dGhlIHNhbXBsZSBub25jZQ==", req.websocket_key);
    try testing.expectEqualStrings("server.example.com", req.host);
}

test "computeAcceptKey: RFC 6455 example" {
    var accept_buf: [28]u8 = undefined;
    const accept_key = computeAcceptKey(&accept_buf, "dGhlIHNhbXBsZSBub25jZQ==");
    try testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", accept_key);
}

test "writeResponse: produces valid 101 response" {
    var buf: [256]u8 = undefined;
    const response = try writeResponse(&buf, "dGhlIHNhbXBsZSBub25jZQ==");

    // Verify the response starts with 101 status.
    try testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 101 Switching Protocols\r\n"));

    // Verify required headers are present.
    try testing.expect(std.mem.indexOf(u8, response, "Upgrade: websocket\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, response, "Connection: Upgrade\r\n") != null);
    const accept_header = "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n";
    try testing.expect(std.mem.indexOf(u8, response, accept_header) != null);

    // Verify response ends with \r\n\r\n.
    try testing.expect(std.mem.endsWith(u8, response, "\r\n\r\n"));
}

test "writeResponse: buffer too small" {
    var buf: [10]u8 = undefined;
    const result = writeResponse(&buf, "dGhlIHNhbXBsZSBub25jZQ==");
    try testing.expectError(WriteError.BufferTooSmall, result);
}

test "writeResponse: accept key matches computeAcceptKey" {
    const client_key = "dGhlIHNhbXBsZSBub25jZQ==";

    // Compute accept key directly.
    var accept_buf: [28]u8 = undefined;
    const expected_accept = computeAcceptKey(&accept_buf, client_key);

    // Write full response.
    var response_buf: [256]u8 = undefined;
    const response = try writeResponse(&response_buf, client_key);

    // Extract accept key from response.
    const accept_prefix = "Sec-WebSocket-Accept: ";
    const accept_start = (std.mem.indexOf(u8, response, accept_prefix) orelse
        return error.TestFailed) + accept_prefix.len;
    const accept_end = std.mem.indexOf(u8, response[accept_start..], "\r\n") orelse
        return error.TestFailed;
    const response_accept = response[accept_start .. accept_start + accept_end];

    try testing.expectEqualStrings(expected_accept, response_accept);
}

test "headerContainsToken: exact match" {
    try testing.expect(headerContainsToken("websocket", "websocket"));
    try testing.expect(headerContainsToken("Upgrade", "upgrade"));
}

test "headerContainsToken: case insensitive" {
    try testing.expect(headerContainsToken("WebSocket", "websocket"));
    try testing.expect(headerContainsToken("WEBSOCKET", "websocket"));
    try testing.expect(headerContainsToken("UPGRADE", "upgrade"));
}

test "headerContainsToken: comma-separated list" {
    try testing.expect(headerContainsToken("keep-alive, Upgrade", "upgrade"));
    try testing.expect(headerContainsToken("Upgrade, keep-alive", "upgrade"));
    try testing.expect(headerContainsToken("foo, Upgrade, bar", "upgrade"));
}

test "headerContainsToken: trims whitespace" {
    try testing.expect(headerContainsToken("  websocket  ", "websocket"));
    try testing.expect(headerContainsToken("keep-alive,\tUpgrade", "upgrade"));
    try testing.expect(headerContainsToken("keep-alive ,  Upgrade  ", "upgrade"));
}

test "headerContainsToken: rejects substrings" {
    try testing.expect(!headerContainsToken("notwebsocket", "websocket"));
    try testing.expect(!headerContainsToken("websocketx", "websocket"));
    try testing.expect(!headerContainsToken("noupgrade", "upgrade"));
    try testing.expect(!headerContainsToken("upgrade2", "upgrade"));
}

test "headerContainsToken: no match" {
    try testing.expect(!headerContainsToken("keep-alive", "upgrade"));
    try testing.expect(!headerContainsToken("", "upgrade"));
    try testing.expect(!headerContainsToken("foo, bar, baz", "upgrade"));
}

// ===========================================================================
// Tests — Client-side (from client_handshake.zig)
// ===========================================================================

test "encodeKey: produces 24-byte base64 string" {
    var buf: [24]u8 = undefined;
    const raw = [_]u8{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    };
    const key = encodeKey(&buf, &raw);
    try testing.expectEqual(@as(usize, 24), key.len);

    // Verify it's valid base64 by decoding
    var decoded: [16]u8 = undefined;
    try std.base64.standard.Decoder.decode(&decoded, key);
    try testing.expectEqualSlices(u8, &raw, &decoded);
}

test "encodeKey: different inputs produce different keys" {
    var buf1: [24]u8 = undefined;
    var buf2: [24]u8 = undefined;
    const raw1: [16]u8 = @splat(0x01);
    const raw2: [16]u8 = @splat(0x02);
    const key1 = encodeKey(&buf1, &raw1);
    const key2 = encodeKey(&buf2, &raw2);
    try testing.expect(!std.mem.eql(u8, key1, key2));
}

test "writeRequest: produces valid HTTP request" {
    var buf: [512]u8 = undefined;
    const addr = std.net.Address.initIp4(.{ 93, 184, 216, 34 }, 443);
    const request = try writeRequest(&buf, addr, "/ws", "dGhlIHNhbXBsZSBub25jZQ==");

    try testing.expect(std.mem.startsWith(u8, request, "GET /ws HTTP/1.1\r\n"));
    try testing.expect(std.mem.indexOf(u8, request, "Host: 93.184.216.34:443\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, request, "Upgrade: websocket\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, request, "Connection: Upgrade\r\n") != null);
    const key_header = "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n";
    try testing.expect(std.mem.indexOf(u8, request, key_header) != null);
    try testing.expect(std.mem.indexOf(u8, request, "Sec-WebSocket-Version: 13\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, request, "\r\n\r\n"));
}

test "writeRequest: buffer too small" {
    var buf: [10]u8 = undefined;
    const addr = std.net.Address.initIp4(.{ 93, 184, 216, 34 }, 443);
    const result = writeRequest(&buf, addr, "/ws", "dGhlIHNhbXBsZSBub25jZQ==");
    try testing.expectError(error.BufferTooSmall, result);
}

test "validateResponse: valid 101 response" {
    const client_key = "dGhlIHNhbXBsZSBub25jZQ==";
    var accept_buf: [28]u8 = undefined;
    const accept_key = computeAcceptKey(&accept_buf, client_key);

    var response_buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&response_buf);
    const w = fbs.writer();
    try w.writeAll("HTTP/1.1 101 Switching Protocols\r\n");
    try w.writeAll("Upgrade: websocket\r\n");
    try w.writeAll("Connection: Upgrade\r\n");
    try w.print("Sec-WebSocket-Accept: {s}\r\n", .{accept_key});
    try w.writeAll("\r\n");

    try validateResponse(response_buf[0..fbs.pos], client_key);
}

test "validateResponse: wrong status code" {
    const response = "HTTP/1.1 400 Bad Request\r\n\r\n";
    const result = validateResponse(response, "somekey");
    try testing.expectError(HandshakeError.InvalidStatusCode, result);
}

test "validateResponse: missing accept header" {
    const response =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "\r\n";
    const result = validateResponse(response, "somekey");
    try testing.expectError(HandshakeError.MissingAcceptHeader, result);
}

test "validateResponse: missing upgrade header" {
    const client_key = "dGhlIHNhbXBsZSBub25jZQ==";
    var accept_buf: [28]u8 = undefined;
    const accept_key = computeAcceptKey(&accept_buf, client_key);

    var response_buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&response_buf);
    const w = fbs.writer();
    try w.writeAll("HTTP/1.1 101 Switching Protocols\r\n");
    try w.writeAll("Connection: Upgrade\r\n");
    try w.print("Sec-WebSocket-Accept: {s}\r\n", .{accept_key});
    try w.writeAll("\r\n");

    const result = validateResponse(response_buf[0..fbs.pos], client_key);
    try testing.expectError(HandshakeError.MissingUpgradeHeader, result);
}

test "validateResponse: missing connection header" {
    const client_key = "dGhlIHNhbXBsZSBub25jZQ==";
    var accept_buf: [28]u8 = undefined;
    const accept_key = computeAcceptKey(&accept_buf, client_key);

    var response_buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&response_buf);
    const w = fbs.writer();
    try w.writeAll("HTTP/1.1 101 Switching Protocols\r\n");
    try w.writeAll("Upgrade: websocket\r\n");
    try w.print("Sec-WebSocket-Accept: {s}\r\n", .{accept_key});
    try w.writeAll("\r\n");

    const result = validateResponse(response_buf[0..fbs.pos], client_key);
    try testing.expectError(HandshakeError.MissingConnectionHeader, result);
}

test "validateResponse: wrong accept key" {
    const response =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: wrongkey=\r\n" ++
        "\r\n";
    const result = validateResponse(response, "dGhlIHNhbXBsZSBub25jZQ==");
    try testing.expectError(HandshakeError.InvalidAcceptKey, result);
}

test "validateResponse: malformed status line" {
    const response = "INVALID\r\n\r\n";
    const result = validateResponse(response, "somekey");
    try testing.expectError(HandshakeError.MalformedResponse, result);
}

test "validateResponse: status-line-only response with no headers" {
    // Regression: a 101 response with no header lines at all. The status line
    // is terminated by the \r\n that starts the \r\n\r\n boundary.
    const response = "HTTP/1.1 101 Switching Protocols\r\n\r\n";
    const result = validateResponse(response, "somekey");
    try testing.expectError(HandshakeError.MissingUpgradeHeader, result);
}

test "validateResponse: non-101 status-line-only response" {
    const response = "HTTP/1.1 403 Forbidden\r\n\r\n";
    const result = validateResponse(response, "somekey");
    try testing.expectError(HandshakeError.InvalidStatusCode, result);
}
