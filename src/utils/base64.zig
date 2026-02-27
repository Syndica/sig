const std = @import("std");

/// Extracts the error type from a writer, supporting both struct writer types
/// (e.g. `GenericWriter`) that have `.Error` and pointer-to-writer types
/// (e.g. `*std.io.Writer`) where `.Error` is on the child type.
fn WriterError(comptime T: type) type {
    return switch (@typeInfo(T)) {
        .pointer => |p| p.child.Error,
        else => T.Error,
    };
}

/// Tool for writing a series of non-contiguous bytes to a contiguous
/// stream, encoded as base64 data.
pub const EncodingStream = struct {
    encoder: std.base64.Base64Encoder,
    trail_buf: [3]u8,
    trail_len: u2,

    pub fn init(encoder: std.base64.Base64Encoder) EncodingStream {
        return .{
            .encoder = encoder,
            .trail_buf = undefined,
            .trail_len = 0,
        };
    }

    pub fn reset(self: *EncodingStream) void {
        self.* = init(self.encoder);
    }

    /// Flushes any buffered writes to the writer, writing the trailing padding character if needed.
    pub fn flush(
        self: *EncodingStream,
        /// `std.io.GenericWriter(...)` | `*std.io.Writer`
        dst_writer: anytype,
    ) WriterError(@TypeOf(dst_writer))!void {
        const trail = self.trail_buf[0..self.trail_len];

        var encoded_trail_buf: [4]u8 = undefined;
        const encoded_trail = self.encoder.encode(&encoded_trail_buf, trail);
        try dst_writer.writeAll(encoded_trail);

        self.trail_len = 0;
    }

    /// Writes some portion of `bytes` encoded as base64 data to `writer`.
    /// Returns the number of bytes which were actually written.
    pub fn write(
        self: *EncodingStream,
        /// `std.io.GenericWriter(...)` | `*std.io.Writer`
        dst_writer: anytype,
        bytes: []const u8,
    ) WriterError(@TypeOf(dst_writer))!usize {
        if (bytes.len == 0) return 0;

        if (self.trail_len == 3) {
            // since `self.trail_len == 3`, it will encode a round 3 bytes,
            // which will encode to an unpadded 4 byte base64 string.
            try self.flush(dst_writer);
        }

        if (self.trail_len != 0 or bytes.len < 3) {
            const trail_dst = self.trail_buf[self.trail_len..];
            const amt: u2 = @intCast(@min(trail_dst.len, bytes.len));
            @memcpy(trail_dst[0..amt], bytes[0..amt]);
            self.trail_len += amt;
            return amt;
        }

        const remain_len: u2 = @intCast(bytes.len % 3);
        const direct_len = bytes.len - remain_len;

        const max_encoded_len = 128;
        const max_raw_len = @divExact(max_encoded_len, 4) * 3;

        var idx: usize = 0;
        while (idx != direct_len) {
            var encoded_buf: [max_encoded_len]u8 = undefined;

            const next_bytes = bytes[idx..direct_len];
            std.debug.assert(next_bytes.len % 3 == 0);
            const amt = @min(next_bytes.len, max_raw_len);
            idx += amt;

            const encoded = self.encoder.encode(&encoded_buf, next_bytes[0..amt]);
            try dst_writer.writeAll(encoded);
        }

        return direct_len;
    }

    pub fn writerCtx(
        self: *EncodingStream,
        dst_writer: anytype,
    ) WriterCtx(@TypeOf(dst_writer)) {
        return .{
            .stream = self,
            .inner = dst_writer,
        };
    }

    pub fn WriterCtx(comptime Inner: type) type {
        const InnerError = WriterError(Inner);

        return struct {
            stream: *EncodingStream,
            inner: Inner,
            const Self = @This();

            pub const Writer = std.io.GenericWriter(Self, InnerError, writeFn);

            pub fn writer(self: Self) Writer {
                return .{ .context = self };
            }

            pub fn flush(self: Self) InnerError!void {
                try self.stream.flush(self.inner);
            }

            fn writeFn(self: Self, bytes: []const u8) InnerError!usize {
                return self.stream.write(self.inner, bytes);
            }
        };
    }
};

test EncodingStream {
    for ([_]std.base64.Base64Encoder{
        std.base64.standard.Encoder,
        std.base64.url_safe.Encoder,
    }) |encoder| {
        try testEncodingStream(encoder, "");
        try testEncodingStream(encoder, "a");
        try testEncodingStream(encoder, "~~");
        try testEncodingStream(encoder, "~0~");
        try testEncodingStream(encoder, "~_0~");
        try testEncodingStream(encoder, "hello");
        try testEncodingStream(encoder, "~0~" ** 5);
        try testEncodingStream(encoder,
            \\good morning, good afternoon, good evening, and goodnight
        );
        try testEncodingStream(encoder,
            \\good morning, good afternoon, good evening, and goodnight
        ** 16);
    }
}

fn testEncodingStream(
    encoder: std.base64.Base64Encoder,
    input: []const u8,
) !void {
    const allocator = std.testing.allocator;

    const expected_output_buf = try allocator.alloc(u8, encoder.calcSize(input.len));
    defer allocator.free(expected_output_buf);
    const expected_output = encoder.encode(expected_output_buf, input);

    var actual_output_buf: std.ArrayListUnmanaged(u8) = .{};
    defer actual_output_buf.deinit(allocator);
    try actual_output_buf.ensureTotalCapacityPrecise(allocator, expected_output_buf.len);

    var stream = EncodingStream.init(encoder);
    const writer_ctx = stream.writerCtx(actual_output_buf.writer(allocator));
    const writer = writer_ctx.writer();

    for (1..input.len + 1) |size_advance| {
        actual_output_buf.clearRetainingCapacity();
        stream.reset();

        var window_iter = std.mem.window(u8, input, size_advance, size_advance);
        while (window_iter.next()) |segment| try writer.writeAll(segment);
        try writer_ctx.flush();
        const actual_output = actual_output_buf.items;

        std.testing.expectEqualStrings(expected_output, actual_output) catch |err| {
            var listing: std.ArrayListUnmanaged(u8) = .{};
            defer listing.deinit(allocator);

            window_iter.reset();
            while (window_iter.next()) |segment| {
                if (listing.items.len != 0) {
                    try listing.appendSlice(allocator, ", ");
                }
                try listing.append(allocator, '"');
                try listing.appendSlice(allocator, segment);
            }

            std.log.err("Segment inputs: {s}", .{listing.items});
            return err;
        };
    }
}
