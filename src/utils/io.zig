const std = @import("std");
const testing = std.testing;

/// Writer which captures only an offset window of data into a buffer.
/// This can be useful for incrementally capturing formatted data.
pub const WindowedWriter = struct {
    remaining_to_ignore: u64,
    end_index: usize,
    buffer: []u8,

    pub fn init(
        buffer: []u8,
        start_bytes_to_ignore: u64,
    ) WindowedWriter {
        std.debug.assert(buffer.len != 0);
        return .{
            .remaining_to_ignore = start_bytes_to_ignore,
            .end_index = 0,
            .buffer = buffer,
        };
    }

    pub fn reset(self: *WindowedWriter, start_bytes_to_ignore: usize) void {
        self.remaining_to_ignore = start_bytes_to_ignore;
        self.end_index = 0;
    }

    pub fn write(self: *WindowedWriter, bytes: []const u8) void {
        const bytes_to_skip = @min(self.remaining_to_ignore, bytes.len);
        self.remaining_to_ignore -|= bytes.len;

        const src_target_bytes = bytes[bytes_to_skip..];
        const writable = self.buffer[self.end_index..];

        const amt = @min(writable.len, src_target_bytes.len);
        @memcpy(writable[0..amt], src_target_bytes[0..amt]);
        self.end_index += amt;
    }

    pub const Writer = std.Io.GenericWriter(*WindowedWriter, error{}, writerFn);
    pub fn writer(self: *WindowedWriter) Writer {
        return .{ .context = self };
    }

    fn writerFn(self: *WindowedWriter, bytes: []const u8) error{}!usize {
        self.write(bytes);
        return bytes.len;
    }
};

fn testWindowedWriter(
    comptime kind: enum { bin, str },
    params: struct { start: usize, size: usize },
    data: []const u8,
    expected: []const u8,
) !void {
    const buffer = try std.testing.allocator.alloc(u8, params.size);
    defer std.testing.allocator.free(buffer);

    var ww = WindowedWriter.init(buffer, params.start);
    for (0..data.len) |split_i| {
        ww.reset(params.start);
        ww.write(data[0..split_i]);
        ww.write(data[split_i..]);
        try std.testing.expectEqual(expected.len, ww.end_index);
        switch (kind) {
            .bin => try std.testing.expectEqualSlices(u8, expected, ww.buffer),
            .str => try std.testing.expectEqualStrings(expected, ww.buffer),
        }
    }
}

test WindowedWriter {
    try testWindowedWriter(.str, .{ .start = 0, .size = 3 }, "foo\n", "foo");
    try testWindowedWriter(.str, .{ .start = 1, .size = 2 }, "foo\n", "oo");
    try testWindowedWriter(.str, .{ .start = 1, .size = 1 }, "foo\n", "o");
    try testWindowedWriter(.str, .{ .start = 2, .size = 1 }, "foo\n", "o");

    try testWindowedWriter(.str, .{ .start = 1, .size = 3 }, "foo\n", "oo\n");
    try testWindowedWriter(.str, .{ .start = 2, .size = 2 }, "foo\n", "o\n");

    try testWindowedWriter(.str, .{ .start = 0, .size = 1 }, "foo\n", "f");
    try testWindowedWriter(.str, .{ .start = 1, .size = 1 }, "foo\n", "o");
    try testWindowedWriter(.str, .{ .start = 2, .size = 1 }, "foo\n", "o");
    try testWindowedWriter(.str, .{ .start = 3, .size = 1 }, "foo\n", "\n");
}
