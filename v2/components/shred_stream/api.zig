const std = @import("std");

pub const Args = extern struct {
    len: u32,
    bytes: [max_bytes]u8,

    pub const max_bytes = 16 * 1024;
    pub const max_args = 128;

    pub fn init(self: *Args, argv: []const []const u8) !void {
        var cursor: usize = 0;
        for (argv) |arg| {
            if (arg.len > std.math.maxInt(u16)) return error.ArgTooLong;
            if (cursor + @sizeOf(u16) + arg.len > self.bytes.len) return error.ArgsTooLong;
            self.bytes[cursor..][0..@sizeOf(u16)].* = @bitCast(@as(u16, @intCast(arg.len)));
            cursor += @sizeOf(u16);
            @memcpy(self.bytes[cursor..][0..arg.len], arg);
            cursor += arg.len;
        }
        self.len = @intCast(cursor);
    }

    pub fn slices(self: *const Args, out: *[max_args][]const u8) ![]const []const u8 {
        var cursor: usize = 0;
        var count: usize = 0;
        while (cursor < self.len) {
            if (count == out.len) return error.TooManyArgs;
            if (cursor + @sizeOf(u16) > self.len) return error.MalformedArgs;
            const len: u16 = @bitCast(self.bytes[cursor..][0..@sizeOf(u16)].*);
            cursor += @sizeOf(u16);
            if (cursor + len > self.len) return error.MalformedArgs;
            out[count] = self.bytes[cursor..][0..len];
            count += 1;
            cursor += len;
        }
        return out[0..count];
    }
};
