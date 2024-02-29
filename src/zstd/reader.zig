const std = @import("std");

const Decompressor = @import("decompress.zig").Decompressor;
const types = @import("types.zig");
const InBuffer = types.InBuffer;
const OutBuffer = types.OutBuffer;
const Error = @import("error.zig").Error;

pub const Reader = struct {
    memory: []u8,
    decompressor: Decompressor,
    pos: usize = 0,

    pub const R = std.io.Reader(*Reader, Error, read);

    pub fn init(
        memory: []u8,
    ) !@This() {
        return .{
            .memory = memory,
            .decompressor = try Decompressor.init(.{}),
        };
    }

    pub fn reader(self: *@This()) R {
        return .{ .context = self };
    }

    pub fn read(self: *@This(), buf: []u8) Error!usize {
        if (self.pos == self.memory.len) {
            return 0;
        }
        var in_buf = InBuffer{ .src = self.memory.ptr, .size = self.memory.len, .pos = self.pos };
        var out_buf = OutBuffer{ .dst = buf.ptr, .size = buf.len, .pos = 0 };
        _ = try self.decompressor.decompressStream(&in_buf, &out_buf);
        self.pos = in_buf.pos;
        return out_buf.pos;
    }
};
