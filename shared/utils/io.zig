const std = @import("std");

pub fn peekableReader(reader: anytype) PeekableReader(@TypeOf(reader)) {
    return .{ .backing_reader = reader };
}

pub fn PeekableReader(comptime ReaderType: type) type {
    return struct {
        backing_reader: ReaderType,
        next_byte: ?u8 = null,

        pub const Error = ReaderType.Error;
        pub const Reader = std.io.GenericReader(*Self, Error, read);

        const Self = @This();

        pub fn read(self: *Self, dest: []u8) Error!usize {
            if (dest.len == 0) return 0;
            if (self.next_byte) |byte| {
                dest[0] = byte;
                self.next_byte = null;
                if (dest.len == 1) return 1;
                return 1 + try self.backing_reader.read(dest[1..]);
            }
            return self.backing_reader.read(dest);
        }

        pub fn peekByte(self: *Self) !u8 {
            if (self.next_byte) |byte| return byte;
            self.next_byte = try self.backing_reader.readByte();
            return self.next_byte.?;
        }

        pub fn reader(self: *Self) Reader {
            return .{ .context = self };
        }
    };
}
