const std = @import("std");

pub fn peekableReader(reader: anytype) PeekableReader(@TypeOf(reader)) {
    return .{ .backing_reader = reader };
}

/// Allows you to view the next byte in the reader without removing it from the reader.
///
/// While BufferedReader could be used for the same purpose, it could also cause a problem
/// in some situations.
///
/// This is used instead of a BufferedReader when you plan to eventually discard this and
/// continue using the original reader. BufferedReader would be problematic for this use
/// case because you could potentially discard some bytes that were already read from the
/// underlying reader into the buffer, but not read from BufferedReader. PeekableReader is
/// safe for this use case as long as you use the byte that you have peeked before
/// discarding the PeekableReader instance.
pub fn PeekableReader(comptime ReaderType: type) type {
    return struct {
        backing_reader: ReaderType,
        next_byte: ?u8 = null,

        pub const Error = ReaderType.Error;
        pub const Reader = std.io.Reader(*Self, Error, read);

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
            if (self.next_byte) |byte| {
                return byte;
            } else {
                self.next_byte = try self.backing_reader.readByte();
                return self.next_byte.?;
            }
        }

        pub fn reader(self: *Self) Reader {
            return .{ .context = self };
        }
    };
}
