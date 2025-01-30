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
            } else {
                return self.backing_reader.read(dest);
            }
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

pub fn NarrowAnyWriter(comptime WriteError: type) type {
    return NarrowAnyStream(WriteError).Writer;
}
/// Returns a wrapper over the `AnyWriter` which narrows the error set from `anyerror`.
pub fn narrowAnyWriter(
    any_writer: std.io.AnyWriter,
    comptime WriteError: type,
) NarrowAnyWriter(WriteError) {
    return .{ .context = any_writer };
}

pub fn NarrowAnyReader(comptime ReadError: type) type {
    return NarrowAnyStream(ReadError).Reader;
}
/// Returns a wrapper over the `AnyReader` which narrows the error set from `anyerror`.
pub fn narrowAnyReader(
    any_reader: std.io.AnyReader,
    comptime ReadError: type,
) NarrowAnyReader(ReadError) {
    return .{ .context = any_reader };
}

fn NarrowAnyStream(comptime Error: type) type {
    return struct {
        const Writer = std.io.GenericWriter(std.io.AnyWriter, Error, write);
        fn write(any_writer: std.io.AnyWriter, bytes: []const u8) Error!usize {
            return @errorCast(any_writer.write(bytes));
        }

        const Reader = std.io.GenericReader(std.io.AnyReader, Error, read);
        fn read(any_reader: std.io.AnyReader, buffer: []u8) Error!usize {
            return @errorCast(any_reader.read(buffer));
        }
    };
}
