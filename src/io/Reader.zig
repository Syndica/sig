bytes: []const u8,
bytes_read: usize,

pub fn init(bytes: []const u8) Reader {
    return .{ .bytes = bytes, .bytes_read = 0 };
}

pub fn peekByte(self: *Reader) !u8 {
    if (self.bytes_read >= self.bytes.len) return error.NoBytesLeft;
    return self.bytes[self.bytes_read];
}

pub fn readByte(self: *Reader) !u8 {
    if (self.bytes_read >= self.bytes.len) return error.NoBytesLeft;
    const byte = self.bytes[self.bytes_read];
    self.bytes_read += 1;
    return byte;
}

pub fn readBytes(self: *Reader, len: usize) ![]const u8 {
    if (self.bytes_read + len > self.bytes.len) return error.NoBytesLeft;
    const bytes = self.bytes[self.bytes_read..(self.bytes_read + len)];
    self.bytes_read += len;
    return bytes;
}

const Reader = @This();
