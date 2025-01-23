bytes: []u8,
bytes_written: usize,

pub fn init(buffer: []u8) Writer {
    return .{
        .bytes = buffer,
        .bytes_written = 0,
    };
}

pub fn writeByte(self: *Writer, byte: u8) !void {
    if (self.bytes_written >= self.bytes.len) return error.NoBytesLeft;
    self.bytes[self.bytes_written] = byte;
    self.bytes_written += 1;
}

pub fn writeBytes(self: *Writer, buffer: []const u8) !void {
    if (self.bytes_written + buffer.len > self.bytes.len) return error.NoBytesLeft;
    @memcpy(self.bytes[self.bytes_written .. self.bytes_written + buffer.len], buffer);
    self.bytes_written += buffer.len;
}

pub fn bytesWritten(self: *Writer) []u8 {
    return self.bytes[0..self.bytes_written];
}

const Writer = @This();
