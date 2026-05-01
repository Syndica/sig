const std = @import("std");
const lib = @import("../lib.zig");

pub fn TarIterator(comptime Effects: type) type {
    lib.util.assertInterface(Effects, struct {
        /// Returns a slice that can be read from. If the stream is empty, error is returned.
        /// Does not consume the returned slice; That is instead done by `advance(n)`
        pub fn getSlice(self: Effects) error{EndOfStream}![]const u8 {
            _ = .{self};
            return undefined;
        }

        /// Tells the stream to advance `n` bytes from the most previous `getSlice()` call.
        /// `n` will always be `<= getSlice().len`.
        pub fn advance(self: Effects, n: usize) void {
            _ = .{ self, n };
            return undefined;
        }
    });

    return struct {
        tar_header: [512]u8 = undefined,
        tar_payload: usize = 0,
        tar_padding: usize = 0,
        effects: Effects,

        const Self = @This();

        pub fn init(effects: Effects) Self {
            return .{ .effects = effects };
        }

        pub const TarFile = struct {
            name: []const u8,
            size: usize,
        };

        pub fn next(self: *Self) !?TarFile {
            while (true) {
                // Skip unprocessed bytes from tar file body
                _ = self.read(null, self.tar_padding + self.tar_payload);

                // Read header
                const n = self.read(self.tar_header[0..].ptr, self.tar_header.len);
                if (n == 0) return null;
                if (n < self.tar_header.len) return error.EndOfStream;

                const is_file = self.tar_header[156] == '0' or self.tar_header[156] == 0;
                const file_name = std.mem.sliceTo(self.tar_header[0..100], 0);
                const file_size = blk: {
                    const buf = self.tar_header[124..][0..12];
                    if (buf[0] == 0xff) return error.InvalidTar; // negative size
                    if (buf[0] == 0x80) {
                        if (std.mem.readInt(u32, buf[0..4], .little) != 0x80) return error.InvalidTar;
                        break :blk std.mem.readInt(u64, buf[4..12], .big);
                    }
                    const trimmed = std.mem.trimRight(u8, std.mem.trimLeft(u8, buf, "0 "), " \x00");
                    if (trimmed.len == 0) break :blk 0;
                    break :blk std.fmt.parseInt(u64, trimmed, 8) catch return error.InvalidTar;
                };

                self.tar_payload = file_size;
                self.tar_padding = std.mem.alignForward(usize, file_size, 512) - file_size;
                if (file_size == 0 and file_name.len == 0) return null; // empty name/size = tar EOF
                if (is_file) return .{ .name = file_name, .size = file_size }; // only return files
            }
        }

        // Functions to emulate std.Io.Reader, but fast

        pub fn readSliceAll(self: *Self, buf: []u8) !void {
            if (buf.len > self.tar_payload) return error.EndOfStream;
            const n = self.read(buf.ptr, buf.len);
            self.tar_payload -= n;
            if (n < buf.len) return error.EndOfStream;
        }

        pub fn discardShort(self: *Self, n: usize) !usize {
            const take = @min(self.tar_payload, n);
            self.tar_payload -= take;
            return self.read(null, take);
        }

        pub fn discardAll(self: *Self, n: usize) !void {
            if ((try self.discardShort(n)) != n) return error.EndOfStream;
        }

        /// Reading from the Effects into a buffer (or skipping bytes if no buffer provided).
        fn read(self: *Self, maybe_ptr: ?[*]u8, len: usize) usize {
            if (len == 0) return 0;

            var n: usize = 0;
            while (true) : (std.atomic.spinLoopHint()) {
                const buf: []const u8 = self.effects.getSlice() catch return n;
                if (buf.len == 0) continue;

                const take = @min(buf.len, len - n);
                if (maybe_ptr) |ptr| {
                    @memcpy(ptr[n..][0..take], buf[0..take]);
                }

                self.effects.advance(take);
                n += take;
                if (n == len) return n;
            }
        }
    };
}
