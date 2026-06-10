const std = @import("std");
const sig = @import("../sig.zig");
const builtin = @import("builtin");

const bincode = sig.bincode;

const FileOffset = u32;

/// slice-like datatype
pub const AccountDataHandle = union(enum) {
    /// Data allocated elsewhere, freed on .deinit.
    owned_allocation: []u8,
    /// Data allocated elsewhere, not owned.
    unowned_allocation: []const u8,
    /// Data owned by parent AccountDataHandle
    sub_read: SubRead,
    /// Used in place of a read, in callsites where it is not actually needed. Provides .len().
    empty: Empty,

    const SubRead = packed struct(u128) {
        parent: *const AccountDataHandle,
        // offset into the parent's read
        start: u32,
        end: u32,
    };

    const Empty = struct {
        len: u32,
    };

    pub const @"!bincode-config" = bincode.FieldConfig(AccountDataHandle){
        .deserializer = bincodeDeserialize,
        .serializer = bincodeSerialize,
        .free = bincodeFree,
    };

    /// Data will be freed upon .deinit
    pub fn initAllocatedOwned(data: []u8) AccountDataHandle {
        return AccountDataHandle{ .owned_allocation = data };
    }

    pub fn initAllocated(data: []const u8) AccountDataHandle {
        return AccountDataHandle{ .unowned_allocation = data };
    }

    pub fn initEmpty(length: u32) AccountDataHandle {
        return .{ .empty = .{ .len = length } };
    }

    pub fn deinit(self: AccountDataHandle, allocator: std.mem.Allocator) void {
        switch (self) {
            .owned_allocation => |owned_allocation| {
                allocator.free(owned_allocation);
            },
            .sub_read,
            .unowned_allocation,
            .empty,
            => {},
        }
    }

    pub fn iterator(self: *const AccountDataHandle) Iterator {
        return .{ .read_handle = self, .start = 0, .end = self.len() };
    }

    /// Copies all data into specified buffer. Buf.len === self.len()
    pub fn readAll(self: AccountDataHandle, buf: []u8) void {
        std.debug.assert(buf.len == self.len());
        _ = self.read(0, buf);
    }

    pub fn readAllAllocate(self: AccountDataHandle, allocator: std.mem.Allocator) ![]u8 {
        return self.readAllocate(allocator, 0, self.len());
    }

    /// Copies data into specified buffer.
    ///
    /// Returns the number of bytes written into buf, which should be equal to
    /// @min(self.len() - start, buf.len)
    pub fn read(
        self: *const AccountDataHandle,
        start: FileOffset,
        buf: []u8,
    ) u32 {
        std.debug.assert(start <= self.len());
        const end: FileOffset = @intCast(start + buf.len);

        switch (self.*) {
            .owned_allocation, .unowned_allocation => |data| {
                @memcpy(buf, data[start..end]);
                return end - start;
            },
            .sub_read => |*sb| return sb.parent.read(sb.start + start, buf),
            .empty => return 0,
        }
    }

    pub fn readAllocate(
        self: AccountDataHandle,
        allocator: std.mem.Allocator,
        start: FileOffset,
        end: FileOffset,
    ) ![]u8 {
        const buf = try allocator.alloc(u8, end - start);
        _ = self.read(start, buf);
        return buf;
    }

    pub fn len(self: AccountDataHandle) u32 {
        return switch (self) {
            .sub_read => |sr| sr.end - sr.start,
            .empty => |empty| empty.len,
            .owned_allocation, .unowned_allocation => |data| @intCast(data.len),
        };
    }

    pub fn iteratorRanged(
        self: *const AccountDataHandle,
        start: FileOffset,
        end: FileOffset,
    ) Iterator {
        std.debug.assert(self.len() >= end);
        std.debug.assert(end >= start);

        return .{ .read_handle = self, .start = start, .end = end };
    }

    pub fn dupeAllocatedOwned(
        self: AccountDataHandle,
        allocator: std.mem.Allocator,
    ) !AccountDataHandle {
        const data_copy = try self.readAllAllocate(allocator);
        return initAllocatedOwned(data_copy);
    }

    pub fn toOwned(self: AccountDataHandle, allocator: std.mem.Allocator) ![]u8 {
        return switch (self) {
            .owned_allocation => |data| data,
            else => {
                const new_data_handle = try self.dupeAllocatedOwned(allocator);
                self.deinit(allocator);
                return new_data_handle.owned_allocation;
            },
        };
    }

    pub fn slice(self: *const AccountDataHandle, start: u32, end: u32) AccountDataHandle {
        return .{ .sub_read = .{
            .parent = self,
            .end = end,
            .start = start,
        } };
    }

    /// testing purposes only
    pub fn expectEqual(expected: AccountDataHandle, actual: AccountDataHandle) !void {
        if (!builtin.is_test)
            @compileError("AccountDataHandle.expectEqual is for testing purposes only");
        const expected_buf = try expected.readAllocate(std.testing.allocator, 0, expected.len());
        defer std.testing.allocator.free(expected_buf);
        const actual_buf = try actual.readAllocate(std.testing.allocator, 0, actual.len());
        defer std.testing.allocator.free(actual_buf);
        try std.testing.expectEqualSlices(u8, expected_buf, actual_buf);
    }

    pub fn eql(h1: AccountDataHandle, h2: AccountDataHandle) bool {
        if (std.meta.eql(h1, h2)) return true;
        if (h1.len() != h2.len()) return false;

        var h1_iter = h1.iterator();
        var h2_iter = h2.iterator();

        while (h1_iter.nextByte()) |h1_byte| {
            const h2_byte = h2_iter.nextByte().?;
            if (h1_byte != h2_byte) return false;
        }

        return true;
    }

    pub fn eqlSlice(self: AccountDataHandle, data: []const u8) bool {
        if (self.len() != data.len) return false;

        var iter = self.iterator();
        var i: u32 = 0;
        while (iter.nextFrame()) |frame_slice| : (i += @intCast(frame_slice.len)) {
            if (!std.mem.eql(u8, frame_slice, data[i..][0..frame_slice.len])) return false;
        }

        return true;
    }

    pub const Iterator = struct {
        read_handle: *const AccountDataHandle,
        bytes_read: FileOffset = 0,
        start: FileOffset,
        end: FileOffset,

        /// Read in chunks of up to this size at a time when iterating frames.
        const CHUNK_SIZE: u32 = 512;

        pub const Reader = std.io.GenericReader(*Iterator, error{}, Iterator.readBytes);

        pub fn reader(self: *Iterator) Reader {
            return .{ .context = self };
        }

        pub fn len(self: Iterator) FileOffset {
            return self.end - self.start;
        }

        pub fn bytesRemaining(self: Iterator) FileOffset {
            return self.len() - self.bytes_read;
        }

        pub fn readBytes(self: *Iterator, buffer: []u8) error{}!usize {
            if (self.bytes_read == self.end) return 0;

            const read_len = @min(self.bytesRemaining(), buffer.len);

            self.bytes_read +=
                self.read_handle.read(self.start + self.bytes_read, buffer[0..read_len]);
            return read_len;
        }

        pub fn nextByte(self: *Iterator) ?u8 {
            var buf: u8 = undefined;
            const buf_len = self.readBytes((&buf)[0..1]) catch unreachable;
            if (buf_len > 1) unreachable;
            if (buf_len == 0) return null;
            return buf;
        }

        /// Does not copy, reads buffers of up to CHUNK_SIZE at a time.
        pub fn nextFrame(self: *Iterator) ?[]const u8 {
            if (self.bytesRemaining() == 0) return null;

            const read_offset: FileOffset = self.start + self.bytes_read;

            const frame_buf = switch (self.read_handle.*) {
                .owned_allocation, .unowned_allocation => |external| buf: {
                    const end_idx = @min(
                        read_offset + CHUNK_SIZE,
                        read_offset + self.bytesRemaining(),
                    );
                    break :buf external[read_offset..end_idx];
                },
                .empty => unreachable,
                .sub_read => @panic("unimplemented"),
            };

            if (frame_buf.len == 0) unreachable; // guarded against by the bytes_read check
            if (self.bytes_read > self.len()) unreachable; // we've gone too far

            self.bytes_read += @intCast(frame_buf.len);
            return frame_buf;
        }
    };

    fn bincodeSerialize(
        writer: anytype,
        read_handle: anytype,
        params: bincode.Params,
    ) anyerror!void {
        // we want to serialise it as if it's a slice
        try bincode.write(writer, @as(u64, read_handle.len()), params);

        var iter = read_handle.iterator();
        while (iter.nextFrame()) |frame| {
            try writer.writeAll(frame);
        }
    }

    fn bincodeDeserialize(
        limit_allocator: *bincode.LimitAllocator,
        reader: anytype,
        params: bincode.Params,
    ) anyerror!AccountDataHandle {
        const data = try bincode.readWithLimit(limit_allocator, []u8, reader, params);
        return AccountDataHandle.initAllocatedOwned(data);
    }

    fn bincodeFree(allocator: std.mem.Allocator, read_handle: anytype) void {
        read_handle.deinit(allocator);
    }
};
