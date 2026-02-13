//! Vendored implementations from Zig 0.14 standard library for compatibility
//! during the migration to 0.15. This file provides implementations that were
//! removed or significantly changed in 0.15. This code exists solely for
//! compatibility with existing code, and should not be used for any new code.
const std = @import("std");
const io = std.io;
const assert = std.debug.assert;

/// Adapts the new Reader interface to the old one.
pub fn deprecatedReader(
    reader: *std.io.Reader,
) std.io.GenericReader(*std.io.Reader, std.io.Reader.StreamError, std.io.Reader.readSliceShort) {
    return .{ .context = reader };
}

pub fn CountingWriter(comptime WriterType: type) type {
    return struct {
        bytes_written: u64 = 0,
        child_stream: WriterType,

        pub const Error = WriterType.Error;
        pub const Writer = io.GenericWriter(*Self, Error, write);

        const Self = @This();

        pub fn write(self: *Self, bytes: []const u8) Error!usize {
            const amt = try self.child_stream.write(bytes);
            self.bytes_written += amt;
            return amt;
        }

        pub fn writer(self: *Self) Writer {
            return .{ .context = self };
        }
    };
}

pub fn countingWriter(child_stream: anytype) CountingWriter(@TypeOf(child_stream)) {
    return .{ .bytes_written = 0, .child_stream = child_stream };
}

pub fn BoundedArray(comptime T: type, comptime buffer_capacity: usize) type {
    return BoundedArrayAligned(T, @alignOf(T), buffer_capacity);
}

pub fn BoundedArrayAligned(
    comptime T: type,
    comptime alignment: u29,
    comptime buffer_capacity: usize,
) type {
    return struct {
        const Self = @This();
        buffer: [buffer_capacity]T align(alignment) = undefined,
        len: usize = 0,

        /// Set the actual length of the slice.
        /// Returns error.Overflow if it exceeds the length of the backing array.
        pub fn init(len: usize) error{Overflow}!Self {
            if (len > buffer_capacity) return error.Overflow;
            return Self{ .len = len };
        }

        /// View the internal array as a slice whose size was previously set.
        pub fn slice(self: anytype) switch (@TypeOf(&self.buffer)) {
            *align(alignment) [buffer_capacity]T => []align(alignment) T,
            *align(alignment) const [buffer_capacity]T => []align(alignment) const T,
            else => unreachable,
        } {
            return self.buffer[0..self.len];
        }

        /// View the internal array as a constant slice whose size was previously set.
        pub fn constSlice(self: *const Self) []align(alignment) const T {
            return self.slice();
        }

        /// Adjust the slice's length to `len`.
        /// Does not initialize added items if any.
        pub fn resize(self: *Self, len: usize) error{Overflow}!void {
            if (len > buffer_capacity) return error.Overflow;
            self.len = len;
        }

        /// Remove all elements from the slice.
        pub fn clear(self: *Self) void {
            self.len = 0;
        }

        /// Copy the content of an existing slice.
        pub fn fromSlice(m: []const T) error{Overflow}!Self {
            var list = try init(m.len);
            @memcpy(list.slice(), m);
            return list;
        }

        /// Return the element at index `i` of the slice.
        pub fn get(self: Self, i: usize) T {
            return self.constSlice()[i];
        }

        /// Set the value of the element at index `i` of the slice.
        pub fn set(self: *Self, i: usize, item: T) void {
            self.slice()[i] = item;
        }

        /// Return the maximum length of a slice.
        pub fn capacity(self: Self) usize {
            return self.buffer.len;
        }

        /// Check that the slice can hold at least `additional_count` items.
        fn ensureUnusedCapacity(self: Self, additional_count: usize) error{Overflow}!void {
            if (self.len + additional_count > buffer_capacity) {
                return error.Overflow;
            }
        }

        /// Increase length by 1, returning a pointer to the new item.
        pub fn addOne(self: *Self) error{Overflow}!*T {
            try self.ensureUnusedCapacity(1);
            return self.addOneAssumeCapacity();
        }

        /// Increase length by 1, returning pointer to the new item.
        /// Asserts that there is space for the new item.
        pub fn addOneAssumeCapacity(self: *Self) *T {
            assert(self.len < buffer_capacity);
            self.len += 1;
            return &self.slice()[self.len - 1];
        }

        /// Remove and return the last element from the slice, or return `null` if the slice is empty.
        pub fn pop(self: *Self) ?T {
            if (self.len == 0) return null;
            const item = self.get(self.len - 1);
            self.len -= 1;
            return item;
        }

        /// Return a slice of only the extra capacity after items.
        /// This can be useful for writing directly into it.
        /// Note that such an operation must be followed up with a
        /// call to `resize()`
        pub fn unusedCapacitySlice(self: *Self) []align(alignment) T {
            return self.buffer[self.len..];
        }

        /// Insert `item` at index `i` by moving `slice[n .. slice.len]` to make room.
        /// This operation is O(N).
        pub fn insert(
            self: *Self,
            i: usize,
            item: T,
        ) error{Overflow}!void {
            if (i > self.len) {
                return error.Overflow;
            }
            _ = try self.addOne();
            var s = self.slice();
            std.mem.copyBackwards(T, s[i + 1 .. s.len], s[i .. s.len - 1]);
            self.buffer[i] = item;
        }

        /// Extend the slice by 1 element.
        pub fn append(self: *Self, item: T) error{Overflow}!void {
            const new_item_ptr = try self.addOne();
            new_item_ptr.* = item;
        }

        /// Extend the slice by 1 element, asserting the capacity is already
        /// enough to store the new item.
        pub fn appendAssumeCapacity(self: *Self, item: T) void {
            const new_item_ptr = self.addOneAssumeCapacity();
            new_item_ptr.* = item;
        }

        /// Remove the element at index `i`, shift elements after index
        /// `i` forward, and return the removed element.
        /// Asserts the slice has at least one item.
        /// This operation is O(N).
        pub fn orderedRemove(self: *Self, i: usize) T {
            const newlen = self.len - 1;
            if (newlen == i) return self.pop().?;
            const old_item = self.get(i);
            for (self.slice()[i..newlen], 0..) |*b, j| b.* = self.get(i + 1 + j);
            self.set(newlen, undefined);
            self.len = newlen;
            return old_item;
        }

        /// Remove the element at the specified index and return it.
        /// The empty slot is filled from the end of the slice.
        /// This operation is O(1).
        pub fn swapRemove(self: *Self, i: usize) T {
            if (self.len - 1 == i) return self.pop().?;
            const old_item = self.get(i);
            self.set(i, self.pop().?);
            return old_item;
        }

        /// Append the slice of items to the slice.
        pub fn appendSlice(self: *Self, items: []const T) error{Overflow}!void {
            try self.ensureUnusedCapacity(items.len);
            self.appendSliceAssumeCapacity(items);
        }

        /// Append the slice of items to the slice, asserting the capacity is already
        /// enough to store the new items.
        pub fn appendSliceAssumeCapacity(self: *Self, items: []const T) void {
            const old_len = self.len;
            self.len += items.len;
            @memcpy(self.slice()[old_len..][0..items.len], items);
        }

        pub const Writer = if (T != u8)
            @compileError("The Writer interface is only defined for BoundedArray(u8, ...) " ++
                "but the given type is BoundedArray(" ++ @typeName(T) ++ ", ...)")
        else
            std.io.GenericWriter(*Self, error{Overflow}, appendWrite);

        /// Initializes a writer which will write into the array.
        pub fn writer(self: *Self) Writer {
            return .{ .context = self };
        }

        /// Same as `appendSlice` except it returns the number of bytes written, which is always the same
        /// as `m.len`. The purpose of this function existing is to match `std.io.Writer` API.
        fn appendWrite(self: *Self, m: []const u8) error{Overflow}!usize {
            try self.appendSlice(m);
            return m.len;
        }
    };
}

/// Specialized for .Slice variant of the implementation from 0.14 since that's
/// all we need.
pub fn LinearFifo(comptime T: type) type {
    return struct {
        buf: []T,
        head: usize = 0,
        count: usize = 0,

        pub fn init(buf: []T) LinearFifo(T) {
            return .{
                .buf = buf,
            };
        }

        pub fn len(self: LinearFifo(T)) usize {
            return self.count;
        }

        pub fn capacity(self: LinearFifo(T)) usize {
            return self.buf.len;
        }

        pub fn writableLength(self: LinearFifo(T)) usize {
            return self.buf.len - self.count;
        }

        pub fn write(self: *LinearFifo(T), data: []const T) !void {
            for (data) |item| {
                try self.writeItem(item);
            }
        }

        pub fn writeItem(self: *LinearFifo(T), item: T) !void {
            if (self.count >= self.buf.len) return error.NoSpaceLeft;
            const index = (self.head + self.count) % self.buf.len;
            self.buf[index] = item;
            self.count += 1;
        }

        pub fn writeItemAssumeCapacity(self: *LinearFifo(T), item: T) void {
            std.debug.assert(self.count < self.buf.len);
            const index = (self.head + self.count) % self.buf.len;
            self.buf[index] = item;
            self.count += 1;
        }

        pub fn readItem(self: *LinearFifo(T)) ?T {
            if (self.count == 0) return null;
            const item = self.buf[self.head];
            self.head = (self.head + 1) % self.buf.len;
            self.count -= 1;
            return item;
        }

        pub fn discard(self: *LinearFifo(T), count_to_discard: usize) void {
            const actual = @min(count_to_discard, self.count);
            self.head = (self.head + actual) % self.buf.len;
            self.count -= actual;
        }
    };
}

pub fn LimitedReader(comptime ReaderType: type) type {
    return struct {
        inner_reader: ReaderType,
        bytes_left: u64,

        pub const Error = ReaderType.Error;
        pub const Reader = std.io.GenericReader(*Self, Error, read);

        const Self = @This();

        pub fn read(self: *Self, dest: []u8) Error!usize {
            const max_read = @min(self.bytes_left, dest.len);
            const n = try self.inner_reader.read(dest[0..max_read]);
            self.bytes_left -= n;
            return n;
        }

        pub fn reader(self: *Self) Reader {
            return .{ .context = self };
        }
    };
}

pub fn limitedReader(inner_reader: anytype, bytes_left: u64) LimitedReader(@TypeOf(inner_reader)) {
    return .{ .inner_reader = inner_reader, .bytes_left = bytes_left };
}
