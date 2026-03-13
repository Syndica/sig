const std = @import("std");

comptime {
    _ = std.testing.refAllDecls(@This());
}

const Atomic = std.atomic.Value;

const Pos = extern struct {
    value: Atomic(u32) = .init(0),
    cached_other: u32 = 0,
};

/// The ring that holds the packet buffers.
pub fn Ring(N: comptime_int, T: type) type {
    return extern struct {
        head: Pos align(std.atomic.cache_line),
        tail: Pos align(std.atomic.cache_line),
        array: [N]T,
        const RingSelf = @This();

        pub fn init(ptr: *RingSelf) void {
            ptr.head = .{};
            ptr.tail = .{};
        }

        pub const SliceWritable = RingSlice(T, .writer);

        /// As the (sole) producer, get a view of items in the ring buffer that you can write to.
        /// If the ring buffer is full, retursn `error.Full`.
        pub fn getWritable(self: *RingSelf) !SliceWritable {
            const tail = self.tail.value.raw;
            var size = tail -% self.tail.cached_other;
            std.debug.assert(size <= N);

            if (size == N) {
                @branchHint(.unlikely);
                const new_head = self.head.value.load(.acquire);
                size = tail -% new_head;
                std.debug.assert(size <= N);
                if (size == N) return error.Full;
                self.tail.cached_other = new_head;
            }

            return .{
                .ring = self.asRef(),
                .idx = tail % N,
                .len = N - size,
            };
        }

        pub const SliceReadable = RingSlice(T, .reader);

        /// As the (sole) consume, get a view of items in the ring buffer that you can read from.
        /// If the ring buffer is empty, retursn `error.Empty`.
        pub fn getReadable(self: *RingSelf) !SliceReadable {
            const head = self.head.value.raw;
            var tail = self.head.cached_other;

            if (head == tail) {
                @branchHint(.unlikely);
                tail = self.tail.value.load(.acquire);
                if (head == tail) return error.Empty;
                self.head.cached_other = tail;
            }

            const size = tail -% head;
            std.debug.assert(size <= N);
            return .{
                .ring = self.asRef(),
                .idx = head % N,
                .len = size,
            };
        }

        fn asRef(self: *RingSelf) RingRef(T) {
            return .{
                .head = &self.head,
                .tail = &self.tail,
                .array = &self.array,
            };
        }
    };
}

fn RingRef(comptime T: type) type {
    return struct {
        head: *align(std.atomic.cache_line) Pos,
        tail: *align(std.atomic.cache_line) Pos,
        array: []T,
    };
}

/// A view of items in the ring buffer, either for reading or writing, for zero-copy use.
/// The contiguous portion of a ring buffer available for use may sometimes wrap around the
/// array. To enable contiguous processing as much as possible, the view exposes two slices:
/// - `first()`: the start of the view into the array that DID NOT wrap around.
/// - `second()`: if any, the view into the array (after `first()`) that DID wrap around.
pub fn RingSlice(
    T: type,
    comptime mode: enum { reader, writer },
) type {
    return struct {
        ring: RingRef(T),
        /// The starting array index for the view.
        idx: u32,
        /// The number of elements the view exposes.
        len: u32,
        const SliceSelf = @This();

        pub const Items = switch (mode) {
            .reader => []const T,
            .writer => []T,
        };

        /// The starting slice of the view that did not wrap around the ring buffer's array.
        pub fn first(self: SliceSelf) Items {
            const N = self.ring.array.len;
            return self.ring.array[self.idx..@min(N, self.idx + self.len)];
        }

        /// If the view wraps around the array, this returns the contiguous slice after the
        /// `first()` that wrapped around.
        /// If the view doesn't wrap, this returns an empty slice.
        pub fn second(self: SliceSelf) Items {
            const N = self.ring.array.len;
            return self.ring.array[0..((self.idx + self.len) -| N)];
        }

        /// Convenience helper function to get a specific item pointer in the view.
        /// The index must be 0 <= index < self.len
        pub fn get(self: SliceSelf, index: usize) @TypeOf(&self.first()[0]) {
            const N = self.ring.array.len;
            std.debug.assert(index < self.len);
            const pos = @as(usize, self.idx) + index;

            // idx = std.math.sub(usize, pos, N) catch pos;
            // this has the best codegen: `sub` + `cmovb`
            const idx = if (pos < N) pos else pos - N;
            std.debug.assert(idx < N);

            return &self.ring.array[pos];
        }

        /// After either reading from (or writing to) the elements in the view, this is used
        /// to update the ring's position telling the other sider that the number of items
        /// given are now available to read from (or be written to).
        ///
        /// `n` must be <= `self.len`.
        /// May be called multiple times, each time shrinking the view by `n`.
        pub fn markUsed(self: *SliceSelf, n: u32) void {
            const N = self.ring.array.len;

            std.debug.assert(n <= self.len);
            self.len -= n;

            const pos = self.idx + n;
            self.idx = if (pos < N) pos else @intCast(pos - N);
            std.debug.assert(self.idx < N);

            const position: *Pos = switch (mode) {
                .reader => self.ring.head,
                .writer => self.ring.tail,
            };
            position.value.store(position.value.raw +% n, .release);
        }

        pub fn reader(self: *RingSlice(u8, .reader), buffer: []u8) Reader {
            return .init(self, buffer);
        }

        pub fn writer(self: *RingSlice(u8, .writer), buffer: []u8) Writer {
            return .init(self, buffer);
        }
    };
}

/// This reader delays releasing data in the ring buffer until an explicit call to `release`,
/// to allow reading full, well-formed, and logically contiguous data, to facilitate cooperative
/// message-based communication, without having to retain the reader's buffer.
pub const Reader = struct {
    slice: *RingSlice(u8, .reader),
    /// Number of elements from the slice that have been read.
    /// Can be used for `slice.markUsed(advanced)`, as is done in `release`.
    advanced: u32,
    interface: std.Io.Reader,

    pub fn init(
        slice: *RingSlice(u8, .reader),
        buffer: []u8,
    ) Reader {
        return .{
            .slice = slice,
            .advanced = 0,
            .interface = .{
                .vtable = &vtable,
                .buffer = buffer,
                .seek = 0,
                .end = 0,
            },
        };
    }

    /// Release some or all of the bytes that have been read from the ring slice.
    pub fn release(self: *const Reader, n: u32) void {
        std.debug.assert(n <= self.advanced);
        self.slice.markUsed(n);
    }

    const vtable: std.Io.Reader.VTable = .{
        .stream = stream,
    };

    fn stream(
        r: *std.Io.Reader,
        w: *std.Io.Writer,
        limit: std.Io.Limit,
    ) std.Io.Reader.StreamError!usize {
        const self: *Reader = @fieldParentPtr("interface", r);
        if (self.advanced == self.slice.len) return error.EndOfStream;

        const first_slice = self.first();
        const second_slice = self.second();
        std.debug.assert(first_slice.len != 0 or second_slice.len != 0);

        var remaining_limit = limit;
        const one = remaining_limit.sliceConst(first_slice);
        remaining_limit = remaining_limit.subtract(first_slice.len) orelse .nothing;
        const two = remaining_limit.sliceConst(second_slice);
        remaining_limit = remaining_limit.subtract(second_slice.len) orelse .nothing;

        var vecs: [2][]const u8 = undefined;
        var vecs_len: usize = 0;

        if (one.len != 0) {
            vecs[vecs_len] = one;
            vecs_len += 1;
        }
        if (two.len != 0) {
            vecs[vecs_len] = two;
            vecs_len += 1;
        }
        std.debug.assert(vecs_len != 0);

        const n = try w.writeVec(vecs[0..vecs_len]);
        self.advanced += @intCast(n);
        return n;
    }

    fn first(self: *const Reader) []const u8 {
        const first_slice = self.slice.first();
        const offset = @min(first_slice.len, self.advanced);
        return first_slice[offset..];
    }

    fn second(self: *const Reader) []const u8 {
        const second_slice = self.slice.second();
        const offset = @min(second_slice.len, self.advanced -| self.slice.first().len);
        return second_slice[offset..];
    }
};

/// This writer delays committing data to the ring buffer until an explicit call to `commit`,
/// to allow writing full, well-formed, and logically contiguous data, to facilitate cooperative
/// message-based communication.
pub const Writer = struct {
    slice: *RingSlice(u8, .writer),
    /// Number of elements from the slice that have been written to.
    /// Can be used for `slice.markUsed(advanced)`, as is done in `commit`.
    advanced: u32,
    interface: std.Io.Writer,

    pub fn init(
        slice: *RingSlice(u8, .writer),
        buffer: []u8,
    ) Writer {
        return .{
            .slice = slice,
            .advanced = 0,
            .interface = .{
                .vtable = &vtable,
                .buffer = buffer,
            },
        };
    }

    /// Commit some or all of the bytes that have been written to the ring slice.
    pub fn commit(self: *const Writer, n: u32) void {
        std.debug.assert(n <= self.advanced);
        self.slice.markUsed(self.advanced);
    }

    const vtable: std.Io.Writer.VTable = .{
        .drain = drain,
    };

    fn drain(
        w: *std.Io.Writer,
        data: []const []const u8,
        splat: usize,
    ) std.Io.Writer.Error!usize {
        const self: *Writer = @fieldParentPtr("interface", w);

        std.debug.assert(data.len != 0);
        if (self.advanced == self.slice.len) return error.WriteFailed;

        if (w.end != 0) {
            var dst = self.first();
            if (dst.len == 0) dst = self.second();
            const amt = @min(dst.len, w.end);
            @memcpy(dst[0..amt], w.buffered()[0..amt]);
            _ = w.consume(amt);
            self.advanced += @intCast(amt);
            if (self.advanced == self.slice.len) return 0;
        }

        const dst = if (self.first().len != 0) self.first() else self.second();
        std.debug.assert(dst.len != 0);

        var dst_w: std.Io.Writer = .fixed(dst);
        const written = dst_w.writeSplat(data, splat) catch |err| switch (err) {
            error.WriteFailed => dst_w.end,
        };
        std.debug.assert(written == dst_w.end);
        self.advanced += @intCast(dst_w.end);
        return dst_w.end;
    }

    fn first(self: *const Writer) []u8 {
        const first_slice = self.slice.first();
        const offset = @min(first_slice.len, self.advanced);
        return first_slice[offset..];
    }

    fn second(self: *const Writer) []u8 {
        const second_slice = self.slice.second();
        const offset = @min(second_slice.len, self.advanced -| self.slice.first().len);
        return second_slice[offset..];
    }
};
