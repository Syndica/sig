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
    };
}
