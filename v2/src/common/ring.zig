const std = @import("std");

comptime {
    _ = std.testing.refAllDecls(@This());
}

const Atomic = std.atomic.Value;

/// The ring that holds the packet buffers.
pub fn Ring(N: comptime_int, T: type) type {
    return extern struct {
        head: Pos align(std.atomic.cache_line),
        tail: Pos align(std.atomic.cache_line),
        array: [N]T,

        const Self = @This();
        const Pos = extern struct {
            value: Atomic(u32) = .init(0),
            cached_other: u32 = 0,
        };

        pub fn init(ptr: *Self) void {
            ptr.head = .{};
            ptr.tail = .{};
        }

        /// As the (sole) producer, get a view of items in the ring buffer that you can write to.
        /// If the ring buffer is full, retursn `error.Full`.
        pub fn getWritable(self: *Self) !Slice(.writer) {
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
                .ring = self,
                .pos = tail % N,
                .len = N - size,
            };
        }

        /// As the (sole) consume, get a view of items in the ring buffer that you can read from.
        /// If the ring buffer is empty, retursn `error.Empty`.
        pub fn getReadable(self: *Self) !Slice(.reader) {
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
                .ring = self,
                .idx = head % N,
                .len = size,
            };
        }

        /// A view of items in the ring buffer, either for reading or writing, for zero-copy use.
        /// The contiguous portion of a ring buffer available for use may sometimes wrap around the
        /// array. To enable contiguous processing as much as possible, the view exposes two slices:
        /// - `first()`: the start of the view into the array that DID NOT wrap around.
        /// - `second()`: if any, the view into the array (after `first()`) that DID wrap around.
        pub fn Slice(comptime mode: enum { reader, writer }) type {
            return struct {
                ring: *Self,
                /// The starting array index for the view.
                idx: u32,
                /// The number of elements the view exposes.
                len: u32,

                pub const Items = switch (mode) {
                    .reader => []const T,
                    .writer => []T,
                };

                /// The starting slice of the view that did not wrap around the ring buffer's array.
                pub fn first(self: @This()) Items {
                    return self.ring.array[self.idx..@min(N, self.idx + self.len)];
                }

                /// If the view wraps around the array, this returns the contiguous slice after the
                /// `first()` that wrapped around.
                /// If the view doesn't wrap, this returns an empty slice.
                pub fn second(self: @This()) Items {
                    return self.ring.array[0..((self.idx + self.len) -| N)];
                }

                /// Convenience helper function to get a specific item pointer in the view.
                /// The index must be 0 <= index < self.len
                pub fn get(self: @This(), index: usize) @TypeOf(&self.first()[0]) {
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
                pub fn markUsed(self: *@This(), n: u32) void {
                    std.debug.assert(n <= self.len);
                    self.len -= n;

                    const pos = self.idx + n;
                    self.idx = if (pos < N) pos else pos - N;
                    std.debug.assert(self.idx < N);

                    const position: *Pos = switch (mode) {
                        .reader => &self.ring.head,
                        .writer => &self.ring.tail,
                    };
                    position.value.store(position.value.raw +% n, .release);
                }
            };
        }
    };
}
