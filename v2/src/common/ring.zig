const std = @import("std");
const Atomic = std.atomic.Value;

/// The ring that holds the packet buffers.
pub fn Ring(N: comptime_int, T: type) type {
    return extern struct {
        magic: u32, // might want one at the end also?
        head: Pos align(std.atomic.cache_line),
        tail: Pos align(std.atomic.cache_line),
        array: [N]T,

        const MAGIC = 0xAABBCCDD;

        const Self = @This();
        const Pos = extern struct {
            value: Atomic(u32) = .init(0),
            cached_other: u32 = 0,
        };

        pub fn init(ptr: *Self) void {
            ptr.magic = MAGIC;
            ptr.head = .{};
            ptr.tail = .{};
        }

        pub fn getWritable(self: *Self) !Slice(.writer) {
            std.debug.assert(self.magic == MAGIC);
            const tail = self.tail.value.raw;
            var size = tail -% self.tail.cached_other;
            std.debug.assert(size <= N);

            if (size == N) {
                const new_head = self.head.value.load(.acquire);
                size = tail -% new_head;
                std.debug.assert(size <= N);
                if (size == N) return error.Full;
                self.tail.cached_other = new_head;
            }

            return .{
                .ring = self,
                .start = tail % N,
                .count = N - size,
            };
        }

        pub fn getReadable(self: *Self) !Slice(.reader) {
            std.debug.assert(self.magic == MAGIC);
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
                .start = head % N,
                .count = size,
            };
        }

        pub fn Slice(comptime mode: enum { reader, writer }) type {
            return struct {
                ring: *Self,
                start: u32,
                count: u32,

                pub const Items = switch (mode) {
                    .reader => []const T,
                    .writer => []T,
                };

                pub fn into(self: *@This(), slice: []const T) void {
                    defer self.markUsed(@intCast(slice.len));
                    std.debug.assert(self.count == slice.len);

                    const back = self.first();
                    const front = self.second();
                    @memcpy(back, slice[0..back.len]);
                    @memcpy(front, slice[back.len..][0..front.len]);
                }

                pub fn one(self: @This()) switch (mode) {
                    .reader => *const T,
                    .writer => *T,
                } {
                    var slice = self.first();
                    if (slice.len == 0) slice = self.second();
                    return &slice[0];
                }

                pub fn first(self: @This()) Items {
                    return self.ring.array[self.start..@min(N, self.start + self.count)];
                }

                pub fn second(self: @This()) Items {
                    return self.ring.array[0..((self.start + self.count) -| N)];
                }

                pub fn markUsed(self: *@This(), n: u32) void {
                    std.debug.assert(n <= self.count);
                    self.start = (self.start +% n) % N;
                    self.count -= n;

                    const pos: *Pos = switch (mode) {
                        .reader => &self.ring.head,
                        .writer => &self.ring.tail,
                    };
                    pos.value.store(pos.value.raw +% n, .release);
                }
            };
        }
    };
}
