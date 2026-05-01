const std = @import("std");
const lib = @import("lib.zig");

pub const bincode = @import("snapshot/bincode.zig");
pub const tar = @import("snapshot/tar.zig");

pub const SnapshotSourceRing = lib.ipc.Ring(256, SnapshotSource);
pub const SnapshotSource = extern struct {
    rpc_addr: lib.gossip.Address,
    slot: lib.solana.Slot,
    hash: lib.solana.Hash,
};

pub const SnapshotConfig = extern struct {
    // TODO rename to "path"
    folder_buffer: [std.fs.max_path_bytes]u8,
    folder_len: u32,
    cluster: lib.solana.Cluster,
};

pub const SnapshotDecodeRing = extern struct {
    head: std.atomic.Value(Pos),
    buffer: [1 * 1024 * 1024 * 1024]u8,
    tail: std.atomic.Value(Pos), // on a far enough cache line

    const Pos = packed struct(u32) { closed: bool, value: u31 };
    const Side = enum { reader, writer };

    pub fn init(self: *SnapshotDecodeRing) void {
        self.head = .init(.{ .closed = false, .value = 0 });
        self.tail = .init(.{ .closed = false, .value = 0 });
    }

    pub fn getSlice(self: *SnapshotDecodeRing, comptime side: Side) ![]u8 {
        switch (side) {
            .reader => {
                const h = self.head.raw;
                std.debug.assert(!h.closed);

                const t = self.tail.load(.acquire);
                const readable = t.value -% h.value;
                std.debug.assert(readable <= self.buffer.len);

                // If closed, readable < 1 == read all items, then returns closed.
                // If !closed, readable < 0 == never true, so never returns closed.
                if (readable < @intFromBool(t.closed)) return error.Closed;

                // Return longest contiguous buffer.
                const idx = h.value % self.buffer.len;
                return self.buffer[idx..@min(idx + readable, self.buffer.len)];
            },
            .writer => {
                const t = self.tail.raw;
                std.debug.assert(!t.closed);

                const h = self.head.load(.acquire);
                const readable = t.value -% h.value;
                std.debug.assert(readable <= self.buffer.len);

                const writable = self.buffer.len - readable;
                const idx = t.value % self.buffer.len;
                return self.buffer[idx..@min(idx + writable, self.buffer.len)];
            },
        }
    }

    pub fn advance(self: *SnapshotDecodeRing, comptime side: Side, n: usize) void {
        const ptr = if (side == .reader) &self.head else &self.tail;
        const pos = ptr.raw;
        std.debug.assert(!pos.closed);
        ptr.store(.{ .closed = false, .value = pos.value +% @as(u31, @intCast(n)) }, .release);
    }

    pub fn close(self: *SnapshotDecodeRing, comptime side: Side) void {
        const ptr = if (side == .reader) &self.head else &self.tail;
        const pos = ptr.raw;
        std.debug.assert(!pos.closed);
        ptr.store(.{ .closed = true, .value = pos.value }, .release);
    }
};
