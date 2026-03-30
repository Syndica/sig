const std = @import("std");

pub const net = @import("net.zig");
pub const crypto = @import("crypto.zig");
pub const solana = @import("solana.zig");
pub const shred = @import("shred.zig");
pub const gossip = @import("gossip.zig");
pub const ipc = @import("ipc.zig");
pub const linux = @import("linux.zig");

pub const test_data_dir = "../data/test-data/";

/// A type that wraps a slice so that it can print the items formatted.
/// `{f}` on a such a slice in `writer.print()` doesn't work for some reason...
pub fn FmtSlice(comptime T: type) type {
    return struct {
        slice: []const T,

        pub fn format(self: @This(), writer: *std.Io.Writer) !void {
            try writer.writeAll("{ ");
            for (self.slice, 0..) |*item, i| {
                try item.format(writer);
                if (i < self.slice.len - 1) try writer.writeAll(", ");
            }
            try writer.writeAll(" }");
        }
    };
}

pub fn fmtSlice(slice: anytype) FmtSlice(@TypeOf(slice[0])) {
    return .{ .slice = slice };
}
