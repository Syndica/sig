const std = @import("std");
const start = @import("start");
const common = @import("common");
const Pair = common.net.Pair;

comptime {
    _ = start;
}

pub const name: []const u8 = "ping";
pub const _start = {};
pub const panic = start.panic;

pub const ReadWrite = struct {
    ping: *Pair,
};

pub fn main(writer: *std.io.Writer, rw: ReadWrite) !noreturn {
    const pair = rw.ping;
    pair.init(8000); // TODO: some sort of shared memory init

    try writer.print("sending one packet onto the send queue\n", .{});
    {
        var slice = try pair.send.getWritable();
        const ptr = slice.one();
        defer slice.markUsed(1);

        ptr.* = .{
            .addr = .initIp4(.{ 127, 0, 0, 1 }, 8000),
            .data = @splat(0xBB),
            .size = 58,
        };
    }

    try writer.print("waiting to hear it back\n", .{});
    {
        while (true) {
            var slice = pair.recv.getReadable() catch continue;
            const ptr = slice.one();
            defer slice.markUsed(1);

            try writer.print("packet got back: {}\n", .{ptr.size});
        }
    }

    try writer.print("ending and waiting\n", .{});
    while (true) {}
}
