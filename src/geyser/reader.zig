const std = @import("std");
const sig = @import("sig");

const GeyserReader = sig.geyser.GeyserReader;

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    var cli_args = try std.process.argsWithAllocator(allocator);
    defer cli_args.deinit();

    _ = cli_args.skip();
    const maybe_pipe_path = cli_args.next();
    const pipe_path = blk: {
        if (maybe_pipe_path) |pipe_path| {
            std.debug.print("pipe path: {s}\n", .{pipe_path});
            break :blk pipe_path;
        } else {
            std.debug.print("Usage: geyser-reader <pipe-path>\n", .{});
            return error.InvalidUsage;
        }
    };

    var reader = try GeyserReader.init(allocator, pipe_path, null, .{
        .io_buf_len = 1 << 30,
        .bincode_buf_len = 1 << 30,
    });
    defer reader.deinit();

    std.debug.print("reading from pipe...\n", .{});
    while (true) {
        const n, const payload = try reader.readPayload();
        defer reader.resetMemory();

        std.debug.print("read {} bytes\n", .{n});
        std.mem.doNotOptimizeAway(payload);
    }
}
