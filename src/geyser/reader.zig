const std = @import("std");
const sig = @import("sig");

const MEASURE_RATE = sig.time.Duration.fromSecs(5);

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    var cli_args = try std.process.argsWithAllocator(allocator);
    defer cli_args.deinit();

    _ = cli_args.skip();
    const maybe_pipe_path = cli_args.next();
    const pipe_path = blk: {
        if (maybe_pipe_path) |pipe_path| {
            break :blk pipe_path;
        } else {
            break :blk sig.VALIDATOR_DIR ++ "geyser.pipe";
        }
    };
    std.debug.print("using pipe path: {s}\n", .{pipe_path});

    var exit = std.atomic.Value(bool).init(false);
    try sig.geyser.core.streamReader(
        allocator,
        &exit,
        pipe_path,
        MEASURE_RATE,
        .{
            .io_buf_len = 1 << 30,
            .bincode_buf_len = 1 << 30,
        },
    );
}
