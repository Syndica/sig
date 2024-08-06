const std = @import("std");
const sig = @import("sig");

const GeyserReader = sig.geyser.GeyserReader;
const MEASURE_RATE = sig.time.Duration.fromSecs(5);

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

    var bytes_read: usize = 0;
    var timer = try sig.time.Timer.start();

    std.debug.print("starting read loop...\n", .{});
    while (true) {
        const n, const payload = try reader.readPayload();
        defer reader.resetMemory();

        bytes_read += n;

        // std.debug.print("read {} bytes\n", .{n});
        std.mem.doNotOptimizeAway(payload);

        // mb/sec reading
        if (timer.read().asNanos() > MEASURE_RATE.asNanos()) {
            // print mb/sec
            const elapsed = timer.read().asSecs();
            const bytes_per_sec = bytes_read / elapsed;
            const mb_per_sec = bytes_per_sec / 1_000_000;
            const mb_per_sec_dec = (bytes_per_sec - mb_per_sec * 1_000_000) / (1_000_000 / 100);
            std.debug.print("read mb/sec: {}.{}\n", .{ mb_per_sec, mb_per_sec_dec });

            bytes_read = 0;
            timer.reset();
        }
    }
}
