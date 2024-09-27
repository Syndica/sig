const std = @import("std");
const sig = @import("sig");
const cli = @import("zig-cli");

pub const Config = struct {
    pipe_path: []const u8 = sig.VALIDATOR_DIR ++ "geyser.pipe",
    measure_rate_secs: u64 = 5,
};

var default_config = Config{};
const config = &default_config;

var pipe_path_option = cli.Option{
    .long_name = "geyser-pipe-path",
    .help = "path to the geyser pipe",
    .value_ref = cli.mkRef(&config.pipe_path),
    .required = false,
    .value_name = "geyser_pipe_path",
};

var measure_rate_option = cli.Option{
    .long_name = "measure-rate",
    .help = "rate at which to measure reads",
    .value_ref = cli.mkRef(&config.measure_rate_secs),
    .required = false,
    .value_name = "measure_rate_secs",
};

const cli_app = cli.App{ .version = "0.0.19", .author = "Syndica & Contributors", .command = .{
    .name = "geyser",
    .description = .{ .one_line = "read from a geyser stream" },
    .target = .{
        .subcommands = &.{
            &cli.Command{
                .name = "benchmark",
                .description = .{ .one_line = "benchmarks reads from a geyser pipe" },
                .target = .{ .action = .{ .exec = benchmark } },
                .options = &.{
                    &pipe_path_option,
                    &measure_rate_option,
                },
            },
            &cli.Command{
                .name = "csv",
                .description = .{ .one_line = "dumps accounts into a csv" },
                .target = .{ .action = .{ .exec = csvDump } },
                .options = &.{
                    &pipe_path_option,
                },
            },
        },
    },
} };

pub fn main() !void {
    try cli.run(&cli_app, std.heap.page_allocator);
}

pub fn csvDump() !void {
    const allocator = std.heap.c_allocator;

    const pipe_path = config.pipe_path;
    std.debug.print("using pipe path: {s}\n", .{pipe_path});

    const exit = try allocator.create(std.atomic.Value(bool));
    defer allocator.destroy(exit);
    exit.* = std.atomic.Value(bool).init(false);

    var reader = try sig.geyser.GeyserReader.init(allocator, pipe_path, exit, .{
        // TODO: make these configurable
    });
    defer reader.deinit();

    // csv file to dump to
    const dump_csv_path = try std.fmt.allocPrint(
        allocator,
        "{s}{s}",
        .{ sig.VALIDATOR_DIR, "accounts.csv" },
    );
    defer allocator.free(dump_csv_path);
    std.debug.print("dumping to csv: {s}\n", .{dump_csv_path});

    const csv_file = try std.fs.cwd().createFile(dump_csv_path, .{});
    defer csv_file.close();

    // setup IO thread to write to csv
    var io_channel = sig.sync.Channel([]u8).init(allocator, 10_000);
    defer io_channel.deinit();

    const recycle_fba = try allocator.create(sig.utils.allocators.RecycleFBA(.{ .thread_safe = true }));
    recycle_fba.* = try sig.utils.allocators.RecycleFBA(.{ .thread_safe = true }).init(allocator, 1 << 30);

    const io_handle = try std.Thread.spawn(.{}, csvDumpIOWriter, .{ csv_file, io_channel, recycle_fba });
    defer io_handle.join();

    // read from geyser
    while (true) {
        _, const payload = try reader.readPayload();
        defer reader.resetMemory();

        if (std.meta.activeTag(payload) != .AccountPayloadV1) {
            std.debug.print("unexpected payload type: {}\n", .{std.meta.activeTag(payload)});
            continue;
        }

        // format to csv
        const account_payload = payload.AccountPayloadV1;
        var fmt_count: u64 = 0;
        for (account_payload.accounts) |account| {
            fmt_count += 120 + 5 * account.data.len;
        }

        var csv_string = try recycle_fba.allocator().alloc(u8, fmt_count);
        var offset: u64 = 0;

        for (account_payload.accounts, account_payload.pubkeys) |account, pubkey| {
            const x = try std.fmt.bufPrint(csv_string[offset..], "{s};{s};{any}\n", .{ pubkey, account.owner, account.data });
            offset += x.len;
        }

        // send to be written
        try io_channel.send(csv_string[0..offset]);
    }
}

pub fn csvDumpIOWriter(
    csv_file: std.fs.File,
    io_channel: *sig.sync.Channel([]u8),
    recycle_fba: *sig.utils.allocators.RecycleFBA(.{ .thread_safe = true }),
) !void {
    var payloads_written: u64 = 0;
    while (true) {
        if (io_channel.receive()) |csv_row| {
            try csv_file.writeAll(csv_row);
            recycle_fba.allocator().free(csv_row);

            payloads_written += 1;
            if (payloads_written % 1000 == 0) {
                std.debug.print("payloads written: {}\n", .{payloads_written});
            }
        }
    }
}

pub fn benchmark() !void {
    const allocator = std.heap.c_allocator;

    const pipe_path = config.pipe_path;
    std.debug.print("using pipe path: {s}\n", .{pipe_path});

    const exit = try allocator.create(std.atomic.Value(bool));
    defer allocator.destroy(exit);
    exit.* = std.atomic.Value(bool).init(false);

    try sig.geyser.core.streamReader(
        exit,
        pipe_path,
        sig.time.Duration.fromSecs(config.measure_rate_secs),
        .{
            .io_buf_len = 1 << 30,
            .bincode_buf_len = 1 << 30,
        },
    );
}
