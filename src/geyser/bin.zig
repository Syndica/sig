const std = @import("std");
const sig = @import("sig");
const cli = @import("zig-cli");

pub const Config = struct {
    pipe_path: []const u8 = sig.VALIDATOR_DIR ++ "geyser.pipe",
    measure_rate_secs: u64 = 5,
    geyser_bincode_buf_len: u64 = 1 << 29,
    geyser_io_buf_len: u64 = 1 << 29,
    owner_accounts: [][]const u8 = &.{},
};

var default_config = Config{};
const config = &default_config;

var owner_accounts_option = cli.Option{
    .long_name = "owner-accounts",
    .short_alias = 'o',
    .help = "list of owner accounts to filter to csv",
    .value_ref = cli.mkRef(&config.owner_accounts),
    .required = false,
    .value_name = "owner_accounts",
};

var geyser_bincode_buf_len_option = cli.Option{
    .long_name = "geyser-bincode-buf-len",
    .help = "size of the bincode buffer",
    .value_ref = cli.mkRef(&config.geyser_bincode_buf_len),
    .required = false,
    .value_name = "geyser_bincode_buf_len",
};

var geyser_io_buf_len_option = cli.Option{
    .long_name = "geyser-io-buf-len",
    .help = "size of the io buffer",
    .value_ref = cli.mkRef(&config.geyser_io_buf_len),
    .required = false,
    .value_name = "geyser_io_buf_len",
};

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
                    &geyser_bincode_buf_len_option,
                    &geyser_io_buf_len_option,
                    &owner_accounts_option,
                },
            },
        },
    },
} };

pub fn main() !void {
    try cli.run(&cli_app, std.heap.page_allocator);
}

pub fn getOwnerFilters(allocator: std.mem.Allocator) !?std.AutoArrayHashMap(sig.core.Pubkey, void) {
    const owner_accounts_str = config.owner_accounts;
    if (owner_accounts_str.len == 0) {
        return null;
    }

    var owner_pubkeys = std.AutoArrayHashMap(sig.core.Pubkey, void).init(allocator);
    try owner_pubkeys.ensureTotalCapacity(@intCast(owner_accounts_str.len));
    for (owner_accounts_str) |owner_str| {
        const owner_pubkey = try sig.core.Pubkey.fromString(owner_str);
        owner_pubkeys.putAssumeCapacity(owner_pubkey, {});
    }

    return owner_pubkeys;
}

pub fn csvDump() !void {
    const allocator = std.heap.c_allocator;

    const metrics_thread = try sig.prometheus.spawnMetrics(allocator, 12355);
    metrics_thread.detach();
    std.debug.print("spawing metrics thread on port 12355\n", .{});

    const pipe_path = config.pipe_path;
    std.debug.print("using pipe path: {s}\n", .{pipe_path});

    // owner filters
    var maybe_owner_pubkeys = try getOwnerFilters(allocator);
    defer if (maybe_owner_pubkeys) |*owners| owners.deinit();
    if (maybe_owner_pubkeys) |owner_pubkeys| {
        std.debug.print("owner filters: {s}\n", .{owner_pubkeys.keys()});
    } else {
        std.debug.print("owner filters: none\n", .{});
    }

    // csv file to dump to
    const dump_csv_path = try std.fmt.allocPrint(
        allocator,
        "{s}{s}",
        .{ sig.VALIDATOR_DIR, "accounts.csv" },
    );
    defer allocator.free(dump_csv_path);

    const csv_file = try std.fs.cwd().createFile(dump_csv_path, .{});
    defer csv_file.close();

    std.debug.print("dumping to csv: {s}\n", .{dump_csv_path});

    // setup reader
    const exit = try allocator.create(std.atomic.Value(bool));
    defer allocator.destroy(exit);
    exit.* = std.atomic.Value(bool).init(false);

    var reader = try sig.geyser.GeyserReader.init(allocator, pipe_path, exit, .{
        .bincode_buf_len = config.geyser_bincode_buf_len,
        .io_buf_len = config.geyser_io_buf_len,
    });
    defer reader.deinit();

    // preallocate memory for csv rows
    const recycle_fba = try allocator.create(sig.utils.allocators.RecycleFBA(.{ .thread_safe = true }));
    recycle_fba.* = try sig.utils.allocators.RecycleFBA(.{ .thread_safe = true }).init(allocator, 1 << 32);
    defer {
        recycle_fba.deinit();
        allocator.destroy(recycle_fba);
    }

    // setup thread to write to csv
    var io_channel = try sig.sync.Channel([]u8).create(allocator);
    defer {
        io_channel.deinit();
        allocator.destroy(io_channel);
    }

    const io_handle = try std.Thread.spawn(.{}, csvDumpIOWriter, .{ exit, csv_file, io_channel, recycle_fba });
    defer io_handle.join();
    errdefer {
        exit.store(true, .release);
    }

    // start to read from geyser
    while (true) {
        _, const payload = try reader.readPayload();
        defer reader.resetMemory();

        if (std.meta.activeTag(payload) == .EndOfSnapshotLoading) {
            break;
        }

        switch (std.meta.activeTag(payload)) {
            .AccountPayloadV1 => {},
            .EndOfSnapshotLoading => {
                std.debug.print("recv end of snapshot loading signal\n", .{});
                exit.store(true, .release);
                break;
            },
        }

        // compute how much memory we need for the rows
        const account_payload = payload.AccountPayloadV1;
        var fmt_count: u64 = 0;
        for (account_payload.accounts) |account| {
            // only dump accounts that match owner filters
            if (maybe_owner_pubkeys) |owners| {
                if (!owners.contains(account.owner)) {
                    continue;
                }
            }
            fmt_count += 120 + 5 * account.data.len;
        }

        var csv_string = try recycle_fba.allocator().alloc(u8, fmt_count);
        var offset: u64 = 0;

        // write the rows
        for (account_payload.accounts, account_payload.pubkeys) |account, pubkey| {
            // only dump accounts that match owner filters
            if (maybe_owner_pubkeys) |owners| {
                if (!owners.contains(account.owner)) {
                    continue;
                }
            }
            const x = try std.fmt.bufPrint(csv_string[offset..], "{d};{s};{s};{any}\n", .{ account_payload.slot, pubkey, account.owner, account.data });
            offset += x.len;
        }

        // send for io writes
        try io_channel.send(csv_string[0..offset]);
    }

    std.debug.print("\ncsv dump done!\n", .{});
}

pub fn csvDumpIOWriter(
    exit: *std.atomic.Value(bool),
    csv_file: std.fs.File,
    io_channel: *sig.sync.Channel([]u8),
    recycle_fba: *sig.utils.allocators.RecycleFBA(.{ .thread_safe = true }),
) !void {
    const total_payloads_estimate: u64 = 405_721;
    var payloads_written: u64 = 0;
    var timer = try sig.time.Timer.start();

    while (!exit.load(.acquire)) {
        while (io_channel.receive()) |csv_row| {
            // write to file
            try csv_file.writeAll(csv_row);
            // recycle memory to be re-used
            recycle_fba.allocator().free(csv_row);

            payloads_written += 1;
            if (payloads_written == 1) {
                // start time estimate on first payload written
                timer.reset();
            }
            if (payloads_written % 1_000 == 0 or total_payloads_estimate - payloads_written < 1_000) {
                sig.time.estimate.printTimeEstimateStd(
                    &timer,
                    total_payloads_estimate,
                    payloads_written,
                    "dumping accounts to csv",
                    null,
                );
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
        allocator,
        exit,
        pipe_path,
        sig.time.Duration.fromSecs(config.measure_rate_secs),
        .{
            .io_buf_len = 1 << 30,
            .bincode_buf_len = 1 << 30,
        },
    );
}