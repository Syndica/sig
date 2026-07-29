const builtin = @import("builtin");
const std = @import("std");
const sig = @import("sig");
const cli = @import("cli");

const servePrometheus = sig.prometheus.servePrometheus;
const globalRegistry = sig.prometheus.globalRegistry;

const Cmd = struct {
    subcmd: ?union(enum) {
        benchmark: Benchmark,
        csv: Csv,
    },

    const cmd_info: cli.CommandInfo(@This()) = .{
        .help = .{
            .short = "read from a geyser stream",
            .long = null,
        },
        .sub = .{
            .subcmd = .{
                .benchmark = Benchmark.cmd_info,
                .csv = Csv.cmd_info,
            },
        },
    };

    const pipe_path_arg: cli.ArgumentInfo([]const u8) = .{
        .kind = .named,
        .name_override = "geyser-pipe-path",
        .alias = .none,
        .default_value = sig.VALIDATOR_DIR ++ "geyser.pipe",
        .config = .string,
        .help = "path to the geyser pipe",
    };

    const Benchmark = struct {
        pipe_path: []const u8,
        measure_rate_secs: u64,

        const cmd_info: cli.CommandInfo(@This()) = .{
            .help = .{
                .short = "benchmarks reads from a geyser pipe",
                .long = null,
            },
            .sub = .{
                .pipe_path = pipe_path_arg,
                .measure_rate_secs = .{
                    .kind = .named,
                    .name_override = "measure-rate",
                    .alias = .none,
                    .default_value = 5,
                    .config = {},
                    .help = "rate at which to measure reads/s",
                },
            },
        };
    };

    const Csv = struct {
        pipe_path: []const u8,
        geyser_bincode_buf_len: u64,
        geyser_io_buf_len: u64,
        owner_accounts: []const []const u8,
        accounts: []const []const u8,
        csv_buf_len: u64,

        const cmd_info: cli.CommandInfo(@This()) = .{
            .help = .{
                .short = "dumps accounts into a csv",
                .long = null,
            },
            .sub = .{
                .pipe_path = pipe_path_arg,
                .geyser_bincode_buf_len = .{
                    .kind = .named,
                    .name_override = null,
                    .alias = .none,
                    .default_value = 1 << 29,
                    .config = {},
                    .help = "size of the bincode buffer",
                },
                .geyser_io_buf_len = .{
                    .kind = .named,
                    .name_override = null,
                    .alias = .none,
                    .default_value = 1 << 29,
                    .config = {},
                    .help = "size of the io buffer",
                },
                .csv_buf_len = .{
                    .kind = .named,
                    .name_override = null,
                    .alias = .none,
                    .default_value = 1 << 32,
                    .config = {},
                    .help = "size of the csv buffer",
                },
                .owner_accounts = .{
                    .kind = .named,
                    .name_override = "owner-account",
                    .alias = .o,
                    .default_value = &.{},
                    .config = .string,
                    .help = "list of owner accounts to filter to csv",
                },
                .accounts = .{
                    .kind = .named,
                    .name_override = "account",
                    .alias = .a,
                    .default_value = &.{},
                    .config = .string,
                    .help = "list of accounts to filter to csv",
                },
            },
        };
    };
};

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = if (builtin.mode == .Debug) gpa_state.allocator() else std.heap.c_allocator;

    const argv = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, argv);

    const parser = cli.Parser(Cmd, Cmd.cmd_info);
    const cmd = try parser.parse(
        gpa,
        "geyser",
        std.io.tty.detectConfig(.stdout()),
        std.fs.File.stdout().deprecatedWriter(),
        argv[1..],
    ) orelse return;
    defer parser.free(gpa, cmd);

    switch (cmd.subcmd orelse return error.MissingSubcommand) {
        .benchmark => |params| try benchmark(params),
        .csv => |params| try csvDump(gpa, params),
    }
}

pub fn getOwnerFilters(
    allocator: std.mem.Allocator,
    owner_accounts: []const []const u8,
) !std.AutoArrayHashMapUnmanaged(sig.core.Pubkey, void) {
    if (owner_accounts.len == 0) return .{};

    var owner_pubkeys: std.AutoArrayHashMapUnmanaged(sig.core.Pubkey, void) = .{};
    errdefer owner_pubkeys.deinit(allocator);

    try owner_pubkeys.ensureTotalCapacity(allocator, owner_accounts.len);
    for (owner_accounts) |owner_str| {
        const owner_pubkey = try sig.core.Pubkey.parseRuntime(owner_str);
        owner_pubkeys.putAssumeCapacity(owner_pubkey, {});
    }

    return owner_pubkeys;
}

pub fn getAccountFilters(
    allocator: std.mem.Allocator,
    accounts: []const []const u8,
) !std.AutoArrayHashMapUnmanaged(sig.core.Pubkey, void) {
    if (accounts.len == 0) return .{};

    var account_pubkeys: std.AutoArrayHashMapUnmanaged(sig.core.Pubkey, void) = .{};
    errdefer account_pubkeys.deinit(allocator);
    try account_pubkeys.ensureTotalCapacity(allocator, accounts.len);

    for (accounts) |account_str| {
        const account_pubkey = try sig.core.Pubkey.parseRuntime(account_str);
        account_pubkeys.putAssumeCapacity(account_pubkey, {});
    }

    return account_pubkeys;
}

pub fn csvDump(allocator: std.mem.Allocator, config: Cmd.Csv) !void {
    var std_logger = try sig.trace.ChannelPrintLogger.init(.{
        .allocator = std.heap.c_allocator,
        .max_buffer = 1 << 20,
    }, null);
    defer std_logger.deinit();

    const logger = std_logger.logger("csvDump", .debug);

    const metrics_thread = try std.Thread
        .spawn(.{}, servePrometheus, .{ allocator, globalRegistry(), 12355 });
    metrics_thread.detach();
    logger.info().log("spawing metrics thread on port 12355");

    const pipe_path = config.pipe_path;
    logger.info().logf("using pipe path: {s}", .{pipe_path});

    // owner filters
    var owner_pubkeys = try getOwnerFilters(allocator, config.owner_accounts);
    defer owner_pubkeys.deinit(allocator);
    logger.info().logf("owner filters: {any}", .{owner_pubkeys.keys()});

    // account filters
    var account_pubkeys = try getAccountFilters(allocator, config.accounts);
    defer account_pubkeys.deinit(allocator);
    logger.info().logf("account filters: {any}", .{account_pubkeys.keys()});

    // csv file to dump to
    const dump_csv_path = sig.VALIDATOR_DIR ++ "accounts.csv";
    const csv_file = try std.fs.cwd().createFile(dump_csv_path, .{});
    defer csv_file.close();
    logger.info().logf("dumping to csv: {s}", .{dump_csv_path});

    // setup reader
    var exit = std.atomic.Value(bool).init(false);

    var reader = try sig.geyser.GeyserReader.init(allocator, pipe_path, &exit, .{
        .bincode_buf_len = config.geyser_bincode_buf_len,
        .io_buf_len = config.geyser_io_buf_len,
    });
    defer reader.deinit();

    // preallocate memory for csv rows
    var recycle_fba = try sig.utils.allocators.RecycleFBA(.{ .thread_safe = true }).init(.{
        .records_allocator = allocator,
        .bytes_allocator = allocator,
    }, config.csv_buf_len);
    defer recycle_fba.deinit();

    // setup thread to write to csv
    var io_channel = try sig.sync.Channel([]const u8).create(allocator);
    defer {
        io_channel.deinit();
        allocator.destroy(io_channel);
    }

    const io_handle = try std.Thread.spawn(.{}, csvDumpIOWriter, .{
        &exit,
        csv_file,
        io_channel,
        &recycle_fba,
    });
    defer io_handle.join();
    errdefer exit.store(true, .release);

    // start to read from geyser
    while (true) {
        _, const payload = try reader.readPayload();
        defer reader.resetMemory();

        switch (payload) {
            .AccountPayloadV1 => {},
            .EndOfSnapshotLoading => {
                // NOTE: since accounts-db isnt hooked up
                // to the rest to the validator (svm, consensus, etc.),
                // valid account state is only from snapshots.
                //
                // we can safely exit here because no new accounts
                // are expected.
                logger.info().log("recv end of snapshot loading signal");
                exit.store(true, .monotonic);
                break;
            },
        }

        // compute how much memory we need for the rows
        const account_payload = payload.AccountPayloadV1;
        var fmt_count: u64 = 0;
        for (account_payload.accounts, account_payload.pubkeys) |account, pubkey| {
            // only dump accounts that match the filters
            if (!owner_pubkeys.contains(account.owner)) continue;
            if (!account_pubkeys.contains(pubkey)) continue;
            fmt_count += 120 + 5 * account.data.len();
        }

        const csv_string = try recycle_fba.allocator().alloc(u8, fmt_count);
        var offset: u64 = 0;

        // write the rows
        for (account_payload.accounts, account_payload.pubkeys) |account, pubkey| {
            // only dump accounts that match the filters
            if (!owner_pubkeys.contains(account.owner)) continue;
            if (!account_pubkeys.contains(pubkey)) continue;

            // build the csv row
            const x = try std.fmt.bufPrint(
                csv_string[offset..],
                "{d};{f};{f};{any}\n",
                .{ account_payload.slot, pubkey, account.owner, account.data },
            );
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
    io_channel: *sig.sync.Channel([]const u8),
    recycle_fba: *sig.utils.allocators.RecycleFBA(.{ .thread_safe = true }),
) !void {
    const total_payloads_estimate: u64 = 405_721;
    var payloads_written: u64 = 0;
    var timer = sig.time.Timer.start();
    errdefer exit.store(true, .monotonic);

    while (true) {
        io_channel.waitToReceive(.{ .unordered = exit }) catch break;

        while (io_channel.tryReceive()) |csv_row| {
            // write to file
            try csv_file.writeAll(csv_row);
            // recycle memory to be re-used
            recycle_fba.allocator().free(csv_row);

            payloads_written += 1;
            if (payloads_written == 1) {
                // start time estimate on first payload written
                timer.reset();
            }
            if (payloads_written % 1_000 == 0 or
                total_payloads_estimate - payloads_written < 1_000)
            {
                sig.time.estimate.printTimeEstimateStderr(
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

/// NOTE: this is different from the other benchmarks because it reads from a stream
/// without writing. This allows us to benchmark any type of data from the pipe.
pub fn benchmark(config: Cmd.Benchmark) !void {
    const allocator = std.heap.c_allocator;
    var std_logger = try sig.trace.ChannelPrintLogger.init(.{
        .allocator = allocator,
        .max_buffer = 1 << 15,
    }, null);
    defer std_logger.deinit();
    const logger = std_logger.logger("geyser.benchmark", .debug);

    const pipe_path = config.pipe_path;
    logger.info().logf("using pipe path: {s}", .{pipe_path});

    var exit = std.atomic.Value(bool).init(false);

    var reader = try sig.geyser.GeyserReader.init(
        allocator,
        pipe_path,
        &exit,
        .{
            .io_buf_len = 1 << 30,
            .bincode_buf_len = 1 << 30,
        },
    );
    defer reader.deinit();

    try sig.geyser.core.streamReader(
        &reader,
        .from(logger),
        &exit,
        sig.time.Duration.fromSecs(config.measure_rate_secs),
    );
}
