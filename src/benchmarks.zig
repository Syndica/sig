const std = @import("std");
const cli = @import("cli");
const builtin = @import("builtin");
const sig = @import("sig.zig");
const pt = @import("prettytable");
const math = std.math;

const Decl = std.builtin.Type.Declaration;
const Duration = sig.time.Duration;
const accounts_db = sig.accounts_db;
const SNAPSHOT_DIR = @import("accountsdb/db.zig").BenchmarkAccountsDBSnapshotLoad.SNAPSHOT_DIR_PATH;

pub const Resolution = enum {
    nanos,
    micros,
    millis,
    seconds,

    pub fn convertDuration(self: Resolution, duration: Duration) u64 {
        return switch (self) {
            .nanos => duration.asNanos(),
            .micros => duration.asMicros(),
            .millis => duration.asMillis(),
            .seconds => duration.asSecs(),
        };
    }
};

const Filter = enum {
    accounts_db,
    accounts_db_readwrite,
    accounts_db_snapshot, // expensive
    bincode,
    crypto,
    geyser,
    gossip,
    ledger,
    socket_utils,
    swissmap,
    sync,
    zksdk,
};

const Benchmark = struct {
    type: type,
    resolution: Resolution,
};

fn usageText() []const u8 {
    var text: []const u8 = "Available Benchmarks:\n";
    const filters = @typeInfo(Filter).@"enum".fields;
    inline for (filters, 0..) |field, i| {
        text = text ++ " " ++ field.name;
        if (i != filters.len - 1) text = text ++ "\n";
    }
    return text;
}

const benchmarks: std.EnumMap(Filter, []const Benchmark) = .init(.{
    .sync = &.{.{
        .type = @import("sync/channel.zig").BenchmarkChannel,
        .resolution = .nanos,
    }},
    .socket_utils = &.{.{
        .type = @import("net/socket_utils.zig").BenchmarkPacketProcessing,
        .resolution = .millis,
    }},
    .gossip = &.{
        .{
            .type = @import("gossip/service.zig").BenchmarkGossipServiceGeneral,
            .resolution = .nanos,
        },
        .{
            .type = @import("gossip/service.zig").BenchmarkGossipServicePullRequests,
            .resolution = .nanos,
        },
    },
    .crypto = &.{
        .{
            .type = @import("crypto/benchmark.zig").BenchmarkSigVerify,
            .resolution = .micros,
        },
        .{
            .type = @import("crypto/benchmark.zig").BenchmarkPohHash,
            .resolution = .nanos,
        },
    },
    .ledger = &.{
        .{
            .type = @import("ledger/benchmarks.zig").BenchmarkLedger,
            .resolution = .nanos,
        },
        .{
            .type = @import("ledger/benchmarks.zig").BenchmarkLedgerSlow,
            .resolution = .millis,
        },
    },
    .swissmap = &.{.{
        .type = @import("accountsdb/swiss_map.zig").BenchmarkSwissMap,
        .resolution = .nanos,
    }},
    .bincode = &.{.{
        .type = @import("bincode/benchmarks.zig").BenchmarkEntry,
        .resolution = .nanos,
    }},
    .zksdk = &.{.{
        .type = @import("zksdk/benchmarks.zig").Benchmark,
        .resolution = .micros,
    }},
});

const Cmd = struct {
    filter: ?Filter,
    debug: bool,
    collect_metrics: bool,
    run_expensive_benchmarks: bool,
    force_fresh_state: bool,
    timeout: u64,

    const cmd_info: cli.CommandInfo(@This()) = .{
        .help = .{
            .short = "Run benchmarks to profile parts of the Sig codebase",
            .long = usageText(),
        },
        .sub = .{
            .filter = .{
                .kind = .positional,
                .name_override = "filter",
                .alias = .none,
                .default_value = null,
                .config = {},
                .help = "chooses which benchmarks to run",
            },
            .debug = .{
                .kind = .named,
                .name_override = "debug",
                .alias = .d,
                .default_value = false,
                .config = {},
                .help = "enable debug logging",
            },
            .collect_metrics = .{
                .kind = .named,
                .name_override = "metrics",
                .alias = .m,
                .default_value = false,
                .config = {},
                .help = "collect more metrics",
            },
            .run_expensive_benchmarks = .{
                .kind = .named,
                .name_override = "run-expensive",
                .alias = .e,
                .default_value = false,
                .config = {},
                .help = "run expensive benchmarks",
            },
            .force_fresh_state = .{
                .kind = .named,
                .name_override = "fresh",
                .alias = .f,
                .default_value = false,
                .config = {},
                .help = "forces fresh database state",
            },
            .timeout = .{
                .kind = .named,
                .name_override = "timeout",
                .alias = .t,
                .default_value = 5,
                .config = {},
                .help = "configures the maximum time per benchmark (in seconds)",
            },
        },
    };
};

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = if (builtin.mode == .Debug) gpa_state.allocator() else std.heap.smp_allocator;

    const logger = sig.trace.direct_print.logger("benchmarks", .info);

    const argv = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, argv);

    const parser = cli.Parser(Cmd, Cmd.cmd_info);
    const cmd = try parser.parse(
        gpa,
        "benchmark",
        std.io.tty.detectConfig(std.io.getStdOut()),
        std.io.getStdOut().writer(),
        argv[1..],
    ) orelse return;
    defer parser.free(gpa, cmd);

    if (cmd.collect_metrics) logger.info().log("collecting metrics");

    const filter = cmd.filter orelse {
        logger.err().log("no filter chosen! please select one");
        return;
    };

    logger.info().logf("running benchmark with filter: {s}", .{@tagName(filter)});
    if (cmd.force_fresh_state) {
        logger.info().log("forcing fresh state for expensive benchmarks");
    }
    if (builtin.mode == .Debug) {
        logger.warn().log("running benchmark in Debug mode");
    }
    const max_time_per_bench = Duration.fromSecs(cmd.timeout);

    var metrics: std.ArrayListUnmanaged(Metric) = .empty;
    defer metrics.deinit(gpa);

    switch (filter) {
        inline else => |tag| {
            const benches = benchmarks.get(tag).?;
            inline for (benches) |bench| {
                try benchmark(
                    gpa,
                    logger,
                    bench.type,
                    max_time_per_bench,
                    bench.resolution,
                    &metrics,
                );
            }
        },
        .geyser => {
            // NOTE: we dont support CSV output on this method so all results are printed as debug
            logger.debug().log("Geyser Streaming Benchmark:");
            try @import("geyser/lib.zig").benchmark.runBenchmark(.from(logger));
        },
        .accounts_db,
        .accounts_db_snapshot,
        .accounts_db_readwrite,
        => |t| {
            const run_all_benchmarks: bool = t == .accounts_db;
            const run_snapshot: bool = t == .accounts_db_snapshot or run_all_benchmarks;
            const run_readwrite: bool = t == .accounts_db_readwrite or run_all_benchmarks;

            if (run_snapshot and !cmd.run_expensive_benchmarks) {
                logger.err().log("use '-e' to run accounts_db_snapshot benchmark");
                return;
            }

            if (run_snapshot) snapshot_benchmark: {
                // NOTE: not a very robust check, but we don't need anything crazy here.
                const snapshot_exists = std.meta.isError(std.fs.cwd().access(SNAPSHOT_DIR, .{}));
                if (cmd.force_fresh_state or !snapshot_exists) {
                    // download a new snapshot
                    if (snapshot_exists) {
                        // delete existing snapshot dir
                        logger.info().log("deleting snapshot dir...");
                        std.fs.cwd().deleteTree(SNAPSHOT_DIR) catch |err| {
                            logger.err().logf("failed to delete snapshot dir ('{s}'): {}", .{
                                SNAPSHOT_DIR,
                                err,
                            });
                            return err;
                        };
                    }

                    // create fresh snapshot dir
                    var snapshot_dir = try std.fs.cwd().makeOpenPath(
                        SNAPSHOT_DIR,
                        .{ .iterate = true },
                    );
                    defer snapshot_dir.close();

                    // start gossip
                    const gossip_service = try sig.gossip.helpers.initGossipFromCluster(
                        gpa,
                        .from(logger),
                        .testnet, // TODO: support other clusters
                        8006,
                    );
                    defer {
                        gossip_service.shutdown();
                        gossip_service.deinit();
                        gpa.destroy(gossip_service);
                    }
                    try gossip_service.start(.{});

                    // download and unpack snapshot
                    const snapshot_manifests, //
                    _ //
                    = sig.accounts_db.snapshot.download.getOrDownloadAndUnpackSnapshot(
                        gpa,
                        .from(logger),
                        SNAPSHOT_DIR,
                        .{
                            .gossip_service = gossip_service,
                            .force_new_snapshot_download = true,
                            .max_number_of_download_attempts = 50,
                            .min_snapshot_download_speed_mbs = 10,
                            .download_timeout = Duration.fromMinutes(5),
                        },
                    ) catch |err| {
                        switch (err) {
                            error.UnableToDownloadSnapshot => {
                                logger.err().log(
                                    "unable to download snapshot, skipping benchmark...",
                                );
                                break :snapshot_benchmark;
                            },
                            else => return err,
                        }
                    };
                    defer snapshot_manifests.deinit(gpa);
                }

                try benchmark(
                    gpa,
                    logger,
                    @import("accountsdb/db.zig").BenchmarkAccountsDBSnapshotLoad,
                    max_time_per_bench,
                    .millis,
                    &metrics,
                );
            }

            if (run_readwrite) {
                try benchmark(
                    gpa,
                    logger,
                    @import("accountsdb/db.zig").BenchmarkAccountsDB,
                    max_time_per_bench,
                    .millis,
                    &metrics,
                );
            }
        },
    }

    if (cmd.collect_metrics) {
        try saveMetricsJson(
            metrics.items,
            "results/output.json",
        );
    }
}

pub fn benchmark(
    allocator: std.mem.Allocator,
    logger: sig.trace.Logger("benchmarks"),
    comptime B: type,
    max_time_per_benchmark: Duration,
    time_unit: Resolution,
    metrics: *std.ArrayListUnmanaged(Metric),
) !void {
    const has_inputs = @hasDecl(B, "inputs");
    const inputs = if (has_inputs) B.inputs else [_]void{{}};

    const functions = comptime blk: {
        var res: []const Decl = &[_]Decl{};
        for (@typeInfo(B).@"struct".decls) |decl| {
            if (@typeInfo(@TypeOf(@field(B, decl.name))) != .@"fn")
                continue;
            res = res ++ [_]Decl{decl};
        }
        break :blk res;
    };
    if (functions.len == 0) @compileError("No benchmarks to run.");

    const results_directory = try std.fs.cwd().makeOpenPath(sig.BENCHMARK_RESULTS_DIR, .{});
    results_directory.makeDir(B.name) catch |err| {
        switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        }
    };

    inline for (functions) |decl| {
        const averages_file_name = B.name ++ "/" ++ decl.name ++ ".csv";
        const averages_file = try results_directory.createFile(
            averages_file_name,
            .{ .read = true },
        );
        defer averages_file.close();
        const averages_writer = averages_file.writer();
        logger.debug().logf("writing benchmark results to {s}", .{averages_file_name});

        const runtimes_file_name = B.name ++ "/" ++ decl.name ++ "_runtimes.csv";
        const runtimes_file = try results_directory.createFile(
            runtimes_file_name,
            .{ .read = true },
        );
        defer runtimes_file.close();
        const runtimes_writer = runtimes_file.writer();

        inline for (inputs, 0..) |input, i| {
            const input_name = if (has_inputs) input.name else "no input";
            const bench_function = @field(B, decl.name);
            logger.debug().logf(
                "benchmarking input: {d}/{d}: {s}",
                .{ i, inputs.len - 1, input_name },
            );

            const info = @typeInfo(@TypeOf(bench_function)).@"fn";
            const ResultType = @typeInfo(info.return_type.?).error_union.payload;
            const needs_time_unit = info.params.len > 0 and info.params[0].type.? == Resolution;
            const time_argument = if (needs_time_unit) .{time_unit} else .{};
            const other_argument = if (@TypeOf(input) != void) .{input} else .{};
            const arguments = time_argument ++ other_argument;

            const RuntimeType = switch (ResultType) {
                Duration => struct { result: u64 },
                else => ResultType,
            };

            var results: std.MultiArrayList(RuntimeType) = .{};
            defer results.deinit(allocator);

            var min: u64 = math.maxInt(u64);
            var max: u64 = 0;
            var sum: u64 = 0;

            const runtime_info = @typeInfo(RuntimeType).@"struct";
            var sum_s: RuntimeType = undefined;
            var min_s: RuntimeType = undefined;
            var max_s: RuntimeType = undefined;

            var benchmark_time = sig.time.Timer.start();
            var ran_out_of_time = false;
            var iterations: u64 = 0;

            while (b: {
                // if we haven't gone past the minimum iteration count, just continue no matter the time.
                if (iterations <= B.min_iterations) break :b true;
                // if we've surpassed the maximum iteration count, stop running.
                if (iterations > B.max_iterations) break :b false;
                // if we're somewhere in the middle, we continue running if we haven't run out of time.
                break :b !ran_out_of_time;
            }) : (iterations += 1) {
                switch (ResultType) {
                    Duration => {
                        const duration = try @call(.never_inline, bench_function, arguments);
                        std.mem.doNotOptimizeAway(duration);
                        const runtime = time_unit.convertDuration(duration);
                        min = @min(runtime, min);
                        max = @max(runtime, max);
                        sum += runtime;
                        try results.append(allocator, .{ .result = runtime });
                    },
                    else => {
                        const result = try @call(.never_inline, bench_function, arguments);
                        std.mem.doNotOptimizeAway(result);
                        try results.append(allocator, result);

                        if (iterations == 0) {
                            min_s = result;
                            max_s = result;
                            sum_s = result;
                        } else {
                            inline for (runtime_info.fields) |field| {
                                const f_max = @field(max_s, field.name);
                                const f_min = @field(min_s, field.name);
                                const result_field = @field(result, field.name);
                                @field(max_s, field.name) = @max(result_field, f_max);
                                @field(min_s, field.name) = @min(result_field, f_min);
                                @field(sum_s, field.name) += result_field;
                            }
                        }
                    },
                }
                // we've run out of time if the benchmark has been running for longer than `max_time_per_benchmark`
                ran_out_of_time = benchmark_time.read().gt(max_time_per_benchmark);
            }
            if (ran_out_of_time) logger.debug().log("ran out of time...");

            // print all results, eg:
            //
            // benchmark, result
            // read_write (100k) (read), 1, 2, 3, 4,
            // read_write (100k) (write), 1, 2, 3, 4,
            switch (ResultType) {
                Duration => {
                    try runtimes_writer.print("{s}({s}), results", .{ decl.name, input_name });
                    for (results.items(.result), 0..) |runtime, j| {
                        if (j != 0) try runtimes_writer.print(", ", .{});
                        try runtimes_writer.print("{d}", .{runtime});
                    }
                    try runtimes_writer.print("\n", .{});
                },
                else => {
                    inline for (runtime_info.fields, 0..) |field, j| {
                        try runtimes_writer.print(
                            "{s}({s}) ({s}), ",
                            .{ decl.name, input_name, field.name },
                        );
                        for (results.items(@enumFromInt(j)), 0..) |runtime, k| {
                            if (k != 0) try runtimes_writer.print(", ", .{});
                            try runtimes_writer.print("{d}", .{runtime});
                        }
                        try runtimes_writer.print("\n", .{});
                    }
                },
            }

            // print aggregated results, eg:
            //
            // benchmark, read_min, read_max, read_mean, read_variance, write_min, write_max, write_mean, write_variance
            // read_write (100k), 1, 2, 3, 4, 1, 2, 3, 4
            // read_write (200k), 1, 2, 3, 4, 1, 2, 3, 4
            switch (ResultType) {
                Duration => {
                    // print column headers
                    if (i == 0) {
                        try averages_writer.print("{s}, min, max, mean, std_dev\n", .{decl.name});
                    }
                    const mean = sum / iterations;
                    var variance: u64 = 0;
                    for (results.items(.result)) |runtime| {
                        const d = if (runtime > mean) runtime - mean else mean - runtime;
                        variance +|= d * d;
                    }
                    variance /= iterations;
                    const std_dev = std.math.sqrt(variance);

                    // print column results
                    try averages_writer.print(
                        "{s}, {d}, {d}, {d}, {d}\n",
                        .{ input_name, min, max, mean, std_dev },
                    );

                    // collect the metric
                    try metrics.append(allocator, .{
                        .name = decl.name ++ "(" ++ input_name ++ ")",
                        .unit = time_unit,
                        .value = max,
                    });
                },
                else => {
                    // print column headers
                    if (i == 0) {
                        try averages_writer.print("{s}, ", .{decl.name});
                        inline for (runtime_info.fields, 0..) |field, j| {
                            if (j == runtime_info.fields.len - 1) {
                                // dont print trailing comma
                                try averages_writer.print(
                                    "{s}_min, {s}_max, {s}_mean, {s}_std_dev",
                                    .{ field.name, field.name, field.name, field.name },
                                );
                            } else {
                                try averages_writer.print(
                                    "{s}_min, {s}_max, {s}_mean, {s}_std_dev, ",
                                    .{ field.name, field.name, field.name, field.name },
                                );
                            }
                        }
                        try averages_writer.print("\n", .{});
                    }

                    // print results
                    try averages_writer.print("{s}, ", .{input_name});
                    inline for (runtime_info.fields, 0..) |field, j| {
                        const f_max = @field(max_s, field.name);
                        const f_min = @field(min_s, field.name);
                        const f_sum = @field(sum_s, field.name);
                        const T = @TypeOf(f_sum);
                        const f_mean = f_sum / iterations;

                        var f_variance: T = 0;
                        for (results.items(@enumFromInt(j))) |f_runtime| {
                            const d = if (f_runtime > f_mean)
                                f_runtime - f_mean
                            else
                                f_mean - f_runtime;
                            f_variance += d * d;
                        }
                        f_variance /= iterations;
                        const f_std_dev = std.math.sqrt(f_variance);

                        if (j == runtime_info.fields.len - 1) {
                            // dont print trailing comma
                            try averages_writer.print(
                                "{d}, {d}, {any}, {any}",
                                .{ f_min, f_max, f_mean, f_std_dev },
                            );
                        } else {
                            try averages_writer.print(
                                "{d}, {d}, {any}, {any}, ",
                                .{ f_min, f_max, f_mean, f_std_dev },
                            );
                        }

                        // collect the metric
                        const name = decl.name ++ "(" ++ input_name ++ ")_" ++ field.name;
                        try metrics.append(allocator, .{
                            .name = name,
                            .unit = time_unit,
                            .value = f_max,
                        });
                    }
                    try averages_writer.print("\n", .{});
                },
            }
        }
    }

    // print the results in a formatted table
    inline for (functions) |decl| {
        const average_file_name = B.name ++ "/" ++ decl.name ++ ".csv";
        const average_file = try results_directory.openFile(average_file_name, .{});
        defer average_file.close();

        var table = pt.Table.init(allocator);
        defer table.deinit();

        var read_buf: [1024 * 1024]u8 = undefined;
        try table.readFrom(average_file.reader(), &read_buf, ",", true);

        const bench_function = @field(B, decl.name);
        const info = @typeInfo(@TypeOf(bench_function)).@"fn";
        const ResultType = @typeInfo(info.return_type.?).error_union.payload;
        const RuntimeType = switch (ResultType) {
            Duration => struct { result: u64 },
            else => ResultType,
        };
        const runtime_info = @typeInfo(RuntimeType).@"struct";

        if (ResultType == Duration) {
            // direct print works ok in this case
            try table.printstd();
        } else {
            // organize the data into a table:
            // field_name,              field_name2
            // min, max, mean, std_dev  min, max, mean, std_dev
            const stat_titles: [4][]const u8 = .{ "min", "max", "mean", "std_dev" };
            const per_field_column_count = stat_titles.len;
            // first column is the field names
            const field_name_data = try allocator.alloc(
                []const u8,
                1 + per_field_column_count * runtime_info.fields.len,
            );
            field_name_data[0] = ""; // benchmark name is blank
            const stat_data_row = try allocator.alloc(
                []const u8,
                1 + per_field_column_count * runtime_info.fields.len,
            );
            stat_data_row[0] = decl.name;
            var i: u64 = 1;
            var k: u64 = 1;

            inline for (runtime_info.fields) |field| {
                field_name_data[i] = field.name;
                i += 1;
                for (0..per_field_column_count - 1) |_| {
                    field_name_data[i] = "";
                    i += 1;
                }
                for (0..per_field_column_count) |j| {
                    stat_data_row[k] = stat_titles[j];
                    k += 1;
                }
            }

            var field_names_cells: std.ArrayList(pt.Cell) = .empty;
            var stats_cells: std.ArrayList(pt.Cell) = .empty;
            for (0..i) |cell_i| {
                try field_names_cells.append(
                    allocator,
                    try pt.Cell.init(allocator, field_name_data[cell_i]),
                );
                try stats_cells.append(
                    allocator,
                    try pt.Cell.init(allocator, stat_data_row[cell_i]),
                );
            }
            const field_name_row = pt.Row.init(allocator, field_names_cells);
            const stats_row = pt.Row.init(allocator, stats_cells);

            table.titles = field_name_row;
            try table.rows.insert(allocator, 0, stats_row);
            try table.printstd();
        }
    }
}

const Metric = struct {
    name: []const u8,
    unit: Resolution,
    value: u64,
};

pub fn saveMetricsJson(metrics: []const Metric, output_path: []const u8) !void {
    const output_file = try std.fs.cwd().createFile(output_path, .{});
    defer output_file.close();
    try std.json.stringify(metrics, .{}, output_file.writer());
}
