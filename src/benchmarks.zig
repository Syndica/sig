const std = @import("std");
const cli = @import("cli");
const builtin = @import("builtin");
const sig = @import("sig.zig");
const pt = @import("prettytable");
const math = std.math;

const Decl = std.builtin.Type.Declaration;
const Duration = sig.time.Duration;

pub const Resolution = enum {
    nanos,
    millis,
    seconds,

    pub fn convertDuration(self: Resolution, duration: Duration) u64 {
        return switch (self) {
            .nanos => duration.asNanos(),
            .millis => duration.asMillis(),
            .seconds => duration.asSecs(),
        };
    }
};

const Filter = enum {
    all,
    // accounts_db,
    // accounts_db_readwrite,
    // accounts_db_snapshot, // expensive
    // bincode,
    // geyser,
    // gossip,
    // ledger,
    // swissmap,
    sync,
    // socket_utils,
};

const Benchmark = struct {
    type: type,
    resolution: Resolution,
};

fn usageText() []const u8 {
    var text =
        \\
    ;

    _ = &text;
    return text;
}

// fn exitWithUsage() noreturn {
//     var stdout = std.io.getStdOut().writer();
//     stdout.writeAll(
//         \\ benchmark name [options]
//         \\
//         \\ Available Benchmarks:
//         \\
//     ) catch @panic("failed to print usage");

//     inline for (std.meta.fields(Benchmark)) |field| {
//         stdout.print(
//             " {s}\n",
//             .{field.name},
//         ) catch @panic("failed to print usage");
//     }

//     stdout.writeAll(
//         \\
//         \\ Options:
//         \\  --help
//         \\    Prints this usage message
//         \\
//         \\  --metrics
//         \\    save benchmark results to results/output.json. default: false.
//         \\
//         \\  -e
//         \\    run expensive benchmarks. default: false.
//         \\
//         \\  -f
//         \\    force fresh state for expensive benchmarks. default: false.
//     ) catch @panic("failed to print usage");
//     std.posix.exit(1);
// }

const benchmarks: std.EnumMap(Filter, Benchmark) = .init(.{
    .all = null,
    .sync = .{
        .type = @import("sync/channel.zig").BenchmarkChannel,
        .resolution = .nanos,
    },
});

const Cmd = struct {
    filter: Filter,
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
                .default_value = .all,
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
                .alias = .none,
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

    var std_logger = sig.trace.DirectPrintLogger.init(
        gpa,
        .info, // NOTE: change to debug to see all logs
    );
    const logger = std_logger.logger();

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
    if (cmd.filter != .all) {
        logger.info().logf("running benchmark with filter: {s}", .{@tagName(cmd.filter)});
    }
    if (cmd.force_fresh_state) {
        logger.info().log("forcing fresh state for expensive benchmarks");
    }
    if (builtin.mode == .Debug) {
        logger.warn().log("running benchmark in Debug mode");
    }
    const max_time_per_bench = Duration.fromSecs(cmd.timeout);

    var metrics: std.ArrayListUnmanaged(Metric) = .empty;
    defer metrics.deinit(gpa);

    switch (cmd.filter) {
        .all => {},
        inline else => |tag| {
            const bench = benchmarks.get(tag).?;
            try benchmark(
                gpa,
                logger,
                bench.type,
                max_time_per_bench,
                bench.resolution,
                &metrics,
            );
        },
    }

    // if (filter == .swissmap or run_all_benchmarks) {
    //     try benchmark(
    //         allocator,
    //         logger,
    //         @import("accountsdb/swiss_map.zig").BenchmarkSwissMap,
    //         max_time_per_bench,
    //         .nanos,
    //         &maybe_metrics,
    //     );
    // }

    // if (std.mem.startsWith(u8, @tagName(filter), "accounts_db") or run_all_benchmarks) {
    //     var run_all = false;
    //     if (filter == .accounts_db or run_all_benchmarks) {
    //         run_all = true;
    //     }

    //     if (filter == .accounts_db_readwrite or run_all) {
    //         try benchmark(
    //             allocator,
    //             logger,
    //             @import("accountsdb/db.zig").BenchmarkAccountsDB,
    //             max_time_per_bench,
    //             .millis,
    //             &maybe_metrics,
    //         );
    //     }

    //     if ((filter == .accounts_db_snapshot or run_all) and !run_expensive_benchmarks) {
    //         logger.warn().log("[accounts_db_snapshot]: skipping benchmark, use -e to run");
    //     }

    //     if ((filter == .accounts_db_snapshot or run_all) and
    //         run_expensive_benchmarks //
    //     ) snapshot_benchmark: {
    //         // NOTE: snapshot must exist in this directory for the benchmark to run
    //         // NOTE: also need to increase file limits to run this benchmark (see debugging.md)
    //         const BENCH_SNAPSHOT_DIR_PATH = @import("accountsdb/db.zig")
    //             .BenchmarkAccountsDBSnapshotLoad
    //             .SNAPSHOT_DIR_PATH;

    //         var test_snapshot_exists = true;
    //         if (std.fs.cwd().openDir(BENCH_SNAPSHOT_DIR_PATH, .{ .iterate = true })) |dir| {
    //             std.posix.close(dir.fd);
    //         } else |_| {
    //             test_snapshot_exists = false;
    //         }

    //         const download_new_snapshot = force_fresh_state or !test_snapshot_exists;
    //         if (download_new_snapshot) {
    //             // delete existing snapshot dir
    //             if (test_snapshot_exists) {
    //                 logger.info().log("deleting snapshot dir...");
    //                 std.fs.cwd().deleteTreeMinStackSize(BENCH_SNAPSHOT_DIR_PATH) catch |err| {
    //                     logger.err().logf("failed to delete snapshot dir ('{s}'): {}", .{
    //                         BENCH_SNAPSHOT_DIR_PATH,
    //                         err,
    //                     });
    //                     return err;
    //                 };
    //             }

    //             // create fresh snapshot dir
    //             var snapshot_dir = try std.fs.cwd().makeOpenPath(
    //                 BENCH_SNAPSHOT_DIR_PATH,
    //                 .{ .iterate = true },
    //             );
    //             defer snapshot_dir.close();

    //             // start gossip
    //             const gossip_service = try sig.gossip.helpers.initGossipFromCluster(
    //                 allocator,
    //                 logger.unscoped(),
    //                 .testnet, // TODO: support other clusters
    //                 8006,
    //             );
    //             defer {
    //                 gossip_service.shutdown();
    //                 gossip_service.deinit();
    //                 allocator.destroy(gossip_service);
    //             }
    //             try gossip_service.start(.{});

    //             // download and unpack snapshot
    //             const snapshot_manifests, //
    //             _ //
    //             = sig.accounts_db.download.getOrDownloadAndUnpackSnapshot(
    //                 allocator,
    //                 logger,
    //                 BENCH_SNAPSHOT_DIR_PATH,
    //                 .{
    //                     .gossip_service = gossip_service,
    //                     .force_new_snapshot_download = true,
    //                     .max_number_of_download_attempts = 50,
    //                     .min_snapshot_download_speed_mbs = 10,
    //                     .download_timeout = Duration.fromMinutes(5),
    //                 },
    //             ) catch |err| {
    //                 switch (err) {
    //                     error.UnableToDownloadSnapshot => {
    //                         logger.err().log("unable to download snapshot, skipping benchmark...");
    //                         break :snapshot_benchmark;
    //                     },
    //                     else => return err,
    //                 }
    //             };
    //             defer snapshot_manifests.deinit(allocator);
    //         }

    //         try benchmark(
    //             allocator,
    //             logger,
    //             @import("accountsdb/db.zig").BenchmarkAccountsDBSnapshotLoad,
    //             max_time_per_bench,
    //             .millis,
    //             &maybe_metrics,
    //         );
    //     }
    // }

    // if (filter == .socket_utils or run_all_benchmarks) {
    //     try benchmark(
    //         allocator,
    //         logger,
    //         @import("net/socket_utils.zig").BenchmarkPacketProcessing,
    //         max_time_per_bench,
    //         .millis,
    //         &maybe_metrics,
    //     );
    // }

    // if (filter == .gossip or run_all_benchmarks) {
    //     try benchmark(
    //         allocator,
    //         logger,
    //         @import("gossip/service.zig").BenchmarkGossipServiceGeneral,
    //         max_time_per_bench,
    //         .nanos,
    //         &maybe_metrics,
    //     );
    //     try benchmark(
    //         allocator,
    //         logger,
    //         @import("gossip/service.zig").BenchmarkGossipServicePullRequests,
    //         max_time_per_bench,
    //         .nanos,
    //         &maybe_metrics,
    //     );
    // }

    // if (filter == .sync or run_all_benchmarks) {
    //     try benchmark(
    //         allocator,
    //         logger,
    //         @import("sync/channel.zig").BenchmarkChannel,
    //         max_time_per_bench,
    //         .nanos,
    //         &maybe_metrics,
    //     );
    // }

    // if (filter == .ledger or run_all_benchmarks) {
    //     try benchmark(
    //         allocator,
    //         logger,
    //         @import("ledger/benchmarks.zig").BenchmarkLedger,
    //         max_time_per_bench,
    //         .nanos,
    //         &maybe_metrics,
    //     );
    //     try benchmark(
    //         allocator,
    //         logger,
    //         @import("ledger/benchmarks.zig").BenchmarkLedgerSlow,
    //         max_time_per_bench,
    //         .millis,
    //         &maybe_metrics,
    //     );
    // }

    // if (filter == .bincode or run_all_benchmarks) {
    //     try benchmark(
    //         allocator,
    //         logger,
    //         @import("bincode/benchmarks.zig").BenchmarkEntry,
    //         max_time_per_bench,
    //         .nanos,
    //         &maybe_metrics,
    //     );
    // }

    // // NOTE: we dont support CSV output on this method so all results are printed as debug
    // if (filter == .geyser or run_all_benchmarks) {
    //     logger.debug().log("Geyser Streaming Benchmark:");
    //     try @import("geyser/lib.zig").benchmark.runBenchmark(logger);
    // }

    // // save metrics
    // if (collect_metrics) {
    //     try saveMetricsJson(
    //         allocator,
    //         try maybe_metrics.?.toOwnedSlice(),
    //         "results/output.json",
    //     );
    // }
}

pub fn benchmark(
    allocator: std.mem.Allocator,
    logger: sig.trace.Logger,
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

    var is_multi_return = try std.ArrayList(bool).initCapacity(allocator, functions.len);
    defer is_multi_return.deinit();

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
                Duration => blk: { // single value
                    try is_multi_return.append(false);
                    break :blk struct { result: u64 };
                },
                else => blk: { // multiple values
                    try is_multi_return.append(true);
                    break :blk ResultType;
                },
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

            var benchmark_time = try sig.time.Timer.start();
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
                        const x: std.MultiArrayList(RuntimeType).Field = @enumFromInt(j);
                        for (results.items(x), 0..) |runtime, k| {
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
                        const d_sq = d *| d;
                        variance +|= d_sq;
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
                        const n_iters = switch (@typeInfo(T)) {
                            .float => @as(T, @floatFromInt(iterations)),
                            else => iterations,
                        };
                        const f_mean = f_sum / n_iters;

                        var f_variance: T = 0;
                        const x: std.MultiArrayList(RuntimeType).Field = @enumFromInt(j);
                        for (results.items(x)) |f_runtime| {
                            const d = if (f_runtime > f_mean)
                                f_runtime - f_mean
                            else
                                f_mean - f_runtime;
                            switch (@typeInfo(T)) {
                                .float => f_variance = d * d,
                                else => f_variance +|= d *| d,
                            }
                        }
                        f_variance /= n_iters;
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
                        //     if (maybe_metrics.*) |*metrics| {
                        //         const fmt_size = std.fmt.count(
                        //             "{s}({s})_{s}",
                        //             .{ def.name, input_name, field.name },
                        //         );
                        //         const name_buf = try allocator.alloc(u8, fmt_size);
                        //         errdefer allocator.free(name_buf);
                        //         const name = try std.fmt.bufPrint(
                        //             name_buf,
                        //             "{s}({s})_{s}",
                        //             .{ def.name, input_name, field.name },
                        //         );
                        //         const value = switch (@typeInfo(T)) {
                        //             // in the float case we retain the last two decimal points by
                        //             // multiplying by 100 and converting to an integer
                        //             .float => @as(u64, @intFromFloat(f_max * 100)),
                        //             else => f_max,
                        //         };
                        //         const metric: Metric = .{
                        //             .name = name,
                        //             .unit = time_unit.toString(),
                        //             .value = value,
                        //             .allocator = allocator,
                        //         };
                        //         try metrics.append(metric);
                        //     }
                    }
                    try averages_writer.print("\n", .{});
                },
            }
        }
    }

    // print the results in a formatted table
    inline for (functions, 0..) |def, fcni| {
        var fmt_buf: [512]u8 = undefined;
        const file_name_average = try std.fmt.bufPrint(
            &fmt_buf,
            "{s}/{s}.csv",
            .{ B.name, def.name },
        );
        const file_average = try results_directory.openFile(file_name_average, .{});
        defer file_average.close();

        var table = pt.Table.init(allocator);
        defer table.deinit();
        var read_buf: [1024 * 1024]u8 = undefined;
        try table.readFrom(file_average.reader(), &read_buf, ",", true);

        if (!is_multi_return.items[fcni]) {
            // direct print works ok in this case
            try table.printstd();
        } else {
            // re-parse the return type
            const benchFunction = @field(B, def.name);
            // NOTE: @TypeOf guarantees no runtime side-effects of argument expressions.
            // this means the function will *not* be called, this is just computing the return
            // type.
            const arguments = blk: {
                // NOTE: to know if we should pass in the time unit we
                // check the input params of the function, so any multi-return
                // function NEEDS to have the time unit as the first parameter
                const info = @typeInfo(@TypeOf(benchFunction)).@"fn";
                const has_time_unit =
                    info.params.len > 0 and
                    info.params[0].type.? == Resolution;
                const time_arg = if (has_time_unit) .{time_unit} else .{};
                const other_arg = if (@TypeOf(inputs[0]) != void) .{inputs[0]} else .{};
                break :blk time_arg ++ other_arg;
            };
            const ResultType: type = @TypeOf(try @call(.auto, benchFunction, arguments));
            const RuntimeType = blk: {
                switch (ResultType) {
                    // single value
                    Duration => {
                        break :blk struct { result: u64 };
                    },
                    // multiple values
                    else => {
                        break :blk ResultType;
                    },
                }
            };
            const runtime_info = @typeInfo(RuntimeType).@"struct";

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
            stat_data_row[0] = def.name;
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

            var field_names_cells = std.ArrayList(pt.Cell).init(allocator);
            var stats_cells = std.ArrayList(pt.Cell).init(allocator);
            for (0..i) |cell_i| {
                try field_names_cells.append(try pt.Cell.init(allocator, field_name_data[cell_i]));
                try stats_cells.append(try pt.Cell.init(allocator, stat_data_row[cell_i]));
            }
            const field_name_row = pt.Row.init(allocator, field_names_cells);
            const stats_row = pt.Row.init(allocator, stats_cells);

            table.titles = field_name_row;
            try table.rows.insert(0, stats_row);
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
