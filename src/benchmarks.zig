const std = @import("std");
const builtin = @import("builtin");
const sig = @import("sig.zig");
const pt = @import("prettytable");
const math = std.math;

const Decl = std.builtin.Type.Declaration;
const Duration = sig.time.Duration;

pub const BenchTimeUnit = enum {
    nanos,
    millis,
    seconds,

    pub fn convertDuration(self: BenchTimeUnit, duration: Duration) u64 {
        return switch (self) {
            .nanos => duration.asNanos(),
            .millis => duration.asMillis(),
            .seconds => duration.asSecs(),
        };
    }

    pub fn toString(self: BenchTimeUnit) []const u8 {
        return switch (self) {
            .nanos => "nanos",
            .millis => "millis",
            .seconds => "seconds",
        };
    }
};

const Benchmark = enum {
    all,
    accounts_db,
    accounts_db_readwrite,
    accounts_db_snapshot, // expensive
    bincode,
    geyser,
    gossip,
    ledger,
    swissmap,
    sync,
    socket_utils,
};

fn exitWithUsage() noreturn {
    var stdout = std.io.getStdOut().writer();
    stdout.writeAll(
        \\ benchmark name [options]
        \\
        \\ Available Benchmarks:
        \\
    ) catch @panic("failed to print usage");

    inline for (@typeInfo(Benchmark).@"enum".fields) |field| {
        stdout.print(
            " {s}\n",
            .{field.name},
        ) catch @panic("failed to print usage");
    }

    stdout.writeAll(
        \\
        \\ Options:
        \\  --help
        \\    Prints this usage message
        \\
        \\  --metrics
        \\    save benchmark results to results/output.json. default: false.
        \\
        \\  -e
        \\    run expensive benchmarks. default: false.
        \\
        \\  -f
        \\    force fresh state for expensive benchmarks. default: false.
    ) catch @panic("failed to print usage");
    std.posix.exit(1);
}

/// to run gossip benchmarks:
/// zig build benchmark -- gossip
pub fn main() !void {
    const allocator = std.heap.c_allocator;
    var std_logger = sig.trace.DirectPrintLogger.init(
        allocator,
        .info, // NOTE: change to debug to see all logs
    );
    const logger = std_logger.logger();

    if (builtin.mode == .Debug) logger.warn().log("running benchmark in Debug mode");

    var cli_args = try std.process.argsWithAllocator(allocator);
    defer cli_args.deinit();

    var run_expensive_benchmarks: bool = false;
    var collect_metrics: bool = false;
    var force_fresh_state: bool = false;

    var maybe_filter: ?Benchmark = null;
    // skip the benchmark argv[0]
    _ = cli_args.skip();
    while (cli_args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--help")) {
            exitWithUsage();
        } else if (std.mem.startsWith(u8, arg, "--metrics")) {
            collect_metrics = true;
            continue;
        } else if (std.mem.startsWith(u8, arg, "-e")) {
            run_expensive_benchmarks = true;
            continue;
        } else if (std.mem.startsWith(u8, arg, "-f")) {
            force_fresh_state = true;
            continue;
        }
        maybe_filter = std.meta.stringToEnum(Benchmark, arg) orelse {
            logger.err().logf("unknown benchmark: {s}", .{arg});
            exitWithUsage();
        };
    }
    if (collect_metrics and builtin.mode != .ReleaseSafe) {
        @panic("collecting metrics is only supported in ReleaseSafe mode");
    }
    if (maybe_filter == null) {
        exitWithUsage();
    }
    const filter = maybe_filter.?;
    if (filter == .all) {
        logger.info().log("running all benchmarks");
    } else {
        logger.info().logf("running benchmark with filter: {s}", .{@tagName(filter)});
    }
    if (collect_metrics) {
        logger.info().log("collecting metrics");
    }
    if (run_expensive_benchmarks) {
        logger.info().log("running expensive benchmarks");
    }
    if (force_fresh_state) {
        logger.info().log("forcing fresh state for expensive benchmarks");
    } else {
        logger.info().log("re-using state for expensive benchmarks");
    }

    const max_time_per_bench = Duration.fromSecs(5); // !!
    const run_all_benchmarks = filter == .all;

    var maybe_metrics: ?std.ArrayList(Metric) = null;
    if (collect_metrics) {
        maybe_metrics = std.ArrayList(Metric).init(allocator);
    }
    defer {
        if (maybe_metrics) |metrics| {
            for (metrics.items) |m| {
                m.deinit();
            }
            metrics.deinit();
        }
    }

    if (filter == .swissmap or run_all_benchmarks) {
        try benchmark(
            allocator,
            logger,
            @import("accountsdb/swiss_map.zig").BenchmarkSwissMap,
            max_time_per_bench,
            .nanos,
            &maybe_metrics,
        );
    }

    if (std.mem.startsWith(u8, @tagName(filter), "accounts_db") or run_all_benchmarks) {
        var run_all = false;
        if (filter == .accounts_db or run_all_benchmarks) {
            run_all = true;
        }

        if (filter == .accounts_db_readwrite or run_all) {
            try benchmark(
                allocator,
                logger,
                @import("accountsdb/db.zig").BenchmarkAccountsDB,
                max_time_per_bench,
                .millis,
                &maybe_metrics,
            );
        }

        if ((filter == .accounts_db_snapshot or run_all) and !run_expensive_benchmarks) {
            logger.warn().log("[accounts_db_snapshot]: skipping benchmark, use -e to run");
        }

        if ((filter == .accounts_db_snapshot or run_all) and
            run_expensive_benchmarks //
        ) snapshot_benchmark: {
            // NOTE: snapshot must exist in this directory for the benchmark to run
            // NOTE: also need to increase file limits to run this benchmark (see debugging.md)
            const BENCH_SNAPSHOT_DIR_PATH = @import("accountsdb/db.zig")
                .BenchmarkAccountsDBSnapshotLoad
                .SNAPSHOT_DIR_PATH;

            var test_snapshot_exists = true;
            if (std.fs.cwd().openDir(BENCH_SNAPSHOT_DIR_PATH, .{ .iterate = true })) |dir| {
                std.posix.close(dir.fd);
            } else |_| {
                test_snapshot_exists = false;
            }

            const download_new_snapshot = force_fresh_state or !test_snapshot_exists;
            if (download_new_snapshot) {
                // delete existing snapshot dir
                if (test_snapshot_exists) {
                    logger.info().log("deleting snapshot dir...");
                    std.fs.cwd().deleteTreeMinStackSize(BENCH_SNAPSHOT_DIR_PATH) catch |err| {
                        logger.err().logf("failed to delete snapshot dir ('{s}'): {}", .{
                            BENCH_SNAPSHOT_DIR_PATH,
                            err,
                        });
                        return err;
                    };
                }

                // create fresh snapshot dir
                var snapshot_dir = try std.fs.cwd().makeOpenPath(
                    BENCH_SNAPSHOT_DIR_PATH,
                    .{ .iterate = true },
                );
                defer snapshot_dir.close();

                // start gossip
                const gossip_service = try sig.gossip.helpers.initGossipFromCluster(
                    allocator,
                    logger.unscoped(),
                    .testnet, // TODO: support other clusters
                    8006,
                );
                defer {
                    gossip_service.shutdown();
                    gossip_service.deinit();
                    allocator.destroy(gossip_service);
                }
                try gossip_service.start(.{});

                // download and unpack snapshot
                const snapshot_manifests, //
                _ //
                = sig.accounts_db.download.getOrDownloadAndUnpackSnapshot(
                    allocator,
                    logger,
                    BENCH_SNAPSHOT_DIR_PATH,
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
                            logger.err().log("unable to download snapshot, skipping benchmark...");
                            break :snapshot_benchmark;
                        },
                        else => return err,
                    }
                };
                defer snapshot_manifests.deinit(allocator);
            }

            try benchmark(
                allocator,
                logger,
                @import("accountsdb/db.zig").BenchmarkAccountsDBSnapshotLoad,
                max_time_per_bench,
                .millis,
                &maybe_metrics,
            );
        }
    }

    if (filter == .socket_utils or run_all_benchmarks) {
        try benchmark(
            allocator,
            logger,
            @import("net/socket_utils.zig").BenchmarkPacketProcessing,
            max_time_per_bench,
            .millis,
            &maybe_metrics,
        );
    }

    if (filter == .gossip or run_all_benchmarks) {
        try benchmark(
            allocator,
            logger,
            @import("gossip/service.zig").BenchmarkGossipServiceGeneral,
            max_time_per_bench,
            .nanos,
            &maybe_metrics,
        );
        try benchmark(
            allocator,
            logger,
            @import("gossip/service.zig").BenchmarkGossipServicePullRequests,
            max_time_per_bench,
            .nanos,
            &maybe_metrics,
        );
    }

    if (filter == .sync or run_all_benchmarks) {
        try benchmark(
            allocator,
            logger,
            @import("sync/channel.zig").BenchmarkChannel,
            max_time_per_bench,
            .nanos,
            &maybe_metrics,
        );
    }

    if (filter == .ledger or run_all_benchmarks) {
        try benchmark(
            allocator,
            logger,
            @import("ledger/benchmarks.zig").BenchmarkLedger,
            max_time_per_bench,
            .nanos,
            &maybe_metrics,
        );
        try benchmark(
            allocator,
            logger,
            @import("ledger/benchmarks.zig").BenchmarkLedgerSlow,
            max_time_per_bench,
            .millis,
            &maybe_metrics,
        );
    }

    if (filter == .bincode or run_all_benchmarks) {
        try benchmark(
            allocator,
            logger,
            @import("bincode/benchmarks.zig").BenchmarkEntry,
            max_time_per_bench,
            .nanos,
            &maybe_metrics,
        );
    }

    // NOTE: we dont support CSV output on this method so all results are printed as debug
    if (filter == .geyser or run_all_benchmarks) {
        logger.debug().log("Geyser Streaming Benchmark:");
        try @import("geyser/lib.zig").benchmark.runBenchmark(logger);
    }

    // save metrics
    if (collect_metrics) {
        try saveMetricsJson(
            allocator,
            try maybe_metrics.?.toOwnedSlice(),
            "results/output.json",
        );
    }
}

pub fn benchmark(
    allocator: std.mem.Allocator,
    logger: sig.trace.Logger,
    comptime B: type,
    max_time_per_benchmark: Duration,
    time_unit: BenchTimeUnit,
    maybe_metrics: *?std.ArrayList(Metric),
) !void {
    const has_args = if (@hasDecl(B, "args")) true else false;
    const args = if (has_args) B.args else [_]void{{}};
    const min_iterations = if (@hasDecl(B, "min_iterations")) B.min_iterations else 10;
    const max_iterations = if (@hasDecl(B, "max_iterations")) B.max_iterations else 5_000;

    const functions = comptime blk: {
        var res: []const Decl = &[_]Decl{};
        for (@typeInfo(B).@"struct".decls) |decl| {
            if (@typeInfo(@TypeOf(@field(B, decl.name))) != .@"fn")
                continue;
            res = res ++ [_]Decl{decl};
        }

        break :blk res;
    };

    if (functions.len == 0) {
        @compileError("No benchmarks to run.");
    }

    const results_dir = try std.fs.cwd().makeOpenPath(sig.BENCHMARK_RESULTS_DIR, .{});
    var raw_benchmark_name = @typeName(B);

    // find the last dot in the benchmark name (since imports are usually x.a.b.YBenchmark, this
    // gets us to YBenchmark)
    var index: u64 = 0;
    while (true) {
        const maybe_index = std.mem.indexOf(u8, raw_benchmark_name[index + 1 ..], ".");
        index += 1;
        index += maybe_index orelse break;
    }
    const benchmark_name = raw_benchmark_name[index..];
    results_dir.makeDir(benchmark_name) catch |err| {
        switch (err) {
            std.fs.Dir.MakeError.PathAlreadyExists => {},
            else => return err,
        }
    };

    var is_multi_return = try std.ArrayList(bool).initCapacity(allocator, functions.len);
    defer is_multi_return.deinit();

    inline for (functions) |def| {
        var fmt_buf: [512]u8 = undefined;
        const file_name_average = try std.fmt.bufPrint(
            &fmt_buf,
            "{s}/{s}.csv",
            .{ benchmark_name, def.name },
        );
        const file_average = try results_dir.createFile(file_name_average, .{ .read = true });
        defer file_average.close();
        const writer_average = file_average.writer();
        logger.debug().logf("writing benchmark results to {s}", .{file_name_average});

        var fmt_buf2: [512]u8 = undefined;
        const file_name_runtimes = try std.fmt.bufPrint(
            &fmt_buf2,
            "{s}/{s}_runtimes.csv",
            .{ benchmark_name, def.name },
        );
        const file_runtimes = try results_dir.createFile(file_name_runtimes, .{ .read = true });
        defer file_runtimes.close();
        const writer_runtimes = file_runtimes.writer();

        inline for (args, 0..) |arg, arg_i| {
            const arg_name = if (has_args) arg.name else "_";
            logger.debug().logf(
                "benchmarking arg: {d}/{d}: {s}",
                .{ arg_i + 1, args.len, arg_name },
            );

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
                    info.params[0].type.? == BenchTimeUnit;
                const time_arg = if (has_time_unit) .{time_unit} else .{};
                const other_arg = if (@TypeOf(arg) != void) .{arg} else .{};
                break :blk time_arg ++ other_arg;
            };
            const ResultType: type = @TypeOf(try @call(.auto, benchFunction, arguments));
            const RuntimeType = blk: {
                switch (ResultType) {
                    // single value
                    Duration => {
                        try is_multi_return.append(false);
                        break :blk struct { result: u64 };
                    },
                    // multiple values
                    else => {
                        try is_multi_return.append(true);
                        break :blk ResultType;
                    },
                }
            };
            var runtimes: std.MultiArrayList(RuntimeType) = .{};
            defer runtimes.deinit(allocator);

            //
            var min: u64 = math.maxInt(u64);
            var max: u64 = 0;
            var sum: u64 = 0;

            // NOTE: these are set to valid values on first iteration
            const runtime_info = @typeInfo(RuntimeType).@"struct";
            var sum_s: RuntimeType = undefined;
            var min_s: RuntimeType = undefined;
            var max_s: RuntimeType = undefined;

            //
            var ran_out_of_time = false;
            var runtime_timer = try sig.time.Timer.start();
            var iter_count: u64 = 0;
            while (iter_count < min_iterations or
                (iter_count < max_iterations and ran_out_of_time)) : (iter_count += 1)
            {
                switch (ResultType) {
                    Duration => {
                        const duration = try @call(.auto, benchFunction, arguments);
                        const runtime = time_unit.convertDuration(duration);
                        min = @min(runtime, min);
                        max = @max(runtime, max);
                        sum += runtime;
                        try runtimes.append(allocator, .{ .result = runtime });
                    },
                    else => {
                        const result = try @call(.auto, benchFunction, arguments);
                        try runtimes.append(allocator, result);

                        if (iter_count == 0) {
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
                ran_out_of_time =
                    runtime_timer.read().asNanos() < max_time_per_benchmark.asNanos();
            }

            if (ran_out_of_time) {
                logger.debug().log("ran out of time...");
            }

            // print all runtimes, eg:
            //
            // benchmark, result
            // read_write (100k) (read), 1, 2, 3, 4,
            // read_write (100k) (write), 1, 2, 3, 4,
            switch (ResultType) {
                Duration => {
                    try writer_runtimes.print("{s}({s}), results", .{ def.name, arg_name });
                    for (runtimes.items(.result), 0..) |runtime, i| {
                        if (i != 0) try writer_runtimes.print(", ", .{});
                        try writer_runtimes.print("{d}", .{runtime});
                    }
                    try writer_runtimes.print("\n", .{});
                },
                else => {
                    inline for (runtime_info.fields, 0..) |field, j| {
                        try writer_runtimes.print(
                            "{s}({s}) ({s}), ",
                            .{ def.name, arg_name, field.name },
                        );
                        const x: std.MultiArrayList(RuntimeType).Field = @enumFromInt(j);
                        for (runtimes.items(x), 0..) |runtime, i| {
                            if (i != 0) try writer_runtimes.print(", ", .{});
                            try writer_runtimes.print("{d}", .{runtime});
                        }
                        try writer_runtimes.print("\n", .{});
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
                    if (arg_i == 0) {
                        try writer_average.print("{s}, min, max, mean, std_dev\n", .{def.name});
                    }
                    const mean = sum / iter_count;
                    var variance: u64 = 0;
                    for (runtimes.items(.result)) |runtime| {
                        const d = if (runtime > mean) runtime - mean else mean - runtime;
                        const d_sq = d *| d;
                        variance +|= d_sq;
                    }
                    variance /= iter_count;
                    const std_dev = std.math.sqrt(variance);

                    // print column results
                    try writer_average.print(
                        "{s}, {d}, {d}, {d}, {d}\n",
                        .{ arg_name, min, max, mean, std_dev },
                    );

                    // collect the metric
                    if (maybe_metrics.*) |*metrics| {
                        const name = try std.fmt.allocPrint(
                            allocator,
                            "{s}({s})",
                            .{ def.name, arg_name },
                        );
                        errdefer allocator.free(name);
                        const metric: Metric = .{
                            .name = name,
                            .unit = time_unit.toString(),
                            .value = max,
                            .allocator = allocator,
                        };
                        try metrics.append(metric);
                    }
                },
                else => {
                    // print column headers
                    if (arg_i == 0) {
                        try writer_average.print("{s}, ", .{def.name});
                        inline for (runtime_info.fields, 0..) |field, i| {
                            if (i == runtime_info.fields.len - 1) {
                                // dont print trailing comma
                                try writer_average.print(
                                    "{s}_min, {s}_max, {s}_mean, {s}_std_dev",
                                    .{ field.name, field.name, field.name, field.name },
                                );
                            } else {
                                try writer_average.print(
                                    "{s}_min, {s}_max, {s}_mean, {s}_std_dev, ",
                                    .{ field.name, field.name, field.name, field.name },
                                );
                            }
                        }
                        try writer_average.print("\n", .{});
                    }

                    // print results
                    try writer_average.print("{s}, ", .{arg_name});
                    inline for (runtime_info.fields, 0..) |field, j| {
                        const f_max = @field(max_s, field.name);
                        const f_min = @field(min_s, field.name);
                        const f_sum = @field(sum_s, field.name);
                        const T = @TypeOf(f_sum);
                        const n_iters = switch (@typeInfo(T)) {
                            .float => @as(T, @floatFromInt(iter_count)),
                            else => iter_count,
                        };
                        const f_mean = f_sum / n_iters;

                        var f_variance: T = 0;
                        const x: std.MultiArrayList(RuntimeType).Field = @enumFromInt(j);
                        for (runtimes.items(x)) |f_runtime| {
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
                            try writer_average.print(
                                "{d}, {d}, {any}, {any}",
                                .{ f_min, f_max, f_mean, f_std_dev },
                            );
                        } else {
                            try writer_average.print(
                                "{d}, {d}, {any}, {any}, ",
                                .{ f_min, f_max, f_mean, f_std_dev },
                            );
                        }

                        // collect the metric
                        if (maybe_metrics.*) |*metrics| {
                            const fmt_size = std.fmt.count(
                                "{s}({s})_{s}",
                                .{ def.name, arg_name, field.name },
                            );
                            const name_buf = try allocator.alloc(u8, fmt_size);
                            errdefer allocator.free(name_buf);
                            const name = try std.fmt.bufPrint(
                                name_buf,
                                "{s}({s})_{s}",
                                .{ def.name, arg_name, field.name },
                            );
                            const value = switch (@typeInfo(T)) {
                                // in the float case we retain the last two decimal points by
                                // multiplying by 100 and converting to an integer
                                .float => @as(u64, @intFromFloat(f_max * 100)),
                                else => f_max,
                            };
                            const metric: Metric = .{
                                .name = name,
                                .unit = time_unit.toString(),
                                .value = value,
                                .allocator = allocator,
                            };
                            try metrics.append(metric);
                        }
                    }
                    try writer_average.print("\n", .{});
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
            .{ benchmark_name, def.name },
        );
        const file_average = try results_dir.openFile(file_name_average, .{});
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
                    info.params[0].type.? == BenchTimeUnit;
                const time_arg = if (has_time_unit) .{time_unit} else .{};
                const other_arg = if (@TypeOf(args[0]) != void) .{args[0]} else .{};
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
    unit: []const u8,
    value: u64,
    // used to deallocate the metric name which
    // is on the heap due to runtime formatting
    allocator: std.mem.Allocator,

    pub fn deinit(self: Metric) void {
        self.allocator.free(self.name);
    }
};

/// this metric struct is used in the json.stringify call
/// which removes non-necessary fields from the `Metric` struct.
const JsonMetric = struct {
    name: []const u8,
    unit: []const u8,
    value: u64,
};

pub fn saveMetricsJson(
    allocator: std.mem.Allocator,
    metrics: []const Metric,
    output_path: []const u8,
) !void {
    var json_metrics = try std.ArrayList(JsonMetric).initCapacity(allocator, metrics.len);
    defer json_metrics.deinit();
    for (metrics) |m| json_metrics.appendAssumeCapacity(.{
        .name = m.name,
        .unit = m.unit,
        .value = m.value,
    });

    const payload = try std.json.stringifyAlloc(
        allocator,
        json_metrics.items,
        .{},
    );
    defer allocator.free(payload);

    const output_file = try std.fs.cwd().createFile(output_path, .{});
    try output_file.writeAll(payload);
}
