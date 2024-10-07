const std = @import("std");
const builtin = @import("builtin");
const sig = @import("sig.zig");

const Decl = std.builtin.Type.Declaration;
const math = std.math;
const Duration = sig.time.Duration;

/// to run gossip benchmarks:
/// zig build benchmark -- gossip
pub fn main() !void {
    const allocator = std.heap.c_allocator;
    var std_logger = try sig.trace.ChannelPrintLogger.init(.{
        .allocator = allocator,
        // NOTE: run with .info for proper CSV output, otherwise use .debug
        .max_level = .info,
        .max_buffer = 1 << 15,
    });
    defer std_logger.deinit();
    const logger = std_logger.logger();

    if (builtin.mode == .Debug) logger.warn().log("warning: running benchmark in Debug mode");

    var cli_args = try std.process.argsWithAllocator(allocator);
    defer cli_args.deinit();

    _ = cli_args.skip();
    const maybe_filter = cli_args.next();
    const filter = blk: {
        if (maybe_filter) |filter| {
            logger.debug().logf("filtering benchmarks with prefix: {s}", .{filter});
            break :blk filter;
        } else {
            logger.debug().logf("no filter: running all benchmarks", .{});
            break :blk "";
        }
    };

    const next_cli_arg = cli_args.next();
    const output_runtimes = blk: {
        if (next_cli_arg != null and std.mem.eql(u8, "-r", next_cli_arg.?)) {
            logger.debug().log("outputting runtimes");
            break :blk true;
        } else {
            logger.debug().log("outputting aggregated results");
            break :blk false;
        }
    };

    const max_time_per_bench = Duration.fromSecs(30); // !!
    const run_all_benchmarks = filter.len == 0;

    if (std.mem.startsWith(u8, filter, "swissmap") or run_all_benchmarks) {
        try benchmarkCSV(
            allocator,
            logger,
            @import("accountsdb/swiss_map.zig").BenchmarkSwissMap,
            max_time_per_bench,
            output_runtimes,
        );
    }

    if (std.mem.startsWith(u8, filter, "accounts_db") or run_all_benchmarks) {
        var run_all = false;
        if (std.mem.eql(u8, "accounts_db", filter) or run_all_benchmarks) {
            run_all = true;
        }

        if (std.mem.eql(u8, "accounts_db_readwrite", filter) or run_all) {
            try benchmarkCSV(
                allocator,
                logger,
                @import("accountsdb/db.zig").BenchmarkAccountsDB,
                max_time_per_bench,
                output_runtimes,
            );
        }

        if (std.mem.eql(u8, "accounts_db_snapshot", filter) or run_all) blk: {
            // NOTE: for this benchmark you need to setup a snapshot in test-data/snapshot_bench
            // and run as a binary ./zig-out/bin/... so the open file limits are ok
            const dir_path = sig.TEST_DATA_DIR ++ "bench_snapshot/";
            var snapshot_dir = std.fs.cwd().openDir(dir_path, .{ .iterate = true }) catch {
                logger.debug().logf("[accounts_db_snapshot]: need to setup a snapshot in {s} for this benchmark...", .{dir_path});
                break :blk;
            };
            snapshot_dir.close();

            try benchmarkCSV(
                allocator,
                logger,
                @import("accountsdb/db.zig").BenchmarkAccountsDBSnapshotLoad,
                max_time_per_bench,
                output_runtimes,
            );
        }
    }

    if (std.mem.startsWith(u8, filter, "socket_utils") or run_all_benchmarks) {
        try benchmarkCSV(
            allocator,
            logger,
            @import("net/socket_utils.zig").BenchmarkPacketProcessing,
            max_time_per_bench,
            output_runtimes,
        );
    }

    if (std.mem.startsWith(u8, filter, "gossip") or run_all_benchmarks) {
        try benchmarkCSV(
            allocator,
            logger,
            @import("gossip/service.zig").BenchmarkGossipServiceGeneral,
            max_time_per_bench,
            output_runtimes,
        );
        try benchmarkCSV(
            allocator,
            logger,
            @import("gossip/service.zig").BenchmarkGossipServicePullRequests,
            max_time_per_bench,
            output_runtimes,
        );
    }

    if (std.mem.startsWith(u8, filter, "sync") or run_all_benchmarks) {
        try benchmarkCSV(
            allocator,
            logger,
            @import("sync/channel.zig").BenchmarkChannel,
            max_time_per_bench,
            output_runtimes,
        );
    }

    // NOTE: we dont support CSV output on this method so all results are printed as debug
    if (std.mem.startsWith(u8, filter, "geyser") or run_all_benchmarks) {
        logger.debug().log("Geyser Streaming Benchmark:");
        try @import("geyser/lib.zig").benchmark.runBenchmark(logger);
    }
}

/// src: https://github.com/Hejsil/zig-bench
/// NOTE: we only support Nanos for now beacuse we also support floats which makes it harder to implement.
pub fn benchmarkCSV(
    allocator: std.mem.Allocator,
    logger: sig.trace.Logger,
    comptime B: type,
    max_time_per_benchmark: Duration,
    output_runtimes: bool,
) !void {
    const args = if (@hasDecl(B, "args")) B.args else [_]void{{}};
    const min_iterations = if (@hasDecl(B, "min_iterations")) B.min_iterations else 10000;
    const max_iterations = if (@hasDecl(B, "max_iterations")) B.max_iterations else 100000;

    const functions = comptime blk: {
        var res: []const Decl = &[_]Decl{};
        for (@typeInfo(B).Struct.decls) |decl| {
            if (@typeInfo(@TypeOf(@field(B, decl.name))) != .Fn)
                continue;
            res = res ++ [_]Decl{decl};
        }

        break :blk res;
    };

    if (functions.len == 0) {
        @compileError("No benchmarks to run.");
    }

    inline for (functions, 0..) |def, fcni| {
        _ = fcni;

        inline for (args, 0..) |arg, arg_i| {
            const benchFunction = @field(B, def.name);
            const arguments = switch (@TypeOf(arg)) {
                void => .{},
                else => .{arg},
            };

            // NOTE: @TypeOf guarantees no runtime side-effects of argument expressions.
            // this means the function will *not* be called, this is just computing the return
            // type.
            const result_type: type = @TypeOf(try @call(.auto, benchFunction, arguments));
            const runtime_type = switch (result_type) {
                // single value
                Duration => struct { result: u64 },
                // multiple values
                else => result_type,
            };
            var runtimes: std.MultiArrayList(runtime_type) = .{};
            defer runtimes.deinit(allocator);

            //
            var min: u64 = math.maxInt(u64);
            var max: u64 = 0;
            var sum: u64 = 0;

            // NOTE: these are set to valid values on first iteration
            const U = @typeInfo(runtime_type).Struct;
            var sum_s: runtime_type = undefined;
            var min_s: runtime_type = undefined;
            var max_s: runtime_type = undefined;

            //
            var ran_out_of_time = false;
            var runtime_timer = try sig.time.Timer.start();
            var iter_count: u64 = 0;
            while (iter_count < min_iterations or
                (iter_count < max_iterations and ran_out_of_time)) : (iter_count += 1)
            {
                switch (result_type) {
                    Duration => {
                        const duration = try @call(.auto, benchFunction, arguments);
                        try runtimes.append(allocator, .{ .result = duration.asNanos() });
                        min = @min(runtimes.items(.result)[iter_count], min);
                        max = @max(runtimes.items(.result)[iter_count], max);
                        sum += duration.asNanos();
                    },
                    inline else => {
                        const result = try @call(.auto, benchFunction, arguments);
                        try runtimes.append(allocator, result);

                        if (iter_count == 0) {
                            min_s = result;
                            max_s = result;
                            sum_s = result;
                        } else {
                            inline for (U.fields) |field| {
                                const f_max = @field(max_s, field.name);
                                const f_min = @field(min_s, field.name);
                                @field(max_s, field.name) = @max(@field(result, field.name), f_max);
                                @field(min_s, field.name) = @min(@field(result, field.name), f_min);
                                @field(sum_s, field.name) += @field(result, field.name);
                            }
                        }
                    },
                }
                ran_out_of_time = runtime_timer.read().asNanos() < max_time_per_benchmark.asNanos();
            }

            if (ran_out_of_time) {
                logger.debug().logf("Benchmark {s} ran out of time", .{def.name});
            }

            if (output_runtimes) {
                // print column headers
                if (arg_i == 0) {
                    std.debug.print("benchmark, results (ns)\n", .{});
                }

                // print all results, eg:
                //
                // benchmark, result
                // read_write (100k) (read), [1, 2, 3, 4],
                // read_write (100k) (write), [1, 2, 3, 4],
                switch (result_type) {
                    Duration => {
                        std.debug.print("{s}({s}), ", .{ def.name, arg.name });
                        std.debug.print("[", .{});
                        for (runtimes.items(.result), 0..) |runtime, i| {
                            if (i != 0) std.debug.print(", ", .{});
                            std.debug.print("{d}", .{runtime});
                        }
                        std.debug.print("]\n", .{});
                    },
                    else => {
                        inline for (U.fields, 0..) |field, j| {
                            std.debug.print("{s}({s}) ({s}), ", .{ def.name, arg.name, field.name });
                            std.debug.print("[", .{});
                            const x: std.MultiArrayList(runtime_type).Field = @enumFromInt(j);
                            for (runtimes.items(x), 0..) |runtime, i| {
                                if (i != 0) std.debug.print(", ", .{});
                                std.debug.print("{d}", .{runtime});
                            }
                            std.debug.print("]\n", .{});
                        }
                    },
                }
            } else {
                // print aggregated results, eg:
                //
                // benchmark, read_min, read_max, read_mean, read_variance, write_min, write_max, write_mean, write_variance
                // read_write (100k), 1, 2, 3, 4, 1, 2, 3, 4
                // read_write (200k), 1, 2, 3, 4, 1, 2, 3, 4
                switch (result_type) {
                    Duration => {
                        // print column headers
                        if (arg_i == 0) {
                            std.debug.print("benchmark, min, max, mean, variance\n", .{});
                        }
                        const mean = sum / iter_count;
                        var variance: u64 = 0;
                        for (runtimes.items(.result)) |runtime| {
                            const d = if (runtime > mean) runtime - mean else mean - runtime;
                            const d_sq = d *| d;
                            variance +|= d_sq;
                        }
                        variance /= iter_count;
                        // print column results
                        std.debug.print("{s}({s}), {d}, {d}, {d}, {d}\n", .{ def.name, arg.name, min, max, mean, variance });
                    },
                    inline else => {
                        // print column headers
                        if (arg_i == 0) {
                            std.debug.print("benchmark, ", .{});
                            inline for (U.fields) |field| {
                                std.debug.print("{s}_min, {s}_max, {s}_mean, {s}_variance, ", .{ field.name, field.name, field.name, field.name });
                            }
                            std.debug.print("\n", .{});
                        }

                        // print results
                        std.debug.print("{s}({s}), ", .{ def.name, arg.name });
                        inline for (U.fields, 0..) |field, j| {
                            const f_max = @field(max_s, field.name);
                            const f_min = @field(min_s, field.name);
                            const f_sum = @field(sum_s, field.name);
                            const T = @TypeOf(f_sum);
                            const n_iters = switch (@typeInfo(T)) {
                                .Float => @as(T, @floatFromInt(iter_count)),
                                else => iter_count,
                            };
                            const f_mean = f_sum / n_iters;

                            var f_variance: T = 0;
                            const x: std.MultiArrayList(runtime_type).Field = @enumFromInt(j);
                            for (runtimes.items(x)) |f_runtime| {
                                const d = if (f_runtime > f_mean) f_runtime - f_mean else f_mean - f_runtime;
                                switch (@typeInfo(T)) {
                                    .Float => f_variance = d * d,
                                    else => f_variance +|= d *| d,
                                }
                            }
                            f_variance /= n_iters;

                            std.debug.print("{d}, {d}, {any}, {any}, ", .{ f_max, f_min, f_mean, f_variance });
                        }
                        std.debug.print("\n", .{});
                    },
                }
            }
        }
    }
}
