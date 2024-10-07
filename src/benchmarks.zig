const std = @import("std");
const builtin = @import("builtin");
const logger = @import("./trace/log.zig");

const Decl = std.builtin.Type.Declaration;

const io = std.io;
const math = std.math;
const meta = std.meta;

/// to run gossip benchmarks:
/// zig build benchmark -- gossip
///
/// optional flag to add --telemetry={git_hash} in the CI
/// this will upload the benchmark results to the Nyrkiö UI.
pub fn main() !void {
    const allocator = std.heap.c_allocator;
    logger.default_logger.* = logger.Logger.init(allocator, .debug);

    if (builtin.mode == .Debug) std.debug.print("warning: running benchmark in Debug mode\n", .{});

    var cli_args = try std.process.argsWithAllocator(allocator);
    defer cli_args.deinit();

    // skip the benchmark argv[0]
    _ = cli_args.skip();

    var telemetry: ?[]const u8 = null;
    var filter: ?Benchmark = null;

    while (cli_args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--help")) {
            usage();
        } else if (std.mem.startsWith(u8, arg, "--telemetry=")) {
            const hash_string = std.mem.trim(u8, arg["--telemetry=".len..], &std.ascii.whitespace);
            if (hash_string.len == 0) @panic("--telemetry expected the current git commit hash");
            telemetry = hash_string;
            continue;
        }

        filter = std.meta.stringToEnum(Benchmark, arg) orelse usage();
    }
    if (telemetry != null and builtin.mode != .ReleaseSafe) @panic("only send telemetry in ReleaseSafe");
    if (filter == null) usage();

    const max_time_per_bench = std.time.ns_per_s;
    const run_all_benchmarks = filter == .all;

    var metrics = std.ArrayList(Metric).init(allocator);
    defer metrics.deinit();

    if (filter == .swissmap or run_all_benchmarks) {
        try benchmark(
            @import("accountsdb/index.zig").BenchmarkSwissMap,
            max_time_per_bench,
            .microseconds,
            &metrics,
        );
    }

    if (filter == .geyser or run_all_benchmarks) {
        std.debug.print("Geyser Streaming Benchmark:\n", .{});
        try @import("geyser/lib.zig").benchmark.runBenchmark();
    }

    if (std.mem.startsWith(u8, @tagName(filter.?), "accounts_db") or run_all_benchmarks) {
        var run_all = false;
        if (filter == .accounts_db or run_all_benchmarks) {
            run_all = true;
        }

        if (filter == .accounts_db_readwrite or run_all) {
            try benchmark(
                @import("accountsdb/db.zig").BenchmarkAccountsDB,
                max_time_per_bench,
                .milliseconds,
                &metrics,
            );
        }

        if (filter == .accounts_db_snapshot or run_all) {
            // NOTE: for this benchmark you need to setup a snapshot in test-data/snapshot_bench
            // and run as a binary ./zig-out/bin/... so the open file limits are ok
            try benchmark(
                @import("accountsdb/db.zig").BenchmarkAccountsDBSnapshotLoad,
                max_time_per_bench,
                .milliseconds,
                &metrics,
            );
        }
    }

    if (filter == .socket_utils or run_all_benchmarks) {
        try benchmark(
            @import("net/socket_utils.zig").BenchmarkPacketProcessing,
            max_time_per_bench,
            .milliseconds,
            &metrics,
        );
    }

    if (filter == .gossip or run_all_benchmarks) {
        try benchmark(
            @import("gossip/service.zig").BenchmarkGossipServiceGeneral,
            max_time_per_bench,
            .milliseconds,
            &metrics,
        );
        try benchmark(
            @import("gossip/service.zig").BenchmarkGossipServicePullRequests,
            max_time_per_bench,
            .milliseconds,
            &metrics,
        );
    }

    if (filter == .sync or run_all_benchmarks) {
        try benchmark(
            @import("sync/channel.zig").BenchmarkChannel,
            max_time_per_bench,
            .microseconds,
            &metrics,
        );
    }

    if (telemetry) |hash| {
        try sendTelemetry(allocator, hash, try metrics.toOwnedSlice());
    }
}

const Benchmark = enum {
    all,
    swissmap,
    geyser,
    accounts_db,
    accounts_db_readwrite,
    accounts_db_snapshot,
    socket_utils,
    gossip,
    sync,
};

fn usage() noreturn {
    var stdout = std.io.getStdOut().writer();
    stdout.writeAll(
        \\ benchmark name [options]
        \\
        \\ Available Benchmarks:
        \\  all
        \\  swissmap
        \\  geyser
        \\  accounts_db
        \\      accounts_db_readwrite
        \\      accounts_db_snapshot
        \\  
        \\  socket_utils
        \\  gossip
        \\  sync
        \\
        \\ Options:
        \\  --help
        \\    Prints this usage message
        \\
        \\  --telemetry=git_hash 
        \\    Sends benchmark to the Nyrkio endpoint, needs the NYRKIO_KEY env-var to be set
        \\
    ) catch @panic("failed to print usage");
    std.posix.exit(1);
}

const TimeUnits = enum {
    nanoseconds,
    microseconds,
    milliseconds,

    const Self = @This();

    pub fn toString(self: Self) []const u8 {
        return switch (self) {
            .nanoseconds => "ns",
            .milliseconds => "ms",
            .microseconds => "us",
        };
    }

    pub fn unitsfromNanoseconds(self: Self, time_ns: u64) !u64 {
        return switch (self) {
            .nanoseconds => time_ns,
            .milliseconds => try std.math.divCeil(u64, time_ns, std.time.ns_per_ms),
            .microseconds => try std.math.divCeil(u64, time_ns, std.time.ns_per_us),
        };
    }
};

// src: https://github.com/Hejsil/zig-bench
pub fn benchmark(
    comptime B: type,
    /// in nanoseconds
    max_time: u64,
    time_unit: TimeUnits,
    metrics: *std.ArrayList(Metric),
) !void {
    const args = if (@hasDecl(B, "args")) B.args else [_]void{{}};
    const min_iterations = if (@hasDecl(B, "min_iterations")) B.min_iterations else 10;
    const max_iterations = if (@hasDecl(B, "max_iterations")) B.max_iterations else 5000;

    const functions = comptime blk: {
        var res: []const Decl = &[_]Decl{};
        for (meta.declarations(B)) |decl| {
            if (@typeInfo(@TypeOf(@field(B, decl.name))) != .Fn)
                continue;
            res = res ++ [_]Decl{decl};
        }

        break :blk res;
    };
    if (functions.len == 0)
        @compileError("No benchmarks to run.");

    const min_width = blk: {
        const writer = io.null_writer;
        var res = [_]u64{ 0, 0, 0, 0, 0, 0 };
        res = try printBenchmark(
            writer,
            res,
            "Benchmark",
            formatter("{s}", ""),
            formatter("{s}", "Iterations"),
            formatter("Min({s})", time_unit.toString()),
            formatter("Max({s})", time_unit.toString()),
            formatter("SDev{s}", ""),
            formatter("Mean({s})", time_unit.toString()),
        );
        inline for (functions) |f| {
            for (args) |arg| {
                const max = math.maxInt(u32);
                res = if (@TypeOf(arg) == void) blk2: {
                    break :blk2 try printBenchmark(writer, res, f.name, formatter("{s}", ""), max, max, max, max, max);
                } else blk2: {
                    break :blk2 try printBenchmark(writer, res, f.name, formatter("{s}", arg.name), max, max, max, max, max);
                };
            }
        }
        break :blk res;
    };

    var buffered_stderr = std.io.bufferedWriter(std.io.getStdErr().writer());
    const stderr = buffered_stderr.writer();
    try stderr.writeAll("\n");
    _ = try printBenchmark(
        stderr,
        min_width,
        "Benchmark",
        formatter("{s}", ""),
        formatter("{s}", "Iterations"),
        formatter("Min({s})", time_unit.toString()),
        formatter("Max({s})", time_unit.toString()),
        formatter("SDev{s}", ""),
        formatter("Mean({s})", time_unit.toString()),
    );
    try stderr.writeAll("\n");
    for (min_width) |w|
        try stderr.writeByteNTimes('-', w);
    try stderr.writeByteNTimes('-', min_width.len - 1);
    try stderr.writeAll("\n");
    try stderr.context.flush();

    inline for (functions, 0..) |def, fcni| {
        if (fcni > 0)
            std.debug.print("---\n", .{});

        inline for (args) |arg| {
            var runtimes: [max_iterations]u64 = undefined;
            var min: u64 = math.maxInt(u64);
            var max: u64 = 0;
            var runtime_sum: u64 = 0;

            var i: usize = 0;
            while (i < min_iterations or
                (i < max_iterations and runtime_sum < max_time)) : (i += 1)
            {
                const ns_time = try switch (@TypeOf(arg)) {
                    void => @field(B, def.name)(),
                    else => @field(B, def.name)(arg),
                };

                const runtime = try time_unit.unitsfromNanoseconds(ns_time);

                runtimes[i] = runtime;
                runtime_sum += runtime;
                min = @min(runtimes[i], min);
                max = @max(runtimes[i], max);
            }

            const runtime_mean = runtime_sum / i;

            var squared_difference_sum: u64 = 0;
            for (runtimes[0..i]) |runtime| {
                const d = @as(i64, @intCast(runtime)) - @as(i64, @intCast(runtime_mean));
                squared_difference_sum += @intCast(d * d);
            }
            // o^2
            const variance = squared_difference_sum / i;
            // o
            const sd = std.math.sqrt(variance);

            _ = try printBenchmark(
                stderr,
                min_width,
                def.name,
                formatter("{s}", if (@TypeOf(arg) == void) "" else arg.name),
                i,
                try time_unit.unitsfromNanoseconds(min),
                try time_unit.unitsfromNanoseconds(max),
                try time_unit.unitsfromNanoseconds(sd),
                try time_unit.unitsfromNanoseconds(runtime_mean),
            );

            try stderr.writeAll("\n");
            try stderr.context.flush();

            const metric: Metric = .{
                .name = if (@TypeOf(arg) == void) "" else arg.name,
                .unit = time_unit.toString(),
                .value = try time_unit.unitsfromNanoseconds(runtime_mean),
            };
            try metrics.append(metric);
        }
    }
}

fn printBenchmark(
    writer: anytype,
    min_widths: [6]u64,
    func_name: []const u8,
    arg_name: anytype,
    iterations: anytype,
    min_runtime: anytype,
    max_runtime: anytype,
    variance: anytype,
    mean_runtime: anytype,
) ![6]u64 {
    const arg_len = std.fmt.count("{}", .{arg_name});
    const name_len = try alignedPrint(writer, .left, min_widths[0], "{s}{s}{}{s}", .{
        func_name,
        "("[0..@intFromBool(arg_len != 0)],
        arg_name,
        ")"[0..@intFromBool(arg_len != 0)],
    });
    try writer.writeAll(" ");
    const it_len = try alignedPrint(writer, .right, min_widths[1], "{}", .{iterations});
    try writer.writeAll(" ");
    const min_runtime_len = try alignedPrint(writer, .right, min_widths[2], "{}", .{min_runtime});
    try writer.writeAll(" ");
    const max_runtime_len = try alignedPrint(writer, .right, min_widths[3], "{}", .{max_runtime});
    try writer.writeAll(" ");
    const variance_len = try alignedPrint(writer, .right, min_widths[4], "{}", .{variance});
    try writer.writeAll(" ");
    const mean_runtime_len = try alignedPrint(writer, .right, min_widths[5], "{}", .{mean_runtime});
    return [_]u64{ name_len, it_len, min_runtime_len, max_runtime_len, variance_len, mean_runtime_len };
}

fn formatter(comptime fmt_str: []const u8, value: anytype) Formatter(fmt_str, @TypeOf(value)) {
    return .{ .value = value };
}

fn Formatter(comptime fmt_str: []const u8, comptime T: type) type {
    return struct {
        value: T,

        pub fn format(
            self: @This(),
            comptime fmt: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            _ = fmt;
            _ = options;
            try std.fmt.format(writer, fmt_str, .{self.value});
        }
    };
}

fn alignedPrint(writer: anytype, dir: enum { left, right }, width: u64, comptime fmt: []const u8, args: anytype) !u64 {
    const value_len = std.fmt.count(fmt, args);

    var cow = io.countingWriter(writer);
    if (dir == .right)
        try cow.writer().writeByteNTimes(' ', math.sub(u64, width, value_len) catch 0);
    try cow.writer().print(fmt, args);
    if (dir == .left)
        try cow.writer().writeByteNTimes(' ', math.sub(u64, width, value_len) catch 0);
    return cow.bytes_written;
}

const Metric = struct {
    name: []const u8,
    unit: []const u8,
    value: u64,
};

const MetricBatch = struct {
    timestamp: u64,
    metrics: []const Metric,
    attributes: struct {
        git_repo: []const u8,
        branch: []const u8,
        git_commit: []const u8,
    },
};

pub fn sendTelemetry(
    allocator: std.mem.Allocator,
    hash: []const u8,
    metrics: []const Metric,
) !void {
    const git_args = &.{
        "git",
        "show",
        "-s",
        "--format=%ct",
        hash,
    };
    const git_result = try std.process.Child.run(.{
        .argv = git_args,
        .allocator = allocator,
    });

    if (git_result.term != .Exited) @panic("git failed");
    const timestamp = try std.fmt.parseInt(u64, std.mem.sliceTo(git_result.stdout, '\n'), 10);

    const batch: *const MetricBatch = &.{
        .timestamp = timestamp,
        .metrics = metrics,
        .attributes = .{
            .git_repo = "https://github.com/Syndica/sig",
            .branch = "main",
            .git_commit = hash,
        },
    };

    const payload = try std.json.stringifyAlloc(
        allocator,
        [_]*const MetricBatch{batch}, // Nyrkiö needs an _array_ of batches.
        .{},
    );
    defer allocator.free(payload);

    const token = try std.process.getEnvVarOwned(allocator, "NYRKIO_KEY");
    defer allocator.free(token);

    const curl_args = &.{
        "curl",
        "-X",
        "POST",
        "-H",
        "Content-type: application/json",
        "-H",
        try std.fmt.allocPrint(allocator, "Authorization: Bearer {s}", .{token}),
        try std.fmt.allocPrint(allocator, "-d {s}", .{payload}),
        "https://nyrkio.com/api/v0/result/sig",
    };

    const result = try std.process.Child.run(.{
        .argv = curl_args,
        .allocator = allocator,
    });
    if (result.term != .Exited) {
        std.debug.print("curl stderr: {s}\n", .{result.stderr});
        @panic("curl failed");
    }
}
