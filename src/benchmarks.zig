const std = @import("std");
const builtin = @import("builtin");
const logger = @import("./trace/log.zig");

const Decl = std.builtin.Type.Declaration;

const io = std.io;
const math = std.math;
const meta = std.meta;

/// to run gossip benchmarks:
/// zig build benchmark -- gossip
pub fn main() !void {
    const allocator = std.heap.page_allocator;
    logger.default_logger.* = logger.Logger.init(allocator, .debug);

    if (builtin.mode == .Debug) std.debug.print("warning: running benchmark in Debug mode\n", .{});

    var cli_args = try std.process.argsWithAllocator(allocator);
    defer cli_args.deinit();

    _ = cli_args.skip();
    const maybe_filter = cli_args.next();
    const filter = blk: {
        if (maybe_filter) |filter| {
            std.debug.print("filtering benchmarks with prefix: {s}\n", .{filter});
            break :blk filter;
        } else {
            std.debug.print("no filter: running all benchmarks\n", .{});
            break :blk "";
        }
    };

    // TODO: very manual for now (bc we only have 2 benchmarks)
    // if we have more benchmarks we can make this more efficient
    const max_time_per_bench = 2 * std.time.ms_per_s; // !!
    const run_all_benchmarks = filter.len == 0;

    if (std.mem.startsWith(u8, filter, "swissmap") or run_all_benchmarks) {
        try benchmark(
            @import("accountsdb/index.zig").BenchmarkSwissMap,
            max_time_per_bench,
            .microseconds,
        );
    }

    if (std.mem.startsWith(u8, filter, "geyser") or run_all_benchmarks) {
        std.debug.print("Geyser Streaming Benchmark:\n", .{});
        try @import("geyser/lib.zig").benchmark.runBenchmark();
    }

    if (std.mem.startsWith(u8, filter, "accounts_db") or run_all_benchmarks) {
        var run_all = false;
        if (std.mem.eql(u8, "accounts_db", filter) or run_all_benchmarks) {
            run_all = true;
        }

        if (std.mem.eql(u8, "accounts_db_readwrite", filter) or run_all) {
            try benchmark(
                @import("accountsdb/db.zig").BenchmarkAccountsDB,
                max_time_per_bench,
                .milliseconds,
            );
        }

        if (std.mem.eql(u8, "accounts_db_snapshot", filter) or run_all) {
            // NOTE: for this benchmark you need to setup a snapshot in test-data/snapshot_bench
            // and run as a binary ./zig-out/bin/... so the open file limits are ok
            try benchmark(
                @import("accountsdb/db.zig").BenchmarkAccountsDBSnapshotLoad,
                max_time_per_bench,
                .milliseconds,
            );
        }
    }

    if (std.mem.startsWith(u8, filter, "socket_utils") or run_all_benchmarks) {
        try benchmark(
            @import("net/socket_utils.zig").BenchmarkPacketProcessing,
            max_time_per_bench,
            .milliseconds,
        );
    }

    if (std.mem.startsWith(u8, filter, "gossip") or run_all_benchmarks) {
        try benchmark(
            @import("gossip/service.zig").BenchmarkGossipServiceGeneral,
            max_time_per_bench,
            .milliseconds,
        );
        try benchmark(
            @import("gossip/service.zig").BenchmarkGossipServicePullRequests,
            max_time_per_bench,
            .milliseconds,
        );
    }

    if (std.mem.startsWith(u8, filter, "sync") or run_all_benchmarks) {
        try benchmark(
            @import("sync/channel.zig").BenchmarkChannel,
            max_time_per_bench,
            .microseconds,
        );
    }
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
    max_time: u128,
    time_unit: TimeUnits,
) !void {
    const args = if (@hasDecl(B, "args")) B.args else [_]void{{}};
    const min_iterations = if (@hasDecl(B, "min_iterations")) B.min_iterations else 10000;
    const max_iterations = if (@hasDecl(B, "max_iterations")) B.max_iterations else 100000;

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
            formatter("Variance{s}", ""),
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

    var _stderr = std.io.bufferedWriter(std.io.getStdErr().writer());
    const stderr = _stderr.writer();
    try stderr.writeAll("\n");
    _ = try printBenchmark(
        stderr,
        min_width,
        "Benchmark",
        formatter("{s}", ""),
        formatter("{s}", "Iterations"),
        formatter("Min({s})", time_unit.toString()),
        formatter("Max({s})", time_unit.toString()),
        formatter("Variance{s}", ""),
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
            var runtime_sum: u128 = 0;

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

            const runtime_mean: u64 = @intCast(runtime_sum / i);

            var d_sq_sum: u128 = 0;
            for (runtimes[0..i]) |runtime| {
                const d = @as(i64, @intCast(@as(i128, @intCast(runtime)) - runtime_mean));
                d_sq_sum += @as(u64, @intCast(d * d));
            }
            const variance = d_sq_sum / i;
            _ = try printBenchmark(
                stderr,
                min_width,
                def.name,
                formatter("{s}", if (@TypeOf(arg) == void) "" else arg.name),
                i,
                min,
                max,
                variance,
                runtime_mean,
            );
            try stderr.writeAll("\n");
            try stderr.context.flush();
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
