const std = @import("std");
const lib = @import("lib.zig");

const Decl = std.builtin.Type.Declaration;
const BENCHMARK_FLAG = "benchmark_";

pub fn main() !void {
    const BenchmarkFnc = struct { *const fn () void, []const u8 };
    const benchmark_fcns = comptime blk: {
        var benchmark_fcns: []const BenchmarkFnc = &[_]BenchmarkFnc{};

        for (std.meta.declarations(lib)) |decl| {
            const pkg = @field(lib, decl.name);
            for (std.meta.declarations(pkg)) |pkg_decl| {
                // if benchmark_ ...
                if (std.mem.startsWith(u8, pkg_decl.name, BENCHMARK_FLAG)) {
                    const func = @field(@field(lib, decl.name), pkg_decl.name);
                    benchmark_fcns = benchmark_fcns ++ &[_]BenchmarkFnc{.{ func, decl.name ++ "." ++ pkg_decl.name }};
                }
            }
        }
        break :blk benchmark_fcns;
    };

    for (benchmark_fcns) |f| {
        const fcn = f[0];
        const fcn_name = f[1];
        std.debug.print("Running benchmark: {s}\n", .{fcn_name});

        var timer = try std.time.Timer.start();
        fcn();
        const elapsed = timer.read();
        std.debug.print("=> Took: {d}ms\n", .{elapsed / std.time.ns_per_ms});
    }
}
