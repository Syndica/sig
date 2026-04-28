const std = @import("std");
const build_options = @import("build-options");

const solfuzz_sig = @import("lib.zig");
const exec = @import("exec.zig");

pub fn main() !void {
    const allocator = std.heap.c_allocator;

    // Parse args
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len != 2 and args.len != 3) {
        std.debug.print("usage: exec <fix-file-or-dir> [target-path]\n", .{});
        std.posix.exit(2);
    }

    // Get the library to test
    var lib: exec.Library = if (args.len == 3) .{
        .dyn = try .open(args[2]),
    } else if (build_options.include_sig) .{
        .map = &solfuzz_sig.entrypoints,
    } else {
        std.debug.print("No lib provided. Build with sig or provide a target path\n", .{});
        std.posix.exit(2);
    };
    defer if (lib == .dyn) lib.dyn.close();

    // Run the tests
    var passed_count: usize = 0;
    var failed_count: usize = 0;
    const stat = try std.fs.cwd().statFile(args[1]);
    if (stat.kind == .directory) {
        const stats = try exec.execDir(allocator, &lib, args[1]);
        for (stats.fix_paths, stats.results) |input_path, result| switch (result) {
            .pass => passed_count += 1,
            else => {
                failed_count += 1;
                std.debug.print("{s}: {}\n", .{ input_path, result });
            },
        };
    } else {
        const out_buf = try allocator.alloc(u8, exec.output_buffer_size);
        defer allocator.free(out_buf);
        switch (try exec.execFixture(allocator, &lib, args[1], out_buf)) {
            .pass => passed_count = 1,
            else => |r| {
                std.debug.print("{s}: {}\n", .{ args[1], r });
                failed_count = 1;
            },
        }
    }

    // Print summary
    std.debug.print(
        \\
        \\Total test cases: {d}
        \\Passed: {d}, Failed: {d}, Skipped: 0
        \\
    , .{ passed_count + failed_count, passed_count, failed_count });

    if (failed_count > 0) std.posix.exit(1);
}
