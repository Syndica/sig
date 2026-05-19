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

        // Group results by dirname relative to input path
        const input_prefix = args[1];
        var group_passed: std.StringArrayHashMapUnmanaged(usize) = .empty;
        var group_failed: std.StringArrayHashMapUnmanaged(usize) = .empty;
        defer {
            group_passed.deinit(allocator);
            group_failed.deinit(allocator);
        }

        for (stats.fix_paths, stats.results) |fix_path, result| {
            const rel = relativeTo(fix_path, input_prefix);
            const dir_part = std.fs.path.dirname(rel) orelse ".";
            const passed_gop = try group_passed.getOrPut(allocator, dir_part);
            if (!passed_gop.found_existing) passed_gop.value_ptr.* = 0;
            const failed_gop = try group_failed.getOrPut(allocator, dir_part);
            if (!failed_gop.found_existing) failed_gop.value_ptr.* = 0;
            switch (result) {
                .pass => passed_gop.value_ptr.* += 1,
                else => {
                    std.debug.print("\t{s}: {}\n", .{ fix_path, result });
                    failed_gop.value_ptr.* += 1;
                },
            }
        }

        // Sort keys for deterministic output
        const keys = group_passed.keys();
        const sorted_keys = try allocator.alloc([]const u8, keys.len);
        defer allocator.free(sorted_keys);
        @memcpy(sorted_keys, keys);
        std.mem.sort([]const u8, sorted_keys, {}, struct {
            fn cmp(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.order(u8, a, b) == .lt;
            }
        }.cmp);

        // Find max name length for alignment
        var max_name_len: usize = 0;
        for (sorted_keys) |key| {
            max_name_len = @max(max_name_len, key.len);
        }

        // Print per-group results
        std.debug.print("\n", .{});
        for (sorted_keys) |key| {
            const passed = group_passed.get(key) orelse 0;
            const failed = group_failed.get(key) orelse 0;
            printRow(key, max_name_len, passed, failed);
            passed_count += passed;
            failed_count += failed;
        }
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
        \\Summary:
        \\        Passed:  {d}
        \\        Failed:  {d}
        \\
    , .{ passed_count, failed_count });

    if (failed_count > 0) std.posix.exit(1);
}

fn relativeTo(path: []const u8, prefix: []const u8) []const u8 {
    if (std.mem.startsWith(u8, path, prefix)) {
        return std.mem.trimLeft(u8, path[prefix.len..], "/");
    }
    return path;
}

fn printRow(
    name: []const u8,
    name_width: usize,
    passed: usize,
    failed: usize,
) void {
    const stderr = std.fs.File.stderr().deprecatedWriter();
    stderr.print("{s}", .{name}) catch {};
    stderr.writeByteNTimes(' ', name_width - name.len + 1) catch {};
    stderr.print("│ Pass {d: >5} │ Fail {d: >5}\n", .{
        passed,
        failed,
    }) catch {};
}
