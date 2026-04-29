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
    var total_passed: usize = 0;
    var total_failed: usize = 0;
    var total_skipped: usize = 0;
    const stat = try std.fs.cwd().statFile(args[1]);

    if (stat.kind == .directory) {
        // Discover leaf directories containing .fix files
        var group_dirs: std.ArrayList([]const u8) = .empty;
        defer {
            for (group_dirs.items) |p| allocator.free(p);
            group_dirs.deinit(allocator);
        }
        {
            var dir = try std.fs.cwd().openDir(args[1], .{ .iterate = true });
            defer dir.close();
            var walker = try dir.walk(allocator);
            defer walker.deinit();
            var seen: std.StringArrayHashMapUnmanaged(void) = .empty;
            defer {
                for (seen.keys()) |k| allocator.free(k);
                seen.deinit(allocator);
            }
            while (try walker.next()) |entry| {
                if (entry.kind != .file) continue;
                if (!std.mem.eql(u8, std.fs.path.extension(entry.path), ".fix")) continue;
                // Get the directory portion of this entry's relative path
                const dir_part = std.fs.path.dirname(entry.path) orelse "";
                const group_rel = if (dir_part.len > 0) dir_part else ".";
                const gop = try seen.getOrPut(allocator, try allocator.dupe(u8, group_rel));
                if (!gop.found_existing) {
                    const full_path = try std.fs.path.join(allocator, &.{ args[1], group_rel });
                    try group_dirs.append(allocator, full_path);
                }
            }
        }

        // Sort for deterministic order
        std.mem.sort([]const u8, group_dirs.items, {}, struct {
            fn cmp(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.order(u8, a, b) == .lt;
            }
        }.cmp);

        // Find max name length for alignment (use relative path for display)
        const input_prefix = args[1];
        var max_name_len: usize = 0;
        for (group_dirs.items) |gd| {
            const rel = relativeTo(gd, input_prefix);
            max_name_len = @max(max_name_len, rel.len);
        }

        // Run each group and print immediately
        std.debug.print("\n", .{});
        for (group_dirs.items) |group_path| {
            const display_name = relativeTo(group_path, input_prefix);
            const stats = exec.execDir(allocator, &lib, group_path) catch |e| {
                std.debug.print("{s}: error: {}\n", .{ display_name, e });
                continue;
            };
            var passed: usize = 0;
            var failed: usize = 0;
            var skipped: usize = 0;
            for (stats.results) |result| switch (result) {
                .pass => passed += 1,
                .missing_entrypoint => skipped += 1,
                else => failed += 1,
            };
            printRow(display_name, max_name_len, passed, failed, skipped);
            total_passed += passed;
            total_failed += failed;
            total_skipped += skipped;
        }
    } else {
        const out_buf = try allocator.alloc(u8, exec.output_buffer_size);
        defer allocator.free(out_buf);
        switch (try exec.execFixture(allocator, &lib, args[1], out_buf)) {
            .pass => total_passed = 1,
            .missing_entrypoint => total_skipped = 1,
            else => total_failed = 1,
        }
    }

    // Print summary
    std.debug.print(
        \\
        \\Summary:
        \\        Passed:  {d}
        \\        Failed:  {d}
        \\        Skipped: {d}
        \\
        \\
    , .{ total_passed, total_failed, total_skipped });

    if (total_failed > 0) std.posix.exit(1);
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
    skipped: usize,
) void {
    const stderr = std.fs.File.stderr().deprecatedWriter();
    stderr.print("{s}", .{name}) catch {};
    stderr.writeByteNTimes(' ', name_width - name.len + 1) catch {};
    stderr.print("│ Pass {d: >5} │ Fail {d: >5} │ Skip {d: >5}\n", .{
        passed,
        failed,
        skipped,
    }) catch {};
}
