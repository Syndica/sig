const std = @import("std");
const build_options = @import("build-options");

const solfuzz_sig = @import("lib.zig");
const exec = @import("exec.zig");

const report_buffer_size: usize = 1024 * 1024 * 1024;

pub fn main() !void {
    const allocator = std.heap.c_allocator;

    // Parse args
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var failure_report_dir: ?[]const u8 = null;
    var positional: [2][]const u8 = undefined;
    var positional_count: usize = 0;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--failure-report-dir")) {
            i += 1;
            if (i >= args.len) usage();
            failure_report_dir = args[i];
        } else {
            if (positional_count == positional.len) usage();
            positional[positional_count] = args[i];
            positional_count += 1;
        }
    }
    if (positional_count < 1) usage();

    const input_path = positional[0];
    const target_path = if (positional_count == 2) positional[1] else null;

    // Get the library to test
    var lib: exec.Library = if (target_path) |path| .{
        .dyn = try .open(path),
    } else if (build_options.include_sig) .{
        .map = &solfuzz_sig.entrypoints,
    } else {
        std.debug.print("No lib provided. Build with sig or provide a target path\n", .{});
        std.posix.exit(2);
    };
    defer if (lib == .dyn) lib.dyn.close();

    // var report_buffer: ?[]u8 = null;
    // defer if (report_buffer) |buffer| allocator.free(buffer);
    // var report_fba: std.heap.FixedBufferAllocator = undefined;
    // const report_allocator = if (failure_report_dir != null) blk: {
    //     const buffer = try allocator.alloc(u8, report_buffer_size);
    //     report_buffer = buffer;
    //     report_fba = std.heap.FixedBufferAllocator.init(buffer);
    //     break :blk report_fba.threadSafeAllocator();
    // } else null;
    // const report_allocator = std.heap.c_allocator;
    // _ = report_allocator; // autofix

    // Run the tests
    var passed_count: usize = 0;
    var failed_count: usize = 0;
    const stat = try std.fs.cwd().statFile(input_path);
    if (stat.kind == .directory) {
        var stats = try exec.execDir(allocator, allocator, &lib, input_path);
        defer stats.deinit(allocator);

        // Group results by dirname relative to input path
        const input_prefix = input_path;
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

        if (failure_report_dir) |output_dir| {
            if (stats.details) |details| try writeFailureReports(output_dir, details);
        }
    } else {
        const out_buf = try allocator.alloc(u8, exec.output_buffer_size);
        defer allocator.free(out_buf);

        var detail: ?exec.ResultDetail = null;

        switch (try exec.execFixture(
            allocator,
            allocator,
            &lib,
            input_path,
            out_buf,
            if (failure_report_dir != null) &detail else null,
        )) {
            .pass => passed_count = 1,
            else => |r| {
                std.debug.print("{s}: {}\n", .{ input_path, r });
                failed_count = 1;
            },
        }

        if (failure_report_dir) |output_dir| {
            if (detail != null) {
                const details = [_]?exec.ResultDetail{detail.?};
                try writeFailureReports(output_dir, &details);
            }
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

fn usage() noreturn {
    std.debug.print("usage: exec [--failure-report-dir <dir>] <fix-file-or-dir> [target-path]\n", .{});
    std.posix.exit(2);
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

pub fn writeFailureReports(
    output_dir_path: []const u8,
    details: []const ?exec.ResultDetail,
) !void {
    try std.fs.cwd().makePath(output_dir_path);
    var output_dir = try std.fs.cwd().openDir(output_dir_path, .{});
    defer output_dir.close();

    const expected = try output_dir.createFile("expected.json", .{});
    defer expected.close();
    var expected_buf: [4096]u8 = undefined;
    var expected_writer = expected.writer(&expected_buf);
    var expected_stringify: std.json.Stringify = .{
        .writer = &expected_writer.interface,
        .options = .{ .whitespace = .indent_4 },
    };

    const actual = try output_dir.createFile("actual.json", .{});
    defer actual.close();
    var actual_buf: [4096]u8 = undefined;
    var actual_writer = actual.writer(&actual_buf);
    var actual_stringify: std.json.Stringify = .{
        .writer = &actual_writer.interface,
        .options = .{ .whitespace = .indent_4 },
    };

    try expected_stringify.beginArray();
    try actual_stringify.beginArray();

    for (details) |detail| {
        if (detail) |d| {
            switch (d) {
                inline else => |fields| {
                    const X = struct {
                        harness: []const u8,
                        value: @TypeOf(fields.actual),
                        pub const _desc_table = .{
                            .harness = @import("protobuf").fd(1, .{ .scalar = .string }),
                            .value = @import("protobuf").fd(2, .{ .scalar = .bytes }),
                        };
                    };
                    try expected_stringify.beginObject();
                    try actual_stringify.beginObject();
                    
                    try expected_stringify.endObject();
                    try actual_stringify.endObject();

                    try writeJson(X{
                        .harness = fields.harness,
                        .value = fields.expected,
                    }, &expected_stringify, null);
                    try writeJson(X{
                        .harness = fields.harness,
                        .value = fields.actual,
                    }, &actual_stringify, null);
                },
            }
        }
    }

    try expected_stringify.endArray();
    try actual_stringify.endArray();

    try expected_writer.interface.flush();
    try actual_writer.interface.flush();
}

pub fn writeJson(v: anytype, jws: anytype, comptime ftype: ?@import("protobuf").FieldType) !void {
    const T = @TypeOf(v);
    if (T == []const u8) {
        if (ftype.?.scalar == .string) {
            try jws.write(v);
        } else if (v.len <= 512) {
            try jws.beginWriteRaw();
            defer jws.endWriteRaw();
            try jws.writer.writeByte('"');
            try std.base64.standard.Encoder.encodeWriter(jws.writer, v);
            try jws.writer.writeByte('"');
        } else {
            var hash: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(v, &hash, .{});
            const hash_hex = std.fmt.bytesToHex(hash, .lower);
            var buf: [128]u8 = @splat(0);
            const s = try std.fmt.bufPrint(&buf, "len: {d}, sha256: {s}", .{ v.len, hash_hex });
            try jws.beginWriteRaw();
            defer jws.endWriteRaw();
            try std.json.Stringify.encodeJsonString(s, jws.options, jws.writer);
        }
    } else switch (@typeInfo(T)) {
        .optional => if (v) |value| try writeJson(value, jws, ftype) else try jws.write(v),
        .@"struct" => |s| {
            try jws.beginObject();
            inline for (s.fields) |field| {
                const value = @field(v, field.name);
                try jws.objectField(field.name);
                if (@typeInfo(field.type) == .@"struct" and
                    @hasField(field.type, "items") and @hasField(field.type, "capacity"))
                {
                    try jws.beginArray();
                    for (value.items) |*account| try writeJson(account.*, jws, null);
                    try jws.endArray();
                } else try writeJson(value, jws, @field(T._desc_table, field.name).ftype);
            }
            try jws.endObject();
        },

        else => try jws.write(v),
    }
}
