const std = @import("std");

const cli = @import("cli.zig");
const core = @import("core.zig");
const line_length = @import("line_length.zig");
const test_inclusion = @import("test_inclusion.zig");
const unused_declarations = @import("unused_declarations.zig");

comptime {
    if (@import("builtin").is_test) {
        _ = @import("cli.zig");
        _ = @import("core.zig");
        _ = @import("line_length.zig");
        _ = @import("test_inclusion.zig");
        _ = @import("unused_declarations.zig");
    }
}

const project_paths = [_][]const u8{ "build.zig", "init", "lib", "lint", "services" };
const test_inclusion_roots = [_][]const u8{ "lib/lib.zig", "lint/main.zig" };

/// Runs v2 lint and exits with 0 for no diagnostics, 1 for diagnostics, and 2 for CLI or internal
/// errors (lint didn't run at all or failed to finish).
pub fn main() u8 {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    const parse_result = cli.parseArgs(allocator) catch |err| {
        switch (err) {
            error.InvalidArguments => {},
            else => {
                std.debug.print("unexpected lint CLI error: {s}\n", .{@errorName(err)});
                if (@errorReturnTrace()) |trace| std.debug.dumpStackTrace(trace.*);
            },
        }
        return 2;
    };
    var config = switch (parse_result) {
        .config => |config| config,
        .help => {
            cli.printHelp();
            return 0;
        },
    };
    defer config.deinit(allocator);

    var ctx: core.Context = .{ .allocator = allocator, .config = config };
    defer ctx.deinit();

    run(&ctx) catch |err| {
        switch (err) {
            error.UncommittedChanges => {
                std.debug.print(
                    "cannot run lint fix mode: there are uncommitted changes/\n",
                    .{},
                );
            },
            else => {
                std.debug.print("lint internal error: {s}\n", .{@errorName(err)});
                if (@errorReturnTrace()) |trace| std.debug.dumpStackTrace(trace.*);
            },
        }
        return 2;
    };

    core.printDiagnostics(ctx.diagnostics.items) catch |err| {
        std.debug.print("failed to print diagnostics: {s}\n", .{@errorName(err)});
        if (@errorReturnTrace()) |trace| std.debug.dumpStackTrace(trace.*);
        return 2;
    };
    if (ctx.diagnostics.items.len == 0) return 0;
    return 1;
}

fn run(ctx: *core.Context) !void {
    try ensureFixModeCleanAtPath(ctx, ".");

    var files = try core.SourceFiles.collectAndReadRecursive(ctx.allocator, &project_paths);
    defer files.deinit();

    if (ctx.config.verbose) {
        std.debug.print("lint files: {d}\n", .{files.items.items.len});
    }

    if (ctx.config.ruleEnabled(.line_length)) {
        try line_length.lintExcludedPathsExist(ctx, &files);
    }

    if (ctx.config.ruleEnabled(.line_length) or ctx.config.ruleEnabled(.unused_declarations)) {
        for (files.items.items) |*file| {
            try lintFileLevelRules(ctx, file);
        }
    }

    if (ctx.config.ruleEnabled(.test_inclusion)) {
        for (test_inclusion_roots) |root| {
            try test_inclusion.lint(ctx, root, &files);
        }
    }

    if (ctx.config.mode == .fix) {
        try files.writeChanged();
        try files.fmtChanged(ctx.allocator);
    }
}

fn ensureFixModeCleanAtPath(ctx: *const core.Context, cwd: []const u8) !void {
    if (ctx.config.mode != .fix or ctx.config.force) {
        return;
    }
    if (try hasUncommittedChanges(ctx.allocator, cwd)) {
        return error.UncommittedChanges;
    }
}

fn hasUncommittedChanges(allocator: std.mem.Allocator, cwd: []const u8) !bool {
    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{
            "git",
            "status",
            "--porcelain",
            "--untracked-files=all",
            "--",
            ".",
        },
        .cwd = cwd,
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    if (result.term != .Exited or result.term.Exited != 0) {
        return error.GitStatusFailed;
    }
    return result.stdout.len != 0;
}

fn lintFileLevelRules(ctx: *core.Context, file: *core.SourceFile) !void {
    if (file.hasParseErrors()) {
        try ctx.addDiagnosticId(file.path, 1, 1, core.parse_errors_diagnostic_id, "parse error");
        return;
    }

    if (ctx.config.ruleEnabled(.line_length)) {
        try line_length.lint(ctx, file);
    }
    if (ctx.config.ruleEnabled(.unused_declarations)) {
        try unused_declarations.lint(ctx, file);
    }
}

test "parse errors report diagnostic and skip file-level rules" {
    const allocator = std.testing.allocator;
    const path = "lint/.tmp_parse_error_test.zig";
    const source = "const x = ; // 12345678901234567890123456789012345678901234567890" ++
        "12345678901234567890123456789012345678901234567890\n";
    try std.fs.cwd().writeFile(.{ .sub_path = path, .data = source });
    defer std.fs.cwd().deleteFile(path) catch {};

    var config: cli.Config = .{};
    defer config.deinit(allocator);
    try config.rules.append(allocator, .line_length);
    var ctx: core.Context = .{ .allocator = allocator, .config = config };
    defer ctx.deinit();

    var file = try core.SourceFile.readAndParse(allocator, path);
    defer file.deinit(allocator);

    try lintFileLevelRules(&ctx, &file);

    try std.testing.expectEqual(1, ctx.diagnostics.items.len);
    try std.testing.expectEqualStrings(
        core.parse_errors_diagnostic_id,
        ctx.diagnostics.items[0].rule_id,
    );
    try std.testing.expectEqualStrings("parse error", ctx.diagnostics.items[0].message);
}

fn runGit(allocator: std.mem.Allocator, cwd: []const u8, argv: []const []const u8) !void {
    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv,
        .cwd = cwd,
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    if (result.term != .Exited or result.term.Exited != 0) {
        std.debug.print("git command failed in {s}: {s}\n", .{ cwd, result.stderr });
        return error.GitCommandFailed;
    }
}

fn tempRepoPaths(
    allocator: std.mem.Allocator,
    sub_path: []const u8,
) !struct { repo: []u8, v2: []u8 } {
    const repo = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/repo", .{sub_path});
    errdefer allocator.free(repo);
    const v2 = try std.fmt.allocPrint(allocator, "{s}/v2", .{repo});
    errdefer allocator.free(v2);
    return .{ .repo = repo, .v2 = v2 };
}

test "dirty preflight rejects tracked and untracked changes unless force is set" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const paths = try tempRepoPaths(allocator, tmp.sub_path[0..]);
    defer allocator.free(paths.repo);
    defer allocator.free(paths.v2);

    try tmp.dir.makePath("repo/v2");
    try tmp.dir.writeFile(.{ .sub_path = "repo/v2/file.zig", .data = "pub const x = 1;\n" });

    try runGit(allocator, paths.repo, &.{ "git", "init" });
    try runGit(allocator, paths.repo, &.{ "git", "config", "user.email", "lint@example.com" });
    try runGit(allocator, paths.repo, &.{ "git", "config", "user.name", "Lint Test" });
    try runGit(allocator, paths.repo, &.{ "git", "add", "v2/file.zig" });
    try runGit(allocator, paths.repo, &.{ "git", "commit", "-m", "init" });

    try std.testing.expect(!(try hasUncommittedChanges(allocator, paths.v2)));

    try tmp.dir.writeFile(.{ .sub_path = "repo/v2/file.zig", .data = "pub const x = 2;\n" });
    try std.testing.expect(try hasUncommittedChanges(allocator, paths.v2));

    var config: cli.Config = .{ .mode = .fix };
    defer config.deinit(allocator);
    var ctx: core.Context = .{ .allocator = allocator, .config = config };
    defer ctx.deinit();
    try std.testing.expectError(error.UncommittedChanges, ensureFixModeCleanAtPath(&ctx, paths.v2));

    ctx.config.force = true;
    try ensureFixModeCleanAtPath(&ctx, paths.v2);

    try runGit(allocator, paths.repo, &.{ "git", "add", "v2/file.zig" });
    try runGit(allocator, paths.repo, &.{ "git", "commit", "-m", "tracked" });
    try tmp.dir.writeFile(.{ .sub_path = "repo/v2/untracked.zig", .data = "pub const y = 1;\n" });

    try std.testing.expect(try hasUncommittedChanges(allocator, paths.v2));
}
