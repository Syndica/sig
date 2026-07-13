const std = @import("std");

const Allocator = std.mem.Allocator;

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

// Paths the linter walks, relative to the repo root (where sig-lint is
// invoked from). "v2/components/runtime" is the embedded runtime component
// that used to be the standalone `shared` package; it now lives inside
// sig itself.
const project_paths = [_][]const u8{
    "build.zig",
    "v2/init",
    "v2/lib",
    "v2/services",
    "v2/tools",
    "v2/components/runtime",
};
const test_inclusion_roots = [_][]const u8{
    "v2/lib/lib.zig",
    "v2/tools/lint/main.zig",
    // The runtime uses a `foo/lib.zig` layout instead of v2's `foo.zig` next
    // to `foo/` convention, so it can't participate in the test_inclusion
    // check without a wholesale restructure of the runtime tree. Its own
    // `comptime { _ = @import("...") }` inclusions in each `lib.zig` cover
    // the same intent.
};

// File-level rules (line_length, unused_declarations) are skipped for files
// under these path prefixes. The runtime component was folded into sig
// wholesale from an external package that never conformed to v2's style
// rules; whitelisting the whole tree here is preferable to a per-file
// waterfall of excluded_paths entries. `test_inclusion` still runs against
// the runtime since it's cheap to satisfy and catches missing companions.
const file_level_lint_exclusions = [_][]const u8{
    "v2/components/runtime/",
};

/// Runs v2 lint and exits with 0 for no diagnostics, 1 for diagnostics, and 2 for CLI or internal
/// errors (lint didn't run at all or failed to finish).
pub fn main() u8 {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    // note: intentionally leaking allocator, OS will cleanup memory on process exit
    const allocator = debug_allocator.allocator();

    const parse_result = cli.parseArgs(allocator) catch |err| {
        switch (err) {
            error.InvalidArguments => {},
            error.OutOfMemory => {
                std.debug.print("OOM parsing args \n", .{});
                if (@errorReturnTrace()) |trace| std.debug.dumpStackTrace(trace.*);
            },
        }
        return 2;
    };
    const config = switch (parse_result) {
        .config => |config| config,
        .help => {
            cli.printHelp();
            return 0;
        },
    };
    var ctx: core.Context = .{ .arena = allocator, .config = config };

    run(&ctx) catch |err| {
        switch (err) {
            error.UncommittedChanges => {
                std.debug.print(
                    "cannot run lint fix mode: there are uncommitted changes\n",
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

    var files = try core.SourceFiles.collectAndReadRecursive(ctx.arena, &project_paths);

    if (ctx.config.verbose) {
        std.debug.print("linting {d} files\n", .{files.items.items.len});
    }

    try line_length.lintExcludedPathsExist(ctx, &files);

    for (files.items.items) |*file| {
        try lintFileLevelRules(ctx, file);
    }

    for (test_inclusion_roots) |root| {
        try test_inclusion.lint(ctx, root, &files);
    }

    if (ctx.config.mode == .fix) {
        for (files.items.items) |*file| {
            if (!file.has_changes) {
                continue;
            }
            if (ctx.config.verbose) {
                std.debug.print("fixing: {s}\n", .{file.path});
            }
            try file.writeIfChanged();
            try core.runZigFmt(ctx.arena, file.path);
        }
    }
}

fn ensureFixModeCleanAtPath(ctx: *const core.Context, cwd: []const u8) !void {
    if (ctx.config.mode != .fix or ctx.config.force) {
        return;
    }
    if (try hasUncommittedChanges(ctx.arena, cwd)) {
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
    if (isFileLevelExcluded(file.path)) return;
    try line_length.lint(ctx, file);
    try unused_declarations.lint(ctx, file);
}

fn isFileLevelExcluded(path: []const u8) bool {
    for (file_level_lint_exclusions) |prefix| {
        if (std.mem.startsWith(u8, path, prefix)) return true;
    }
    return false;
}

test "parse errors report diagnostic and skip file-level rules" {
    const allocator = std.heap.page_allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const source = "const x = ; // 12345678901234567890123456789012345678901234567890" ++
        "12345678901234567890123456789012345678901234567890\n";
    try tmp.dir.writeFile(.{ .sub_path = "parse_error_test.zig", .data = source });
    const path = try tmp.dir.realpathAlloc(allocator, "parse_error_test.zig");

    const config: cli.Config = .{};
    var ctx: core.Context = .{ .arena = allocator, .config = config };

    var file = try core.SourceFile.readAndParse(allocator, path);

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

test "dirty preflight rejects tracked and untracked changes unless force is set" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("v2");
    const repo_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(repo_path);
    const v2_path = try tmp.dir.realpathAlloc(allocator, "v2");
    defer allocator.free(v2_path);
    try tmp.dir.writeFile(.{ .sub_path = "v2/file.zig", .data = "pub const x = 1;\n" });

    try runGit(allocator, repo_path, &.{ "git", "init" });
    try runGit(allocator, repo_path, &.{ "git", "config", "user.email", "lint@example.com" });
    try runGit(allocator, repo_path, &.{ "git", "config", "user.name", "Lint Test" });
    try runGit(allocator, repo_path, &.{ "git", "add", "v2/file.zig" });
    try runGit(allocator, repo_path, &.{ "git", "commit", "-m", "init" });

    try std.testing.expect(!(try hasUncommittedChanges(allocator, v2_path)));

    try tmp.dir.writeFile(.{ .sub_path = "v2/file.zig", .data = "pub const x = 2;\n" });
    try std.testing.expect(try hasUncommittedChanges(allocator, v2_path));

    const config: cli.Config = .{ .mode = .fix };
    var ctx: core.Context = .{ .arena = allocator, .config = config };
    try std.testing.expectError(error.UncommittedChanges, ensureFixModeCleanAtPath(&ctx, v2_path));

    ctx.config.force = true;
    try ensureFixModeCleanAtPath(&ctx, v2_path);

    try runGit(allocator, repo_path, &.{ "git", "add", "v2/file.zig" });
    try runGit(allocator, repo_path, &.{ "git", "commit", "-m", "tracked" });
    try tmp.dir.writeFile(.{ .sub_path = "v2/untracked.zig", .data = "pub const y = 1;\n" });

    try std.testing.expect(try hasUncommittedChanges(allocator, v2_path));
}
