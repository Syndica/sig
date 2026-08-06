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

// Paths the linter walks, relative to the repo root (where sig-lint is invoked from).
// Used when no paths are requested with `--path`.
const project_paths = [_][]const u8{
    "build.zig",
    "v2/main.zig",
    "v2/services.zig",
    "v2/components",
    "v2/init",
    "v2/lib",
    "v2/services",
    "v2/tests",
    "tools",
};

/// Predefined roots to lint for test inclusion. Does not include dynamically
/// located paths, which are resolved at runtime (looks in v2/components/)
const test_inclusion_static_roots = [_][]const u8{
    "v2/lib/lib.zig",
    "tools/lint/main.zig",
};

/// Directory searched for the component test inclusion roots named by `component_root_files`.
const components_dir_path = "v2/components";

/// The companion files that jointly cover a component directory.
const component_root_files = [_][]const u8{ "api.zig", "component.zig" };

// File-level rules (line_length, unused_declarations) are skipped for files
// under these path prefixes.
const file_level_lint_exclusions = [_][]const u8{};

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
            // resolveLintPaths already explained which path was rejected and why.
            error.InvalidLintPath => {},
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

    const lint_paths = try resolveLintPaths(ctx.arena, ctx.config.paths);

    var files = try core.SourceFiles.collectAndReadRecursive(ctx.arena, lint_paths.all);

    if (ctx.config.verbose) {
        std.debug.print("linting {d} files\n", .{files.items.items.len});
    }

    try line_length.lintExcludedPathsExist(ctx, lint_paths.all, &files);

    for (files.items.items) |*file| {
        try lintFileLevelRules(ctx, file);
    }

    const test_inclusion_roots = try collectTestInclusionRoots(ctx.arena, lint_paths.directories);
    try test_inclusion.lint(ctx, test_inclusion_roots, &files);

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

const NormalizeLintPathError = error{
    LintPathEmpty,
    LintPathAbsolute,
    LintPathEscapesRepository,
    OutOfMemory,
};

const is_windows = @import("builtin").os.tag == .windows;

/// `\` only separates path components on Windows; on POSIX it is a legal filename character.
const path_separators = if (is_windows) "/\\" else "/";

/// A drive designator resolves against a drive rather than the repository root, whether it is
/// drive absolute (`C:\foo`) or drive relative (`C:foo`).
fn hasWindowsDriveDesignator(path: []const u8) bool {
    return path.len >= 2 and path[1] == ':' and std.ascii.isAlphabetic(path[0]);
}

/// Normalizes a requested lint path into the repository relative, forward slash form the rest
/// of the linter compares against. Redundant `.` components, repeated separators and trailing
/// separators are dropped. The repository root itself normalizes to ".".
fn normalizeLintPath(
    arena: std.mem.Allocator,
    path: []const u8,
) NormalizeLintPathError![]const u8 {
    if (path.len == 0) return error.LintPathEmpty;
    if (std.fs.path.isAbsolute(path)) return error.LintPathAbsolute;
    if (is_windows and hasWindowsDriveDesignator(path)) return error.LintPathAbsolute;

    var components: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitAny(u8, path, path_separators);
    while (it.next()) |component| {
        if (component.len == 0) continue;
        if (std.mem.eql(u8, component, ".")) continue;
        // Only a whole `..` component escapes; names like `..foo` are ordinary files.
        if (std.mem.eql(u8, component, "..")) return error.LintPathEscapesRepository;
        try components.append(arena, component);
    }

    if (components.items.len == 0) return ".";
    return try std.mem.join(arena, "/", components.items);
}

const LintPathKind = enum { file, directory };

/// Rejects lint paths the linter cannot walk: paths that do not exist, explicit files that
/// are not zig sources, and anything that is neither a file nor a directory.
fn validateLintPath(path: []const u8) !LintPathKind {
    const kind: std.fs.File.Kind = blk: {
        const stat = std.fs.cwd().statFile(path) catch |err| switch (err) {
            error.IsDir => break :blk .directory,
            error.FileNotFound, error.NotDir => {
                core.log("lint path does not exist: {s}\n", .{path});
                return error.InvalidLintPath;
            },
            else => |e| return e,
        };
        break :blk stat.kind;
    };

    switch (kind) {
        .directory => return .directory,
        .file => {
            if (!std.mem.endsWith(u8, path, ".zig")) {
                core.log("lint path is not a zig source file: {s}\n", .{path});
                return error.InvalidLintPath;
            }
            return .file;
        },
        else => {
            core.log("lint path is neither a file nor a directory: {s}\n", .{path});
            return error.InvalidLintPath;
        },
    }
}

const LintPaths = struct {
    all: []const []const u8,
    /// Test inclusion compares a companion file against its siblings, so only a selected
    /// directory can supply a root. An explicitly selected file gets file level rules only.
    directories: []const []const u8,
};

/// Resolves and validates the paths to walk. Falls back to `project_paths` when nothing was
/// requested, so an argument-free run lints exactly what it always has.
fn resolveLintPaths(
    arena: std.mem.Allocator,
    requested: []const []const u8,
) !LintPaths {
    const use_defaults = requested.len == 0;
    const sources: []const []const u8 = if (use_defaults) &project_paths else requested;

    var all: std.ArrayList([]const u8) = .empty;
    var directories: std.ArrayList([]const u8) = .empty;
    for (sources) |source| {
        const path = if (use_defaults) source else try normalizeRequestedPath(arena, source);
        const kind = try validateLintPath(path);
        try all.append(arena, path);
        if (kind == .directory) try directories.append(arena, path);
    }

    return .{ .all = all.items, .directories = directories.items };
}

fn normalizeRequestedPath(arena: std.mem.Allocator, request: []const u8) ![]const u8 {
    return normalizeLintPath(arena, request) catch |err| {
        switch (err) {
            error.OutOfMemory => return err,
            error.LintPathEmpty => core.log("lint path is empty\n", .{}),
            error.LintPathAbsolute => core.log(
                "lint path must be relative to the repository root: {s}\n",
                .{request},
            ),
            error.LintPathEscapesRepository => core.log(
                "lint path must not contain a '..' component: {s}\n",
                .{request},
            ),
        }
        return error.InvalidLintPath;
    };
}

/// Test inclusion roots that fall inside `lint_dirs`. Walks `v2/components/` and adds each
/// subdir's `{api,component}.zig` as a joint pair of roots.
///
/// Roots are filtered by path rather than by whether their file was collected, so a genuinely
/// missing companion file is still reported instead of being quietly dropped.
fn collectTestInclusionRoots(
    arena: std.mem.Allocator,
    lint_dirs: []const []const u8,
) ![]const []const u8 {
    if (lint_dirs.len == 0) return &.{};

    var roots: std.ArrayList([]const u8) = .empty;
    for (test_inclusion_static_roots) |root| {
        if (core.pathSelectsAny(lint_dirs, root)) try roots.append(arena, root);
    }

    var components_dir = std.fs.cwd().openDir(
        components_dir_path,
        .{ .iterate = true },
    ) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return roots.items,
        else => |e| return e,
    };
    defer components_dir.close();

    var it = components_dir.iterate();
    while (try it.next()) |entry| {
        if (entry.kind != .directory) continue;
        if (std.mem.eql(u8, entry.name, "runtime")) continue;
        for (component_root_files) |file_name| {
            const root = try std.fmt.allocPrint(
                arena,
                "{s}/{s}/{s}",
                .{ components_dir_path, entry.name, file_name },
            );
            if (core.pathSelectsAny(lint_dirs, root)) try roots.append(arena, root);
        }
    }

    return roots.items;
}

fn containsPath(paths: []const []const u8, needle: []const u8) bool {
    for (paths) |path| {
        if (std.mem.eql(u8, path, needle)) return true;
    }
    return false;
}

fn expectNormalized(expected: []const u8, path: []const u8) !void {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();

    const normalized = try normalizeLintPath(arena_state.allocator(), path);
    try std.testing.expectEqualStrings(expected, normalized);
}

fn expectNormalizeError(expected: NormalizeLintPathError, path: []const u8) !void {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();

    try std.testing.expectError(expected, normalizeLintPath(arena_state.allocator(), path));
}

test "lint paths normalize to repository relative form" {
    try expectNormalized("tools/lint", "tools/lint");
    try expectNormalized("tools/lint", "./tools/lint");
    try expectNormalized("tools/lint", "tools/lint/");
    try expectNormalized("tools/lint", "tools//lint");
    try expectNormalized("tools/lint", "./tools/./lint///");
    try expectNormalized("tools/lint/cli.zig", "tools/lint/cli.zig");
    try expectNormalized(".", ".");
    try expectNormalized(".", "./");
    // Only a whole `..` component escapes the repository.
    try expectNormalized("tools/..foo", "tools/..foo");
}

test "backslashes only separate components on windows" {
    if (is_windows) {
        try expectNormalized("tools/lint", "tools\\lint");
    } else {
        try expectNormalized("tools\\lint", "tools\\lint");
    }
}

test "windows drive designators are not repository relative" {
    try std.testing.expect(hasWindowsDriveDesignator("C:foo"));
    try std.testing.expect(hasWindowsDriveDesignator("c:\\foo"));
    try std.testing.expect(!hasWindowsDriveDesignator("tools/lint"));
    try std.testing.expect(!hasWindowsDriveDesignator("2:foo"));

    if (is_windows) {
        try expectNormalizeError(error.LintPathAbsolute, "C:foo");
        try expectNormalizeError(error.LintPathAbsolute, "C:\\foo");
        try expectNormalizeError(error.LintPathAbsolute, "\\\\server\\share");
    }
}

test "lint paths outside the repository are rejected" {
    try expectNormalizeError(error.LintPathEmpty, "");
    try expectNormalizeError(error.LintPathAbsolute, "/tools/lint");
    try expectNormalizeError(error.LintPathEscapesRepository, "..");
    try expectNormalizeError(error.LintPathEscapesRepository, "../outside");
    try expectNormalizeError(error.LintPathEscapesRepository, "tools/../../outside");
    try expectNormalizeError(error.LintPathEscapesRepository, "tools/lint/..");
}

test "no requested paths keeps the default project paths" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();

    const resolved = try resolveLintPaths(arena_state.allocator(), &.{});

    try std.testing.expectEqual(project_paths.len, resolved.all.len);
    for (project_paths, resolved.all) |expected, actual| {
        try std.testing.expectEqualStrings(expected, actual);
    }
}

test "requested paths accept directories and zig files" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const directory = try resolveLintPaths(arena, &.{"./tools/lint/"});
    try std.testing.expectEqual(1, directory.all.len);
    try std.testing.expectEqualStrings("tools/lint", directory.all[0]);
    try std.testing.expectEqual(1, directory.directories.len);
    try std.testing.expectEqualStrings("tools/lint", directory.directories[0]);

    const file = try resolveLintPaths(arena, &.{"tools/lint/cli.zig"});
    try std.testing.expectEqual(1, file.all.len);
    try std.testing.expectEqualStrings("tools/lint/cli.zig", file.all[0]);
    try std.testing.expectEqual(0, file.directories.len);

    const both = try resolveLintPaths(arena, &.{ "tools/lint", "v2/lib" });
    try std.testing.expectEqual(2, both.all.len);
    try std.testing.expectEqualStrings("tools/lint", both.all[0]);
    try std.testing.expectEqualStrings("v2/lib", both.all[1]);

    const root = try resolveLintPaths(arena, &.{"."});
    try std.testing.expectEqual(1, root.all.len);
    try std.testing.expectEqualStrings(".", root.all[0]);
}

test "requested paths reject missing paths and non zig files" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    core.should_log_in_test = false;
    defer core.should_log_in_test = true;

    try std.testing.expectError(
        error.InvalidLintPath,
        resolveLintPaths(arena, &.{"tools/lint/.missing_lint_path.zig"}),
    );
    try std.testing.expectError(
        error.InvalidLintPath,
        resolveLintPaths(arena, &.{"README.md"}),
    );
    try std.testing.expectError(
        error.InvalidLintPath,
        resolveLintPaths(arena, &.{"/tools/lint"}),
    );
    try std.testing.expectError(
        error.InvalidLintPath,
        resolveLintPaths(arena, &.{"../outside"}),
    );
}

test "test inclusion roots are limited to the linted paths" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // A default run keeps every static root and every discovered component root.
    const default_paths = try resolveLintPaths(arena, &.{});
    const defaults = try collectTestInclusionRoots(arena, default_paths.directories);
    for (test_inclusion_static_roots) |root| {
        try std.testing.expect(containsPath(defaults, root));
    }
    try std.testing.expect(containsPath(defaults, "v2/components/gossip/api.zig"));
    try std.testing.expect(containsPath(defaults, "v2/components/gossip/component.zig"));
    try std.testing.expect(!containsPath(defaults, "v2/components/runtime/api.zig"));

    // A directory selects the roots underneath it, and nothing else.
    const scoped = try collectTestInclusionRoots(arena, &.{"tools/lint"});
    try std.testing.expectEqual(1, scoped.len);
    try std.testing.expectEqualStrings("tools/lint/main.zig", scoped[0]);

    const sibling = try collectTestInclusionRoots(arena, &.{"v2/lib/crypto"});
    try std.testing.expectEqual(0, sibling.len);
}

test "an explicit file does not activate test inclusion" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // `tools/lint/main.zig` is itself a static root, but naming it directly asks for file
    // level rules only.
    const file = try resolveLintPaths(arena, &.{"tools/lint/main.zig"});
    const file_roots = try collectTestInclusionRoots(arena, file.directories);
    try std.testing.expectEqual(0, file_roots.len);

    const directory = try resolveLintPaths(arena, &.{"tools/lint"});
    const directory_roots = try collectTestInclusionRoots(arena, directory.directories);
    try std.testing.expectEqual(1, directory_roots.len);
    try std.testing.expectEqualStrings("tools/lint/main.zig", directory_roots[0]);
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
    var env_map: std.process.EnvMap = .init(allocator);
    defer env_map.deinit();

    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv,
        .cwd = cwd,
        // passing an empty map suppresses the environment to prevent git from
        // using the user's git config
        .env_map = &env_map,
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
