const std = @import("std");

const Allocator = std.mem.Allocator;

pub const Mode = enum { check, fix };

pub const Rule = enum {
    line_length,
    unused_declarations,
    test_inclusion,

    pub fn id(rule: Rule) []const u8 {
        return @tagName(rule);
    }
};

pub const Config = struct {
    mode: Mode = .check,
    force: bool = false,
    verbose: bool = false,
    /// Paths requested with `--path`, exactly as the user wrote them. Empty means the caller
    /// decides which paths to lint. Interpreting and validating these is not this module's job.
    paths: []const []const u8 = &.{},
};

pub const ParseResult = union(enum) {
    config: Config,
    help,
};

pub const ParseArgsError = error{
    InvalidArguments,
    OutOfMemory,
};

/// Parse cli arguments, assumes arena allocator and no memory is freed by this function.
pub fn parseArgs(arena: Allocator) ParseArgsError!ParseResult {
    var args = try std.process.argsWithAllocator(arena);
    _ = args.next();

    var argv: std.ArrayList([]const u8) = .empty;
    while (args.next()) |arg| try argv.append(arena, arg);

    return parseArgSlice(arena, argv.items);
}

/// Parse arguments that have already been collected, excluding the executable name. Assumes
/// arena allocator and no memory is freed by this function.
fn parseArgSlice(arena: Allocator, args: []const []const u8) ParseArgsError!ParseResult {
    var config: Config = .{};
    var paths: std.ArrayList([]const u8) = .empty;

    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const arg = args[index];
        if (std.mem.eql(u8, arg, "--check")) {
            config.mode = .check;
        } else if (std.mem.eql(u8, arg, "--fix")) {
            config.mode = .fix;
        } else if (std.mem.eql(u8, arg, "--force")) {
            config.force = true;
        } else if (std.mem.eql(u8, arg, "--verbose")) {
            config.verbose = true;
        } else if (std.mem.eql(u8, arg, "--path")) {
            // A flag is never treated as the value, otherwise a forgotten value would
            // silently swallow the next option.
            const value = if (index + 1 < args.len) args[index + 1] else "";
            if (value.len == 0 or std.mem.startsWith(u8, value, "-")) {
                log("--path requires a path value\n", .{});
                return error.InvalidArguments;
            }
            try paths.append(arena, value);
            index += 1;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            return .help;
        } else if (std.mem.startsWith(u8, arg, "-")) {
            log("unknown flag: {s}\n", .{arg});
            return error.InvalidArguments;
        } else {
            log("unexpected argument: {s}\n", .{arg});
            return error.InvalidArguments;
        }
    }

    config.paths = paths.items;
    return .{ .config = config };
}

pub fn printHelp() void {
    std.debug.print(
        \\usage: sig-lint [--check|--fix] [--force] [--verbose] [--path <path>]...
        \\
        \\  --check   report diagnostics without changing files (default)
        \\  --fix     apply fixes, requires a clean git tree unless --force is set
        \\  --force   allow fix mode to run with uncommitted changes
        \\  --verbose print progress while linting
        \\  --path    lint this path instead of the default project paths. Repeatable, and
        \\            relative to the repository root. Directories are collected recursively,
        \\            and an explicit file must be a .zig source file.
        \\
    , .{});
}

var should_log_in_test = true;

fn log(comptime fmt: []const u8, args: anytype) void {
    if (!@import("builtin").is_test or should_log_in_test) std.debug.print(fmt, args);
}

fn expectConfig(arena: Allocator, args: []const []const u8) !Config {
    return switch (try parseArgSlice(arena, args)) {
        .config => |config| config,
        .help => error.TestUnexpectedResult,
    };
}

fn expectInvalidArguments(arena: Allocator, args: []const []const u8) !void {
    should_log_in_test = false;
    defer should_log_in_test = true;
    try std.testing.expectError(error.InvalidArguments, parseArgSlice(arena, args));
}

fn expectHelp(arena: Allocator, args: []const []const u8) !void {
    switch (try parseArgSlice(arena, args)) {
        .help => {},
        .config => return error.TestUnexpectedResult,
    }
}

fn expectPaths(expected: []const []const u8, actual: []const []const u8) !void {
    try std.testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |want, got| try std.testing.expectEqualStrings(want, got);
}

test "no arguments produces the default config" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();

    const config = try expectConfig(arena_state.allocator(), &.{});

    try std.testing.expectEqual(Mode.check, config.mode);
    try std.testing.expect(!config.force);
    try std.testing.expect(!config.verbose);
    try std.testing.expectEqual(0, config.paths.len);
}

test "mode and boolean flags are parsed" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const fixing = try expectConfig(arena, &.{ "--fix", "--force", "--verbose" });
    try std.testing.expectEqual(Mode.fix, fixing.mode);
    try std.testing.expect(fixing.force);
    try std.testing.expect(fixing.verbose);

    const checking = try expectConfig(arena, &.{ "--fix", "--check" });
    try std.testing.expectEqual(Mode.check, checking.mode);
}

test "single path is collected" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const config = try expectConfig(arena, &.{ "--path", "tools/lint" });

    try expectPaths(&.{"tools/lint"}, config.paths);
    try std.testing.expectEqual(Mode.check, config.mode);
}

test "path option is repeatable and keeps order" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const config = try expectConfig(arena, &.{ "--path", "v2/lib", "--path", "tools/lint" });

    try expectPaths(&.{ "v2/lib", "tools/lint" }, config.paths);
}

test "flags and paths may be interleaved" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const config = try expectConfig(arena, &.{
        "--verbose",
        "--path",
        "tools/lint",
        "--force",
        "--path",
        "v2/lib",
    });

    try expectPaths(&.{ "tools/lint", "v2/lib" }, config.paths);
    try std.testing.expect(config.verbose);
    try std.testing.expect(config.force);
}

test "path option rejects a missing or flag-like value" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try expectInvalidArguments(arena, &.{"--path"});
    try expectInvalidArguments(arena, &.{ "--path", "" });
    try expectInvalidArguments(arena, &.{ "--path", "--verbose" });
    try expectInvalidArguments(arena, &.{ "--path", "tools/lint", "--path" });
    // The joined form is deliberately unsupported, so it falls through to the unknown flag.
    try expectInvalidArguments(arena, &.{"--path=tools/lint"});
}

test "unknown flags and positional arguments are rejected" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try expectInvalidArguments(arena, &.{"--unknown"});
    try expectInvalidArguments(arena, &.{"tools/lint"});
    try expectInvalidArguments(arena, &.{ "--verbose", "tools/lint" });
}

test "help wins over other arguments" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try expectHelp(arena, &.{"--help"});
    try expectHelp(arena, &.{"-h"});
    try expectHelp(arena, &.{ "--path", "tools/lint", "--help" });
}
