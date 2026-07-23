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
    var config: Config = .{};

    var args = try std.process.argsWithAllocator(arena);
    _ = args.next();

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--check")) {
            config.mode = .check;
        } else if (std.mem.eql(u8, arg, "--fix")) {
            config.mode = .fix;
        } else if (std.mem.eql(u8, arg, "--force")) {
            config.force = true;
        } else if (std.mem.eql(u8, arg, "--verbose")) {
            config.verbose = true;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            return .help;
        } else if (std.mem.startsWith(u8, arg, "-")) {
            std.debug.print("unknown flag: {s}\n", .{arg});
            return error.InvalidArguments;
        } else {
            std.debug.print("unexpected argument: {s}\n", .{arg});
            return error.InvalidArguments;
        }
    }

    return .{ .config = config };
}

pub fn printHelp() void {
    std.debug.print(
        \\usage: v2-lint [--check|--fix] [--force] [--verbose]
        \\
    , .{});
}
