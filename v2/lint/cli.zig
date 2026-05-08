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

    fn parse(value: []const u8) ?Rule {
        inline for (std.meta.fields(Rule)) |field| {
            if (std.mem.eql(u8, value, field.name)) return @enumFromInt(field.value);
        }
        return null;
    }
};

pub const Config = struct {
    mode: Mode = .check,
    force: bool = false,
    verbose: bool = false,
    rules: std.ArrayList(Rule) = .empty,

    pub fn deinit(self: *Config, allocator: Allocator) void {
        self.rules.deinit(allocator);
    }

    pub fn ruleEnabled(self: Config, rule: Rule) bool {
        if (self.rules.items.len == 0) return true;
        for (self.rules.items) |enabled| {
            if (enabled == rule) return true;
        }
        return false;
    }
};

pub const ParseResult = union(enum) {
    config: Config,
    help,
};

pub fn parseArgs(allocator: Allocator) !ParseResult {
    var config: Config = .{};
    errdefer config.deinit(allocator);

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();
    _ = args.next();

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--check")) {
            config.mode = .check;
        } else if (std.mem.eql(u8, arg, "--fix")) {
            config.mode = .fix;
        } else if (std.mem.eql(u8, arg, "--force")) {
            config.force = true;
        } else if (std.mem.eql(u8, arg, "--rule")) {
            const value = args.next() orelse {
                std.debug.print("--rule requires a rule id\n", .{});
                return error.InvalidArguments;
            };
            try config.rules.append(allocator, Rule.parse(value) orelse {
                std.debug.print("unknown rule: {s}\n", .{value});
                return error.InvalidArguments;
            });
        } else if (std.mem.eql(u8, arg, "--verbose")) {
            config.verbose = true;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            config.deinit(allocator);
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
    const rules_list = comptime blk: {
        const fields = std.meta.fields(Rule);
        var text: []const u8 = "";
        for (fields, 0..) |field, i| {
            if (i != 0) text = text ++ ", ";
            text = text ++ field.name;
        }
        break :blk text;
    };

    std.debug.print(
        \\usage: v2-lint [--check|--fix] [--force] [--rule id] [--verbose]
        \\
        \\rules: {s}
        \\
    , .{rules_list});
}
