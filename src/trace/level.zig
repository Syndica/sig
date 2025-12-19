pub const std = @import("std");

pub const Level = enum {
    /// Error: something has gone wrong. This might be recoverable or might
    /// be followed by the program exiting.
    err,
    /// Warning: it is uncertain if something has gone wrong or not, but the
    /// circumstances would be worth investigating.
    warn,
    /// Info: general messages about the state of the program.
    info,
    /// Debug: messages only useful for debugging.
    debug,
    /// Trace: fine-grained messages that track execution flow.
    trace,

    /// Returns a string literal of the given level in full text form.
    pub fn asText(self: Level) []const u8 {
        return switch (self) {
            .err => "error",
            .warn => "warn",
            .info => "info",
            .debug => "debug",
            .trace => "trace",
        };
    }

    pub fn parse(string: []const u8) !Level {
        // zig fmt: off
        return 
            if (std.mem.eql(u8, string, "error")) .err   else
            if (std.mem.eql(u8, string, "warn"))  .warn  else
            if (std.mem.eql(u8, string, "info"))  .info  else
            if (std.mem.eql(u8, string, "debug")) .debug else
            if (std.mem.eql(u8, string, "trace")) .trace else
            error.InvalidLogLevel;
        // zig fmt: on
    }
};

pub const Filters = struct {
    /// The filter to use by default for scopes not explicitly listed in `scopes`.
    root: Level = default_level,
    /// Filters to apply for specific scopes.
    scopes: []const ScopeFilter = &.{},

    const ScopeFilter = struct {
        name: []const u8,
        level: Level,
    };

    const default_level: Level = .info;

    pub const err: Filters = .{ .root = .err };
    pub const warn: Filters = .{ .root = .warn };
    pub const info: Filters = .{ .root = .info };
    pub const debug: Filters = .{ .root = .debug };
    pub const trace: Filters = .{ .root = .trace };

    pub fn deinit(self: *const Filters, allocator: std.mem.Allocator) void {
        for (self.scopes) |scope| allocator.free(scope.name);
        allocator.free(self.scopes);
    }

    pub fn level(self: *const Filters, scope: []const u8) Level {
        for (self.scopes) |scope_level| {
            // match exact
            if (std.mem.eql(u8, scope_level.name, scope)) return scope_level.level;

            // match prefix with a dot. For example, the "net" filter matches
            // scope "net.http" but not scope "network"
            if (std.mem.startsWith(u8, scope, scope_level.name) and
                scope_level.name.len < scope.len and
                scope[scope_level.name.len] == '.') return scope_level.level;
        }
        return self.root;
    }

    pub const ParseError = error{
        OutOfMemory,
        InvalidLogLevel,
        DuplicateDefaultFilter,
        DuplicateScopeFilter,
    };

    pub fn parse(allocator: std.mem.Allocator, string: []const u8) ParseError!Filters {
        var scopes: std.ArrayListUnmanaged(ScopeFilter) = .{};
        errdefer {
            for (scopes.items) |scope| allocator.free(scope.name);
            scopes.deinit(allocator);
        }

        var main_filter: ?Level = null;
        var filters = std.mem.tokenizeScalar(u8, string, ',');
        while (filters.next()) |filter| {
            if (filter.len == 0) continue;
            if (std.mem.lastIndexOfLinear(u8, filter, "=")) |eq_index| {
                const scope = try allocator.dupe(u8, filter[0..eq_index]);
                errdefer allocator.free(scope);
                for (scopes.items) |existing_scope| {
                    if (std.mem.eql(u8, existing_scope.name, scope)) {
                        return error.DuplicateScopeFilter;
                    }
                }
                try scopes.append(allocator, .{
                    .name = scope,
                    .level = try .parse(filter[eq_index + 1 ..]),
                });
            } else if (main_filter == null) {
                main_filter = try .parse(filter);
            } else return error.DuplicateDefaultFilter;
        }

        return .{
            .root = if (main_filter) |f| f else default_level,
            .scopes = try scopes.toOwnedSlice(allocator),
        };
    }
};

test "Filters.parse happy path" {
    const allocator = std.testing.allocator;

    const filter_str = "debug,net=info,db=error";
    const filters = try Filters.parse(allocator, filter_str);
    defer filters.deinit(allocator);

    try std.testing.expect(filters.root == .debug);
    try std.testing.expect(filters.scopes.len == 2);
    try std.testing.expect(filters.level("net") == .info);
    try std.testing.expect(filters.level("db") == .err);
    try std.testing.expect(filters.level("other") == .debug);
}

test "Filters.parse invalid level" {
    const allocator = std.testing.allocator;

    const filter_str = "debug,net=invalid,db=error";
    const parse_result = Filters.parse(allocator, filter_str);
    try std.testing.expectError(error.InvalidLogLevel, parse_result);
}

test "Filters.parse duplicate default filter is invalid" {
    const allocator = std.testing.allocator;

    const filter_str = "debug,info,net=error";
    const parse_result = Filters.parse(allocator, filter_str);
    try std.testing.expectError(error.DuplicateDefaultFilter, parse_result);
}

test "Filters.parse no scopes" {
    const allocator = std.testing.allocator;

    const filter_str = "warn";
    const filters = try Filters.parse(allocator, filter_str);
    defer filters.deinit(allocator);

    try std.testing.expect(filters.root == .warn);
    try std.testing.expect(filters.level("anyscope") == .warn);
}

test "Filters.parse empty string uses default" {
    const allocator = std.testing.allocator;

    const filter_str = "";
    const filters = try Filters.parse(allocator, filter_str);

    try std.testing.expect(filters.root == .info);
    try std.testing.expect(filters.scopes.len == 0);
    try std.testing.expect(filters.level("net") == .info);
    try std.testing.expect(filters.level("db") == .info);
    try std.testing.expect(filters.level("other") == .info);
}

test "Filters.parse only scopes defaults to info" {
    const allocator = std.testing.allocator;

    const filter_str = "net=info,db=error";
    const filters = try Filters.parse(allocator, filter_str);
    defer filters.deinit(allocator);

    try std.testing.expect(filters.root == .info);
    try std.testing.expect(filters.scopes.len == 2);
    try std.testing.expect(filters.level("net") == .info);
    try std.testing.expect(filters.level("db") == .err);
    try std.testing.expect(filters.level("other") == .info);
}

test "Filters.parse extra commas are fine" {
    const allocator = std.testing.allocator;

    const filter_str = ",,debug,,net=info,,";
    const filters = try Filters.parse(allocator, filter_str);
    defer filters.deinit(allocator);

    try std.testing.expect(filters.root == .debug);
    try std.testing.expect(filters.scopes.len == 1);
    try std.testing.expect(filters.level("net") == .info);
    try std.testing.expect(filters.level("db") == .debug);
    try std.testing.expect(filters.level("other") == .debug);
}

test "Filters.parse duplicate scope is invalid" {
    const allocator = std.testing.allocator;

    const filter_str = "debug,net=info,net=error";
    const parse_result = Filters.parse(allocator, filter_str);
    try std.testing.expectError(error.DuplicateScopeFilter, parse_result);
}

test "Filters.parse scopes with spaces are valid" {
    const allocator = std.testing.allocator;

    const filter_str = "debug,the network=info,db=error";
    const filters = try Filters.parse(allocator, filter_str);
    defer filters.deinit(allocator);

    try std.testing.expect(filters.root == .debug);
    try std.testing.expect(filters.scopes.len == 2);
    try std.testing.expect(filters.level("the network") == .info);
    try std.testing.expect(filters.level("db") == .err);
    try std.testing.expect(filters.level("other") == .debug);
}

test "Filters.parse scopes with = are valid" {
    const allocator = std.testing.allocator;

    const filter_str = "debug,the=network=info,db=error";
    const filters = try Filters.parse(allocator, filter_str);
    defer filters.deinit(allocator);

    try std.testing.expect(filters.root == .debug);
    try std.testing.expect(filters.scopes.len == 2);
    try std.testing.expect(filters.level("the=network") == .info);
    try std.testing.expect(filters.level("db") == .err);
    try std.testing.expect(filters.level("other") == .debug);
}

test "Filters.parse prefixes work" {
    const allocator = std.testing.allocator;

    const filter_str = "debug,net=info,db=error";
    const filters = try Filters.parse(allocator, filter_str);
    defer filters.deinit(allocator);

    try std.testing.expect(filters.root == .debug);
    try std.testing.expect(filters.scopes.len == 2);
    try std.testing.expect(filters.level("net") == .info);
    try std.testing.expect(filters.level("net.http") == .info);
    try std.testing.expect(filters.level("network") == .debug);
    try std.testing.expect(filters.level("db") == .err);
    try std.testing.expect(filters.level("other") == .debug);
}
