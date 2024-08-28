const std = @import("std");

const JsonParseOptions = std.json.ParseOptions;

pub const Request = struct {
    id: u64 = 1,
    jsonrpc: []const u8 = "2.0",
    method: []const u8,
    params: ?[]const u8 = null,
    parse_options: JsonParseOptions = .{},

    pub fn toJsonString(self: Request, allocator: std.mem.Allocator) ![]const u8 {
        if (self.params) |params|
            return try std.fmt.allocPrint(
                allocator,
                "{{\"id\":{},\"jsonrpc\":\"{s}\",\"method\":\"{s}\",\"params\":{s}}}",
                .{
                    self.id,
                    self.jsonrpc,
                    self.method,
                    params,
                },
            );
        return try std.fmt.allocPrint(
            allocator,
            "{{\"id\":{d},\"jsonrpc\":\"{s}\",\"method\":\"{s}\"}}",
            .{
                self.id,
                self.jsonrpc,
                self.method,
            },
        );
    }

    pub const ParamsBuilder = struct {
        allocator: std.mem.Allocator,
        array: std.ArrayList([]const u8),

        pub fn init(allocator: std.mem.Allocator) ParamsBuilder {
            return .{
                .allocator = allocator,
                .array = std.ArrayList([]const u8).init(allocator),
            };
        }

        pub fn addArgument(self: *ParamsBuilder, comptime fmt: []const u8, arg: anytype) !void {
            try self.array.append(try std.fmt.allocPrint(self.allocator, fmt, .{arg}));
        }

        pub fn addOptionalArgument(self: *ParamsBuilder, comptime fmt: []const u8, maybe_arg: anytype) !void {
            if (maybe_arg) |arg| {
                try self.array.append(try std.fmt.allocPrint(self.allocator, fmt, .{arg}));
            }
        }

        pub fn addConfig(self: *ParamsBuilder, config: anytype) !void {
            const config_string = try std.json.stringifyAlloc(
                self.allocator,
                config,
                .{ .emit_null_optional_fields = false },
            );
            if (!std.mem.eql(u8, config_string, "{}")) {
                try self.array.append(try std.fmt.allocPrint(self.allocator, "{s}", .{config_string}));
            }
        }

        pub fn build(self: *ParamsBuilder) !?[]const u8 {
            if (self.array.items.len == 0) return null;
            // TODO: Replace hacky solution with proper json serialization
            var params = try std.fmt.allocPrint(self.allocator, "{s}", .{self.array.items});
            params[0] = '[';
            params[params.len - 1] = ']';
            return params;
        }
    };
};
