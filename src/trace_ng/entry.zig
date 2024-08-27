const std = @import("std");
const Level = @import("level.zig").Level;
const logfmt = @import("logfmt.zig");

pub const Entry = union(enum) {
    standard: StdEntry,
    noop: NoopEntry,

    pub fn log(self: Entry, msg: []const u8) void {
        switch (self) {
            .standard => |standard| standard.log(msg),
            .noop => unreachable(),
        }
    }

    pub fn add(self: Entry, key: []const u8, value: []const u8) Entry {
        switch (self) {
            .standard => |standard| {
                return .{ .standard = standard.add(key, value) };
            },
            .noop => unreachable(),
        }
    }
};

pub const StdEntry = struct {
    // TODO: The size of the bounded array can be made configurable.
    field_buf: std.BoundedArray(u8, 64),
    scope: ?[]const u8,
    level: Level,
    pub fn init(comptime scope: ?type, level: Level) StdEntry {
        return .{ .field_buf = std.BoundedArray(u8, 64).init(32) catch unreachable(), .scope = blk: {
            if (scope) |s| {
                break :blk @typeName(s);
            } else {
                break :blk null;
            }
        }, .level = level };
    }

    pub fn add(self: StdEntry, key: []const u8, value: []const u8) StdEntry {
        var buff = self.field_buf;
        buff.appendSlice(key) catch unreachable();
        buff.appendSlice("=") catch unreachable();
        buff.appendSlice(value) catch unreachable();
        buff.appendSlice(" ") catch unreachable();
        return StdEntry{ .field_buf = buff, .scope = self.scope, .level = self.level };
    }

    pub fn log(self: StdEntry, msg: []const u8) void {
        // TODO: The output the entry writes to should be configurable.
        const stderr = std.io.getStdErr().writer();
        logfmt.formatter(
            stderr,
            self.level,
            self.scope,
            self.field_buf.constSlice(),
            msg,
            null,
            null,
            null,
        ) catch unreachable();
    }
};

pub const NoopEntry = struct {};
