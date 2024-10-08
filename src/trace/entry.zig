const std = @import("std");
const logfmt = @import("logfmt.zig");
const Level = @import("level.zig").Level;
const Channel = @import("../sync/channel.zig").Channel;
const AtomicBool = std.atomic.Value(bool);

pub const Entry = union(enum) {
    channel_print: ChannelPrintEntry,
    direct_print: DirectPrintEntry,
    noop,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, channel: *Channel(logfmt.LogMsg), log_level: Level) Self {
        return .{ .channel_print = ChannelPrintEntry.init(allocator, channel, log_level) };
    }

    pub fn deinit(self: Self) void {
        switch (self) {
            .noop => {},
            .channel_print => |impl| impl.deinit(),
            .direct_print => |impl| impl.deinit(),
        }
    }

    pub fn field(self: Self, name: []const u8, value: anytype) Self {
        switch (self) {
            .noop => {
                return self;
            },
            .channel_print => |entry| {
                var log_entry = entry;
                _ = log_entry.field(name, value);
                return Entry{ .channel_print = log_entry };
            },
            .direct_print => |entry| {
                var log_entry = entry;
                _ = log_entry.field(name, value);
                return Entry{ .direct_print = log_entry };
            },
        }
    }

    pub fn log(self: Self, comptime msg: []const u8) void {
        switch (self) {
            .noop => {},
            .channel_print => |impl| {
                var logger = impl;
                logger.log(msg);
            },
            .direct_print => |impl| {
                var logger = impl;
                logger.log(msg);
            },
        }
    }

    pub fn logf(self: Self, comptime fmt: []const u8, args: anytype) void {
        switch (self) {
            .noop => {},
            .channel_print => |impl| {
                var logger = impl;
                logger.logf(fmt, args);
            },
            .direct_print => |impl| {
                var logger = impl;
                logger.logf(fmt, args);
            },
        }
    }
};

pub const ChannelPrintEntry = struct {
    allocator: std.mem.Allocator,
    scope: ?[]const u8,
    log_level: Level,
    fields: std.ArrayList(u8),
    exit_sig: std.atomic.Value(bool),
    channel: *Channel(logfmt.LogMsg),
    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        scope: ?[]const u8,
        channel: *Channel(logfmt.LogMsg),
        log_level: Level,
    ) Self {
        return .{
            .allocator = allocator,
            .scope = scope,
            .exit_sig = AtomicBool.init(false),
            .log_level = log_level,
            .fields = std.ArrayList(u8).init(allocator),
            .channel = channel,
        };
    }

    pub fn deinit(self: *Self) void {
        self.fields.deinit();
    }

    pub fn field(self: *Self, name: []const u8, value: anytype) *Self {
        const min_capacity = self.fields.items.len + logfmt.countField(name, value);
        self.fields.ensureTotalCapacity(min_capacity) catch return self;
        logfmt.fmtField(self.fields.writer(), name, value);
        return self;
    }

    pub fn log(self: *Self, comptime msg: []const u8) void {
        const log_msg = logfmt.LogMsg{
            .level = self.log_level,
            .maybe_scope = self.scope,
            .maybe_msg = msg,
            .maybe_fields = self.fields.toOwnedSlice() catch |err| {
                std.debug.print("Processing fields failed with err: {any}", .{err});
                self.deinit();
                return;
            },
            .maybe_fmt = null,
        };

        self.channel.send(log_msg) catch |err| {
            std.debug.print("Send msg through channel failed with err: {any}", .{err});
            self.deinit();
            return;
        };
    }

    pub fn logf(self: *Self, comptime fmt: []const u8, args: anytype) void {
        // Get memory for formatting message.
        const msg_buf = self.allocBuf(std.fmt.count(fmt, args)) catch |err| {
            std.debug.print("allocBuff failed with err: {any}", .{err});
            self.deinit();
            return;
        };
        var fmt_message = std.io.fixedBufferStream(msg_buf);
        // Format message.
        logfmt.fmtMsg(fmt_message.writer(), fmt, args);

        const log_msg = logfmt.LogMsg{
            .level = self.log_level,
            .maybe_scope = self.scope,
            .maybe_msg = null,
            .maybe_fields = self.fields.toOwnedSlice() catch |err| {
                std.debug.print("Processing fields failed with err: {any}", .{err});
                self.deinit();
                return;
            },
            .maybe_fmt = fmt_message.getWritten(),
        };

        self.channel.send(log_msg) catch |err| {
            std.debug.print("Send msg through channel failed with err: {any}", .{err});
            self.deinit();
            return;
        };
    }

    // Utility function for allocating memory from RecycleFBA for part of the log message.
    fn allocBuf(self: *const Self, size: u64) ![]u8 {
        const buf = blk: while (true) {
            const buf = self.allocator.alloc(u8, size) catch {
                std.time.sleep(std.time.ns_per_ms);
                if (self.exit_sig.load(.unordered)) {
                    return error.MemoryBlockedWithExitSignaled;
                }
                continue;
            };
            break :blk buf;
        };
        errdefer {
            self.allocator.free(buf);
        }
        return buf;
    }
};

/// An instance of `Entry` that logs directly to std.debug.print, instead of sending to channel.
pub const DirectPrintEntry = struct {
    const builtin = @import("builtin");

    log_level: Level,
    scope: ?[]const u8,
    allocator: std.mem.Allocator,
    log_msg: std.ArrayList(u8),

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        scope: ?[]const u8,
        log_level: Level,
    ) Self {
        return .{
            .allocator = allocator,
            .scope = scope,
            .log_level = log_level,
            .log_msg = std.ArrayList(u8).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.log_msg.deinit();
    }

    pub fn field(self: *Self, name: []const u8, value: anytype) *Self {
        logfmt.fmtField(self.log_msg.writer(), name, value);
        return self;
    }

    pub fn log(self: *Self, comptime msg: []const u8) void {
        defer self.deinit();
        const log_msg = logfmt.LogMsg{
            .level = self.log_level,
            .maybe_scope = self.scope,
            .maybe_msg = msg,
            .maybe_fields = null,
            .maybe_fmt = null,
        };

        const writer = self.log_msg.writer();
        logfmt.writeLog(writer, log_msg) catch @panic("Failed to write log");
        std.debug.print("{s}", .{self.log_msg.items});
    }

    pub fn logf(self: *Self, comptime fmt: []const u8, args: anytype) void {
        defer self.deinit();
        // Format message.
        var fmt_msg = std.ArrayList(u8).initCapacity(self.allocator, 256) catch @panic("could not initCapacity for message");
        defer fmt_msg.deinit();
        logfmt.fmtMsg(fmt_msg.writer(), fmt, args);

        const log_msg = logfmt.LogMsg{
            .level = self.log_level,
            .maybe_scope = self.scope,
            .maybe_msg = null,
            .maybe_fields = null,
            .maybe_fmt = fmt_msg.items,
        };

        const writer = self.log_msg.writer();
        logfmt.writeLog(writer, log_msg) catch @panic("Failed to write log");
        std.debug.print("{s}", .{self.log_msg.items});
    }
};
