const std = @import("std");
const xquic = @import("xquic");

pub const EngineCallbacks = struct {
    pub fn writeLogFile(
        level: xquic.xqc_log_level_t,
        buf: ?*const anyopaque,
        size: usize,
        engine_user_data: ?*anyopaque,
    ) callconv(.C) void {
        _ = level;
        _ = buf;
        _ = size;
        _ = engine_user_data;
        std.debug.print("writeLogFile\n", .{});
    }

    pub fn writeQLogFile(
        imp: xquic.qlog_event_importance_t,
        buf: ?*const anyopaque,
        size: usize,
        engine_user_data: ?*anyopaque,
    ) callconv(.C) void {
        _ = imp;
        _ = buf;
        _ = size;
        _ = engine_user_data;
        std.debug.print("writeQLogFile\n", .{});
    }

    pub fn keyLogCb(
        scid: ?*const xquic.xqc_cid_t,
        line: ?[*]const u8,
        engine_user_data: ?*anyopaque,
    ) callconv(.C) void {
        _ = scid;
        _ = line;
        _ = engine_user_data;
        std.debug.print("keyLogCb\n", .{});
    }

    pub fn setEventTimer(wake_after: xquic.xqc_usec_t, engine_user_data: ?*anyopaque) callconv(.C) void {
        _ = wake_after;
        _ = engine_user_data;
        std.debug.print("setEventTimer\n", .{});
    }
};
