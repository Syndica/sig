const std = @import("std");
const xquic = @import("xquic");

pub const TransportCallbacks = struct {
    pub fn writeSocket(
        buf: ?[*]const u8,
        size: usize,
        peer_address: ?*const xquic.struct_sockaddr,
        addr_len: std.c.socklen_t,
        user_data: ?*anyopaque,
    ) callconv(.C) isize {
        std.debug.print("writeSocket\n", .{});
        return writeSocketEx(
            0,
            buf,
            size,
            peer_address,
            addr_len,
            user_data,
        );
    }

    pub fn writeSocketEx(
        path_id: u64,
        buf: ?[*]const u8,
        size: usize,
        peer_address: ?*const xquic.struct_sockaddr,
        addr_len: std.c.socklen_t,
        user_data: ?*anyopaque,
    ) callconv(.C) isize {
        std.debug.print("writeSocketEx\n", .{});
        _ = path_id;
        _ = buf;
        _ = size;
        _ = peer_address;
        _ = addr_len;
        _ = user_data;
        return -1;
    }

    pub fn saveToken(
        token: ?[*]const u8,
        token_len: u32,
        user_data: ?*anyopaque,
    ) callconv(.C) void {
        _ = token;
        _ = token_len;
        _ = user_data;
        std.debug.print("saveToken\n", .{});
    }

    pub fn saveSessionCb(
        data: ?[*]const u8,
        data_len: usize,
        user_data: ?*anyopaque,
    ) callconv(.C) void {
        _ = data;
        _ = data_len;
        _ = user_data;
        std.debug.print("saveSessionCb\n", .{});
    }

    pub fn saveTpCb(
        data: ?[*]const u8,
        data_len: usize,
        user_data: ?*anyopaque,
    ) callconv(.C) void {
        _ = data;
        _ = data_len;
        _ = user_data;
        std.debug.print("saveSessionCb\n", .{});
    }

    pub fn connUpdateCidNotify(
        conn: ?*xquic.xqc_connection_t,
        retire_cid: ?*const xquic.xqc_cid_t,
        new_cid: ?*const xquic.xqc_cid_t,
        user_data: ?*anyopaque,
    ) callconv(.C) void {
        _ = conn;
        _ = retire_cid;
        _ = new_cid;
        _ = user_data;
        std.debug.print("connUpdateCidNotify\n", .{});
    }

    pub fn readyToCreatePathNotify(
        cid: ?*const xquic.xqc_cid_t,
        conn_user_data: ?*anyopaque,
    ) callconv(.C) void {
        _ = cid;
        _ = conn_user_data;
        std.debug.print("connCreatePath\n", .{});
    }

    pub fn pathRemoved(
        scid: ?*const xquic.xqc_cid_t,
        path_id: u64,
        user_data: ?*anyopaque,
    ) callconv(.C) void {
        _ = scid;
        _ = path_id;
        _ = user_data;
        std.debug.print("pathRemoved\n", .{});
    }
};
