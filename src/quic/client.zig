const std = @import("std");
const xquic = @import("xquic");

extern const default_client_config: xquic.xqc_config_t;

pub fn runClient() !void {
    std.debug.print("config: {}\n", .{default_client_config.conn_pool_size});
}
