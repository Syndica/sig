const std = @import("std");

comptime {
    _ = @import("server/tests.zig");
    _ = @import("client/tests.zig");
}
