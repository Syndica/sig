const std = @import("std");
const lib = @import("lib.zig");

test {
    std.testing.log_level = std.log.Level.debug;
    std.testing.refAllDecls(lib);
}
