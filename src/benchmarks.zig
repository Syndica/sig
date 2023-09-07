const std = @import("std");
const lib = @import("lib.zig");
const builtin = @import("builtin");

test {
    std.testing.log_level = std.log.Level.err;
    // need to mention benchmark file here
    _ = &lib.benchmark.gossip;
}
