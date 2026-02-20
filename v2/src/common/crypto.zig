const std = @import("std");

test {
    _ = std.testing.refAllDecls(@This());
}

pub const ed25519 = @import("crypto/ed25519.zig");
