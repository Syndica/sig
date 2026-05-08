comptime {
    if (@import("builtin").is_test) {
        _ = @import("crypto/ed25519.zig");
    }
}

pub const ed25519 = @import("crypto/ed25519.zig");
