const std = @import("std");

comptime {
    std.debug.assert(@import("builtin").mode == .ReleaseFast);
}

comptime {
    if (@import("builtin").is_test) {
        _ = @import("ed25519.zig");
        _ = @import("pubkey.zig");
        _ = @import("signature.zig");
        _ = @import("hash.zig");
    }
}

pub const ed25519 = @import("ed25519.zig");
pub const Pubkey = @import("pubkey.zig").Pubkey;
pub const Signature = @import("signature.zig").Signature;
pub const Hash = @import("hash.zig").Hash;
