comptime {
    if (@import("builtin").is_test) {
        _ = @import("collections/pool.zig");
        _ = @import("collections/pubkey_map.zig");
    }
}

pub const Pool = @import("collections/pool.zig").Pool;
pub const SharedPool = @import("collections/pool.zig").SharedPool;
pub const FixedPubkeyMap = @import("collections/pubkey_map.zig").FixedPubkeyMap;
