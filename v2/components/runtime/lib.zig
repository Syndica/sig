pub const ELF_DATA_DIR = "v2/components/runtime/data/test-elfs/";

comptime {
    if (@import("builtin").is_test) {
        _ = @import("bincode/bincode.zig");
        _ = @import("bloom/bit_set.zig");
        _ = @import("bloom/bit_vec.zig");
        _ = @import("core/lib.zig");
        _ = @import("crypto/lib.zig");
        _ = @import("runtime/lib.zig");
        _ = @import("time/lib.zig");
        _ = @import("utils/lib.zig");
        _ = @import("vm/lib.zig");
        _ = @import("zksdk/lib.zig");
    }
}

pub const bincode = @import("bincode/bincode.zig");
pub const bloom = struct {
    pub const bit_set = @import("bloom/bit_set.zig");
    pub const bit_vec = @import("bloom/bit_vec.zig");
};
pub const core = @import("core/lib.zig");
pub const crypto = @import("crypto/lib.zig");
pub const runtime = @import("runtime/lib.zig");
pub const time = @import("time/lib.zig");
pub const utils = @import("utils/lib.zig");
pub const vm = @import("vm/lib.zig");
pub const zksdk = @import("zksdk/lib.zig");
pub const build_options = @import("build-options");
