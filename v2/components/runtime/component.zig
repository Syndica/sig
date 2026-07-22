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

/// This is a re-export of all the code that is deduplicated across v1 and v2. They
/// live inside v2, and not this runtime component because that's where it makes the
/// most sense of v2.
///
/// They are re-exported here because the runtime is the primary v2 dependency of
/// v1, and many of these types are required to be the same exact type across v1 and
/// v2 because of the runtime integration. Exporting them here makes it clear and
/// explicit exactly what v1 needs from v2 instead of deeply entangling the two
/// versions.
pub const v2 = struct {
    const lib = @import("lib");

    pub const epoch_schedule = lib.solana.epoch_schedule;
    pub const features = lib.solana.features;
    pub const pubkey = lib.solana.pubkey;
    pub const signature = lib.solana.signature;
    pub const time = lib.solana.time;
    pub const transaction = lib.solana.transaction;

    pub const Epoch = lib.solana.Epoch;
    pub const EpochSchedule = lib.solana.EpochSchedule;
    pub const FeatureSet = lib.solana.features.Set;
    pub const Hash = lib.solana.Hash;
    pub const Slot = lib.solana.Slot;
};
