const sig = @import("../../../sig.zig");

const Pubkey = sig.core.Pubkey;

pub const ID =
    Pubkey.parseBase58String("Config1111111111111111111111111111111111111") catch unreachable;

pub const COMPUTE_UNITS = 450;
