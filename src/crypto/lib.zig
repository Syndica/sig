const std = @import("std");
const builtin = @import("builtin");

pub const FnvHasher = @import("fnv.zig").FnvHasher;
pub const bn254 = @import("bn254/lib.zig");

const vector = @import("vector.zig");
const avx512 = @import("avx512.zig");
const use_avx512 = builtin.cpu.arch == .x86_64 and
    std.Target.x86.featureSetHas(builtin.cpu.features, .avx512ifma) and
    std.Target.x86.featureSetHas(builtin.cpu.features, .avx512vl);

const namespace = if (use_avx512) avx512 else vector;
pub const ExtendedPoint = namespace.ExtendedPoint;
pub const CachedPoint = namespace.CachedPoint;
pub const pippenger = @import("pippenger.zig");
