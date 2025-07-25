const std = @import("std");
const builtin = @import("builtin");

pub const FnvHasher = @import("fnv.zig").FnvHasher;
pub const bn254 = @import("bn254/lib.zig");

pub const ed25519 = struct {
    const generic = @import("generic.zig");
    const avx512 = @import("avx512.zig");
    const has_avx512 = builtin.cpu.arch == .x86_64 and
        std.Target.x86.featureSetHas(builtin.cpu.features, .avx512ifma) and
        std.Target.x86.featureSetHas(builtin.cpu.features, .avx512vl);

    // avx512 implementation relies on llvm specific tricks
    const namespace = if (has_avx512 and builtin.zig_backend == .stage2_llvm) avx512 else generic;
    pub const ExtendedPoint = namespace.ExtendedPoint;
    pub const CachedPoint = namespace.CachedPoint;
    pub const pippenger = @import("pippenger.zig");
};
