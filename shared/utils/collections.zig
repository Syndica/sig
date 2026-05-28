const std = @import("std");
const sig = @import("../lib.zig");

pub fn PubkeyMap(T: type) type {
    // TODO: benchmark true vs false?
    return std.ArrayHashMapUnmanaged(sig.core.Pubkey, T, MapContext, true);
}

pub fn PubkeyMapManaged(T: type) type {
    return std.ArrayHashMap(sig.core.Pubkey, T, MapContext, true);
}

const MapContext = struct {
    // Applies a Murmur-like LCG to the public key, in order to alivate a
    // bit of the bucketing that may happen if we load many vanity public keys,
    // where the first bytes are mined.
    pub fn hash(_: MapContext, pubkey: sig.core.Pubkey) u32 {
        var h: u32 = 0;
        const pk: [8]u32 = @bitCast(pubkey.data);
        for (pk) |k| h ^= k +% 1;
        h ^= h >> 16;
        h *%= 0x85ebca6b;
        h ^= h >> 13;
        h *%= 0xc2b2ae35;
        h ^= h >> 16;
        return h;
    }

    pub fn eql(_: MapContext, a: sig.core.Pubkey, b: sig.core.Pubkey, _: usize) bool {
        return a.equals(&b);
    }
};
