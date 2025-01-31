const sig = @import("../../sig.zig");

const Slot = sig.core.Slot;
const Hash = sig.core.Hash;

/// [agave] https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/slot-hashes/src/lib.rs#L43
pub const SlotHashes = struct {
    entries: []const struct { Slot, Hash },
};
