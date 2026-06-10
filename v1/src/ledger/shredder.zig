const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;

const DataShred = sig.ledger.shred.DataShred;

/// Combines all shreds to recreate the original buffer
///
/// Analogous to [Shredder::deshred](https://github.com/anza-xyz/agave/blob/42e72bf1b31f5335d3f7ee56ce1f607ceb899c3f/ledger/src/shredder.rs#L394)
pub fn deshred(allocator: Allocator, shreds: []const DataShred) !std.array_list.Managed(u8) {
    // sanitize inputs
    if (shreds.len == 0) return error.TooFewDataShards;
    const index = shreds[0].common.index;
    for (shreds, index..) |shred, i| {
        if (shred.common.index != i) {
            return error.TooFewDataShards;
        }
    }
    const last_shred = shreds[shreds.len - 1];
    if (!last_shred.dataComplete() and !last_shred.isLastInSlot()) {
        return error.TooFewDataShards;
    }

    // deshred
    var data = std.array_list.Managed(u8).init(allocator);
    for (shreds) |shred| {
        try data.appendSlice(try shred.data());
    }

    return data;
}
