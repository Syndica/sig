const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;

const DataShred = sig.ledger.shred.DataShred;

/// Combines all shreds to recreate the original buffer
pub fn deshred(allocator: Allocator, shreds: []const DataShred) !std.ArrayList(u8) {
    // sanitize inputs
    if (shreds.len == 0) return error.TooFewDataShards;
    const index = shreds[0].fields.common.index;
    for (shreds, index..) |shred, i| {
        if (shred.fields.common.index != i) {
            return error.TooFewDataShards;
        }
    }
    const last_shred = shreds[shreds.len - 1];
    if (!last_shred.dataComplete() and !last_shred.isLastInSlot()) {
        return error.TooFewDataShards;
    }

    // deshred
    var data = std.ArrayList(u8).init(allocator);
    for (shreds) |shred| {
        try data.appendSlice(try shred.data());
    }

    return data;
}
