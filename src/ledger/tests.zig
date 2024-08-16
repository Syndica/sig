const std = @import("std");
const sig = @import("../sig.zig");
const blockstore = @import("lib.zig");

const Logger = sig.trace.Logger;

const schema = blockstore.schema.schema;
const TestState = sig.ledger.insert_shred.TestState;

test "put/get data consistency for merkle root" {
    const logger = Logger.init(std.testing.allocator, Logger.TEST_DEFAULT_LEVEL);
    defer logger.deinit();
    var rng = std.Random.DefaultPrng.init(100);
    const random = rng.random();

    var state = try TestState.init("bsdbMerkleRootDatabaseConsistency");
    defer state.deinit();
    var db = state.db;

    const id = sig.ledger.shred.ErasureSetId{
        .slot = 1234127498,
        .fec_set_index = 4932874234,
    };
    const root = sig.core.Hash.random(random);

    try db.put(
        schema.merkle_root_meta,
        id,
        sig.ledger.meta.MerkleRootMeta{
            .merkle_root = root,
            .first_received_shred_index = 100,
            .first_received_shred_type = .data,
        },
    );
    const output: sig.ledger.meta.MerkleRootMeta = (try db.get(schema.merkle_root_meta, id)).?;
    try std.testing.expectEqualSlices(u8, &root.data, &output.merkle_root.?.data);
}

/// ensures the path exists as an empty directory.
/// deletes anything else that might exist here.
pub fn freshDir(path: []const u8) !void {
    if (std.fs.cwd().access(path, .{})) |_| {
        try std.fs.cwd().deleteTree(path);
    } else |_| {}
    try std.fs.cwd().makePath(path);
}
