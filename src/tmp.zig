const std = @import("std");
const sig = @import("lib.zig");
const blockstore = sig.blockstore;

const BlockstoreDB = sig.blockstore.BlockstoreDB;
const BlockstoreReader = sig.blockstore.reader.BlockstoreReader;
const Logger = sig.trace.Logger;
const ShredInserter = sig.blockstore.ShredInserter;

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    var logger = Logger.init(allocator, .debug);
    defer logger.deinit();
    logger.spawn();

    const registry = sig.prometheus.globalRegistry();

    var db = try BlockstoreDB.open(allocator, logger, "test_data/blockstore");
    defer db.deinit(true);

    var reader = try BlockstoreReader.init(allocator, logger, db, registry);
    const shred_inserter = try ShredInserter.init(allocator, logger, registry, db);

    var slot_meta = blockstore.meta.SlotMeta.init(allocator, 1, null);
    var data_index = blockstore.meta.ShredIndex.init(allocator);
    // first data shred index
    try data_index.put(0);

    const shred_payload = sig.shred_collector.shred.test_data_shred;
    var shred = try sig.shred_collector.shred.Shred.fromPayload(allocator, &shred_payload);
    defer shred.deinit();

    var write_batch = try db.initWriteBatch();
    _ = try shred_inserter.insertDataShred(&slot_meta, &data_index, &shred.data, &write_batch, .repaired);

    try db.commit(write_batch);

    const read_bytes_ref = try reader.getDataShred(shred.commonHeader().slot, shred.commonHeader().index) orelse {
        return error.NullDataShred;
    };

    try std.testing.expectEqualSlices(
        u8,
        shred_payload[0..sig.shred_collector.shred.DataShred.constants.payload_size],
        read_bytes_ref.data,
    );
}
