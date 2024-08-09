const sig = @import("../lib.zig");

pub const BlockstoreDB = sig.blockstore.rocksdb.RocksDB(&sig.blockstore.schema.list);

test BlockstoreDB {
    sig.blockstore.database.assertIsDatabase(BlockstoreDB);
}
