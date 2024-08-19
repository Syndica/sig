const sig = @import("../lib.zig");

pub const BlockstoreDB = sig.ledger.rocksdb.RocksDB(&sig.ledger.schema.list);

test BlockstoreDB {
    sig.ledger.database.assertIsDatabase(BlockstoreDB);
}
