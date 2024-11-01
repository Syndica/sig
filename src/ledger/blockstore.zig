const ledger = @import("lib.zig");

pub const BlockstoreDB = switch (@import("build-options").blockstore_db) {
    .rocksdb => ledger.database.RocksDB(&ledger.schema.list),
    .hashmap => ledger.database.SharedHashMapDB(&ledger.schema.list),
    .lmdb => ledger.database.LMDB(&ledger.schema.list),
};

test BlockstoreDB {
    ledger.database.assertIsDatabase(BlockstoreDB);
}
