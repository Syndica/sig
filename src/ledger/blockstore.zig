const ledger = @import("lib.zig");

pub const BlockstoreDB = ledger.database.RocksDB(&ledger.schema.list);

test BlockstoreDB {
    ledger.database.assertIsDatabase(BlockstoreDB);
}
