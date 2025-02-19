const sig = @import("../sig.zig");
const ledger = @import("lib.zig");

pub const BlockstoreDB = switch (sig.build_options.blockstore_db) {
    .rocksdb => ledger.database.RocksDB(&ledger.schema.list),
    .hashmap => ledger.database.SharedHashMapDB(&ledger.schema.list),
};

test BlockstoreDB {
    ledger.database.assertIsDatabase(BlockstoreDB);
}
