const sig = @import("../sig.zig");
const ledger = @import("lib.zig");

pub const LedgerDB = switch (sig.build_options.ledger_db) {
    .rocksdb => ledger.database.RocksDB(&ledger.schema.list),
    .hashmap => ledger.database.SharedHashMapDB(&ledger.schema.list),
};

test LedgerDB {
    ledger.database.assertIsDatabase(LedgerDB);
}
