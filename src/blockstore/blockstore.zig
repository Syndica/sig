const sig = @import("../lib.zig");

pub fn BlockstoreDB(comptime DB: type) type {
    return sig.blockstore.database
        .Database(DB, &sig.blockstore.schema.list);
}
