const std = @import("std");
const rocks = @import("rocksdb");
const sig = @import("../lib.zig");

const Allocator = std.mem.Allocator;
const Logger = sig.trace.Logger;
const fieldNames = sig.utils.types.fieldNames;

const ColumnFamily = sig.blockstore.database.ColumnFamily;
const Database = sig.blockstore.database.Database;

pub const Blockstore = AbstractBlockstore(sig.blockstore.rocksdb.RocksDB);

pub fn AbstractBlockstore(comptime DB: type) type {
    const cfs = &sig.blockstore.schema.schema.list();
    return struct {
        db: Database(DB, cfs),

        const Self = @This();

        pub fn init(allocator: Allocator, logger: Logger, dir: []const u8) !@This() {
            return .{ .db = try Database(DB, cfs).open(allocator, logger, dir, cfs) };
        }

        pub fn deinit(self: Self) void {
            self.db.deinit();
        }
    };
}
