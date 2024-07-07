const std = @import("std");
const rocks = @import("rocksdb");
const sig = @import("../lib.zig");

const Allocator = std.mem.Allocator;
const Logger = sig.trace.Logger;
const fieldNames = sig.utils.types.fieldNames;

const ColumnFamily = sig.blockstore.database.ColumnFamily;
const Database = sig.blockstore.database.Database;

pub fn Blockstore(comptime DB: type) type {
    return struct {
        db: Database(DB),
        schema: Schema(DB.CF),

        const Self = @This();

        pub fn init(allocator: Allocator, logger: Logger, dir: []const u8) !@This() {
            const cf_names = comptime fieldNames(Schema(DB.CF));
            const database, const cfs = try Database(DB).open(allocator, logger, dir, &cf_names);
            var stores: Schema(DB.CF) = undefined;
            inline for (cf_names, 0..) |cf_name, i| {
                std.debug.assert(std.mem.eql(u8, cf_name, cfs[i].name));
                @field(stores, cf_name) = cfs[i];
            }
            return .{
                .db = database,
                .schema = stores,
            };
        }

        pub fn deinit(self: Self) void {
            self.db.deinit();
        }
    };
}

pub fn Schema(comptime CF: type) type {
    return struct {
        meta: ColumnFamily(CF),
        dead_slots: ColumnFamily(CF),
        duplicate_slots: ColumnFamily(CF),
        roots: ColumnFamily(CF),
        erasure_meta: ColumnFamily(CF),
        orphans: ColumnFamily(CF),
        index: ColumnFamily(CF),
        data_shred: ColumnFamily(CF),
        code_shred: ColumnFamily(CF),
        transaction_status: ColumnFamily(CF),
        address_signatures: ColumnFamily(CF),
        transaction_memos: ColumnFamily(CF),
        transaction_status_index: ColumnFamily(CF),
        rewards: ColumnFamily(CF),
        blocktime: ColumnFamily(CF),
        perf_samples: ColumnFamily(CF),
        block_height: ColumnFamily(CF),
        program_costs: ColumnFamily(CF),
        bank_hash: ColumnFamily(CF),
        optimistic_slots: ColumnFamily(CF),
        merkle_root_meta: ColumnFamily(CF),
    };
}
