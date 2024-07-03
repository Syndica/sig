const std = @import("std");
const rocks = @import("rocksdb");
const sig = @import("../lib.zig");

const Allocator = std.mem.Allocator;
const Logger = sig.trace.Logger;
const fieldNames = sig.utils.types.fieldNames;

pub fn Blockstore(comptime DB: type) type {
    return struct {
        db: Database(DB),
        schema: Schema(DB.CF),

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

/// Interface defining the blockstore's dependency on a database
pub fn Database(comptime Impl: type) type {
    return struct {
        impl: Impl,

        pub const CF: type = Impl.CF;

        const Self = @This();

        pub fn open(
            allocator: Allocator,
            logger: Logger,
            path: []const u8,
            column_family_names: []const []const u8,
        ) !struct { Self, []ColumnFamily(CF) } {
            const impl, const cfs = try Impl.open(allocator, logger, path, column_family_names);
            defer allocator.free(cfs);
            const wcfs = try allocator.alloc(ColumnFamily(CF), column_family_names.len);
            for (0..column_family_names.len) |i| {
                wcfs[i] = .{
                    .impl = cfs[i],
                    .name = column_family_names[i],
                };
            }
            return .{ .{ .impl = impl }, wcfs };
        }
    };
}

/// Interface defining the blockstore's dependency on column families
pub fn ColumnFamily(comptime Impl: type) type {
    return struct {
        impl: Impl,
        name: []const u8,

        const Self = @This();

        pub inline fn put(self: Self, key: []const u8, value: []const u8) !void {
            return self.impl.put(key, value);
        }

        pub inline fn get(self: Self, key: []const u8) !?[]const u8 {
            return self.impl.get(key);
        }

        pub inline fn delete(self: Self, key: []const u8) !bool {
            return self.impl.delete(key);
        }
    };
}

test Blockstore {
    try testBlockstore(sig.blockstore.hashmap_db.SharedHashMapDB);
    try testBlockstore(sig.blockstore.rocksdb.RocksDB);
}

fn testBlockstore(comptime DB: type) !void {
    const logger = Logger.init(std.testing.allocator, Logger.TEST_DEFAULT_LEVEL);
    const blockstore = try Blockstore(DB).init(std.testing.allocator, logger, "test_data/blockstore");
    try blockstore.schema.meta.put("123", "345");
    const got = try blockstore.schema.meta.get("123");
    try std.testing.expect(std.mem.eql(u8, "345", got.?));
    const not = try blockstore.schema.dead_slots.get("123");
    try std.testing.expect(null == not);
    const wrong_was_deleted = try blockstore.schema.duplicate_slots.delete("123");
    _ = wrong_was_deleted;
    // try std.testing.expect(!wrong_was_deleted); // FIXME
    const was_deleted = try blockstore.schema.meta.delete("123");
    try std.testing.expect(was_deleted);
    const not_now = try blockstore.schema.meta.get("123");
    try std.testing.expect(null == not_now);
}
