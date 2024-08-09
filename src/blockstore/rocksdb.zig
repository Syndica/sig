const std = @import("std");
const rocks = @import("rocksdb");
const sig = @import("../lib.zig");

const Allocator = std.mem.Allocator;

const BytesRef = sig.blockstore.database.BytesRef;
const ColumnFamily = sig.blockstore.database.ColumnFamily;
const Logger = sig.trace.Logger;
const ReturnType = sig.utils.types.ReturnType;

const serializeToRef = sig.blockstore.database.serializer.serializeToRef;
const deserialize = sig.blockstore.database.serializer.deserialize;

pub fn RocksDB(comptime column_families: []const ColumnFamily) type {
    return struct {
        allocator: Allocator,
        db: rocks.DB,
        logger: Logger,
        cf_handles: []const rocks.ColumnFamilyHandle,

        const Self = @This();

        pub fn open(
            allocator: Allocator,
            logger: Logger,
            path: []const u8,
        ) Error!Self {
            // allocate cf descriptions
            const column_family_descriptions = try allocator
                .alloc(rocks.ColumnFamilyDescription, column_families.len + 1);
            defer allocator.free(column_family_descriptions);

            // initialize cf descriptions
            column_family_descriptions[0] = .{ .name = "default", .options = .{} };
            inline for (column_families, 1..) |bcf, i| {
                column_family_descriptions[i] = .{ .name = bcf.name, .options = .{} };
            }

            // open rocksdb
            const database: rocks.DB, //
            const cfs: []const rocks.ColumnFamily //
            = try callRocks(
                logger,
                rocks.DB.openCf,
                .{
                    allocator,
                    path,
                    .{ .create_if_missing = true, .create_missing_column_families = true },
                    column_family_descriptions,
                },
            );
            defer allocator.free(cfs);

            // allocate handle slice
            var cf_handles = try allocator.alloc(rocks.ColumnFamilyHandle, column_families.len);
            errdefer allocator.free(cf_handles); // kept alive as a field

            // initialize handle slice
            for (1..cfs.len) |i| {
                cf_handles[i - 1] = cfs[i].handle;
            }

            return .{
                .allocator = allocator,
                .db = database,
                .logger = logger,
                .cf_handles = cf_handles,
            };
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.cf_handles);
            self.db.deinit();
        }

        pub fn put(
            self: *Self,
            comptime cf: ColumnFamily,
            key: cf.Key,
            value: cf.Value,
        ) Error!void {
            const key_bytes = try serializeToRef(self.allocator, key);
            defer key_bytes.deinit();
            const val_bytes = try serializeToRef(self.allocator, value);
            defer val_bytes.deinit();
            return try callRocks(
                self.logger,
                rocks.DB.put,
                .{
                    &self.db,
                    self.cf_handles[cf.find(column_families)],
                    key_bytes.data,
                    val_bytes.data,
                },
            );
        }

        pub fn get(self: *Self, comptime cf: ColumnFamily, key: cf.Key) Error!?cf.Value {
            const val_bytes = try self.getBytes(cf, key) orelse return null;
            defer val_bytes.deinit();
            return try deserialize(cf.Value, self.allocator, val_bytes.data);
        }

        pub fn getBytes(self: *Self, comptime cf: ColumnFamily, key: cf.Key) Error!?BytesRef {
            const key_bytes = try serializeToRef(self.allocator, key);
            defer key_bytes.deinit();
            const val_bytes: rocks.Data = try callRocks(
                self.logger,
                rocks.DB.get,
                .{ &self.db, self.cf_handles[cf.find(column_families)], key_bytes.data },
            ) orelse return null;
            return .{
                .allocator = val_bytes.allocator,
                .data = val_bytes.data,
            };
        }

        pub fn delete(self: *Self, comptime cf: ColumnFamily, key: cf.Key) Error!void {
            const key_bytes = try serializeToRef(self.allocator, key);
            defer key_bytes.deinit();
            return try callRocks(
                self.logger,
                rocks.DB.delete,
                .{ &self.db, self.cf_handles[cf.find(column_families)], key_bytes.data },
            );
        }

        pub fn initWriteBatch(self: *Self) Error!WriteBatch {
            return .{
                .inner = rocks.WriteBatch.init(),
                .cf_handles = self.cf_handles,
            };
        }

        pub fn commit(self: *Self, batch: WriteBatch) Error!void {
            return callRocks(self.logger, self.db.write, .{batch.inner});
        }

        /// A write batch is a sequence of operations that execute atomically.
        /// This is typically called a "transaction" in most databases.
        ///
        /// Use this instead of Database.put or Database.delete when you need
        /// to ensure that a group of operations are either all executed
        /// successfully, or none of them are executed.
        ///
        /// It is called a write batch instead of a transaction because:
        /// - rocksdb uses the name "write batch" for this concept
        /// - this name avoids confusion with solana transactions
        pub const WriteBatch = struct {
            inner: rocks.WriteBatch,
            cf_handles: []const rocks.ColumnFamilyHandle,

            pub fn put(
                self: *WriteBatch,
                comptime cf: ColumnFamily,
                key: cf.Key,
                value: cf.Value,
            ) Error!void {
                const key_bytes = try serializeToRef(self.allocator, key);
                defer key_bytes.deinit();
                const val_bytes = try serializeToRef(self.allocator, value);
                defer val_bytes.deinit();
                self.inner.put(
                    self.cf_handles[cf.find(column_families)],
                    key_bytes.data,
                    val_bytes.data,
                );
            }

            pub fn delete(
                self: *WriteBatch,
                comptime cf: ColumnFamily,
                key: cf.Key,
            ) Error!void {
                const key_bytes = try serializeToRef(self.allocator, key);
                defer key_bytes.deinit();
                self.inner.delete(self.cf_handles[cf.find(column_families)], key_bytes.data);
            }
        };

        const Error = error{
            RocksDBOpen,
            RocksDBPut,
            RocksDBGet,
            RocksDBDelete,
            RocksDBDeleteFileInRange,
            RocksDBWrite,
        } || Allocator.Error;
    };
}

fn callRocks(logger: Logger, comptime func: anytype, args: anytype) ReturnType(@TypeOf(func)) {
    var err_str: ?rocks.Data = null;
    return @call(.auto, func, args ++ .{&err_str}) catch |e| {
        logger.errf("{} - {s}", .{ e, err_str.? });
        return e;
    };
}

test "rocksdb database" {
    sig.blockstore.database.testDatabase(RocksDB);
}
