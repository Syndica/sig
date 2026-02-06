const std = @import("std");
const rocks = @import("rocksdb");
const sig = @import("../../sig.zig");
const database = @import("lib.zig");
const tracy = @import("tracy");

const Allocator = std.mem.Allocator;

const BytesRef = database.interface.BytesRef;
const ColumnFamily = database.interface.ColumnFamily;
const IteratorDirection = database.interface.IteratorDirection;
const ReturnType = sig.utils.types.ReturnType;

const key_serializer = database.interface.key_serializer;
const value_serializer = database.interface.value_serializer;

const Logger = sig.trace.Logger("rocksdb");

pub fn RocksDB(comptime column_families: []const ColumnFamily) type {
    return struct {
        allocator: Allocator,
        db: rocks.DB,
        logger: Logger,
        cf_handles: []const rocks.ColumnFamilyHandle,
        path: [:0]const u8,

        const Self = @This();
        const OpenError = Error || std.posix.MakeDirError || std.fs.Dir.StatFileError;
        pub const name: []const u8 = "RocksDB";

        pub fn open(
            allocator: Allocator,
            logger: database.interface.Logger,
            path: []const u8,
            open_read_only: bool,
        ) OpenError!Self {
            logger.info().log("Opening RocksDB for ledger");
            const owned_path = try std.fmt.allocPrintZ(allocator, "{s}/rocksdb", .{path});
            errdefer allocator.free(owned_path);
            try std.fs.cwd().makePath(owned_path);

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
            const db: rocks.DB, //
            const cfs: []const rocks.ColumnFamily //
            = try callRocks(
                .from(logger),
                rocks.DB.open,
                .{
                    allocator,
                    owned_path,
                    rocks.DBOptions{
                        .create_if_missing = true,
                        .create_missing_column_families = true,
                    },
                    column_family_descriptions,
                    open_read_only,
                },
            );
            errdefer db.deinit();
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
                .db = db,
                .logger = .from(logger),
                .cf_handles = cf_handles,
                .path = owned_path,
            };
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.cf_handles);
            self.db.deinit();
            self.allocator.free(self.path);
        }

        pub fn count(self: *Self, comptime cf: ColumnFamily) Allocator.Error!u64 {
            const live_files = try self.db.liveFiles(self.allocator);
            defer live_files.deinit();
            defer for (live_files.items) |file| file.deinit();

            var sum: u64 = 0;
            for (live_files.items) |live_file| {
                if (std.mem.eql(u8, live_file.column_family_name, cf.name)) {
                    sum += live_file.num_entries;
                }
            }

            return sum;
        }

        pub fn put(
            self: Self,
            comptime cf: ColumnFamily,
            key: cf.Key,
            value: cf.Value,
        ) anyerror!void {
            const key_bytes = try key_serializer.serializeToRef(self.allocator, key);
            defer key_bytes.deinit();
            const val_bytes = try value_serializer.serializeToRef(self.allocator, value);
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

        pub fn get(
            self: *Self,
            allocator: Allocator,
            comptime cf: ColumnFamily,
            key: cf.Key,
        ) anyerror!?cf.Value {
            const zone = tracy.Zone.init(@src(), .{ .name = "RocksDb.get" });
            defer zone.deinit();

            const val_bytes = try self.getBytes(cf, key) orelse return null;
            defer val_bytes.deinit();
            return try value_serializer.deserialize(cf.Value, allocator, val_bytes.data);
        }

        pub fn getBytes(self: *Self, comptime cf: ColumnFamily, key: cf.Key) anyerror!?BytesRef {
            const zone = tracy.Zone.init(@src(), .{ .name = "RocksDb.getBytes" });
            defer zone.deinit();

            const key_bytes = try key_serializer.serializeToRef(self.allocator, key);
            defer key_bytes.deinit();
            const val_bytes: rocks.Data = try callRocks(
                self.logger,
                rocks.DB.get,
                .{ &self.db, self.cf_handles[cf.find(column_families)], key_bytes.data },
            ) orelse return null;
            return .{
                .deinitializer = .{ .rocksdb = val_bytes.free },
                .data = val_bytes.data,
            };
        }

        pub fn contains(self: *Self, comptime cf: ColumnFamily, key: cf.Key) anyerror!bool {
            return try self.getBytes(cf, key) != null;
        }

        pub fn delete(self: *Self, comptime cf: ColumnFamily, key: cf.Key) anyerror!void {
            const key_bytes = try key_serializer.serializeToRef(self.allocator, key);
            defer key_bytes.deinit();
            return try callRocks(
                self.logger,
                rocks.DB.delete,
                .{ &self.db, self.cf_handles[cf.find(column_families)], key_bytes.data },
            );
        }

        pub fn deleteFilesInRange(
            self: *Self,
            comptime cf: ColumnFamily,
            start: cf.Key,
            end: cf.Key,
        ) anyerror!void {
            const start_bytes = try key_serializer.serializeToRef(self.allocator, start);
            defer start_bytes.deinit();

            const end_bytes = try key_serializer.serializeToRef(self.allocator, end);
            defer end_bytes.deinit();

            return try callRocks(
                self.logger,
                rocks.DB.deleteFilesInRange,
                .{ &self.db, self.cf_handles[cf.find(column_families)], start_bytes.data, end_bytes.data },
            );
        }

        pub fn initWriteBatch(self: *Self) Error!WriteBatch {
            return .{
                .allocator = self.allocator,
                .inner = rocks.WriteBatch.init(),
                .cf_handles = self.cf_handles,
            };
        }

        pub fn commit(self: *Self, batch: *WriteBatch) Error!void {
            return callRocks(self.logger, rocks.DB.write, .{ &self.db, batch.inner });
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
            allocator: Allocator,
            inner: rocks.WriteBatch,
            cf_handles: []const rocks.ColumnFamilyHandle,

            pub fn deinit(self: *WriteBatch) void {
                self.inner.deinit();
            }

            pub fn put(
                self: *WriteBatch,
                comptime cf: ColumnFamily,
                key: cf.Key,
                value: cf.Value,
            ) anyerror!void {
                const key_bytes = try key_serializer.serializeToRef(self.allocator, key);
                defer key_bytes.deinit();
                const val_bytes = try value_serializer.serializeToRef(self.allocator, value);
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
            ) anyerror!void {
                const key_bytes = try key_serializer.serializeToRef(self.allocator, key);
                defer key_bytes.deinit();
                self.inner.delete(self.cf_handles[cf.find(column_families)], key_bytes.data);
            }

            pub fn deleteRange(
                self: *WriteBatch,
                comptime cf: ColumnFamily,
                start: cf.Key,
                end: cf.Key,
            ) anyerror!void {
                const start_bytes = try key_serializer.serializeToRef(self.allocator, start);
                defer start_bytes.deinit();

                const end_bytes = try key_serializer.serializeToRef(self.allocator, end);
                defer end_bytes.deinit();

                self.inner.deleteRange(
                    self.cf_handles[cf.find(column_families)],
                    start_bytes.data,
                    end_bytes.data,
                );
            }
        };

        pub fn iterator(
            self: Self,
            comptime cf: ColumnFamily,
            comptime direction: IteratorDirection,
            start: ?cf.Key,
        ) anyerror!Iterator(cf, direction) {
            const start_bytes = if (start) |s| try key_serializer.serializeToRef(self.allocator, s) else null;
            defer if (start_bytes) |sb| sb.deinit();
            return .{
                .allocator = self.allocator,
                .logger = self.logger,
                .inner = self.db.iterator(
                    self.cf_handles[cf.find(column_families)],
                    switch (direction) {
                        .forward => .forward,
                        .reverse => .reverse,
                    },
                    if (start_bytes) |s| s.data else null,
                ),
            };
        }

        pub fn Iterator(cf: ColumnFamily, _: IteratorDirection) type {
            return struct {
                allocator: Allocator,
                inner: rocks.Iterator,
                logger: Logger,

                /// Calling this will free all slices returned by the iterator
                pub fn deinit(self: *@This()) void {
                    self.inner.deinit();
                }

                pub fn next(self: *@This()) anyerror!?cf.Entry() {
                    const entry = try callRocks(self.logger, rocks.Iterator.next, .{&self.inner});
                    return if (entry) |kv| {
                        return .{
                            try key_serializer.deserialize(cf.Key, self.allocator, kv[0].data),
                            try value_serializer.deserialize(cf.Value, self.allocator, kv[1].data),
                        };
                    } else null;
                }

                pub fn nextKey(self: *@This()) anyerror!?cf.Key {
                    const entry = try callRocks(self.logger, rocks.Iterator.next, .{&self.inner});
                    return if (entry) |kv|
                        try key_serializer.deserialize(cf.Key, self.allocator, kv[0].data)
                    else
                        null;
                }

                pub fn nextValue(self: *@This()) anyerror!?cf.Value {
                    const entry = try callRocks(self.logger, rocks.Iterator.next, .{&self.inner});
                    return if (entry) |kv|
                        try key_serializer.deserialize(cf.Value, self.allocator, kv[1].data)
                    else
                        null;
                }

                /// Returned data does not outlive the iterator.
                pub fn nextBytes(self: *@This()) Error!?[2]BytesRef {
                    const entry = try callRocks(self.logger, rocks.Iterator.next, .{&self.inner});
                    return if (entry) |kv| .{
                        .{ .deinitializer = null, .data = kv[0].data },
                        .{ .deinitializer = null, .data = kv[1].data },
                    } else null;
                }
            };
        }

        pub fn flush(self: *Self, comptime cf: ColumnFamily) error{RocksDBFlush}!void {
            try callRocks(
                self.logger,
                rocks.DB.flush,
                .{ &self.db, self.cf_handles[cf.find(column_families)] },
            );
        }

        const Error = error{
            RocksDBOpen,
            RocksDBPut,
            RocksDBGet,
            RocksDBDelete,
            RocksDBDeleteFilesInRange,
            RocksDBIterator,
            RocksDBWrite,
            RocksDBFlush,
        } || Allocator.Error;
    };
}

fn callRocks(logger: Logger, comptime func: anytype, args: anytype) ReturnType(@TypeOf(func)) {
    var maybe_err_str: ?rocks.Data = null;
    return @call(.auto, func, args ++ .{&maybe_err_str}) catch |e| {
        if (maybe_err_str) |err_str|
            logger.err().logf("{} - {s}", .{ e, err_str })
        else
            logger.err().logf("{}", .{e});
        return e;
    };
}

test {
    if (sig.build_options.ledger_db == .rocksdb) {
        _ = &database.interface.testDatabase(RocksDB);
    }
}
