const std = @import("std");
const c = @import("lmdb");
const sig = @import("../../sig.zig");
const database = @import("lib.zig");

const Allocator = std.mem.Allocator;

const BytesRef = database.interface.BytesRef;
const ColumnFamily = database.interface.ColumnFamily;
const IteratorDirection = database.interface.IteratorDirection;
const Logger = sig.trace.Logger;

const key_serializer = database.interface.key_serializer;
const value_serializer = database.interface.value_serializer;

pub fn LMDB(comptime column_families: []const ColumnFamily) type {
    return struct {
        allocator: Allocator,
        env: *c.MDB_env,
        dbis: []const c.MDB_dbi,
        path: []const u8,

        const Self = @This();

        pub fn open(allocator: Allocator, _: Logger, path: []const u8) anyerror!Self {
            const owned_path = try allocator.dupe(u8, path);

            // create and open the database
            const env = try ret(c.mdb_env_create, .{});
            try result(c.mdb_env_set_maxdbs(env, column_families.len));
            try result(c.mdb_env_open(env, @ptrCast(path), 0, 0o700));

            // begin transaction to create column families aka "databases" in lmdb
            const txn = try ret(c.mdb_txn_begin, .{ env, null, 0 });
            errdefer c.mdb_txn_abort(txn);

            // allocate cf handles
            const dbis = try allocator.alloc(c.MDB_dbi, column_families.len);
            errdefer allocator.free(dbis);

            // save cf handles
            inline for (column_families, 0..) |cf, i| {
                // open cf/database, creating if necessary
                dbis[i] = try ret(c.mdb_dbi_open, .{
                    txn,
                    @as([*c]const u8, @ptrCast(cf.name)),
                    MDB_CREATE,
                });
            }

            // persist column families
            try result(c.mdb_txn_commit(txn));

            return .{
                .allocator = allocator,
                .env = env,
                .dbis = dbis,
                .path = owned_path,
            };
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.dbis);
            self.allocator.free(self.path);
        }

        fn dbi(self: *Self, comptime cf: ColumnFamily) c.MDB_dbi {
            return self.dbis[cf.find(column_families)];
        }

        pub fn count(self: *Self, comptime cf: ColumnFamily) Allocator.Error!u64 {
            const live_files = try self.db.liveFiles(self.allocator);
            defer live_files.deinit();

            var sum: u64 = 0;
            for (live_files.items) |live_file| {
                if (std.mem.eql(u8, live_file.column_family_name, cf.name)) {
                    sum += live_file.num_entries;
                }
            }

            return sum;
        }

        pub fn put(
            self: *Self,
            comptime cf: ColumnFamily,
            key: cf.Key,
            value: cf.Value,
        ) anyerror!void {
            const key_bytes = try key_serializer.serializeToRef(self.allocator, key);
            defer key_bytes.deinit();
            const val_bytes = try value_serializer.serializeToRef(self.allocator, value);
            defer val_bytes.deinit();

            const txn = try ret(c.mdb_txn_begin, .{ self.env, null, 0 });
            errdefer c.mdb_txn_abort(txn);

            var key_val = toVal(key_bytes.data);
            var val_val = toVal(val_bytes.data);
            try result(c.mdb_put(txn, self.dbi(cf), &key_val, &val_val, 0));
            try result(c.mdb_txn_commit(txn));
        }

        pub fn get(
            self: *Self,
            allocator: Allocator,
            comptime cf: ColumnFamily,
            key: cf.Key,
        ) anyerror!?cf.Value {
            const key_bytes = try key_serializer.serializeToRef(self.allocator, key);
            defer key_bytes.deinit();
            var key_val = toVal(key_bytes.data);

            const txn = try ret(c.mdb_txn_begin, .{ self.env, null, MDB_RDONLY });
            defer c.mdb_txn_abort(txn);

            const value = ret(c.mdb_get, .{ txn, self.dbi(cf), &key_val }) catch |e| switch (e) {
                error.MDB_NOTFOUND => return null,
                else => return e,
            };

            return try value_serializer.deserialize(cf.Value, allocator, fromVal(value));
        }

        pub fn getBytes(self: *Self, comptime cf: ColumnFamily, key: cf.Key) anyerror!?BytesRef {
            const key_bytes = try key_serializer.serializeToRef(self.allocator, key);
            defer key_bytes.deinit();
            var key_val = toVal(key_bytes.data);

            const txn = try ret(c.mdb_txn_begin, .{ self.env, null, MDB_RDONLY });
            errdefer c.mdb_txn_abort(txn);

            const item = try ret(c.mdb_get, .{ txn, self.dbi(cf), &key_val }) catch |e| switch (e) {
                error.MDB_NOTFOUND => return null,
                else => return e,
            };

            return .{
                .allocator = txnResetter(txn),
                .data = fromVal(item),
            };
        }

        pub fn contains(self: *Self, comptime cf: ColumnFamily, key: cf.Key) anyerror!bool {
            return try self.getBytes(cf, key) != null;
        }

        pub fn delete(self: *Self, comptime cf: ColumnFamily, key: cf.Key) anyerror!void {
            const key_bytes = try key_serializer.serializeToRef(self.allocator, key);
            defer key_bytes.deinit();
            var key_val = toVal(key_bytes.data);
            var val_val: c.MDB_val = undefined;

            const txn = try ret(c.mdb_txn_begin, .{ self.env, null, 0 });
            errdefer c.mdb_txn_abort(txn);

            result(c.mdb_del(txn, self.dbi(cf), &key_val, &val_val)) catch |e| switch (e) {
                error.MDB_NOTFOUND => {},
                else => return e,
            };
            try result(c.mdb_txn_commit(txn));
        }

        pub fn deleteFilesInRange(
            self: *Self,
            comptime cf: ColumnFamily,
            start: cf.Key,
            end: cf.Key,
        ) anyerror!void {
            var batch = try self.initWriteBatch();
            errdefer batch.deinit();
            try batch.deleteRange(cf, start, end);
            try self.commit(batch);
        }

        pub fn initWriteBatch(self: *Self) anyerror!WriteBatch {
            const executed = try self.allocator.create(bool);
            errdefer self.allocator.destroy(executed);
            executed.* = false;
            return .{
                .allocator = self.allocator,
                .txn = try ret(c.mdb_txn_begin, .{ self.env, null, 0 }),
                .dbis = self.dbis,
                .executed = executed,
            };
        }

        pub fn commit(_: *Self, batch: WriteBatch) LmdbError!void {
            try result(c.mdb_txn_commit(batch.txn));
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
            txn: *c.MDB_txn,
            dbis: []const c.MDB_dbi,
            executed: *bool,

            pub fn deinit(self: *WriteBatch) void {
                if (!self.executed.*) c.mdb_txn_abort(self.txn);
                self.allocator.destroy(self.executed);
            }

            fn dbi(self: *WriteBatch, comptime cf: ColumnFamily) c.MDB_dbi {
                return self.dbis[cf.find(column_families)];
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

                var key_val = toVal(key_bytes.data);
                var val_val = toVal(val_bytes.data);
                try result(c.mdb_put(self.txn, self.dbi(cf), &key_val, &val_val, 0));
            }

            pub fn delete(
                self: *WriteBatch,
                comptime cf: ColumnFamily,
                key: cf.Key,
            ) anyerror!void {
                const key_bytes = try key_serializer.serializeToRef(self.allocator, key);
                defer key_bytes.deinit();

                var key_val = toVal(key_bytes.data);
                try result(c.mdb_del(self.txn, self.dbi(cf), &key_val, 0));
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

                const cursor = try ret(c.mdb_cursor_open, .{ self.txn, self.dbi(cf) });
                defer c.mdb_cursor_close(cursor);

                var key, _ = if (try cursorGet(cursor, start_bytes.data, .set_range)) |kv|
                    kv
                else
                    return;

                while (std.mem.lessThan(u8, key, end_bytes.data)) {
                    try result(c.mdb_cursor_del(cursor, 0));
                    key, _ = try cursorGetRelative(cursor, .next) orelse return;
                }
            }
        };

        pub fn iterator(
            self: *Self,
            comptime cf: ColumnFamily,
            comptime direction: IteratorDirection,
            start: ?cf.Key,
        ) anyerror!Iterator(cf, direction) {
            const maybe_start_bytes = if (start) |s|
                try key_serializer.serializeToRef(self.allocator, s)
            else
                null;
            defer if (maybe_start_bytes) |sb| sb.deinit();

            const txn = try ret(c.mdb_txn_begin, .{ self.env, null, 0 });
            errdefer c.mdb_txn_abort(txn);

            const cursor = try ret(c.mdb_cursor_open, .{ txn, self.dbi(cf) });
            errdefer c.mdb_cursor_close(cursor);

            var start_operation: CursorRelativeOperation = .get_current;

            if (null == try cursorGetRelative(cursor, .first)) {
                // if the db is empty, it has this annoying behavior where a call to
                // GET_CURRENT results in EINVAL. but we want it to return NOTFOUND.
                // calling NEXT ensures that NOTFOUND will be returned.
                start_operation = .next;
            } else if (maybe_start_bytes) |start_bytes| {
                switch (direction) {
                    .forward => _ = try cursorGet(cursor, start_bytes.data, .set_range),
                    .reverse => if (null == try cursorGet(cursor, start_bytes.data, .set)) {
                        _ = try cursorGet(cursor, start_bytes.data, .set_range);
                        start_operation = .prev;
                    },
                }
            } else if (direction == .reverse) {
                _ = try cursorGetRelative(cursor, .last);
            }

            return .{
                .allocator = self.allocator,
                .txn = txn,
                .cursor = cursor,
                .direction = switch (direction) {
                    .forward => .next,
                    .reverse => .prev,
                },
                .next_operation = start_operation,
            };
        }

        pub fn Iterator(cf: ColumnFamily, _: IteratorDirection) type {
            return struct {
                allocator: Allocator,
                txn: *c.MDB_txn,
                cursor: *c.MDB_cursor,
                direction: CursorRelativeOperation,
                next_operation: CursorRelativeOperation,

                /// Calling this will free all slices returned by the iterator
                pub fn deinit(self: *@This()) void {
                    c.mdb_cursor_close(self.cursor);
                    c.mdb_txn_abort(self.txn);
                }

                pub fn next(self: *@This()) anyerror!?cf.Entry() {
                    const key, const val = try self.nextImpl() orelse return null;
                    return .{
                        try key_serializer.deserialize(cf.Key, self.allocator, key),
                        try value_serializer.deserialize(cf.Value, self.allocator, val),
                    };
                }

                pub fn nextKey(self: *@This()) anyerror!?cf.Key {
                    const key, _ = try self.nextImpl() orelse return null;
                    return try key_serializer.deserialize(cf.Key, self.allocator, key);
                }

                pub fn nextValue(self: *@This()) anyerror!?cf.Value {
                    _, const val = try self.nextImpl() orelse return null;
                    return try key_serializer.deserialize(cf.Key, self.allocator, val);
                }

                /// Returned data does not outlive the iterator.
                pub fn nextBytes(self: *@This()) LmdbError!?[2]BytesRef {
                    const key, const val = try self.nextImpl() orelse return null;
                    return .{
                        .{ .allocator = null, .data = key },
                        .{ .allocator = null, .data = val },
                    };
                }

                fn nextImpl(self: *@This()) LmdbError!?struct { []const u8, []const u8 } {
                    defer self.next_operation = self.direction;
                    return try cursorGetRelative(self.cursor, self.next_operation);
                }
            };
        }
    };
}

fn toVal(bytes: []const u8) c.MDB_val {
    return .{
        .mv_size = bytes.len,
        .mv_data = @constCast(@ptrCast(bytes.ptr)),
    };
}

fn fromVal(value: c.MDB_val) []const u8 {
    const ptr: [*c]u8 = @ptrCast(value.mv_data);
    return ptr[0..value.mv_size];
}

fn txnResetter(txn: *c.MDB_txn) Allocator {
    return .{
        .ptr = @ptrCast(@alignCast(txn)),
        .vtable = .{
            .alloc = &sig.utils.allocators.noAlloc,
            .resize = &Allocator.noResize,
            .free = &resetTxnFree,
        },
    };
}

fn resetTxnFree(ctx: *anyopaque, _: []u8, _: u8, _: usize) void {
    const txn: *c.MDB_txn = @ptrCast(@alignCast(ctx));
    c.mdb_txn_abort(txn);
}

fn ret(constructor: anytype, args: anytype) LmdbError!TypeToCreate(constructor) {
    const Intermediate = IntermediateType(constructor);
    var maybe: IntermediateType(constructor) = switch (@typeInfo(Intermediate)) {
        .Optional => null,
        .Int => 0,
        else => undefined,
    };
    try result(@call(.auto, constructor, args ++ .{&maybe}));
    return switch (@typeInfo(Intermediate)) {
        .Optional => maybe.?,
        else => maybe,
    };
}

fn TypeToCreate(function: anytype) type {
    const InnerType = IntermediateType(function);
    return switch (@typeInfo(InnerType)) {
        .Optional => |o| o.child,
        else => InnerType,
    };
}

fn IntermediateType(function: anytype) type {
    const params = @typeInfo(@TypeOf(function)).Fn.params;
    return @typeInfo(params[params.len - 1].type.?).Pointer.child;
}

const MDB_CREATE = 0x40000;
const MDB_RDONLY = 0x20000;

fn cursorGet(
    cursor: *c.MDB_cursor,
    key: []const u8,
    operation: CursorAbsoluteOperation,
) LmdbError!?struct { []const u8, []const u8 } {
    var key_val = toVal(key);
    var val_val: c.MDB_val = undefined;
    result(c.mdb_cursor_get(
        cursor,
        &key_val,
        &val_val,
        @intFromEnum(operation),
    )) catch |err| switch (err) {
        error.MDB_NOTFOUND => return null,
        else => return err,
    };
    return .{ fromVal(key_val), fromVal(val_val) };
}

fn cursorGetRelative(
    cursor: *c.MDB_cursor,
    operation: CursorRelativeOperation,
) LmdbError!?struct { []const u8, []const u8 } {
    var key_val: c.MDB_val = undefined;
    var val_val: c.MDB_val = undefined;
    result(c.mdb_cursor_get(
        cursor,
        &key_val,
        &val_val,
        @intFromEnum(operation),
    )) catch |err| switch (err) {
        error.MDB_NOTFOUND => return null,
        else => return err,
    };
    return .{ fromVal(key_val), fromVal(val_val) };
}

/// Cursor Get operations that require a key to execute a lookup
const CursorAbsoluteOperation = enum(c_uint) {
    /// Position at key/data pair. Only for #MDB_DUPSORT
    get_both = 2,
    /// position at key, nearest data. Only for #MDB_DUPSORT
    get_both_range = 3,

    /// Position at specified key
    set = 15,
    /// Position at specified key, return key + data
    set_key = 16,
    /// Position at first key greater than or equal to specified key.
    set_range = 17,
};

/// Cursor Get operations that do *not* require a key to execute a lookup
const CursorRelativeOperation = enum(c_uint) {
    /// Position at first key/data item
    first = 0,
    /// Position at first data item of current key. Only for #MDB_DUPSORT
    first_dup = 1,

    /// Return key/data at current cursor position
    get_current = 4,
    /// Return up to a page of duplicate data items from current cursor position.
    /// Move cursor to prepare for #MDB_NEXT_MULTIPLE. Only for #MDB_DUPFIXED
    get_multiple = 5,
    /// Position at last key/data item
    last = 6,
    /// Position at last data item of current key. Only for #MDB_DUPSORT
    last_dup = 7,
    /// Position at next data item
    next = 8,
    /// Position at next data item of current key. Only for #MDB_DUPSORT
    next_dup = 9,
    /// Return up to a page of duplicate data items from next cursor position.
    /// Move cursor to prepare for #MDB_NEXT_MULTIPLE. Only for #MDB_DUPFIXED
    next_multiple = 10,
    /// Position at first data item of next key
    next_nodup = 11,
    /// Position at previous data item
    prev = 12,
    /// Position at previous data item of current key. Only for #MDB_DUPSORT
    prev_dup = 13,
    /// Position at last data item of previous key
    prev_nodup = 14,

    /// Position at previous page and return up to a page of duplicate data items.
    /// Only for #MDB_DUPFIXED
    prev_multiple = 18,
};

fn result(int: isize) LmdbError!void {
    return switch (int) {
        0 => {},
        -30799 => error.MDB_KEYEXIST,
        -30798 => error.MDB_NOTFOUND,
        -30797 => error.MDB_PAGE_NOTFOUND,
        -30796 => error.MDB_CORRUPTED,
        -30795 => error.MDB_PANIC,
        -30794 => error.MDB_VERSION_MISMATCH,
        -30793 => error.MDB_INVALID,
        -30792 => error.MDB_MAP_FULL,
        -30791 => error.MDB_DBS_FULL,
        -30790 => error.MDB_READERS_FULL,
        -30789 => error.MDB_TLS_FULL,
        -30788 => error.MDB_TXN_FULL,
        -30787 => error.MDB_CURSOR_FULL,
        -30786 => error.MDB_PAGE_FULL,
        -30785 => error.MDB_MAP_RESIZED,
        -30784 => error.MDB_INCOMPATIBLE,
        -30783 => error.MDB_BAD_RSLOT,
        -30782 => error.MDB_BAD_TXN,
        -30781 => error.MDB_BAD_VALSIZE,
        -30780 => error.MDB_BAD_DBI,
        -30779 => error.MDB_PROBLEM,
        1 => error.EPERM,
        2 => error.ENOENT,
        3 => error.ESRCH,
        4 => error.EINTR,
        5 => error.EIO,
        6 => error.ENXIO,
        7 => error.E2BIG,
        8 => error.ENOEXEC,
        9 => error.EBADF,
        10 => error.ECHILD,
        11 => error.EAGAIN,
        12 => error.ENOMEM,
        13 => error.EACCES,
        14 => error.EFAULT,
        15 => error.ENOTBLK,
        16 => error.EBUSY,
        17 => error.EEXIST,
        18 => error.EXDEV,
        19 => error.ENODEV,
        20 => error.ENOTDIR,
        21 => error.EISDIR,
        22 => error.EINVAL,
        23 => error.ENFILE,
        24 => error.EMFILE,
        25 => error.ENOTTY,
        26 => error.ETXTBSY,
        27 => error.EFBIG,
        28 => error.ENOSPC,
        29 => error.ESPIPE,
        30 => error.EROFS,
        31 => error.EMLINK,
        32 => error.EPIPE,
        33 => error.EDOM,
        34 => error.ERANGE,
        else => error.UnspecifiedErrorCode,
    };
}

pub const LmdbError = error{
    ////////////////////////////////////////////////////////
    /// lmdb-specific errors
    ////

    /// Successful result
    MDB_SUCCESS,
    /// key/data pair already exists
    MDB_KEYEXIST,
    /// key/data pair not found (EOF)
    MDB_NOTFOUND,
    /// Requested page not found - this usually indicates corruption
    MDB_PAGE_NOTFOUND,
    /// Located page was wrong type
    MDB_CORRUPTED,
    /// Update of meta page failed or environment had fatal error
    MDB_PANIC,
    /// Environment version mismatch
    MDB_VERSION_MISMATCH,
    /// File is not a valid LMDB file
    MDB_INVALID,
    /// Environment mapsize reached
    MDB_MAP_FULL,
    /// Environment maxdbs reached
    MDB_DBS_FULL,
    /// Environment maxreaders reached
    MDB_READERS_FULL,
    /// Too many TLS keys in use - Windows only
    MDB_TLS_FULL,
    /// Txn has too many dirty pages
    MDB_TXN_FULL,
    /// Cursor stack too deep - internal error
    MDB_CURSOR_FULL,
    /// Page has not enough space - internal error
    MDB_PAGE_FULL,
    /// Database contents grew beyond environment mapsize
    MDB_MAP_RESIZED,
    /// Operation and DB incompatible, or DB type changed. This can mean:
    /// The operation expects an #MDB_DUPSORT / #MDB_DUPFIXED database.
    /// Opening a named DB when the unnamed DB has #MDB_DUPSORT / #MDB_INTEGERKEY.
    /// Accessing a data record as a database, or vice versa.
    /// The database was dropped and recreated with different flags.
    MDB_INCOMPATIBLE,
    /// Invalid reuse of reader locktable slot
    MDB_BAD_RSLOT,
    /// Transaction must abort, has a child, or is invalid
    MDB_BAD_TXN,
    /// Unsupported size of key/DB name/data, or wrong DUPFIXED size
    MDB_BAD_VALSIZE,
    /// The specified DBI was changed unexpectedly
    MDB_BAD_DBI,
    /// Unexpected problem - txn should abort
    MDB_PROBLEM,

    ////////////////////////////////////////////////////////
    /// asm-generic errors - may be thrown by lmdb
    ////

    /// Operation not permitted
    EPERM,
    /// No such file or directory
    ENOENT,
    /// No such process
    ESRCH,
    /// Interrupted system call
    EINTR,
    /// I/O error
    EIO,
    /// No such device or address
    ENXIO,
    /// Argument list too long
    E2BIG,
    /// Exec format error
    ENOEXEC,
    /// Bad file number
    EBADF,
    /// No child processes
    ECHILD,
    /// Try again
    EAGAIN,
    /// Out of memory
    ENOMEM,
    /// Permission denied
    EACCES,
    /// Bad address
    EFAULT,
    /// Block device required
    ENOTBLK,
    /// Device or resource busy
    EBUSY,
    /// File exists
    EEXIST,
    /// Cross-device link
    EXDEV,
    /// No such device
    ENODEV,
    /// Not a directory
    ENOTDIR,
    /// Is a directory
    EISDIR,
    /// Invalid argument
    EINVAL,
    /// File table overflow
    ENFILE,
    /// Too many open files
    EMFILE,
    /// Not a typewriter
    ENOTTY,
    /// Text file busy
    ETXTBSY,
    /// File too large
    EFBIG,
    /// No space left on device
    ENOSPC,
    /// Illegal seek
    ESPIPE,
    /// Read-only file system
    EROFS,
    /// Too many links
    EMLINK,
    /// Broken pipe
    EPIPE,
    /// Math argument out of domain of func
    EDOM,
    /// Math result not representable
    ERANGE,

    ////////////////////////////////////////////////////////
    /// errors interfacing with Lmdb
    ////

    /// Got a return value that is not specified in LMDB's header files
    UnspecifiedErrorCode,
};

comptime {
    _ = &database.interface.testDatabase(LMDB);
}