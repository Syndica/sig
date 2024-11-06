const std = @import("std");
const c = @import("lmdb");
const sig = @import("../../sig.zig");
const database = @import("lib.zig");
const build_options = @import("build-options");

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
        path: [:0]const u8,

        const Self = @This();

        pub fn open(allocator: Allocator, logger: Logger, path: []const u8) anyerror!Self {
            logger.info().log("Initializing LMDB");
            const owned_path = try allocator.dupeZ(u8, path);

            // create and open the database
            const env = try returnOutput(c.mdb_env_create, .{});
            try maybeError(c.mdb_env_set_maxdbs(env, column_families.len));
            try maybeError(c.mdb_env_open(env, owned_path.ptr, 0, 0o700));

            // begin transaction to create column families aka "databases" in lmdb
            const txn = try returnOutput(c.mdb_txn_begin, .{ env, null, 0 });
            errdefer c.mdb_txn_reset(txn);

            // allocate cf handles
            const dbis = try allocator.alloc(c.MDB_dbi, column_families.len);
            errdefer allocator.free(dbis);

            // save cf handles
            inline for (column_families, 0..) |cf, i| {
                // open cf/database, creating if necessary
                dbis[i] = try returnOutput(c.mdb_dbi_open, .{ txn, cf.name.ptr, c.MDB_CREATE });
            }

            // persist column families
            try maybeError(c.mdb_txn_commit(txn));

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
            c.mdb_env_close(self.env);
        }

        fn dbi(self: *Self, comptime cf: ColumnFamily) c.MDB_dbi {
            return self.dbis[cf.find(column_families)];
        }

        pub fn count(self: *Self, comptime cf: ColumnFamily) LmdbOrAllocatorError!u64 {
            const txn = try returnOutput(c.mdb_txn_begin, .{ self.env, null, c.MDB_RDONLY });
            defer c.mdb_txn_abort(txn);

            const stat = try returnOutput(c.mdb_stat, .{ txn, self.dbi(cf) });

            return stat.ms_entries;
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

            const txn = try returnOutput(c.mdb_txn_begin, .{ self.env, null, 0 });
            errdefer c.mdb_txn_reset(txn);

            var key_val = toVal(key_bytes.data);
            var val_val = toVal(val_bytes.data);
            try maybeError(c.mdb_put(txn, self.dbi(cf), &key_val, &val_val, 0));
            try maybeError(c.mdb_txn_commit(txn));
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

            const txn = try returnOutput(c.mdb_txn_begin, .{ self.env, null, c.MDB_RDONLY });
            defer c.mdb_txn_abort(txn);

            const value = returnOutput(c.mdb_get, .{ txn, self.dbi(cf), &key_val }) catch |e| switch (e) {
                error.MDB_NOTFOUND => return null,
                else => return e,
            };

            return try value_serializer.deserialize(cf.Value, allocator, fromVal(value));
        }

        pub fn getBytes(self: *Self, comptime cf: ColumnFamily, key: cf.Key) anyerror!?BytesRef {
            const key_bytes = try key_serializer.serializeToRef(self.allocator, key);
            defer key_bytes.deinit();
            var key_val = toVal(key_bytes.data);

            const txn = try returnOutput(c.mdb_txn_begin, .{ self.env, null, c.MDB_RDONLY });
            errdefer c.mdb_txn_abort(txn);

            const item = returnOutput(c.mdb_get, .{ txn, self.dbi(cf), &key_val }) catch |e| switch (e) {
                error.MDB_NOTFOUND => return null,
                else => return e,
            };

            return .{
                .deinitializer = txnAborter(txn),
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

            const txn = try returnOutput(c.mdb_txn_begin, .{ self.env, null, 0 });
            errdefer c.mdb_txn_reset(txn);

            maybeError(c.mdb_del(txn, self.dbi(cf), &key_val, &val_val)) catch |e| switch (e) {
                error.MDB_NOTFOUND => {},
                else => return e,
            };
            try maybeError(c.mdb_txn_commit(txn));
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
            try self.commit(&batch);
        }

        pub fn initWriteBatch(self: *Self) anyerror!WriteBatch {
            const executed = try self.allocator.create(bool);
            errdefer self.allocator.destroy(executed);
            executed.* = false;
            return .{
                .allocator = self.allocator,
                .txn = try returnOutput(c.mdb_txn_begin, .{ self.env, null, 0 }),
                .dbis = self.dbis,
                .executed = executed,
            };
        }

        pub fn commit(_: *Self, batch: *WriteBatch) LmdbError!void {
            try maybeError(c.mdb_txn_commit(batch.txn));
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
                if (!self.executed.*) c.mdb_txn_reset(self.txn);
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
                try maybeError(c.mdb_put(self.txn, self.dbi(cf), &key_val, &val_val, 0));
            }

            pub fn delete(
                self: *WriteBatch,
                comptime cf: ColumnFamily,
                key: cf.Key,
            ) anyerror!void {
                const key_bytes = try key_serializer.serializeToRef(self.allocator, key);
                defer key_bytes.deinit();

                var key_val = toVal(key_bytes.data);
                try maybeError(c.mdb_del(self.txn, self.dbi(cf), &key_val, 0));
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

                const cursor = try returnOutput(c.mdb_cursor_open, .{ self.txn, self.dbi(cf) });
                defer c.mdb_cursor_close(cursor);

                var key, _ = if (try cursorGet(cursor, start_bytes.data, .set_range)) |kv|
                    kv
                else
                    return;

                while (std.mem.lessThan(u8, key, end_bytes.data)) {
                    try maybeError(c.mdb_cursor_del(cursor, 0));
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

            const txn = try returnOutput(c.mdb_txn_begin, .{ self.env, null, c.MDB_RDONLY });
            errdefer c.mdb_txn_abort(txn);

            const cursor = try returnOutput(c.mdb_cursor_open, .{ txn, self.dbi(cf) });
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
                    return try key_serializer.deserialize(cf.Value, self.allocator, val);
                }

                /// Returned data does not outlive the iterator.
                pub fn nextBytes(self: *@This()) LmdbError!?[2]BytesRef {
                    const key, const val = try self.nextImpl() orelse return null;
                    return .{
                        .{ .deinitializer = null, .data = key },
                        .{ .deinitializer = null, .data = val },
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
    const ptr: [*]u8 = @ptrCast(value.mv_data);
    return ptr[0..value.mv_size];
}

/// Returns an `BytesRef.Deinitializer` that frees memory by aborting the transaction
/// that owns the memory.
///
/// Calling `deinit` with any input will free all memory that was allocated
/// by the transaction. This means you cannot manage lifetimes of multiple
/// items separately. Ideally you would only use this when you've only
/// read exactly one item in the transaction.
fn txnAborter(txn: *c.MDB_txn) BytesRef.Deinitializer {
    return BytesRef.Deinitializer.init(txn, resetTxnFree);
}

fn resetTxnFree(txn: *c.MDB_txn, _: []const u8) void {
    c.mdb_txn_abort(txn);
}

/// Call an LMDB function and return its combined output as an error union.
///
/// This converts parameter-based outputs into return values, and converts error
/// code integers into zig errors.
///
/// LMDB functions only return integers representing an error code. If the
/// function actually needs to provide more data as an output, the caller needs
/// to pass in a pointer as the final argument to the function. LMDB will write
/// the output data to that pointer. This makes LMDB cumbersome to use because it
/// requires you to have a few extra lines of code every time you call an LMDB
/// function that has any outputs. This function implements this process for you,
/// so you can get the output data as a normal return value.
///
/// To use it, pass in the LMDB function you'd like to call, and all of the
/// arguments for that function *except the last*. The last argument is for the
/// output, and will be provided by this function.
///
/// Without `returnOutput`:
/// ```zig
/// const maybe_env: ?*MDB_env = null;
/// try maybeError(c.mdb_env_create(&maybe_env));
/// const env = maybe_env.?;
/// ```
///
/// With `returnOutput`:
/// ```zig
/// const env = try returnOutput(c.mdb_env_create, .{});
/// ```
fn returnOutput(fn_with_output: anytype, args: anytype) LmdbError!OutputType(fn_with_output) {
    // create a local variable to hold the function's output.
    const MaybeOutput = LastParamChild(fn_with_output);
    var maybe_output: MaybeOutput = switch (@typeInfo(MaybeOutput)) {
        .Optional => null,
        .Int => 0,
        else => undefined,
    };

    // call the function, passing a pointer to the output variable.
    // check the return code, and return an error if there was an error.
    try maybeError(@call(.auto, fn_with_output, args ++ .{&maybe_output}));

    // return the output value, unwrapping the optional if needed.
    return switch (@typeInfo(MaybeOutput)) {
        .Optional => maybe_output.?,
        else => maybe_output,
    };
}

/// For an LMDB function that provides its output by writing to a pointer, this
/// is the data type of the output.
fn OutputType(fn_with_output: anytype) type {
    const InnerType = LastParamChild(fn_with_output);
    return switch (@typeInfo(InnerType)) {
        .Optional => |o| o.child,
        else => InnerType,
    };
}

/// Returns the child type of the last parameter of a function,
/// assuming that parameter is a pointer.
fn LastParamChild(function: anytype) type {
    const params = @typeInfo(@TypeOf(function)).Fn.params;
    return @typeInfo(params[params.len - 1].type.?).Pointer.child;
}

fn cursorGet(
    cursor: *c.MDB_cursor,
    key: []const u8,
    operation: CursorAbsoluteOperation,
) LmdbError!?struct { []const u8, []const u8 } {
    var key_val = toVal(key);
    var val_val: c.MDB_val = undefined;
    maybeError(c.mdb_cursor_get(
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
    maybeError(c.mdb_cursor_get(
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

/// Converts an error return code from LMDB into an error union
fn maybeError(int: isize) LmdbError!void {
    return switch (int) {
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
        else => sig.utils.errors.errnoToError(@enumFromInt(int)),
    };
}

pub const LmdbOrAllocatorError = LmdbError || Allocator.Error;

pub const LmdbError = sig.utils.errors.LibcError || error{
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
};

comptime {
    if (build_options.blockstore_db == .lmdb) {
        _ = &database.interface.testDatabase(LMDB);
    }
}
