//! Database for rooted accounts.
const std = @import("std");
const builtin = @import("builtin");
const sig = @import("../../sig.zig");
const sql = @import("sqlite");
const tracy = @import("tracy");
const zstd = @import("zstd");
const Rooted = @This();

const Slot = sig.core.Slot;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const AccountSharedData = sig.runtime.AccountSharedData;

const StatusCache = sig.accounts_db.snapshot.StatusCache;
const Manifest = sig.accounts_db.snapshot.Manifest;
const SnapshotFiles = sig.accounts_db.snapshot.SnapshotFiles;
const FullAndIncrementalManifest = sig.accounts_db.snapshot.FullAndIncrementalManifest;

const OK = sql.SQLITE_OK;
const DONE = sql.SQLITE_DONE;
const ROW = sql.SQLITE_ROW;

/// Handle to the underlying sqlite database.
handle: *sql.sqlite3,
/// Tracks the largest rooted slot.
largest_rooted_slot: ?Slot,

/// These aren't thread safe, but we can have as many as we want. Clean up with deinitThreadLocals
/// on any threads that use put or get.
threadlocal var put_stmt: ?*sql.sqlite3_stmt = null;
threadlocal var get_stmt: ?*sql.sqlite3_stmt = null;

pub fn init(file_path: [:0]const u8) !Rooted {
    const zone = tracy.Zone.init(@src(), .{ .name = "Rooted.init" });
    defer zone.deinit();

    const db = blk: {
        var maybe_db: ?*sql.sqlite3 = null;
        if (sql.sqlite3_open(file_path.ptr, &maybe_db) != OK)
            return error.FailedToOpenDb;
        break :blk maybe_db orelse return error.SqliteDbNull;
    };

    var self: Rooted = .{
        .handle = db,
        .largest_rooted_slot = null,
    };

    if (self.isEmpty()) {
        const schema =
            \\ PRAGMA journal_mode = OFF;
            \\ PRAGMA synchronous = 0;
            \\ PRAGMA cache_size = 1000000;
            \\ PRAGMA locking_mode = EXCLUSIVE;
            \\ PRAGMA temp_store = MEMORY;
            \\ PRAGMA page_size = 65536;
            \\
            \\CREATE TABLE IF NOT EXISTS entries (
            \\  address BLOB(32) NOT NULL UNIQUE,
            \\  lamports INTEGER NOT NULL,
            \\  data BLOB NOT NULL,
            \\  owner BLOB(32) NOT NULL,
            \\  executable INTEGER NOT NULL,
            \\  rent_epoch INTEGER NOT NULL,
            \\  last_modified_slot INTEGER NOT NULL
            \\);
        ;

        if (sql.sqlite3_exec(db, schema, null, null, null) != OK) {
            std.debug.print("err  {s}\n", .{sql.sqlite3_errmsg(db)});
            return error.FailedToCreateTables;
        }
    }

    return self;
}

pub fn deinit(self: *Rooted) void {
    _ = sql.sqlite3_close(self.handle);
}

/// Call this before a thread that accesses Rooted closes. Safe to call multiple times.
pub fn deinitThreadLocals() void {
    if (put_stmt) |stmt| {
        _ = sql.sqlite3_finalize(stmt);
        put_stmt = null;
    }
    if (get_stmt) |stmt| {
        _ = sql.sqlite3_finalize(stmt);
        get_stmt = null;
    }
}

pub fn isEmpty(self: *Rooted) bool {
    const query = "SELECT count(*) from entries";

    var stmt: ?*sql.sqlite3_stmt = null;
    defer if (stmt) |st| std.debug.assert(sql.sqlite3_finalize(st) == OK);
    const prep_err = sql.sqlite3_prepare_v2(self.handle, query, -1, &stmt, null);
    if (prep_err != OK) return true; // table does not exist

    const rc = sql.sqlite3_step(stmt);
    if (rc != ROW) return true; // other err

    return sql.sqlite3_column_int64(stmt, 0) == 0;
}

/// Returns `null` if no such account exists.
///
/// The `data` field in the returned `AccountSharedData` is owned by the caller and is allocated
/// by the provided allocator.
///
/// TODO: we really don't want to be doing these clones, so some other solution would be good.
/// TODO: getBatched() to SELECT from multiple pubkeys
pub fn get(
    self: *Rooted,
    allocator: std.mem.Allocator,
    address: Pubkey,
) error{OutOfMemory}!?AccountSharedData {
    const zone = tracy.Zone.init(@src(), .{ .name = "Rooted.get" });
    defer zone.deinit();

    const stmt: *sql.sqlite3_stmt = if (get_stmt) |stmt| stmt else blk: {
        const query =
            \\SELECT lamports, data, owner, executable, rent_epoch 
            \\FROM entries WHERE address = ?;
        ;
        self.err(sql.sqlite3_prepare_v2(self.handle, query, -1, &get_stmt, null));
        break :blk get_stmt.?;
    };
    defer std.debug.assert(sql.sqlite3_reset(stmt) == OK);

    self.err(sql.sqlite3_bind_blob(stmt, 1, &address.data, Pubkey.SIZE, sql.SQLITE_STATIC));

    const rc = sql.sqlite3_step(stmt);

    switch (rc) {
        ROW => {}, // ok
        DONE => return null, // not found
        else => self.err(rc),
    }

    const data = blk: {
        const len: usize = @intCast(sql.sqlite3_column_bytes(stmt, 1));
        if (len == 0) break :blk &.{}; // sqlite returns null pointers for 0-len data
        const ptr: [*]const u8 = @ptrCast(sql.sqlite3_column_blob(stmt, 1));
        break :blk ptr[0..len];
    };

    const duped = try allocator.dupe(u8, data);
    errdefer allocator.free(duped);

    const owner_ptr: [*]const u8 = @ptrCast(sql.sqlite3_column_blob(stmt, 2));
    const owner: Pubkey = .{ .data = owner_ptr[0..32].* };

    return .{
        .lamports = @bitCast(sql.sqlite3_column_int64(stmt, 0)),
        .data = duped,
        .owner = owner,
        .executable = sql.sqlite3_column_int(stmt, 3) != 0,
        .rent_epoch = @bitCast(sql.sqlite3_column_int64(stmt, 4)),
    };
}

pub fn getLargestRootedSlot(self: *const Rooted) ?Slot {
    if (!builtin.is_test) @compileError("only used in tests");
    return self.largest_rooted_slot;
}

fn err(self: *Rooted, code: c_int) void {
    if (code == OK) return;
    std.debug.panic(
        "internal accountsdb sqlite error ({}): {s}\n",
        .{ code, sql.sqlite3_errmsg(self.handle) },
    );
}

pub fn beginTransaction(self: *Rooted) void {
    self.err(sql.sqlite3_exec(self.handle, "BEGIN TRANSACTION;", null, null, null));
}

pub fn commitTransaction(self: *Rooted) void {
    const zone = tracy.Zone.init(@src(), .{ .name = "Rooted.commitTransaction" });
    defer zone.deinit();

    self.err(sql.sqlite3_exec(self.handle, "COMMIT;", null, null, null));
}

/// Should not be called outside of snapshot loading or slot rooting.
/// TODO: write putRootedSlot(slot, []pk, []account) and make that public instead.
pub fn put(self: *Rooted, address: Pubkey, slot: Slot, account: AccountSharedData) void {
    const stmt: *sql.sqlite3_stmt = if (put_stmt) |stmt| stmt else blk: {
        // Insert or update only if last_modified_slot is greater (excluded = VALUES)
        // https://sqlite.org/lang_upsert.html#examples
        const query =
            \\INSERT INTO entries 
            \\(address, lamports, data, owner, executable, rent_epoch, last_modified_slot)
            \\VALUES (?, ?, ?, ?, ?, ?, ?)
            \\ON CONFLICT(address) DO UPDATE SET
            \\  lamports=excluded.lamports,
            \\  data=excluded.data,
            \\  owner=excluded.owner,
            \\  executable=excluded.executable,
            \\  rent_epoch=excluded.rent_epoch,
            \\  last_modified_slot=excluded.last_modified_slot
            \\WHERE excluded.last_modified_slot > entries.last_modified_slot
            \\;
        ;
        self.err(sql.sqlite3_prepare_v2(self.handle, query, -1, &put_stmt, null));
        break :blk put_stmt.?;
    };
    defer std.debug.assert(sql.sqlite3_reset(stmt) == OK);

    self.err(sql.sqlite3_bind_blob(stmt, 1, &address.data, Pubkey.SIZE, sql.SQLITE_STATIC));
    self.err(sql.sqlite3_bind_int64(stmt, 2, @bitCast(account.lamports)));
    self.err(sql.sqlite3_bind_blob(
        stmt,
        3,
        account.data.ptr,
        @intCast(account.data.len),
        sql.SQLITE_STATIC,
    ));
    self.err(sql.sqlite3_bind_blob(
        stmt,
        4,
        &account.owner.data,
        Pubkey.SIZE,
        sql.SQLITE_STATIC,
    ));
    self.err(sql.sqlite3_bind_int(stmt, 5, @intFromBool(account.executable)));
    self.err(sql.sqlite3_bind_int64(stmt, 6, @bitCast(account.rent_epoch)));

    self.err(sql.sqlite3_bind_int64(stmt, 7, @bitCast(slot)));

    const result = sql.sqlite3_step(stmt);
    if (result != DONE) self.err(result);
}
