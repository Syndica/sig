//! Database for rooted accounts.
const std = @import("std");
const builtin = @import("builtin");
const sig = @import("../sig.zig");
const sql = @import("sqlite");
const tracy = @import("tracy");
const Rooted = @This();

const ids = sig.runtime.ids;

const Slot = sig.core.Slot;
const Pubkey = sig.core.Pubkey;
const Account = sig.core.Account;
const AccountSharedData = sig.runtime.AccountSharedData;
const Gauge = sig.prometheus.Gauge(u64);
const ThreadPool = sig.sync.ThreadPool;

const OK = sql.SQLITE_OK;
const DONE = sql.SQLITE_DONE;
const ROW = sql.SQLITE_ROW;

/// Handle to the underlying sqlite database.
handle: *sql.sqlite3,
/// Tracks the largest rooted slot.
largest_rooted_slot: ?Slot,
/// Updates a prometheus counter for mem usage.
sqlite_mem_used: ?*Gauge = null,
/// Whether the SPL token owner index column is enabled (runtime CLI flag).
enable_spl_token_owner_index: bool,
/// In-memory top-N accounts by lamport balance, updated on every put().
largest_tracker: LargestTracker = .{},

/// These aren't thread safe, but we can have as many as we want. Clean up with deinitThreadLocals
/// on any threads that use put or get.
threadlocal var put_stmt: ?*sql.sqlite3_stmt = null;
threadlocal var put_with_token_owner_stmt: ?*sql.sqlite3_stmt = null;
threadlocal var get_stmt: ?*sql.sqlite3_stmt = null;
threadlocal var get_by_owner_stmt: ?*sql.sqlite3_stmt = null;
threadlocal var get_by_spl_token_owner_stmt: ?*sql.sqlite3_stmt = null;

pub fn init(
    file_path: [:0]const u8,
    enable_owner_index: bool,
    enable_spl_token_owner_index: bool,
) !Rooted {
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
        .enable_spl_token_owner_index = enable_spl_token_owner_index,
    };

    {
        const pragmas =
            \\ PRAGMA journal_mode = OFF;
            \\ PRAGMA synchronous = 0;
            \\ PRAGMA cache_size = -8290304;
            \\ PRAGMA locking_mode = EXCLUSIVE;
            \\ PRAGMA temp_store = MEMORY;
            \\ PRAGMA page_size = 65536;
            \\ PRAGMA cache_spill = OFF;
        ;

        if (sql.sqlite3_exec(db, pragmas, null, null, null) != OK) {
            std.debug.print("err  {s}\n", .{sql.sqlite3_errmsg(db)});
            return error.FailedToSetPragmas;
        }
    }

    if (self.count() == 0) {
        const schema =
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

    if (enable_owner_index) {
        if (sql.sqlite3_exec(
            db,
            "CREATE INDEX IF NOT EXISTS rpc_owner_idx ON entries(owner)",
            null,
            null,
            null,
        ) != OK)
            return error.FailedToCreateIndex;
    } else {
        if (sql.sqlite3_exec(
            db,
            "DROP INDEX IF EXISTS rpc_owner_idx",
            null,
            null,
            null,
        ) != OK)
            return error.FailedToDropIndex;
    }

    if (enable_spl_token_owner_index) {
        // Add nullable token_owner column. Silently ignored if it already exists.
        // NULL means "not a token account", so non-token rows never match
        // `WHERE token_owner = ?` queries (SQL NULL != anything).
        _ = sql.sqlite3_exec(
            db,
            "ALTER TABLE entries ADD COLUMN token_owner BLOB(32) DEFAULT NULL",
            null,
            null,
            null,
        );
        if (sql.sqlite3_exec(
            db,
            "CREATE INDEX IF NOT EXISTS rpc_spl_token_owner_idx ON entries(token_owner)" ++
                " WHERE token_owner IS NOT NULL",
            null,
            null,
            null,
        ) != OK)
            return error.FailedToCreateIndex;
    } else {
        if (sql.sqlite3_exec(
            db,
            "DROP INDEX IF EXISTS rpc_spl_token_owner_idx",
            null,
            null,
            null,
        ) != OK)
            return error.FailedToDropIndex;
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
    if (put_with_token_owner_stmt) |stmt| {
        _ = sql.sqlite3_finalize(stmt);
        put_with_token_owner_stmt = null;
    }
    if (get_stmt) |stmt| {
        _ = sql.sqlite3_finalize(stmt);
        get_stmt = null;
    }
    if (get_by_owner_stmt) |stmt| {
        _ = sql.sqlite3_finalize(stmt);
        get_by_owner_stmt = null;
    }
    if (get_by_spl_token_owner_stmt) |stmt| {
        _ = sql.sqlite3_finalize(stmt);
        get_by_spl_token_owner_stmt = null;
    }
}

pub fn count(self: *const Rooted) u64 {
    const query = "SELECT count(*) from entries";

    var stmt: ?*sql.sqlite3_stmt = null;
    defer if (stmt) |st| std.debug.assert(sql.sqlite3_finalize(st) == OK);
    const prep_err = sql.sqlite3_prepare_v2(self.handle, query, -1, &stmt, null);
    if (prep_err != OK) return 0; // table does not exist

    const rc = sql.sqlite3_step(stmt);
    if (rc != ROW) return 0; // other err

    return @intCast(sql.sqlite3_column_int64(stmt, 0));
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

    {
        const mem_used = sql.sqlite3_memory_used();
        tracy.plot(u48, "sqlite3_memory_used", @intCast(mem_used));
        if (self.sqlite_mem_used) |guage| guage.set(@intCast(mem_used));
    }

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

    const fields = readAccountFields(stmt);

    const duped = try allocator.dupe(u8, fields.data);
    errdefer allocator.free(duped);

    return .{
        .lamports = fields.lamports,
        .data = duped,
        .owner = fields.owner,
        .executable = fields.executable,
        .rent_epoch = fields.rent_epoch,
    };
}

/// Returns an iterator over all accounts with the given `owner`.
/// The caller must ensure `owner` outlives the returned `OwnerIterator`
/// (i.e. remains valid through all `next()` calls and `deinit()`),
/// because the pointer is bound with `SQLITE_STATIC`.
///
/// TODO: Accept getProgramAccounts parameters and build a dynamic query that
/// pushes filters down to the DB level. This would allow:
/// - Filtering out zero-lamport accounts (`lamports > 0`)
/// - Applying `dataSize` / `memcmp` filters in SQL
/// - Fetching only the data slice requested via `dataSlice`
pub fn getByOwner(self: *Rooted, owner: *const Pubkey) OwnerIterator {
    const stmt: *sql.sqlite3_stmt = if (get_by_owner_stmt) |stmt| stmt else blk: {
        const query =
            \\ SELECT lamports, data, owner, executable, rent_epoch, address
            \\ FROM entries WHERE owner = ? AND lamports > 0;
        ;
        self.err(sql.sqlite3_prepare_v2(self.handle, query, -1, &get_by_owner_stmt, null));
        break :blk get_by_owner_stmt.?;
    };

    self.err(sql.sqlite3_bind_blob(
        stmt,
        1,
        owner,
        Pubkey.SIZE,
        sql.SQLITE_STATIC,
    ));
    return .{ .stmt = stmt, .rooted = self };
}

pub const OwnerIterator = struct {
    rooted: *Rooted,
    stmt: *sql.sqlite3_stmt,

    pub fn next(self: *OwnerIterator) ?struct { Pubkey, Account } {
        const rc = sql.sqlite3_step(self.stmt);
        switch (rc) {
            ROW => {},
            DONE => return null,
            else => self.rooted.err(rc),
        }

        const fields = readAccountFields(self.stmt);
        const pubkey: Pubkey = .{
            .data = @as([*]const u8, @ptrCast(sql.sqlite3_column_blob(self.stmt, 5)))[0..32].*,
        };

        return .{
            pubkey, .{
                .lamports = fields.lamports,
                .data = .{ .unowned_allocation = fields.data },
                .owner = fields.owner,
                .executable = fields.executable,
                .rent_epoch = fields.rent_epoch,
            },
        };
    }

    pub fn deinit(self: *OwnerIterator) void {
        defer std.debug.assert(sql.sqlite3_reset(self.stmt) == OK);
    }
};

/// Returns an iterator over all token accounts where the token owner (bytes 32..64
/// of account data) matches the given `token_owner`.
///
/// When `enable_spl_token_owner_index` is true, queries the indexed `token_owner`
/// column. When false, falls back to a full-scan query using `substr(data, 33, 32)`
/// filtered to the SPL Token and Token-2022 program owners.
///
/// The caller must ensure `token_owner` outlives the returned iterator.
pub fn getBySplTokenOwner(self: *Rooted, token_owner: *const Pubkey) OwnerIterator {
    const stmt: *sql.sqlite3_stmt = if (get_by_spl_token_owner_stmt) |stmt| stmt else blk: {
        const query = if (self.enable_spl_token_owner_index)
            // Indexed path: query the token_owner column directly.
            \\ SELECT lamports, data, owner, executable, rent_epoch, address
            \\ FROM entries WHERE token_owner = ? AND lamports > 0;
        else
            // Fallback: full scan extracting the token owner from data bytes 32..64
            // (sqlite substr is 1-based, so byte 33 with length 32).
            // Restricted to SPL Token and Token-2022 program owners.
            " SELECT lamports, data, owner, executable, rent_epoch, address" ++
                " FROM entries WHERE substr(data, 33, 32) = ? AND lamports > 0" ++
                " AND (owner = X'" ++ ids.TOKEN_PROGRAM_ID.hexBytesLower() ++ "'" ++
                " OR owner = X'" ++ ids.TOKEN_2022_PROGRAM_ID.hexBytesLower() ++ "');";
        self.err(sql.sqlite3_prepare_v2(self.handle, query, -1, &get_by_spl_token_owner_stmt, null));
        break :blk get_by_spl_token_owner_stmt.?;
    };

    self.err(sql.sqlite3_bind_blob(
        stmt,
        1,
        token_owner,
        Pubkey.SIZE,
        sql.SQLITE_STATIC,
    ));
    return .{ .stmt = stmt, .rooted = self };
}

/// Reads the common account fields (lamports, data, owner, executable, rent_epoch)
/// from a sqlite row starting at column `base`. The returned `data` slice borrows
/// directly from sqlite's internal buffer and is only valid until the statement is
/// stepped or reset.
fn readAccountFields(stmt: *sql.sqlite3_stmt) struct {
    lamports: u64,
    data: []const u8,
    owner: Pubkey,
    executable: bool,
    rent_epoch: u64,
} {
    const lamports: u64 = @bitCast(sql.sqlite3_column_int64(stmt, 0));
    const data: []const u8 = blk: {
        const len: usize = @intCast(sql.sqlite3_column_bytes(stmt, 1));
        if (len == 0) break :blk &.{};
        const ptr: [*]const u8 = @ptrCast(sql.sqlite3_column_blob(stmt, 1));
        break :blk ptr[0..len];
    };
    const owner: Pubkey = .{
        .data = @as([*]const u8, @ptrCast(sql.sqlite3_column_blob(stmt, 2)))[0..32].*,
    };
    const executable: bool = sql.sqlite3_column_int(stmt, 3) != 0;
    const rent_epoch: u64 = @bitCast(sql.sqlite3_column_int64(stmt, 4));
    return .{
        .lamports = lamports,
        .data = data,
        .owner = owner,
        .executable = executable,
        .rent_epoch = rent_epoch,
    };
}

pub fn computeLtHash(
    self: *const Rooted,
    allocator: std.mem.Allocator,
    pool: *ThreadPool,
) !sig.core.LtHash {
    const zone = tracy.Zone.init(@src(), .{ .name = "Rooted.computeLtHash" });
    defer zone.deinit();

    const Worker = struct {
        task: ThreadPool.Task = .{ .callback = @This().run },
        wg: *std.Thread.WaitGroup,
        rooted: *const Rooted,
        lt_hash: sig.core.LtHash,
        offset: u64,
        limit: u64,

        fn run(task: *ThreadPool.Task) void {
            const worker: *@This() = @alignCast(@fieldParentPtr("task", task));
            defer worker.wg.finish();

            worker.lt_hash = worker.rooted.computeLtHashForAccountRange(
                worker.offset,
                worker.limit,
            ) catch |e| std.debug.panic("computeLtHash fail: {}", .{e});
        }
    };

    const total_accounts = self.count();
    const num_workers = @min(total_accounts, pool.max_threads);
    const accounts_per_worker = @max(1, total_accounts / pool.max_threads);

    var workers: std.ArrayListUnmanaged(Worker) = .{};
    try workers.ensureTotalCapacity(allocator, num_workers);
    defer workers.deinit(allocator);

    {
        var wg = std.Thread.WaitGroup{};
        wg.startMany(num_workers);
        defer wg.wait();

        var batch = ThreadPool.Batch{};
        defer pool.schedule(batch);

        for (0..num_workers) |i| {
            const start = i * accounts_per_worker;
            const end = if (i == num_workers - 1) total_accounts else (i + 1) * accounts_per_worker;

            const worker = workers.addOneAssumeCapacity();
            worker.* = .{
                .rooted = self,
                .wg = &wg,
                .lt_hash = undefined, // filled in by worker
                .offset = start,
                .limit = end - start,
            };
            batch.push(.from(&worker.task));
        }
    }

    var lt_hash: sig.core.LtHash = .IDENTITY;
    for (workers.items) |*worker| lt_hash.mixIn(worker.lt_hash);
    return lt_hash;
}

fn computeLtHashForAccountRange(
    self: *const Rooted,
    offset: u64,
    limit: u64,
) !sig.core.LtHash {
    const zone = tracy.Zone.init(@src(), .{ .name = "Rooted.LtHash" });
    defer zone.deinit();

    const query =
        \\SELECT
        \\address, owner, data, lamports, executable, rent_epoch
        \\FROM entries LIMIT ? OFFSET ?;
    ;

    var stmt: ?*sql.sqlite3_stmt = undefined;
    self.err(sql.sqlite3_prepare_v2(self.handle, query, -1, &stmt, null));
    defer self.err(sql.sqlite3_finalize(stmt));

    self.err(sql.sqlite3_bind_int64(stmt, 1, @intCast(limit)));
    self.err(sql.sqlite3_bind_int64(stmt, 2, @intCast(offset)));

    var lt_hash: sig.core.LtHash = .IDENTITY;
    while (true) {
        const step_result = sql.sqlite3_step(stmt);
        switch (step_result) {
            ROW => {},
            DONE => break,
            else => self.err(step_result),
        }

        const pubkey = blk: {
            const ptr: [*]const u8 = @ptrCast(sql.sqlite3_column_blob(stmt, 0));
            const slice = ptr[0..@intCast(sql.sqlite3_column_bytes(stmt, 0))];
            std.debug.assert(slice.len == Pubkey.SIZE);
            break :blk try Pubkey.fromBytes(slice[0..32].*);
        };

        const owner = blk: {
            const ptr: [*]const u8 = @ptrCast(sql.sqlite3_column_blob(stmt, 1));
            const slice = ptr[0..@intCast(sql.sqlite3_column_bytes(stmt, 1))];
            std.debug.assert(slice.len == Pubkey.SIZE);
            break :blk try Pubkey.fromBytes(slice[0..32].*);
        };

        const data = blk: {
            const len: usize = @intCast(sql.sqlite3_column_bytes(stmt, 2));
            if (len == 0) break :blk &.{}; // sqlite returns null pointers for 0-len data
            const ptr: [*]const u8 = @ptrCast(sql.sqlite3_column_blob(stmt, 2));
            break :blk ptr[0..len];
        };

        const lamports: u64 = @bitCast(sql.sqlite3_column_int64(stmt, 3));
        const executable: bool = sql.sqlite3_column_int(stmt, 4) != 0;
        const rent_epoch: u64 = @bitCast(sql.sqlite3_column_int64(stmt, 5));

        const account: sig.core.Account = .{
            .data = .{ .unowned_allocation = data },
            .executable = executable,
            .lamports = lamports,
            .owner = owner,
            .rent_epoch = rent_epoch,
        };
        lt_hash.mixIn(account.ltHash(pubkey));
    }
    return lt_hash;
}

pub fn getLargestRootedSlot(self: *const Rooted) ?Slot {
    if (!builtin.is_test) @compileError("only used in tests");
    return self.largest_rooted_slot;
}

fn err(self: *const Rooted, code: c_int) void {
    if (code == OK) return;
    std.debug.panic(
        "internal accountsdb sqlite error ({}): {s}\n",
        .{ code, sql.sqlite3_errmsg(self.handle) },
    );
}

/// Switch from exclusive locking + journal OFF (used during snapshot loading
/// for maximum write throughput) to WAL mode, which allows concurrent readers
/// on separate connections. Call once after snapshot loading and before
/// starting the RPC server.
pub fn enableWalMode(self: *Rooted) void {
    // Release the exclusive lock so other connections can access the DB.
    self.err(sql.sqlite3_exec(self.handle,
        \\PRAGMA locking_mode = NORMAL;
    , null, null, null));
    // A read must occur to actually release the EXCLUSIVE lock.
    _ = sql.sqlite3_exec(self.handle, "SELECT 1 FROM entries LIMIT 1;", null, null, null);
    // Enable WAL journal mode for concurrent reader support, and use
    // NORMAL synchronous which is safe with WAL and faster than FULL.
    _ = sql.sqlite3_exec(self.handle,
        \\PRAGMA journal_mode = WAL;
    , null, null, null);
    self.err(sql.sqlite3_exec(self.handle,
        \\PRAGMA synchronous = NORMAL;
    , null, null, null));
}

/// Open a separate read-only connection to the same database file.
/// Requires WAL mode to be enabled on the writer connection first
/// (via `enableWalMode`). The returned handle can be used concurrently
/// with the writer without blocking it.
pub fn initReader(file_path: [:0]const u8) !Rooted {
    const db = blk: {
        var maybe_db: ?*sql.sqlite3 = null;
        if (sql.sqlite3_open(file_path.ptr, &maybe_db) != OK)
            return error.FailedToOpenDb;
        break :blk maybe_db orelse return error.SqliteDbNull;
    };

    // Reader pragmas: WAL mode (auto-detected from the DB file but set
    // explicitly for clarity), smaller cache, and memory temp store.
    const pragmas =
        \\ PRAGMA journal_mode = WAL;
        \\ PRAGMA cache_size = -2097152;
        \\ PRAGMA temp_store = MEMORY;
    ;

    if (sql.sqlite3_exec(db, pragmas, null, null, null) != OK) {
        _ = sql.sqlite3_close(db);
        return error.FailedToSetPragmas;
    }

    return .{
        .handle = db,
        .largest_rooted_slot = null,
        .enable_spl_token_owner_index = false,
    };
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
    const zone = tracy.Zone.init(@src(), .{ .name = "Rooted.put" });
    defer zone.deinit();

    {
        const mem_used = sql.sqlite3_memory_used();
        tracy.plot(u48, "sqlite3_memory_used", @intCast(mem_used));
        if (self.sqlite_mem_used) |guage| guage.set(@intCast(mem_used));
    }

    if (self.enable_spl_token_owner_index and account.data.len >= 64 and
        (account.owner.equals(&ids.TOKEN_PROGRAM_ID) or
            account.owner.equals(&ids.TOKEN_2022_PROGRAM_ID)))
    {
        self.putWithTokenOwner(address, slot, account);
    } else {
        self.putWithoutTokenOwner(address, slot, account);
    }
}

fn putWithoutTokenOwner(
    self: *Rooted,
    address: Pubkey,
    slot: Slot,
    account: AccountSharedData,
) void {
    const stmt: *sql.sqlite3_stmt = if (put_stmt) |stmt| stmt else blk: {
        // Insert or update only if last_modified_slot is greater (excluded = VALUES)
        // https://sqlite.org/lang_upsert.html#examples
        const query = if (self.enable_spl_token_owner_index)
            \\INSERT INTO entries
            \\(address, lamports, data, owner, executable, rent_epoch, last_modified_slot)
            \\VALUES (?, ?, ?, ?, ?, ?, ?)
            \\ON CONFLICT(address) DO UPDATE SET
            \\  lamports=excluded.lamports,
            \\  data=excluded.data,
            \\  owner=excluded.owner,
            \\  executable=excluded.executable,
            \\  rent_epoch=excluded.rent_epoch,
            \\  last_modified_slot=excluded.last_modified_slot,
            \\  token_owner=NULL
            \\WHERE excluded.last_modified_slot > entries.last_modified_slot
            \\;
        else
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
        self.err(sql.sqlite3_prepare_v2(
            self.handle,
            query,
            -1,
            &put_stmt,
            null,
        ));
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

    self.largest_tracker.update(address, account.lamports);
}

fn putWithTokenOwner(self: *Rooted, address: Pubkey, slot: Slot, account: AccountSharedData) void {
    const stmt: *sql.sqlite3_stmt = if (put_with_token_owner_stmt) |stmt| stmt else blk: {
        const query =
            \\INSERT INTO entries
            \\(address, lamports, data, owner, executable, rent_epoch, last_modified_slot, token_owner)
            \\VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            \\ON CONFLICT(address) DO UPDATE SET
            \\  lamports=excluded.lamports,
            \\  data=excluded.data,
            \\  owner=excluded.owner,
            \\  executable=excluded.executable,
            \\  rent_epoch=excluded.rent_epoch,
            \\  last_modified_slot=excluded.last_modified_slot,
            \\  token_owner=excluded.token_owner
            \\WHERE excluded.last_modified_slot > entries.last_modified_slot
            \\;
        ;
        self.err(sql.sqlite3_prepare_v2(
            self.handle,
            query,
            -1,
            &put_with_token_owner_stmt,
            null,
        ));
        break :blk put_with_token_owner_stmt.?;
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

    // Extract the token-level owner from data[32..64]. The caller already
    // verified this is a token program account with data.len >= 64.
    self.err(sql.sqlite3_bind_blob(stmt, 8, account.data.ptr + 32, Pubkey.SIZE, sql.SQLITE_STATIC));

    const result = sql.sqlite3_step(stmt);
    if (result != DONE) self.err(result);

    self.largest_tracker.update(address, account.lamports);
}

/// Tracks the top 20 accounts by lamport balance in rooted storage.
/// Populated incrementally during snapshot loading and slot rooting
/// via Rooted.put(). RPC threads read via snapshot().
pub const LargestTracker = struct {
    pub const CAPACITY = 20;
    pub const Entry = struct { Pubkey, u64 };

    len: usize = 0,
    keys: [CAPACITY]Pubkey = .{Pubkey.ZEROES} ** CAPACITY,
    lamports: [CAPACITY]u64 = .{0} ** CAPACITY,

    /// Cached minimum lamports in the tracker. Enables fast rejection of puts
    /// that can't enter the top-N. Only meaningful when tracker is full.
    /// Only accessed by the single writer thread (snapshot load or replay).
    min_lamports: u64 = 0,
    /// Protects mutations for concurrent RPC snapshot() readers.
    lock: sig.sync.RwLock = .{},

    fn indexOf(self: *const LargestTracker, pk: Pubkey) ?usize {
        for (self.keys[0..self.len], 0..) |*key, i| {
            if (key.equals(&pk)) return i;
        }
        return null;
    }

    fn swapRemoveAt(self: *LargestTracker, index: usize) void {
        self.len -= 1;
        self.keys[index] = self.keys[self.len];
        self.lamports[index] = self.lamports[self.len];
    }

    fn recomputeMin(self: *LargestTracker) void {
        if (self.len == 0) {
            self.min_lamports = 0;
            return;
        }
        self.min_lamports = std.mem.min(u64, self.lamports[0..self.len]);
    }

    fn removeMin(self: *LargestTracker) void {
        if (self.len == 0) return;
        const min_idx = std.mem.indexOfMin(u64, self.lamports[0..self.len]);
        self.swapRemoveAt(min_idx);
    }

    /// Append an entry. Caller must ensure self.len < CAPACITY.
    fn put(self: *LargestTracker, pubkey: Pubkey, lam: u64) void {
        std.debug.assert(self.len < CAPACITY);
        self.keys[self.len] = pubkey;
        self.lamports[self.len] = lam;
        self.len += 1;
    }

    /// Update the tracker with a new account balance.
    /// Called from Rooted.put() on the single writer thread (snapshot load or replay).
    pub fn update(self: *LargestTracker, pubkey: Pubkey, lamports: u64) void {
        // Fast path: tracker is full, balance is below the minimum, and the
        // pubkey isn't already tracked. Reading the arrays here without a lock
        // is safe because we are the single writer thread.
        if (lamports > 0 and self.len == CAPACITY and
            lamports <= self.min_lamports and
            self.indexOf(pubkey) == null)
        {
            return;
        }

        self.lock.lock();
        defer self.lock.unlock();

        // NOTE: we re-scan the (20) pubkeys here. This path is infrequent anyways
        // (only gets hit for very large accounts, when they aren't already in the map).
        if (self.indexOf(pubkey)) |idx| {
            // Already tracked, update or remove.
            if (lamports == 0) {
                const was_min = self.lamports[idx] == self.min_lamports;
                self.swapRemoveAt(idx);
                if (was_min) self.recomputeMin();
            } else {
                self.lamports[idx] = lamports;
                if (lamports < self.min_lamports) {
                    self.min_lamports = lamports;
                }
            }
        } else {
            // Not tracked.
            if (lamports == 0) return;

            if (self.len < CAPACITY) {
                self.put(pubkey, lamports);
                // Track min incrementally as the map fills up.
                const min = self.min_lamports;
                if (min == 0 or lamports < min) {
                    self.min_lamports = lamports;
                }
            } else if (lamports > self.min_lamports) {
                // Displace the minimum entry.
                // NOTE: removeMin only runs on two unavoidable cases:
                // * When removing the current min (lamports -> 0)
                // * displacement (a new entry knocked the min entry out)
                // Both cases require finding the second-smallest, which we don't track (just 20 entries).
                self.removeMin();
                self.put(pubkey, lamports);
                self.recomputeMin();
            }
        }
    }

    /// Copy current entries into caller's buffer. Returns count of entries copied.
    /// Safe to call from any RPC thread (takes shared lock).
    pub fn snapshot(self: *LargestTracker, buf: *[CAPACITY]Entry) usize {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        for (self.keys[0..self.len], self.lamports[0..self.len], 0..) |key, lam, i| {
            buf[i] = .{ key, lam };
        }
        return self.len;
    }
};

test "LargestTracker: empty snapshot" {
    var tracker: LargestTracker = .{};

    var buf: [LargestTracker.CAPACITY]LargestTracker.Entry = undefined;
    const n = tracker.snapshot(&buf);
    try std.testing.expectEqual(0, n);
}

test "LargestTracker: basic insert and snapshot" {
    var tracker: LargestTracker = .{};

    const pk_a: Pubkey = .parse("GBuP6xK2zcUHbQuUWM4gbBjom46AomsG8JzSp1bzJyn8");
    const pk_b: Pubkey = .parse("Fd7btgySsrjuo25CJCj7oE7VPMyezDhnx7pZkj2v69Nk");
    const pk_c: Pubkey = .parse("7EqfdGiB5UZgLWc1U9xYbKdy9Ky9NoYcMbEwUq9aAWR6");

    tracker.update(pk_a, 1000);
    tracker.update(pk_b, 2000);
    tracker.update(pk_c, 500);

    var buf: [LargestTracker.CAPACITY]LargestTracker.Entry = undefined;
    const n = tracker.snapshot(&buf);
    try std.testing.expectEqual(3, n);
    try std.testing.expectEqual(1000, tracker.lamports[tracker.indexOf(pk_a).?]);
    try std.testing.expectEqual(2000, tracker.lamports[tracker.indexOf(pk_b).?]);
    try std.testing.expectEqual(500, tracker.lamports[tracker.indexOf(pk_c).?]);
}

test "LargestTracker: update existing entry" {
    var tracker: LargestTracker = .{};

    const pk: Pubkey = .parse("GBuP6xK2zcUHbQuUWM4gbBjom46AomsG8JzSp1bzJyn8");
    tracker.update(pk, 1000);
    tracker.update(pk, 5000);

    var buf: [LargestTracker.CAPACITY]LargestTracker.Entry = undefined;
    try std.testing.expectEqual(1, tracker.snapshot(&buf));
    try std.testing.expectEqual(5000, tracker.lamports[tracker.indexOf(pk).?]);
}

test "LargestTracker: remove by zero lamports" {
    var tracker: LargestTracker = .{};

    const pk_a: Pubkey = .parse("GBuP6xK2zcUHbQuUWM4gbBjom46AomsG8JzSp1bzJyn8");
    const pk_b: Pubkey = .parse("Fd7btgySsrjuo25CJCj7oE7VPMyezDhnx7pZkj2v69Nk");

    tracker.update(pk_a, 1000);
    tracker.update(pk_b, 2000);
    tracker.update(pk_a, 0); // remove

    var buf: [LargestTracker.CAPACITY]LargestTracker.Entry = undefined;
    try std.testing.expectEqual(1, tracker.snapshot(&buf));
    try std.testing.expectEqual(null, tracker.indexOf(pk_a));
    try std.testing.expectEqual(2000, tracker.lamports[tracker.indexOf(pk_b).?]);
}

test "LargestTracker: zero lamports insert is no-op" {
    var tracker: LargestTracker = .{};

    const pk: Pubkey = .parse("GBuP6xK2zcUHbQuUWM4gbBjom46AomsG8JzSp1bzJyn8");
    tracker.update(pk, 0);

    var buf: [LargestTracker.CAPACITY]LargestTracker.Entry = undefined;
    try std.testing.expectEqual(0, tracker.snapshot(&buf));
}

test "LargestTracker: displacement when full" {
    var tracker: LargestTracker = .{};

    // Fill to capacity with deterministic random pubkeys
    var random = std.Random.DefaultPrng.init(0);
    var pks: [LargestTracker.CAPACITY]Pubkey = undefined;
    for (0..LargestTracker.CAPACITY) |i| {
        pks[i] = Pubkey.initRandom(random.random());
        tracker.update(pks[i], (i + 1) * 100);
    }

    var buf: [LargestTracker.CAPACITY]LargestTracker.Entry = undefined;
    try std.testing.expectEqual(LargestTracker.CAPACITY, tracker.snapshot(&buf));
    try std.testing.expectEqual(100, tracker.min_lamports);

    // Insert a new entry above the min — should displace the min (lamports=100)
    const newcomer: Pubkey = .parse("GBuP6xK2zcUHbQuUWM4gbBjom46AomsG8JzSp1bzJyn8");
    tracker.update(newcomer, 9999);

    try std.testing.expectEqual(LargestTracker.CAPACITY, tracker.snapshot(&buf));
    // The old minimum (100) should be gone; new minimum is 200
    try std.testing.expectEqual(200, tracker.min_lamports);
    try std.testing.expectEqual(null, tracker.indexOf(pks[0]));
    try std.testing.expectEqual(9999, tracker.lamports[tracker.indexOf(newcomer).?]);
}

test "LargestTracker: no displacement below min" {
    var tracker: LargestTracker = .{};

    var random = std.Random.DefaultPrng.init(0);
    for (0..LargestTracker.CAPACITY) |i| {
        tracker.update(Pubkey.initRandom(random.random()), (i + 1) * 100);
    }
    try std.testing.expectEqual(100, tracker.min_lamports);

    // Insert below min — should be rejected
    const newcomer: Pubkey = .parse("GBuP6xK2zcUHbQuUWM4gbBjom46AomsG8JzSp1bzJyn8");
    tracker.update(newcomer, 50);

    var buf: [LargestTracker.CAPACITY]LargestTracker.Entry = undefined;
    try std.testing.expectEqual(LargestTracker.CAPACITY, tracker.snapshot(&buf));
    // Min unchanged, newcomer not present
    try std.testing.expectEqual(100, tracker.min_lamports);
    try std.testing.expectEqual(null, tracker.indexOf(newcomer));
}
