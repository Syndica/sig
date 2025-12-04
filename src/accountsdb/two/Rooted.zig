//! Database for rooted accounts.
const std = @import("std");
const builtin = @import("builtin");
const sig = @import("../../sig.zig");
const sql = @import("sqlite");
const tracy = @import("tracy");
const Rooted = @This();

const Slot = sig.core.Slot;
const Pubkey = sig.core.Pubkey;
const AccountSharedData = sig.runtime.AccountSharedData;

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

    return .{
        .handle = db,
        .largest_rooted_slot = null,
    };
}

pub fn initSnapshot(
    allocator: std.mem.Allocator,
    file_path: [:0]const u8,
    /// Set to directory which contains snapshot account files to pre-load the rooted storage from them.
    accounts_dir: std.fs.Dir,
) !Rooted {
    const zone = tracy.Zone.init(@src(), .{ .name = "Rooted.initSnapshot" });
    defer zone.deinit();

    const db = blk: {
        var maybe_db: ?*sql.sqlite3 = null;
        if (sql.sqlite3_open(file_path.ptr, &maybe_db) != OK)
            return error.FailedToOpenDb;
        break :blk maybe_db orelse return error.SqliteDbNull;
    };

    const db_has_entries = blk: {
        const query = "SELECT count(*) from entries";

        var stmt: ?*sql.sqlite3_stmt = null;
        defer if (stmt) |st| std.debug.assert(sql.sqlite3_finalize(st) == OK);
        const prep_err = sql.sqlite3_prepare_v2(db, query, -1, &stmt, null);
        if (prep_err != OK) break :blk false; // table does not exist

        const rc = sql.sqlite3_step(stmt);
        if (rc != ROW) break :blk false; // other err

        break :blk sql.sqlite3_column_int64(stmt, 0) > 0;
    };

    var self: Rooted = try .init(file_path);
    if (db_has_entries) {
        std.debug.print("db has entries, skipping load from snapshot\n", .{});
    } else {
        std.debug.print("db is empty -  loading from snapshot!\n", .{});
        try self.insertFromSnapshot(allocator, accounts_dir);
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

fn accountsHash(self: *Rooted) !sig.core.LtHash {
    const zone = tracy.Zone.init(@src(), .{ .name = "Rooted.accountsHash" });
    defer zone.deinit();

    const query =
        \\SELECT address, owner, data, lamports, executable, rent_epoch, last_modified_slot FROM entries;
    ;

    var stmt: ?*sql.sqlite3_stmt = undefined;
    if (sql.sqlite3_prepare_v2(self.handle, query, -1, &stmt, null) != OK)
        return error.FailedToPrepareGet;
    defer err(self, sql.sqlite3_finalize(stmt));

    var hash: sig.core.LtHash = .IDENTITY;

    while (true) {
        const step_result = sql.sqlite3_step(stmt);
        switch (step_result) {
            ROW => {},
            DONE => break,
            else => err(self, step_result),
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

        const account: AccountSharedData = .{
            .lamports = lamports,
            .data = @constCast(data),
            .owner = owner,
            .executable = executable,
            .rent_epoch = rent_epoch,
        };

        hash.mixIn(account.asAccount().ltHash(pubkey));
    }

    return hash;
}

fn insertFromSnapshot(
    self: *Rooted,
    allocator: std.mem.Allocator,
    accounts_dir: std.fs.Dir,
) !void {
    const zone = tracy.Zone.init(@src(), .{ .name = "Rooted.insertFromSnapshot" });
    defer zone.deinit();

    const accounts_entries = try getEntries(allocator, accounts_dir);
    defer allocator.free(accounts_entries);

    self.err(sql.sqlite3_exec(self.handle, "BEGIN TRANSACTION;", null, null, null));

    var bp = try sig.accounts_db.buffer_pool.BufferPool.init(allocator, 20480 + 2);
    defer bp.deinit(allocator);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    {
        const loading_zone = tracy.Zone.init(
            @src(),
            .{ .name = "Rooted.insertFromSnapshot: loading files" },
        );
        defer loading_zone.deinit();

        const progress = std.Progress.start(.{});
        defer progress.end();
        var progress_node = progress.start("loading account files", accounts_entries.len);

        for (accounts_entries) |entry| {
            var entry_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
            const entry_path = try std.fmt.bufPrint(
                &entry_path_buffer,
                "{d}.{d}",
                .{ entry.slot, entry.id },
            );
            const file = try accounts_dir.openFile(entry_path, .{});
            defer file.close();

            // TODO: assuming length is the file length is technically not correct
            const accounts_file = try AccountFile.init(
                file,
                .{ .id = .fromInt(entry.id), .length = (try file.stat()).size },
                entry.slot,
            );

            const file_zone = tracy.Zone.init(
                @src(),
                .{ .name = "Rooted.insertFromSnapshot: accounts files" },
            );
            defer file_zone.deinit();

            defer _ = arena.reset(.retain_capacity);

            var n_accounts_in_file: u48 = 0;

            var accounts = accounts_file.iterator(&bp);
            while (try accounts.next(arena.allocator())) |account| {
                defer account.deinit(arena.allocator());

                const cloned_data = try account.data.dupeAllocatedOwned(arena.allocator());
                defer cloned_data.deinit(arena.allocator());

                const data = @constCast(cloned_data.owned_allocation);

                self.put(
                    account.store_info.pubkey,
                    accounts_file.slot,
                    .{
                        .data = data,
                        .executable = account.account_info.executable,
                        .lamports = account.account_info.lamports,
                        .owner = account.account_info.owner,
                        .rent_epoch = account.account_info.rent_epoch,
                    },
                );

                n_accounts_in_file += 1;
            }
            progress_node.completeOne();
            file_zone.value(n_accounts_in_file);
        }

        progress_node.end();
    }

    {
        const commit_zone = tracy.Zone.init(
            @src(),
            .{ .name = "Rooted.insertFromSnapshot: committing" },
        );
        defer commit_zone.deinit();

        std.debug.print("committing\n", .{});
        self.err(sql.sqlite3_exec(self.handle, "COMMIT;", null, null, null));
    }
}

fn getInner(self: *Rooted, allocator: std.mem.Allocator, address: Pubkey) !?AccountSharedData {
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

/// Returns `null` if no such account exists.
///
/// The `data` field in the returned `AccountSharedData` is owned by the caller and is allocated
/// by the provided allocator.
///
/// TODO: we really don't want to be doing these clones, so some other solution would be good.
pub fn get(
    self: *Rooted,
    allocator: std.mem.Allocator,
    address: Pubkey,
) error{OutOfMemory}!?AccountSharedData {
    const zone = tracy.Zone.init(@src(), .{ .name = "Rooted.get" });
    defer zone.deinit();

    return try self.getInner(allocator, address);
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
    self.err(sql.sqlite3_exec(self.handle, "COMMIT;", null, null, null));
}

/// Should not be called outside of snapshot loading or slot rooting.
/// TODO: write putRootedSlot(slot, []pk, []account) and make that public instead.
pub fn put(self: *Rooted, address: Pubkey, slot: Slot, account: AccountSharedData) void {
    const stmt: *sql.sqlite3_stmt = if (put_stmt) |stmt| stmt else blk: {
        const query =
            \\INSERT OR REPLACE INTO entries 
            \\(address, lamports, data, owner, executable, rent_epoch, last_modified_slot)
            \\VALUES (?, ?, ?, ?, ?, ?, ?);
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

const AccountFile = sig.accounts_db.accounts_file.AccountFile;

// Represents an account file
const Entry = struct {
    slot: Slot,
    id: u32,
};

fn getEntries(allocator: std.mem.Allocator, accounts_dir: std.fs.Dir) ![]Entry {
    var entries: std.ArrayList(Entry) = .init(allocator);
    errdefer entries.deinit();

    var accounts_iter = accounts_dir.iterate();
    while (try accounts_iter.next()) |entry| {
        if (entry.kind != .file) return error.BadAccountsDir;
        const split = std.mem.indexOf(u8, entry.name, ".") orelse return error.BadAccountsDir;
        if (entry.name.len - 1 == split) return error.BadAccountsDir;
        const slot_str = entry.name[0..split];
        const id_str = entry.name[split + 1 ..];

        const slot = try std.fmt.parseInt(u64, slot_str, 10);
        const id = try std.fmt.parseInt(u32, id_str, 10);
        try entries.append(.{ .slot = slot, .id = id });
    }

    const lessThanFn = struct {
        fn f(context: void, lhs: Entry, rhs: Entry) bool {
            _ = context;
            return lhs.slot < rhs.slot;
        }
    }.f;

    std.mem.sort(Entry, entries.items, {}, lessThanFn);

    return try entries.toOwnedSlice();
}
