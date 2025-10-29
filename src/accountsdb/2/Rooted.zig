//! Database for rooted accounts.
const std = @import("std");
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
put_stmt: *sql.sqlite3_stmt,

pub fn init(file_path: [:0]const u8) !Rooted {
    const db = blk: {
        var maybe_db: ?*sql.sqlite3 = null;
        if (sql.sqlite3_open(file_path.ptr, &maybe_db) != OK)
            return error.FailedToOpenDb;
        break :blk maybe_db orelse return error.SqliteDbNull;
    };

    const schema =
        // \\PRAGMA journal_mode = wal2;
        // \\PRAGMA synchronous = NORMAL;
        \\
        \\ PRAGMA journal_mode = OFF;
        \\ PRAGMA synchronous = 0;
        \\ PRAGMA cache_size = 1000000;
        \\ PRAGMA locking_mode = EXCLUSIVE;
        \\ PRAGMA temp_store = MEMORY;
        \\ PRAGMA page_size = 65536;
        \\
        \\
        \\CREATE TABLE IF NOT EXISTS entries (
        \\  address BLOB(32) PRIMARY KEY,
        \\  lamports INTEGER NOT NULL,
        \\  data BLOB NOT NULL,
        \\  owner BLOB(32) NOT NULL,
        \\  executable INTEGER NOT NULL,
        \\  rent_epoch INTEGER NOT NULL
        \\) WITHOUT ROWID;
        \\
    ;

    if (sql.sqlite3_exec(db, schema, null, null, null) != OK)
        return error.FailedToCreateTables;

    const put_stmt = blk: {
        const query =
            \\INSERT OR REPLACE INTO entries 
            \\(address, lamports, data, owner, executable, rent_epoch)
            \\VALUES (?, ?, ?, ?, ?, ?);
        ;

        var stmt: ?*sql.sqlite3_stmt = null;
        if (sql.sqlite3_prepare_v2(db, query, -1, &stmt, null) != OK)
            return error.FailedToPreparePut;
        break :blk stmt orelse return error.PutStmtNull;
    };

    return .{ .handle = db, .put_stmt = put_stmt };
}

pub fn deinit(self: *Rooted) void {
    _ = sql.sqlite3_close(self.handle);
    _ = sql.sqlite3_finalize(self.put_stmt);
}

pub fn put(self: *Rooted, address: Pubkey, account: AccountSharedData) !void {
    const stmt = self.put_stmt;

    _ = sql.sqlite3_bind_blob(stmt, 1, &address.data, Pubkey.SIZE, sql.SQLITE_STATIC);
    _ = sql.sqlite3_bind_int64(stmt, 2, @bitCast(account.lamports));
    _ = sql.sqlite3_bind_blob(
        stmt,
        3,
        account.data.ptr,
        @intCast(account.data.len),
        sql.SQLITE_STATIC,
    );
    _ = sql.sqlite3_bind_blob(stmt, 4, &account.owner.data, Pubkey.SIZE, sql.SQLITE_STATIC);
    _ = sql.sqlite3_bind_int(stmt, 5, @intFromBool(account.executable));
    _ = sql.sqlite3_bind_int64(stmt, 6, @bitCast(account.rent_epoch));

    if (sql.sqlite3_step(stmt) != DONE)
        return error.StepFailed;

    _ = sql.sqlite3_reset(stmt);
}

// TODO: perhaps add a check function that checks if such an account exists? might be possible to do with less contention?

/// Returns `null` if no such account exists.
///
/// The `data` field in the returned `AccountSharedData` is owned by the caller and is allocated
/// by the provided allocator.
///
/// TODO: we really don't want to be doing these clones, so some other solution would be good.
pub fn get(self: *Rooted, allocator: std.mem.Allocator, address: Pubkey) !?AccountSharedData {
    const query =
        \\SELECT lamports, data, owner, executable, rent_epoch 
        \\FROM entries WHERE address = ?;
    ;

    var stmt: ?*sql.sqlite3_stmt = undefined;
    if (sql.sqlite3_prepare_v2(self.handle, query, -1, &stmt, null) != OK)
        @panic("failed to prepare get");

    _ = sql.sqlite3_bind_blob(stmt, 1, &address.data, Pubkey.SIZE, sql.SQLITE_STATIC);

    const rc = sql.sqlite3_step(stmt);
    defer _ = sql.sqlite3_finalize(stmt);
    if (rc == ROW) {
        const data_ptr: [*]const u8 = @ptrCast(sql.sqlite3_column_blob(stmt, 1));
        const data = data_ptr[0..@intCast(sql.sqlite3_column_bytes(stmt, 1))];
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
    } else return null;
}

pub fn main() !void {
    const zone = tracy.Zone.init(@src(), .{ .name = "main" });
    defer zone.deinit();

    var gpa: std.heap.DebugAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var iter = std.process.args();
    _ = iter.next() orelse @panic("");
    const accounts_folder = iter.next() orelse @panic("arg missing");
    const destination_file = iter.next() orelse @panic("arg missing");

    var rooted = try Rooted.init(destination_file);
    defer rooted.deinit();

    var accounts_dir = try std.fs.cwd().openDir(accounts_folder, .{ .iterate = true });
    var accounts_iter = accounts_dir.iterate();

    var bp = try sig.accounts_db.buffer_pool.BufferPool.init(allocator, 20480 + 2);
    defer bp.deinit(allocator);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    _ = sql.sqlite3_exec(rooted.handle, "BEGIN TRANSACTION;", null, null, null);

    while (try accounts_iter.next()) |entry| {
        defer tracy.frameMarkNamed("accountfile put");

        if (entry.kind != .file) continue;
        defer _ = arena.reset(.retain_capacity);

        std.debug.print("entry.name: {s}\n", .{entry.name});

        const split = std.mem.indexOf(u8, entry.name, ".") orelse {
            std.debug.print("WARNING: invalid file? (no dot) {s}\n", .{entry.name});
            continue;
        };

        if (entry.name.len - 1 == split) {
            std.debug.print("WARNING: invalid file? (no id) {s}\n", .{entry.name});
            continue;
        }

        const slot_str = entry.name[0..split];
        const id_str = entry.name[split + 1 ..];

        const slot = try std.fmt.parseInt(u64, slot_str, 10);
        const id = try std.fmt.parseInt(u32, id_str, 10);

        const file = try accounts_dir.openFile(entry.name, .{});
        defer file.close();

        const file_len = (try file.stat()).size;

        const accounts_file = try sig.accounts_db.accounts_file.AccountFile.init(
            file,
            .{ .id = .fromInt(id), .length = file_len },
            slot,
        );

        var accounts_pushed: u48 = 0;

        var accounts = accounts_file.iterator(&bp);
        while (try accounts.next(arena.allocator())) |account| : (accounts_pushed += 1) {
            defer account.deinit(arena.allocator());

            const pk = try sig.core.Pubkey.fromBytes(account.hash.data);

            const cloned_data = try account.data.dupeAllocatedOwned(arena.allocator());
            defer cloned_data.deinit(arena.allocator());

            const data = @constCast(cloned_data.owned_allocation);

            try rooted.put(pk, .{
                .data = data,
                .executable = account.account_info.executable,
                .lamports = account.account_info.lamports,
                .owner = account.account_info.owner,
                .rent_epoch = account.account_info.rent_epoch,
            });
        }
    }

    std.debug.print("committing\n", .{});

    _ = sql.sqlite3_exec(rooted.handle, "COMMIT;", null, null, null);

    // std.debug.print("creating index\n", .{});

    // const make_index =
    //     \\ CREATE UNIQUE INDEX entries_addr_idx ON entries(address);
    // ;

    // if (sql.sqlite3_exec(rooted.handle, make_index, null, null, null) != OK)
    //     return error.MakeIndexFailed;
}
