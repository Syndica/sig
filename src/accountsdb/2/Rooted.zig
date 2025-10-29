//! Database for rooted accounts.
const std = @import("std");
const sig = @import("sig");
const sql = @import("sqlite");
const Rooted = @This();

const Slot = sig.core.Slot;
const Pubkey = sig.core.Pubkey;
const AccountSharedData = sig.runtime.AccountSharedData;

const OK = sql.SQLITE_OK;
const DONE = sql.SQLITE_DONE;
const ROW = sql.SQLITE_ROW;

/// Handle to the underlying sqlite database.
handle: *sql.sqlite3,

pub fn init(file_path: [:0]const u8) !Rooted {
    var maybe_db: ?*sql.sqlite3 = undefined;
    if (sql.sqlite3_open(file_path.ptr, &maybe_db) != OK)
        return error.FailedToOpenDb;

    const schema =
        \\CREATE TABLE IF NOT EXISTS entries (
        \\  address BLOB PRIMARY KEY,
        \\  lamports INTEGER NOT NULL,
        \\  data BLOB NOT NULL,
        \\  owner BLOB NOT NULL,
        \\  executable INTEGER NOT NULL,
        \\  rent_epoch INTEGER NOT NULL
        \\);
    ;

    if (sql.sqlite3_exec(maybe_db, schema, null, null, null) != OK)
        return error.FailedToCreateTables;

    return .{
        .handle = maybe_db orelse return error.SqliteDbNull,
    };
}

pub fn deinit(self: *Rooted) void {
    _ = sql.sqlite3_close(self.handle);
}

pub fn put(self: *Rooted, address: Pubkey, account: AccountSharedData) !void {
    const query =
        \\INSERT OR REPLACE INTO entries 
        \\(address, lamports, data, owner, executable, rent_epoch)
        \\VALUES (?, ?, ?, ?, ?, ?);
    ;

    var stmt: ?*sql.sqlite3_stmt = undefined;
    if (sql.sqlite3_prepare_v2(self.handle, query, -1, &stmt, null) != OK)
        return error.FailedToPreparePut;

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

    _ = sql.sqlite3_finalize(stmt);
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
        return error.FailedToPrepareGet;

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
    var gpa: std.heap.DebugAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var rooted = try Rooted.init("test.db");
    defer rooted.deinit();

    // TODO: figure out who owns this
    const account_data = try allocator.dupe(u8, &.{ 10, 20, 30 });
    defer allocator.free(account_data);

    const account_key: Pubkey = .parse("GBuP6xK2zcUHbQuUWM4gbBjom46AomsG8JzSp1bzJyn8");

    try rooted.put(
        account_key,
        .{
            .data = account_data,
            .executable = true,
            .lamports = 1_000_000,
            .owner = .parse("Fd7btgySsrjuo25CJCj7oE7VPMyezDhnx7pZkj2v69Nk"),
            .rent_epoch = 30,
        },
    );

    const maybe_result = try rooted.get(allocator, account_key);
    const result = maybe_result.?;
    defer result.deinit(allocator);

    std.debug.print("returned: {any}\n", .{result});
}
