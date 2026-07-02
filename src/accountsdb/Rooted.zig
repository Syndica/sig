//! Database for rooted accounts.
const std = @import("std");
const builtin = @import("builtin");
const sig = @import("../sig.zig");
const sql = @import("sqlite");
const tracy = @import("tracy");
const Rooted = @This();
const CompressedAccountStore = @import("CompressedAccountStore.zig");

const Slot = sig.core.Slot;
const Pubkey = sig.core.Pubkey;
const Hash = sig.core.Hash;
const AccountSharedData = sig.runtime.AccountSharedData;
const Gauge = sig.prometheus.Gauge(u64);
const ThreadPool = sig.sync.ThreadPool;

const OK = sql.SQLITE_OK;
const DONE = sql.SQLITE_DONE;
const ROW = sql.SQLITE_ROW;

extern "c" fn malloc_zone_pressure_relief(zone: ?*anyopaque, goal: usize) usize;

/// Handle to the underlying sqlite database.
handle: *sql.sqlite3,
/// Directory that contains accounts.db and, when present, unpacked snapshot account files.
snapshot_dir_path: []const u8,
/// Optional read-only compressed cold store for SSD-constrained snapshot state.
compressed_account_store: ?CompressedAccountStore = null,
/// Tracks the largest rooted slot.
largest_rooted_slot: ?Slot,
/// Updates a prometheus counter for mem usage.
sqlite_mem_used: ?*Gauge = null,

/// These aren't thread safe, but we can have as many as we want. Clean up with deinitThreadLocals
/// on any threads that use put or get.
threadlocal var put_stmt: ?*sql.sqlite3_stmt = null;
threadlocal var get_stmt: ?*sql.sqlite3_stmt = null;
threadlocal var put_snapshot_ref_stmt: ?*sql.sqlite3_stmt = null;
threadlocal var get_snapshot_ref_stmt: ?*sql.sqlite3_stmt = null;

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
        .snapshot_dir_path = try snapshotDirPathFromDbPath(file_path),
        .largest_rooted_slot = null,
    };
    errdefer std.heap.page_allocator.free(self.snapshot_dir_path);

    self.compressed_account_store = try CompressedAccountStore.initFromEnv(std.heap.page_allocator);
    errdefer if (self.compressed_account_store) |*store| store.deinit();

    {
        const pragmas =
            \\ PRAGMA journal_mode = OFF;
            \\ PRAGMA synchronous = 0;
            \\ PRAGMA locking_mode = EXCLUSIVE;
            \\ PRAGMA temp_store = FILE;
            \\ PRAGMA page_size = 65536;
            \\ PRAGMA cache_spill = ON;
        ;

        if (sql.sqlite3_exec(db, pragmas, null, null, null) != OK) {
            std.debug.print("err  {s}\n", .{sql.sqlite3_errmsg(db)});
            return error.FailedToSetPragmas;
        }

        const cache_mib = envU64("SIG_ROOTED_SQLITE_CACHE_MIB", 64);
        const mmap_mib = envU64("SIG_ROOTED_SQLITE_MMAP_MIB", 0);
        const cache_kib = cache_mib * 1024;
        const mmap_bytes = mmap_mib * 1024 * 1024;
        var dynamic_pragmas_buf: [160]u8 = undefined;
        const dynamic_pragmas = std.fmt.bufPrintZ(
            &dynamic_pragmas_buf,
            " PRAGMA cache_size = -{}; PRAGMA mmap_size = {}; ",
            .{ cache_kib, mmap_bytes },
        ) catch return error.FailedToSetPragmas;
        if (sql.sqlite3_exec(db, dynamic_pragmas, null, null, null) != OK) {
            std.debug.print("err  {s}\n", .{sql.sqlite3_errmsg(db)});
            return error.FailedToSetPragmas;
        }
    }

    {
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
            \\CREATE TABLE IF NOT EXISTS snapshot_refs (
            \\  pubkey BLOB(32) PRIMARY KEY,
            \\  slot INTEGER NOT NULL,
            \\  file_id INTEGER NOT NULL,
            \\  offset INTEGER NOT NULL,
            \\  len INTEGER NOT NULL,
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

fn snapshotDirPathFromDbPath(file_path: [:0]const u8) ![]const u8 {
    const dir = std.fs.path.dirname(file_path) orelse ".";
    return try std.heap.page_allocator.dupe(u8, dir);
}

fn envU64(key: []const u8, default_value: u64) u64 {
    const allocator = std.heap.page_allocator;
    const raw = std.process.getEnvVarOwned(allocator, key) catch return default_value;
    defer allocator.free(raw);

    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return default_value;
    return std.fmt.parseInt(u64, trimmed, 10) catch default_value;
}

pub fn deinit(self: *Rooted) void {
    if (self.compressed_account_store) |*store| {
        store.deinit();
        self.compressed_account_store = null;
    }
    std.heap.page_allocator.free(self.snapshot_dir_path);
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
    if (put_snapshot_ref_stmt) |stmt| {
        _ = sql.sqlite3_finalize(stmt);
        put_snapshot_ref_stmt = null;
    }
    if (get_snapshot_ref_stmt) |stmt| {
        _ = sql.sqlite3_finalize(stmt);
        get_snapshot_ref_stmt = null;
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

pub fn snapshotRefCount(self: *const Rooted) u64 {
    const query = "SELECT count(*) from snapshot_refs";

    var stmt: ?*sql.sqlite3_stmt = null;
    defer if (stmt) |st| std.debug.assert(sql.sqlite3_finalize(st) == OK);
    const prep_err = sql.sqlite3_prepare_v2(self.handle, query, -1, &stmt, null);
    if (prep_err != OK) return 0;

    const rc = sql.sqlite3_step(stmt);
    if (rc != ROW) return 0;

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
) !?AccountSharedData {
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
    defer {
        std.debug.assert(sql.sqlite3_reset(stmt) == OK);
        std.debug.assert(sql.sqlite3_clear_bindings(stmt) == OK);
    }

    self.err(sql.sqlite3_bind_blob(stmt, 1, &address.data, Pubkey.SIZE, sql.SQLITE_STATIC));

    const rc = sql.sqlite3_step(stmt);

    switch (rc) {
        ROW => {
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
        },
        DONE => return try self.getColdAccount(allocator, address),
        else => {
            self.err(rc);
            unreachable;
        },
    }
}

const SnapshotRef = struct {
    slot: Slot,
    file_id: u32,
    offset: u64,
    len: u64,
};

pub fn hasCompressedAccountStore(self: *const Rooted) bool {
    return self.compressed_account_store != null;
}

pub fn compressedStoreSamplePubkeys(
    self: *Rooted,
    allocator: std.mem.Allocator,
    max_samples: usize,
) ![]CompressedAccountStore.Sample {
    if (self.compressed_account_store) |*store| {
        return try store.samplePubkeys(allocator, max_samples);
    }
    return error.MissingCompressedAccountStore;
}

pub fn compressedAccountChunkId(self: *Rooted, address: Pubkey) !?u32 {
    if (self.compressed_account_store) |*store| {
        return try store.lookupChunkId(address);
    }
    return null;
}

pub fn prefetchCompressedChunksForPubkeys(
    self: *Rooted,
    allocator: std.mem.Allocator,
    pubkeys: []const Pubkey,
) !CompressedAccountStore.PrefetchResult {
    if (self.compressed_account_store) |*store| {
        return try store.prefetchChunksForPubkeys(allocator, pubkeys);
    }
    return .{ .pubkeys = @intCast(pubkeys.len) };
}

fn getColdAccount(
    self: *Rooted,
    allocator: std.mem.Allocator,
    address: Pubkey,
) !?AccountSharedData {
    if (try self.getSnapshotRefAccount(allocator, address)) |account| return account;
    if (self.compressed_account_store) |*store| return try store.get(allocator, address);
    return null;
}

pub fn putSnapshotRef(
    self: *Rooted,
    address: Pubkey,
    slot: Slot,
    file_id: u32,
    offset: u64,
    len: u64,
) void {
    const stmt: *sql.sqlite3_stmt = if (put_snapshot_ref_stmt) |stmt| stmt else blk: {
        const query =
            \\INSERT INTO snapshot_refs
            \\(pubkey, slot, file_id, offset, len, last_modified_slot)
            \\VALUES (?, ?, ?, ?, ?, ?)
            \\ON CONFLICT(pubkey) DO UPDATE SET
            \\  slot=excluded.slot,
            \\  file_id=excluded.file_id,
            \\  offset=excluded.offset,
            \\  len=excluded.len,
            \\  last_modified_slot=excluded.last_modified_slot
            \\WHERE excluded.last_modified_slot > snapshot_refs.last_modified_slot
            \\;
        ;
        self.err(sql.sqlite3_prepare_v2(self.handle, query, -1, &put_snapshot_ref_stmt, null));
        break :blk put_snapshot_ref_stmt.?;
    };
    defer {
        std.debug.assert(sql.sqlite3_reset(stmt) == OK);
        std.debug.assert(sql.sqlite3_clear_bindings(stmt) == OK);
    }

    self.err(sql.sqlite3_bind_blob(stmt, 1, &address.data, Pubkey.SIZE, sql.SQLITE_STATIC));
    self.err(sql.sqlite3_bind_int64(stmt, 2, @bitCast(slot)));
    self.err(sql.sqlite3_bind_int64(stmt, 3, file_id));
    self.err(sql.sqlite3_bind_int64(stmt, 4, @bitCast(offset)));
    self.err(sql.sqlite3_bind_int64(stmt, 5, @bitCast(len)));
    self.err(sql.sqlite3_bind_int64(stmt, 6, @bitCast(slot)));

    const result = sql.sqlite3_step(stmt);
    if (result != DONE) self.err(result);
}

fn getSnapshotRefAccount(
    self: *Rooted,
    allocator: std.mem.Allocator,
    address: Pubkey,
) !?AccountSharedData {
    const ref = try self.getSnapshotRef(address) orelse return null;
    return try self.readSnapshotRefAccount(allocator, address, ref);
}

fn getSnapshotRef(self: *Rooted, address: Pubkey) !?SnapshotRef {
    const stmt: *sql.sqlite3_stmt = if (get_snapshot_ref_stmt) |stmt| stmt else blk: {
        const query =
            \\SELECT slot, file_id, offset, len
            \\FROM snapshot_refs WHERE pubkey = ?;
        ;
        self.err(sql.sqlite3_prepare_v2(self.handle, query, -1, &get_snapshot_ref_stmt, null));
        break :blk get_snapshot_ref_stmt.?;
    };
    defer {
        std.debug.assert(sql.sqlite3_reset(stmt) == OK);
        std.debug.assert(sql.sqlite3_clear_bindings(stmt) == OK);
    }

    self.err(sql.sqlite3_bind_blob(stmt, 1, &address.data, Pubkey.SIZE, sql.SQLITE_STATIC));

    const rc = sql.sqlite3_step(stmt);
    switch (rc) {
        ROW => return .{
            .slot = @bitCast(sql.sqlite3_column_int64(stmt, 0)),
            .file_id = @intCast(sql.sqlite3_column_int64(stmt, 1)),
            .offset = @bitCast(sql.sqlite3_column_int64(stmt, 2)),
            .len = @bitCast(sql.sqlite3_column_int64(stmt, 3)),
        },
        DONE => return null,
        else => {
            self.err(rc);
            unreachable;
        },
    }
}

const SnapshotAccountHeader = extern struct {
    write_version: u64,
    data_len: u64,
    pubkey: Pubkey,
    lamports: u64,
    rent_epoch: sig.core.Epoch,
    owner: Pubkey,
    executable: u8,
    _padding: [7]u8,
    hash: Hash,
};

fn readSnapshotRefAccount(
    self: *Rooted,
    allocator: std.mem.Allocator,
    address: Pubkey,
    ref: SnapshotRef,
) !AccountSharedData {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(
        &path_buf,
        "{s}/accounts/{d}.{d}",
        .{ self.snapshot_dir_path, ref.slot, ref.file_id },
    );

    const file = try std.fs.cwd().openFile(path, .{ .mode = .read_only });
    defer file.close();

    var header_buf: [@sizeOf(SnapshotAccountHeader)]u8 = undefined;
    const header_read = try file.preadAll(&header_buf, ref.offset);
    if (header_read != header_buf.len) return error.InvalidSnapshotAccountRef;

    const header = decodeSnapshotAccountHeader(&header_buf);
    if (!header.pubkey.equals(&address)) return error.InvalidSnapshotAccountRef;
    if (!header.hash.eql(Hash.ZEROES)) return error.InvalidSnapshotAccountRef;
    if (header.executable > 1) return error.InvalidSnapshotAccountRef;
    if (header.data_len > sig.runtime.program.system.MAX_PERMITTED_DATA_LENGTH)
        return error.InvalidSnapshotAccountRef;

    const header_len = std.mem.alignForward(usize, @sizeOf(SnapshotAccountHeader), 8);
    const padded_data_len = std.mem.alignForward(u64, header.data_len, 8);
    const expected_len = header_len + padded_data_len;
    if (ref.len != expected_len) return error.InvalidSnapshotAccountRef;

    const data = try allocator.alloc(u8, @intCast(header.data_len));
    errdefer allocator.free(data);

    if (data.len > 0) {
        const data_read = try file.preadAll(data, ref.offset + header_len);
        if (data_read != data.len) return error.InvalidSnapshotAccountRef;
    }

    return .{
        .lamports = header.lamports,
        .data = data,
        .owner = header.owner,
        .executable = header.executable == 1,
        .rent_epoch = header.rent_epoch,
    };
}

fn decodeSnapshotAccountHeader(bytes: *const [@sizeOf(SnapshotAccountHeader)]u8) SnapshotAccountHeader {
    var offset: usize = 0;
    const write_version = std.mem.readInt(u64, bytes[offset..][0..8], .little);
    offset += 8;
    const data_len = std.mem.readInt(u64, bytes[offset..][0..8], .little);
    offset += 8;
    const pubkey: Pubkey = .{ .data = bytes[offset..][0..Pubkey.SIZE].* };
    offset += Pubkey.SIZE;
    const lamports = std.mem.readInt(u64, bytes[offset..][0..8], .little);
    offset += 8;
    const rent_epoch = std.mem.readInt(sig.core.Epoch, bytes[offset..][0..8], .little);
    offset += 8;
    const owner: Pubkey = .{ .data = bytes[offset..][0..Pubkey.SIZE].* };
    offset += Pubkey.SIZE;
    const executable = bytes[offset];
    offset += 1;
    const padding = bytes[offset..][0..7].*;
    offset += 7;
    const hash: Hash = .{ .data = bytes[offset..][0..Hash.SIZE].* };

    return .{
        .write_version = write_version,
        .data_len = data_len,
        .pubkey = pubkey,
        .lamports = lamports,
        .rent_epoch = rent_epoch,
        .owner = owner,
        .executable = executable,
        ._padding = padding,
        .hash = hash,
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

pub fn beginTransaction(self: *Rooted) void {
    self.err(sql.sqlite3_exec(self.handle, "BEGIN TRANSACTION;", null, null, null));
}

pub fn commitTransaction(self: *Rooted) void {
    const zone = tracy.Zone.init(@src(), .{ .name = "Rooted.commitTransaction" });
    defer zone.deinit();

    self.err(sql.sqlite3_exec(self.handle, "COMMIT;", null, null, null));
    self.err(sql.sqlite3_db_release_memory(self.handle));
    _ = sql.sqlite3_release_memory(std.math.maxInt(c_int));
    if (builtin.os.tag == .macos) {
        _ = malloc_zone_pressure_relief(null, 0);
    }
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
    defer {
        std.debug.assert(sql.sqlite3_reset(stmt) == OK);
        std.debug.assert(sql.sqlite3_clear_bindings(stmt) == OK);
    }

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

fn writeTestSnapshotAccountFile(
    dir: std.fs.Dir,
    sub_path: []const u8,
    address: Pubkey,
    account: AccountSharedData,
) !u64 {
    const header_len = std.mem.alignForward(usize, @sizeOf(SnapshotAccountHeader), 8);
    const data_len = account.data.len;
    const padded_data_len = std.mem.alignForward(usize, data_len, 8);
    const total_len = header_len + padded_data_len;

    var bytes = try std.testing.allocator.alloc(u8, total_len);
    defer std.testing.allocator.free(bytes);
    @memset(bytes, 0);

    var offset: usize = 0;
    std.mem.writeInt(u64, bytes[offset..][0..8], 0, .little);
    offset += 8;
    std.mem.writeInt(u64, bytes[offset..][0..8], data_len, .little);
    offset += 8;
    @memcpy(bytes[offset..][0..Pubkey.SIZE], &address.data);
    offset += Pubkey.SIZE;
    std.mem.writeInt(u64, bytes[offset..][0..8], account.lamports, .little);
    offset += 8;
    std.mem.writeInt(sig.core.Epoch, bytes[offset..][0..8], account.rent_epoch, .little);
    offset += 8;
    @memcpy(bytes[offset..][0..Pubkey.SIZE], &account.owner.data);
    offset += Pubkey.SIZE;
    bytes[offset] = @intFromBool(account.executable);
    offset += 8;
    @memcpy(bytes[offset..][0..Hash.SIZE], &Hash.ZEROES.data);
    offset += Hash.SIZE;
    std.debug.assert(offset == header_len);

    @memcpy(bytes[offset..][0..data_len], account.data);

    try dir.writeFile(.{ .sub_path = sub_path, .data = bytes });
    return total_len;
}

test "snapshot refs cold-load from unpacked accounts file" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("accounts");

    var tmp_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    var rooted_path_buf: [std.fs.max_path_bytes + 1]u8 = undefined;
    const tmp_path = try tmp.dir.realpath(".", &tmp_path_buf);
    const rooted_path = try std.fmt.bufPrintZ(&rooted_path_buf, "{s}/accounts.db", .{tmp_path});

    const address: Pubkey = .{ .data = [_]u8{7} ** Pubkey.SIZE };
    const owner: Pubkey = .{ .data = [_]u8{8} ** Pubkey.SIZE };
    var account_data = [_]u8{ 1, 2, 3, 4, 5 };
    const account: AccountSharedData = .{
        .lamports = 123,
        .data = &account_data,
        .owner = owner,
        .executable = false,
        .rent_epoch = 42,
    };

    const len = try writeTestSnapshotAccountFile(tmp.dir, "accounts/10.0", address, account);

    var rooted: Rooted = try .init(rooted_path);
    defer rooted.deinit();
    defer Rooted.deinitThreadLocals();

    rooted.putSnapshotRef(address, 10, 0, 0, len);

    const loaded = (try rooted.get(allocator, address)) orelse return error.MissingColdLoadedAccount;
    defer loaded.deinit(allocator);

    try std.testing.expectEqual(account.lamports, loaded.lamports);
    try std.testing.expect(account.owner.equals(&loaded.owner));
    try std.testing.expectEqual(account.executable, loaded.executable);
    try std.testing.expectEqual(account.rent_epoch, loaded.rent_epoch);
    try std.testing.expectEqualSlices(u8, account.data, loaded.data);
}

test "rooted entries override snapshot refs" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("accounts");

    var tmp_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    var rooted_path_buf: [std.fs.max_path_bytes + 1]u8 = undefined;
    const tmp_path = try tmp.dir.realpath(".", &tmp_path_buf);
    const rooted_path = try std.fmt.bufPrintZ(&rooted_path_buf, "{s}/accounts.db", .{tmp_path});

    const address: Pubkey = .{ .data = [_]u8{9} ** Pubkey.SIZE };
    const owner: Pubkey = .{ .data = [_]u8{10} ** Pubkey.SIZE };
    var snapshot_data = [_]u8{ 1, 1, 1 };
    const snapshot_account: AccountSharedData = .{
        .lamports = 100,
        .data = &snapshot_data,
        .owner = owner,
        .executable = false,
        .rent_epoch = 1,
    };
    const len = try writeTestSnapshotAccountFile(
        tmp.dir,
        "accounts/10.0",
        address,
        snapshot_account,
    );

    var rooted: Rooted = try .init(rooted_path);
    defer rooted.deinit();
    defer Rooted.deinitThreadLocals();

    rooted.putSnapshotRef(address, 10, 0, 0, len);

    var rooted_data = [_]u8{ 2, 2, 2, 2 };
    rooted.put(address, 11, .{
        .lamports = 200,
        .data = &rooted_data,
        .owner = owner,
        .executable = true,
        .rent_epoch = 2,
    });

    const loaded = (try rooted.get(allocator, address)) orelse return error.MissingRootedAccount;
    defer loaded.deinit(allocator);

    try std.testing.expectEqual(@as(u64, 200), loaded.lamports);
    try std.testing.expectEqual(true, loaded.executable);
    try std.testing.expectEqual(@as(u64, 2), loaded.rent_epoch);
    try std.testing.expectEqualSlices(u8, &rooted_data, loaded.data);
}
