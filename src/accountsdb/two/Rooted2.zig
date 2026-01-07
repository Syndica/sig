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

const SnapshotFiles = sig.accounts_db.snapshot.SnapshotFiles;

pub fn initSnapshot(
    allocator: std.mem.Allocator,
    file_path: [:0]const u8,
    snapshot_files: SnapshotFiles,
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
        try self.insertFromSnapshot(allocator, snapshot_files);
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

    defer err(self, sql.sqlite3_finalize(stmt)) catch {};

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

const FullAndIncrementalManifest = sig.accounts_db.snapshot.FullAndIncrementalManifest;

fn insertFromSnapshot(
    self: *Rooted,
    allocator: std.mem.Allocator,
    snapshot_files: SnapshotFiles,
) !FullAndIncrementalManifest {
    const zone = tracy.Zone.init(@src(), .{ .name = "Rooted.insertFromSnapshot" });
    defer zone.deinit();

    self.beginTransaction();
    defer self.commitTransaction();

    const full = blk: {
        const full_zone = tracy.Zone.init(@src(), .{ .name = "Rooted.insertFromSnapshot: full" });
        defer full_zone.deinit();

        const path = snapshot_files.full.snapshotArchiveName();
        break :blk try self.insertFromSnapshotArchive(
            allocator,
            path.constSlice(),
            .{ .slot = snapshot_files.full.slot, .hash = snapshot_files.full.hash },
        );
    };
    errdefer full.deinit(allocator);

    const incremental: ?Manifest = blk: {
        const incr_zone = 
            tracy.Zone.init(@src(), .{ .name = "Rooted.insertFromSnapshot: incremental" });
        defer incr_zone.deinit();

        const info = snapshot_files.incremental() orelse break :blk null;
        const incremental_path = info.snapshotArchiveName();
        break :blk try self.insertFromSnapshotArchive(
            allocator,
            incremental_path.constSlice(),
            info.slotAndHash(),
        );
    };
    errdefer if (incremental) |manifest| manifest.deinit(allocator);

    return .{
        .full = full,
        .incremental = incremental,
    };
}

const StatusCache = sig.accounts_db.snapshot.StatusCache;
const Manifest = sig.accounts_db.snapshot.Manifest;
const zstd = @import("zstd");

fn insertFromSnapshotArchive(
    self: *Rooted,
    allocator: std.mem.Allocator,
    snapshot_path: []const u8,
    slot_and_hash: sig.core.hash.SlotAndHash,
) !struct{ Manifest, StatusCache } {
    const zone = tracy.Zone.init(@src(), .{ .name = "Rooted.insertFromSnapshotArchive" });
    defer zone.deinit();

    std.debug.print("loading snapshot archive: {s}\n", .{snapshot_path});

    const file = try std.fs.cwd().openFile(snapshot_path, .{ .mode = .read_only });
    defer file.close();

    // calling posix.mmap on a zero-sized file will cause illegal behaviour
    const file_size = (try file.stat()).size;
    if (file_size == 0) return error.ZeroSizedTarball;

    const memory = try std.posix.mmap(
        null,
        file_size,
        std.posix.PROT.READ,
        std.posix.MAP{ .TYPE = .PRIVATE },
        file.handle,
        0,
    );
    defer std.posix.munmap(memory);

    if (@import("builtin").os.tag != .macos) {
        try std.posix.madvise(
            memory.ptr,
            memory.len,
            std.posix.MADV.SEQUENTIAL | std.posix.MADV.WILLNEED,
        );
    }

    var maybe_manifest: ?Manifest = null;
    errdefer if (maybe_manifest) |manifest| manifest.deinit(allocator);

    var maybe_status_cache: ?StatusCache = null;
    errdefer if (maybe_status_cache) |status_cache| status_cache.deinit(allocator);

    const manifest_path = sig.utils.fmt.boundedFmt(
        "snapshots/{0}/{0}",
        .{slot_and_hash.slot},
    );

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var tar_stream = try zstd.Reader.init(memory);
    defer tar_stream.deinit();

    const reader = tar_stream.reader();
    while (true) {
        var header_buf: [512]u8 = undefined;
        const header: sig.utils.tar.TarHeaderMinimal = 
            switch (try reader.readAtLeast(&header_buf, 512)) {
                0 => break,
                512 => .{ .bytes = header_buf[0..512] },
                else => |actual_size| std.debug.panic(
                    "Actual file size ({d}) too small for header (< 512).",
                    .{actual_size},
                ),
            };

        var name_buf: [255]u8 = undefined;
        const name = try header.fullName(&name_buf);

        const size = try header.size();
        const padded_size = std.mem.alignForward(u64, size, 512);
        
        switch (header.kind()) {
            .normal => {},
            .directory => continue, // ignore
            .global_extended_header, .extended_header => {
                return error.TarUnsupportedFileType;
            },
            .hard_link => return error.TarUnsupportedFileType,
            .symbolic_link => return error.TarUnsupportedFileType,
            else => return error.TarUnsupportedFileType,
        }

        if (size == 0 and name.len == 0) {
            break; // tar EOF
        }

        // Read data
        const data = try arena.allocator().alloc(u8, size);
        defer _ = arena.reset(.retain_capacity);
        std.debug.assert(data.len == try reader.readAll(data));

        // skip tar padding
        try reader.skipBytes(padded_size - size, .{});

        // Check for metadata files.
        var fba = std.io.fixedBufferStream(data);
        if (std.mem.eql(u8, name, manifest_path.constSlice())) {
            std.debug.assert(maybe_manifest == null);
            maybe_manifest = 
                try sig.accounts_db.snapshot.Manifest.decodeFromBincode(allocator, fba.reader());
            continue;
        } else if (std.mem.eql(u8, name, "snapshots/status_cache")) {
            std.debug.assert(maybe_status_cache == null);
            maybe_status_cache = 
                try sig.accounts_db.snapshot.StatusCache.decodeFromBincode(allocator, fba.reader());
            continue;
        }

        // Try to load an account file
        if (!std.mem.startsWith(u8, name, "accounts/")) {
            std.debug.print("ignoring snapshot file: {s}\n", .{name});
            continue;
        }

        const split = std.mem.indexOf(u8, name, ".") orelse return error.BadAccountFileName;
        if (name.len - 1 == split) return error.BadAccountFileName;
        const slot = try std.fmt.parseInt(u64, name["accounts/".len..split], 10);
        const id = try std.fmt.parseInt(u32, name[split + 1 ..], 10);

        if (size > @as(usize, sig.accounts_db.snapshot.data.MAXIMUM_ACCOUNT_FILE_SIZE)) {
            return error.FileSizeTooLarge;
        }

        // Load accounts from AccountFile
        var offset: u64 = 0;
        while (true) {
            

            

            try account.validate();
            offset = offset + account.len;
        }

        if (offset != std.mem.alignForward(usize, self.length, @sizeOf(u64))) {
            return error.InvalidAccountFileLength;
        }
    }

    return .{
        maybe_manifest.?,
        maybe_status_cache.?,
    };
}

fn insertFromSnapshotAccountFile(
    self: *Rooted,
    allocator: std.mem.Allocator,
    start_offset: u64,
) !void {
    const AccountInFile = sig.accounts_db.accounts_file.AccountInFile;
    const max_header_buf_len = sig.accounts_db.accounts_file.AccountFile.max_header_buf_len;

    var offset = start_offset;
    offset += @sizeOf(AccountInFile.StorageInfo);
    offset = std.mem.alignForward(usize, offset, @sizeOf(u64));

    const account_info_start = offset;
    offset += @sizeOf(AccountInFile.AccountInfo);
    offset = std.mem.alignForward(usize, offset, @sizeOf(u64));

    const hash_start = offset;
    offset += @sizeOf(sig.core.Hash);
    offset = std.mem.alignForward(usize, offset, @sizeOf(u64));

    const header_byte_len = offset - start_offset;
    std.debug.assert(header_byte_len <= max_header_buf_len);

    var offset_restarted = start_offset;
    var buf: [max_header_buf_len]u8 = undefined;
    {
        const read = try self.getSlice(
            allocator,
            buffer_pool,
            &offset_restarted,
            header_byte_len,
        );
        defer read.deinit(metadata_allocator);
        std.debug.assert(offset == offset_restarted);
        read.readAll(buf[0..header_byte_len]);
    }

    var store_info: AccountInFile.StorageInfo = undefined;
    @memcpy(
        std.mem.asBytes(&store_info),
        buf[0..][0..@sizeOf(AccountInFile.StorageInfo)],
    );

    var account_info: AccountInFile.AccountInfo = undefined;
    @memcpy(
        std.mem.asBytes(&account_info),
        buf[account_info_start - start_offset ..][0..@sizeOf(AccountInFile.AccountInfo)],
    );

    var hash: Hash = undefined;
    @memcpy(
        std.mem.asBytes(&hash),
        buf[hash_start - start_offset ..][0..@sizeOf(Hash)],
    );

    const data = try self.getSlice(
        metadata_allocator,
        buffer_pool,
        &offset_restarted,
        store_info.data_len,
    );
    errdefer data.deinit(metadata_allocator);

    const len = offset_restarted - start_offset;
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
