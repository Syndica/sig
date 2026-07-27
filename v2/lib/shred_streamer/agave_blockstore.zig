//! RocksDB-backed Agave ledger access.
//!
//! Provides read-only access to an Agave validator's RocksDB ledger,
//! supporting iteration over slot metadata and shred data/code columns.

const std = @import("std");
const rocks = @import("rocksdb");
const rocks_c = @import("rocksdb-c");
const config = @import("config.zig");

const Allocator = std.mem.Allocator;

const agave_cf_default = config.agave_cf_default;
const agave_cf_meta = config.agave_cf_meta;
const agave_cf_data_shred = config.agave_cf_data_shred;
const agave_cf_code_shred = config.agave_cf_code_shred;

pub const AgaveBlockstore = struct {
    rocksdb_path: []const u8,
    db: rocks.DB,
    column_families: []const rocks.ColumnFamily,
    has_code_shred: bool,

    /// Opens a RocksDB blockstore at `rocksdb_path`. The caller is responsible
    /// for resolving the path (e.g. via `resolveRocksDbPath`) — `rocksdb_path`
    /// must already point at the actual RocksDB directory.
    pub fn open(allocator: Allocator, rocksdb_path: []const u8) !AgaveBlockstore {
        const owned_path = try allocator.dupe(u8, rocksdb_path);
        errdefer allocator.free(owned_path);

        var available_cfs = try listColumnFamilies(allocator, rocksdb_path);
        defer available_cfs.deinit(allocator);

        try requireColumnFamily(&available_cfs, agave_cf_default);
        try requireColumnFamily(&available_cfs, agave_cf_meta);
        try requireColumnFamily(&available_cfs, agave_cf_data_shred);

        const has_code_shred = available_cfs.contains(agave_cf_code_shred);

        // Stack-allocated column family descriptions — no heap allocation needed.
        var cfs_buf: [4]rocks.ColumnFamilyDescription = undefined;
        const cfs = cfs: {
            const count: usize = if (has_code_shred) 4 else 3;
            const slice = cfs_buf[0..count];
            slice[0] = .{ .name = agave_cf_default };
            slice[1] = .{ .name = agave_cf_meta };
            slice[2] = .{ .name = agave_cf_data_shred };
            if (has_code_shred) slice[3] = .{ .name = agave_cf_code_shred };
            break :cfs slice;
        };

        const rocksdb_path_z = try allocator.dupeZ(u8, rocksdb_path);
        defer allocator.free(rocksdb_path_z);

        var err_data: ?rocks.Data = null;
        defer if (err_data) |err| err.deinit();

        const db, const opened_cfs = try rocks.DB.open(
            allocator,
            rocksdb_path_z,
            .{},
            cfs,
            true,
            &err_data,
        );

        return .{
            .rocksdb_path = owned_path,
            .db = db,
            .column_families = opened_cfs,
            .has_code_shred = has_code_shred,
        };
    }

    pub fn deinit(self: *AgaveBlockstore, allocator: Allocator) void {
        self.db.deinit();
        allocator.free(self.rocksdb_path);
    }

    pub fn columnFamily(
        self: *const AgaveBlockstore,
        cf_name: []const u8,
    ) !rocks.ColumnFamilyHandle {
        for (self.column_families) |cf| {
            if (std.mem.eql(u8, cf.name, cf_name)) return cf.handle;
        }
        return error.ColumnFamilyNotFound;
    }
};

// ---------------------------------------------------------------------------
// RocksDB helpers
// ---------------------------------------------------------------------------

/// Resolves a ledger path to the actual RocksDB directory.
///
/// Agave ledger layouts have RocksDB either at `<ledger>/rocksdb` (nested) or
/// directly at `<ledger>`. This tries the nested path first, then falls back
/// to the direct path. Returns an owned string that must be freed by the
/// caller.
///
/// Callers should invoke this before calling `AgaveBlockstore.open`.
pub fn resolveRocksDbPath(allocator: Allocator, ledger_path: []const u8) ![]const u8 {
    const nested_rocksdb_path = try std.fs.path.join(allocator, &.{ ledger_path, "rocksdb" });

    if (std.fs.cwd().statFile(nested_rocksdb_path)) |stat| {
        if (stat.kind == .directory) return nested_rocksdb_path;
    } else |_| {}
    allocator.free(nested_rocksdb_path);

    if (std.fs.cwd().statFile(ledger_path)) |stat| {
        if (stat.kind == .directory) return try allocator.dupe(u8, ledger_path);
    } else |_| {}

    return error.InvalidLedgerPath;
}

const ColumnFamilyNames = struct {
    names: []const [*:0]const u8,

    fn deinit(self: *ColumnFamilyNames, allocator: Allocator) void {
        for (self.names) |cf_name| allocator.free(std.mem.span(cf_name));
        allocator.free(self.names);
    }

    fn contains(self: *const ColumnFamilyNames, cf_name: []const u8) bool {
        for (self.names) |candidate| {
            if (std.mem.eql(u8, std.mem.span(candidate), cf_name)) return true;
        }
        return false;
    }
};

fn listColumnFamilies(allocator: Allocator, rocksdb_path: []const u8) !ColumnFamilyNames {
    const options = rocks_c.rocksdb_options_create() orelse return error.RocksDBOptionsCreate;
    defer rocks_c.rocksdb_options_destroy(options);

    const rocksdb_path_z = try allocator.dupeZ(u8, rocksdb_path);
    defer allocator.free(rocksdb_path_z);

    var err_ptr: ?[*:0]u8 = null;
    var count: usize = 0;
    const raw_names = rocks_c.rocksdb_list_column_families(
        options,
        rocksdb_path_z.ptr,
        &count,
        @ptrCast(&err_ptr),
    );
    if (err_ptr) |err_z| {
        defer rocks_c.rocksdb_free(err_z);
        return error.RocksDBListColumnFamilies;
    }
    if (raw_names == null) return error.RocksDBListColumnFamilies;
    defer rocks_c.rocksdb_list_column_families_destroy(raw_names, count);

    const names = try allocator.alloc([*:0]const u8, count);
    var names_len: usize = 0;
    errdefer {
        for (names[0..names_len]) |n| allocator.free(std.mem.span(n));
        allocator.free(names);
    }

    for (names, raw_names[0..count]) |*n, raw_name| {
        const duped = try allocator.dupeZ(u8, std.mem.span(raw_name));
        n.* = duped.ptr;
        names_len += 1;
    }

    return .{ .names = names };
}

fn requireColumnFamily(available_cfs: *const ColumnFamilyNames, cf_name: []const u8) !void {
    if (available_cfs.contains(cf_name)) return;
    return error.MissingRequiredColumnFamily;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "resolve rocksdb path" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("ledger/rocksdb");

    const ledger_path = try tmp.dir.realpathAlloc(std.testing.allocator, "ledger");
    defer std.testing.allocator.free(ledger_path);

    const rocksdb_path = try resolveRocksDbPath(std.testing.allocator, ledger_path);
    defer std.testing.allocator.free(rocksdb_path);

    const expected = try tmp.dir.realpathAlloc(std.testing.allocator, "ledger/rocksdb");
    defer std.testing.allocator.free(expected);

    try std.testing.expectEqualStrings(expected, rocksdb_path);

    const direct_path = try tmp.dir.realpathAlloc(std.testing.allocator, "ledger/rocksdb");
    defer std.testing.allocator.free(direct_path);

    const direct_rocksdb_path = try resolveRocksDbPath(std.testing.allocator, direct_path);
    defer std.testing.allocator.free(direct_rocksdb_path);

    try std.testing.expectEqualStrings(direct_path, direct_rocksdb_path);
}
