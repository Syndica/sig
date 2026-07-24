//! RocksDB-backed Agave ledger access.
//!
//! Provides read-only access to an Agave validator's RocksDB ledger,
//! supporting iteration over slot metadata and shred data/code columns.

const std = @import("std");
const rocks = @import("rocksdb");
const rocks_c = @import("rocksdb-c");
const config = @import("config.zig");

const Allocator = std.mem.Allocator;
const Slot = config.Slot;
const ShredKind = config.ShredKind;

const agave_cf_default = config.agave_cf_default;
const agave_cf_meta = config.agave_cf_meta;
const agave_cf_data_shred = config.agave_cf_data_shred;
const agave_cf_code_shred = config.agave_cf_code_shred;

pub const AgaveBlockstore = struct {
    rocksdb_path: []const u8,
    db: rocks.DB,
    column_families: []const rocks.ColumnFamily,
    has_code_shred: bool,

    pub fn open(allocator: Allocator, ledger_path: []const u8) !AgaveBlockstore {
        const rocksdb_path = try resolveRocksDbPath(allocator, ledger_path);
        errdefer allocator.free(rocksdb_path);

        var available_cfs = try listColumnFamilies(allocator, rocksdb_path);
        defer available_cfs.deinit(allocator);

        try requireColumnFamily(&available_cfs, agave_cf_default);
        try requireColumnFamily(&available_cfs, agave_cf_meta);
        try requireColumnFamily(&available_cfs, agave_cf_data_shred);

        const has_code_shred = available_cfs.contains(agave_cf_code_shred);
        const cfs = try columnFamilyDescriptions(allocator, has_code_shred);
        defer allocator.free(cfs);

        const rocksdb_path_z = try allocator.dupeZ(u8, rocksdb_path);
        defer allocator.free(rocksdb_path_z);

        var err_data: ?rocks.Data = null;
        defer if (err_data) |err| err.deinit();

        const db, const opened_cfs = rocks.DB.open(
            allocator,
            rocksdb_path_z,
            .{},
            cfs,
            true,
            &err_data,
        ) catch |err| {
            if (err_data) |rocks_err| {
                std.debug.print(
                    "failed to open RocksDB at {s}: {s}\n",
                    .{ rocksdb_path, rocks_err.data },
                );
            }
            return err;
        };

        return .{
            .rocksdb_path = rocksdb_path,
            .db = db,
            .column_families = opened_cfs,
            .has_code_shred = has_code_shred,
        };
    }

    pub fn deinit(self: *AgaveBlockstore, allocator: Allocator) void {
        self.db.deinit();
        allocator.free(self.rocksdb_path);
    }

    pub fn columnFamily(self: *const AgaveBlockstore, cf_name: []const u8) !rocks.ColumnFamilyHandle {
        for (self.column_families) |cf| {
            if (std.mem.eql(u8, cf.name, cf_name)) return cf.handle;
        }
        return error.ColumnFamilyNotFound;
    }
};

// ---------------------------------------------------------------------------
// RocksDB helpers
// ---------------------------------------------------------------------------

pub fn resolveRocksDbPath(allocator: Allocator, ledger_path: []const u8) ![]const u8 {
    const nested_rocksdb_path = try std.fs.path.join(allocator, &.{ ledger_path, "rocksdb" });

    if (std.fs.cwd().statFile(nested_rocksdb_path)) |stat| {
        if (stat.kind == .directory) return nested_rocksdb_path;
    } else |_| {}
    allocator.free(nested_rocksdb_path);

    if (std.fs.cwd().statFile(ledger_path)) |stat| {
        if (stat.kind == .directory) return try allocator.dupe(u8, ledger_path);
    } else |_| {}

    std.debug.print("ledger path does not exist or is not a directory: {s}\n", .{ledger_path});
    return error.InvalidLedgerPath;
}

const ColumnFamilyNames = struct {
    names: []const []const u8,

    fn deinit(self: *ColumnFamilyNames, allocator: Allocator) void {
        for (self.names) |cf_name| allocator.free(cf_name);
        allocator.free(self.names);
    }

    fn contains(self: *const ColumnFamilyNames, cf_name: []const u8) bool {
        for (self.names) |candidate| {
            if (std.mem.eql(u8, candidate, cf_name)) return true;
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
        std.debug.print(
            "failed to list RocksDB column families at {s}: {s}\n",
            .{ rocksdb_path, std.mem.span(err_z) },
        );
        return error.RocksDBListColumnFamilies;
    }
    if (raw_names == null) return error.RocksDBListColumnFamilies;
    defer rocks_c.rocksdb_list_column_families_destroy(raw_names, count);

    const names = try allocator.alloc([]const u8, count);
    var names_len: usize = 0;
    errdefer {
        for (names[0..names_len]) |n| allocator.free(n);
        allocator.free(names);
    }

    for (names, raw_names[0..count]) |*n, raw_name| {
        n.* = try allocator.dupe(u8, std.mem.span(raw_name));
        names_len += 1;
    }

    return .{ .names = names };
}

fn requireColumnFamily(available_cfs: *const ColumnFamilyNames, cf_name: []const u8) !void {
    if (available_cfs.contains(cf_name)) return;
    std.debug.print("missing required column family: {s}\n", .{cf_name});
    return error.MissingRequiredColumnFamily;
}

fn columnFamilyDescriptions(
    allocator: Allocator,
    has_code_shred: bool,
) Allocator.Error![]const rocks.ColumnFamilyDescription {
    const count: usize = if (has_code_shred) 4 else 3;
    const cfs = try allocator.alloc(rocks.ColumnFamilyDescription, count);
    cfs[0] = .{ .name = agave_cf_default };
    cfs[1] = .{ .name = agave_cf_meta };
    cfs[2] = .{ .name = agave_cf_data_shred };
    if (has_code_shred) cfs[3] = .{ .name = agave_cf_code_shred };
    return cfs;
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
