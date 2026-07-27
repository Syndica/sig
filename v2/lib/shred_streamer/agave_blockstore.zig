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
    /// for resolving the path so that `rocksdb_path` points directly at the
    /// actual RocksDB directory (not the enclosing Agave ledger directory).
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
        allocator.free(self.column_families);
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
