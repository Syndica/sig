const std = @import("std");
const rocks = @import("rocksdb");
const sig = @import("../../sig.zig");

const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;

const AccountFields = sig.core.AccountFields;
const Ancestors = sig.core.Ancestors;
const Epoch = sig.core.Epoch;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;

const Logger = sig.trace.Logger("accountsdb.rocks.rooted");

const ColumnFamily = enum {
    /// metadata about the account
    metadata,
    /// the accounts' data field
    data,
};

pub const RootedDB = struct {
    db: rocks.DB,
    cf_handles: []const rocks.ColumnFamilyHandle,
    logger: Logger,

    pub fn deinit(self: RootedDB, allocator: Allocator) void {
        self.logger.info().log("Closing RocksDB for accounts");
        self.db.deinit();
        allocator.free(self.cf_handles);
    }

    const OpenError =
        error{RocksDBOpen} ||
        Allocator.Error ||
        std.posix.MakeDirError ||
        std.fs.Dir.StatFileError;

    pub fn init(
        allocator: Allocator,
        logger: Logger,
        path: []const u8,
    ) OpenError!RootedDB {
        logger.info().log("Opening RocksDB for accounts");
        const owned_path = try std.fmt.allocPrintZ(allocator, "{s}/rocksdb", .{path});
        try std.fs.cwd().makePath(owned_path);

        const cf_enum_fields = @typeInfo(ColumnFamily).@"enum".fields;
        const num_cfs = cf_enum_fields.len;

        // configure column families
        const cf_descriptions = try allocator.alloc(rocks.ColumnFamilyDescription, num_cfs);
        defer allocator.free(cf_descriptions);
        for (cf_enum_fields) |field| {
            // this is an implicit assertion that ColumnFamily enum values are contiguous from 0
            cf_descriptions[field.value] = .{ .name = field.name, .options = .{} };
        }

        // open rocksdb
        const db: rocks.DB, //
        const cfs: []const rocks.ColumnFamily //
        = try callRocks(
            .from(logger),
            rocks.DB.open,
            .{
                allocator,
                owned_path,
                rocks.DBOptions{ .create_if_missing = true, .create_missing_column_families = true },
                cf_descriptions,
            },
        );
        defer allocator.free(cfs);

        // cf handles to use at runtime
        const cf_handles = try allocator.alloc(rocks.ColumnFamilyHandle, num_cfs);
        errdefer allocator.free(cf_handles); // kept alive as a field
        for (cf_handles, cfs) |*handle, cf| handle.* = cf.handle;

        var self = RootedDB{
            .db = db,
            .logger = logger,
            .cf_handles = cf_handles,
            .next_data_id = .init(0),
        };

        if (self.getMetadata(.sequence_number)) |number| self.next_data_id = .init(number);

        return self;
    }

    pub const InputAccount = struct {
        fields: AccountFields,
        data: []const u8,
    };

    pub fn put(self: *RootedDB, address: Pubkey, account: InputAccount) !void {
        const metadata = AccountMetadata{
            .fields = account.fields,
            .data_len = account.data.len,
        };
        try self.rocksPut(.metadata, &address.bytes, &metadata.serialize());
        try self.rocksPut(.data, &address.bytes, &account.data);
    }

    pub const OutputAccount = struct {
        fields: AccountFields,
        data: rocks.Data,
    };

    pub fn get(self: *RootedDB, address: Pubkey) !?OutputAccount {
        const metadata_bytes = try self.rocksGet(.metadata, &address.data) orelse return null;
        errdefer metadata_bytes.deinit();

        const data = try self.rocksGet(.data, &address.data) orelse return null;
        errdefer data.deinit();

        const metadata = try AccountMetadata.deserialize(metadata_bytes.data);

        return .{
            .fields = metadata.fields,
            .data = data,
        };
    }

    /////////////////////////////////////////////////////////
    /// helper methods for interacting with rocksdb
    // -----------------------------------------------------

    fn rocksGet(self: RootedDB, comptime cf: ColumnFamily, key: []const u8) !?rocks.Data {
        return try callRocks(
            self.logger,
            rocks.DB.get,
            .{ &self.db, self.cf_handles[@intFromEnum(cf)], key },
        );
    }

    fn rocksPut(
        self: RootedDB,
        comptime cf: ColumnFamily,
        key: []const u8,
        value: []const u8,
    ) !void {
        return try callRocks(
            self.logger,
            rocks.DB.put,
            .{ &self.db, self.cf_handles[@intFromEnum(cf)], key, value },
        );
    }

    fn rocksBatchPut(
        self: RootedDB,
        comptime cf: ColumnFamily,
        batch: rocks.WriteBatch,
        key: []const u8,
        value: []const u8,
    ) !void {
        _ = batch; // autofix
        return try callRocks(
            self.logger,
            rocks.WriteBatch.put,
            .{ &self.db, self.cf_handles[@intFromEnum(cf)], key, value },
        );
    }
};

pub const AccountMetadata = struct {
    fields: AccountFields,
    data_len: u32,

    const bincode_size = sig.bincode.sizeOf(AccountMetadata, .{});

    pub fn serialize(self: AccountMetadata) [bincode_size]u8 {
        var bytes: [bincode_size]u8 = undefined;
        var stream = std.io.fixedBufferStream(&bytes);
        sig.bincode.write(stream.writer(), self, .{}) catch
            unreachable; // size is comptime known
        return bytes;
    }

    pub fn deserialize(bytes: []const u8) !AccountMetadata {
        const noalloc = sig.utils.allocators.failing.allocator(.{});
        var stream = std.io.fixedBufferStream(bytes);
        return try sig.bincode.read(noalloc, AccountMetadata, stream.reader(), .{});
    }
};

fn callRocks(
    logger: Logger,
    comptime func: anytype,
    args: anytype,
) sig.utils.types.ReturnType(@TypeOf(func)) {
    var err_str: ?rocks.Data = null;
    return @call(.auto, func, args ++ .{&err_str}) catch |e| {
        logger.err().logf("{} - {s}", .{ e, err_str.? });
        return e;
    };
}

// TODO:
// - pinnable slice
// - replace callRocks with cleaner integration
// - carefully consider whether a common abstraction for backing kv-store
//   database with the ledger could be superior to either of the individual
//   abstractions.
