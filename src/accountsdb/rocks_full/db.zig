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

const Logger = sig.trace.Logger("accountsdb.rocks.db");

const ColumnFamily = enum {
    /// general metadata about the database
    /// - last rooted slot
    /// - account_data sequence number
    metadata,

    pubkey_id,

    /// metadata for rooted accounts
    rooted,
    /// metadata for unrooted accounts, indexed by pubkey then slot
    pubkey_slot,
    /// metadata for unrooted accounts, indexed by pubkey then slot
    slot_pubkey,

    /// the accounts' data field
    account_data,

    // pub fn helper(comptime self: ColumnFamily) type {
    //     switch (self) {
    //         // use MetadataField for this
    //         .metadata => unreachable,
    //         .rooted => struct {
    //             pub fn writeKey(address: Pubkey) [32]u8 {
    //                 _ = address; // autofix
    //             }
    //             pub const readValue = void;
    //             pub const writeValue = void;
    //         },
    //         .pubkey_slot => struct {},
    //         .slot_pubkey => struct {},
    //         .account_data => struct {},
    //     }
    // }
};

const MetadataField = enum {
    last_rooted_slot,
    next_data_id_batch,
};

pub const AccountsDB = struct {
    db: rocks.DB,
    cf_handles: []const rocks.ColumnFamilyHandle,
    logger: Logger,

    next_data_id: Atomic(u64),
    next_data_id_lock: std.Thread.RwLock,
    next_data_id_to_sync: u64,

    last_initiated_prune_slot: Atomic(Slot),

    pub fn deinit(self: AccountsDB, allocator: Allocator) void {
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
    ) OpenError!AccountsDB {
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

        var self = AccountsDB{
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

    pub fn put(self: *AccountsDB, slot: Slot, address: Pubkey, account: InputAccount) !void {
        var slot_pubkey: [40]u8 = undefined;
        std.mem.writeInt(u64, slot_pubkey[0..8], slot, .big);
        @memcpy(slot_pubkey[8..], &address.data);

        var pubkey_slot: [40]u8 = undefined;
        @memcpy(pubkey_slot[0..32], &address.data);
        std.mem.writeInt(u64, pubkey_slot[32..], slot, .big);

        if (self.rocksGet(.slot_pubkey, &slot_pubkey)) |existing_value| {
            var metadata = try AccountMetadata.deserialize(existing_value);
            if (metadata.fields != account.fields) {
                metadata.fields = account.fields;
                const bytes = metadata.serialize();
                try self.rocksPut(.pubkey_slot, &pubkey_slot, &bytes);
                try self.rocksPut(.slot_pubkey, &slot_pubkey, &bytes);
            }

            try self.rocksPut(.account_data, &metadata.data_id, &account.data);
        } else {
            const data_id = self.nextDataId();
            try self.rocksPut(.account_data, &data_id, account.data);

            const metadata = AccountMetadata{
                .fields = account.fields,
                .data_id = data_id,
                .data_len = account.data.len,
            };
            const bytes = metadata.serialize();
            try self.rocksPut(.pubkey_slot, &pubkey_slot, &bytes);
            try self.rocksPut(.slot_pubkey, &slot_pubkey, &bytes);
        }
    }

    pub const OutputAccount = struct {
        fields: AccountFields,
        data: rocks.Data,
    };

    pub fn get(self: *AccountsDB, address: Pubkey, ancestors: Ancestors) OutputAccount {
        var start_key: [40]u8 = undefined;
        @memcpy(start_key[0..32], &address.data);
        std.mem.writeInt(u64, start_key[32..], std.math.maxInt(Slot), .big);

        const iterator = self.db.iterator(
            self.cf_handles[@intFromEnum(ColumnFamily.pubkey_slot)],
            .reverse,
            start_key,
        );
        while (try callRocks(rocks.Iterator.next, .{iterator})) |item| {
            const key, const value = item;
            defer key.deinit();
            defer value.deinit();

            if (!address.equals(&.{ .data = key[0..32] })) {
                // there are no unrooted versions left from this address.
                break;
            }

            const slot = std.mem.readInt(Slot, key[32..], .big);
            if (ancestors.containsSlot(slot)) {
                const metadata = try AccountMetadata.deserialize(value);
                const data = try self.rocksGet(.account_data, &metadata.data_id) orelse
                    error.Corruption;
                return .{
                    .fields = metadata.fields,
                    .data = data,
                };
            }
        }

        const metadata_bytes = try self.rocksGet(.rooted, &address.data) orelse return null;
        const metadata = try AccountMetadata.deserialize(metadata_bytes);
        const data = try self.rocksGet(.account_data, &metadata.data_id) orelse
            return error.Corruption;
        return .{
            .fields = metadata.fields,
            .data = data,
        };
    }

    fn nextDataId(self: *AccountsDB) [8]u8 {
        self.next_data_id_lock.lockShared();
        const id = self.next_data_id.fetchAdd(1, .monotonic);
        if (id > self.next_data_id_to_sync) {
            self.next_data_id_lock.unlockShared();
            self.next_data_id_lock.lock();
            if (id > self.next_data_id_to_sync) {
                self.next_data_id_to_sync += 1000;
                try self.putMetadata(.next_data_id_batch, self.next_data_id_to_sync);
            }
        } else {
            self.next_data_id_lock.unlockShared();
        }

        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, id, .little);

        return bytes;
    }

    /////////////////////////////////////////////////////////
    /// helper methods for interacting with rocksdb
    // -----------------------------------------------------

    fn getMetadata(self: AccountsDB, comptime field: MetadataField) !u64 {
        const data = try self.rocksGet(.metadata, std.enums.tagName(MetadataField, field));
        defer data.deinit();
        std.mem.readInt(u64, data.data, .little);
    }

    fn putMetadata(
        self: AccountsDB,
        comptime field: MetadataField,
        value: u64,
    ) !void {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, value, .little);
        try self.rocksPut(.metadata, std.enums.tagName(MetadataField, field), bytes);
    }

    fn batchPutMetadata(
        self: AccountsDB,
        comptime field: MetadataField,
        batch: rocks.WriteBatch,
        value: u64,
    ) !void {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, value, .little);
        try self.rocksBatchPut(.metadata, batch, std.enums.tagName(MetadataField, field), bytes);
    }

    fn rocksGet(self: AccountsDB, comptime cf: ColumnFamily, key: []const u8) !rocks.Data {
        return try callRocks(
            self.logger,
            rocks.DB.get,
            .{ &self.db, self.cf_handles[@intFromEnum(cf)], key },
        );
    }

    fn rocksPut(
        self: AccountsDB,
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
        self: AccountsDB,
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
    data_id: [8]u8,

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
