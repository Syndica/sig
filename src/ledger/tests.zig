//! Tests and test helpers that exceed the scope of any individual file in the ledger package.

const std = @import("std");
const sig = @import("../sig.zig");
const ledger = @import("lib.zig");

const Allocator = std.mem.Allocator;

const BlockstoreDB = ledger.BlockstoreDB;
const Entry = sig.core.Entry;
const Shred = ledger.shred.Shred;
const Slot = sig.core.Slot;
const SlotMeta = ledger.meta.SlotMeta;
const VersionedTransactionWithStatusMeta = ledger.reader.VersionedTransactionWithStatusMeta;

const comptimePrint = std.fmt.comptimePrint;

const schema = ledger.schema.schema;
const test_logger = sig.trace.TestLogger.default.logger();

test "put/get data consistency for merkle root" {
    var rng = std.Random.DefaultPrng.init(100);
    const random = rng.random();

    var db = try DB.init("bsdbMerkleRootDatabaseConsistency");
    defer db.deinit();

    const id = sig.ledger.shred.ErasureSetId{
        .slot = 1234127498,
        .fec_set_index = 4932874234,
    };
    const root = sig.core.Hash.random(random);

    try db.put(
        schema.merkle_root_meta,
        id,
        sig.ledger.meta.MerkleRootMeta{
            .merkle_root = root,
            .first_received_shred_index = 100,
            .first_received_shred_type = .data,
        },
    );
    const output: sig.ledger.meta.MerkleRootMeta = (try db.get(
        std.testing.allocator,
        schema.merkle_root_meta,
        id,
    )).?;
    try std.testing.expectEqualSlices(u8, &root.data, &output.merkle_root.?.data);
}

// Analogous to [test_get_rooted_block](https://github.com/anza-xyz/agave/blob/a72f981370c3f566fc1becf024f3178da041547a/ledger/src/blockstore.rs#L8271)
test "insert shreds and transaction statuses then get blocks" {
    var state = try State.init("insert shreds and transaction statuses then get blocks");
    defer state.deinit();
    const allocator = state.allocator();

    var db = state.db;
    var inserter = try state.shredInserter();
    var writer = try state.writer();
    var reader = try state.reader();

    const slot = 10;

    const prefix = "agave.blockstore.test_get_rooted_block.";
    const entries = try loadEntriesFromFile(
        allocator,
        test_shreds_dir ++ "/" ++ prefix ++ "entries.bin",
    );
    defer {
        for (entries) |e| e.deinit(allocator);
        allocator.free(entries);
    }
    const blockhash = entries[entries.len - 1].hash;
    const blockhash_string = blockhash.base58String();

    const shreds = try testShreds(prefix ++ "shreds.bin");
    const more_shreds = try testShreds(prefix ++ "more_shreds.bin");
    const unrooted_shreds = try testShreds(prefix ++ "unrooted_shreds.bin");
    defer inline for (.{ shreds, more_shreds, unrooted_shreds }) |slice| {
        deinitShreds(std.testing.allocator, slice);
    };

    _ = try ledger.insert_shred.insertShredsForTest(&inserter, shreds);
    _ = try ledger.insert_shred.insertShredsForTest(&inserter, more_shreds);
    _ = try ledger.insert_shred.insertShredsForTest(&inserter, unrooted_shreds);

    try writer.setRoots(&.{ slot - 1, slot, slot + 1 });

    const parent_meta = SlotMeta.init(allocator, 0, null);
    try db.put(schema.slot_meta, slot - 1, parent_meta);

    var expected_transactions = std.ArrayList(VersionedTransactionWithStatusMeta).init(allocator);
    defer {
        for (expected_transactions.items) |etx| {
            allocator.free(etx.meta.pre_balances);
            allocator.free(etx.meta.post_balances);
        }
        expected_transactions.deinit();
    }
    for (entries) |entry| {
        for (entry.transactions.items) |transaction| {
            var pre_balances = std.ArrayList(u64).init(allocator);
            var post_balances = std.ArrayList(u64).init(allocator);
            const num_accounts = transaction.message.accountKeys().len;
            for (0..num_accounts) |i| {
                try pre_balances.append(i * 10);
                try post_balances.append(i * 11);
            }
            const compute_units_consumed = 12345;
            const signature = transaction.signatures[0];

            var pre_cloned = try pre_balances.clone();
            const pre_owned = try pre_cloned.toOwnedSlice();
            defer allocator.free(pre_owned);
            var post_cloned = try post_balances.clone();
            const post_owned = try post_cloned.toOwnedSlice();
            defer allocator.free(post_owned);

            const status = ledger.meta.TransactionStatusMeta{
                .status = null,
                .fee = 42,
                .pre_balances = pre_owned,
                .post_balances = post_owned,
                .inner_instructions = &.{},
                .log_messages = &.{},
                .pre_token_balances = &.{},
                .post_token_balances = &.{},
                .rewards = &.{},
                .loaded_addresses = .{},
                .return_data = .{},
                .compute_units_consumed = compute_units_consumed,
            };
            try db.put(schema.transaction_status, .{ signature, slot }, status);
            try db.put(schema.transaction_status, .{ signature, slot + 1 }, status);
            try db.put(schema.transaction_status, .{ signature, slot + 2 }, status);
            try expected_transactions.append(VersionedTransactionWithStatusMeta{
                .transaction = transaction,
                .meta = ledger.meta.TransactionStatusMeta{
                    .status = null,
                    .fee = 42,
                    .pre_balances = try pre_balances.toOwnedSlice(),
                    .post_balances = try post_balances.toOwnedSlice(),
                    .inner_instructions = &.{},
                    .log_messages = &.{},
                    .pre_token_balances = &.{},
                    .post_token_balances = &.{},
                    .rewards = &.{},
                    .loaded_addresses = .{},
                    .return_data = .{},
                    .compute_units_consumed = compute_units_consumed,
                },
            });
        }
    }

    // Even if marked as root, a slot that is empty of entries should return an error
    try std.testing.expectError(error.SlotUnavailable, reader.getRootedBlock(slot - 1, true));

    // The previous_blockhash of `expected_block` is default because its parent slot is a root,
    // but empty of entries (eg. snapshot root slots). This now returns an error.
    try std.testing.expectError(error.ParentEntriesUnavailable, reader.getRootedBlock(slot, true));

    // Test if require_previous_blockhash is false
    {
        const confirmed_block = try reader.getRootedBlock(slot, false);
        defer confirmed_block.deinit(allocator);
        try std.testing.expectEqual(100, confirmed_block.transactions.len);
        const expected_block = ledger.reader.VersionedConfirmedBlock{
            .allocator = allocator,
            .transactions = expected_transactions.items,
            .parent_slot = slot - 1,
            .blockhash = blockhash_string.slice(),
            .previous_blockhash = sig.core.Hash.default().base58String().slice(),
            .rewards = &.{},
            .num_partitions = null,
            .block_time = null,
            .block_height = null,
        };
        try std.testing.expect(sig.utils.types.eql(expected_block, confirmed_block));
    }

    const confirmed_block = try reader.getRootedBlock(slot + 1, false);
    defer confirmed_block.deinit(allocator);
    try std.testing.expectEqual(100, confirmed_block.transactions.len);
    var expected_block = ledger.reader.VersionedConfirmedBlock{
        .allocator = allocator,
        .transactions = expected_transactions.items,
        .parent_slot = slot,
        .blockhash = blockhash_string.slice(),
        .previous_blockhash = blockhash_string.slice(),
        .rewards = &.{},
        .num_partitions = null,
        .block_time = null,
        .block_height = null,
    };
    try std.testing.expect(sig.utils.types.eql(expected_block, confirmed_block));

    try std.testing.expectError(error.SlotNotRooted, reader.getRootedBlock(slot + 2, true));

    const complete_block = try reader.getCompleteBlock(slot + 2, true);
    defer complete_block.deinit(allocator);
    try std.testing.expectEqual(100, complete_block.transactions.len);
    var expected_complete_block = ledger.reader.VersionedConfirmedBlock{
        .allocator = allocator,
        .transactions = expected_transactions.items,
        .parent_slot = slot + 1,
        .blockhash = blockhash_string.slice(),
        .previous_blockhash = blockhash_string.slice(),
        .rewards = &.{},
        .num_partitions = null,
        .block_time = null,
        .block_height = null,
    };
    try std.testing.expect(sig.utils.types.eql(expected_complete_block, complete_block));

    // Test block_time & block_height return, if available
    {
        const timestamp = 1_576_183_541;
        try db.put(schema.blocktime, slot + 1, timestamp);
        expected_block.block_time = timestamp;
        const block_height = slot - 2;
        try db.put(schema.block_height, slot + 1, block_height);
        expected_block.block_height = block_height;

        const confirmed_block_extra = try reader.getRootedBlock(slot + 1, true);
        defer confirmed_block_extra.deinit(allocator);
        try std.testing.expect(sig.utils.types.eql(expected_block, confirmed_block_extra));
    }
    {
        const timestamp = 1_576_183_542;
        try db.put(schema.blocktime, slot + 2, timestamp);
        expected_complete_block.block_time = timestamp;
        const block_height = slot - 1;
        try db.put(schema.block_height, slot + 2, block_height);
        expected_complete_block.block_height = block_height;

        const complete_block_extra = try reader.getCompleteBlock(slot + 2, true);
        defer complete_block_extra.deinit(allocator);
        try std.testing.expect(sig.utils.types.eql(expected_complete_block, complete_block_extra));
    }
}

/// ensures the path exists as an empty directory.
/// deletes anything else that might exist here.
pub fn freshDir(path: []const u8) !void {
    if (std.fs.cwd().access(path, .{})) |_| {
        try std.fs.cwd().deleteTree(path);
    } else |_| {}
    try std.fs.cwd().makePath(path);
}

const test_shreds_dir = sig.TEST_DATA_DIR ++ "/shreds";

fn testShreds(comptime filename: []const u8) ![]const Shred {
    const path = comptimePrint("{s}/{s}", .{ test_shreds_dir, filename });
    return loadShredsFromFile(std.testing.allocator, path);
}

/// Read shreds from binary file structured like this:
/// [shred0_len: u64(little endian)][shred0_payload][shred1_len...
///
/// loadShredsFromFile can read shreds produced by saveShredsToFile or this rust function:
/// ```rust
/// fn save_shreds_to_file(shreds: &[Shred], path: &str) {
///     let mut file = std::fs::File::create(path).unwrap();
///     for shred in shreds {
///         let payload = shred.payload();
///         file.write(&payload.len().to_le_bytes()).unwrap();
///         file.write(payload).unwrap();
///     }
/// }
/// ```
pub fn loadShredsFromFile(allocator: Allocator, path: []const u8) ![]const Shred {
    const file = try std.fs.cwd().openFile(path, .{});
    const reader = file.reader();
    var shreds = std.ArrayList(Shred).init(allocator);
    errdefer {
        for (shreds.items) |shred| shred.deinit();
        shreds.deinit();
    }
    while (try readChunk(allocator, reader)) |chunk| {
        defer allocator.free(chunk);
        try shreds.append(try Shred.fromPayload(allocator, chunk));
    }
    return shreds.toOwnedSlice();
}

pub fn saveShredsToFile(path: []const u8, shreds: []const Shred) !void {
    const file = try std.fs.cwd().createFile(path, .{});
    for (shreds) |s| writeChunk(file.writer(), s.payload());
}

fn readChunk(allocator: Allocator, reader: anytype) !?[]const u8 {
    var size_bytes: [8]u8 = undefined;
    const num_size_bytes_read = try reader.readAll(&size_bytes);
    if (num_size_bytes_read == 0) {
        return null;
    }
    if (num_size_bytes_read != 8) {
        return error.IncompleteSize;
    }
    const size = std.mem.readInt(u64, &size_bytes, .little);

    const chunk = try allocator.alloc(u8, @intCast(size));
    errdefer allocator.free(chunk);
    const num_bytes_read = try reader.readAll(chunk);
    if (num_bytes_read != size) {
        return error.IncompleteChunk;
    }

    return chunk;
}

fn writeChunk(writer: anytype, chunk: []const u8) !void {
    var chunk_size_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &chunk_size_bytes, @intCast(chunk.len), .little);
    try writer.writeAll(&chunk_size_bytes);
    try writer.writeAll(chunk);
}

pub fn deinitShreds(allocator: Allocator, shreds: []const Shred) void {
    for (shreds) |shred| shred.deinit();
    allocator.free(shreds);
}

/// Read entries from binary file structured like this:
/// [entry0_len: u64(little endian)][entry0_bincode][entry1_len...
pub fn loadEntriesFromFile(allocator: Allocator, path: []const u8) ![]const Entry {
    const file = try std.fs.cwd().openFile(path, .{});
    const reader = file.reader();
    var entries = std.ArrayList(Entry).init(allocator);
    errdefer {
        for (entries.items) |entry| entry.deinit(allocator);
        entries.deinit();
    }
    while (try readChunk(allocator, reader)) |chunk| {
        defer allocator.free(chunk);
        try entries.append(try sig.bincode.readFromSlice(allocator, Entry, chunk, .{}));
    }
    return entries.toOwnedSlice();
}

const State = TestState("global");
const DB = TestDB("global");

pub fn TestState(scope: []const u8) type {
    return struct {
        db: BlockstoreDB,
        registry: sig.prometheus.Registry(.{}),
        lowest_cleanup_slot: sig.sync.RwMux(Slot),
        max_root: std.atomic.Value(Slot),

        // if this leaks, you forgot to call `TestState.deinit`
        _leak_check: *u8,

        /// This is used instead of std.testing.allocator because it includes more stack trace frames
        /// std.testing.allocator is already the same exact allocator, just with a call to detectLeaks
        /// run at the end of the test. TestState does the same, so we can use the gpa directly.
        var gpa = std.heap.GeneralPurposeAllocator(.{ .stack_trace_frames = 100 }){};
        /// This is private to ensure _leak_check is initialized before this is used.
        const _allocator = gpa.allocator();

        const Self = @This();

        pub fn init(comptime test_name: []const u8) !*Self {
            const self = try _allocator.create(Self);
            self.* = .{
                .db = try TestDB(scope).initCustom(_allocator, test_name),
                .registry = sig.prometheus.Registry(.{}).init(_allocator),
                .lowest_cleanup_slot = sig.sync.RwMux(Slot).init(0),
                .max_root = std.atomic.Value(Slot).init(0),
                ._leak_check = try std.testing.allocator.create(u8),
            };
            return self;
        }

        pub fn allocator(_: Self) Allocator {
            return _allocator;
        }

        pub fn shredInserter(self: *Self) !ledger.ShredInserter {
            return ledger.ShredInserter.init(_allocator, test_logger, &self.registry, self.db);
        }

        pub fn writer(self: *Self) !ledger.BlockstoreWriter {
            return try ledger.BlockstoreWriter.init(
                _allocator,
                test_logger,
                self.db,
                &self.registry,
                &self.lowest_cleanup_slot,
                &self.max_root,
            );
        }

        pub fn reader(self: *Self) !ledger.BlockstoreReader {
            return try ledger.BlockstoreReader.init(
                _allocator,
                test_logger,
                self.db,
                &self.registry,
                &self.lowest_cleanup_slot,
                &self.max_root,
            );
        }

        pub fn deinit(self: *Self) void {
            self.db.deinit();
            self.registry.deinit();
            std.testing.allocator.destroy(self._leak_check);
            _allocator.destroy(self);
            _ = gpa.detectLeaks();
        }
    };
}

pub fn TestDB(scope: []const u8) type {
    const dir = sig.TEST_DATA_DIR ++ "blockstore";

    return struct {
        pub fn init(comptime test_name: []const u8) !BlockstoreDB {
            return try initCustom(std.testing.allocator, test_name);
        }

        pub fn initCustom(allocator: Allocator, comptime test_name: []const u8) !BlockstoreDB {
            const path = comptimePrint("{s}/{s}/{s}", .{ dir, scope, test_name });
            try sig.ledger.tests.freshDir(path);
            return try BlockstoreDB.open(allocator, test_logger, path);
        }
    };
}
