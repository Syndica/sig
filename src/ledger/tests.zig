//! Tests and test helpers that exceed the scope of any individual file in the ledger package.

const std = @import("std");
const sig = @import("../sig.zig");
const ledger = @import("lib.zig");

const Allocator = std.mem.Allocator;

const BlockstoreDB = ledger.BlockstoreDB;
const Entry = sig.core.Entry;
const Shred = ledger.shred.Shred;
const Slot = sig.core.Slot;
const DirectPrintLogger = sig.trace.DirectPrintLogger;
const Logger = sig.trace.Logger;
const SlotMeta = ledger.meta.SlotMeta;
const VersionedTransactionWithStatusMeta = ledger.reader.VersionedTransactionWithStatusMeta;

const comptimePrint = std.fmt.comptimePrint;
const insertShredsForTest = ledger.shred_inserter.shred_inserter.insertShredsForTest;

const schema = ledger.schema.schema;

test "put/get data consistency for merkle root" {
    var prng = std.Random.DefaultPrng.init(100);
    const random = prng.random();

    var db = try TestDB.init(@src());
    defer db.deinit();

    const id = sig.ledger.shred.ErasureSetId{
        .slot = 1234127498,
        .erasure_set_index = 4932874234,
    };
    const root = sig.core.Hash.initRandom(random);

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
    var test_logger = DirectPrintLogger.init(std.testing.allocator, Logger.TEST_DEFAULT_LEVEL);

    const logger = test_logger.logger();

    var state = try TestState.init(std.testing.allocator, @src(), logger);
    const result = try insertDataForBlockTest(state);
    defer result.deinit();

    const blockhash = result.entries[result.entries.len - 1].hash;

    defer state.deinit();
    const allocator = state.allocator;

    var db = state.db;
    var reader = try state.reader();

    const slot = result.slot;

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
        const expected_block: ledger.reader.VersionedConfirmedBlock = .{
            .allocator = allocator,
            .transactions = result.expected_transactions,
            .parent_slot = slot - 1,
            .blockhash = blockhash,
            .previous_blockhash = sig.core.Hash.ZEROES,
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
        .transactions = result.expected_transactions,
        .parent_slot = slot,
        .blockhash = blockhash,
        .previous_blockhash = blockhash,
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
        .transactions = result.expected_transactions,
        .parent_slot = slot + 1,
        .blockhash = blockhash,
        .previous_blockhash = blockhash,
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

pub const test_shreds_dir = sig.TEST_DATA_DIR ++ "/shreds";

pub fn testShreds(allocator: std.mem.Allocator, comptime filename: []const u8) ![]const Shred {
    const path = comptimePrint("{s}/{s}", .{ test_shreds_dir, filename });
    return loadShredsFromFile(allocator, path);
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
    defer file.close();

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
    for (shreds) |s| try writeChunk(file.writer(), s.payload());
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
///
/// loadEntriesFromFile can read entries produced by this rust function:
/// ```rust
/// fn save_entries_to_file(shreds: &[Entry], path: &str) {
///     let mut file = std::fs::File::create(path).unwrap();
///    for entry in &entries {
///        let payload = bincode::serialize(&entry).unwrap();
///        file.write(&payload.len().to_le_bytes()).unwrap();
///        file.write(&*payload).unwrap();
///    }
/// }
/// ```
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

pub const TestState = struct {
    db: BlockstoreDB,
    registry: sig.prometheus.Registry(.{}),
    lowest_cleanup_slot: sig.sync.RwMux(Slot),
    max_root: std.atomic.Value(Slot),
    allocator: std.mem.Allocator,
    logger: sig.trace.Logger,

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        comptime test_src: std.builtin.SourceLocation,
        logger: sig.trace.Logger,
    ) !*Self {
        const self = try allocator.create(Self);
        self.* = .{
            .allocator = allocator,
            .db = try TestDB.initCustom(allocator, test_src),
            .registry = sig.prometheus.Registry(.{}).init(allocator),
            .lowest_cleanup_slot = sig.sync.RwMux(Slot).init(0),
            .max_root = std.atomic.Value(Slot).init(0),
            .logger = logger,
        };
        return self;
    }

    pub fn shredInserter(self: *Self) !ledger.ShredInserter {
        return ledger.ShredInserter.init(self.allocator, self.logger, &self.registry, self.db);
    }

    pub fn writer(self: *Self) !ledger.LedgerResultWriter {
        return try ledger.LedgerResultWriter.init(
            self.allocator,
            self.logger,
            self.db,
            &self.registry,
            &self.lowest_cleanup_slot,
            &self.max_root,
        );
    }

    pub fn reader(self: *Self) !ledger.BlockstoreReader {
        return try ledger.BlockstoreReader.init(
            self.allocator,
            self.logger,
            self.db,
            &self.registry,
            &self.lowest_cleanup_slot,
            &self.max_root,
        );
    }

    pub fn deinit(self: *Self) void {
        self.db.deinit();
        self.registry.deinit();
        self.allocator.destroy(self);
    }
};

pub const TestDB = struct {
    const dir = sig.TEST_STATE_DIR ++ "/blockstore";

    pub fn init(comptime test_src: std.builtin.SourceLocation) !BlockstoreDB {
        return try initCustom(std.testing.allocator, test_src);
    }

    pub fn reuseBlockstore(comptime test_src: std.builtin.SourceLocation) !BlockstoreDB {
        const path = comptimePrint("{s}/{s}/{s}", .{ dir, test_src.file, test_src.fn_name });
        try std.fs.cwd().makePath(path);
        return try BlockstoreDB.open(std.testing.allocator, .noop, path);
    }

    pub fn initCustom(
        allocator: Allocator,
        comptime test_src: std.builtin.SourceLocation,
    ) !BlockstoreDB {
        const path = comptimePrint("{s}/{s}/{s}", .{ dir, test_src.file, test_src.fn_name });
        try sig.ledger.tests.freshDir(path);
        return try BlockstoreDB.open(allocator, .noop, path);
    }
};

const InsertDataForBlockResult = struct {
    allocator: Allocator,
    slot: Slot,
    entries: []const Entry,
    expected_transactions: []const VersionedTransactionWithStatusMeta,

    pub fn deinit(self: InsertDataForBlockResult) void {
        for (self.entries) |e| e.deinit(self.allocator);
        for (self.expected_transactions) |etx| {
            self.allocator.free(etx.meta.pre_balances);
            self.allocator.free(etx.meta.post_balances);
        }
        self.allocator.free(self.entries);
        self.allocator.free(self.expected_transactions);
    }
};

pub fn insertDataForBlockTest(state: *TestState) !InsertDataForBlockResult {
    const allocator = state.allocator;

    var db = state.db;
    var inserter = try state.shredInserter();
    var writer = try state.writer();

    const slot = 10;

    const prefix = "agave.blockstore.test_get_rooted_block.";
    const entries = try loadEntriesFromFile(
        allocator,
        test_shreds_dir ++ "/" ++ prefix ++ "entries.bin",
    );
    errdefer {
        for (entries) |e| e.deinit(allocator);
        allocator.free(entries);
    }

    const shreds = try testShreds(allocator, prefix ++ "shreds.bin");
    const more_shreds = try testShreds(allocator, prefix ++ "more_shreds.bin");
    const unrooted_shreds = try testShreds(allocator, prefix ++ "unrooted_shreds.bin");
    defer inline for (.{ shreds, more_shreds, unrooted_shreds }) |slice| {
        deinitShreds(allocator, slice);
    };

    var result = try insertShredsForTest(&inserter, shreds);
    result.deinit();
    result = try insertShredsForTest(&inserter, more_shreds);
    result.deinit();
    result = try insertShredsForTest(&inserter, unrooted_shreds);
    result.deinit();

    try writer.setRoots(&.{ slot - 1, slot, slot + 1 });

    const parent_meta = SlotMeta.init(allocator, 0, null);
    try db.put(schema.slot_meta, slot - 1, parent_meta);

    var expected_transactions = std.ArrayList(VersionedTransactionWithStatusMeta).init(allocator);
    for (entries) |entry| {
        for (entry.transactions) |transaction| {
            var pre_balances = std.ArrayList(u64).init(allocator);
            var post_balances = std.ArrayList(u64).init(allocator);
            const num_accounts = transaction.msg.account_keys.len;
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

    return .{
        .allocator = allocator,
        .slot = slot,
        .entries = entries,
        .expected_transactions = try expected_transactions.toOwnedSlice(),
    };
}
