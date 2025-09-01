pub const cleanup_service = @import("cleanup_service.zig");
pub const database = @import("database/lib.zig");
pub const db = @import("db.zig");
pub const fuzz_ledger = @import("fuzz.zig");
pub const meta = @import("meta.zig");
pub const reader = @import("reader.zig");
pub const reed_solomon = @import("reed_solomon.zig");
pub const result_writer = @import("result_writer.zig");
pub const schema = @import("schema.zig");
pub const shred = @import("shred.zig");
pub const shred_inserter = @import("shred_inserter/lib.zig");
pub const shredder = @import("shredder.zig");
pub const tests = @import("tests.zig");
pub const transaction_status = @import("transaction_status.zig");

pub const LedgerDB = db.LedgerDB;
pub const LedgerReader = reader.LedgerReader;
pub const LedgerResultWriter = result_writer.LedgerResultWriter;
pub const ShredInserter = shred_inserter.ShredInserter;

/// Helper for initializing all the ledger components
pub const UnifiedLedger = struct {
    db: *LedgerDB,
    reader: *LedgerReader,
    result_writer: *LedgerResultWriter,
    cleanup_service_handle: std.Thread,
    exit: *std.atomic.Value(bool),

    const std = @import("std");
    const sig = @import("../sig.zig");

    pub fn deinit(self: UnifiedLedger, allocator: std.mem.Allocator) void {
        self.exit.store(true, .monotonic);
        self.db.deinit();
        allocator.destroy(self.reader.lowest_cleanup_slot);
        allocator.destroy(self.reader.max_root);
        allocator.destroy(self.reader);
        allocator.destroy(self.result_writer);
        allocator.destroy(self.db);
    }

    pub fn init(
        allocator: std.mem.Allocator,
        logger: sig.trace.Logger("ledger"),
        path: []const u8,
        metrics_registry: *sig.prometheus.Registry(.{}),
        exit: *std.atomic.Value(bool),
        max_shreds: u64,
    ) !UnifiedLedger {
        const ledger_db = try allocator.create(LedgerDB);
        errdefer allocator.destroy(ledger_db);
        ledger_db.* = try LedgerDB.open(allocator, .from(logger), path);
        errdefer ledger_db.deinit();

        const lowest_cleanup_slot = try allocator.create(sig.sync.RwMux(sig.core.Slot));
        lowest_cleanup_slot.* = sig.sync.RwMux(sig.core.Slot).init(0);
        errdefer allocator.destroy(lowest_cleanup_slot);

        const max_root = try allocator.create(std.atomic.Value(sig.core.Slot));
        max_root.* = std.atomic.Value(sig.core.Slot).init(0);
        errdefer allocator.destroy(max_root);

        const ledger_reader = try allocator.create(LedgerReader);
        errdefer allocator.destroy(ledger_reader);
        ledger_reader.* = try LedgerReader.init(
            allocator,
            .from(logger),
            ledger_db.*,
            metrics_registry,
            lowest_cleanup_slot,
            max_root,
        );

        const ledger_result_writer = try allocator.create(LedgerResultWriter);
        errdefer allocator.destroy(ledger_result_writer);
        ledger_result_writer.* = try LedgerResultWriter.init(
            allocator,
            .from(logger),
            ledger_db.*,
            metrics_registry,
            lowest_cleanup_slot,
            max_root,
        );

        const cleanup_service_handle = try std.Thread.spawn(.{}, cleanup_service.run, .{
            cleanup_service.Logger.from(logger),
            ledger_reader,
            ledger_db,
            lowest_cleanup_slot,
            max_shreds,
            exit,
        });

        return .{
            .db = ledger_db,
            .reader = ledger_reader,
            .result_writer = ledger_result_writer,
            .cleanup_service_handle = cleanup_service_handle,
            .exit = exit,
        };
    }
};

test "UnifiedLedger doesn't leak" {
    const std = UnifiedLedger.std;
    const sig = UnifiedLedger.sig;

    const allocator = std.testing.allocator;
    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();
    var exit = std.atomic.Value(bool).init(false);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makeDir("ledger");
    const path = try tmp.dir.realpathAlloc(allocator, "ledger");
    defer allocator.free(path);

    const ledger = try UnifiedLedger.init(allocator, .FOR_TESTS, path, &registry, &exit, 1_000);
    ledger.deinit(allocator);
}
