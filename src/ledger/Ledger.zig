const std = @import("std");
const sig = @import("../sig.zig");
const lib = @import("lib.zig");

const Allocator = std.mem.Allocator;
const RwMux = sig.sync.RwMux;
const Slot = sig.core.Slot;

const LedgerDB = lib.db.LedgerDB;

pub const Reader = lib.Reader;
pub const ResultWriter = lib.ResultWriter;
pub const ShredInserter = lib.ShredInserter;

db: LedgerDB,
highest_slot_cleaned: RwMux(Slot),
max_root: std.atomic.Value(u64),

logger: sig.trace.Logger("ledger"),
metrics: ?struct {
    reader: Reader.Metrics,
    rpc: Reader.LedgerRpcApiMetrics,
    scan_and_fix_roots: ResultWriter.ScanAndFixRootsMetrics,
    shred_inserter: ShredInserter.Metrics,
},

const Ledger = @This();

pub fn deinit(self: *Ledger) void {
    self.db.deinit();
}

pub fn init(
    allocator: Allocator,
    logger: sig.trace.Logger("ledger"),
    path: []const u8,
    registry: ?*sig.prometheus.Registry(.{}),
) !Ledger {
    var db = try LedgerDB.open(allocator, .from(logger), path, false);
    errdefer db.deinit();

    return .{
        .db = db,
        .highest_slot_cleaned = RwMux(Slot).init(0),
        .max_root = std.atomic.Value(u64).init(0),
        .logger = logger,
        .metrics = if (registry) |r| .{
            .reader = try r.initStruct(Reader.Metrics),
            .rpc = try r.initStruct(Reader.LedgerRpcApiMetrics),
            .scan_and_fix_roots = try r.initStruct(ResultWriter.ScanAndFixRootsMetrics),
            .shred_inserter = try r.initStruct(ShredInserter.Metrics),
        } else null,
    };
}

pub fn reader(self: *Ledger) Reader {
    return .{
        .ledger = self,
        .logger = .from(self.logger),
        .metrics = if (self.metrics) |m| m.reader else null,
        .rpc_metrics = if (self.metrics) |m| m.rpc else null,
    };
}

pub fn resultWriter(self: *Ledger) ResultWriter {
    return .{
        .ledger = self,
        .logger = .from(self.logger),
        .metrics = if (self.metrics) |m| m.scan_and_fix_roots else null,
    };
}

pub fn shredInserter(self: *Ledger) ShredInserter {
    return .{
        .ledger = self,
        .logger = .from(self.logger),
        .metrics = if (self.metrics) |m| m.shred_inserter else null,
    };
}

test "Ledger doesn't leak" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makeDir("ledger");
    const path = try tmp.dir.realpathAlloc(allocator, "ledger");
    defer allocator.free(path);

    var ledger_state = try Ledger.init(allocator, .FOR_TESTS, path, null);
    defer ledger_state.deinit();
}
