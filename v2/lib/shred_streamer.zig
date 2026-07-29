const std = @import("std");

// The `lib/shred_streamer/` directory is a separate module (`shred_stream_mod`)
// with its own test runner. Its tests are not included here to avoid
// double-inclusion. See v2/build.zig where `shred_stream_mod` is created.
comptime {
    if (@import("builtin").is_test) {
        // lint: skip shred_streamer/lib.zig
        // lint: skip shred_streamer/config.zig
        // lint: skip shred_streamer/agave_blockstore.zig
        // lint: skip shred_streamer/plan.zig
        // lint: skip shred_streamer/stream.zig
    }
}

/// Shared-memory configuration for the shred_streamer service.
///
/// This is a strongly-typed extern struct that lives in a shared memory region.
/// The topology launcher parses CLI args, builds a streaming Config, and writes
/// the fields directly into this struct. The service reads them without any
/// string parsing.
pub const Config = extern struct {
    ledger_len: u16,
    ledger_data: [max_path_len]u8,

    start_slot: u64,
    end_slot: u64,
    has_start_slot: bool,
    has_end_slot: bool,

    rate_hz: f64,
    has_rate_hz: bool,

    test_mode: TestMode,
    seed: u64,
    has_seed: bool,

    selected_count: u32,
    shred_kind: ShredKindFilter,
    plan_limit: u32,
    corrupt_bytes: u32,
    dry_run: bool,

    pub const max_path_len = 4096;

    // NOTE: The TestMode and ShredKindFilter enums here must match the ones in
    // v2/lib/shred_streamer/config.zig (shred_stream module) by ordinal.
    // The service converts between them via @enumFromInt(@intFromEnum(...)).
    // Field order MUST match config.TestMode / config.ShredKindFilter.

    pub const TestMode = enum(u8) {
        linear = 0,
        reverse = 1,
        shuffle_global = 2,
        shuffle_slot = 3,
        drop = 4,
        late = 5,
        duplicate = 6,
        corrupt = 7,
    };

    pub const ShredKindFilter = enum(u8) {
        any = 0,
        data = 1,
        code = 2,
    };

    pub fn getLedger(self: *const Config) []const u8 {
        return self.ledger_data[0..self.ledger_len];
    }

    /// Populate from strongly-typed fields. Called by the topology launcher
    /// after parsing CLI args.
    pub fn populate(
        self: *Config,
        ledger: []const u8,
        start_slot: ?u64,
        end_slot: ?u64,
        rate_hz: ?f64,
        test_mode: TestMode,
        seed: ?u64,
        selected_count: u32,
        shred_kind: ShredKindFilter,
        plan_limit: u32,
        corrupt_bytes: u32,
        dry_run: bool,
    ) error{LedgerPathTooLong}!void {
        if (ledger.len > max_path_len) return error.LedgerPathTooLong;
        self.ledger_len = @intCast(ledger.len);
        @memcpy(self.ledger_data[0..ledger.len], ledger);

        self.has_start_slot = start_slot != null;
        self.start_slot = start_slot orelse 0;
        self.has_end_slot = end_slot != null;
        self.end_slot = end_slot orelse 0;

        self.has_rate_hz = rate_hz != null;
        self.rate_hz = rate_hz orelse 0;

        self.test_mode = test_mode;
        self.has_seed = seed != null;
        self.seed = seed orelse 0;

        self.selected_count = selected_count;
        self.shred_kind = shred_kind;
        self.plan_limit = plan_limit;
        self.corrupt_bytes = corrupt_bytes;
        self.dry_run = dry_run;
    }
};

test "Config populate and read back" {
    var cfg: Config = undefined;
    try cfg.populate(
        "/path/to/ledger",
        100,
        200,
        null,
        .linear,
        null,
        1,
        .any,
        20,
        1,
        false,
    );
    try std.testing.expectEqualStrings("/path/to/ledger", cfg.getLedger());
    try std.testing.expect(cfg.has_start_slot);
    try std.testing.expectEqual(@as(u64, 100), cfg.start_slot);
    try std.testing.expect(cfg.has_end_slot);
    try std.testing.expectEqual(@as(u64, 200), cfg.end_slot);
    try std.testing.expect(!cfg.has_rate_hz);
    try std.testing.expectEqual(Config.TestMode.linear, cfg.test_mode);
    try std.testing.expect(!cfg.has_seed);
    try std.testing.expect(!cfg.dry_run);
}
