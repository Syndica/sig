const std = @import("std");
const sig = @import("sig");

const schema = sig.ledger.schema.schema;
const key_serializer = sig.ledger.database.key_serializer;

const Slot = sig.core.Slot;
const Ledger = sig.ledger.Ledger;
const Shred = sig.ledger.shred.Shred;

const MISSING_DETAIL_LIMIT = 256;
const INVALID_TX_DETAIL_LIMIT = 64;
const SUMMARY_FORMAT_VERSION = "ledger-inspect-summary-v1";

const InspectMode = enum {
    full,
    summary,
    tx_check,
};

pub fn main() !void {
    var gpa_state = std.heap.DebugAllocator(.{}){};
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len > 1 and std.mem.eql(u8, args[1], "--format-version")) {
        std.debug.print("{s}\n", .{SUMMARY_FORMAT_VERSION});
        return;
    }

    const mode: InspectMode = if (args.len > 1 and std.mem.eql(u8, args[1], "--summary"))
        .summary
    else if (args.len > 1 and std.mem.eql(u8, args[1], "--tx-check"))
        .tx_check
    else
        .full;
    const first_positional_arg: usize = if (mode == .full) 1 else 2;

    if (args.len < first_positional_arg + 3) {
        std.debug.print(
            "usage: ledger-inspect [--summary|--tx-check] <ledger-path> <start-slot> <end-slot>\n",
            .{},
        );
        return;
    }

    const ledger_path = args[first_positional_arg];
    const start_slot = try std.fmt.parseUnsigned(Slot, args[first_positional_arg + 1], 10);
    const end_slot = try std.fmt.parseUnsigned(Slot, args[first_positional_arg + 2], 10);

    var ledger = try Ledger.initReadOnly(allocator, sig.trace.Logger("ledger").noop, ledger_path, null);
    defer ledger.deinit();

    std.debug.print("ledger_path={s}\n", .{ledger_path});
    std.debug.print("slot_range={}..{}\n", .{ start_slot, end_slot });

    var slot: Slot = start_slot;
    while (slot <= end_slot) : (slot += 1) {
        switch (mode) {
            .summary => try inspectSlotSummary(allocator, &ledger, slot),
            .tx_check => try inspectSlotTransactions(allocator, &ledger, slot),
            .full => try inspectSlot(allocator, &ledger, slot),
        }
    }
}

fn inspectSlotSummary(allocator: std.mem.Allocator, ledger: *Ledger, slot: Slot) !void {
    var meta_present = false;
    var parent_slot: ?Slot = null;
    var is_full = false;
    var is_connected = false;
    var meta_received: ?u64 = null;
    var meta_last_index: ?u64 = null;

    if (try ledger.db.get(allocator, schema.slot_meta, slot)) |meta_value| {
        var meta = meta_value;
        defer meta.deinit();
        meta_present = true;
        parent_slot = meta.parent_slot;
        is_full = meta.isFull();
        is_connected = meta.isConnected();
        meta_received = meta.received;
        meta_last_index = meta.last_index;
    }

    const data_stats = try countShreds(allocator, ledger, schema.data_shred, slot);
    defer data_stats.deinit(allocator);

    const code_stats = try countShreds(allocator, ledger, schema.code_shred, slot);
    defer code_stats.deinit(allocator);

    const entries, const tx_count = try entrySummary(allocator, ledger, slot);

    std.debug.print(
        "summary slot={} meta={s} parent_slot={?} is_full={} is_connected={} meta_received={?} meta_last_index={?} entries={} tx_count={} data_shreds={} code_shreds={} data_first_missing={?}\n",
        .{
            slot,
            if (meta_present) "present" else "missing",
            parent_slot,
            is_full,
            is_connected,
            meta_received,
            meta_last_index,
            entries,
            tx_count,
            data_stats.count,
            code_stats.count,
            data_stats.first_missing,
        },
    );
}

fn entrySummary(
    allocator: std.mem.Allocator,
    ledger: *Ledger,
    slot: Slot,
) !struct { usize, usize } {
    const entries, _, _ = ledger.reader().getSlotEntriesWithShredInfo(
        allocator,
        slot,
        0,
        false,
    ) catch return .{ 0, 0 };
    defer {
        for (entries) |entry| entry.deinit(allocator);
        allocator.free(entries);
    }
    var tx_count: usize = 0;
    for (entries) |entry| tx_count += entry.transactions.len;
    return .{ entries.len, tx_count };
}

fn inspectSlot(allocator: std.mem.Allocator, ledger: *Ledger, slot: Slot) !void {
    std.debug.print("\nslot={}\n", .{slot});

    if (try ledger.db.get(allocator, schema.slot_meta, slot)) |meta_value| {
        var meta = meta_value;
        defer meta.deinit();

        std.debug.print("  meta=present\n", .{});
        std.debug.print("  parent_slot={?}\n", .{meta.parent_slot});
        std.debug.print("  child_slots={any}\n", .{meta.child_slots.items});
        std.debug.print("  consecutive_received_from_0={}\n", .{meta.consecutive_received_from_0});
        std.debug.print("  received={}\n", .{meta.received});
        std.debug.print("  last_index={?}\n", .{meta.last_index});
        std.debug.print("  is_full={}\n", .{meta.isFull()});
        std.debug.print("  is_connected={}\n", .{meta.isConnected()});
        std.debug.print("  is_parent_connected={}\n", .{meta.isParentConnected()});
        std.debug.print("  completed_data_indexes_count={}\n", .{meta.completed_data_indexes.count()});
        std.debug.print("  completed_data_indexes_sample=", .{});
        printSample(u32, meta.completed_data_indexes.items());

        const completed_ranges = try completedRanges(
            allocator,
            meta.completed_data_indexes.items(),
            @intCast(meta.consecutive_received_from_0),
        );
        defer allocator.free(completed_ranges);
        std.debug.print("  completed_ranges={any}\n", .{completed_ranges});
    } else {
        std.debug.print("  meta=missing\n", .{});
    }

    const data_stats = try countShreds(allocator, ledger, schema.data_shred, slot);
    defer data_stats.deinit(allocator);
    std.debug.print(
        "  data_shreds count={} first={?} last={?} has_0={} first_missing={?}\n",
        .{
            data_stats.count,
            data_stats.first_index,
            data_stats.last_index,
            data_stats.has_zero,
            data_stats.first_missing,
        },
    );
    printMissingStats("data", &data_stats);

    const code_stats = try countShreds(allocator, ledger, schema.code_shred, slot);
    defer code_stats.deinit(allocator);
    std.debug.print(
        "  code_shreds count={} first={?} last={?} has_0={} first_missing={?}\n",
        .{
            code_stats.count,
            code_stats.first_index,
            code_stats.last_index,
            code_stats.has_zero,
            code_stats.first_missing,
        },
    );
    printMissingStats("code", &code_stats);

    try printDataShredFlags(allocator, ledger, slot, 0);
    if (data_stats.last_index) |last| try printDataShredFlags(allocator, ledger, slot, last);

    const entries, const num_shreds, const slot_is_full =
        try ledger.reader().getSlotEntriesWithShredInfo(allocator, slot, 0, false);
    defer {
        for (entries) |entry| entry.deinit(allocator);
        allocator.free(entries);
    }
    var tx_count: usize = 0;
    for (entries) |entry| tx_count += entry.transactions.len;
    std.debug.print(
        "  entries count={} tx_count={} num_shreds={} slot_is_full={}\n",
        .{ entries.len, tx_count, num_shreds, slot_is_full },
    );
}

fn inspectSlotTransactions(allocator: std.mem.Allocator, ledger: *Ledger, slot: Slot) !void {
    const entries, const num_shreds, const slot_is_full =
        ledger.reader().getSlotEntriesWithShredInfo(allocator, slot, 0, false) catch |err| {
            std.debug.print(
                "tx_check slot={} error={s}\n",
                .{ slot, @errorName(err) },
            );
            return;
        };
    defer {
        for (entries) |entry| entry.deinit(allocator);
        allocator.free(entries);
    }

    var total_tx: usize = 0;
    var invalid_tx: usize = 0;
    var program_oob_tx: usize = 0;
    var account_oob_tx: usize = 0;
    var detail_count: usize = 0;

    for (entries, 0..) |entry, entry_index| {
        if (entry.isTick()) continue;

        for (entry.transactions, 0..) |txn, tx_index| {
            total_tx += 1;

            const structural = transactionStructuralFlags(txn);
            if (structural.program_oob) program_oob_tx += 1;
            if (structural.account_oob) account_oob_tx += 1;

            txn.validate() catch |err| {
                invalid_tx += 1;
                if (detail_count < INVALID_TX_DETAIL_LIMIT) {
                    detail_count += 1;
                    printInvalidTransaction(
                        slot,
                        entry_index,
                        tx_index,
                        txn,
                        err,
                        structural,
                    );
                }
            };
        }
    }

    std.debug.print(
        "tx_check slot={} entries={} num_shreds={} slot_is_full={} total_tx={} invalid_tx={} program_oob_tx={} account_oob_tx={} detail_limit={} detail_truncated={}\n",
        .{
            slot,
            entries.len,
            num_shreds,
            slot_is_full,
            total_tx,
            invalid_tx,
            program_oob_tx,
            account_oob_tx,
            INVALID_TX_DETAIL_LIMIT,
            invalid_tx > INVALID_TX_DETAIL_LIMIT,
        },
    );
}

const TransactionStructuralFlags = struct {
    program_oob: bool = false,
    account_oob: bool = false,
    lookup_key_count: usize = 0,
    max_account_index: ?usize = null,
};

fn transactionStructuralFlags(txn: sig.core.Transaction) TransactionStructuralFlags {
    var flags: TransactionStructuralFlags = .{};

    for (txn.msg.address_lookups) |lookup| {
        flags.lookup_key_count += lookup.writable_indexes.len + lookup.readonly_indexes.len;
    }

    const max_program_index = if (txn.msg.account_keys.len == 0)
        null
    else
        txn.msg.account_keys.len - 1;
    flags.max_account_index = if (txn.msg.account_keys.len + flags.lookup_key_count == 0)
        null
    else
        txn.msg.account_keys.len + flags.lookup_key_count - 1;

    for (txn.msg.instructions) |instr| {
        if (max_program_index) |max_index| {
            flags.program_oob = flags.program_oob or instr.program_index > max_index;
        } else {
            flags.program_oob = true;
        }

        for (instr.account_indexes) |account_index| {
            if (flags.max_account_index) |max_index| {
                flags.account_oob = flags.account_oob or account_index > max_index;
            } else {
                flags.account_oob = true;
            }
        }
    }

    return flags;
}

fn printInvalidTransaction(
    slot: Slot,
    entry_index: usize,
    tx_index: usize,
    txn: sig.core.Transaction,
    err: anyerror,
    structural: TransactionStructuralFlags,
) void {
    std.debug.print(
        "invalid_tx slot={} entry={} tx={} err={s} version={s} signatures={} static_keys={} lookup_tables={} lookup_keys={} instructions={} max_account_index={?} program_oob={} account_oob={}\n",
        .{
            slot,
            entry_index,
            tx_index,
            @errorName(err),
            @tagName(txn.version),
            txn.signatures.len,
            txn.msg.account_keys.len,
            txn.msg.address_lookups.len,
            structural.lookup_key_count,
            txn.msg.instructions.len,
            structural.max_account_index,
            structural.program_oob,
            structural.account_oob,
        },
    );

    for (txn.msg.instructions, 0..) |instr, ix_index| {
        const max_ix_account = maxAccountIndex(instr.account_indexes);
        std.debug.print(
            "  instruction ix={} program_index={} account_count={} max_account_index={?}\n",
            .{ ix_index, instr.program_index, instr.account_indexes.len, max_ix_account },
        );
    }

    for (txn.msg.address_lookups, 0..) |lookup, lookup_index| {
        std.debug.print(
            "  lookup table={} writable_count={} writable_max={?} readonly_count={} readonly_max={?}\n",
            .{
                lookup_index,
                lookup.writable_indexes.len,
                maxAccountIndex(lookup.writable_indexes),
                lookup.readonly_indexes.len,
                maxAccountIndex(lookup.readonly_indexes),
            },
        );
    }
}

fn maxAccountIndex(indexes: []const u8) ?u8 {
    if (indexes.len == 0) return null;
    var max_index: u8 = indexes[0];
    for (indexes[1..]) |index| max_index = @max(max_index, index);
    return max_index;
}

const ShredStats = struct {
    count: usize = 0,
    first_index: ?u64 = null,
    last_index: ?u64 = null,
    has_zero: bool = false,
    first_missing: ?u64 = null,
    missing_count: usize = 0,
    missing_windows: std.ArrayListUnmanaged(MissingWindow) = .empty,
    missing_indexes: std.ArrayListUnmanaged(u64) = .empty,

    fn deinit(self: *const ShredStats, allocator: std.mem.Allocator) void {
        var windows = self.missing_windows;
        var indexes = self.missing_indexes;
        windows.deinit(allocator);
        indexes.deinit(allocator);
    }
};

const MissingWindow = struct {
    start: u64,
    end: u64,
};

fn countShreds(
    allocator: std.mem.Allocator,
    ledger: *Ledger,
    comptime cf: anytype,
    slot: Slot,
) !ShredStats {
    var iter = try ledger.db.iterator(cf, .forward, .{ slot, 0 });
    defer iter.deinit();

    var stats: ShredStats = .{};
    var expected: u64 = 0;
    while (try iter.nextBytes()) |entry| {
        const key, const payload = entry;
        defer key.deinit();
        defer payload.deinit();

        const found_slot, const index = try key_serializer.deserialize(
            cf.Key,
            allocator,
            key.data,
        );
        if (found_slot != slot) break;

        stats.count += 1;
        stats.first_index = stats.first_index orelse index;
        stats.last_index = index;
        if (index == 0) stats.has_zero = true;
        if (stats.first_missing == null and index != expected) {
            stats.first_missing = expected;
        }
        if (index > expected) {
            try recordMissingRange(allocator, &stats, expected, index);
        }
        expected = index + 1;
    }
    return stats;
}

fn recordMissingRange(
    allocator: std.mem.Allocator,
    stats: *ShredStats,
    start: u64,
    end: u64,
) !void {
    if (start >= end) return;

    stats.missing_count += @intCast(end - start);
    if (stats.missing_windows.items.len < MISSING_DETAIL_LIMIT) {
        try stats.missing_windows.append(allocator, .{ .start = start, .end = end });
    }

    var index = start;
    while (index < end and stats.missing_indexes.items.len < MISSING_DETAIL_LIMIT) : (index += 1) {
        try stats.missing_indexes.append(allocator, index);
    }
}

fn printMissingStats(label: []const u8, stats: *const ShredStats) void {
    std.debug.print(
        "  {s}_missing_bounded count={} detail_limit={} windows_truncated={} indexes_truncated={} windows=",
        .{
            label,
            stats.missing_count,
            MISSING_DETAIL_LIMIT,
            stats.missing_windows.items.len >= MISSING_DETAIL_LIMIT and stats.missing_count > MISSING_DETAIL_LIMIT,
            stats.missing_indexes.items.len >= MISSING_DETAIL_LIMIT and stats.missing_count > MISSING_DETAIL_LIMIT,
        },
    );
    printMissingWindows(stats.missing_windows.items);
    std.debug.print("  {s}_missing_indexes_sample=", .{label});
    printSample(u64, stats.missing_indexes.items);
}

fn printMissingWindows(items: []const MissingWindow) void {
    std.debug.print("[", .{});
    for (items, 0..) |item, i| {
        if (i != 0) std.debug.print(", ", .{});
        if (item.end == item.start + 1) {
            std.debug.print("{}", .{item.start});
        } else {
            std.debug.print("{}..{}", .{ item.start, item.end - 1 });
        }
    }
    std.debug.print("]\n", .{});
}

fn printDataShredFlags(
    allocator: std.mem.Allocator,
    ledger: *Ledger,
    slot: Slot,
    index: u64,
) !void {
    const bytes = try ledger.db.getBytes(schema.data_shred, .{ slot, index }) orelse {
        std.debug.print("  data_shred[{}]=missing\n", .{index});
        return;
    };
    defer bytes.deinit();

    var shred = try Shred.fromPayload(allocator, bytes.data);
    defer shred.deinit();

    switch (shred) {
        .data => |data| {
            std.debug.print(
                "  data_shred[{}] parent={} erasure_set={} data_complete={} last_in_slot={} reference_tick={}\n",
                .{
                    index,
                    try data.parent(),
                    data.common.erasure_set_index,
                    data.dataComplete(),
                    data.isLastInSlot(),
                    data.referenceTick(),
                },
            );
        },
        .code => unreachable,
    }
}

fn completedRanges(
    allocator: std.mem.Allocator,
    completed_indexes: []const u32,
    consumed: u32,
) ![]const struct { u32, u32 } {
    var ranges = std.ArrayListUnmanaged(struct { u32, u32 }).empty;
    var begin: u32 = 0;
    for (completed_indexes) |index| {
        if (index >= consumed) break;
        try ranges.append(allocator, .{ begin, index + 1 });
        begin = index + 1;
    }
    return ranges.toOwnedSlice(allocator);
}

fn printSample(comptime T: type, items: []const T) void {
    std.debug.print("[", .{});
    const max_head = @min(items.len, 12);
    for (items[0..max_head], 0..) |item, i| {
        if (i != 0) std.debug.print(", ", .{});
        std.debug.print("{}", .{item});
    }
    if (items.len > max_head) {
        std.debug.print(", ...", .{});
        const tail_start = if (items.len > 5) items.len - 5 else max_head;
        for (items[tail_start..]) |item| std.debug.print(", {}", .{item});
    }
    std.debug.print("]\n", .{});
}
