const std = @import("std");
const sig = @import("sig");

const schema = sig.ledger.schema.schema;
const key_serializer = sig.ledger.database.key_serializer;

const Slot = sig.core.Slot;
const Ledger = sig.ledger.Ledger;
const Shred = sig.ledger.shred.Shred;

pub fn main() !void {
    var gpa_state = std.heap.DebugAllocator(.{}){};
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 4) {
        std.debug.print(
            "usage: ledger-inspect <ledger-path> <start-slot> <end-slot>\n",
            .{},
        );
        return error.InvalidArgs;
    }

    const ledger_path = args[1];
    const start_slot = try std.fmt.parseUnsigned(Slot, args[2], 10);
    const end_slot = try std.fmt.parseUnsigned(Slot, args[3], 10);

    var ledger = try Ledger.init(allocator, sig.trace.Logger("ledger").noop, ledger_path, null);
    defer ledger.deinit();

    std.debug.print("ledger_path={s}\n", .{ledger_path});
    std.debug.print("slot_range={}..{}\n", .{ start_slot, end_slot });

    var slot: Slot = start_slot;
    while (slot <= end_slot) : (slot += 1) {
        try inspectSlot(allocator, &ledger, slot);
    }
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

    const code_stats = try countShreds(allocator, ledger, schema.code_shred, slot);
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

const ShredStats = struct {
    count: usize = 0,
    first_index: ?u64 = null,
    last_index: ?u64 = null,
    has_zero: bool = false,
    first_missing: ?u64 = null,
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
        expected = index + 1;
    }
    return stats;
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
