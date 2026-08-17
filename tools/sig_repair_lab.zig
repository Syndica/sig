const std = @import("std");
const sig = @import("sig");

const schema = sig.ledger.schema.schema;
const key_serializer = sig.ledger.database.key_serializer;

const Allocator = std.mem.Allocator;
const ArrayList = std.array_list.Managed;
const AutoHashMap = std.AutoHashMap;
const Slot = sig.core.Slot;
const Ledger = sig.ledger.Ledger;
const ErasureMeta = sig.ledger.meta.ErasureMeta;
const ErasureSetId = sig.ledger.shred.ErasureSetId;
const Index = sig.ledger.meta.Index;
const Shred = sig.ledger.shred.Shred;
const Recovery = sig.ledger.shred_inserter.recovery;

const SAMPLE_LIMIT = 32;

const Args = struct {
    ledger_path: []const u8,
    slot: Slot,
    fec_set: ?u64,
};

const ShredGroup = struct {
    data_indexes: ArrayList(u64),
    code_indexes: ArrayList(u64),

    fn init(allocator: Allocator) ShredGroup {
        return .{
            .data_indexes = ArrayList(u64).init(allocator),
            .code_indexes = ArrayList(u64).init(allocator),
        };
    }

    fn deinit(self: *ShredGroup) void {
        self.data_indexes.deinit();
        self.code_indexes.deinit();
    }
};

const ShredGroups = AutoHashMap(u64, ShredGroup);

pub fn main() !void {
    var gpa_state = std.heap.DebugAllocator(.{}){};
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    const raw_args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, raw_args);

    const args = parseArgs(raw_args) catch |err| {
        std.debug.print(
            "usage: sig-repair-lab --ledger <ledger-path> --slot <slot> [--fec-set <index>]\nerror: {s}\n",
            .{@errorName(err)},
        );
        return err;
    };

    var ledger = try Ledger.initReadOnly(allocator, sig.trace.Logger("ledger").noop, args.ledger_path, null);
    defer ledger.deinit();

    std.debug.print("ledger_path={s}\n", .{args.ledger_path});
    std.debug.print("slot={}\n", .{args.slot});
    std.debug.print("fec_set_filter={?}\n", .{args.fec_set});

    try printSlotMeta(allocator, &ledger, args.slot);

    var maybe_index = try ledger.db.get(allocator, schema.index, args.slot);
    defer if (maybe_index) |*index| index.deinit();

    var fallback_index = Index.init(allocator, args.slot);
    defer fallback_index.deinit();
    const index: *Index = if (maybe_index) |*found| found else &fallback_index;
    std.debug.print("index_present={}\n", .{maybe_index != null});

    var groups = ShredGroups.init(allocator);
    defer deinitGroups(&groups);

    try scanSlotShreds(allocator, &ledger, args.slot, .data, &groups, if (maybe_index == null) index else null);
    try scanSlotShreds(allocator, &ledger, args.slot, .code, &groups, if (maybe_index == null) index else null);
    try addErasureMetaGroups(allocator, &ledger, args.slot, &groups);

    var set_indexes = ArrayList(u64).init(allocator);
    defer set_indexes.deinit();
    var group_iter = groups.keyIterator();
    while (group_iter.next()) |set_index| {
        try set_indexes.append(set_index.*);
    }
    std.mem.sort(u64, set_indexes.items, {}, lessThanU64);

    std.debug.print("fec_set_count={}\n", .{set_indexes.items.len});
    for (set_indexes.items) |set_index| {
        if (args.fec_set) |wanted| {
            if (set_index != wanted) continue;
        }
        try printFecSet(allocator, &ledger, args.slot, set_index, index, groups.getPtr(set_index).?);
    }
}

fn parseArgs(args: []const []const u8) !Args {
    if (args.len == 3) {
        return .{
            .ledger_path = args[1],
            .slot = try std.fmt.parseUnsigned(Slot, args[2], 10),
            .fec_set = null,
        };
    }

    var ledger_path: ?[]const u8 = null;
    var slot: ?Slot = null;
    var fec_set: ?u64 = null;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--ledger")) {
            i += 1;
            if (i >= args.len) return error.MissingLedgerPath;
            ledger_path = args[i];
        } else if (std.mem.eql(u8, args[i], "--slot")) {
            i += 1;
            if (i >= args.len) return error.MissingSlot;
            slot = try std.fmt.parseUnsigned(Slot, args[i], 10);
        } else if (std.mem.eql(u8, args[i], "--fec-set")) {
            i += 1;
            if (i >= args.len) return error.MissingFecSet;
            fec_set = try std.fmt.parseUnsigned(u64, args[i], 10);
        } else {
            return error.UnknownArgument;
        }
    }

    return .{
        .ledger_path = ledger_path orelse return error.MissingLedgerPath,
        .slot = slot orelse return error.MissingSlot,
        .fec_set = fec_set,
    };
}

fn printSlotMeta(allocator: Allocator, ledger: *Ledger, slot: Slot) !void {
    if (try ledger.db.get(allocator, schema.slot_meta, slot)) |meta_value| {
        var meta = meta_value;
        defer meta.deinit();
        std.debug.print(
            "slot_meta=present parent_slot={?} received={} consecutive_received_from_0={} last_index={?} is_full={} entries_unknown=true\n",
            .{
                meta.parent_slot,
                meta.received,
                meta.consecutive_received_from_0,
                meta.last_index,
                meta.isFull(),
            },
        );
    } else {
        std.debug.print("slot_meta=missing\n", .{});
    }
}

fn scanSlotShreds(
    allocator: Allocator,
    ledger: *Ledger,
    slot: Slot,
    comptime shred_type: sig.ledger.shred.ShredType,
    groups: *ShredGroups,
    maybe_fallback_index: ?*Index,
) !void {
    const cf = switch (shred_type) {
        .data => schema.data_shred,
        .code => schema.code_shred,
    };

    var iter = try ledger.db.iterator(cf, .forward, .{ slot, 0 });
    defer iter.deinit();

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

        var shred = try Shred.fromPayload(allocator, payload.data);
        defer shred.deinit();

        const erasure_set_index = switch (shred) {
            .data => |data| data.common.erasure_set_index,
            .code => |code| code.common.erasure_set_index,
        };
        const group = try getOrPutGroup(allocator, groups, erasure_set_index);
        switch (shred_type) {
            .data => {
                try group.data_indexes.append(index);
                if (maybe_fallback_index) |fallback| try fallback.data_index.put(index);
            },
            .code => {
                try group.code_indexes.append(index);
                if (maybe_fallback_index) |fallback| try fallback.code_index.put(index);
            },
        }
    }
}

fn addErasureMetaGroups(
    allocator: Allocator,
    ledger: *Ledger,
    slot: Slot,
    groups: *ShredGroups,
) !void {
    var iter = try ledger.db.iterator(
        schema.erasure_meta,
        .forward,
        ErasureSetId{ .slot = slot, .erasure_set_index = 0 },
    );
    defer iter.deinit();

    while (try iter.nextBytes()) |entry| {
        const key, const value = entry;
        defer key.deinit();
        defer value.deinit();

        const erasure_set_id = try key_serializer.deserialize(
            ErasureSetId,
            allocator,
            key.data,
        );
        if (erasure_set_id.slot != slot) break;
        _ = try getOrPutGroup(allocator, groups, erasure_set_id.erasure_set_index);
    }
}

fn printFecSet(
    allocator: Allocator,
    ledger: *Ledger,
    slot: Slot,
    set_index: u64,
    index: *Index,
    group: *ShredGroup,
) !void {
    std.mem.sort(u64, group.data_indexes.items, {}, lessThanU64);
    std.mem.sort(u64, group.code_indexes.items, {}, lessThanU64);

    const erasure_set_id = ErasureSetId{ .slot = slot, .erasure_set_index = set_index };
    const maybe_erasure_meta = try ledger.db.get(allocator, schema.erasure_meta, erasure_set_id);

    std.debug.print("\nfec_set={}\n", .{set_index});
    if (maybe_erasure_meta) |erasure_meta| {
        const data_start, const data_end = erasure_meta.dataShredsIndices();
        const code_start, const code_end = erasure_meta.codeShredsIndices();
        const data_present = index.data_index.range(data_start, data_end);
        const code_present = index.code_index.range(code_start, code_end);
        const data_missing_count = data_end - data_start - data_present.len;
        const code_missing_count = code_end - code_start - code_present.len;

        std.debug.print(
            "  erasure_meta=present data_range={}..{} code_range={}..{} num_data={} num_code={} first_code_index={} first_received_code_index={}\n",
            .{
                data_start,
                data_end - 1,
                code_start,
                code_end - 1,
                erasure_meta.config.num_data,
                erasure_meta.config.num_code,
                erasure_meta.first_code_index,
                erasure_meta.first_received_code_index,
            },
        );
        std.debug.print("  data_present_count={} data_present_sample=", .{data_present.len});
        printSample(data_present);
        std.debug.print("  data_missing_count={} data_missing_sample=", .{data_missing_count});
        printMissingSample(data_present, data_start, data_end);
        std.debug.print("  code_present_count={} code_present_sample=", .{code_present.len});
        printSample(code_present);
        std.debug.print("  code_missing_count={} code_missing_sample=", .{code_missing_count});
        printMissingSample(code_present, code_start, code_end);

        switch (erasure_meta.status(index)) {
            .data_full => {
                std.debug.print(
                    "  recoverable_now=false recovery_status=data_full dry_run_recovery_attempted=false last_recovery_result=not_needed\n",
                    .{},
                );
            },
            .can_recover => {
                try printFecShardLengths(allocator, ledger, slot, &erasure_meta);
                try printDryRunRecovery(allocator, ledger, slot, &erasure_meta);
            },
            .still_need => |needed| {
                std.debug.print(
                    "  recoverable_now=false recovery_status=still_need needed_shards={} dry_run_recovery_attempted=false last_recovery_result=not_enough_shards\n",
                    .{needed},
                );
            },
        }
    } else {
        std.debug.print("  erasure_meta=missing\n", .{});
        std.debug.print("  data_present_count={} data_present_sample=", .{group.data_indexes.items.len});
        printSample(group.data_indexes.items);
        std.debug.print("  code_present_count={} code_present_sample=", .{group.code_indexes.items.len});
        printSample(group.code_indexes.items);
        std.debug.print(
            "  recoverable_now=false recovery_status=no_erasure_meta dry_run_recovery_attempted=false last_recovery_result=missing_fec_config\n",
            .{},
        );
    }
}

fn printFecShardLengths(
    allocator: Allocator,
    ledger: *Ledger,
    slot: Slot,
    erasure_meta: *const ErasureMeta,
) !void {
    var data_payload_min: usize = std.math.maxInt(usize);
    var data_payload_max: usize = 0;
    var data_shard_min: usize = std.math.maxInt(usize);
    var data_shard_max: usize = 0;
    var data_count: usize = 0;
    const data_start, const data_end = erasure_meta.dataShredsIndices();
    for (data_start..data_end) |i| {
        if (try loadShred(allocator, ledger, .data, slot, i)) |shred| {
            defer shred.deinit();
            const shard = try shred.erasureShardAsSlice();
            data_payload_min = @min(data_payload_min, shred.payload().len);
            data_payload_max = @max(data_payload_max, shred.payload().len);
            data_shard_min = @min(data_shard_min, shard.len);
            data_shard_max = @max(data_shard_max, shard.len);
            data_count += 1;
        }
    }

    var code_payload_min: usize = std.math.maxInt(usize);
    var code_payload_max: usize = 0;
    var code_shard_min: usize = std.math.maxInt(usize);
    var code_shard_max: usize = 0;
    var code_count: usize = 0;
    const code_start, const code_end = erasure_meta.codeShredsIndices();
    for (code_start..code_end) |i| {
        if (try loadShred(allocator, ledger, .code, slot, i)) |shred| {
            defer shred.deinit();
            const shard = try shred.erasureShardAsSlice();
            code_payload_min = @min(code_payload_min, shred.payload().len);
            code_payload_max = @max(code_payload_max, shred.payload().len);
            code_shard_min = @min(code_shard_min, shard.len);
            code_shard_max = @max(code_shard_max, shard.len);
            code_count += 1;
        }
    }

    std.debug.print(
        "  shard_lengths data_count={} data_payload={}..{} data_erasure={}..{} code_count={} code_payload={}..{} code_erasure={}..{}\n",
        .{
            data_count,
            if (data_count == 0) 0 else data_payload_min,
            data_payload_max,
            if (data_count == 0) 0 else data_shard_min,
            data_shard_max,
            code_count,
            if (code_count == 0) 0 else code_payload_min,
            code_payload_max,
            if (code_count == 0) 0 else code_shard_min,
            code_shard_max,
        },
    );
}

fn printDryRunRecovery(
    allocator: Allocator,
    ledger: *Ledger,
    slot: Slot,
    erasure_meta: *const ErasureMeta,
) !void {
    var available_shreds = ArrayList(Shred).init(allocator);
    defer {
        for (available_shreds.items) |shred| shred.deinit();
        available_shreds.deinit();
    }

    const data_start, const data_end = erasure_meta.dataShredsIndices();
    for (data_start..data_end) |i| {
        if (try loadShred(allocator, ledger, .data, slot, i)) |shred| {
            try available_shreds.append(shred);
        }
    }

    const code_start, const code_end = erasure_meta.codeShredsIndices();
    for (code_start..code_end) |i| {
        if (try loadShred(allocator, ledger, .code, slot, i)) |shred| {
            try available_shreds.append(shred);
        }
    }

    var cache = try Recovery.ReedSolomonCache.init(allocator);
    defer cache.deinit();

    if (Recovery.recover(allocator, available_shreds.items, &cache)) |recovered_shreds| {
        var recovered = recovered_shreds;
        defer {
            for (recovered.items) |shred| shred.deinit();
            recovered.deinit();
        }
        std.debug.print(
            "  recoverable_now=true recovery_status=can_recover dry_run_recovery_attempted=true last_recovery_result=ok recovered_shreds={}\n",
            .{recovered.items.len},
        );
    } else |err| {
        std.debug.print(
            "  recoverable_now=true recovery_status=can_recover dry_run_recovery_attempted=true last_recovery_result=decode_failed error={s}\n",
            .{@errorName(err)},
        );
    }
}

fn loadShred(
    allocator: Allocator,
    ledger: *Ledger,
    comptime shred_type: sig.ledger.shred.ShredType,
    slot: Slot,
    index: u64,
) !?Shred {
    const cf = switch (shred_type) {
        .data => schema.data_shred,
        .code => schema.code_shred,
    };
    const bytes = try ledger.db.getBytes(cf, .{ slot, index }) orelse return null;
    defer bytes.deinit();
    return try Shred.fromPayload(allocator, bytes.data);
}

fn getOrPutGroup(
    allocator: Allocator,
    groups: *ShredGroups,
    erasure_set_index: u64,
) !*ShredGroup {
    const gop = try groups.getOrPut(erasure_set_index);
    if (!gop.found_existing) {
        gop.value_ptr.* = ShredGroup.init(allocator);
    }
    return gop.value_ptr;
}

fn deinitGroups(groups: *ShredGroups) void {
    var iter = groups.valueIterator();
    while (iter.next()) |group| {
        group.deinit();
    }
    groups.deinit();
}

fn printSample(items: []const u64) void {
    std.debug.print("[", .{});
    const len = @min(items.len, SAMPLE_LIMIT);
    for (items[0..len], 0..) |item, i| {
        if (i != 0) std.debug.print(", ", .{});
        std.debug.print("{}", .{item});
    }
    if (items.len > len) std.debug.print(", ...", .{});
    std.debug.print("]\n", .{});
}

fn printMissingSample(present: []const u64, start: u64, end: u64) void {
    std.debug.print("[", .{});
    var printed: usize = 0;
    var present_index: usize = 0;
    var candidate = start;
    while (candidate < end and printed < SAMPLE_LIMIT) : (candidate += 1) {
        while (present_index < present.len and present[present_index] < candidate) {
            present_index += 1;
        }
        if (present_index < present.len and present[present_index] == candidate) continue;
        if (printed != 0) std.debug.print(", ", .{});
        std.debug.print("{}", .{candidate});
        printed += 1;
    }
    if (end - start > present.len + printed) std.debug.print(", ...", .{});
    std.debug.print("]\n", .{});
}

fn lessThanU64(_: void, a: u64, b: u64) bool {
    return a < b;
}
