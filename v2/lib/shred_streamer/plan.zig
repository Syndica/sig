//! Plan builders for selected-shred test modes (drop, late, duplicate, corrupt).

const std = @import("std");
const rocks = @import("rocksdb");
const config = @import("config.zig");
const blockstore_mod = @import("agave_blockstore.zig");

const Allocator = std.mem.Allocator;
const Slot = config.Slot;
const ShredKind = config.ShredKind;
const ShredRef = config.ShredRef;
const RefSchedule = config.RefSchedule;
const SelectedShredPlan = config.SelectedShredPlan;
const Config = config.Config;

const AgaveBlockstore = blockstore_mod.AgaveBlockstore;

const agave_cf_meta = config.agave_cf_meta;
const parseSlotKey = config.parseSlotKey;
const writeSlotKey = config.writeSlotKey;
const writeShredKey = config.writeShredKey;
const parseShredKey = config.parseShredKey;
const countEligibleShreds = config.countEligibleShreds;
const chooseSelectedRefIndices = config.chooseSelectedRefIndices;

pub fn buildSelectedShredPlan(
    allocator: Allocator,
    stdout: *std.Io.Writer,
    blockstore: *const AgaveBlockstore,
    cfg: Config,
    cancel: anytype,
) !SelectedShredPlan {
    var plan: SelectedShredPlan = .{
        .schedule = try buildOrderedRefSchedule(allocator, blockstore, cfg, cancel),
    };
    errdefer plan.deinit(allocator);

    plan.eligible_shreds = countEligibleShreds(plan.schedule.refs.items, cfg.shred_kind);
    plan.selected_ref_indices = try chooseSelectedRefIndices(
        allocator,
        stdout,
        plan.schedule.refs.items,
        cfg.shred_kind,
        cfg.selected_count,
        cfg.seed.?,
    );
    return plan;
}

pub fn buildOrderedRefSchedule(
    allocator: Allocator,
    blockstore: *const AgaveBlockstore,
    cfg: Config,
    cancel: anytype,
) !RefSchedule {
    var schedule: RefSchedule = .{};
    errdefer schedule.deinit(allocator);

    var start_key_buf: [8]u8 = undefined;
    const start_key: ?[]const u8 = if (cfg.start_slot) |slot| start_key: {
        writeSlotKey(&start_key_buf, slot);
        break :start_key start_key_buf[0..];
    } else null;

    var slot_iter = blockstore.db.iterator(
        try blockstore.columnFamily(agave_cf_meta),
        .forward,
        start_key,
    );
    defer slot_iter.deinit();

    var err_data: ?rocks.Data = null;
    defer if (err_data) |err| err.deinit();

    while (try slot_iter.next(&err_data)) |entry| {
        if (cancel.isCanceled()) break;

        const slot = parseSlotKey(entry[0].data) catch |err| {
            std.debug.print("invalid {s} key length: {d}\n", .{ agave_cf_meta, entry[0].data.len });
            return err;
        };
        if (cfg.pastEndSlot(slot)) break;
        if (!cfg.slotSelected(slot)) continue;

        schedule.selected_slots += 1;
        try collectSlotShredRefs(allocator, blockstore, slot, .data, &schedule.refs, cancel);
        if (blockstore.has_code_shred) {
            try collectSlotShredRefs(allocator, blockstore, slot, .code, &schedule.refs, cancel);
        }
    }

    return schedule;
}

pub fn collectSlotShredRefs(
    allocator: Allocator,
    blockstore: *const AgaveBlockstore,
    slot: Slot,
    kind: ShredKind,
    refs: *std.ArrayList(ShredRef),
    cancel: anytype,
) !void {
    var start_key_buf: [16]u8 = undefined;
    writeShredKey(&start_key_buf, .{ .slot = slot, .index = 0 });

    var shred_iter = blockstore.db.iterator(
        try blockstore.columnFamily(kind.columnFamilyName()),
        .forward,
        start_key_buf[0..],
    );
    defer shred_iter.deinit();

    var err_data: ?rocks.Data = null;
    defer if (err_data) |err| err.deinit();

    while (try shred_iter.next(&err_data)) |entry| {
        if (cancel.isCanceled()) break;

        const key = parseShredKey(entry[0].data) catch |err| {
            std.debug.print(
                "invalid {s} key length: {d}\n",
                .{ kind.columnFamilyName(), entry[0].data.len },
            );
            return err;
        };
        if (key.slot != slot) break;
        try refs.append(
            allocator,
            .{ .slot = key.slot, .index = key.index, .kind = kind },
        );
    }
}
