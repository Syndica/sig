const std = @import("std");
const sig = @import("sig");

const Allocator = std.mem.Allocator;
const AutoHashMap = std.AutoHashMap;
const ArrayList = std.array_list.Managed;
const Slot = sig.core.Slot;
const Shred = sig.ledger.shred.Shred;
const Recovery = sig.ledger.shred_inserter.recovery;

const CHRS_MAGIC: u32 = 0x53524843;
const CHRS_HEADER_LEN: usize = 32;
const DEFAULT_MAX_FRAMES: u64 = std.math.maxInt(u64);

const Args = struct {
    spool_path: []const u8,
    max_frames: u64 = DEFAULT_MAX_FRAMES,
    min_window: u64 = 128,
    repair_plan_path: ?[]const u8 = null,
};

const FecKey = struct {
    slot: Slot,
    fec_set_index: u64,
    leader_signature: [sig.core.Signature.SIZE]u8,
};

const FecInfo = struct {
    num_data_shreds: u16,
    data_complete: bool,
    slot_complete: bool,
};

const SlotState = struct {
    parent_slot: ?Slot = null,
    completed_fecs: AutoHashMap(u64, FecInfo),
    last_fec_index: ?u64 = null,

    fn init(allocator: Allocator) SlotState {
        return .{ .completed_fecs = AutoHashMap(u64, FecInfo).init(allocator) };
    }

    fn deinit(self: *SlotState) void {
        self.completed_fecs.deinit();
    }

    fn addCompletedFec(self: *SlotState, index: u64, info: FecInfo) !void {
        try self.completed_fecs.put(index, info);
        if (info.slot_complete) {
            if (self.last_fec_index) |current| {
                self.last_fec_index = @min(current, index);
            } else {
                self.last_fec_index = index;
            }
        }
    }

    fn isSlotComplete(self: *const SlotState) bool {
        const last = self.last_fec_index orelse return false;
        var index: u64 = 0;
        var guard: usize = 0;
        while (index <= last and guard < 2048) : (guard += 1) {
            const info = self.completed_fecs.get(index) orelse return false;
            if (info.slot_complete) return true;
            if (info.num_data_shreds == 0) return false;
            index += info.num_data_shreds;
        }
        return false;
    }
};

const FecSet = struct {
    allocator: Allocator,
    key: FecKey,
    seen_shards: AutoHashMap(usize, void),
    shreds: ArrayList(Shred),
    num_data_shreds: ?u16 = null,
    num_code_shreds: ?u16 = null,
    data_shreds_seen: u64 = 0,
    code_shreds_seen: u64 = 0,
    seen_data_shards: std.StaticBitSet(32) = .initEmpty(),
    data_complete_shard_index: ?usize = null,
    data_complete: bool = false,
    slot_complete: bool = false,
    parent_slot: ?Slot = null,
    completed: bool = false,

    fn init(allocator: Allocator, key: FecKey) FecSet {
        return .{
            .allocator = allocator,
            .key = key,
            .seen_shards = AutoHashMap(usize, void).init(allocator),
            .shreds = ArrayList(Shred).init(allocator),
        };
    }

    fn deinit(self: *FecSet) void {
        for (self.shreds.items) |shred| shred.deinit();
        self.shreds.deinit();
        self.seen_shards.deinit();
    }

    fn addShred(self: *FecSet, shred: Shred) !bool {
        const shard_index = shred.erasureShardIndex() catch {
            shred.deinit();
            return false;
        };
        const entry = try self.seen_shards.getOrPut(shard_index);
        if (entry.found_existing) {
            shred.deinit();
            return false;
        }

        switch (shred) {
            .data => |data| {
                self.data_shreds_seen += 1;
                if (shard_index < 32) self.seen_data_shards.set(shard_index);
                self.data_complete = self.data_complete or data.dataComplete();
                self.slot_complete = self.slot_complete or data.isLastInSlot();
                if (data.dataComplete()) {
                    if (self.data_complete_shard_index) |current| {
                        self.data_complete_shard_index = @min(current, shard_index);
                    } else {
                        self.data_complete_shard_index = shard_index;
                    }
                }
                if (self.parent_slot == null) self.parent_slot = data.parent() catch null;
            },
            .code => |code| {
                self.code_shreds_seen += 1;
                self.num_data_shreds = code.custom.num_data_shreds;
                self.num_code_shreds = code.custom.num_code_shreds;
            },
        }

        try self.shreds.append(shred);
        return true;
    }

    fn dataOnlyCompleteInfo(self: *FecSet) ?FecInfo {
        if (self.completed) return null;
        if (self.data_complete_shard_index) |last_data_shard| {
            if (last_data_shard >= 32) return null;
            var shard_index: usize = 0;
            while (shard_index <= last_data_shard) : (shard_index += 1) {
                if (!self.seen_data_shards.isSet(shard_index)) return null;
            }
            self.completed = true;
            return .{
                .num_data_shreds = @intCast(last_data_shard + 1),
                .data_complete = true,
                .slot_complete = self.slot_complete,
            };
        }

        if (self.seen_data_shards.count() == 32) {
            self.completed = true;
            return .{
                .num_data_shreds = 32,
                .data_complete = self.data_complete,
                .slot_complete = self.slot_complete,
            };
        }

        return null;
    }

    fn canAttemptRecovery(self: *const FecSet) bool {
        if (self.completed) return false;
        const num_data = self.num_data_shreds orelse return false;
        return self.shreds.items.len >= num_data and self.code_shreds_seen > 0;
    }

    fn tryComplete(
        self: *FecSet,
        allocator: Allocator,
        cache: *Recovery.ReedSolomonCache,
    ) !?FecInfo {
        if (!self.canAttemptRecovery()) return null;

        var recovered = Recovery.recover(allocator, self.shreds.items, cache) catch |err| switch (err) {
            error.TooFewShards,
            error.TooFewParityShards,
            error.InvalidIndex,
            => return null,
            else => return err,
        };
        defer {
            for (recovered.items) |shred| shred.deinit();
            recovered.deinit();
        }

        for (self.shreds.items) |shred| {
            if (shred == .data) {
                self.data_complete = self.data_complete or shred.data.dataComplete();
                self.slot_complete = self.slot_complete or shred.data.isLastInSlot();
            }
        }
        for (recovered.items) |shred| {
            if (shred == .data) {
                self.data_complete = self.data_complete or shred.data.dataComplete();
                self.slot_complete = self.slot_complete or shred.data.isLastInSlot();
                if (self.parent_slot == null) self.parent_slot = shred.data.parent() catch null;
            }
        }

        self.completed = true;
        return .{
            .num_data_shreds = self.num_data_shreds.?,
            .data_complete = self.data_complete,
            .slot_complete = self.slot_complete,
        };
    }
};

const Stats = struct {
    frames: u64 = 0,
    bytes: u64 = 0,
    parsed_shreds: u64 = 0,
    data_shreds: u64 = 0,
    code_shreds: u64 = 0,
    duplicate_shreds: u64 = 0,
    parse_errors: u64 = 0,
    bad_frames: u64 = 0,
    fec_sets_started: u64 = 0,
    fec_sets_completed: u64 = 0,
    recovery_attempts: u64 = 0,
    recovery_errors: u64 = 0,
    first_seen_slot: ?Slot = null,
    last_seen_slot: ?Slot = null,
};

const Probe = struct {
    allocator: Allocator,
    fec_sets: AutoHashMap(FecKey, FecSet),
    slots: AutoHashMap(Slot, SlotState),
    cache: Recovery.ReedSolomonCache,
    stats: Stats = .{},

    fn init(allocator: Allocator) !Probe {
        return .{
            .allocator = allocator,
            .fec_sets = AutoHashMap(FecKey, FecSet).init(allocator),
            .slots = AutoHashMap(Slot, SlotState).init(allocator),
            .cache = try Recovery.ReedSolomonCache.init(allocator),
        };
    }

    fn deinit(self: *Probe) void {
        var fec_iter = self.fec_sets.valueIterator();
        while (fec_iter.next()) |fec_set| fec_set.deinit();
        self.fec_sets.deinit();

        var slot_iter = self.slots.valueIterator();
        while (slot_iter.next()) |slot| slot.deinit();
        self.slots.deinit();

        self.cache.deinit();
    }

    fn processPacket(self: *Probe, payload: []const u8) !void {
        var shred = Shred.fromPayload(self.allocator, payload) catch {
            self.stats.parse_errors += 1;
            return;
        };
        errdefer shred.deinit();

        self.stats.parsed_shreds += 1;
        switch (shred) {
            .data => self.stats.data_shreds += 1,
            .code => self.stats.code_shreds += 1,
        }

        const common = shred.commonHeader();
        if (self.stats.first_seen_slot) |first| {
            self.stats.first_seen_slot = @min(first, common.slot);
        } else {
            self.stats.first_seen_slot = common.slot;
        }
        if (self.stats.last_seen_slot) |last| {
            self.stats.last_seen_slot = @max(last, common.slot);
        } else {
            self.stats.last_seen_slot = common.slot;
        }

        const key: FecKey = .{
            .slot = common.slot,
            .fec_set_index = common.erasure_set_index,
            .leader_signature = common.leader_signature.toBytes(),
        };

        const entry = try self.fec_sets.getOrPut(key);
        if (!entry.found_existing) {
            entry.value_ptr.* = FecSet.init(self.allocator, key);
            self.stats.fec_sets_started += 1;
        }

        const added = try entry.value_ptr.addShred(shred);
        if (!added) {
            self.stats.duplicate_shreds += 1;
            return;
        }
        errdefer unreachable;

        if (entry.value_ptr.dataOnlyCompleteInfo()) |info| {
            self.stats.fec_sets_completed += 1;
            try self.recordCompletedFec(entry.value_ptr, info);
            return;
        }

        if (entry.value_ptr.canAttemptRecovery()) {
            self.stats.recovery_attempts += 1;
            const maybe_info = entry.value_ptr.tryComplete(
                self.allocator,
                &self.cache,
            ) catch {
                self.stats.recovery_errors += 1;
                return;
            };
            if (maybe_info) |info| {
                self.stats.fec_sets_completed += 1;
                try self.recordCompletedFec(entry.value_ptr, info);
            }
        }
    }

    fn recordCompletedFec(self: *Probe, fec_set: *const FecSet, info: FecInfo) !void {
        const slot_entry = try self.slots.getOrPut(fec_set.key.slot);
        if (!slot_entry.found_existing) {
            slot_entry.value_ptr.* = SlotState.init(self.allocator);
        }
        if (slot_entry.value_ptr.parent_slot == null) {
            slot_entry.value_ptr.parent_slot = fec_set.parent_slot;
        }
        try slot_entry.value_ptr.addCompletedFec(fec_set.key.fec_set_index, info);
    }

    fn printReport(self: *Probe, min_window: u64) !void {
        var stdout_buf: [8192]u8 = undefined;
        var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
        const stdout = &stdout_writer.interface;

        var slot_list = ArrayList(Slot).init(self.allocator);
        defer slot_list.deinit();

        var slot_iter = self.slots.iterator();
        while (slot_iter.next()) |entry| {
            if (entry.value_ptr.isSlotComplete()) {
                try slot_list.append(entry.key_ptr.*);
            }
        }
        std.mem.sort(Slot, slot_list.items, {}, lessThanSlot);

        const best_consecutive = bestConsecutive(slot_list.items);
        const best_parent_linked = bestParentLinked(&self.slots, slot_list.items);
        var missing = try missingFecSummary(self.allocator, &self.slots, &self.fec_sets, 16, null, null);
        defer missing.deinit();
        var missing_after_best = try missingFecSummary(
            self.allocator,
            &self.slots,
            &self.fec_sets,
            16,
            if (best_parent_linked.end) |end| end + 1 else null,
            null,
        );
        defer missing_after_best.deinit();

        try stdout.print("fec_capture_probe_result pass={}\n", .{
            best_parent_linked.len >= min_window,
        });
        try stdout.print(
            "frames={} bytes={} parsed_shreds={} data_shreds={} code_shreds={} duplicate_shreds={} parse_errors={} bad_frames={}\n",
            .{
                self.stats.frames,
                self.stats.bytes,
                self.stats.parsed_shreds,
                self.stats.data_shreds,
                self.stats.code_shreds,
                self.stats.duplicate_shreds,
                self.stats.parse_errors,
                self.stats.bad_frames,
            },
        );
        try stdout.print(
            "fec_sets_started={} fec_sets_completed={} recovery_attempts={} recovery_errors={}\n",
            .{
                self.stats.fec_sets_started,
                self.stats.fec_sets_completed,
                self.stats.recovery_attempts,
                self.stats.recovery_errors,
            },
        );
        try stdout.print(
            "observed_slot_range_start={?} observed_slot_range_end={?}\n",
            .{ self.stats.first_seen_slot, self.stats.last_seen_slot },
        );
        try stdout.print(
            "complete_slots={} best_consecutive_len={} best_consecutive_start={?} best_consecutive_end={?}\n",
            .{
                slot_list.items.len,
                best_consecutive.len,
                best_consecutive.start,
                best_consecutive.end,
            },
        );
        try stdout.print(
            "best_parent_linked_len={} best_parent_linked_start={?} best_parent_linked_end={?} min_window={}\n",
            .{
                best_parent_linked.len,
                best_parent_linked.start,
                best_parent_linked.end,
                min_window,
            },
        );
        if (best_parent_linked.len >= min_window) {
            const window_start = best_parent_linked.start.?;
            const window_end = best_parent_linked.end.?;
            try stdout.print(
                "SOURCE_GATE_MIN_INCREMENTAL_SLOT={} SOURCE_GATE_MAX_INCREMENTAL_SLOT={}\n",
                .{ window_start - 1, window_end - min_window },
            );
        }
        if (best_parent_linked.start) |start| {
            if (start > 0) {
                try printSlotBlocker(
                    stdout,
                    &self.slots,
                    &self.fec_sets,
                    self.stats.first_seen_slot,
                    self.stats.last_seen_slot,
                    "before",
                    start - 1,
                    null,
                );
            }
        }
        if (best_parent_linked.end) |end| {
            try printSlotBlocker(
                stdout,
                &self.slots,
                &self.fec_sets,
                self.stats.first_seen_slot,
                self.stats.last_seen_slot,
                "after",
                end + 1,
                end,
            );
        }
        try stdout.print(
            "missing_fec_sets={} missing_fec_sample_count={}\n",
            .{ missing.count, missing.samples.items.len },
        );
        try printMissingFecBreakdown(stdout, "all", &missing);
        for (missing.samples.items) |sample| {
            try stdout.print(
                "missing_fec_sample slot={} fec_set_index={} data_seen={} code_seen={} expected_data={?} expected_code={?} unique_shards={}\n",
                .{
                    sample.slot,
                    sample.fec_set_index,
                    sample.data_seen,
                    sample.code_seen,
                    sample.expected_data,
                    sample.expected_code,
                    sample.unique_shards,
                },
            );
        }
        try stdout.print(
            "missing_fec_sets_after_best_window={} missing_fec_after_window_sample_count={}\n",
            .{ missing_after_best.count, missing_after_best.samples.items.len },
        );
        try printMissingFecBreakdown(stdout, "after_best", &missing_after_best);
        for (missing_after_best.samples.items) |sample| {
            try stdout.print(
                "missing_fec_after_window_sample slot={} fec_set_index={} data_seen={} code_seen={} expected_data={?} expected_code={?} unique_shards={}\n",
                .{
                    sample.slot,
                    sample.fec_set_index,
                    sample.data_seen,
                    sample.code_seen,
                    sample.expected_data,
                    sample.expected_code,
                    sample.unique_shards,
                },
            );
        }
        try stdout.flush();
    }
};

const Window = struct {
    len: u64 = 0,
    start: ?Slot = null,
    end: ?Slot = null,
};

const MissingFecSample = struct {
    slot: Slot,
    fec_set_index: u64,
    data_seen: u64,
    code_seen: u64,
    expected_data: ?u16,
    expected_code: ?u16,
    unique_shards: u64,
};

const FecProgress = struct {
    data_seen: u64 = 0,
    code_seen: u64 = 0,
    expected_data: ?u16 = null,
    expected_code: ?u16 = null,
    unique_shards: u64 = 0,
    seen_data_shards: std.StaticBitSet(32) = .initEmpty(),
};

const RepairPlanStats = struct {
    missing_fec_sets: u64 = 0,
    data_shred_requests: u64 = 0,
    never_seen_sets: u64 = 0,
    partial_sets: u64 = 0,
};

const MissingFecSummary = struct {
    count: u64 = 0,
    index_0_count: u64 = 0,
    index_32_count: u64 = 0,
    index_ge_64_count: u64 = 0,
    never_seen_count: u64 = 0,
    partial_unrecoverable_count: u64 = 0,
    apparently_recoverable_count: u64 = 0,
    samples: ArrayList(MissingFecSample),
    top_slots: ArrayList(MissingSlotCount),

    fn init(allocator: Allocator) MissingFecSummary {
        return .{
            .samples = ArrayList(MissingFecSample).init(allocator),
            .top_slots = ArrayList(MissingSlotCount).init(allocator),
        };
    }

    fn deinit(self: *MissingFecSummary) void {
        self.samples.deinit();
        self.top_slots.deinit();
    }
};

const MissingSlotCount = struct {
    slot: Slot,
    count: u64,
};

pub fn main() !void {
    const allocator = std.heap.smp_allocator;

    const raw_args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, raw_args);
    const args = parseArgs(raw_args) catch |err| {
        std.debug.print(
            "usage: fec-capture-probe --spool <raw-shreds.chrs> [--max-frames <n>] [--min-window <n>] [--repair-plan <path>]\nerror: {s}\n",
            .{@errorName(err)},
        );
        return err;
    };

    var probe = try Probe.init(allocator);
    defer probe.deinit();

    try readSpool(allocator, args, &probe);
    try probe.printReport(args.min_window);
    if (args.repair_plan_path) |path| {
        const stats = try writeRepairPlan(path, &probe.slots, &probe.fec_sets);
        var stdout_buf: [1024]u8 = undefined;
        var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
        const stdout = &stdout_writer.interface;
        try stdout.print(
            "repair_plan_written path={s} missing_fec_sets={} data_shred_requests={} never_seen_sets={} partial_sets={}\n",
            .{
                path,
                stats.missing_fec_sets,
                stats.data_shred_requests,
                stats.never_seen_sets,
                stats.partial_sets,
            },
        );
        try stdout.flush();
    }
}

fn parseArgs(argv: []const []const u8) !Args {
    var spool_path: ?[]const u8 = null;
    var max_frames: u64 = DEFAULT_MAX_FRAMES;
    var min_window: u64 = 128;
    var repair_plan_path: ?[]const u8 = null;

    var i: usize = 1;
    while (i < argv.len) : (i += 1) {
        if (std.mem.eql(u8, argv[i], "--spool")) {
            i += 1;
            if (i >= argv.len) return error.MissingSpoolPath;
            spool_path = argv[i];
        } else if (std.mem.eql(u8, argv[i], "--max-frames")) {
            i += 1;
            if (i >= argv.len) return error.MissingMaxFrames;
            max_frames = try std.fmt.parseUnsigned(u64, argv[i], 10);
        } else if (std.mem.eql(u8, argv[i], "--min-window")) {
            i += 1;
            if (i >= argv.len) return error.MissingMinWindow;
            min_window = try std.fmt.parseUnsigned(u64, argv[i], 10);
        } else if (std.mem.eql(u8, argv[i], "--repair-plan")) {
            i += 1;
            if (i >= argv.len) return error.MissingRepairPlanPath;
            repair_plan_path = argv[i];
        } else {
            return error.UnknownArgument;
        }
    }

    return .{
        .spool_path = spool_path orelse return error.MissingSpoolPath,
        .max_frames = max_frames,
        .min_window = min_window,
        .repair_plan_path = repair_plan_path,
    };
}

fn readSpool(allocator: Allocator, args: Args, probe: *Probe) !void {
    var file = try std.fs.cwd().openFile(args.spool_path, .{});
    defer file.close();

    while (probe.stats.frames < args.max_frames) {
        var header: [CHRS_HEADER_LEN]u8 = undefined;
        const header_read = try file.readAll(&header);
        if (header_read == 0) break;
        if (header_read != CHRS_HEADER_LEN) {
            probe.stats.bad_frames += 1;
            break;
        }

        const magic = std.mem.readInt(u32, header[0..4], .little);
        const packet_len = std.mem.readInt(u32, header[4..8], .little);
        if (magic != CHRS_MAGIC or packet_len == 0 or packet_len > 2048) {
            probe.stats.bad_frames += 1;
            break;
        }

        const packet = try allocator.alloc(u8, packet_len);
        defer allocator.free(packet);
        const packet_read = try file.readAll(packet);
        if (packet_read != packet_len) {
            probe.stats.bad_frames += 1;
            break;
        }

        probe.stats.frames += 1;
        probe.stats.bytes += packet_len;
        try probe.processPacket(packet);
    }
}

fn lessThanSlot(_: void, a: Slot, b: Slot) bool {
    return a < b;
}

fn greaterMissingSlotCount(_: void, a: MissingSlotCount, b: MissingSlotCount) bool {
    if (a.count == b.count) return a.slot < b.slot;
    return a.count > b.count;
}

fn bestConsecutive(slots: []const Slot) Window {
    var best: Window = .{};
    var current: Window = .{};
    var prev: ?Slot = null;

    for (slots) |slot| {
        if (prev != null and slot == prev.? + 1) {
            current.len += 1;
            current.end = slot;
        } else {
            current = .{ .len = 1, .start = slot, .end = slot };
        }
        if (current.len > best.len) best = current;
        prev = slot;
    }

    return best;
}

fn bestParentLinked(slots: *AutoHashMap(Slot, SlotState), complete_slots: []const Slot) Window {
    var best_by_slot = AutoHashMap(Slot, Window).init(slots.allocator);
    defer best_by_slot.deinit();

    var best: Window = .{};
    for (complete_slots) |slot| {
        const state = slots.get(slot) orelse continue;
        const parent_window = if (state.parent_slot) |parent|
            best_by_slot.get(parent)
        else
            null;
        const window: Window = if (parent_window) |parent|
            .{ .len = parent.len + 1, .start = parent.start, .end = slot }
        else
            .{ .len = 1, .start = slot, .end = slot };

        best_by_slot.put(slot, window) catch continue;
        if (window.len > best.len) best = window;
    }
    return best;
}

fn printMissingFecBreakdown(
    stdout: anytype,
    label: []const u8,
    summary: *const MissingFecSummary,
) !void {
    try stdout.print(
        "missing_fec_breakdown label={s} index_0={} index_32={} index_ge_64={} never_seen={} partial_unrecoverable={} apparently_recoverable={}\n",
        .{
            label,
            summary.index_0_count,
            summary.index_32_count,
            summary.index_ge_64_count,
            summary.never_seen_count,
            summary.partial_unrecoverable_count,
            summary.apparently_recoverable_count,
        },
    );
    for (summary.top_slots.items) |slot_count| {
        try stdout.print(
            "missing_fec_top_slot label={s} slot={} count={}\n",
            .{ label, slot_count.slot, slot_count.count },
        );
    }
}

fn missingFecSummary(
    allocator: Allocator,
    slots: *AutoHashMap(Slot, SlotState),
    fec_sets: *AutoHashMap(FecKey, FecSet),
    sample_limit: usize,
    min_slot: ?Slot,
    max_slot: ?Slot,
) !MissingFecSummary {
    var summary = MissingFecSummary.init(allocator);
    errdefer summary.deinit();
    var slot_counts = AutoHashMap(Slot, u64).init(allocator);
    defer slot_counts.deinit();

    var slot_list = ArrayList(Slot).init(allocator);
    defer slot_list.deinit();

    var slot_iter = slots.iterator();
    while (slot_iter.next()) |entry| {
        if (entry.value_ptr.last_fec_index != null) {
            try slot_list.append(entry.key_ptr.*);
        }
    }
    std.mem.sort(Slot, slot_list.items, {}, lessThanSlot);

    for (slot_list.items) |slot| {
        if (min_slot) |min| {
            if (slot < min) continue;
        }
        if (max_slot) |max| {
            if (slot > max) continue;
        }

        const state = slots.get(slot) orelse continue;
        const last = state.last_fec_index orelse continue;
        var index: u64 = 0;
        var guard: usize = 0;
        while (index <= last and guard < 4096) : (guard += 1) {
            if (state.completed_fecs.get(index)) |info| {
                index += if (info.num_data_shreds == 0) 1 else info.num_data_shreds;
                continue;
            }

            summary.count += 1;
            if (index == 0) {
                summary.index_0_count += 1;
            } else if (index == 32) {
                summary.index_32_count += 1;
            } else {
                summary.index_ge_64_count += 1;
            }

            const progress = bestFecProgress(fec_sets, slot, index);
            const recovery_threshold: u64 = progress.expected_data orelse 32;
            if (progress.unique_shards == 0) {
                summary.never_seen_count += 1;
            } else if (progress.unique_shards < recovery_threshold) {
                summary.partial_unrecoverable_count += 1;
            } else {
                summary.apparently_recoverable_count += 1;
            }

            const slot_count = try slot_counts.getOrPut(slot);
            if (!slot_count.found_existing) {
                slot_count.value_ptr.* = 0;
            }
            slot_count.value_ptr.* += 1;

            if (summary.samples.items.len < sample_limit) {
                try summary.samples.append(.{
                    .slot = slot,
                    .fec_set_index = index,
                    .data_seen = progress.data_seen,
                    .code_seen = progress.code_seen,
                    .expected_data = progress.expected_data,
                    .expected_code = progress.expected_code,
                    .unique_shards = progress.unique_shards,
                });
            }
            index += 32;
        }
    }

    var slot_count_iter = slot_counts.iterator();
    while (slot_count_iter.next()) |entry| {
        try summary.top_slots.append(.{ .slot = entry.key_ptr.*, .count = entry.value_ptr.* });
    }
    std.mem.sort(MissingSlotCount, summary.top_slots.items, {}, greaterMissingSlotCount);
    if (summary.top_slots.items.len > 8) {
        summary.top_slots.shrinkRetainingCapacity(8);
    }

    return summary;
}

fn createRepairPlanFile(path: []const u8) !std.fs.File {
    if (std.fs.path.isAbsolute(path)) {
        return try std.fs.createFileAbsolute(path, .{ .truncate = true });
    }
    return try std.fs.cwd().createFile(path, .{ .truncate = true });
}

fn writeRepairPlan(
    path: []const u8,
    slots: *AutoHashMap(Slot, SlotState),
    fec_sets: *AutoHashMap(FecKey, FecSet),
) !RepairPlanStats {
    var file = try createRepairPlanFile(path);
    defer file.close();
    var write_buf: [65536]u8 = undefined;
    var file_writer = file.writer(&write_buf);
    const writer = &file_writer.interface;

    try writer.print(
        "# repair_data_shred lines are Agave-style Shred(slot,index) data-repair candidates\n",
        .{},
    );

    var stats: RepairPlanStats = .{};
    var slot_list = ArrayList(Slot).init(slots.allocator);
    defer slot_list.deinit();

    var slot_iter = slots.iterator();
    while (slot_iter.next()) |entry| {
        if (entry.value_ptr.last_fec_index != null) {
            try slot_list.append(entry.key_ptr.*);
        }
    }
    std.mem.sort(Slot, slot_list.items, {}, lessThanSlot);

    for (slot_list.items) |slot| {
        const state = slots.get(slot) orelse continue;
        const last = state.last_fec_index orelse continue;
        var fec_set_index: u64 = 0;
        var guard: usize = 0;
        while (fec_set_index <= last and guard < 4096) : (guard += 1) {
            if (state.completed_fecs.get(fec_set_index)) |info| {
                fec_set_index += if (info.num_data_shreds == 0) 1 else info.num_data_shreds;
                continue;
            }

            stats.missing_fec_sets += 1;
            const progress = bestFecProgress(fec_sets, slot, fec_set_index);
            if (progress.unique_shards == 0) {
                stats.never_seen_sets += 1;
            } else {
                stats.partial_sets += 1;
            }

            const expected_data = @min(@as(usize, progress.expected_data orelse 32), 32);
            for (0..expected_data) |shard_index| {
                if (progress.seen_data_shards.isSet(shard_index)) continue;
                const shred_index = fec_set_index + @as(u64, @intCast(shard_index));
                try writer.print(
                    "repair_data_shred slot={} index={} fec_set_index={} data_seen={} code_seen={} expected_data={?} expected_code={?} unique_shards={}\n",
                    .{
                        slot,
                        shred_index,
                        fec_set_index,
                        progress.data_seen,
                        progress.code_seen,
                        progress.expected_data,
                        progress.expected_code,
                        progress.unique_shards,
                    },
                );
                stats.data_shred_requests += 1;
            }

            fec_set_index += 32;
        }
    }

    try writer.flush();
    return stats;
}

fn bestFecProgress(
    fec_sets: *AutoHashMap(FecKey, FecSet),
    slot: Slot,
    fec_set_index: u64,
) FecProgress {
    var best: FecProgress = .{};
    var iter = fec_sets.iterator();
    while (iter.next()) |entry| {
        if (entry.key_ptr.slot != slot or entry.key_ptr.fec_set_index != fec_set_index) {
            continue;
        }
        const fec_set = entry.value_ptr;
        const progress: FecProgress = .{
            .data_seen = fec_set.data_shreds_seen,
            .code_seen = fec_set.code_shreds_seen,
            .expected_data = fec_set.num_data_shreds,
            .expected_code = fec_set.num_code_shreds,
            .unique_shards = fec_set.seen_shards.count(),
            .seen_data_shards = fec_set.seen_data_shards,
        };
        if (progress.unique_shards > best.unique_shards) {
            best = progress;
        }
    }
    return best;
}

fn firstMissingFec(state: *const SlotState) ?u64 {
    const last = state.last_fec_index orelse return 0;
    var index: u64 = 0;
    var guard: usize = 0;
    while (index <= last and guard < 4096) : (guard += 1) {
        if (state.completed_fecs.get(index)) |info| {
            index += if (info.num_data_shreds == 0) 1 else info.num_data_shreds;
            continue;
        }
        return index;
    }
    return null;
}

fn printSlotBlocker(
    stdout: anytype,
    slots: *AutoHashMap(Slot, SlotState),
    fec_sets: *AutoHashMap(FecKey, FecSet),
    first_seen: ?Slot,
    last_seen: ?Slot,
    side: []const u8,
    slot: Slot,
    expected_parent: ?Slot,
) !void {
    if (first_seen) |first| {
        if (slot < first) {
            try stdout.print(
                "window_blocker side={s} slot={} status=outside_observed_range first_seen={?} last_seen={?}\n",
                .{ side, slot, first_seen, last_seen },
            );
            return;
        }
    }
    if (last_seen) |last| {
        if (slot > last) {
            try stdout.print(
                "window_blocker side={s} slot={} status=outside_observed_range first_seen={?} last_seen={?}\n",
                .{ side, slot, first_seen, last_seen },
            );
            return;
        }
    }

    const state = slots.get(slot) orelse {
        try stdout.print(
            "window_blocker side={s} slot={} status=missing_slot_state expected_parent={?}\n",
            .{ side, slot, expected_parent },
        );
        return;
    };

    if (expected_parent) |parent| {
        if (state.parent_slot == null or state.parent_slot.? != parent) {
            try stdout.print(
                "window_blocker side={s} slot={} status=parent_mismatch parent={?} expected_parent={} last_fec_index={?} completed_fec_count={}\n",
                .{
                    side,
                    slot,
                    state.parent_slot,
                    parent,
                    state.last_fec_index,
                    state.completed_fecs.count(),
                },
            );
            return;
        }
    }

    if (state.last_fec_index == null) {
        try stdout.print(
            "window_blocker side={s} slot={} status=no_last_fec parent={?} completed_fec_count={}\n",
            .{ side, slot, state.parent_slot, state.completed_fecs.count() },
        );
        return;
    }

    if (firstMissingFec(&state)) |missing_index| {
        const progress = bestFecProgress(fec_sets, slot, missing_index);
        try stdout.print(
            "window_blocker side={s} slot={} status=missing_fec parent={?} last_fec_index={?} missing_fec_index={} completed_fec_count={} data_seen={} code_seen={} expected_data={?} expected_code={?} unique_shards={}\n",
            .{
                side,
                slot,
                state.parent_slot,
                state.last_fec_index,
                missing_index,
                state.completed_fecs.count(),
                progress.data_seen,
                progress.code_seen,
                progress.expected_data,
                progress.expected_code,
                progress.unique_shards,
            },
        );
        return;
    }

    try stdout.print(
        "window_blocker side={s} slot={} status=complete parent={?} last_fec_index={?} completed_fec_count={}\n",
        .{ side, slot, state.parent_slot, state.last_fec_index, state.completed_fecs.count() },
    );
}
