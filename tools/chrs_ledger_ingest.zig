const std = @import("std");
const sig = @import("sig");

const Allocator = std.mem.Allocator;
const ArrayList = std.array_list.Managed;
const Ledger = sig.ledger.Ledger;
const LeaderSchedule = sig.core.leader_schedule.LeaderSchedule;
const LeaderSchedules = sig.core.leader_schedule.LeaderSchedules;
const ReducedCheckpoint = sig.accounts_db.snapshot.ReducedCheckpoint;
const Shred = sig.ledger.shred.Shred;
const Slot = sig.core.Slot;

const CHRS_MAGIC: u32 = 0x53524843;
const CHRS_HEADER_LEN: usize = 32;
const MAX_PACKET_BYTES: usize = 4096;

const Args = struct {
    write: bool = false,
    append: bool = false,
    recover: bool = false,
    ledger_path: ?[]const u8 = null,
    checkpoint_path: ?[]const u8 = null,
    leader_schedule_path: ?[]const u8 = null,
    spool_paths: ArrayList([]const u8),
    min_slot: ?Slot = null,
    max_slot: ?Slot = null,
    verify_slot: ?Slot = null,
    batch_shreds: usize = 4096,

    fn init(allocator: Allocator) Args {
        return .{ .spool_paths = ArrayList([]const u8).init(allocator) };
    }

    fn deinit(self: *Args) void {
        self.spool_paths.deinit();
    }
};

const Stats = struct {
    frames: u64 = 0,
    packet_bytes: u64 = 0,
    parsed_shreds: u64 = 0,
    non_shred_packets: u64 = 0,
    skipped_before_min: u64 = 0,
    skipped_after_max: u64 = 0,
    insertion_candidates: u64 = 0,
    insertion_batches: u64 = 0,
    completed_data_sets: u64 = 0,
    duplicate_proofs: u64 = 0,
    verify_slot_shreds: u64 = 0,
    verify_slot_valid: u64 = 0,
    verify_slot_invalid: u64 = 0,
    verify_slot_leader_missing: u64 = 0,
    first_inserted_slot: ?Slot = null,
    last_inserted_slot: ?Slot = null,
};

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const raw_args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, raw_args);

    var args = Args.init(allocator);
    defer args.deinit();
    parseArgs(raw_args, &args) catch |err| {
        printUsage();
        std.debug.print("error: {s}\n", .{@errorName(err)});
        return err;
    };

    const ledger_path = args.ledger_path.?;
    try requireSafeLedgerPath(ledger_path, args.append);
    for (args.spool_paths.items) |spool_path| try requireInternalPath(spool_path);
    if (args.checkpoint_path) |checkpoint_path| try requireInternalPath(checkpoint_path);
    if (args.leader_schedule_path) |leader_schedule_path| try requireInternalPath(leader_schedule_path);

    std.debug.print(
        "chrs_ledger_ingest_plan=pass write={} append={} recover={} ledger_path={s} checkpoint_path={?s} leader_schedule_path={?s} spool_files={} min_slot={} max_slot={} batch_shreds={} trusted_authentic_chrs=true udp_bypassed=true\n",
        .{
            args.write,
            args.append,
            args.recover,
            ledger_path,
            args.checkpoint_path,
            args.leader_schedule_path,
            args.spool_paths.items.len,
            args.min_slot.?,
            args.max_slot.?,
            args.batch_shreds,
        },
    );
    if (!args.write) {
        std.debug.print("dry_run=pass set --write to create the isolated ledger\n", .{});
        return;
    }

    try std.fs.cwd().makePath(ledger_path);
    var ledger = try Ledger.init(
        allocator,
        sig.trace.Logger("ledger").noop,
        ledger_path,
        null,
    );
    defer ledger.deinit();

    if (args.append) {
        const existing_highest_slot = try ledger.reader().highestSlot() orelse
            return error.AppendLedgerHasNoSlots;
        if (existing_highest_slot == std.math.maxInt(Slot) or
            args.min_slot.? != existing_highest_slot + 1)
        {
            std.debug.print(
                "refusing_append=true reason=min_slot_must_follow_existing_highest existing_highest_slot={} requested_min_slot={}\n",
                .{ existing_highest_slot, args.min_slot.? },
            );
            return error.AppendMinSlotMismatch;
        }
        std.debug.print(
            "chrs_ledger_append_plan=pass existing_highest_slot={} append_min_slot={} append_max_slot={}\n",
            .{ existing_highest_slot, args.min_slot.?, args.max_slot.? },
        );
    }

    var batch = ArrayList(Shred).init(allocator);
    defer {
        deinitBatch(&batch);
        batch.deinit();
    }
    try batch.ensureTotalCapacity(args.batch_shreds);

    var stats: Stats = .{};
    var timer = try std.time.Timer.start();
    if (args.recover) {
        if (args.leader_schedule_path) |leader_schedule_path| {
            var schedule_file = try std.fs.cwd().openFile(leader_schedule_path, .{});
            defer schedule_file.close();
            var leader_schedule = try LeaderSchedule.read(allocator, schedule_file.deprecatedReader());
            defer leader_schedule.deinit(allocator);
            const leader_schedules: LeaderSchedules = .{
                .curr = leader_schedule,
                .prev = null,
                .next = null,
            };
            try verifyScheduleCoverage(&args, &leader_schedules);
            try ingestAll(allocator, &ledger, &args, &batch, &stats, &leader_schedules);
        } else {
            var checkpoint = try ReducedCheckpoint.readFromFilePath(allocator, args.checkpoint_path.?);
            defer checkpoint.deinit(allocator);
            var manifest = try checkpoint.toManifest(allocator);
            defer manifest.deinit(allocator);
            var epoch_tracker = try sig.core.EpochTracker.initFromManifest(
                allocator,
                &manifest,
                &.ALL_DISABLED,
            );
            defer epoch_tracker.deinit();
            var schedules_with_infos = try epoch_tracker.getLeaderSchedules();
            defer schedules_with_infos.release();
            try verifyScheduleCoverage(&args, &schedules_with_infos.leader_schedules);
            try ingestAll(
                allocator,
                &ledger,
                &args,
                &batch,
                &stats,
                &schedules_with_infos.leader_schedules,
            );
        }
    } else {
        try ingestAll(allocator, &ledger, &args, &batch, &stats, null);
    }

    const elapsed_ns = timer.read();
    const elapsed_ms = elapsed_ns / std.time.ns_per_ms;
    const candidates_per_second = if (elapsed_ns == 0)
        0
    else
        stats.insertion_candidates * std.time.ns_per_s / elapsed_ns;
    std.debug.print(
        "chrs_ledger_ingest_result pass=true frames={} packet_bytes={} parsed_shreds={} non_shred_packets={} skipped_before_min={} skipped_after_max={} insertion_candidates={} insertion_batches={} completed_data_sets={} duplicate_proofs={} verify_slot_shreds={} verify_slot_valid={} verify_slot_invalid={} verify_slot_leader_missing={} first_inserted_slot={?} last_inserted_slot={?} elapsed_ms={} candidates_per_second={}\n",
        .{
            stats.frames,
            stats.packet_bytes,
            stats.parsed_shreds,
            stats.non_shred_packets,
            stats.skipped_before_min,
            stats.skipped_after_max,
            stats.insertion_candidates,
            stats.insertion_batches,
            stats.completed_data_sets,
            stats.duplicate_proofs,
            stats.verify_slot_shreds,
            stats.verify_slot_valid,
            stats.verify_slot_invalid,
            stats.verify_slot_leader_missing,
            stats.first_inserted_slot,
            stats.last_inserted_slot,
            elapsed_ms,
            candidates_per_second,
        },
    );
}

fn parseArgs(argv: []const []const u8, args: *Args) !void {
    var i: usize = 1;
    while (i < argv.len) : (i += 1) {
        const arg = argv[i];
        if (std.mem.eql(u8, arg, "--write")) {
            args.write = true;
        } else if (std.mem.eql(u8, arg, "--append")) {
            args.append = true;
        } else if (std.mem.eql(u8, arg, "--recover")) {
            args.recover = true;
        } else if (std.mem.eql(u8, arg, "--ledger")) {
            i += 1;
            if (i >= argv.len) return error.MissingLedgerPath;
            args.ledger_path = argv[i];
        } else if (std.mem.eql(u8, arg, "--checkpoint")) {
            i += 1;
            if (i >= argv.len) return error.MissingCheckpointPath;
            args.checkpoint_path = argv[i];
        } else if (std.mem.eql(u8, arg, "--leader-schedule")) {
            i += 1;
            if (i >= argv.len) return error.MissingLeaderSchedulePath;
            args.leader_schedule_path = argv[i];
        } else if (std.mem.eql(u8, arg, "--spool")) {
            i += 1;
            if (i >= argv.len) return error.MissingSpoolPath;
            try args.spool_paths.append(argv[i]);
        } else if (std.mem.eql(u8, arg, "--min-slot")) {
            i += 1;
            if (i >= argv.len) return error.MissingMinSlot;
            args.min_slot = try std.fmt.parseUnsigned(Slot, argv[i], 10);
        } else if (std.mem.eql(u8, arg, "--max-slot")) {
            i += 1;
            if (i >= argv.len) return error.MissingMaxSlot;
            args.max_slot = try std.fmt.parseUnsigned(Slot, argv[i], 10);
        } else if (std.mem.eql(u8, arg, "--verify-slot")) {
            i += 1;
            if (i >= argv.len) return error.MissingVerifySlot;
            args.verify_slot = try std.fmt.parseUnsigned(Slot, argv[i], 10);
        } else if (std.mem.eql(u8, arg, "--batch-shreds")) {
            i += 1;
            if (i >= argv.len) return error.MissingBatchShreds;
            args.batch_shreds = try std.fmt.parseUnsigned(usize, argv[i], 10);
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            printUsage();
            std.process.exit(0);
        } else {
            return error.UnknownArgument;
        }
    }

    if (args.ledger_path == null) return error.MissingLedgerPath;
    if (args.spool_paths.items.len == 0) return error.MissingSpoolPath;
    const recovery_source_count = @intFromBool(args.checkpoint_path != null) +
        @intFromBool(args.leader_schedule_path != null);
    if (args.recover and recovery_source_count == 0) return error.RecoveryRequiresLeaderSource;
    if (args.recover and recovery_source_count > 1) return error.MultipleRecoveryLeaderSources;
    if (!args.recover and recovery_source_count != 0) return error.LeaderSourceRequiresRecovery;
    if (args.verify_slot != null and !args.recover) return error.VerifySlotRequiresRecovery;
    if (args.min_slot == null or args.min_slot.? == 0) return error.InvalidMinSlot;
    if (args.max_slot == null or args.max_slot.? < args.min_slot.?) return error.InvalidMaxSlot;
    if (args.batch_shreds == 0 or args.batch_shreds > 65_536) return error.InvalidBatchShreds;
}

fn printUsage() void {
    std.debug.print(
        "usage: chrs-ledger-ingest [--write] [--append] [--recover (--checkpoint <reduced-checkpoint.bin> | --leader-schedule <leader-schedule.txt>)] [--verify-slot <slot>] --ledger <isolated-/private/tmp/chrs-ledger-path> --spool <completed.chrs> [--spool <completed.chrs> ...] --min-slot <slot> --max-slot <slot> [--batch-shreds <1..65536>]\n",
        .{},
    );
}

fn verifyScheduleCoverage(args: *const Args, leader_schedules: *const LeaderSchedules) !void {
    _ = leader_schedules.getLeaderOrNull(args.min_slot.?) orelse
        return error.MinSlotLeaderMissing;
    _ = leader_schedules.getLeaderOrNull(args.max_slot.?) orelse
        return error.MaxSlotLeaderMissing;
    if (args.verify_slot) |verify_slot| {
        const leader = leader_schedules.getLeaderOrNull(verify_slot) orelse
            return error.VerifySlotLeaderMissing;
        std.debug.print(
            "chrs_ledger_verify_slot_plan slot={} leader={s}\n",
            .{ verify_slot, leader.base58String().slice() },
        );
    }
}

fn ingestAll(
    allocator: Allocator,
    ledger: *Ledger,
    args: *const Args,
    batch: *ArrayList(Shred),
    stats: *Stats,
    leader_schedules: ?*const LeaderSchedules,
) !void {
    for (args.spool_paths.items) |spool_path| {
        try ingestSpoolFile(
            allocator,
            ledger,
            spool_path,
            args.min_slot.?,
            args.max_slot.?,
            args.batch_shreds,
            batch,
            stats,
            leader_schedules,
            args.verify_slot,
        );
    }
    try flushBatch(allocator, ledger, batch, stats, leader_schedules);
}

fn requireInternalPath(path: []const u8) !void {
    if (std.mem.eql(u8, path, "/Volumes") or std.mem.startsWith(u8, path, "/Volumes/")) {
        return error.ExternalVolumePathRejected;
    }
}

fn requireSafeLedgerPath(path: []const u8, append: bool) !void {
    try requireInternalPath(path);
    if (!std.mem.startsWith(u8, path, "/private/tmp/") or
        std.mem.indexOf(u8, path, "chrs-ledger") == null)
    {
        std.debug.print(
            "refusing_write=true reason=unsafe_ledger_path expected=/private/tmp/*chrs-ledger* actual={s}\n",
            .{path},
        );
        return error.UnsafeLedgerPath;
    }

    var dir = std.fs.cwd().openDir(path, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => if (append) return error.AppendLedgerMissing else return,
        else => return err,
    };
    defer dir.close();
    var iterator = dir.iterate();
    const first_entry = try iterator.next();
    if (!append) {
        if (first_entry != null) return error.LedgerPathNotEmpty;
        return;
    }
    if (first_entry == null) return error.AppendLedgerEmpty;
    var current = dir.openFile("rocksdb/CURRENT", .{}) catch
        return error.AppendLedgerMissingRocksDbCurrent;
    current.close();
}

fn ingestSpoolFile(
    allocator: Allocator,
    ledger: *Ledger,
    spool_path: []const u8,
    min_slot: Slot,
    max_slot: Slot,
    batch_shreds: usize,
    batch: *ArrayList(Shred),
    stats: *Stats,
    leader_schedules: ?*const LeaderSchedules,
    verify_slot: ?Slot,
) !void {
    var file = try std.fs.cwd().openFile(spool_path, .{});
    defer file.close();

    var packet: [MAX_PACKET_BYTES]u8 = undefined;
    while (true) {
        var header: [CHRS_HEADER_LEN]u8 = undefined;
        const header_read = try file.readAll(&header);
        if (header_read == 0) break;
        if (header_read != CHRS_HEADER_LEN) return error.TruncatedChrsHeader;

        const magic = std.mem.readInt(u32, header[0..4], .little);
        const packet_len_u32 = std.mem.readInt(u32, header[4..8], .little);
        const packet_len: usize = @intCast(packet_len_u32);
        if (magic != CHRS_MAGIC or packet_len == 0 or packet_len > packet.len) {
            return error.InvalidChrsFrame;
        }
        if (try file.readAll(packet[0..packet_len]) != packet_len) return error.TruncatedChrsPacket;

        stats.frames += 1;
        stats.packet_bytes += packet_len;
        var shred = Shred.fromPayload(allocator, packet[0..packet_len]) catch {
            stats.non_shred_packets += 1;
            continue;
        };
        errdefer shred.deinit();
        stats.parsed_shreds += 1;
        const slot = shred.commonHeader().slot;
        if (verify_slot != null and slot == verify_slot.?) {
            stats.verify_slot_shreds += 1;
            if (leader_schedules) |schedules| {
                if (schedules.getLeaderOrNull(slot)) |leader| {
                    if (shred.verify(leader)) |_| {
                        stats.verify_slot_valid += 1;
                    } else |_| {
                        stats.verify_slot_invalid += 1;
                    }
                } else {
                    stats.verify_slot_leader_missing += 1;
                }
            } else {
                stats.verify_slot_leader_missing += 1;
            }
        }
        if (slot < min_slot) {
            stats.skipped_before_min += 1;
            shred.deinit();
            continue;
        }
        if (slot > max_slot) {
            stats.skipped_after_max += 1;
            shred.deinit();
            continue;
        }

        stats.first_inserted_slot = if (stats.first_inserted_slot) |first| @min(first, slot) else slot;
        stats.last_inserted_slot = if (stats.last_inserted_slot) |last| @max(last, slot) else slot;
        try batch.append(shred);
        stats.insertion_candidates += 1;
        if (batch.items.len >= batch_shreds) {
            try flushBatch(allocator, ledger, batch, stats, leader_schedules);
        }
    }
}

fn flushBatch(
    allocator: Allocator,
    ledger: *Ledger,
    batch: *ArrayList(Shred),
    stats: *Stats,
    leader_schedules: ?*const LeaderSchedules,
) !void {
    if (batch.items.len == 0) return;
    const repaired = try allocator.alloc(bool, batch.items.len);
    defer allocator.free(repaired);
    @memset(repaired, false);

    var insertion = try ledger.shredInserter().insertShreds(
        allocator,
        batch.items,
        repaired,
        .{
            .is_trusted = true,
            .leader_schedules = leader_schedules,
            .skip_recovery = leader_schedules == null,
            .skip_shred_tracker = true,
            .skip_data_recovery_meta_load = leader_schedules == null,
        },
    );
    defer insertion.deinit();
    stats.insertion_batches += 1;
    stats.completed_data_sets += insertion.completed_data_set_infos.items.len;
    stats.duplicate_proofs += insertion.duplicate_shreds.items.len;
    deinitBatch(batch);
}

fn deinitBatch(batch: *ArrayList(Shred)) void {
    for (batch.items) |shred| shred.deinit();
    batch.clearRetainingCapacity();
}
