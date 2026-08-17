const std = @import("std");
const sig = @import("sig");

const Manifest = sig.accounts_db.snapshot.Manifest;
const FullAndIncrementalManifest = sig.accounts_db.snapshot.FullAndIncrementalManifest;
const ReducedCheckpoint = sig.accounts_db.snapshot.ReducedCheckpoint;
const Args = struct {
    full_manifest: ?[]u8 = null,
    incremental_manifest: ?[]u8 = null,
    out: ?[]u8 = null,
    dump: ?[]u8 = null,
};

pub fn main() !void {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    const args = parseArgs(allocator) catch |err| {
        std.debug.print(
            "usage: reduced-checkpoint-from-manifest --full-manifest <path> [--incremental-manifest <path>] --out <path>\n       reduced-checkpoint-from-manifest --dump <path>\nerror: {s}\n",
            .{@errorName(err)},
        );
        return err;
    };
    defer if (args.full_manifest) |path| allocator.free(path);
    defer if (args.incremental_manifest) |path| allocator.free(path);
    defer if (args.out) |path| allocator.free(path);
    defer if (args.dump) |path| allocator.free(path);

    if (args.dump) |path| {
        var checkpoint = try ReducedCheckpoint.readFromFilePath(allocator, path);
        defer checkpoint.deinit(allocator);

        const bank_fields = checkpoint.bank_fields;
        const expected_max_tick_height = (bank_fields.slot + 1) * bank_fields.ticks_per_slot;
        const expected_epoch = bank_fields.epoch_schedule.getEpoch(bank_fields.slot);
        const accounts_lt_hash_digest = sig.core.hash.Hash.init(
            checkpoint.bank_extra.accounts_lt_hash.constBytes(),
        );
        std.debug.print(
            "reduced_checkpoint_dump path={s} slot={} parent_slot={} bank_hash={s} parent_hash={s} accounts_lt_hash_digest={s} ticks_per_slot={} max_tick_height={} expected_max_tick_height={} max_tick_height_valid={} epoch={} expected_epoch={} epoch_valid={} block_height={} transaction_count={} capitalization={} rent_lamports_per_byte_year={} rent_exemption_threshold={} rent_burn_percent={} fee_burn_percent={}\n",
            .{
                path,
                bank_fields.slot,
                bank_fields.parent_slot,
                bank_fields.hash.base58String().slice(),
                bank_fields.parent_hash.base58String().slice(),
                accounts_lt_hash_digest.base58String().slice(),
                bank_fields.ticks_per_slot,
                bank_fields.max_tick_height,
                expected_max_tick_height,
                bank_fields.max_tick_height == expected_max_tick_height,
                bank_fields.epoch,
                expected_epoch,
                bank_fields.epoch == expected_epoch,
                bank_fields.block_height,
                bank_fields.transaction_count,
                bank_fields.capitalization,
                bank_fields.rent_collector.rent.lamports_per_byte_year,
                bank_fields.rent_collector.rent.exemption_threshold,
                bank_fields.rent_collector.rent.burn_percent,
                bank_fields.fee_rate_governor.burn_percent,
            },
        );
        std.debug.print(
            "reduced_checkpoint_epoch_stakes count={}\n",
            .{checkpoint.bank_extra.versioned_epoch_stakes.count()},
        );
        for (
            checkpoint.bank_extra.versioned_epoch_stakes.keys(),
            checkpoint.bank_extra.versioned_epoch_stakes.values(),
        ) |map_epoch, value| {
            std.debug.print(
                "reduced_checkpoint_epoch_stake map_epoch={} embedded_epoch={}\n",
                .{ map_epoch, value.current.stakes.epoch },
            );
        }
        var manifest = try checkpoint.toManifest(allocator);
        defer manifest.deinit(allocator);
        std.debug.print(
            "reduced_checkpoint_bank_stakes epoch={} vote_accounts={} stake_accounts={}\n",
            .{
                manifest.bank_fields.stakes.epoch,
                manifest.bank_fields.stakes.vote_accounts.vote_accounts.count(),
                manifest.bank_fields.stakes.stake_accounts.count(),
            },
        );
        var epoch_tracker = try sig.core.EpochTracker.initFromManifest(
            allocator,
            &manifest,
            &.ALL_DISABLED,
        );
        defer epoch_tracker.deinit();
        const next_slot = bank_fields.slot + 1;
        const next_epoch_info = try epoch_tracker.getEpochInfoNoOffset(
            next_slot,
            &manifest.bank_fields.ancestors,
        );
        defer next_epoch_info.release();
        std.debug.print(
            "reduced_checkpoint_epoch_tracker next_slot={} next_slot_epoch={} stake_epoch={}\n",
            .{
                next_slot,
                bank_fields.epoch_schedule.getEpoch(next_slot),
                next_epoch_info.stakes.stakes.epoch,
            },
        );
        var leader_schedules = try epoch_tracker.getLeaderSchedules();
        defer leader_schedules.release();
        const after_leader_lookup = try epoch_tracker.getEpochInfoNoOffset(
            next_slot,
            &manifest.bank_fields.ancestors,
        );
        defer after_leader_lookup.release();
        std.debug.print(
            "reduced_checkpoint_epoch_tracker_after_leader_schedules next_slot={} stake_epoch={}\n",
            .{ next_slot, after_leader_lookup.stakes.stakes.epoch },
        );
        return;
    }

    const full_manifest_path = args.full_manifest orelse return error.MissingFullManifest;
    const out_path = args.out orelse return error.MissingOutput;

    var full_manifest = try Manifest.readFromFilePath(allocator, full_manifest_path);
    defer full_manifest.deinit(allocator);

    const maybe_incremental_manifest: ?Manifest = if (args.incremental_manifest) |path|
        try Manifest.readFromFilePath(allocator, path)
    else
        null;
    defer if (maybe_incremental_manifest) |manifest| manifest.deinit(allocator);

    const combined: FullAndIncrementalManifest = .{
        .full = full_manifest,
        .incremental = maybe_incremental_manifest,
    };

    var collapsed = try combined.collapse(allocator);
    defer collapsed.deinit(allocator);

    var checkpoint = try sig.accounts_db.snapshot.ReducedCheckpoint.fromManifest(allocator, &collapsed);
    defer checkpoint.deinit(allocator);

    try checkpoint.writeToFilePath(out_path);

    std.debug.print(
        "reduced_checkpoint_written path={s} root_slot={} full_slot={} incremental_slot={?}\n",
        .{
            out_path,
            collapsed.bank_fields.slot,
            full_manifest.bank_fields.slot,
            if (maybe_incremental_manifest) |manifest| manifest.bank_fields.slot else null,
        },
    );
}

fn parseArgs(allocator: std.mem.Allocator) !Args {
    const raw = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, raw);

    var full_manifest: ?[]u8 = null;
    var incremental_manifest: ?[]u8 = null;
    var out: ?[]u8 = null;

    var i: usize = 1;
    while (i < raw.len) : (i += 1) {
        const arg = raw[i];
        if (std.mem.eql(u8, arg, "--full-manifest")) {
            i += 1;
            if (i >= raw.len) return error.MissingFullManifest;
            full_manifest = try allocator.dupe(u8, raw[i]);
        } else if (std.mem.eql(u8, arg, "--incremental-manifest")) {
            i += 1;
            if (i >= raw.len) return error.MissingIncrementalManifest;
            incremental_manifest = try allocator.dupe(u8, raw[i]);
        } else if (std.mem.eql(u8, arg, "--out")) {
            i += 1;
            if (i >= raw.len) return error.MissingOutput;
            out = try allocator.dupe(u8, raw[i]);
        } else if (std.mem.eql(u8, arg, "--dump")) {
            i += 1;
            if (i >= raw.len) return error.MissingDumpPath;
            return .{
                .dump = try allocator.dupe(u8, raw[i]),
            };
        } else {
            return error.UnknownArgument;
        }
    }

    return .{
        .full_manifest = full_manifest orelse return error.MissingFullManifest,
        .incremental_manifest = incremental_manifest,
        .out = out orelse return error.MissingOutput,
    };
}
