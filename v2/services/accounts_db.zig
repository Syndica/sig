const std = @import("std");
const start = @import("start_service");
const lib = @import("lib");

const tel = lib.telemetry;

const SnapshotConfig = lib.snapshot.SnapshotConfig;
const SnapshotReadyRing = lib.snapshot.SnapshotReadyRing;
const SnapshotIter = lib.solana.snapshot.SnapshotIter;

const Rooted = lib.accounts_db.Rooted;
const RootedConfig = lib.accounts_db.RootedConfig;
const AccountPool = lib.accounts_db.AccountPool;
const AccountLookups = lib.accounts_db.AccountLookups;

comptime {
    _ = start;
}

pub const name = .accounts_db;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadOnly = struct {
    snapshot_config: *const SnapshotConfig,
};

pub const ReadWrite = struct {
    ready_snapshot_in: *SnapshotReadyRing,
    rooted_config: *RootedConfig,
    account_pool: *AccountPool,
    replay_lookups: *AccountLookups,
    tel: *tel.Region,
};

pub fn serviceMain(ro: ReadOnly, rw: ReadWrite) !noreturn {
    const logger = rw.tel.acquireLogger(@tagName(name), "main");
    rw.tel.signalReady();

    const file_path = rw.rooted_config.file_path[0..rw.rooted_config.file_len];
    logger.info().logf("accounts_db started into file: {s}", .{file_path});

    const Global = struct {
        var fba_memory: [32 * 1024 * 1024]u8 = blk: {
            @setRuntimeSafety(false);
            break :blk undefined;
        };
        var snapshot_iter: SnapshotIter = blk: {
            @setRuntimeSafety(false);
            break :blk undefined;
        };
        var rooted: Rooted = blk: {
            @setRuntimeSafety(false);
            break :blk undefined;
        };
    };

    const rooted = &Global.rooted;
    try rooted.init(
        .from(logger),
        std.fs.cwd(),
        file_path,
        rw.rooted_config.memory[0..].ptr[0..rw.rooted_config.memory_len],
        rw.account_pool,
    );
    defer rooted.deinit();

    if (rooted.table.count == 0) {
        logger.info().logf("no existing rooted db. waiting for ready snapshot", .{});

        var snapshot_path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const snapshot_path: []const u8 = blk: {
            var ready_snapshot_iter = rw.ready_snapshot_in.get(.reader);
            while (true) : (std.atomic.spinLoopHint()) {
                const ready_ptr = ready_snapshot_iter.next() orelse continue;
                defer ready_snapshot_iter.markUsed();
                break :blk try ready_ptr.name(&snapshot_path_buf);
            }
        };

        const dir_path = ro.snapshot_config.folder_buffer[0..ro.snapshot_config.folder_len];
        logger.info().logf("reading snapshot {s}/{s}", .{ dir_path, snapshot_path });

        var snapshot_dir = try std.fs.cwd().openDir(
            ro.snapshot_config.folder_buffer[0..ro.snapshot_config.folder_len],
            .{},
        );
        defer snapshot_dir.close();

        var fba = std.heap.FixedBufferAllocator.init(&Global.fba_memory);
        const snapshot_iter = &Global.snapshot_iter;
        try snapshot_iter.init(
            .from(logger),
            &fba,
            snapshot_dir,
            snapshot_path,
        );
        defer snapshot_iter.deinit();

        logger.info().logf("reading snapshot accounts", .{});
        try rooted.loadSnapshot(.from(logger), snapshot_iter);
    }

    {
        logger.info().logf("looking up feature accounts", .{});

        const features = lib.solana.features;
        const FeatureSet = features.Set;

        var feature_set = FeatureSet.ALL_DISABLED;
        const slot = rooted.journal.committed_slot;
        const allow_new_activations = true;

        try rooted.beginTransaction(.from(logger), slot);

        var new_activations = FeatureSet.ALL_DISABLED;
        var inactive_iterator = feature_set.iterator(slot, .inactive);
        while (inactive_iterator.next()) |feature| {
            const feature_id = features.pubkey_map.get(feature);

            std.debug.assert(try rooted.queueRead(.from(logger), &feature_id));
            const result = while (true) break (try rooted.pollRead(.from(logger))) orelse {
                std.atomic.spinLoopHint();
                continue;
            };

            logger.info().logf(
                "feature lookup: {s}: pubkey:{f} idx:{}",
                .{@tagName(feature), result.pubkey, result.account_index },
            );

            if (result.account_index == AccountPool.invalid_index) {
                continue;
            }

            const acc = rooted.account_pool.getAccount(result.account_index);
            logger.info().logf("feature:{s} pubkey:{f} owner:{f} lamports:{} data:{} ({any})\n", .{
                @tagName(feature),
                acc.pubkey,
                acc.owner,
                acc.lamports,
                acc.getData().len,
                acc.getData(),
            });

            switch (try features.activationStateFromAccount(acc.owner, acc.getData())) {
                .activated => |activation_slot| if (slot >= activation_slot) feature_set.setSlot(
                    feature,
                    activation_slot,
                ),
                .pending => if (allow_new_activations) {
                    feature_set.setSlot(feature, slot);
                    new_activations.setSlot(feature, slot);

                    var new_data: [9]u8 = undefined;
                    new_data[0] = 1;
                    std.mem.writeInt(u64, new_data[1..9], slot, .little);
                    
                    var r = std.Io.Reader.fixed(&new_data);
                    try rooted.put(
                        .from(logger),
                        slot,
                        acc.pubkey,
                        acc.owner,
                        acc.lamports,
                        acc.rent_epoch,
                        acc.data.executable,
                        acc.data.len,
                        &r,
                    );
                    logger.info().logf("Feature {} activated at slot {}", .{ feature, slot });
                },
                .invalid => continue,
            }
        }

        if (allow_new_activations) feature_set = new_activations;

        try rooted.commitTransaction(.from(logger));
    }

    logger.info().logf("accounts_db loaded - servicing replay requests", .{});

    var replay_in = rw.replay_lookups.in.get(.reader);
    var replay_out = rw.replay_lookups.out.get(.writer);
    while (true) : (std.atomic.spinLoopHint()) {
        if (replay_in.peek()) |pubkey| {
            if (try rooted.queueRead(.from(logger), pubkey)) {
                _ = replay_in.next();
                replay_in.markUsed();
            }
        }
        if (replay_out.peek()) |result| {
            if (try rooted.pollRead(.from(logger))) |res| {
                result.* = res;
                _ = replay_out.next();
                replay_out.markUsed();
            }
        }
    }
}


// const features = lib.solana.features;
// const Slot = lib.solana.Slot;

// /// Iterate through the inactive features and:
// /// 1. Try and load the feature account from the accounts db.
// /// 2. If the account exists, check if it has been activated already.
// /// 3. If it has been activated, add it to the active set.
// /// 4. If it has not been activated, and new activations are allowed,
// ///    add it to the active set and activate it by setting the slot
// ///    and writing it back to the accounts db.
// fn computeFeatureSet(
//     logger: tel.Logger("computeFeatureSet"),
//     feature_set: *features.Set,
//     allow_new_activations: bool,
//     slot: Slot,
//     accountsb_db: anytype,
// ) !void {
//     // queueRead(self, logger, *pubkey) !bool
//     // pollRead(self, logger) !?
//     // freeRead(self, )
    
// }