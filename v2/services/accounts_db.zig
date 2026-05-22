const std = @import("std");
const start = @import("start_service");
const lib = @import("lib");
const tel = lib.telemetry;

comptime {
    _ = start;
}

pub const name = .accounts_db;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadOnly = struct {
    snapshot_config: *const lib.snapshot.SnapshotConfig,
};

pub const ReadWrite = struct {
    rooted_config: *lib.accounts_db.RootedConfig,
    pool: *lib.accounts_db.AccountPool,
    snapshot_to_accounts_db: *lib.snapshot.SnapshotReadyRing,
    replay_lookups: *lib.accounts_db.AccountLookups,
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
        var snapshot_iter: lib.solana.snapshot.SnapshotIter = blk: {
            @setRuntimeSafety(false);
            break :blk undefined;
        };
        var rooted: lib.accounts_db.Rooted = blk: {
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
    );
    defer rooted.deinit();

    if (rooted.table.count == 0) {
        logger.info().logf("no existing rooted db. waiting for ready snapshot", .{});

        var snapshot_path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const snapshot_path: []const u8 = blk: {
            var ready_snapshot_iter = rw.snapshot_to_accounts_db.get(.reader);
            while (true) : (std.atomic.spinLoopHint()) {
                const ready_ptr = ready_snapshot_iter.next() orelse continue;
                defer ready_snapshot_iter.markUsed();
                break :blk try ready_ptr.name(&snapshot_path_buf);
            }
        };

        const dir_path = ro.snapshot_config.folder_buffer[0..ro.snapshot_config.folder_len];
        logger.info().logf("reading snapshot {s}/{s}", .{dir_path, snapshot_path});

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

    logger.info().logf("accounts_db finished", .{});
    while (true) std.atomic.spinLoopHint();
}
