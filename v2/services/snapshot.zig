const std = @import("std");
const start = @import("start_service");
const lib = @import("lib");
const tel = lib.telemetry;

const download = lib.snapshot.download;

const SnapshotConfig = lib.snapshot.SnapshotConfig;
const SnapshotSourceRing = lib.snapshot.SnapshotSourceRing;
const SnapshotReadyRing = lib.snapshot.SnapshotReadyRing;
const SnapshotIter = lib.solana.snapshot.SnapshotIter;

const Metrics = download.Metrics;
const DownloadResult = download.DownloadResult;
const Downloader = download.Downloader;

comptime {
    _ = start;
}

// Note: matches services.zon name
pub const name = .snapshot;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadOnly = struct {
    config: *const SnapshotConfig,
};

pub const ReadWrite = struct {
    gossip_to_snapshot: *SnapshotSourceRing,
    snapshot_to_accounts_db: *SnapshotReadyRing,
    tel: *tel.Region,
};

pub fn serviceMain(ro: ReadOnly, rw: ReadWrite) !noreturn {
    const logger = rw.tel.acquireLogger(@tagName(name), "main");
    const metrics = rw.tel.metricAppender().appendFields(Metrics, Metrics.fields_config);
    rw.tel.signalReady();

    const snapshot_dir_path = ro.config.folder_buffer[0..ro.config.folder_len];
    const known_validators = ro.config.knownValidators();

    const result: DownloadResult = result: {
        var snapshot_dir = try std.fs.cwd().makeOpenPath(snapshot_dir_path, .{ .iterate = true });
        defer snapshot_dir.close();

        logger.info().logf("snapshot path {s}", .{snapshot_dir_path});

        if (try download.findExistingSnapshot(snapshot_dir)) |existing| {
            break :result .{ .already_exists = existing };
        }

        var downloader = try Downloader.init(
            rw.gossip_to_snapshot,
            known_validators,
            snapshot_dir,
            metrics,
            .from(logger),
        );
        defer downloader.deinit();

        break :result try downloader.run();
    };

    const ready_snapshot = switch (result) {
        .already_exists => |existing| blk: {
            logger.info().logf("snapshot already exists, skipping download name={f}", .{
                existing,
            });
            break :blk existing;
        },
        .downloaded => |snapshot| blk: {
            logger.info().logf("snapshot download completed slot={d} hash={f} path={s}/{f}", .{
                snapshot.slot,
                snapshot.hash,
                snapshot_dir_path,
                snapshot,
            });
            break :blk snapshot;
        },
        .failed => |reason| {
            logger.err().logf("snapshot download failed reason={s}", .{
                @tagName(reason),
            });
            return error.SnapshotDownloadFailed;
        },
    };

    {
        var ready_snapshot_writer = rw.snapshot_to_accounts_db.get(.writer);
        const ready_ptr = ready_snapshot_writer.next() orelse unreachable;
        ready_ptr.* = ready_snapshot;
        ready_snapshot_writer.markUsed();
    }

    logger.info().logf("snapshot service finished", .{});
    while (true) std.atomic.spinLoopHint();
}
