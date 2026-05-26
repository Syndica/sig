const std = @import("std");
const start = @import("start_service");
const lib = @import("lib");
const tel = lib.telemetry;

const download = lib.snapshot.download;

const SnapshotSourceRing = lib.snapshot.SnapshotSourceRing;
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
    config: *const lib.snapshot.SnapshotConfig,
};

pub const ReadWrite = struct {
    gossip_to_snapshot: *SnapshotSourceRing,
    tel: *tel.Region,
};

pub fn serviceMain(runner: lib.runner.Connection, ro: ReadOnly, rw: ReadWrite) !noreturn {
    _ = runner;
    const logger = rw.tel.acquireLogger(@tagName(name), "snapshot");
    const metrics = rw.tel.metricAppender().appendFields(Metrics, Metrics.fields_config);

    rw.tel.signalReady();

    const snapshot_dir = ro.config.folder_buffer[0..ro.config.folder_len];
    const known_validators = ro.config.knownValidators();

    const result: DownloadResult = result: {
        var snapshot_dir_handle = try std.fs.cwd().makeOpenPath(snapshot_dir, .{ .iterate = true });
        defer snapshot_dir_handle.close();

        logger.info().logf("snapshot path {s}", .{snapshot_dir});

        if (try download.findExistingSnapshot(snapshot_dir_handle)) |existing| {
            break :result .{ .already_exists = existing };
        }

        var downloader = try Downloader.init(
            rw.gossip_to_snapshot,
            known_validators,
            snapshot_dir_handle,
            metrics,
            logger,
        );
        defer downloader.deinit();

        break :result try downloader.run();
    };

    switch (result) {
        .already_exists => |existing| {
            logger.info().logf("snapshot already exists, skipping download name={f}", .{
                existing,
            });
        },
        .downloaded => |snapshot| {
            logger.info().logf("snapshot download completed slot={d} hash={f} path={s}/{f}", .{
                snapshot.slot,
                snapshot.hash,
                snapshot_dir,
                snapshot,
            });
        },
        .failed => |reason| {
            logger.err().logf("snapshot download failed reason={s}", .{
                @tagName(reason),
            });
        },
    }

    // TODO: load snapshot and stream to accountsdb service.
    while (true) std.atomic.spinLoopHint();
}
