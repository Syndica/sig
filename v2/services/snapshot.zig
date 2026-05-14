const std = @import("std");
const start = @import("start");
const lib = @import("lib");
const tel = lib.telemetry;

const download = lib.snapshot.download;

const SnapshotSourceRing = lib.snapshot.SnapshotSourceRing;
const Metrics = download.Metrics;
const DownloadResult = download.DownloadResult;
const Downloader = download.Downloader;

var dedupe_map_buf: [512 * 1024]u8 = @splat(0);

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
    tel: *tel.Region,
    gossip_to_snapshot: *SnapshotSourceRing,
};

pub fn serviceMain(ro: ReadOnly, rw: ReadWrite) !noreturn {
    const logger = rw.tel.acquireLogger(@tagName(name), "snapshot");
    const metrics = rw.tel.metricAppender().appendFields(Metrics, Metrics.fields_config);

    rw.tel.signalReady();

    const snapshot_dir = ro.config.folder_buffer[0..ro.config.folder_len];
    const known_validators = ro.config.knownValidators();

    const result: DownloadResult = result: {
        std.fs.cwd().makeDir(snapshot_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => |e| return e,
        };

        logger.info().logf("snapshot path {s}", .{snapshot_dir});

        if (try download.findExistingSnapshot(snapshot_dir)) |existing| {
            break :result .{ .already_exists = existing };
        }

        var dedupe_fba = std.heap.FixedBufferAllocator.init(&dedupe_map_buf);
        var downloader = try Downloader.init(
            rw.gossip_to_snapshot,
            dedupe_fba.allocator(),
            known_validators,
            snapshot_dir,
            metrics,
            logger,
        );
        defer downloader.deinit();

        break :result try downloader.run();
    };

    switch (result) {
        .already_exists => |existing| {
            logger.info().logf("snapshot already exists, skipping download name={s}", .{
                existing.name(),
            });
        },
        .downloaded => |snapshot| {
            logger.info().logf("snapshot download completed slot={d} hash={f} path={s}", .{
                snapshot.slot,
                snapshot.hash,
                snapshot.path(),
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
