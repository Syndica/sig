const std = @import("std");
const start = @import("start_service");
const lib = @import("lib");
const tel = lib.telemetry;

const download = lib.snapshot.download;

const SnapshotConfig = lib.snapshot.SnapshotConfig;
const SnapshotSourceRing = lib.snapshot.SnapshotSourceRing;
const SnapshotReadyRing = lib.snapshot.SnapshotReadyRing;

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
    source_from_gossip: *SnapshotSourceRing,
    ready_snapshot_out: *SnapshotReadyRing,
    tel: *tel.Region,
};

pub fn serviceMain(ro: ReadOnly, rw: ReadWrite) !noreturn {
    const logger = rw.tel.acquireLogger(@tagName(name), "main");
    const metrics = rw.tel.metricAppender().appendFields(Metrics, Metrics.fields_config);
    rw.tel.signalReady();

    const snapshot_dir_path = ro.config.folder_buffer[0..ro.config.folder_len];
    const known_validators = ro.config.knownValidators();

    var snapshot_dir = try std.fs.cwd().makeOpenPath(snapshot_dir_path, .{ .iterate = true });
    defer snapshot_dir.close();

    const result: DownloadResult = result: {
        logger.info().logf("snapshot path {s}", .{snapshot_dir_path});

        if (try download.findExistingSnapshot(snapshot_dir)) |existing| {
            break :result .{ .already_exists = existing };
        }

        var downloader = try Downloader.init(
            rw.source_from_gossip,
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
        const Global = struct {
            var zst_reader: lib.solana.snapshot.ZstReader = blk: {
                @setRuntimeSafety(false);
                break :blk undefined;
            };
        };

        var snapshot_path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const snapshot_path = try ready_snapshot.name(&snapshot_path_buf);

        const zst_reader = &Global.zst_reader;
        try zst_reader.init(snapshot_dir, snapshot_path);
        defer zst_reader.deinit();

        var out = rw.ready_snapshot_out.getView(.writer);
        defer out.close();

        while (true) : (std.atomic.spinLoopHint()) {
            const buf: []u8 = out.getBuffer() orelse continue;
            if (buf.len == 0) break; // reader closed their side

            const n = try zst_reader.read(.from(logger), buf[0..@min(buf.len, 128 * 1024)]);
            if (n == 0) break;
            out.advance(n);
        }
    }

    logger.info().logf("snapshot service finished", .{});
    while (true) std.atomic.spinLoopHint();
}
