const std = @import("std");
const start = @import("start_service");
const lib = @import("lib");
const services = @import("services");
const tel = lib.telemetry;

const download = lib.snapshot.download;

const Metrics = download.Metrics;
const DownloadResult = download.DownloadResult;
const Downloader = download.Downloader;

comptime {
    _ = start;
}

pub const name = .snapshot;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadOnly = services.snapshot.ReadOnly;
pub const ReadWrite = services.snapshot.ReadWrite;

pub fn serviceMain(runner: lib.runner.Connection, ro: ReadOnly, rw: ReadWrite) !noreturn {
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

    { // Send the decompressed snapshot data to accounts_db service
        const Global = struct {
            var zst_reader: lib.solana.snapshot.ZstReader = undefined;
        };

        var snapshot_path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const snapshot_path = try ready_snapshot.name(&snapshot_path_buf);

        const zst_reader = &Global.zst_reader;
        try zst_reader.init(snapshot_dir, snapshot_path);
        defer zst_reader.deinit();

        var out = rw.ready_snapshot_out.ring.getView(.writer);
        defer out.close();

        while (true) {
            const buf: []u8 = try out.getBufferBlocking(runner);
            if (buf.len == 0) break; // reader closed their side

            // cap decompress size to ensure advance() is called frequently enough to unblock rooted
            const decompressed = buf[0..@min(buf.len, 128 * 1024)];
            const n = try zst_reader.read(.from(logger), decompressed);

            // Update the completion value
            const total: f64 = @floatFromInt(zst_reader.file_size);
            const consumed: f64 = @floatFromInt(zst_reader.file_reader.getOffset());
            var completion = @min(100.0, (consumed * 100) / total);
            if (zst_reader.file_size == 0) completion = 100.0; // guard against 0-len snapshots
            rw.ready_snapshot_out.completion.store(completion, .monotonic);

            if (n == 0) break; // file reader EOF
            out.advance(n);
        }
    }

    logger.info().logf("snapshot service finished", .{});
    while (true) try runner.activity.signalIdleSpinning();
}

test "service has required declarations" {
    try std.testing.expectEqual(.snapshot, name);
    const ro_fields = @typeInfo(ReadOnly).@"struct".fields;
    const rw_fields = @typeInfo(ReadWrite).@"struct".fields;
    try std.testing.expect(ro_fields.len > 0);
    try std.testing.expect(rw_fields.len > 0);
}
