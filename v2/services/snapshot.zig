const std = @import("std");
const start = @import("start");
const lib = @import("lib");
const tel = lib.telemetry;

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
    gossip_to_snapshot: *lib.snapshot.SnapshotSourceRing,
};

pub fn serviceMain(ro: ReadOnly, rw: ReadWrite) !noreturn {
    const logger = rw.tel.acquireLogger(@tagName(name), "snapshot");
    rw.tel.signalReady();

    const folder_path = ro.config.folder_buffer[0..ro.config.folder_len];
    logger.info().logf("snapshot path {s}", .{folder_path});

    var it = rw.gossip_to_snapshot.get(.reader);
    while (true) {
        const source = it.next() orelse continue;
        logger.info().logf(
            "snapshot source {f} slot={d} hash={f}",
            .{ source.rpc_addr, source.slot, source.hash },
        );
        it.markUsed();
    }
}
