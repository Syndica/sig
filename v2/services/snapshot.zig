const std = @import("std");
const start = @import("start");
const lib = @import("lib");
const tel = lib.telemetry;

const Pair = lib.net.Pair;
const Packet = lib.net.Packet;

const Pubkey = lib.solana.Pubkey;
const Signature = lib.solana.Signature;

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
};

pub fn serviceMain(ro: ReadOnly, rw: ReadWrite) !noreturn {
    const logger = rw.tel.acquireLogger(@tagName(name), "snapshot");
    rw.tel.signalReady();

    const folder_path = ro.config.folder_buffer[0..ro.config.folder_len];
    const cluster_rpc_url = ro.config.cluster.getRpcUrl();

    logger.info().logf(
        "snapshot path {s} -- {s}",
        .{
            folder_path,
            cluster_rpc_url,
        },
    );

    // * make an HTTP request
    // * have fun!

    while (true) {}
}
