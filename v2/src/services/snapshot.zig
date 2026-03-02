//! This service listens on a ringbuffer of packets, and validates, verifies, and deserialises
//! shreds.

const std = @import("std");
const start = @import("start");
const common = @import("common");
const tracy = @import("tracy");

const Slot = common.solana.Slot;
const Hash = common.solana.Hash;

comptime {
    _ = start;
}

pub const name = .snapshot;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadWrite = struct {
    contact_queue: *common.gossip.SnapshotContactQueue,
};

pub fn serviceMain(rw: ReadWrite) !noreturn {
    std.log.debug("Snapshot service started", .{});

    while (true) {
        var slice = rw.contact_queue.incoming.getReadable() catch continue;
        const event = slice.one();
        slice.markUsed(1);

        std.log.debug("Snapshot Event: {any}", .{event});
    }
}
