//! This service listens on a ringbuffer of packets, communicating with other solana gossip nodes to
//! share and broadcast validator contact information and events
//! (votes, duplicate_shred, fork restarts, snapshot hashes)

const std = @import("std");
const start = @import("start");
const common = @import("common");
const tracy = @import("tracy");

comptime {
    _ = start;
}

pub const name = .signer;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadWrite = struct {
    gossip_signer: *common.gossip.GossipSigner,
};

pub const ReadOnly = struct {
    identity_file_path: *const [:0]u8,
};

pub fn serviceMain(ro: ReadOnly, rw: ReadWrite) !noreturn {
    std.log.debug("Signer service started", .{});

    // TODO: load keypair from identity file
    _ = ro;
    const keypair: common.signer.KeyPair = .generate();

    while (true) {
        if (try rw.gossip_signer.tryCompleteSignature(&keypair)) |signed_bytes| {
            std.log.debug("Signed {} bytes from gossip", .{signed_bytes});
        }
    }
}