const std = @import("std");
const lib = @import("lib.zig");

pub const download = @import("snapshot/download.zig");

comptime {
    if (@import("builtin").is_test) {
        _ = @import("snapshot/download.zig");
    }
}

pub const SnapshotSourceRing = lib.ipc.Ring(256, SnapshotSource);

pub const SnapshotSource = extern struct {
    from: lib.solana.Pubkey,
    rpc_addr: lib.gossip.Address,
    slot: lib.solana.Slot,
    hash: lib.solana.Hash,
};

pub const SnapshotConfig = extern struct {
    // TODO: Can this be configurable at runtime in the future? Requires dynamically sizing this config region.
    pub const MAX_KNOWN_VALIDATORS = 64;

    folder_buffer: [std.fs.max_path_bytes]u8,
    folder_len: u32,
    cluster: lib.solana.Cluster,
    known_validators_buffer: [MAX_KNOWN_VALIDATORS]lib.solana.Pubkey,
    known_validators_len: u32,

    /// If true, the snapshot can be downloaded from any peer (explicit "*" opt-in).
    /// NOTE: When true, `known_validators_len` is 0.
    known_validators_allow_all: bool,

    pub const KnownValidators = union(enum) {
        allow_all,
        set: []const lib.solana.Pubkey,

        pub fn trusts(self: KnownValidators, pk: lib.solana.Pubkey) bool {
            return switch (self) {
                .allow_all => true,
                .set => |kvs| pk.indexIn(kvs) != null,
            };
        }
    };

    pub fn knownValidators(self: *const SnapshotConfig) KnownValidators {
        if (self.known_validators_allow_all) return .allow_all;
        return .{ .set = self.known_validators_buffer[0..self.known_validators_len] };
    }
};
