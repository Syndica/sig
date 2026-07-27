const std = @import("std");
const lib = @import("lib.zig");

const Slot = lib.solana.Slot;
const Hash = lib.solana.Hash;

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

    /// Populates a shared-memory SnapshotConfig from parsed config fields.
    /// Used by both the main validator topology (v2/init/main.zig) and the
    /// offline replay topology (v2/tests/replay_offline/main.zig).
    ///
    /// `known_validators` must be non-empty. A single `"*"` entry opts into
    /// downloading from any peer (untrusted). Otherwise every entry must be
    /// a valid base58 Pubkey.
    pub fn populate(
        self: *SnapshotConfig,
        folder: []const u8,
        known_validators: []const []const u8,
        cluster: lib.solana.Cluster,
    ) !void {
        if (folder.len > std.fs.max_path_bytes) {
            std.log.err(
                "snapshot folder path too long: {d} bytes (max {d})",
                .{ folder.len, std.fs.max_path_bytes },
            );
            return error.PathTooLong;
        }
        if (known_validators.len == 0) {
            std.log.err(
                "known_validators must not be empty. Specify validator pubkeys, " ++
                    "or \"*\" to opt in to untrusted snapshot sources.",
                .{},
            );
            return error.NoKnownValidators;
        }
        if (known_validators.len > MAX_KNOWN_VALIDATORS) {
            return error.TooManyKnownValidators;
        }

        @memcpy(self.folder_buffer[0..folder.len], folder);
        self.folder_len = @intCast(folder.len);
        self.cluster = cluster;

        const has_wildcard = for (known_validators) |entry| {
            if (std.mem.eql(u8, entry, "*")) break true;
        } else false;

        if (has_wildcard) {
            if (known_validators.len > 1) {
                std.log.warn(
                    "known_validators contains \"*\" alongside other entries; " ++
                        "\"*\" takes precedence, ignoring the rest.",
                    .{},
                );
            }
            self.known_validators_allow_all = true;
            // NOTE: we zero out known_validators_len to make it clear that no validator pubkeys were provided.
            self.known_validators_len = 0;
        } else {
            self.known_validators_allow_all = false;
            self.known_validators_len = @intCast(known_validators.len);
            for (
                known_validators,
                self.known_validators_buffer[0..known_validators.len],
            ) |pkstr, *pkptr| {
                pkptr.* = lib.solana.Pubkey.parseRuntime(pkstr) catch |err| {
                    std.log.err(
                        "invalid known_validator entry '{s}': {s}",
                        .{ pkstr, @errorName(err) },
                    );
                    return err;
                };
            }
        }
    }
};

// Holds decompressed snapshot data given to accounts_db service
pub const SnapshotData = extern struct {
    ring: lib.ipc.Ring(16 * 1024 * 1024, u8),
    completion: std.atomic.Value(f64),

    pub fn init(self: *SnapshotData) void {
        self.ring.init();
        self.completion = .init(0);
    }
};

pub const ReadySnapshot = extern struct {
    slot: Slot,
    hash: Hash,

    pub fn format(self: *const ReadySnapshot, writer: *std.Io.Writer) !void {
        return try writer.print("snapshot-{d}-{f}.tar.zst", .{ self.slot, self.hash });
    }

    pub fn name(self: *const ReadySnapshot, buf: []u8) ![]const u8 {
        return try std.fmt.bufPrint(buf, "{f}", .{self});
    }
};
