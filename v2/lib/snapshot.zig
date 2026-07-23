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

/// A deserialized snapshot Manifest + StatusCache.
///
/// All variable-sized data (blockhash queue is fixed at 300 entries inline;
/// pubkey maps, vote-account chains, etc.) points into the trailing `memory` (manifestBase)
/// VLA via `snapshot.RelativeSlice` / `snapshot.RelativeOffset`.
///
/// Before a consumer reads the fields, it must call `getSlotBlocking()`.
/// The producer that sets the fields will call `populateSlot()` to mark them as consumable.
pub const SnapshotMetadata = extern struct {
    slot: std.atomic.Value(u64),

    manifest: lib.solana.snapshot.Manifest,
    status_cache: lib.solana.snapshot.StatusCache,

    memory_len: usize,
    memory: [0]u8 align(16), // VLA for [0..memory_len]

    // 0 may be a valid slot, so use something that will never be reached.
    const invalid_slot = std.math.maxInt(Slot);

    pub fn init(self: *SnapshotMetadata, memory_len: usize) void {
        self.slot = .init(invalid_slot);
        self.memory_len = memory_len;
    }

    /// Returns the base pointer used to resolve `RelativeSlice`/`RelativeOffset`
    /// values inside `manifest` / `status_cache`.
    pub fn manifestBase(self: *SnapshotMetadata) [*]u8 {
        return @ptrCast(&self.memory);
    }

    /// Unblocks all getSlotBlocking() callers with the given slot value.
    /// Can be called only once.
    /// Should also only call after all other SnapshotMetadata fields are populated.
    pub fn populateSlot(self: *SnapshotMetadata, slot: Slot) void {
        std.debug.assert(slot != invalid_slot);
        std.debug.assert(self.slot.swap(slot, .release) == invalid_slot);
    }

    pub fn getSlotBlocking(self: *SnapshotMetadata, runner: lib.runner.Connection) !Slot {
        while (true) {
            const slot = self.slot.load(.acquire);
            if (slot != invalid_slot) {
                try runner.activity.signalActive();
                return slot;
            }
            try runner.activity.signalIdleSpinning();
        }
    }
};
