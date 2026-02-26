//! This service listens on a ringbuffer of packets, and validates, verifies, and deserialises
//! shreds.

const std = @import("std");
const start = @import("start");
const common = @import("common");
const tracy = @import("tracy");

const shred = common.shred;
const layout = shred.layout;

const Pair = common.net.Pair;
const Packet = common.net.Packet;
const Slot = common.solana.Slot;
const Hash = common.solana.Hash;
const Atomic = std.atomic.Value;

comptime {
    _ = start;
}

pub const name = .shred_receiver;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadWrite = struct {
    pair: *Pair,
};

pub const ReadOnly = struct {
    leader_schedule: *const common.solana.LeaderSchedule,
};

// stubs
const stub_root_slot = 0;
const stub_shred_version: Atomic(u16) = .{ .raw = 29062 }; // TODO: port over getShredAndIPFromEchoServer
const stub_max_slot = std.math.maxInt(Slot); // TODO agave uses BankForks for this

pub fn serviceMain(ro: ReadOnly, rw: ReadWrite) !noreturn {
    std.log.info("Waiting for shreds on port {}", .{rw.pair.port});

    var verified_roots_fba_buf: [64 * 1024]u8 = undefined;
    var verified_roots_fba: std.heap.FixedBufferAllocator = .init(&verified_roots_fba_buf);
    const roots_allocator = verified_roots_fba.allocator();

    var verified_roots: VerifiedMerkleRoots = try .init(roots_allocator, 128);
    defer verified_roots.deinit(roots_allocator);

    while (true) {
        var slice = rw.pair.recv.getReadable() catch continue;

        const zone = tracy.Zone.init(@src(), .{ .name = "shred recv" });
        defer zone.deinit();

        const packet = slice.one();
        defer slice.markUsed(1);

        validateShred(packet, stub_root_slot, &stub_shred_version, stub_max_slot) catch |err| {
            std.log.debug("invalid shred: {}", .{err});
            continue;
        };

        verifyShred(packet, ro.leader_schedule, &verified_roots) catch |err| {
            std.log.debug("failed to verify shred: {}", .{err});
            continue;
        };

        // TODO: this is where we might retransmit

        const payload = layout.getShred(packet, false) orelse {
            std.log.debug("failed to get shred", .{});
            continue;
        };

        const packet_shred = shred.Shred.fromPayload(payload) catch |err| {
            std.log.debug(
                "failed to deserialize verified shred {?}.{?}: {}",
                .{ layout.getSlot(payload), layout.getIndex(payload), err },
            );
            continue;
        };

        std.log.debug(
            \\slot: {}
            \\erasure_set_index: {}
            \\index: {}
            \\shred_type: {}
            \\
        , .{
            packet_shred.commonHeader().slot,
            packet_shred.commonHeader().erasure_set_index,
            packet_shred.commonHeader().index,
            packet_shred.commonHeader().variant.shred_type,
        });
    }
}

const VerifiedMerkleRoots = struct {
    map: Map,
    max_count: u32,

    const Map = std.ArrayHashMapUnmanaged(Hash, void, MapContext, true);

    const MapContext = struct {
        pub fn hash(_: MapContext, pubkey: Hash) u32 {
            return @bitCast(pubkey.data[0..4].*);
        }

        pub fn eql(_: MapContext, a: Hash, b: Hash, _: usize) bool {
            return a.eql(&b);
        }
    };

    fn init(allocator: std.mem.Allocator, max_count: u32) !VerifiedMerkleRoots {
        var map: Map = .{};
        errdefer map.deinit(allocator);

        try map.ensureTotalCapacity(allocator, max_count);

        return .{ .map = map, .max_count = max_count };
    }

    fn deinit(self: *VerifiedMerkleRoots, allocator: std.mem.Allocator) void {
        self.map.deinit(allocator);
    }

    fn wasVerified(self: *VerifiedMerkleRoots, hash: *const Hash) bool {
        return self.map.contains(hash.*);
    }

    fn insert(self: *VerifiedMerkleRoots, hash: *const Hash) void {
        if (self.map.count() == self.max_count) self.map.orderedRemoveAt(0);
        self.map.putAssumeCapacityNoClobber(hash.*, {});
    }
};

fn validateShred(
    packet: *const Packet,
    root: Slot,
    shred_version: *const Atomic(u16),
    max_slot: Slot,
) ShredValidationError!void {
    const packet_shred = layout.getShred(packet, false) orelse return error.InsufficientShredSize;
    const version = layout.getVersion(packet_shred) orelse return error.MissingVersion;
    const slot = layout.getSlot(packet_shred) orelse return error.SlotMissing;
    const index = layout.getIndex(packet_shred) orelse return error.IndexMissing;
    const variant = layout.getShredVariant(packet_shred) orelse return error.VariantMissing;

    if (version != shred_version.load(.acquire)) return error.WrongVersion;
    if (slot > max_slot) return error.SlotTooNew;
    switch (variant.shred_type) {
        .code => {
            if (index >= shred.CodeShred.constants.max_per_slot) {
                return error.CodeIndexTooHigh;
            }
            if (slot <= root) return error.RootedSlot;
        },
        .data => {
            if (index >= shred.DataShred.constants.max_per_slot) {
                return error.DataIndexTooHigh;
            }
            const parent_slot_offset = layout.getParentSlotOffset(packet_shred) orelse {
                return error.ParentSlotOffsetMissing;
            };
            const parent = slot -| @as(Slot, @intCast(parent_slot_offset));
            if (!verifyShredSlots(slot, parent, root)) return error.SlotVerificationFailed;
        },
    }

    // TODO: check for feature activation of enable_chained_merkle_shreds
    // 7uZBkJXJ1HkuP6R3MJfZs7mLwymBcDbKdqbF51ZWLier
    // https://github.com/solana-labs/solana/pull/34916
    // https://github.com/solana-labs/solana/pull/35076
}

fn verifyShredSlots(slot: Slot, parent: Slot, root: Slot) bool {
    if (slot == 0 and parent == 0 and root == 0) {
        return true; // valid write to slot zero.
    }
    // Ignore shreds that chain to slots before the root,
    // or have invalid parent >= slot.
    return root <= parent and parent < slot;
}

/// Analogous to [verify_shred_cpu](https://github.com/anza-xyz/agave/blob/83e7d84bcc4cf438905d07279bc07e012a49afd9/ledger/src/sigverify_shreds.rs#L35)
pub fn verifyShred(
    packet: *const Packet,
    leader_schedule: *const common.solana.LeaderSchedule,
    verified_merkle_roots: *VerifiedMerkleRoots,
) ShredVerificationFailure!void {
    const zone = tracy.Zone.init(@src(), .{ .name = "verifyShred" });
    defer zone.deinit();

    const shred_ = layout.getShred(packet, false) orelse return error.InsufficientShredSize;
    const slot = layout.getSlot(shred_) orelse return error.SlotMissing;
    const signature = layout.getLeaderSignature(shred_) orelse return error.SignatureMissing;
    const signed_data = layout.merkleRoot(shred_) orelse return error.SignedDataMissing;

    if (verified_merkle_roots.wasVerified(&signed_data)) return;

    const leader = leader_schedule.get(slot) orelse return error.LeaderUnknown;

    signature.verify(leader, &signed_data.data) catch return error.FailedVerification;

    verified_merkle_roots.insert(&signed_data);
}

pub const ShredVerificationFailure = error{
    InsufficientShredSize,
    SlotMissing,
    SignatureMissing,
    SignedDataMissing,
    LeaderUnknown,
    FailedVerification,
    FailedCaching,
};

/// Something about the shred was unexpected, so we will discard it.
pub const ShredValidationError = error{
    InsufficientShredSize,
    MissingVersion,
    SlotMissing,
    IndexMissing,
    VariantMissing,
    WrongVersion,
    SlotTooNew,
    CodeIndexTooHigh,
    RootedSlot,
    DataIndexTooHigh,
    ParentSlotOffsetMissing,
    SlotVerificationFailed,
    SignatureMissing,
    SignedDataMissing,
};
