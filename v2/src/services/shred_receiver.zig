//! This service listens on a ringbuffer of packets, and validates, verifies, and deserialises
//! shreds.

const std = @import("std");
const start = @import("start");
const common = @import("common");

const shred = common.shred;
const layout = shred.layout;

const Pair = common.net.Pair;
const Packet = common.net.Packet;
const Slot = common.solana.Slot;
const Pubkey = common.solana.Pubkey;
const Atomic = std.atomic.Value;

comptime {
    _ = start;
}

pub const name: []const u8 = "shred_receiver";
pub const _start = {};
pub const panic = start.panic;

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

pub fn main(writer: *std.io.Writer, ro: ReadOnly, rw: ReadWrite) !noreturn {
    try writer.print("Waiting for shreds on port {}\n", .{rw.pair.port});

    var fba_buf: [16 * 1024]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&fba_buf);
    const allocator = fba.allocator();

    while (true) {
        defer fba.reset();

        var slice = rw.pair.recv.getReadable() catch continue;
        const packet = slice.one();
        defer slice.markUsed(1);

        validateShred(packet, stub_root_slot, &stub_shred_version, stub_max_slot) catch |err| {
            try writer.print("invalid shred: {}\n", .{err});
            continue;
        };

        verifyShred(packet, ro.leader_schedule) catch |err| {
            _ = err catch {};
            try writer.print("failed to verify shred: {}\n", .{err});
            continue;
        };

        // TODO: this is where we might retransmit

        const payload = layout.getShred(packet, false) orelse {
            try writer.print("failed to get shred\n", .{});
            continue;
        };

        const packet_shred = shred.Shred.fromPayload(allocator, payload) catch |err| {
            try writer.print(
                "failed to deserialize verified shred {?}.{?}: {}\n",
                .{ layout.getSlot(payload), layout.getIndex(payload), err },
            );
            continue;
        };

        try writer.print(
            \\slot: {}
            \\erasure_set_index: {}
            \\index: {}
            \\shred_type: {}
            \\
            \\
        , .{
            packet_shred.commonHeader().slot,
            packet_shred.commonHeader().erasure_set_index,
            packet_shred.commonHeader().index,
            packet_shred.commonHeader().variant.shred_type,
        });
    }
}

fn validateShred(
    packet: *const Packet,
    root: Slot,
    shred_version: *const Atomic(u16),
    max_slot: Slot,
) ShredValidationError!void {
    const packet_shred = layout.getShred(packet, false) orelse return error.insufficient_shred_size;
    const version = layout.getVersion(packet_shred) orelse return error.missing_version;
    const slot = layout.getSlot(packet_shred) orelse return error.slot_missing;
    const index = layout.getIndex(packet_shred) orelse return error.index_missing;
    const variant = layout.getShredVariant(packet_shred) orelse return error.variant_missing;

    if (version != shred_version.load(.acquire)) return error.wrong_version;
    if (slot > max_slot) return error.slot_too_new;
    switch (variant.shred_type) {
        .code => {
            if (index >= shred.CodeShred.constants.max_per_slot) {
                return error.code_index_too_high;
            }
            if (slot <= root) return error.rooted_slot;
        },
        .data => {
            if (index >= shred.DataShred.constants.max_per_slot) {
                return error.data_index_too_high;
            }
            const parent_slot_offset = layout.getParentSlotOffset(packet_shred) orelse {
                return error.parent_slot_offset_missing;
            };
            const parent = slot -| @as(Slot, @intCast(parent_slot_offset));
            if (!verifyShredSlots(slot, parent, root)) return error.slot_verification_failed;
        },
    }

    // TODO: check for feature activation of enable_chained_merkle_shreds
    // 7uZBkJXJ1HkuP6R3MJfZs7mLwymBcDbKdqbF51ZWLier
    // https://github.com/solana-labs/solana/pull/34916
    // https://github.com/solana-labs/solana/pull/35076

    _ = layout.getLeaderSignature(packet_shred) orelse return error.signature_missing;
    _ = layout.merkleRoot(packet_shred) orelse return error.signed_data_missing;
}

fn verifyShredSlots(slot: Slot, parent: Slot, root: Slot) bool {
    if (slot == 0 and parent == 0 and root == 0) {
        return true; // valid write to slot zero.
    }
    // Ignore shreds that chain to slots before the root,
    // or have invalid parent >= slot.
    return root <= parent and parent < slot;
}

/// Something about the shred was unexpected, so we will discard it.
pub const ShredValidationError = error{
    insufficient_shred_size,
    missing_version,
    slot_missing,
    index_missing,
    variant_missing,
    wrong_version,
    slot_too_new,
    code_index_too_high,
    rooted_slot,
    data_index_too_high,
    parent_slot_offset_missing,
    slot_verification_failed,
    signature_missing,
    signed_data_missing,
};

/// Analogous to [verify_shred_cpu](https://github.com/anza-xyz/agave/blob/83e7d84bcc4cf438905d07279bc07e012a49afd9/ledger/src/sigverify_shreds.rs#L35)
pub fn verifyShred(
    packet: *const Packet,
    leader_schedule: *const common.solana.LeaderSchedule,
    // verified_merkle_roots: *VerifiedMerkleRoots,
    // metrics: Metrics,
) ShredVerificationFailure!void {
    const shred_ = layout.getShred(packet, false) orelse return error.InsufficientShredSize;
    const slot = layout.getSlot(shred_) orelse return error.SlotMissing;
    const signature = layout.getLeaderSignature(shred_) orelse return error.SignatureMissing;
    const signed_data = layout.merkleRoot(shred_) orelse return error.SignedDataMissing;

    // if (verified_merkle_roots.get(signed_data) != null) return;

    // metrics.cache_miss_count.inc();
    const leader = leader_schedule.get(slot) orelse return error.LeaderUnknown;

    signature.verify(leader, &signed_data.data) catch return error.FailedVerification;
    // verified_merkle_roots.insert(signed_data, {}) catch return error.FailedCaching;
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
