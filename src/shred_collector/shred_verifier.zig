const std = @import("std");
const sig = @import("../sig.zig");
const shred_collector = @import("lib.zig");

const shred_layout = sig.ledger.shred.layout;

const Atomic = std.atomic.Value;

const Channel = sig.sync.Channel;
const Counter = sig.prometheus.Counter;
const Histogram = sig.prometheus.Histogram;
const Packet = sig.net.Packet;
const Registry = sig.prometheus.Registry;
const SlotLeaderProvider = sig.core.leader_schedule.SlotLeaderProvider;
const VariantCounter = sig.prometheus.VariantCounter;

/// Analogous to [run_shred_sigverify](https://github.com/anza-xyz/agave/blob/8c5a33a81a0504fd25d0465bed35d153ff84819f/turbine/src/sigverify_shreds.rs#L82)
pub fn runShredVerifier(
    exit: *Atomic(bool),
    registry: *Registry(.{}),
    /// shred receiver --> me
    unverified_shred_receiver: *Channel(Packet),
    /// me --> shred processor
    verified_shred_sender: *Channel(Packet),
    /// me --> retransmit service
    retransmit_shred_sender: *Channel(Packet),
    leader_schedule: SlotLeaderProvider,
) !void {
    const metrics = try registry.initStruct(Metrics);
    while (!exit.load(.acquire) or
        unverified_shred_receiver.len() != 0)
    {
        var packet_count: usize = 0;
        while (unverified_shred_receiver.receive()) |packet| {
            packet_count += 1;
            metrics.received_count.inc();
            if (verifyShred(&packet, leader_schedule)) |_| {
                metrics.verified_count.inc();
                try verified_shred_sender.send(packet);
                try retransmit_shred_sender.send(packet);
            } else |err| {
                metrics.fail.observe(err);
            }
        }
        metrics.batch_size.observe(packet_count);
    }
}

/// Analogous to [verify_shred_cpu](https://github.com/anza-xyz/agave/blob/83e7d84bcc4cf438905d07279bc07e012a49afd9/ledger/src/sigverify_shreds.rs#L35)
fn verifyShred(
    packet: *const Packet,
    leader_schedule: SlotLeaderProvider,
) ShredVerificationFailure!void {
    const shred = shred_layout.getShred(packet) orelse return error.insufficient_shred_size;
    const slot = shred_layout.getSlot(shred) orelse return error.slot_missing;
    const signature = shred_layout.getSignature(shred) orelse return error.signature_missing;
    const signed_data = shred_layout.getSignedData(shred) orelse return error.signed_data_missing;
    const leader = leader_schedule.call(slot) orelse return error.leader_unknown;

    _ = signature.verify(leader, &signed_data.data) or return error.failed_verification;
}

pub const ShredVerificationFailure = error{
    insufficient_shred_size,
    slot_missing,
    signature_missing,
    signed_data_missing,
    leader_unknown,
    failed_verification,
};

const Metrics = struct {
    received_count: *Counter,
    verified_count: *Counter,
    batch_size: *Histogram,
    fail: *VariantCounter(ShredVerificationFailure),

    pub const prefix = "shred_verifier";
    pub const histogram_buckets = sig.prometheus.histogram.exponentialBuckets(2, -1, 8);
};
