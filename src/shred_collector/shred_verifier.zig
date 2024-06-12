const std = @import("std");
const sig = @import("../lib.zig");
const shred_collector = @import("lib.zig");

const shred_layout = shred_collector.shred.layout;

const ArrayList = std.ArrayList;
const Atomic = std.atomic.Value;

const Channel = sig.sync.Channel;
const SlotLeaderProvider = sig.core.leader_schedule.SlotLeaderProvider;
const Packet = sig.net.Packet;

/// Analogous to [run_shred_sigverify](https://github.com/anza-xyz/agave/blob/8c5a33a81a0504fd25d0465bed35d153ff84819f/turbine/src/sigverify_shreds.rs#L82)
pub fn runShredVerifier(
    exit: *Atomic(bool),
    /// shred receiver --> me
    unverified_shred_receiver: *Channel(ArrayList(Packet)),
    /// me --> shred processor
    verified_shred_sender: *Channel(ArrayList(Packet)),
    leader_schedule: SlotLeaderProvider,
) !void {
    var verified_count: usize = 0;
    var buf = ArrayList(ArrayList(Packet)).init(unverified_shred_receiver.allocator);
    while (true) {
        try unverified_shred_receiver.tryDrainRecycle(&buf);
        if (buf.items.len == 0) {
            std.time.sleep(10 * std.time.ns_per_ms);
            continue;
        }
        for (buf.items) |packet_batch| {
            // TODO parallelize this once it's actually verifying signatures
            for (packet_batch.items) |*packet| {
                if (!verifyShred(packet, leader_schedule)) {
                    packet.flags.set(.discard);
                } else {
                    verified_count += 1;
                }
            }
            try verified_shred_sender.send(packet_batch);
            if (exit.load(.monotonic)) return;
        }
    }
}

/// verify_shred_cpu
fn verifyShred(packet: *const Packet, leader_schedule: SlotLeaderProvider) bool {
    if (packet.flags.isSet(.discard)) return false;
    const shred = shred_layout.getShred(packet) orelse return false;
    const slot = shred_layout.getSlot(shred) orelse return false;
    const signature = shred_layout.getSignature(shred) orelse return false;
    const signed_data = shred_layout.getSignedData(shred) orelse return false;

    const leader = leader_schedule.call(slot) orelse return false;

    return signature.verify(leader, &signed_data.data);
}
