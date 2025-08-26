const std = @import("std");
const sig = @import("../sig.zig");

const shred_layout = sig.ledger.shred.layout;

const Atomic = std.atomic.Value;

const Channel = sig.sync.Channel;
const Counter = sig.prometheus.Counter;
const Histogram = sig.prometheus.Histogram;
const Packet = sig.net.Packet;
const Registry = sig.prometheus.Registry;
const SlotLeaders = sig.core.leader_schedule.SlotLeaders;
const VariantCounter = sig.prometheus.VariantCounter;

const VerifiedMerkleRoots = sig.utils.lru.LruCache(.non_locking, sig.core.Hash, void);

/// Analogous to [verify_shred_cpu](https://github.com/anza-xyz/agave/blob/83e7d84bcc4cf438905d07279bc07e012a49afd9/ledger/src/sigverify_shreds.rs#L35)
pub fn verifyShred(
    packet: *const Packet,
    leader_schedule: SlotLeaders,
    verified_merkle_roots: *VerifiedMerkleRoots,
    metrics: Metrics,
) ShredVerificationFailure!void {
    const shred = shred_layout.getShred(packet) orelse return error.insufficient_shred_size;
    const slot = shred_layout.getSlot(shred) orelse return error.slot_missing;
    const signature = shred_layout.getLeaderSignature(shred) orelse return error.signature_missing;
    const signed_data = shred_layout.merkleRoot(shred) orelse return error.signed_data_missing;

    if (verified_merkle_roots.get(signed_data)) |_| {
        return;
    }
    metrics.cache_miss_count.inc();
    const leader = leader_schedule.get(slot) orelse return error.leader_unknown;
    const valid = signature.verify(leader, &signed_data.data) catch
        return error.failed_verification;
    if (!valid) return error.failed_verification;
    verified_merkle_roots.insert(signed_data, {}) catch return error.failed_caching;
}

pub const ShredVerificationFailure = error{
    insufficient_shred_size,
    slot_missing,
    signature_missing,
    signed_data_missing,
    leader_unknown,
    failed_verification,
    failed_caching,
};

pub const Metrics = struct {
    received_count: *Counter,
    verified_count: *Counter,
    cache_miss_count: *Counter,
    batch_size: *Histogram,
    fail: *VariantCounter(ShredVerificationFailure),

    pub const prefix = "shred_verifier";
    pub const histogram_buckets = sig.prometheus.histogram.exponentialBuckets(2, -1, 8);
};
