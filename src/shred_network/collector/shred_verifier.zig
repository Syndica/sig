const sig = @import("../../sig.zig");

const shred_layout = sig.ledger.shred.layout;

const Counter = sig.prometheus.Counter;
const Histogram = sig.prometheus.Histogram;
const Packet = sig.net.Packet;
const VariantCounter = sig.prometheus.VariantCounter;

const VerifiedMerkleRoots = sig.utils.lru.LruCache(.non_locking, sig.core.Hash, void);

/// Analogous to [verify_shred_cpu](https://github.com/anza-xyz/agave/blob/83e7d84bcc4cf438905d07279bc07e012a49afd9/ledger/src/sigverify_shreds.rs#L35)
pub fn verifyShred(
    packet: *const Packet,
    leader_schedule: *const sig.core.magic_leader_schedule.LeaderSchedules,
    verified_merkle_roots: *VerifiedMerkleRoots,
    metrics: Metrics,
) ShredVerificationFailure!void {
    const shred = shred_layout.getShred(packet) orelse return error.InsufficientShredSize;
    const slot = shred_layout.getSlot(shred) orelse return error.SlotMissing;
    const signature = shred_layout.getLeaderSignature(shred) orelse return error.SignatureMissing;
    const signed_data = shred_layout.merkleRoot(shred) orelse return error.SignedDataMissing;

    if (verified_merkle_roots.get(signed_data) != null) return;

    metrics.cache_miss_count.inc();
    const leader = leader_schedule.getLeader(slot) catch return error.LeaderUnknown;

    signature.verify(leader, &signed_data.data) catch return error.FailedVerification;
    verified_merkle_roots.insert(signed_data, {}) catch return error.FailedCaching;
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

pub const Metrics = struct {
    received_count: *Counter,
    verified_count: *Counter,
    cache_miss_count: *Counter,
    batch_size: *Histogram,
    fail: *VariantCounter(ShredVerificationFailure),

    pub const prefix = "shred_verifier";
    pub const histogram_buckets = sig.prometheus.histogram.exponentialBuckets(2, -1, 8);
};
