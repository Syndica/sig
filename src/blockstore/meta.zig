const std = @import("std");
const sig = @import("../lib.zig");

const BitFlags = sig.utils.bitflags.BitFlags;
const Slot = sig.core.Slot;

/// The Meta column family
pub const SlotMeta = struct {
    /// The number of slots above the root (the genesis block). The first
    /// slot has slot 0.
    slot: Slot,
    /// The total number of consecutive shreds starting from index 0 we have received for this slot.
    /// At the same time, it is also an index of the first missing shred for this slot, while the
    /// slot is incomplete.
    consumed: u64,
    /// The index *plus one* of the highest shred received for this slot.  Useful
    /// for checking if the slot has received any shreds yet, and to calculate the
    /// range where there is one or more holes: `(consumed..received)`.
    received: u64,
    /// The timestamp of the first time a shred was added for this slot
    first_shred_timestamp: u64,
    /// The index of the shred that is flagged as the last shred for this slot.
    /// None until the shred with LAST_SHRED_IN_SLOT flag is received.
    last_index: ?u64,
    /// The slot height of the block this one derives from.
    /// The parent slot of the head of a detached chain of slots is None.
    parent_slot: ?Slot,
    /// The list of slots, each of which contains a block that derives
    /// from this one.
    next_slots: []const Slot,
    /// Connected status flags of this slot
    connected_flags: ConnectedFlags,
    /// Shreds indices which are marked data complete.  That is, those that have the
    /// [`ShredFlags::DATA_COMPLETE_SHRED`][`crate::shred::ShredFlags::DATA_COMPLETE_SHRED`] set.
    completed_data_indexes: std.AutoHashMap(u32, void),
};

/// Flags to indicate whether a slot is a descendant of a slot on the main fork
pub const ConnectedFlags = BitFlags(enum(u8) {
    // A slot S should be considered to be connected if:
    // 1) S is a rooted slot itself OR
    // 2) S's parent is connected AND S is full (S's complete block present)
    //
    // 1) is a straightfoward case, roots are finalized blocks on the main fork
    // so by definition, they are connected. All roots are connected, but not
    // all connected slots are (or will become) roots.
    //
    // Based on the criteria stated in 2), S is connected iff it has a series
    // of ancestors (that are each connected) that form a chain back to
    // some root slot.
    //
    // A ledger that is updating with a cluster will have either begun at
    // genesis or at at some snapshot slot.
    // - Genesis is obviously a special case, and slot 0's parent is deemed
    //   to be connected in order to kick off the induction
    // - Snapshots are taken at rooted slots, and as such, the snapshot slot
    //   should be marked as connected so that a connected chain can start
    //
    // CONNECTED is explicitly the first bit to ensure backwards compatibility
    // with the boolean field that ConnectedFlags replaced in SlotMeta.
    connected = 0b0000_0001,
    // PARENT_CONNECTED IS INTENTIIONALLY UNUSED FOR NOW
    parent_connected = 0b1000_0000,
});

pub const DuplicateSlotProof = struct {
    // #[serde(with = "serde_bytes")]
    shred1: []const u8,
    // #[serde(with = "serde_bytes")]
    shred2: []const u8,
};

/// Erasure coding information
pub const ErasureMeta = struct {
    /// Which erasure set in the slot this is
    fec_set_index: u64,
    /// First coding index in the FEC set
    first_coding_index: u64,
    /// Index of the first received coding shred in the FEC set
    first_received_coding_index: u64,
    /// Erasure configuration for this erasure set
    config: ErasureConfig,
};

pub const ErasureConfig = struct {
    num_data: usize,
    num_coding: usize,
};

/// Index recording presence/absence of shreds
pub const Index = struct {
    slot: Slot,
    data: ShredIndex,
    coding: ShredIndex,
};

pub const ShredIndex = struct {
    /// Map representing presence/absence of shreds
    index: std.AutoHashMap(u64, void),
};

pub const TransactionStatusMeta = sig.blockstore.transaction_status.TransactionStatusMeta;

pub const AddressSignatureMeta = struct {
    writeable: bool,
};

pub const TransactionStatusIndexMeta = struct {
    max_slot: Slot,
    frozen: bool,
};

pub const Reward = sig.blockstore.transaction_status.Reward;

pub const UnixTimestamp = i64;

// TODO consider union
pub const PerfSample = struct {
    tag: u32 = 1, // for binary compatibility with rust enum serialization
    // `PerfSampleV1` part
    num_transactions: u64,
    num_slots: u64,
    sample_period_secs: u16,

    // New fields.
    num_non_vote_transactions: u64,
};

pub const ProgramCost = struct {
    cost: u64,
};

pub const FrozenHashVersioned = union(enum) {
    Current: FrozenHashStatus,
};

pub const FrozenHashStatus = struct {
    frozen_hash: sig.core.Hash,
    is_duplicate_confirmed: bool,
};

pub const OptimisticSlotMetaVersioned = union(enum) {
    V0: OptimisticSlotMetaV0,
};

pub const OptimisticSlotMetaV0 = struct {
    hash: sig.core.Hash,
    timestamp: UnixTimestamp,
};

pub const ErasureSetId = struct {
    slot: Slot,
    fec_set_index: u64,
};

pub const MerkleRootMeta = struct {
    /// The merkle root, `None` for legacy shreds
    merkle_root: ?sig.core.Hash,
    /// The first received shred index
    first_received_shred_index: u32,
    /// The shred type of the first received shred
    first_received_shred_type: sig.shred_collector.shred.ShredType,
};
