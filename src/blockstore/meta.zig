const std = @import("std");
const sig = @import("../lib.zig");

const Allocator = std.mem.Allocator;

const BitFlags = sig.utils.bitflags.BitFlags;
const Shred = sig.shred_collector.shred.Shred;
const CodingShred = sig.shred_collector.shred.CodingShred;
const Slot = sig.core.Slot;
const SortedSet = sig.utils.collections.SortedSet;

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
    next_slots: std.ArrayList(Slot),
    /// Connected status flags of this slot
    connected_flags: ConnectedFlags,
    /// Shreds indices which are marked data complete.  That is, those that have the
    /// [`ShredFlags::DATA_COMPLETE_SHRED`][`crate::shred::ShredFlags::DATA_COMPLETE_SHRED`] set.
    completed_data_indexes: SortedSet(u32),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, slot: Slot, parent_slot: ?Slot) Self {
        const connected_flags = if (slot == 0)
            // Slot 0 is the start, mark it as having its' parent connected
            // such that slot 0 becoming full will be updated as connected
            ConnectedFlags.from(.parent_connected)
        else
            ConnectedFlags{};
        return .{
            .slot = slot,
            .parent_slot = parent_slot,
            .connected_flags = connected_flags,
            .consumed = 0,
            .received = 0,
            .first_shred_timestamp = 0,
            .last_index = null,
            .next_slots = std.ArrayList(Slot).init(allocator),
            .completed_data_indexes = SortedSet(u32).init(allocator),
        };
    }

    pub fn deinit(self: Self) void {
        self.next_slots.deinit();
    }

    pub fn clone(self: Self, allocator: Allocator) Allocator.Error!Self {
        var next_slots = try std.ArrayList(Slot).initCapacity(allocator, self.next_slots.items.len);
        next_slots.appendSliceAssumeCapacity(self.next_slots.items);
        return .{
            .slot = self.slot,
            .parent_slot = self.parent_slot,
            .connected_flags = self.connected_flags,
            .consumed = self.consumed,
            .received = self.received,
            .first_shred_timestamp = self.first_shred_timestamp,
            .last_index = self.last_index,
            .next_slots = next_slots,
            .completed_data_indexes = try self.completed_data_indexes.clone(),
        };
    }

    pub fn eql(self: *Self, other: *Self) bool {
        return self.slot == other.slot and
            self.consumed == other.consumed and
            self.received == other.received and
            self.first_shred_timestamp == other.first_shred_timestamp and
            self.last_index == other.last_index and
            self.parent_slot == other.parent_slot and
            std.mem.eql(Slot, self.next_slots.items, other.next_slots.items) and
            self.connected_flags.state == other.connected_flags.state and
            self.completed_data_indexes.eql(&other.completed_data_indexes);
    }

    pub fn isFull(self: Self) bool {
        return if (self.last_index) |last_index|
            self.consumed > last_index + 1
        else
            false;
    }

    pub fn isOrphan(self: Self) bool {
        return self.parent_slot == null;
    }

    pub fn isConnected(self: *Self) bool {
        return self.connected_flags.isSet(.connected);
    }

    pub fn setConnected(self: *Self) void {
        std.debug.assert(self.isParentConnected());
        self.connected_flags.set(.connected);
    }

    pub fn isParentConnected(self: Self) bool {
        return self.connected_flags.isSet(.parent_connected);
    }

    /// Mark the meta's parent as connected.
    /// If the meta is also full, the meta is now connected as well. Return a
    /// boolean indicating whether the meta becamed connected from this call.
    pub fn setParentConnected(self: *Self) bool {
        // Already connected so nothing to do, bail early
        if (self.isConnected()) {
            return false;
        }

        self.connected_flags.set(.parent_connected);

        if (self.isFull()) {
            self.setConnected();
        }

        return self.isConnected();
    }
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
    shred1: []const u8,
    shred2: []const u8,
};

/// Erasure coding information
/// TODO: why does this need such large integer types?
pub const ErasureMeta = struct {
    /// Which erasure set in the slot this is
    fec_set_index: u64,
    /// First coding index in the FEC set
    first_coding_index: u64,
    /// Index of the first received coding shred in the FEC set
    first_received_coding_index: u64,
    /// Erasure configuration for this erasure set
    config: ErasureConfig,

    const Self = @This();

    pub fn fromCodingShred(shred: CodingShred) ?Self {
        return .{
            .fec_set_index = @intCast(shred.fields.common.fec_set_index),
            .config = ErasureConfig{
                .num_data = @intCast(shred.fields.custom.num_data_shreds),
                .num_coding = @intCast(shred.fields.custom.num_coding_shreds),
            },
            .first_coding_index = @intCast(shred.firstCodingIndex() catch return null),
            .first_received_coding_index = @intCast(shred.fields.common.index),
        };
    }

    /// Returns true if the erasure fields on the shred
    /// are consistent with the erasure-meta.
    pub fn checkCodingShred(self: Self, shred: CodingShred) bool {
        var other = fromCodingShred(shred) orelse return false;
        other.first_received_coding_index = self.first_received_coding_index;
        return sig.utils.types.eql(self, other);
    }

    /// Analogous to [status](https://github.com/anza-xyz/agave/blob/7a9317fe25621c211fe4ab5491b88a4757d4b6d4/ledger/src/blockstore_meta.rs#L442)
    pub fn status(self: Self, index: *Index) union(enum) {
        can_recover,
        data_full,
        still_need: usize,
    } {
        const c_start, const c_end = self.codingShredsIndices();
        const d_start, const d_end = self.dataShredsIndices();
        const num_code = index.code.range(c_start, c_end).len;
        const num_data = index.data.range(d_start, d_end).len;

        const data_missing = self.config.num_data -| num_data;
        const num_needed = data_missing -| num_code;

        return if (data_missing == 0)
            .data_full
        else if (num_needed == 0)
            .can_recover
        else
            .{ .still_need = num_needed };
    }

    /// Analogous to [data_shreds_indices](https://github.com/anza-xyz/agave/blob/7a9317fe25621c211fe4ab5491b88a4757d4b6d4/ledger/src/blockstore_meta.rs#L422)
    pub fn dataShredsIndices(self: Self) [2]u64 {
        const num_data = self.config.num_data;
        return .{ self.fec_set_index, self.fec_set_index + num_data };
    }

    /// Analogous to [coding_shreds_indices](https://github.com/anza-xyz/agave/blob/7a9317fe25621c211fe4ab5491b88a4757d4b6d4/ledger/src/blockstore_meta.rs#L428)
    pub fn codingShredsIndices(self: Self) [2]u64 {
        const num_coding = self.config.num_coding;
        return .{ self.first_coding_index, self.first_coding_index + num_coding };
    }

    /// Analogous to [next_fec_set_index](https://github.com/anza-xyz/agave/blob/7a9317fe25621c211fe4ab5491b88a4757d4b6d4/ledger/src/blockstore_meta.rs#L437)
    pub fn nextFecSetIndex(self: Self) ?u32 {
        const num_data: u32 = @intCast(self.config.num_data);
        return sig.utils.math.checkedSub(@as(u32, @intCast(self.fec_set_index)), num_data) catch null;
    }
};

/// TODO: usize seems like a poor choice here, but i just copied agave
pub const ErasureConfig = struct {
    num_data: usize,
    num_coding: usize,
};

/// Index recording presence/absence of shreds
pub const Index = struct {
    slot: Slot,
    data: ShredIndex,
    code: ShredIndex,

    pub fn init(allocator: std.mem.Allocator, slot: Slot) Index {
        return .{
            .slot = slot,
            .data = ShredIndex.init(allocator),
            .code = ShredIndex.init(allocator),
        };
    }
};

pub const ShredIndex = SortedSet(u64);

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

pub const MerkleRootMeta = struct {
    /// The merkle root, `None` for legacy shreds
    merkle_root: ?sig.core.Hash,
    /// The first received shred index
    first_received_shred_index: u32,
    /// The shred type of the first received shred
    first_received_shred_type: sig.shred_collector.shred.ShredType,

    pub fn fromShred(shred: Shred) MerkleRootMeta {
        return .{
            // An error here after the shred has already sigverified
            // can only indicate that the leader is sending
            // legacy or malformed shreds. We should still store
            // `None` for those cases in blockstore, as a later
            // shred that contains a proper merkle root would constitute
            // a valid duplicate shred proof.
            .merkle_root = shred.merkleRoot() catch null,
            .first_received_shred_index = shred.commonHeader().index,
            .first_received_shred_type = shred,
        };
    }
};
