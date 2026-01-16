const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;

const BitFlags = sig.utils.bitflags.BitFlags;
const Slot = sig.core.Slot;
const SortedSet = sig.utils.collections.SortedSet;
const UnixTimestamp = sig.core.UnixTimestamp;

const CodeShred = sig.ledger.shred.CodeShred;

/// The Meta column family
pub const SlotMeta = struct {
    /// The number of slots above the root (the genesis block). The first
    /// slot has slot 0.
    slot: Slot,
    /// The total number of consecutive shreds starting from index 0 we have received for this slot.
    /// At the same time, it is also an index of the first missing shred for this slot, while the
    /// slot is incomplete.
    consecutive_received_from_0: u64,
    /// The index *plus one* of the highest shred received for this slot.  Useful
    /// for checking if the slot has received any shreds yet, and to calculate the
    /// range where there is one or more holes: `(consumed..received)`.
    received: u64,
    /// The timestamp of the first time a shred was added for this slot
    first_shred_timestamp_milli: u64,
    /// The index of the shred that is flagged as the last shred for this slot.
    /// None until the shred with LAST_SHRED_IN_SLOT flag is received.
    last_index: ?u64,
    /// The slot height of the block this one derives from.
    /// The parent slot of the head of a detached chain of slots is None.
    parent_slot: ?Slot,
    /// The list of slots, each of which contains a block that derives
    /// from this one.
    child_slots: std.ArrayListUnmanaged(Slot),
    /// Connected status flags of this slot
    connected_flags: ConnectedFlags,
    /// Shreds indices which are marked data complete.  That is, those that have the
    /// [`ShredFlags::DATA_COMPLETE_SHRED`][`crate::shred::ShredFlags::DATA_COMPLETE_SHRED`] set.
    completed_data_indexes: DataIndexes,

    const DataIndexes = SortedSet(u32, .{ .empty_key = std.math.maxInt(u32) });

    const Self = @This();

    pub fn init(slot: Slot, parent_slot: ?Slot) Self {
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
            .consecutive_received_from_0 = 0,
            .received = 0,
            .first_shred_timestamp_milli = 0,
            .last_index = null,
            .child_slots = .empty,
            .completed_data_indexes = .empty,
        };
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        self.child_slots.deinit(allocator);
        self.completed_data_indexes.deinit(allocator);
    }

    pub fn clone(self: Self, allocator: Allocator) Allocator.Error!Self {
        var child_slots = try std.ArrayListUnmanaged(Slot).initCapacity(
            allocator,
            self.child_slots.items.len,
        );
        errdefer child_slots.deinit(allocator);
        child_slots.appendSliceAssumeCapacity(self.child_slots.items);
        return .{
            .slot = self.slot,
            .parent_slot = self.parent_slot,
            .connected_flags = self.connected_flags,
            .consecutive_received_from_0 = self.consecutive_received_from_0,
            .received = self.received,
            .first_shred_timestamp_milli = self.first_shred_timestamp_milli,
            .last_index = self.last_index,
            .child_slots = child_slots,
            .completed_data_indexes = try self.completed_data_indexes.clone(allocator),
        };
    }

    pub fn eql(self: *Self, other: *Self) bool {
        return self.slot == other.slot and
            self.consecutive_received_from_0 == other.consecutive_received_from_0 and
            self.received == other.received and
            self.first_shred_timestamp_milli == other.first_shred_timestamp_milli and
            self.last_index == other.last_index and
            self.parent_slot == other.parent_slot and
            std.mem.eql(Slot, self.child_slots.items, other.child_slots.items) and
            self.connected_flags.state == other.connected_flags.state and
            self.completed_data_indexes.eql(&other.completed_data_indexes);
    }

    pub fn isFull(self: Self) bool {
        if (self.last_index) |last_index| {
            std.debug.assert(self.consecutive_received_from_0 <= last_index + 1);
            return self.consecutive_received_from_0 == last_index + 1;
        } else {
            return false;
        }
    }

    pub fn isOrphan(self: Self) bool {
        return self.parent_slot == null;
    }

    pub fn isConnected(self: Self) bool {
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

/// Erasure code information
/// TODO: why does this need such large integer types?
pub const ErasureMeta = struct {
    /// Which erasure set in the slot this is
    erasure_set_index: u64,
    /// First code index in the FEC set
    first_code_index: u64,
    /// Index of the first received code shred in the FEC set
    first_received_code_index: u64,
    /// Erasure configuration for this erasure set
    config: ErasureConfig,

    const Self = @This();

    pub fn fromCodeShred(shred: CodeShred) ?Self {
        return .{
            .erasure_set_index = shred.common.erasure_set_index,
            .config = ErasureConfig{
                .num_data = shred.custom.num_data_shreds,
                .num_code = shred.custom.num_code_shreds,
            },
            .first_code_index = shred.firstCodeIndex() catch return null,
            .first_received_code_index = shred.common.index,
        };
    }

    /// Returns true if the erasure fields on the shred
    /// are consistent with the erasure-meta.
    pub fn checkCodeShred(self: Self, shred: CodeShred) bool {
        var other = fromCodeShred(shred) orelse return false;
        other.first_received_code_index = self.first_received_code_index;
        return sig.utils.types.eql(self, other);
    }

    /// Analogous to [status](https://github.com/anza-xyz/agave/blob/7a9317fe25621c211fe4ab5491b88a4757d4b6d4/ledger/src/blockstore_meta.rs#L442)
    pub fn status(self: Self, index: *Index) union(enum) {
        can_recover,
        data_full,
        still_need: usize,
    } {
        const c_start, const c_end = self.codeShredsIndices();
        const d_start, const d_end = self.dataShredsIndices();

        const num_code = blk: {
            var iter = index.code_index.iteratorRanged(c_start, c_end, .start);
            break :blk iter.countForwards();
        };
        const num_data = blk: {
            var iter = index.data_index.iteratorRanged(d_start, d_end, .start);
            break :blk iter.countForwards();
        };

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
        return .{ self.erasure_set_index, self.erasure_set_index + num_data };
    }

    /// Analogous to [code_shreds_indices](https://github.com/anza-xyz/agave/blob/7a9317fe25621c211fe4ab5491b88a4757d4b6d4/ledger/src/blockstore_meta.rs#L428)
    pub fn codeShredsIndices(self: Self) [2]u64 {
        const num_code = self.config.num_code;
        return .{ self.first_code_index, self.first_code_index + num_code };
    }

    /// Analogous to [next_erasure_set_index](https://github.com/anza-xyz/agave/blob/7a9317fe25621c211fe4ab5491b88a4757d4b6d4/ledger/src/blockstore_meta.rs#L437)
    pub fn nextErasureSetIndex(self: Self) ?u32 {
        const num_data: u32 = @intCast(self.config.num_data);
        return std.math.add(
            u32,
            @intCast(self.erasure_set_index),
            num_data,
        ) catch null;
    }
};

/// TODO: usize seems like a poor choice here, but i just copied agave
pub const ErasureConfig = struct {
    num_data: usize,
    num_code: usize,
};

/// Index recording presence/absence of shreds
pub const Index = struct {
    slot: Slot,
    data_index: ShredIndex,
    code_index: ShredIndex,

    pub fn init(slot: Slot) Index {
        return .{
            .slot = slot,
            .data_index = .empty,
            .code_index = .empty,
        };
    }

    pub fn deinit(self: *Index, allocator: std.mem.Allocator) void {
        self.data_index.deinit(allocator);
        self.code_index.deinit(allocator);
    }
};

pub const ShredIndex = SortedSet(u64, .{ .empty_key = std.math.maxInt(u64) });

pub const TransactionStatusMeta = sig.ledger.transaction_status.TransactionStatusMeta;

pub const AddressSignatureMeta = struct {
    writeable: bool,
};

pub const TransactionStatusIndexMeta = struct {
    max_slot: Slot,
    frozen: bool,
};

pub const Reward = sig.ledger.transaction_status.Reward;

// TODO consider union
pub const PerfSample = struct {
    version: u32 = 1, // for binary compatibility with rust enum serialization
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
    current: FrozenHashStatus,

    pub fn isDuplicateConfirmed(self: @This()) bool {
        return switch (self) {
            .current => |c| c.is_duplicate_confirmed,
        };
    }

    pub fn frozenHash(self: @This()) sig.core.Hash {
        return switch (self) {
            .current => |c| c.frozen_hash,
        };
    }
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
    first_received_shred_type: sig.ledger.shred.ShredType,

    pub fn fromFirstReceivedShred(shred: anytype) MerkleRootMeta {
        comptime std.debug.assert(
            @TypeOf(shred) == sig.ledger.shred.DataShred or
                @TypeOf(shred) == sig.ledger.shred.CodeShred,
        );
        return MerkleRootMeta{
            // An error here after the shred has already sigverified
            // can only indicate that the leader is sending
            // legacy or malformed shreds. We should still store
            // `None` for those cases in ledger, as a later
            // shred that contains a proper merkle root would constitute
            // a valid duplicate shred proof.
            .merkle_root = shred.merkleRoot() catch null,
            .first_received_shred_index = shred.common.index,
            .first_received_shred_type = shred.common.variant.shred_type,
        };
    }
};
