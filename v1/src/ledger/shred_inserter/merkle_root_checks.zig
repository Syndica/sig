const std = @import("std");
const sig = @import("../../sig.zig");
const ledger = @import("../lib.zig");
const shred_inserter = @import("lib.zig");

const shred_mod = sig.ledger.shred;

const Allocator = std.mem.Allocator;

const ErasureSetId = sig.ledger.shred.ErasureSetId;
const Hash = sig.core.Hash;
const Logger = sig.trace.Logger;
const Slot = sig.core.Slot;

const CodeShred = ledger.shred.CodeShred;
const ErasureMeta = ledger.meta.ErasureMeta;
const Shred = ledger.shred.Shred;
const ShredId = ledger.shred.ShredId;

const DuplicateShredsWorkingStore = shred_inserter.working_state.DuplicateShredsWorkingStore;
const ErasureMetaWorkingStore = shred_inserter.working_state.ErasureMetaWorkingStore;
const MerkleRootMetaWorkingStore = shred_inserter.working_state.MerkleRootMetaWorkingStore;
const PendingInsertShredsState = shred_inserter.working_state.PendingInsertShredsState;
const ShredWorkingStore = shred_inserter.working_state.ShredWorkingStore;

const newlinesToSpaces = sig.utils.fmt.newlinesToSpaces;

pub const MerkleRootValidator = struct {
    allocator: Allocator,
    logger: Logger(@typeName(Self)),
    shreds: ShredWorkingStore,
    duplicate_shreds: DuplicateShredsWorkingStore,

    const Self = @This();

    pub fn init(pending_state: *PendingInsertShredsState) Self {
        return .{
            .allocator = pending_state.allocator,
            .logger = pending_state.logger.withScope(@typeName(Self)),
            .shreds = pending_state.shreds(),
            .duplicate_shreds = pending_state.duplicateShreds(),
        };
    }

    /// agave: check_merkle_root_consistency
    pub fn checkConsistency(
        self: Self,
        slot: Slot,
        merkle_root_meta: *const ledger.meta.MerkleRootMeta,
        shred: *const Shred,
    ) !bool {
        const new_merkle_root = shred.merkleRoot() catch null;
        if (new_merkle_root == null and merkle_root_meta.merkle_root == null or
            new_merkle_root != null and merkle_root_meta.merkle_root != null and
                std.mem.eql(u8, &merkle_root_meta.merkle_root.?.data, &new_merkle_root.?.data))
        {
            // No conflict, either both merkle shreds with same merkle root
            // or both legacy shreds with merkle_root `None`
            return true;
        }

        self.logger.warn().logf(&newlinesToSpaces(
            \\Received conflicting merkle roots for slot: {}, erasure_set: {any} original merkle
            \\root meta {any} vs conflicting merkle root {any} shred index {} type {any}. Reporting
            \\as duplicate
        ), .{
            slot,
            shred.commonHeader().erasureSetId(),
            merkle_root_meta,
            new_merkle_root,
            shred.commonHeader().index,
            shred,
        });

        if (!try self.duplicate_shreds.contains(slot)) {
            // TODO this could be handled by caller (similar for chaining methods)
            const shred_id = ShredId{
                .slot = slot,
                .index = merkle_root_meta.first_received_shred_index,
                .shred_type = merkle_root_meta.first_received_shred_type,
            };
            if (try self.shreds.get(shred_id)) |conflicting_shred| {
                defer conflicting_shred.deinit();
                const original = try shred.clone();
                errdefer original.deinit();
                const conflict = try conflicting_shred.clone(self.allocator);
                errdefer conflict.deinit();
                try self.duplicate_shreds.append(.{
                    .MerkleRootConflict = .{ .original = original, .conflict = conflict },
                });
            } else {
                self.logger.err().logf(&newlinesToSpaces(
                    \\Shred {any} indiciated by merkle root meta {any} is
                    \\missing from ledger. This should only happen in extreme cases where
                    \\ledger cleanup has caught up to the root. Skipping the merkle root
                    \\consistency check
                ), .{ shred_id, merkle_root_meta });
                return true;
            }
        }
        return false;
    }

    /// Returns true if there is no chaining conflict between
    /// the `shred` and `merkle_root_meta` of the next FEC set,
    /// or if shreds from the next set are yet to be received.
    ///
    /// Otherwise return false and add duplicate proof to
    /// `duplicate_shreds`.
    ///
    /// This is intended to be used right after `shred`'s `erasure_meta`
    /// has been created for the first time.
    ///
    /// agave: check_forward_chained_merkle_root_consistency
    pub fn checkForwardChaining(
        self: Self,
        shred: CodeShred,
        erasure_meta: ErasureMeta,
        merkle_root_metas: MerkleRootMetaWorkingStore,
    ) !bool {
        std.debug.assert(erasure_meta.checkCodeShred(shred));
        const slot = shred.common.slot;

        // If a shred from the next fec set has already been inserted, check the chaining
        const next_erasure_set_index = if (erasure_meta.nextErasureSetIndex()) |n| n else {
            self.logger.err().logf(
                "Invalid erasure meta, unable to compute next fec set index {any}",
                .{erasure_meta},
            );
            return false;
        };
        const next_erasure_set =
            ErasureSetId{ .slot = slot, .erasure_set_index = next_erasure_set_index };
        const next_merkle_root_meta = try merkle_root_metas.get(next_erasure_set) orelse {
            // No shred from the next fec set has been received
            return true;
        };

        const next_shred_id = ShredId{
            .slot = slot,
            .index = next_merkle_root_meta.first_received_shred_index,
            .shred_type = next_merkle_root_meta.first_received_shred_type,
        };

        return self.checkAndReportChaining(.forward, .{ .code = shred }, next_shred_id);
    }

    /// Returns true if there is no chaining conflict between
    /// the `shred` and `merkle_root_meta` of the previous FEC set,
    /// or if shreds from the previous set are yet to be received.
    ///
    /// Otherwise return false and add duplicate proof to
    /// `duplicate_shreds`.
    ///
    /// This is intended to be used right after `shred`'s `merkle_root_meta`
    /// has been created for the first time.
    ///
    /// agave: check_backwards_chained_merkle_root_consistency
    pub fn checkBackwardChaining(
        self: Self,
        shred: Shred,
        erasure_metas: ErasureMetaWorkingStore,
    ) !bool {
        const slot = shred.commonHeader().slot;
        const erasure_set_id = shred.commonHeader().erasureSetId();
        const erasure_set_index = shred.commonHeader().erasure_set_index;

        if (erasure_set_index == 0) {
            // Although the first fec set chains to the last fec set of the parent block,
            // if this chain is incorrect we do not know which block is the duplicate until votes
            // are received. We instead delay this check until the block reaches duplicate
            // confirmation.
            return true;
        }

        // If a shred from the previous fec set has already been inserted, check the chaining.
        // Since we cannot compute the previous fec set index, we check the in memory map, otherwise
        // check the previous key from ledger to see if it is consecutive with our current set.
        _, const prev_erasure_meta = if (try erasure_metas.previousSet(erasure_set_id)) |pes|
            pes
        else
            // No shreds from the previous erasure batch have been received,
            // so nothing to check. Once the previous erasure batch is received,
            // we will verify this chain through the forward check above.
            return true;

        const prev_shred_id = ShredId{
            .slot = slot,
            .index = @intCast(prev_erasure_meta.first_received_code_index),
            .shred_type = .code,
        };

        return self.checkAndReportChaining(.backward, shred, prev_shred_id);
    }

    /// The input shreds must be from adjacent erasure sets in the same slot,
    /// or this function will not work correctly.
    fn checkAndReportChaining(
        self: Self,
        direction: enum { forward, backward },
        shred: Shred,
        other_shred_id: ShredId,
    ) !bool {
        const other_shred = if (try self.shreds.get(other_shred_id)) |other_shred|
            other_shred
        else {
            self.logger.warn().logf(
                "Shred {any} is missing from ledger. " ++
                    "This can happen if ledger cleanup has caught up to the root. " ++
                    "Skipping the {} chained merkle root consistency check.",
                .{ other_shred_id, direction },
            );
            return true;
        };
        defer other_shred.deinit();

        const older_shred, const newer_shred = switch (direction) {
            .forward => .{ shred.payload(), other_shred.data },
            .backward => .{ other_shred.data, shred.payload() },
        };

        const chained_merkle_root = shred_mod.layout.getChainedMerkleRoot(newer_shred);
        const early_merkle_root = shred_mod.layout.merkleRoot(older_shred) orelse {
            return error.NoMerkleRoot;
        };

        if (chainedMerkleRootIsConsistent(early_merkle_root, chained_merkle_root)) {
            return true;
        }

        const slot = other_shred_id.slot;

        self.logger.warn().logf(
            "Received conflicting chained merkle roots for slot: {}. Reporting as duplicate. " ++
                \\Conflicting shreds:
                \\    erasure set: {any}, type: {any}, index: {any}, merkle root: {any}
                \\    erasure set: {any}, type: {any}, index: {any}, chained merkle root: {any}
            ,
            .{
                slot,
                // early shred
                shred_mod.layout.getErasureSetIndex(older_shred),
                if (shred_mod.layout.getShredVariant(older_shred)) |v| v.shred_type else null,
                shred_mod.layout.getIndex(older_shred),
                early_merkle_root,
                // late shred
                shred_mod.layout.getErasureSetIndex(newer_shred),
                if (shred_mod.layout.getShredVariant(newer_shred)) |v| v.shred_type else null,
                shred_mod.layout.getIndex(newer_shred),
                chained_merkle_root,
            },
        );

        if (!try self.duplicate_shreds.contains(slot)) {
            const original = try shred.clone();
            errdefer original.deinit();
            const conflict = try other_shred.clone(self.allocator);
            errdefer conflict.deinit();
            try self.duplicate_shreds.append(.{
                .ChainedMerkleRootConflict = .{ .original = original, .conflict = conflict },
            });
        }

        return false;
    }
};

/// agave: check_chaining
fn chainedMerkleRootIsConsistent(merkle_root: Hash, chained_merkle_root: ?Hash) bool {
    return chained_merkle_root == null or // Chained merkle roots have not been enabled yet
        sig.utils.types.eql(chained_merkle_root, merkle_root);
}
