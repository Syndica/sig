const std = @import("std");
const sig = @import("../../sig.zig");
const ledger = @import("../lib.zig");
const shred_inserter = @import("lib.zig");

const schema = ledger.schema.schema;
const shred_mod = sig.ledger.shred;

const Allocator = std.mem.Allocator;
const AutoHashMap = std.AutoHashMap;

const ErasureSetId = sig.ledger.shred.ErasureSetId;
const Hash = sig.core.Hash;
const Logger = sig.trace.Logger;
const Slot = sig.core.Slot;
const SortedMap = sig.utils.collections.SortedMap;

const BlockstoreDB = ledger.blockstore.BlockstoreDB;
const CodeShred = ledger.shred.CodeShred;
const ErasureMeta = ledger.meta.ErasureMeta;
const MerkleRootMeta = ledger.meta.MerkleRootMeta;
const PossibleDuplicateShred = shred_inserter.working_state.PossibleDuplicateShred;
const Shred = ledger.shred.Shred;
const ShredId = ledger.shred.ShredId;
const WorkingEntry = shred_inserter.working_state.WorkingEntry;
const WorkingShredStore = shred_inserter.working_state.WorkingShredStore;

const key_serializer = ledger.database.key_serializer;
const value_serializer = ledger.database.value_serializer;

const newlinesToSpaces = sig.utils.fmt.newlinesToSpaces;

/// agave: check_merkle_root_consistency
pub fn checkMerkleRootConsistency(
    logger: Logger,
    db: *BlockstoreDB,
    shred_store: WorkingShredStore,
    slot: Slot,
    merkle_root_meta: *const ledger.meta.MerkleRootMeta,
    shred: *const Shred,
    duplicate_shreds: *std.ArrayList(PossibleDuplicateShred),
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

    logger.warn().logf(&newlinesToSpaces(
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

    if (!try db.contains(schema.duplicate_slots, slot)) {
        // TODO this could be handled by caller (similar for chaining methods)
        const shred_id = ShredId{
            .slot = slot,
            .index = merkle_root_meta.first_received_shred_index,
            .shred_type = merkle_root_meta.first_received_shred_type,
        };
        if (try shred_store.get(shred_id)) |conflicting_shred| {
            try duplicate_shreds.append(.{
                .MerkleRootConflict = .{
                    .original = shred.*, // TODO lifetimes (cloned in rust)
                    .conflict = conflicting_shred,
                },
            });
        } else {
            logger.err().logf(&newlinesToSpaces(
                \\Shred {any} indiciated by merkle root meta {any} is 
                \\missing from blockstore. This should only happen in extreme cases where 
                \\blockstore cleanup has caught up to the root. Skipping the merkle root 
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
pub fn checkForwardChainedMerkleRootConsistency(
    allocator: Allocator,
    logger: Logger,
    db: *BlockstoreDB,
    shred: CodeShred,
    erasure_meta: ErasureMeta,
    shred_store: WorkingShredStore,
    merkle_root_metas: *AutoHashMap(ErasureSetId, WorkingEntry(MerkleRootMeta)),
    duplicate_shreds: *std.ArrayList(PossibleDuplicateShred),
) !bool {
    std.debug.assert(erasure_meta.checkCodeShred(shred));
    const slot = shred.common.slot;

    // If a shred from the next fec set has already been inserted, check the chaining
    const next_erasure_set_index = if (erasure_meta.nextErasureSetIndex()) |n| n else {
        logger.err().logf(
            "Invalid erasure meta, unable to compute next fec set index {any}",
            .{erasure_meta},
        );
        return false;
    };
    const next_erasure_set = ErasureSetId{ .slot = slot, .erasure_set_index = next_erasure_set_index };
    const next_merkle_root_meta = if (merkle_root_metas.get(next_erasure_set)) |nes|
        nes.asRef().*
    else if (try db.get(allocator, schema.merkle_root_meta, next_erasure_set)) |nes|
        nes
    else
        // No shred from the next fec set has been received
        return true;

    const next_shred_id = ShredId{
        .slot = slot,
        .index = next_merkle_root_meta.first_received_shred_index,
        .shred_type = next_merkle_root_meta.first_received_shred_type,
    };

    return checkAndReportMerkleRootConsistency(
        .forward,
        logger,
        db,
        shred_store,
        duplicate_shreds,
        .{ .code = shred },
        next_shred_id,
    );
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
pub fn checkBackwardChainedMerkleRootConsistency(
    allocator: Allocator,
    logger: Logger,
    db: *BlockstoreDB,
    shred: Shred,
    shred_store: WorkingShredStore,
    erasure_metas: *SortedMap(ErasureSetId, WorkingEntry(ErasureMeta)), // BTreeMap in agave
    duplicate_shreds: *std.ArrayList(PossibleDuplicateShred),
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
    // check the previous key from blockstore to see if it is consecutive with our current set.
    _, const prev_erasure_meta =
        if (try previousErasureSet(allocator, db, erasure_set_id, erasure_metas)) |pes|
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

    return checkAndReportMerkleRootConsistency(
        .backward,
        logger,
        db,
        shred_store,
        duplicate_shreds,
        shred,
        prev_shred_id,
    );
}

/// The input shreds must be from adjacent erasure sets in the same slot,
/// or this function will not work correctly.
fn checkAndReportMerkleRootConsistency(
    direction: enum { forward, backward },
    logger: Logger,
    db: *BlockstoreDB,
    shred_store: WorkingShredStore,
    duplicate_shreds: *std.ArrayList(PossibleDuplicateShred),
    shred: Shred,
    other_shred_id: ShredId,
) !bool {
    const other_shred = if (try shred_store.get(other_shred_id)) |other_shred|
        other_shred
    else {
        logger.warn().logf(
            "Shred {any} is missing from blockstore. " ++
                "This can happen if blockstore cleanup has caught up to the root. " ++
                "Skipping the {} chained merkle root consistency check.",
            .{ other_shred_id, direction },
        );
        return true;
    };

    const early_shred, const late_shred = switch (direction) {
        .forward => .{ shred.payload(), other_shred },
        .backward => .{ other_shred, shred.payload() },
    };

    const chained_merkle_root = shred_mod.layout.getChainedMerkleRoot(late_shred);
    const early_merkle_root = shred_mod.layout.merkleRoot(early_shred) orelse {
        return error.NoMerkleRoot;
    };

    if (chainedMerkleRootIsConsistent(early_merkle_root, chained_merkle_root)) {
        return true;
    }

    const slot = other_shred_id.slot;

    logger.warn().logf(
        "Received conflicting chained merkle roots for slot: {}. Reporting as duplicate. " ++
            "Conflicting shreds:\n" ++
            "    erasure set: {?}, type: {?}, index: {?}, merkle root: {any}\n" ++
            "    erasure set: {?}, type: {?}, index: {?}, chained merkle root: {any}",
        .{
            slot,
            // early shred
            shred_mod.layout.getErasureSetIndex(early_shred),
            if (shred_mod.layout.getShredVariant(early_shred)) |v| v.shred_type else null,
            shred_mod.layout.getIndex(early_shred),
            early_merkle_root,
            // late shred
            shred_mod.layout.getErasureSetIndex(late_shred),
            if (shred_mod.layout.getShredVariant(late_shred)) |v| v.shred_type else null,
            shred_mod.layout.getIndex(late_shred),
            chained_merkle_root,
        },
    );

    if (!try db.contains(schema.duplicate_slots, slot)) {
        // TODO lifetime
        try duplicate_shreds.append(.{ .ChainedMerkleRootConflict = .{
            .original = shred,
            .conflict = other_shred,
        } });
    }

    return false;
}

/// agave: previous_erasure_set
fn previousErasureSet(
    allocator: Allocator,
    db: *BlockstoreDB,
    erasure_set: ErasureSetId,
    erasure_metas: *SortedMap(ErasureSetId, WorkingEntry(ErasureMeta)),
) !?struct { ErasureSetId, ErasureMeta } { // TODO: agave uses CoW here
    const slot = erasure_set.slot;
    const erasure_set_index = erasure_set.erasure_set_index;

    // Check the previous entry from the in memory map to see if it is the consecutive
    // set to `erasure set`
    const id_range, const meta_range = erasure_metas.range(
        .{ .slot = slot, .erasure_set_index = 0 },
        erasure_set,
    );
    if (id_range.len != 0) {
        const i = id_range.len - 1;
        const last_meta = meta_range[i].asRef();
        if (@as(u32, @intCast(erasure_set_index)) == last_meta.nextErasureSetIndex()) {
            return .{ id_range[i], last_meta.* };
        }
    }

    // Consecutive set was not found in memory, scan blockstore for a potential candidate
    var iter = try db.iterator(schema.erasure_meta, .reverse, erasure_set);
    defer iter.deinit();
    const candidate_set: ErasureSetId, //
    const candidate: ErasureMeta //
    = while (try iter.nextBytes()) |entry| {
        defer for (entry) |e| e.deinit();
        const key = try key_serializer.deserialize(ErasureSetId, allocator, entry[0].data);
        if (key.slot != slot) return null;
        if (key.erasure_set_index != erasure_set_index) break .{
            key,
            try value_serializer.deserialize(ErasureMeta, allocator, entry[1].data),
        };
    } else return null;

    // Check if this is actually the consecutive erasure set
    const next = if (candidate.nextErasureSetIndex()) |n| n else return error.InvalidErasureConfig;
    return if (next == erasure_set_index)
        .{ candidate_set, candidate }
    else
        return null;
}

/// agave: check_chaining
fn chainedMerkleRootIsConsistent(merkle_root: Hash, chained_merkle_root: ?Hash) bool {
    return chained_merkle_root == null or // Chained merkle roots have not been enabled yet
        sig.utils.types.eql(chained_merkle_root, merkle_root);
}
