const std = @import("std");
const sig = @import("../sig.zig");

const ledger = sig.ledger;
const schema = ledger.schema.schema;
const shred_mod = sig.ledger.shred;

const Allocator = std.mem.Allocator;
const AutoHashMap = std.AutoHashMap;

const ErasureSetId = sig.ledger.shred.ErasureSetId;
const Hash = sig.core.Hash;
const Logger = sig.trace.Logger;
const SortedMap = sig.utils.collections.SortedMap;

const BlockstoreDB = ledger.blockstore.BlockstoreDB;
const CodeShred = ledger.shred.CodeShred;
const ErasureMeta = ledger.meta.ErasureMeta;
const MerkleRootMeta = ledger.meta.MerkleRootMeta;
const Shred = ledger.shred.Shred;
const ShredId = ledger.shred.ShredId;
const WorkingEntry = ledger.insert_shred.WorkingEntry;
const PossibleDuplicateShred = ledger.insert_shred.PossibleDuplicateShred;

const key_serializer = sig.ledger.database.key_serializer;
const value_serializer = sig.ledger.database.value_serializer;

const getShredFromJustInsertedOrDb = ledger.insert_shred.getShredFromJustInsertedOrDb;

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
    just_inserted_shreds: *const AutoHashMap(ShredId, Shred),
    merkle_root_metas: *AutoHashMap(ErasureSetId, WorkingEntry(MerkleRootMeta)),
    duplicate_shreds: *std.ArrayList(PossibleDuplicateShred),
) !bool {
    std.debug.assert(erasure_meta.checkCodeShred(shred));
    const slot = shred.fields.common.slot;
    const erasure_set_id = shred.fields.common.erasureSetId();

    // If a shred from the next fec set has already been inserted, check the chaining
    const next_fec_set_index = if (erasure_meta.nextFecSetIndex()) |n| n else {
        logger.errf(
            "Invalid erasure meta, unable to compute next fec set index {any}",
            .{erasure_meta},
        );
        return false;
    };
    const next_erasure_set = ErasureSetId{ .slot = slot, .fec_set_index = next_fec_set_index };
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
    const next_shred = if (try getShredFromJustInsertedOrDb(db, just_inserted_shreds, next_shred_id)) |ns|
        ns
    else {
        logger.errf(
            \\Shred {any} indicated by merkle root meta {any} \
            \\is missing from blockstore. This should only happen in extreme cases where \
            \\blockstore cleanup has caught up to the root. Skipping the forward chained \
            \\merkle root consistency check
        , .{ next_shred_id, next_merkle_root_meta });
        return true;
    };
    const merkle_root = shred.fields.merkleRoot() catch null;
    const chained_merkle_root = shred_mod.layout.getChainedMerkleRoot(next_shred);

    if (!checkChaining(merkle_root, chained_merkle_root)) {
        logger.warnf(
            \\Received conflicting chained merkle roots for slot: {}, shred \
            \\{any} type {any} has merkle root {any}, however next fec set \
            \\shred {any} type {any} chains to merkle root \
            \\{any}. Reporting as duplicate
        , .{
            slot,
            erasure_set_id,
            shred.fields.common.variant.shred_type,
            merkle_root,
            next_erasure_set,
            next_merkle_root_meta.first_received_shred_type,
            chained_merkle_root,
        });
        if (!try db.contains(schema.duplicate_slots, slot)) {
            // TODO lifetime
            try duplicate_shreds.append(.{ .ChainedMerkleRootConflict = .{
                .original = .{ .code = shred },
                .conflict = next_shred,
            } });
        }
        return false;
    }

    return true;
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
pub fn checkBackwardsChainedMerkleRootConsistency(
    allocator: Allocator,
    logger: Logger,
    db: *BlockstoreDB,
    shred: Shred,
    just_inserted_shreds: *const AutoHashMap(ShredId, Shred),
    erasure_metas: *SortedMap(ErasureSetId, WorkingEntry(ErasureMeta)), // BTreeMap in agave
    duplicate_shreds: *std.ArrayList(PossibleDuplicateShred),
) !bool {
    const slot = shred.commonHeader().slot;
    const erasure_set_id = shred.commonHeader().erasureSetId();
    const fec_set_index = shred.commonHeader().fec_set_index;

    if (fec_set_index == 0) {
        // Although the first fec set chains to the last fec set of the parent block,
        // if this chain is incorrect we do not know which block is the duplicate until votes
        // are received. We instead delay this check until the block reaches duplicate
        // confirmation.
        return true;
    }

    // If a shred from the previous fec set has already been inserted, check the chaining.
    // Since we cannot compute the previous fec set index, we check the in memory map, otherwise
    // check the previous key from blockstore to see if it is consecutive with our current set.
    const prev_erasure_set, const prev_erasure_meta =
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
    const prev_shred =
        if (try getShredFromJustInsertedOrDb(db, just_inserted_shreds, prev_shred_id)) |ps| ps else {
        logger.warnf(
            \\Shred {any} indicated by the erasure meta {any} \
            \\is missing from blockstore. This can happen if you have recently upgraded \
            \\from a version < v1.18.13, or if blockstore cleanup has caught up to the root. \
            \\Skipping the backwards chained merkle root consistency check
        , .{ prev_shred_id, prev_erasure_meta });
        return true;
    };
    const merkle_root = shred_mod.layout.getChainedMerkleRoot(prev_shred);
    const chained_merkle_root = shred.chainedMerkleRoot() catch null;

    if (!checkChaining(merkle_root, chained_merkle_root)) {
        logger.warnf(
            \\Received conflicting chained merkle roots for slot: {}, shred {any} type {any} \
            \\chains to merkle root {any}, however previous fec set code \
            \\shred {any} has merkle root {any}. Reporting as duplicate
        , .{
            slot,
            shred.commonHeader().erasureSetId(),
            shred.commonHeader().variant.shred_type,
            chained_merkle_root,
            prev_erasure_set,
            merkle_root,
        });
    }

    if (!try db.contains(schema.duplicate_slots, slot)) {
        // TODO lifetime
        try duplicate_shreds.append(.{ .ChainedMerkleRootConflict = .{
            .original = shred,
            .conflict = prev_shred,
        } });
    }

    return true;
}

/// agave: previous_erasure_set
fn previousErasureSet(
    allocator: Allocator,
    db: *BlockstoreDB,
    erasure_set: ErasureSetId,
    erasure_metas: *SortedMap(ErasureSetId, WorkingEntry(ErasureMeta)),
) !?struct { ErasureSetId, ErasureMeta } { // TODO: agave uses CoW here
    const slot = erasure_set.slot;
    const fec_set_index = erasure_set.fec_set_index;

    // Check the previous entry from the in memory map to see if it is the consecutive
    // set to `erasure set`
    const id_range, const meta_range = erasure_metas.range(
        .{ .slot = slot, .fec_set_index = 0 },
        erasure_set,
    );
    if (id_range.len != 0) {
        const i = id_range.len - 1;
        const last_meta = meta_range[i].asRef();
        if (@as(u32, @intCast(fec_set_index)) == last_meta.nextFecSetIndex()) {
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
        if (key.fec_set_index != fec_set_index) break .{
            key,
            try value_serializer.deserialize(ErasureMeta, allocator, entry[1].data),
        };
    } else return null;

    // Check if this is actually the consecutive erasure set
    const next = if (candidate.nextFecSetIndex()) |n| n else return error.InvalidErasureConfig;
    return if (next == fec_set_index)
        .{ candidate_set, candidate }
    else
        return null;
}

/// agave: check_chaining
fn checkChaining(
    merkle_root: ?Hash,
    chained_merkle_root: ?Hash,
) bool {
    return chained_merkle_root == null or // Chained merkle roots have not been enabled yet
        sig.utils.types.eql(chained_merkle_root, merkle_root);
}
