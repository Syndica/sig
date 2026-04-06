const std = @import("std");
const tracy = @import("tracy");
const lib = @import("../lib.zig");
const reed_sol = @import("reed_solomon.zig");

const solana = lib.solana;
const net = lib.net;

const Hash = solana.Hash;
const Slot = solana.Slot;
const Signature = solana.Signature;

const Packet = net.Packet;

const DeshreddedFecSet = lib.shred.DeshreddedFecSet;
const DeshredRing = lib.shred.DeshredRing;
const FecSetId = lib.shred.FecSetId;
const Shred = lib.shred.Shred;

/// Takes in shreds, and writes out deshredded fec sets.
/// For full docs see `services/shred_receiver.zig`.
pub const Receiver = struct {
    // We will ignore shreds outside of this range, as they're not useful to us
    root_slot: Slot,
    max_slot: Slot,

    in_progress: InProgressSets,
    done: DoneSets,

    pub fn init(
        allocator: std.mem.Allocator,
        in_progress_capacity: u32,
        done_capacity: u32,
    ) !Receiver {
        var in_progress: InProgressSets = try .init(allocator, in_progress_capacity);
        errdefer in_progress.deinit(allocator);

        var done: DoneSets = try .init(allocator, done_capacity);
        errdefer done.deinit(allocator);

        return .{
            .in_progress = in_progress,
            .done = done,

            .root_slot = 0,
            .max_slot = std.math.maxInt(Slot),
        };
    }

    pub fn deinit(self: *Receiver, allocator: std.mem.Allocator) void {
        self.in_progress.deinit(allocator);
        self.done.deinit(allocator);
    }

    pub fn updateSlotRange(self: *Receiver, root_slot: Slot, max_slot: Slot) void {
        self.root_slot = root_slot;
        self.max_slot = max_slot;

        // TODO: this is where we would add code to prune entries outside of the new range.
    }

    // TODO: report return values to observability
    // TODO: report back equivocating shreds, so that we can construct and send out duplicate proofs
    pub fn processPacket(
        state: *Receiver,
        leader_schedule: *const lib.solana.LeaderSchedule,
        network_shred_version: u16,
        packet: *const Packet,
        deshred_writer: *DeshredRing.Iterator(.writer),
    ) !NonErrorStatus {
        const zone = tracy.Zone.init(@src(), .{ .name = "processPacket" });
        defer zone.deinit();

        // check that the shred variant is supported and the header is valid
        const shred = try Shred.fromPacketChecked(packet);

        const in_type_idx = if (shred.variant.isData())
            shred.slot_idx - shred.fec_set_idx
        else
            shred.code_or_data.code.code_shred_idx;

        // some additional "free" filtering + sanity checks
        {
            // ignore shred from a slot that's too old or too new
            if (shred.slot < state.root_slot) return error.ShredOlderThanRoot;
            if (shred.slot > state.max_slot) return error.ShredTooNew;

            // ignore shred with wrong version
            if (shred.version != network_shred_version) return error.ShredVersionMismatch;

            // ignore any with bad counts or indices (SIMD 0317 enforces this)
            if (shred.variant.isCode()) {
                if (shred.code_or_data.code.data_count != FecSetCtx.fec_shred_cnt)
                    return error.BadDataShredCount;
                if (shred.code_or_data.code.code_count != FecSetCtx.fec_shred_cnt)
                    return error.BadCodeShredCount;
                if (shred.code_or_data.code.code_shred_idx >= FecSetCtx.fec_shred_cnt)
                    return error.BadCodeShredIdx;
            }

            if (shred.fec_set_idx % FecSetCtx.fec_shred_cnt != 0) return error.InvalidFecSetIdx;
            if (in_type_idx >= FecSetCtx.fec_shred_cnt) return error.ShredIdxTooLarge;

            const merkle_layer_count = 7;
            if (shred.variant.merkleCount() > merkle_layer_count - 1) {
                return error.MerkleCountTooLarge;
            }
        }

        const fec_set_id: FecSetId = .{ .fec_set_idx = shred.fec_set_idx, .slot = shred.slot };

        var buf: [128]u8 = undefined;
        const str = try std.fmt.bufPrint(
            &buf,
            "slot: {}, idx: {}",
            .{ fec_set_id.slot, fec_set_id.fec_set_idx },
        );
        zone.text(str);

        const fec_set_ctx = if (state.in_progress.getFecSetCtx(
            &shred.signature,
        )) |fec_set_ctx| existing_set: {
            // fec set is already being built
            @branchHint(.likely); // ~31/32 expected

            // variant should match that of the first recorded shred in the fec set
            if ((shred.variant.isData() and !shred.variant.eql(fec_set_ctx.data_variant)) or
                (shred.variant.isCode() and !shred.variant.eql(fec_set_ctx.code_variant)))
            {
                return error.VariantMismatchFromFecSet;
            }

            // NOTE: we do not recalculate the merkle root here to check if it matches the in-progress
            // set. This is because the merkle root is protected by the signature, which we are already
            // matching here.
            // NOTE: firedancer does additional checks on the merkle tree here, see
            // fd_bmtree_commitp_insert_with_proof.

            break :existing_set fec_set_ctx;
        } else new_set: {
            // fec set is not currently being built (likely finished already)

            switch (state.done.doneSignatureHash(fec_set_id, &shred.signature)) {
                // fec set isn't finished, this is a new set
                .missing => {},
                // fec set was finished already, let's ignore it
                .matching_signature => return .fec_set_already_finished,

                // NOTE: when we detect equivocation at the shred level, we just drop the incoming
                // shred. i.e. the first shred in a fet set "wins", and until it is fully built,
                // all other conflicting shreds are dropped until the in-progress fec set is built.
                //
                // This is intention as it stops the leader from producing many equivocating shreds
                // that would a) fill up our in-progress map, and b) starve our CPU from shred
                // verification.
                //
                // TODO: once repair is implemented, repaired shreds should skip these checks to
                // allow conflicting fec sets to be inside the in-progress map. We will need to do
                // this to reliably repair when equivocation is detected.
                .mismatching_signature => return error.EquivocationDifferentHashForSameFecSetId,
            }

            // if we have this FecSetId with a different signature, this means equivocation has occured
            if (state.in_progress.containsId(fec_set_id)) {
                // NOTE: see above note.
                return error.EquivocationMatchingFecSetWithDifferentSignatureAlreadyInProgress;
            }

            // This is the first shred of a new in-progress fec set.
            const slot_leader = leader_schedule.get(shred.slot) orelse return error.UnknownLeader;

            var shred_merkle_root: Hash = undefined;
            try shred.merkleRoot(&shred_merkle_root);

            try shred.signature.verify(
                slot_leader,
                &shred_merkle_root.data,
            );

            const fec_set_ctx = try state.in_progress.createFecSetCtx(fec_set_id, &shred.signature);

            fec_set_ctx.* = .{
                // we will check against these for equality in later received shreds
                .data_variant = if (shred.variant.isData())
                    shred.variant
                else
                    shred.variant.swapType(),

                .code_variant = if (shred.variant.isCode())
                    shred.variant
                else
                    shred.variant.swapType(),

                .merkle_root = shred_merkle_root,

                .data_shreds_received = .initEmpty(),
                .code_shreds_received = .initEmpty(),

                .data_shreds_buf = undefined,
                .code_shreds_buf = undefined,
            };

            break :new_set fec_set_ctx;
        };

        // in the case that we just acquired a fec set, it is critical that we do not leak it
        errdefer comptime unreachable;

        zone.value(fec_set_ctx.totalShredsReceived());

        // if (fec_set_ctx.totalShredsReceived() > FecSetCtx.fec_shred_cnt) return .shred_already_seen; // TODO: <-- REMOVE THIS ( should be handled be early if in finished check )

        tracy.plot(u8, "totalShredsReceived", fec_set_ctx.totalShredsReceived());

        // We now have a new shred that has passed validation, time to add it to our in-progress fec set

        if (shred.variant.isCode()) {
            if (fec_set_ctx.code_shreds_received.isSet(in_type_idx)) return .shred_already_seen;

            fec_set_ctx.code_shreds_received.set(in_type_idx); // track shred as received
            fec_set_ctx.code_shreds_buf[in_type_idx] = packet.data; // persist packet to our state
        }
        if (shred.variant.isData()) {
            if (fec_set_ctx.data_shreds_received.isSet(in_type_idx)) return .shred_already_seen;

            fec_set_ctx.data_shreds_received.set(in_type_idx); // track shred as received
            fec_set_ctx.data_shreds_buf[in_type_idx] = packet.data; // persist packet to our state
        }

        tracy.plot(u8, "totalShredsReceived", fec_set_ctx.totalShredsReceived());

        // we just received one
        std.debug.assert(fec_set_ctx.totalShredsReceived() >= 1);
        // this fec set should have completed last iteration
        std.debug.assert(fec_set_ctx.totalShredsReceived() <= FecSetCtx.fec_shred_cnt);

        if (fec_set_ctx.totalShredsReceived() < FecSetCtx.fec_shred_cnt) {
            // we're all good, but we haven't received enough to reconstruct the fec set yet
            @branchHint(.likely);
            return .{
                .unfinished_fec_set = .{
                    .total_shreds_received = @intCast(fec_set_ctx.totalShredsReceived()),
                },
            };
        }

        // starting fec set reconstruction now
        // NOTE: as an optimisation we should reconstruct directly into the out buffer
        reed_sol.reconstructFecSet(fec_set_ctx);
        std.debug.assert(fec_set_ctx.data_shreds_received.count() == FecSetCtx.data_shreds_max);

        // writing out deshredded fec set
        {
            const sending_zone = tracy.Zone.init(@src(), .{ .name = "writing deshredded" });
            defer sending_zone.deinit();

            const total_payload_len, const data_complete, const slot_complete = blk: {
                var len: u16 = 0;
                var data_complete: bool = false;
                var slot_complete: bool = false;

                for (&fec_set_ctx.data_shreds_buf) |*buffer| {
                    const data_shred: *const Shred = Shred.fromBufferUnchecked(buffer);
                    const flags = data_shred.code_or_data.data.flags;

                    len += @intCast(data_shred.dataPayload().len);

                    data_complete = data_complete or flags.data_complete;
                    slot_complete = slot_complete or flags.last_shred_in_slot;
                }
                break :blk .{ len, data_complete, slot_complete };
            };

            const finished: *DeshreddedFecSet = deshred_writer.next() orelse
                // If there's nowhere to write to, then this means that services downstream haven't been
                // keeping up for a while.
                // For now let's just exit if this happens, however this might leave us vulnerable to denial
                // of service.
                //
                // TODO: consider handling this case by pausing writing to this ring.
                @panic("Can't send deshredded fec sets to replay, is it alive?");
            defer deshred_writer.markUsed();

            finished.* = .{
                .merkle_root = fec_set_ctx.merkle_root,
                .chained_merkle_root = shred.chainedMerkleRoot().*,
                .id = fec_set_id,
                .data_complete = data_complete,
                .slot_complete = slot_complete,
                .payload_len = total_payload_len,
                .payload_buf = undefined, //set below
            };

            var bytes_written: u16 = 0;
            for (&fec_set_ctx.data_shreds_buf) |*buffer| {
                const data_shred: *const Shred = Shred.fromBufferUnchecked(buffer);
                const payload = data_shred.dataPayload();

                @memcpy(finished.payload_buf[bytes_written..][0..payload.len], payload);
                bytes_written += @intCast(payload.len);
            }

            std.debug.assert(bytes_written == total_payload_len);
        }

        state.done.setDone(&shred.signature, fec_set_id);
        state.in_progress.removeFinishedSet(fec_set_ctx);

        tracy.frameMarkNamed("finished FEC sets");

        return .fec_set_finished;
    }

    pub const NonErrorStatus = union(enum) {
        unfinished_fec_set: struct {
            // 0..=31 (if it had 32, it would be finished)
            total_shreds_received: std.math.IntFittingRange(0, FecSetCtx.fec_shred_cnt - 1),
        },
        fec_set_finished,
        fec_set_already_finished,
        shred_already_seen,
    };
};

/// Represents a FEC (Forward Error Correction) set which has yet to be reconstructed.
// TODO: use a separate pool for the packet buffers! We're using at least 2x the memory for these,
// and are ruining our cache locality.
pub const FecSetCtx = extern struct {
    data_shreds_received: std.StaticBitSet(data_shreds_max),
    code_shreds_received: std.StaticBitSet(code_shreds_max),

    // all packets are pre-validated shreds, i.e. Shred.fromPacketUnchecked is safe
    // items are valid iff its index is set to 1 in its corresponding bitset
    data_shreds_buf: [data_shreds_max]Packet.Buffer,
    code_shreds_buf: [code_shreds_max]Packet.Buffer,

    // used to make sure that all code and data shreds have the same variant as eachother
    data_variant: Shred.Variant,
    code_variant: Shred.Variant,

    // we store the first seen, and make sure later shreds have the same one
    merkle_root: Hash,

    // https://github.com/firedancer-io/firedancer/blob/ecd2d6d8f5b9f926d0b9aa9360efe36ea1550ad6/src/ballet/reedsol/fd_reedsol.h#L23
    // https://github.com/solana-foundation/specs/blob/main/p2p/shred.md

    // There's now a max of 32+32 shreds
    // https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0317-enforce-32-data-shreds.md
    const data_shreds_max = 32;
    const code_shreds_max = 32;
    pub const fec_shred_cnt = 32;

    fn totalShredsReceived(self: *const FecSetCtx) u8 {
        const data_recv: u8 = @intCast(self.data_shreds_received.count());
        std.debug.assert(data_recv <= data_shreds_max);
        const code_recv: u8 = @intCast(self.code_shreds_received.count());
        std.debug.assert(code_recv <= code_shreds_max);

        return data_recv + code_recv;
    }
};

fn hashSignature(a: *const Signature) u32 {
    return @bitCast((a.r[0..2] ++ a.s[0..2]).*);
}

// Tracks fec sets, keyed by their signature
const InProgressSets = struct {
    ctx_pool: Pool,

    ids: []FecSetId, // idx correspond with fecset idxs
    signatures: []Signature, // idx correspond with fecset idxs

    signature_map: SignatureMap,
    eviction: Eviction,

    const Eviction = std.PriorityQueue(Pool.ItemId, QueueContext, QueueContext.order);
    const Pool = lib.collections.Pool(FecSetCtx, u32);
    const Queue = std.PriorityQueue(Pool.ItemId, QueueContext, QueueContext.order);

    // Key from signature-hash, rather than merkle root, as it's equivalent for lookup and we don't
    // have to compute it.
    const SignatureMap = std.ArrayHashMapUnmanaged(void, *FecSetCtx, SignatureContext, true);

    fn init(allocator: std.mem.Allocator, capacity: u32) !InProgressSets {
        const buf = try allocator.alloc(FecSetCtx, capacity);
        errdefer allocator.free(buf);

        const ctx_pool: Pool = .init(buf);

        const ids = try allocator.alloc(FecSetId, capacity);
        errdefer allocator.free(ids);

        const signatures = try allocator.alloc(Signature, capacity);
        errdefer allocator.free(signatures);

        var signature_map: SignatureMap = .empty;
        errdefer signature_map.deinit(allocator);
        try signature_map.ensureTotalCapacity(allocator, capacity);

        var eviction: Eviction = .init(allocator, .{ .ids = ids });
        errdefer eviction.deinit();
        try eviction.ensureTotalCapacity(capacity);

        eviction.allocator = std.testing.failing_allocator;
        return .{
            .ctx_pool = ctx_pool,
            .ids = ids,
            .signatures = signatures,
            .signature_map = signature_map,
            .eviction = eviction,
        };
    }

    fn deinit(self: *InProgressSets, allocator: std.mem.Allocator) void {
        allocator.free(self.ctx_pool.buf[0..self.ctx_pool.len]);
        allocator.free(self.ids);
        allocator.free(self.signatures);
        self.signature_map.deinit(allocator);

        self.eviction.allocator = allocator;
        self.eviction.deinit();
    }

    fn getFecSetCtx(self: *const InProgressSets, signature: *const Signature) ?*FecSetCtx {
        const map_ctx = self.mapContext();
        return self.signature_map.getAdapted(signature, map_ctx);
    }

    // returns undefined memory, which must be immediately set by the caller
    fn createFecSetCtx(
        self: *InProgressSets,
        id: FecSetId,
        signature: *const Signature,
    ) !*FecSetCtx {
        const map_ctx = self.mapContext();

        self.assertCounts();
        defer self.assertCounts();

        const new_pool_id: Pool.ItemId = self.ctx_pool.createId() catch id: {
            @branchHint(.likely);
            self.removeEvicting();
            break :id self.ctx_pool.createId() catch unreachable;
        };

        const new_idx: u32 = new_pool_id.index().?;

        self.ids[new_idx] = id;
        self.eviction.add(new_pool_id) catch unreachable; // eviction can't be full, we *just* evicted
        self.signatures[new_idx] = signature.*;
        const result = self.signature_map.getOrPutAssumeCapacityAdapted(signature, map_ctx);
        if (result.found_existing) unreachable; // you can't create a fecsetctx that already exists

        const node: *FecSetCtx = self.ctx_pool.indexToPtr(@enumFromInt(new_idx));

        result.value_ptr.* = node;

        return node;
    }

    fn removeFinishedSet(self: *InProgressSets, fec_set_ctx: *FecSetCtx) void {
        const finished_pool_idx = self.ctx_pool.ptrToIndex(fec_set_ctx);

        self.assertCounts();
        defer self.assertCounts();

        // remove from eviction queue
        var iter = self.eviction.iterator();
        while (iter.next()) |pool_idx| {
            if (pool_idx == finished_pool_idx) {
                const removal_pool_idx = self.eviction.removeIndex(iter.count -| 1);
                std.debug.assert(removal_pool_idx == finished_pool_idx);
                break;
            }
        } else unreachable;

        self.removeEvictedSet(finished_pool_idx);
    }

    fn removeEvicting(self: *InProgressSets) void {
        self.assertCounts();
        defer self.assertCounts();

        const evicted_idx = self.eviction.remove();
        self.removeEvictedSet(evicted_idx);
    }

    fn removeEvictedSet(self: *InProgressSets, evicted_pool_idx: Pool.ItemId) void {
        const map_ctx = self.mapContext();

        const evicted_idx = evicted_pool_idx.index().?;

        const evicted_sig: *Signature = &self.signatures[evicted_idx];
        // const node: *FecSetCtx = @ptrCast(&self.ctx_pool.buf[evicted_idx]);
        self.ids[evicted_idx] =
            // an impossible FecSetID which can never be matched with
            .{ .slot = std.math.maxInt(Slot), .fec_set_idx = std.math.maxInt(u32) - 1 };

        self.ctx_pool.destroyId(evicted_pool_idx);
        const removed = self.signature_map.swapRemoveContextAdapted(evicted_sig, map_ctx, map_ctx);
        std.debug.assert(removed);

        evicted_sig.* = undefined;

        // NOTE: it may be tempting to set the evicted Node to undefined, but this will destroy our
        // pool's free list
    }

    fn containsId(self: *const InProgressSets, id: FecSetId) bool {
        return for (self.signature_map.values()) |fec_set_ctx| {
            const pool_id = self.ctx_pool.ptrToIndex(fec_set_ctx);
            const idx = pool_id.index().?;

            if (self.ids[idx].eql(&id)) break true;
        } else false;
    }

    fn assertCounts(self: *const InProgressSets) void {
        std.debug.assert(self.signature_map.count() == self.eviction.items.len);
        tracy.plot(u32, "in-progress FEC sets", @intCast(self.eviction.items.len));
    }

    fn mapContext(self: *const InProgressSets) SignatureContext {
        return .{
            .ctx_pool = self.ctx_pool,
            .map = self.signature_map,
            .signatures = self.signatures,
        };
    }

    const SignatureContext = struct {
        map: SignatureMap,
        ctx_pool: Pool,
        signatures: []const Signature,

        pub fn hash(ctx: SignatureContext, key: *const Signature) u32 {
            _ = ctx;
            return hashSignature(key);
        }

        // NOTE: we could optimise this by getting rid of the Signature and only storing the hash,
        // as collisions aren't important.
        pub fn eql(ctx: SignatureContext, a: *const Signature, _: void, key_idx: usize) bool {
            const set: *FecSetCtx = ctx.map.values()[key_idx];
            const pool_id = ctx.ctx_pool.ptrToIndex(set);
            const idx = pool_id.index().?;

            const b: *const Signature = &ctx.signatures[idx];
            return a.eql(b);
        }
    };

    const QueueContext = struct {
        ids: []const FecSetId,
        fn order(self: QueueContext, a: Pool.ItemId, b: Pool.ItemId) std.math.Order {

            // remove greatest (slot, fec id) first
            return std.math.Order.invert(FecSetId.order(
                &self.ids[a.index().?],
                &self.ids[b.index().?],
            ));
        }
    };
};

test "InProgressSets basic usage" {
    const allocator = std.testing.allocator;
    const set_signature: Signature = .ZEROES;
    const set_id: FecSetId = .{ .slot = 123, .fec_set_idx = 32 };

    var in_progress: InProgressSets = try .init(allocator, 16);
    defer in_progress.deinit(allocator);

    // doesn't contain anything yet
    try std.testing.expect(!in_progress.containsId(set_id));
    try std.testing.expectEqual(null, in_progress.getFecSetCtx(&Signature.ZEROES));

    // add set
    const ctx = try in_progress.createFecSetCtx(set_id, &set_signature);

    // find set
    const found_ctx = in_progress.getFecSetCtx(&set_signature) orelse unreachable;
    try std.testing.expectEqual(ctx, found_ctx);
    try std.testing.expect(in_progress.containsId(set_id));

    // context is evicted
    {
        const ctx_idx = in_progress.eviction.remove();
        in_progress.removeEvictedSet(ctx_idx);
    }

    // can't find set
    try std.testing.expectEqual(null, in_progress.getFecSetCtx(&set_signature));
    try std.testing.expect(!in_progress.containsId(set_id));
}

const DoneSets = struct {
    done_pool: Pool,
    done_map: DoneMap,
    eviction: Eviction,

    fn init(allocator: std.mem.Allocator, capacity: u32) !DoneSets {
        std.debug.assert(capacity < std.math.maxInt(u32));

        const buf = try allocator.alloc(DoneItem, capacity);
        errdefer allocator.free(buf);

        const done_pool: Pool = .init(buf);

        var map: DoneMap = .empty;
        errdefer map.deinit(allocator);
        try map.ensureTotalCapacity(allocator, capacity);

        var eviction: Eviction = .init(allocator, .{ .done_pool = done_pool });
        errdefer eviction.deinit();
        try eviction.ensureTotalCapacity(capacity);

        eviction.allocator = std.testing.failing_allocator;
        return .{
            .done_pool = done_pool,
            .done_map = map,
            .eviction = eviction,
        };
    }

    fn deinit(self: *DoneSets, allocator: std.mem.Allocator) void {
        allocator.free(self.done_pool.buf[0..self.done_pool.len]);
        self.done_map.deinit(allocator);
        self.eviction.allocator = allocator;
        self.eviction.deinit();
    }

    // This signature+id must not be inside DoneSet already - any shred inside DoneSets should be
    // dropped early, so setDone should be unreachable in this case.
    fn setDone(self: *DoneSets, signature: *const Signature, id: FecSetId) void {
        const done_ctx: DoneContext = .{ .done_map = &self.done_map };

        self.assertCounts();
        defer self.assertCounts();

        const new_pool_id: Pool.ItemId = self.done_pool.createId() catch id: {
            @branchHint(.likely);

            const evicted_pool_id = self.eviction.remove();
            const evicted_node: *DoneItem = self.done_pool.indexToPtr(evicted_pool_id);

            const removed = self.done_map.swapRemoveAdapted(&evicted_node.id, done_ctx);
            std.debug.assert(removed);

            evicted_node.* = undefined;

            self.done_pool.destroyId(evicted_pool_id);

            break :id self.done_pool.createId() catch unreachable;
        };

        const new_done: *DoneItem = self.done_pool.indexToPtr(new_pool_id);
        new_done.* = .{ .id = id, .signature_hashed = hashSignature(signature) };
        self.eviction.add(new_pool_id) catch unreachable;
        const entry = self.done_map.getOrPutAssumeCapacityAdapted(&id, done_ctx);
        std.debug.assert(!entry.found_existing);
        entry.value_ptr.* = new_done;
    }

    fn doneSignatureHash(
        self: *const DoneSets,
        id: FecSetId,
        signature: *const Signature,
    ) enum { missing, matching_signature, mismatching_signature } {
        const done_ctx: DoneContext = .{ .done_map = &self.done_map };
        const entry = self.done_map.getAdapted(&id, done_ctx) orelse return .missing;
        const hashed = hashSignature(signature);

        return if (hashed == entry.signature_hashed)
            .matching_signature
        else
            .mismatching_signature;
    }

    fn assertCounts(self: *const DoneSets) void {
        std.debug.assert(self.eviction.items.len == self.done_map.count());
        tracy.plot(u32, "done FEC sets", @intCast(self.eviction.items.len));
    }

    const DoneItem = extern struct { signature_hashed: u32, id: FecSetId };
    const Eviction = std.PriorityQueue(Pool.ItemId, QueueContext, QueueContext.order);
    const Pool = lib.collections.Pool(DoneItem, u32);
    const DoneMap = std.ArrayHashMapUnmanaged(void, *DoneItem, DoneContext, true);

    const QueueContext = struct {
        done_pool: Pool,
        fn order(self: QueueContext, a: Pool.ItemId, b: Pool.ItemId) std.math.Order {
            const a_id: *const FecSetId = &self.done_pool.indexToPtr(a).id;
            const b_id: *const FecSetId = &self.done_pool.indexToPtr(b).id;
            return FecSetId.order(a_id, b_id); // remove oldest (slot, fec id) first
        }
    };

    const DoneContext = struct {
        done_map: *const DoneMap,
        pub fn hash(ctx: DoneContext, key: *const FecSetId) u32 {
            _ = ctx;
            const idx_trunc: u32 = @as(u16, @truncate(key.fec_set_idx / 32));
            return (idx_trunc << 16) ^ @as(u32, @truncate(key.slot));
        }
        pub fn eql(ctx: DoneContext, a: *const FecSetId, _: void, key_idx: usize) bool {
            const b: *const FecSetId = &ctx.done_map.values()[key_idx].id;
            return a.eql(b);
        }
    };
};

test "DoneSets basic usage" {
    const allocator = std.testing.allocator;

    var done_sets: DoneSets = try .init(allocator, 2);
    defer done_sets.deinit(allocator);

    const sig_1: Signature = .parse(
        \\3NyXqg7XjPBX5eW2zpExpAJTdXCHpVt4RR2uPPc6XUzTCVeAphwzpNBxHtYPpipE1gne2NW6ELW6HVdaB7oV9DEn
    );
    const sig_2: Signature = .parse(
        \\2RUa9Sv3T2vwxeubSwJUS63W7N2wT9RaMcaoGJS6a28zGmSvpdArZMcDe7n3JTeBtuh1BkSgaJ8eN3WF7TBMjkG6
    );
    const sig_3: Signature = .parse(
        \\pfj5CrTzHZ69ynRVXfzitUoSWSNqFJVkUzy17FWiC72FE1nw4nHLR2EWFipRnkp6NoeaPyn7uRt5HXZPngz6wsW
    );

    const id_1: FecSetId = .{ .slot = 1, .fec_set_idx = 0 };
    const id_2: FecSetId = .{ .slot = 2, .fec_set_idx = 0 };
    const id_3: FecSetId = .{ .slot = 3, .fec_set_idx = 0 };

    done_sets.setDone(&sig_1, id_1);

    try std.testing.expectEqual(.matching_signature, done_sets.doneSignatureHash(id_1, &sig_1));
    try std.testing.expectEqual(.missing, done_sets.doneSignatureHash(id_2, &sig_2));
    try std.testing.expectEqual(.missing, done_sets.doneSignatureHash(id_3, &sig_3));

    done_sets.setDone(&sig_2, id_2);

    try std.testing.expectEqual(.matching_signature, done_sets.doneSignatureHash(id_1, &sig_1));
    try std.testing.expectEqual(.matching_signature, done_sets.doneSignatureHash(id_2, &sig_2));
    try std.testing.expectEqual(.missing, done_sets.doneSignatureHash(id_3, &sig_3));

    done_sets.setDone(&sig_3, id_3);

    try std.testing.expectEqual(.missing, done_sets.doneSignatureHash(id_1, &sig_1)); // 1 was evicted
    try std.testing.expectEqual(.matching_signature, done_sets.doneSignatureHash(id_2, &sig_2));
    try std.testing.expectEqual(.matching_signature, done_sets.doneSignatureHash(id_3, &sig_3));
}
