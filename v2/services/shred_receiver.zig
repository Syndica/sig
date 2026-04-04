//! Incoming UDP packets (typically port 8002) are sent in by the net service, via
//! `ReadWrite.tvu_socket`. This port is currently set by config.shred_network.recv_port.
//!
//! Shred receiver takes in these packets and emits completed FEC (Forward Error Correction) sets.
//! Each FEC set contains up to 32 packets (AKA shreds) worth of data, which are always sent out as
//! 32 code and 32 data shreds.
//!
//! A FEC set may be reconstructed once any of these 32/64 shreds have been received. This
//! reconstructed data encodes portions of (or whole) Entry batches.
//!
//! These Entry batches are produced by the leader, with each Entry batch forming a portion of the
//! block being produced. This is the data that feeds into Replay.
//!
//!
//!
//! This service has the following responsibilities:
//! 1) Checking that incoming packets are valid shreds, making sure that shreds:
//!     - Are the correct size
//!     - Have valid headers, and have a valid layout
//!     - Are properly signed by the leader for their respective slot
//!     - Have the same merkle root and signature as others in their FEC set
//!     - etc
//! 2) Grouping them into FEC sets
//! 3) Upon receiving enough shreds to complete a FEC set, using Reed-Solomon to reconstruct the
//!    data from said FEC set
//! 4) Sending the reconstructed data onwards
//!
//!
//! NOTE: This currently does not implement repair. Repair requests when implemented should bypass
//!       early equivocation checks.
//!
//! NOTE: This service stores at most one instance of each FecSetId (slot + fecset index).
//!
//!       This means that incoming shreds with the same FecSetId which cannot fit into the currently
//!       in-progress FEC set due to a mismatch (i.e. when the Signature or Merkle root are
//!       different) are dropped under equivocation.
//!
//!       For example, if the shreds of two mismatching FEC sets of the same FecSetId came in
//!       interleaved we would drop the 2nd FEC set. In this case we may have to get shreds from
//!       the missing set from repair. I expect this to be rare, and this behaviour matches
//!       Firedancer's.
//!
//!       Once we complete a FEC set, we are free to build another FEC set of that very same
//!       FecSetId; the downstream service must be fully aware of equivocation.
//!
//!       Once repair is implemented, shreds from it should bypass these checks and enter the map,
//!       even if there is already an instance of that FecSetId.
//!

const std = @import("std");
const bk = @import("binkode");
const start = @import("start_service");
const lib = @import("lib");
const tracy = @import("tracy");

const tel = lib.telemetry;

const Packet = lib.net.Packet;

const Hash = lib.solana.Hash;
const Pubkey = lib.solana.Pubkey;
const Signature = lib.solana.Signature;
const Slot = lib.solana.Slot;

const Atomic = std.atomic.Value;

const DeshreddedFecSet = lib.shred.DeshreddedFecSet;
const DeshredRing = lib.shred.DeshredRing;
const FecSetId = lib.shred.FecSetId;
const rs_table = lib.shred.reed_solomon_table;
const Shred = lib.shred.Shred;

comptime {
    _ = start;
}

pub const name = .shred_receiver;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadWrite = struct {
    /// Translation Validation Unit (TVU)'s UDP socket, i.e. where we receive shreds. This is
    /// typically port 8002. While we've obtained a net Pair, we only currently receive on this.
    /// I believe once we support retransmit, we will be sending on it too.
    tvu_socket: *lib.net.Pair,

    /// Where we send our deshredded FEC (Forward Error Correction) sets to be assembled for replay.
    /// FEC sets will be sent out as they complete.
    ///
    /// NOTE: it will be more performant in future to only send headers down the ring buffer, and
    /// write to a shared fec-set pool.
    deshredded_out: *DeshredRing,

    tel: *tel.Region,
};

pub const ReadOnly = struct {
    config: *const lib.shred.RecvConfig,
};

// We will ignore shreds outside of this range, as they're not useful to us
// TODO: get this information from our fork-aware data structures
// TODO: aggressively evict any in-progress entries <= the root slot
const stub_root_slot = 0;
const stub_max_slot = std.math.maxInt(Slot);

var scratch_memory: [1024 * 1024 * 1024]u8 = undefined;
const max_in_progress = 8192;
const max_done = 65536;

const State = struct {
    in_progress: InProgressSets,
    done: DoneSets,

    // NOTE: this sets the capacity for both done *and* in_progress. We may want to configure these
    // separately in future.
    fn init(allocator: std.mem.Allocator, in_progress_capacity: u32, done_capacity: u32) !State {
        var in_progress: InProgressSets = try .init(allocator, in_progress_capacity);
        errdefer in_progress.deinit(allocator);

        var done: DoneSets = try .init(allocator, done_capacity);
        errdefer done.deinit(allocator);

        return .{ .in_progress = in_progress, .done = done };
    }

    fn deinit(self: *State, allocator: std.mem.Allocator) void {
        self.in_progress.deinit(allocator);
        self.done.deinit(allocator);
    }
};

pub fn serviceMain(ro: ReadOnly, rw: ReadWrite) !noreturn {
    const zone = tracy.Zone.init(@src(), .{ .name = @tagName(name) });
    defer zone.deinit();

    var fba: std.heap.FixedBufferAllocator = .init(&scratch_memory);
    const allocator = fba.allocator();

    std.log.info("Waiting for shreds on port {}", .{rw.tvu_socket.port});

    var state: State = try .init(allocator, max_in_progress, max_done);
    defer state.deinit(allocator);

    const idle_src = @src();
    var maybe_idle_zone: ?tracy.Zone = tracy.Zone.init(idle_src, .{ .name = "idle" });
    while (true) {
        var recv_slice = rw.tvu_socket.recv.getReadable() catch {
            if (maybe_idle_zone == null) maybe_idle_zone = tracy.Zone.init(idle_src, .{ .name = "idle" });
            continue;
        };
        if (maybe_idle_zone) |idle_zone| {
            idle_zone.deinit();
            maybe_idle_zone = null;
        }

        const recv_zone = tracy.Zone.init(@src(), .{ .name = "shred recv" });
        defer recv_zone.deinit();

        const packet = recv_slice.get(0);
        defer recv_slice.markUsed(1);

        // Where we write our completed/deshredded fec sets to.
        // If there's nowhere to write to, then this means that services downstream haven't been
        // keeping up for a while.
        // For now let's just exit if this happens, however this might leave us vulnerable to denial
        // of service.
        //
        // TODO: consider handling this case by pausing writing to this ring.
        var writer_slice = try rw.deshredded_out.getWritable();

        const result = processPacket(
            &state,
            &ro.config.leader_schedule,
            ro.config.shred_version,
            packet,
            &writer_slice,
        ) catch |err| {
            std.log.warn("packet failed with {}", .{err});
            recv_zone.color(0xFF000000); // a nice red
            continue;
        };

        _ = result;
    }
}

const NonErrorStatus = union(enum) {
    unfinished_fec_set: struct {
        // 0..=31 (if it had 32, it would be finished)
        total_shreds_received: std.math.IntFittingRange(0, FecSetCtx.fec_shred_cnt - 1),
    },
    fec_set_finished,
    fec_set_already_finished,
    shred_already_seen,
};

// TODO: we should be notified when the root slot changes, which we will use to eagerly prune our
// state.
// TODO: report return values to observability
// TODO: report back equivocating shreds, so that we can construct and send out duplicate proofs
fn processPacket(
    state: *State,
    leader_schedule: *const lib.solana.LeaderSchedule,
    network_shred_version: u16,
    packet: *const Packet,
    deshred_ring: *DeshredRing.Slice(.writer),
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
        if (shred.slot < stub_root_slot) return error.ShredOlderThanRoot;
        if (shred.slot > stub_max_slot) return error.ShredTooNew;

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
    const str = try std.fmt.bufPrint(&buf, "slot: {}, idx: {}", .{ fec_set_id.slot, fec_set_id.fec_set_idx });
    zone.text(str);

    const fec_set_ctx = if (state.in_progress.getFecSetCtx(&shred.signature)) |fec_set_ctx| existing_set: {
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
    reedsol.reconstructFecSet(fec_set_ctx);
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

        const finished: *DeshreddedFecSet = deshred_ring.get(0);
        defer deshred_ring.markUsed(1);

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

/// Represents a FEC (Forward Error Correction) set which has yet to be reconstructed.
// TODO: use a separate pool for the packet buffers! We're using at least 2x the memory for these,
// and are ruining our cache locality.
const FecSetCtx = extern struct {
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
    const fec_shred_cnt = 32;

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
    const Eviction = std.PriorityQueue(Pool.ItemId, QueueContext, QueueContext.compare);
    const Pool = lib.collections.Pool(DoneItem, u32);
    const DoneMap = std.ArrayHashMapUnmanaged(void, *DoneItem, DoneContext, true);

    const QueueContext = struct {
        done_pool: Pool,
        fn compare(self: QueueContext, a: Pool.ItemId, b: Pool.ItemId) std.math.Order {
            const a_id: *const FecSetId = &self.done_pool.indexToPtr(a).id;
            const b_id: *const FecSetId = &self.done_pool.indexToPtr(b).id;
            return FecSetId.compare(a_id, b_id); // remove oldest (slot, fec id) first
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

    const sig_1: Signature = .parse("3NyXqg7XjPBX5eW2zpExpAJTdXCHpVt4RR2uPPc6XUzTCVeAphwzpNBxHtYPpipE1gne2NW6ELW6HVdaB7oV9DEn");
    const sig_2: Signature = .parse("2RUa9Sv3T2vwxeubSwJUS63W7N2wT9RaMcaoGJS6a28zGmSvpdArZMcDe7n3JTeBtuh1BkSgaJ8eN3WF7TBMjkG6");
    const sig_3: Signature = .parse("pfj5CrTzHZ69ynRVXfzitUoSWSNqFJVkUzy17FWiC72FE1nw4nHLR2EWFipRnkp6NoeaPyn7uRt5HXZPngz6wsW");

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

// Tracks fec sets, keyed by their signature
const InProgressSets = struct {
    ctx_pool: Pool,

    ids: []FecSetId, // idx correspond with fecset idxs
    signatures: []Signature, // idx correspond with fecset idxs

    signature_map: SignatureMap,
    eviction: Eviction,

    const Eviction = std.PriorityQueue(Pool.ItemId, QueueContext, QueueContext.compare);
    const Pool = lib.collections.Pool(FecSetCtx, u32);
    const Queue = std.PriorityQueue(Pool.ItemId, QueueContext, QueueContext.compare);

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
        fn compare(self: QueueContext, a: Pool.ItemId, b: Pool.ItemId) std.math.Order {

            // remove greatest (slot, fec id) first
            return std.math.Order.invert(FecSetId.compare(
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

const reedsol = struct {
    // Reconstructs data shreds when 32/64 shreds have been received
    fn reconstructFecSet(fec_set_ctx: *FecSetCtx) void {
        const zone = tracy.Zone.init(@src(), .{ .name = "reconstructFecSet" });
        defer zone.deinit();

        const data_count = FecSetCtx.fec_shred_cnt;
        const code_count = FecSetCtx.fec_shred_cnt;
        const total_count = data_count + code_count;

        // Build present[] mask and collect erasure shard length from first present shred
        var present: [total_count]bool = @splat(false);
        var shard_len: usize = 0;

        for (0..data_count) |i| {
            if (fec_set_ctx.data_shreds_received.isSet(i)) {
                present[i] = true;
                if (shard_len == 0) {
                    const shred = Shred.fromBufferUnchecked(&fec_set_ctx.data_shreds_buf[i]);
                    if (shred.erasureFragment()) |frag| {
                        shard_len = frag.len;
                    }
                }
            }
        }
        for (0..code_count) |i| {
            if (fec_set_ctx.code_shreds_received.isSet(i)) {
                present[data_count + i] = true;
                if (shard_len == 0) {
                    const shred = Shred.fromBufferUnchecked(&fec_set_ctx.code_shreds_buf[i]);
                    if (shred.erasureFragment()) |frag| {
                        shard_len = frag.len;
                    }
                }
            }
        }

        if (shard_len == 0) return; // no valid shreds found

        // Collect 32 valid indices (indices of present shreds in encoding_matrix row order)
        var valid_indices: [data_count]u8 = undefined;
        var valid_count: u8 = 0;
        for (0..total_count) |i| {
            if (present[i]) {
                valid_indices[valid_count] = @intCast(i);
                valid_count += 1;
                if (valid_count == data_count) break;
            }
        }

        if (valid_count < data_count) return; // not enough shreds

        // Build 32x32 sub-matrix by picking rows from encoding_matrix
        var sub_matrix: [data_count][data_count]u8 = undefined;
        for (0..data_count) |r| {
            sub_matrix[r] = encoding_matrix[valid_indices[r]];
        }

        // Invert sub_matrix via Gaussian elimination on augmented [sub_matrix | identity]
        var aug: [data_count][data_count * 2]u8 = undefined;
        for (0..data_count) |r| {
            for (0..data_count) |c| {
                aug[r][c] = sub_matrix[r][c];
                aug[r][data_count + c] = if (r == c) @as(u8, 1) else @as(u8, 0);
            }
        }

        // Forward elimination
        for (0..data_count) |r| {
            if (aug[r][r] == 0) {
                for (r + 1..data_count) |r_below| {
                    if (aug[r_below][r] != 0) {
                        const tmp = aug[r];
                        aug[r] = aug[r_below];
                        aug[r_below] = tmp;
                        break;
                    }
                }
            }
            if (aug[r][r] == 0) {
                std.log.warn("FEC reconstruction: singular matrix at row {}", .{r});
                return;
            }
            if (aug[r][r] != 1) {
                const scale = field.div(1, aug[r][r]);
                for (0..data_count * 2) |c| {
                    aug[r][c] = field.mul(scale, aug[r][c]);
                }
            }
            for (r + 1..data_count) |r_below| {
                if (aug[r_below][r] != 0) {
                    const scale = aug[r_below][r];
                    for (0..data_count * 2) |c| {
                        aug[r_below][c] = field.add(aug[r_below][c], field.mul(scale, aug[r][c]));
                    }
                }
            }
        }
        // Back-substitution
        for (0..data_count) |d| {
            for (0..d) |r_above| {
                if (aug[r_above][d] != 0) {
                    const scale = aug[r_above][d];
                    for (0..data_count * 2) |c| {
                        aug[r_above][c] = field.add(aug[r_above][c], field.mul(scale, aug[d][c]));
                    }
                }
            }
        }

        // Extract inverted matrix from right half
        var inv: [data_count][data_count]u8 = undefined;
        for (0..data_count) |r| {
            for (0..data_count) |c| {
                inv[r][c] = aug[r][data_count + c];
            }
        }

        // Find leader signature from any present data or code shred (first 64 bytes)
        var leader_sig: [Signature.SIZE]u8 = undefined;
        var have_sig = false;
        for (0..data_count) |i| {
            if (fec_set_ctx.data_shreds_received.isSet(i)) {
                @memcpy(&leader_sig, fec_set_ctx.data_shreds_buf[i][0..Signature.SIZE]);
                have_sig = true;
                break;
            }
        }
        if (!have_sig) {
            for (0..code_count) |i| {
                if (fec_set_ctx.code_shreds_received.isSet(i)) {
                    @memcpy(&leader_sig, fec_set_ctx.code_shreds_buf[i][0..Signature.SIZE]);
                    have_sig = true;
                    break;
                }
            }
        }

        // Collect pointers to erasure shards for the 32 valid indices
        var shard_ptrs: [data_count][*]const u8 = undefined;
        for (0..data_count) |k| {
            const idx = valid_indices[k];
            if (idx < data_count) {
                const shred = Shred.fromBufferUnchecked(&fec_set_ctx.data_shreds_buf[idx]);
                shard_ptrs[k] = (shred.erasureFragment() orelse return).ptr;
            } else {
                const shred = Shred.fromBufferUnchecked(&fec_set_ctx.code_shreds_buf[idx - data_count]);
                shard_ptrs[k] = (shred.erasureFragment() orelse return).ptr;
            }
        }

        // For each missing data shred, reconstruct its erasure shard
        for (0..data_count) |i| {
            if (present[i]) continue; // already have this data shred

            // We need the i-th row of the inverted matrix to recover data shard i
            const inv_row = &inv[i];

            // Destination: write directly into the packet buffer
            var dest_packet = &fec_set_ctx.data_shreds_buf[i];

            // First, copy leader signature into bytes 0..64
            if (have_sig) {
                @memcpy(dest_packet[0..Signature.SIZE], &leader_sig);
            }

            // For data shreds, erasure shard starts at offset 64 (after signature)
            // and ends at headers_size + capacity. We compute it the same way.
            // The erasure shard for data shreds covers bytes [64 .. 64 + shard_len]
            const dest_start = Signature.SIZE; // 64
            const dest_end = dest_start + shard_len;
            if (dest_end > Packet.capacity) return;

            var dest = dest_packet[dest_start..dest_end];

            // Multiply: dest[byte] = sum over k of (inv_row[k] * shard_ptrs[k][byte])
            // First pass: dest = inv_row[0] * shard_ptrs[0]
            const coeff0 = inv_row[0];
            for (0..shard_len) |b| {
                dest[b] = field.mul(coeff0, shard_ptrs[0][b]);
            }
            // Remaining passes: dest += inv_row[k] * shard_ptrs[k]
            for (1..data_count) |k| {
                const coeff = inv_row[k];
                if (coeff == 0) continue;
                for (0..shard_len) |b| {
                    dest[b] = field.add(dest[b], field.mul(coeff, shard_ptrs[k][b]));
                }
            }

            // Mark this data shred as received
            fec_set_ctx.data_shreds_received.set(i);
        }
    }

    // GF(2^8) arithmetic and Reed-Solomon encoding matrix for erasure coding.
    // All operations use pre-computed lookup tables from reed_solomon_table.zig.
    const field = struct {
        inline fn add(a: u8, b: u8) u8 {
            return a ^ b;
        }

        inline fn mul(a: u8, b: u8) u8 {
            return rs_table.mul[a][b];
        }

        inline fn div(a: u8, b: u8) u8 {
            if (a == 0) return 0;
            const log_a = rs_table.log[a];
            const log_b = rs_table.log[b];
            const log_result: i16 = @as(i16, log_a) - @as(i16, log_b);
            return rs_table.exp[@intCast(if (log_result < 0) log_result + 255 else log_result)];
        }

        fn exp(a: u8, n: usize) u8 {
            if (n == 0) return 1;
            if (a == 0) return 0;
            var log_result: usize = @as(usize, rs_table.log[a]) * n;
            while (log_result >= 255) {
                log_result -= 255;
            }
            return rs_table.exp[log_result];
        }
    };

    /// Comptime-generated 64x32 encoding matrix for Reed-Solomon with data_count=32, code_count=32.
    /// Top 32 rows = identity matrix (for data shreds), bottom 32 rows = parity coefficients.
    /// Derived from: Vandermonde(64x32) * inverse(Vandermonde_top(32x32))
    const encoding_matrix: [64][32]u8 = blk: {
        @setEvalBranchQuota(1_000_000);

        const total = 64;
        const data = 32;

        // Step 1: Build 64x32 Vandermonde matrix
        var vandermonde: [total][data]u8 = undefined;
        for (0..total) |r| {
            for (0..data) |c| {
                vandermonde[r][c] = field.exp(@intCast(r), c);
            }
        }

        // Step 2: Extract top 32x32 submatrix and invert via Gaussian elimination
        // Build augmented matrix [top | identity]
        var aug: [data][data * 2]u8 = undefined;
        for (0..data) |r| {
            for (0..data) |c| {
                aug[r][c] = vandermonde[r][c];
            }
            for (0..data) |c| {
                aug[r][data + c] = if (r == c) 1 else 0;
            }
        }

        // Gaussian elimination (forward)
        for (0..data) |r| {
            // Find pivot
            if (aug[r][r] == 0) {
                for (r + 1..data) |r_below| {
                    if (aug[r_below][r] != 0) {
                        const tmp = aug[r];
                        aug[r] = aug[r_below];
                        aug[r_below] = tmp;
                        break;
                    }
                }
            }
            // Scale pivot row
            if (aug[r][r] != 1) {
                const scale = field.div(1, aug[r][r]);
                for (0..data * 2) |c| {
                    aug[r][c] = field.mul(scale, aug[r][c]);
                }
            }
            // Eliminate below
            for (r + 1..data) |r_below| {
                if (aug[r_below][r] != 0) {
                    const scale = aug[r_below][r];
                    for (0..data * 2) |c| {
                        aug[r_below][c] = field.add(aug[r_below][c], field.mul(scale, aug[r][c]));
                    }
                }
            }
        }
        // Back-substitution (eliminate above)
        for (0..data) |d| {
            for (0..d) |r_above| {
                if (aug[r_above][d] != 0) {
                    const scale = aug[r_above][d];
                    for (0..data * 2) |c| {
                        aug[r_above][c] = field.add(aug[r_above][c], field.mul(scale, aug[d][c]));
                    }
                }
            }
        }

        // Extract inverted top matrix from right half of augmented matrix
        var inv_top: [data][data]u8 = undefined;
        for (0..data) |r| {
            for (0..data) |c| {
                inv_top[r][c] = aug[r][data + c];
            }
        }

        // Step 3: Multiply Vandermonde(64x32) * inv_top(32x32) = encoding_matrix(64x32)
        var result: [total][data]u8 = undefined;
        for (0..total) |r| {
            for (0..data) |c| {
                var val: u8 = 0;
                for (0..data) |i| {
                    val = field.add(val, field.mul(vandermonde[r][i], inv_top[i][c]));
                }
                result[r][c] = val;
            }
        }

        break :blk result;
    };
};

const bincode = struct {
    // This isn't quite a bincode fixed int, nor a varint. It's some custom Solana thing used in
    // Agave's `short_vec`. I think it's supposed to be smaller than a fixed or varint for a u16.
    const compact_u16: bk.Codec(u16) = .implement(void, void, struct {
        pub fn encode(
            writer: *std.Io.Writer,
            _: bk.Config,
            values: []const u16,
            _: ?*[encode_stack_size]u64,
            limit: std.Io.Limit,
            _: void,
        ) bk.EncodeToWriterError!bk.EncodedCounts {
            const max_count = limit.max(values.len);
            var byte_count: usize = 0;
            for (values[0..max_count]) |val| {
                var rem: u16 = val;
                while (true) {
                    var elem: u8 = @truncate(rem & 0x7f);
                    rem >>= 7;
                    if (rem == 0) {
                        writer.writeByte(elem) catch return error.EncodeFailed;
                        byte_count += 1;
                        break;
                    } else {
                        elem |= 0x80;
                        writer.writeByte(elem) catch return error.EncodeFailed;
                        byte_count += 1;
                    }
                }
            }
            return .{ .value_count = max_count, .byte_count = byte_count };
        }

        pub const encode_min_size: usize = 1;
        pub const encode_stack_size: usize = 0;
        pub const decodeInit = null;

        pub fn decode(
            reader: *std.Io.Reader,
            _: bk.Config,
            _: ?std.mem.Allocator,
            values: []u16,
            decoded_count: *usize,
            _: void,
        ) bk.DecodeFromReaderError!void {
            for (values, 0..) |*value, i| {
                errdefer decoded_count.* = i;

                var result: u16 = 0;
                var shift: u4 = 0;
                for (0..3) |_| {
                    const byte = try reader.takeByte();
                    result |= @as(u16, byte & 0x7f) << shift;
                    if (byte & 0x80 == 0) break;
                    shift += 7;
                } else {
                    // Fourth byte would be needed → overflow for u16
                    return error.DecodeFailed;
                }
                value.* = result;
            }
            decoded_count.* = values.len;
        }

        pub fn decodeSkip(
            reader: *std.Io.Reader,
            _: bk.Config,
            value_count: usize,
            decoded_count: *usize,
            _: void,
        ) bk.DecodeSkipError!void {
            for (0..value_count) |i| {
                errdefer decoded_count.* = i;
                for (0..3) |_| {
                    const byte = try reader.takeByte();
                    if (byte & 0x80 == 0) break;
                } else {
                    return error.DecodeFailed;
                }
            }
            decoded_count.* = value_count;
        }

        pub const free = null;
    });

    // For slices that have a compact_u16 length rather than a u64
    fn shortVec(comptime Element: type, comptime element: bk.Codec(Element)) bk.Codec([]Element) {
        return comptime .implement(element.EncodeCtx, element.DecodeCtx, struct {
            pub fn encode(
                writer: *std.Io.Writer,
                config: bk.Config,
                values: []const []Element,
                _: ?*[encode_stack_size]u64,
                limit: std.Io.Limit,
                ctx: element.EncodeCtx,
            ) bk.EncodeToWriterError!bk.EncodedCounts {
                const max_count = limit.max(values.len);
                var byte_count: usize = 0;
                for (values[0..max_count]) |slice_val| {
                    // Write compact-u16 length
                    const len: u16 = std.math.cast(u16, slice_val.len) orelse return error.EncodeFailed;
                    const len_counts = try compact_u16.encodeOnePartialRaw(writer, config, &len, null, .unlimited, {});
                    byte_count += len_counts.byte_count;

                    // Write elements
                    const elem_counts = try element.encodeManyPartialRaw(writer, config, slice_val, null, .unlimited, ctx);
                    byte_count += elem_counts.byte_count;
                }
                return .{ .value_count = max_count, .byte_count = byte_count };
            }

            pub const encode_min_size: usize = 1;
            pub const encode_stack_size: usize = 0;

            pub fn decodeInit(
                gpa_opt: ?std.mem.Allocator,
                values: [][]Element,
                _: element.DecodeCtx,
            ) std.mem.Allocator.Error!void {
                _ = gpa_opt.?;
                @memset(values, &.{});
            }

            pub fn decode(
                reader: *std.Io.Reader,
                config: bk.Config,
                gpa_opt: ?std.mem.Allocator,
                values: [][]Element,
                decoded_count: *usize,
                ctx: element.DecodeCtx,
            ) bk.DecodeFromReaderError!void {
                const gpa = gpa_opt.?;
                for (values, 0..) |*value, i| {
                    errdefer decoded_count.* = i;

                    const len = try compact_u16.decode(reader, null, .default, {});

                    const elems = try gpa.alloc(Element, len);
                    errdefer gpa.free(elems);

                    // decode into elems
                    try element.decodeInitMany(gpa, elems, ctx);
                    errdefer element.freeMany(gpa, elems, ctx);

                    try element.decodeIntoMany(reader, gpa, config, elems, ctx);

                    value.* = elems;
                }
                decoded_count.* = values.len;
            }

            pub fn decodeSkip(
                reader: *std.Io.Reader,
                config: bk.Config,
                value_count: usize,
                decoded_count: *usize,
                ctx: element.DecodeCtx,
            ) bk.DecodeSkipError!void {
                for (0..value_count) |i| {
                    errdefer decoded_count.* = i;
                    const len = try compact_u16.decode(reader, null, .default, null);
                    try element.decodeSkip(reader, config, len, ctx);
                }
                decoded_count.* = value_count;
            }

            pub fn free(
                gpa_opt: ?std.mem.Allocator,
                slice_list: []const []Element,
                ctx: element.DecodeCtx,
            ) void {
                const gpa = gpa_opt.?;
                for (slice_list) |slice_value| {
                    element.freeMany(gpa, slice_value, ctx);
                    gpa.free(slice_value);
                }
            }
        });
    }

    const hash_codec: bk.Codec(Hash) = .standard(.tuple(.{
        .data = .array(.fixint),
    }));

    const pubkey_codec: bk.Codec(Pubkey) = .standard(.tuple(.{
        .data = .array(.fixint),
    }));

    const MessageHeader = struct {
        num_required_signatures: u8,
        num_readonly_signed_accounts: u8,
        num_readonly_unsigned_accounts: u8,

        const bk_config: bk.Codec(MessageHeader) = .standard(.tuple(.{
            .num_required_signatures = .fixint,
            .num_readonly_signed_accounts = .fixint,
            .num_readonly_unsigned_accounts = .fixint,
        }));
    };

    const CompiledInstruction = struct {
        program_id_index: u8,
        accounts: []u8,
        data: []u8,

        const bk_config: bk.Codec(CompiledInstruction) = .standard(.tuple(.{
            .program_id_index = .fixint,
            .accounts = .from(shortVec(u8, bk.StdCodec(u8).fixint.codec)),
            .data = .from(shortVec(u8, bk.StdCodec(u8).fixint.codec)),
        }));
    };

    const AddressLookup = struct {
        account_key: Pubkey,
        writable_indexes: []u8,
        readonly_indexes: []u8,

        const bk_config: bk.Codec(AddressLookup) = .standard(.tuple(.{
            .account_key = .from(pubkey_codec),
            .writable_indexes = .from(shortVec(u8, bk.StdCodec(u8).fixint.codec)),
            .readonly_indexes = .from(shortVec(u8, bk.StdCodec(u8).fixint.codec)),
        }));
    };

    const LegacyMessage = struct {
        header: MessageHeader,
        account_keys: []Pubkey,
        recent_blockhash: Hash,
        instructions: []CompiledInstruction,

        const bk_config: bk.Codec(LegacyMessage) = .standard(.tuple(.{
            .header = .from(MessageHeader.bk_config),
            .account_keys = .from(shortVec(Pubkey, pubkey_codec)),
            .recent_blockhash = .from(hash_codec),
            .instructions = .from(shortVec(CompiledInstruction, CompiledInstruction.bk_config)),
        }));
    };

    const V0Message = struct {
        header: MessageHeader,
        account_keys: []Pubkey,
        recent_blockhash: Hash,
        instructions: []CompiledInstruction,
        address_table_lookups: []AddressLookup,

        const bk_config: bk.Codec(V0Message) = .standard(.tuple(.{
            .header = .from(MessageHeader.bk_config),
            .account_keys = .from(shortVec(Pubkey, pubkey_codec)),
            .recent_blockhash = .from(hash_codec),
            .instructions = .from(shortVec(CompiledInstruction, CompiledInstruction.bk_config)),
            .address_table_lookups = .from(shortVec(AddressLookup, AddressLookup.bk_config)),
        }));
    };

    const VersionedMessage = union(enum) {
        // first byte & 0x80 == 0
        legacy: LegacyMessage,
        // first byte & 0x80 != 0
        v0: V0Message,

        const bk_config: bk.Codec(VersionedMessage) = .implement(void, void, struct {
            pub fn encode(
                writer: *std.Io.Writer,
                config: bk.Config,
                values: []const VersionedMessage,
                _: ?*[encode_stack_size]u64,
                limit: std.Io.Limit,
                _: void,
            ) bk.EncodeToWriterError!bk.EncodedCounts {
                const max_count = limit.max(values.len);
                var byte_count: usize = 0;
                for (values[0..max_count]) |value| {
                    switch (value) {
                        .legacy => |msg| {
                            // Legacy: no version prefix byte; MessageHeader.num_required_signatures
                            // is the first byte on the wire (written by LegacyMessage codec).
                            const counts = LegacyMessage.bk_config.encodeOnePartialRaw(
                                writer,
                                config,
                                &msg,
                                null,
                                .unlimited,
                                {},
                            ) catch return error.EncodeFailed;
                            byte_count += counts.byte_count;
                        },
                        .v0 => |msg| {
                            // V0: write version prefix byte (0x80 | 0x00 = 0x80), then V0Message.
                            writer.writeByte(0x80) catch return error.EncodeFailed;
                            byte_count += 1;
                            const counts = V0Message.bk_config.encodeOnePartialRaw(
                                writer,
                                config,
                                &msg,
                                null,
                                .unlimited,
                                {},
                            ) catch return error.EncodeFailed;
                            byte_count += counts.byte_count;
                        },
                    }
                }
                return .{ .value_count = max_count, .byte_count = byte_count };
            }

            pub const encode_min_size: usize = 1;
            pub const encode_stack_size: usize = 0;
            pub const decodeInit = null;

            pub fn decode(
                reader: *std.Io.Reader,
                config: bk.Config,
                gpa_opt: ?std.mem.Allocator,
                values: []VersionedMessage,
                decoded_count: *usize,
                _: void,
            ) bk.DecodeFromReaderError!void {
                for (values, 0..) |*value, i| {
                    errdefer decoded_count.* = i;

                    // Peek the first byte to determine version.
                    const first_byte = try reader.takeByte();

                    if (first_byte & 0x80 == 0) {
                        // Legacy message. The byte we just read is num_required_signatures.
                        // We need to "put it back" — reconstruct by reading the remaining
                        // MessageHeader fields (2 more bytes), then the rest of the message.
                        const num_readonly_signed = try reader.takeByte();
                        const num_readonly_unsigned = try reader.takeByte();
                        const header: MessageHeader = .{
                            .num_required_signatures = first_byte,
                            .num_readonly_signed_accounts = num_readonly_signed,
                            .num_readonly_unsigned_accounts = num_readonly_unsigned,
                        };

                        // Decode the remaining fields of LegacyMessage (account_keys, recent_blockhash, instructions)
                        const account_keys_codec = shortVec(Pubkey, pubkey_codec);
                        const account_keys = try account_keys_codec.decode(reader, gpa_opt, config, null);

                        var recent_blockhash: Hash = undefined;
                        try hash_codec.decodeIntoOne(reader, null, config, &recent_blockhash, null);

                        const instructions_codec = shortVec(CompiledInstruction, CompiledInstruction.bk_config);
                        const instructions = try instructions_codec.decode(reader, gpa_opt, config, null);

                        value.* = .{ .legacy = .{
                            .header = header,
                            .account_keys = account_keys,
                            .recent_blockhash = recent_blockhash,
                            .instructions = instructions,
                        } };
                    } else {
                        // Versioned message. The byte was consumed. Check version.
                        const version = first_byte & 0x7F;
                        if (version != 0) {
                            return error.DecodeFailed; // unsupported version
                        }

                        // Decode V0Message
                        const msg = try V0Message.bk_config.decode(reader, gpa_opt, config, null);
                        value.* = .{ .v0 = msg };
                    }
                }
                decoded_count.* = values.len;
            }

            pub fn decodeSkip(
                reader: *std.Io.Reader,
                config: bk.Config,
                value_count: usize,
                decoded_count: *usize,
                _: void,
            ) bk.DecodeSkipError!void {
                for (0..value_count) |i| {
                    errdefer decoded_count.* = i;
                    const first_byte = try reader.takeByte();

                    if (first_byte & 0x80 == 0) {
                        // Legacy: skip remaining 2 header bytes + fields
                        try reader.discardAll(2);
                        // Skip account_keys (shortVec of 32-byte pubkeys)
                        const ak_len = try compact_u16.decode(reader, null, .default, null);
                        try reader.discardAll(ak_len * Pubkey.SIZE);
                        // Skip recent_blockhash
                        try reader.discardAll(Hash.SIZE);
                        // Skip instructions
                        const ix_len = try compact_u16.decode(reader, null, .default, null);
                        try CompiledInstruction.bk_config.decodeSkip(reader, config, ix_len, {});
                    } else {
                        // V0: version byte already consumed. Skip V0Message.
                        try V0Message.bk_config.decodeSkip(reader, config, 1, {});
                    }
                }
                decoded_count.* = value_count;
            }

            pub fn free(
                gpa_opt: ?std.mem.Allocator,
                values: []const VersionedMessage,
                _: void,
            ) void {
                for (values) |value| {
                    switch (value) {
                        .legacy => |msg| LegacyMessage.bk_config.free(gpa_opt, &msg, null),
                        .v0 => |msg| V0Message.bk_config.free(gpa_opt, &msg, null),
                    }
                }
            }
        });
    };

    const VersionedTransaction = struct {
        signatures: []Signature,
        message: VersionedMessage,

        const bk_config: bk.Codec(VersionedTransaction) = .standard(.tuple(.{
            .signatures = .from(shortVec(Signature, Signature.bk_config)),
            .message = .from(VersionedMessage.bk_config),
        }));
    };

    const Entry = struct {
        num_hashes: u64,
        hash: Hash,
        transactions: []VersionedTransaction,

        const bk_config: bk.Codec(Entry) = .standard(.tuple(.{
            .num_hashes = .fixint,
            .hash = .from(hash_codec),
            .transactions = .sliceNonStd(VersionedTransaction.bk_config),
        }));

        // slice of entries
        const slice_config: bk.Codec([]Entry) = .standard(.sliceNonStd(Entry.bk_config));
    };
};
