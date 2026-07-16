const std = @import("std");
const tracy = @import("tracy");
const lib = @import("../lib.zig");
const reed_sol = @import("reed_solomon.zig");
const build_options = @import("build-options");

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

    features: Features,

    in_progress: InProgressSets,
    done: DoneSets,

    /// Per-feature activation slots. A feature is enforced for shreds
    /// whose slot is `>= activation_slot`; the default `maxInt(Slot)`
    /// keeps every feature inactive.
    pub const Features = struct {
        discard_unexpected_data_complete_shreds: Slot = std.math.maxInt(Slot),
    };

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
            .features = .{},
        };
    }

    pub fn deinit(self: *Receiver, allocator: std.mem.Allocator) void {
        self.in_progress.deinit(allocator);
        self.done.deinit(allocator);
    }

    /// Reset to the post-init state without freeing any heap memory. Intended
    /// for callers that reuse a single Receiver across many independent inputs
    /// (e.g. the conformance shred-parse harness, which runs one fixture per
    /// invocation and must not leak state between them).
    pub fn reset(self: *Receiver) void {
        self.in_progress.reset();
        self.done.reset();
        self.root_slot = 0;
        self.max_slot = std.math.maxInt(Slot);
        self.features = .{};
    }

    pub fn updateSlotRange(self: *Receiver, root_slot: Slot, max_slot: Slot) void {
        self.root_slot = root_slot;
        self.max_slot = max_slot;

        // TODO: prune `in_progress` / `done` entries below the new root.
    }

    // TODO: report return values to observability
    // TODO: report back equivocating shreds, so that we can construct and send out duplicate proofs
    pub fn processPacket(
        state: *Receiver,
        leader_schedule: *const lib.solana.LeaderSchedule,
        network_shred_version: u16,
        packet: *const Packet,
        deshred_writer: *DeshredRing.Iterator(.writer),
        logger: lib.telemetry.Logger("processPacket"),
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
            if (shred.version != network_shred_version and
                !build_options.debug_skip_shred_version_check)
                return error.ShredVersionMismatch;

            // reject shreds greater than the max per slot
            if (shred.fec_set_idx > lib.shred.max_shreds_per_slot - FecSetCtx.fec_shred_count)
                return error.FecSetIndexTooHigh;
            if (shred.slot_idx >= lib.shred.max_shreds_per_slot)
                return error.SlotIndexTooHigh;

            // ignore any with bad counts or indices (SIMD 0317 enforces this)
            if (shred.variant.isCode()) {
                if (shred.code_or_data.code.data_count != FecSetCtx.fec_shred_count)
                    return error.BadDataShredCount;
                if (shred.code_or_data.code.code_count != FecSetCtx.fec_shred_count)
                    return error.BadCodeShredCount;
                if (shred.code_or_data.code.code_shred_idx >= FecSetCtx.fec_shred_count)
                    return error.BadCodeShredIdx;
            } else {
                // [agave] https://github.com/anza-xyz/agave/blob/v4.1.0-rc.1/ledger/src/shred/filter.rs#L327-L342
                if (shred.slot >= state.features.discard_unexpected_data_complete_shreds and
                    shred.code_or_data.data.flags.data_complete and
                    shred.slot_idx != shred.fec_set_idx + FecSetCtx.fec_shred_count - 1)
                {
                    return error.UnexpectedDataCompleteShred;
                }
                // LAST_SHRED_IN_SLOT terminates the slot, so the shred must
                // sit at the end of a fixed 32-shred FEC set: its
                // `slot_idx + 1` must be a multiple of `fec_shred_count`.
                // Rejecting a misaligned last-in-slot at parse prevents the
                // fuzzer from smuggling a short trailing FEC set past the
                // fixed-shape (SIMD-0317) assumption every downstream check
                // relies on. Unlike the DATA_COMPLETE check above, agave
                // applies this unconditionally (`misaligned_last_data_index`).
                if (shred.code_or_data.data.flags.last_shred_in_slot and
                    (shred.slot_idx + 1) % FecSetCtx.fec_shred_count != 0)
                {
                    return error.MisalignedLastDataIndex;
                }
            }

            if (shred.fec_set_idx % FecSetCtx.fec_shred_count != 0) return error.InvalidFecSetIdx;
            if (in_type_idx >= FecSetCtx.fec_shred_count) return error.ShredIdxTooLarge;

            const merkle_layer_count = 7;
            if (shred.variant.merkle_count > merkle_layer_count - 1) {
                return error.MerkleCountTooLarge;
            }
        }

        // Layout-level filter: drop data shreds whose declared parent is
        // older than the current root. Agave's
        // `ShredFilterContext::should_discard_shred` rejects the same at
        // the layout level via `verify_shred_slots` (in
        // `ledger/src/shred/filter.rs`) before the shred reaches
        // `insert_shreds`. Per-slot parent-slot *consistency* (any two
        // data shreds in a slot must declare the same parent) is
        // reconstructed by the conformance harness from admitted
        // in_progress ctxs' data shreds — the receiver keeps no per-slot
        // parent pin.
        if (shred.variant.isData()) {
            const parent_slot = shred.slot - shred.code_or_data.data.parent_offset;
            if (parent_slot < state.root_slot) return error.ShredParentBeforeRoot;
        }

        const fec_set_id: FecSetId = .{ .fec_set_idx = shred.fec_set_idx, .slot = shred.slot };

        var buf: [128]u8 = undefined;
        const str = try std.fmt.bufPrint(
            &buf,
            "slot: {}, idx: {}",
            .{ fec_set_id.slot, fec_set_id.fec_set_idx },
        );
        zone.text(str);

        // Recompute this shred's own merkle_root from its embedded proof.
        // Needed for both the FEC-set consistency checks inside the ctx
        // routing below and the cross-FEC chain check that follows.
        // Cheap (~1us); signature verification against this root is only
        // done in the new_set path where we haven't verified it yet.
        var shred_merkle_root: Hash = undefined;
        try shred.merkleRoot(&shred_merkle_root);

        // In production (flag off) this is just `shred.signature`; DCE'd to
        // a field read. Under `-Ddebug-signature-disambiguation` it becomes
        // a `(slot, fec_set_idx, merkle_root)`-derived synthetic Signature.
        // See `ctxKey` doc comment.
        const ctx_key = ctxKey(shred, &shred_merkle_root);

        const fec_set_ctx = if (state.in_progress.getFecSetCtx(
            &ctx_key,
        )) |fec_set_ctx| existing_set: {
            // fec set is already being built. This branch will be taken for 31/64 shreds (assuming
            // zero packet loss).

            // A signature (or, under `-Ddebug-signature-disambiguation`,
            // a synthetic `ctxKey`) is a unique routing key for one
            // `(slot, fec_set_idx)`. In production this holds because
            // the leader signs the merkle root of a specific FEC set
            // and Ed25519 is deterministic. Under the harness flag it
            // holds because `ctxKey` folds `merkle_root` into the key,
            // and distinct `(slot, fec_set_idx, merkle_root)` triples
            // hash to distinct 64-byte outputs.
            //
            // Reaching this branch with a mismatched `existing_id`
            // requires either an ed25519 collision or a sha512
            // collision on the ctx-key derivation \u2014 both are
            // cryptographically infeasible. If it fires, something is
            // wrong with the routing invariants (flag wiring, key
            // derivation, or the sig-verify short-circuit); crash
            // rather than continue with a corrupted ctx pool.
            const existing_id = state.in_progress.fecSetIdOf(fec_set_ctx);
            if (!existing_id.eql(&fec_set_id)) {
                @panic(
                    "ctx routing invariant violated: getFecSetCtx returned a " ++
                        "ctx whose FecSetId differs from the shred's. Requires " ++
                        "an ed25519 collision (production) or a sha512 " ++
                        "collision on ctxKey (harness).",
                );
            }

            // variant should match that of the first recorded shred in the fec set
            if ((shred.variant.isData() and !shred.variant.eql(fec_set_ctx.data_variant)) or
                (shred.variant.isCode() and !shred.variant.eql(fec_set_ctx.code_variant)))
            {
                return error.VariantMismatchFromFecSet;
            }

            // The signature of a shred protects its merkle root. We now have a shred that matches a
            // signature that we verified against a merkle root earlier - we just need to check if
            // the merkle root is the same. `shred_merkle_root` was computed above for the cross-FEC
            // chain check.
            //
            // NOTE: firedancer optimises "inserting" shreds into fec sets using
            // fd_bmtree_commitp_insert_with_proof, which may be of interest.
            if (!shred_merkle_root.eql(&fec_set_ctx.merkle_root))
                // This failing implies that signature verification would fail, i.e. it isn't an
                // equivocation problem.
                return error.MismatchedMerkleRoot;

            // Every shred in a FEC set declares the same `chained_merkle_root`
            // (the merkle root of the previous FEC set). Compare against the
            // value pinned from the first-seen shred; deshredding reads from
            // the pinned value, so this also keeps completion deterministic
            // under shred arrival reordering.
            if (!shred.chainedMerkleRoot().eql(&fec_set_ctx.chained_merkle_root))
                return error.MismatchedChainedMerkleRoot;

            break :existing_set fec_set_ctx;
        } else new_set: {
            // fec set is not currently being built (likely finished already)

            switch (state.done.lookupStatus(fec_set_id, &ctx_key)) {
                // fec set isn't finished, this is a new set
                .missing => {},
                // fec set was finished already, let's ignore it
                .matching_signature => return .fec_set_already_finished,

                // Two distinct signatures over the same
                // `(slot, fec_set_idx)` sign two distinct merkle roots for
                // one erasure set — leader equivocation. Under
                // `-Ddebug-signature-disambiguation` the second variant
                // has its own `ctx_key`; letting it proceed to
                // `new_set` creates a distinct ctx so both variants
                // complete and surface as sibling MerkleNodes for
                // `deriveBlockParseResult` to fold into REJECTED.
                .mismatching_signature => {},
            }

            // Under P1 (`-Ddebug-signature-disambiguation`), two variants
            // at the same `fec_set_id` have distinct `ctx_key`s and land
            // in distinct in_progress ctxs; the harness sees both
            // through the deshred ring and folds equivocation into
            // REJECTED via `hasSiblingsWithSameId`. Without the flag the
            // second variant would still fall through here, but
            // production sig-verify would already have caught it.

            // This is the first shred of a new in-progress fec set. The
            // shred's merkle_root was recomputed above; only the leader
            // signature check is new here.
            if (!build_options.debug_skip_shred_sig_verify) {
                const slot_leader = leader_schedule.get(shred.slot) orelse {
                    logger.warn().logf("slot {} missing?\n", .{shred.slot});
                    return error.UnknownLeader;
                };
                shred.signature.verify(
                    slot_leader,
                    &shred_merkle_root.data,
                ) catch return error.SignatureVerificationFailed;
            }

            const fec_set_ctx = try state.in_progress.createFecSetCtx(fec_set_id, &ctx_key);

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
                // Pinned from the first-seen shred and never overwritten;
                // every other shred in this FEC set must declare the same
                // value (see existing-set branch above), and deshredding
                // reads it back from here.
                .chained_merkle_root = shred.chainedMerkleRoot().*,

                .data_shreds_received = .initEmpty(),
                .code_shreds_received = .initEmpty(),

                .data_shreds_buf = undefined,
                .code_shreds_buf = undefined,
            };

            break :new_set fec_set_ctx;
        };

        zone.value(fec_set_ctx.totalShredsReceived());

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
        std.debug.assert(fec_set_ctx.totalShredsReceived() <= FecSetCtx.fec_shred_count);

        if (fec_set_ctx.totalShredsReceived() < FecSetCtx.fec_shred_count) {
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
        const data_received_before_recovery = fec_set_ctx.data_shreds_received;
        {
            const shreds_bitset, const shreds_reedsol_bufs = fec_set_ctx.erasureEncoded();

            const recover_zone = tracy.Zone.init(@src(), .{ .name = "reconstructFecSet" });
            defer recover_zone.deinit();

            reed_sol.recover64(
                shred.erasureFragment().?.len,
                &shreds_reedsol_bufs,
                32,
                32,
                shreds_bitset.mask,
            ) catch @panic("todo: handle bad recovery");

            fec_set_ctx.data_shreds_received = .initFull();
        }

        std.debug.assert(fec_set_ctx.data_shreds_received.count() == FecSetCtx.data_shreds_max);

        // Re-validate every data shred we just reconstructed. RS recovery
        // fills the erasure-protected region (header + payload) but leaves
        // the trailer (chained_merkle_root, merkle proof, optional
        // retransmitter sig) and the leading signature untouched, so we can
        // only re-check invariants derivable from the recovered bytes:
        // structural layout, slot/fec_set_idx vs the pinned ctx, variant
        // consistency, and positional `slot_idx`. The merkle and
        // chained-merkle roots are pinned on `FecSetCtx` from the first
        // wire shred; a recovered shred can't disagree with values it
        // doesn't carry.
        //
        // agave runs the equivalent gauntlet in
        // `Blockstore::handle_shred_recovery` -> `check_insert_data_shred`.
        for (0..FecSetCtx.data_shreds_max) |idx| {
            if (data_received_before_recovery.isSet(idx)) continue;
            var recovered_packet: Packet = .{
                .data = fec_set_ctx.data_shreds_buf[idx],
                .len = lib.shred.Shred.min_size,
                .addr = std.net.Address.initIp4(.{ 0, 0, 0, 0 }, 0),
            };
            const recovered = Shred.fromPacketChecked(&recovered_packet) catch |err| {
                // Byzantine-only path in production, but silent by
                // design (no downstream signal, no ring emission).
                // Surface it here so operators and fuzz-crash triage
                // can attribute a missing FEC set to bad recovery vs.
                // insufficient input.
                logger.warn().logf(
                    "RS-recovered shred failed structural re-validation: " ++
                        "slot={} fec_set_idx={} idx={} err={s}. Dropping FEC set.",
                    .{ shred.slot, shred.fec_set_idx, idx, @errorName(err) },
                );
                return error.RecoveredShredMalformed;
            };
            if (recovered.slot != shred.slot or
                recovered.fec_set_idx != shred.fec_set_idx or
                !recovered.variant.isData() or
                !recovered.variant.eql(fec_set_ctx.data_variant) or
                recovered.slot_idx != shred.fec_set_idx + idx)
            {
                logger.warn().logf(
                    "RS-recovered shred header disagrees with ctx: slot={} " ++
                        "fec_set_idx={} idx={} " ++
                        "(recovered slot={} fec_set_idx={} slot_idx={} isData={}). " ++
                        "Dropping FEC set.",
                    .{
                        shred.slot,                 shred.fec_set_idx,     idx,
                        recovered.slot,             recovered.fec_set_idx, recovered.slot_idx,
                        recovered.variant.isData(),
                    },
                );
                return error.RecoveredShredMalformed;
            }
        }

        // Emission to the deshred ring runs unconditionally once RS
        // recovery and per-shred re-validation have succeeded. Block-
        // level rejection is derived post-hoc by the conformance
        // harness's `deriveBlockParseResult` from `MerkleForest` state
        // and `Receiver.in_progress` — not from any per-slot flag
        // maintained here.

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

                    slot_complete = slot_complete or flags.last_shred_in_slot;

                    if (flags.data_complete) {
                        data_complete = true;
                        break;
                    }
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
                .chained_merkle_root = fec_set_ctx.chained_merkle_root,
                .id = fec_set_id,
                // Every data shred in a FEC set carries the same
                // `parent_offset` (merkle-hashed DataHeader field). The
                // ctx contains all 32 data shreds at this point (RS
                // recovery has run above, so index 0 is populated even
                // if the wire shred at index 0 was missing).
                .parent_offset = Shred.fromBufferUnchecked(
                    &fec_set_ctx.data_shreds_buf[0],
                ).code_or_data.data.parent_offset,
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

                if (Shred.fromBufferUnchecked(buffer).code_or_data.data.flags.data_complete) break;
            }

            std.debug.assert(bytes_written == total_payload_len);
        }

        state.done.setDone(
            &ctx_key,
            fec_set_id,
            &fec_set_ctx.merkle_root,
            &fec_set_ctx.chained_merkle_root,
        );
        state.in_progress.removeFinishedSet(fec_set_ctx);

        tracy.frameMarkNamed("finished FEC sets");

        return .fec_set_finished;
    }

    pub const NonErrorStatus = union(enum) {
        unfinished_fec_set: struct {
            // 0..=31 (if it had 32, it would be finished)
            total_shreds_received: std.math.IntFittingRange(0, FecSetCtx.fec_shred_count - 1),
        },
        fec_set_finished,
        fec_set_already_finished,
        shred_already_seen,
    };
};

/// Pair of roots pinned for a single FEC set. Returned by neighbor lookup
/// during the cross-FEC chain check.
pub const FecSetRoots = struct {
    merkle_root: Hash,
    chained_merkle_root: Hash,
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
    // The merkle root of the previous FEC set. Identical for every shred in
    // this set; pinned from the first-seen shred so completion output is
    // independent of shred arrival order.
    chained_merkle_root: Hash,

    // https://github.com/firedancer-io/firedancer/blob/ecd2d6d8f5b9f926d0b9aa9360efe36ea1550ad6/src/ballet/reedsol/fd_reedsol.h#L23
    // https://github.com/solana-foundation/specs/blob/main/p2p/shred.md

    // There's now a max of 32+32 shreds
    // https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0317-enforce-32-data-shreds.md
    const data_shreds_max = 32;
    const code_shreds_max = 32;
    pub const fec_shred_count = 32;

    fn totalShredsReceived(self: *const FecSetCtx) u8 {
        const data_recv: u8 = @intCast(self.data_shreds_received.count());
        std.debug.assert(data_recv <= data_shreds_max);
        const code_recv: u8 = @intCast(self.code_shreds_received.count());
        std.debug.assert(code_recv <= code_shreds_max);

        return data_recv + code_recv;
    }

    // prep for recover64
    fn erasureEncoded(self: *FecSetCtx) struct { std.StaticBitSet(64), [64][]u8 } {
        const base_variant = variant: {
            for (&self.data_shreds_buf, 0..) |*data_shred, i| {
                if (!self.data_shreds_received.isSet(i)) continue;
                const shred: *const Shred = .fromBufferUnchecked(data_shred);
                break :variant shred.variant;
            }
            for (&self.code_shreds_buf, 0..) |*code_shred, i| {
                if (!self.code_shreds_received.isSet(i)) continue;
                const shred: *const Shred = .fromBufferUnchecked(code_shred);
                break :variant shred.variant;
            }
            unreachable;
        };

        var erasure_buffers: [64][]u8 = undefined;

        for (erasure_buffers[0..32], &self.data_shreds_buf, 0..) |*erasure_buf, *data_shred, i| {
            const shred: *Shred = .fromBufferUncheckedMut(data_shred);

            // set variant for unused buffers so we can get the erasure fragment offset+size
            if (!self.data_shreds_received.isSet(i)) {
                shred.variant = if (base_variant.isCode())
                    base_variant.swapType()
                else
                    base_variant;
            }

            erasure_buf.* = shred.erasureFragment().?;
        }

        for (erasure_buffers[32..64], &self.code_shreds_buf, 0..) |*erasure_buf, *code_shred, i| {
            const shred: *Shred = .fromBufferUncheckedMut(code_shred);

            // set variant for unused buffers so we can get the erasure fragment offset+size
            if (!self.code_shreds_received.isSet(i)) {
                shred.variant = if (base_variant.isData())
                    base_variant.swapType()
                else
                    base_variant;
            }

            erasure_buf.* = shred.erasureFragment().?;
        }

        var bitset: std.StaticBitSet(64) = .{
            .mask = (@as(u64, self.code_shreds_received.mask) << 32) |
                @as(u64, self.data_shreds_received.mask),
        };

        bitset.toggleAll();

        return .{ bitset, erasure_buffers };
    }
};

fn hashSignature(a: *const Signature) u32 {
    return @bitCast((a.r[0..2] ++ a.s[0..2]).*);
}

/// Synthetic key for `in_progress` / `done` ctx routing.
///
/// Sig's `in_progress` map is signature-primary keyed for admission-time
/// performance, while agave / FD's analogous state is keyed by
/// `(slot, fec_set_idx)`. Under sig-verify-off fuzz inputs a mutator can
/// synthesise two FEC sets at distinct `(slot, fec_set_idx)` sharing a
/// signature; Sig's ctx routing then collides and drops the second writer.
/// Cryptographically infeasible in production (would require breaking
/// ed25519), so this flag only affects harness builds.
///
/// Including `merkle_root` in the synthetic key preserves equivocation
/// detection: two variants at the same `(slot, fec_set_idx)` with different
/// merkle roots route to distinct ctxs, both complete, and appear as
/// sibling entries downstream where equivocation is folded into the
/// harness-side REJECTED verdict.
///
/// TODO: remove this helper (and the `debug-signature-disambiguation` build
/// option) once solfuzz's `disambiguate_signatures` mutator is upstreamed —
/// that mutator normalises signatures per `(slot, fec_set_idx)` at the input
/// layer, achieving the same effect without any Sig-side machinery.
inline fn ctxKey(shred: *const Shred, merkle_root: *const Hash) Signature {
    if (!build_options.debug_signature_disambiguation) return shred.signature;
    var hasher = std.crypto.hash.sha2.Sha512.init(.{});
    var slot_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &slot_bytes, shred.slot, .little);
    hasher.update(&slot_bytes);
    var idx_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &idx_bytes, shred.fec_set_idx, .little);
    hasher.update(&idx_bytes);
    hasher.update(&merkle_root.data);
    var digest: [64]u8 = undefined;
    hasher.final(&digest);
    return .{ .r = digest[0..32].*, .s = digest[32..64].* };
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

    /// Returns the set to its post-init state without freeing any heap memory.
    /// Preserves the existing capacities of `ctx_pool`, `signature_map`, and
    /// `eviction`.
    fn reset(self: *InProgressSets) void {
        self.ctx_pool.reset();
        self.signature_map.clearRetainingCapacity();
        self.eviction.items.len = 0;
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

        const new_idx: u32 = new_pool_id.index();

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

        const evicted_idx = evicted_pool_idx.index();

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
            const idx = pool_id.index();

            if (self.ids[idx].eql(&id)) break true;
        } else false;
    }

    fn getCtxById(self: *const InProgressSets, id: FecSetId) ?*FecSetCtx {
        return for (self.signature_map.values()) |fec_set_ctx| {
            const pool_id = self.ctx_pool.ptrToIndex(fec_set_ctx);
            const idx = pool_id.index();

            if (self.ids[idx].eql(&id)) break fec_set_ctx;
        } else null;
    }

    /// Returns the `FecSetId` under which `ctx` was inserted. Only valid for
    /// a live pointer returned by `getFecSetCtx` / `getCtxById`.
    pub fn fecSetIdOf(self: *const InProgressSets, ctx: *const FecSetCtx) FecSetId {
        const pool_id = self.ctx_pool.ptrToIndex(@constCast(ctx));
        return self.ids[pool_id.index()];
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
            const idx = pool_id.index();

            const b: *const Signature = &ctx.signatures[idx];
            return a.eql(b);
        }
    };

    const QueueContext = struct {
        ids: []const FecSetId,
        fn order(self: QueueContext, a: Pool.ItemId, b: Pool.ItemId) std.math.Order {

            // remove greatest (slot, fec id) first
            return std.math.Order.invert(FecSetId.order(
                &self.ids[a.index()],
                &self.ids[b.index()],
            ));
        }
    };
};

const TEST_DATA_SHRED_PACKET_LEN = 1203;

fn initTestDataPacket(packet: *Packet, version: u16) void {
    packet.data = @splat(0);
    packet.len = TEST_DATA_SHRED_PACKET_LEN;

    const shred: *Shred = @ptrCast(packet);
    shred.* = .{
        .signature = .ZEROES,
        .variant = .{ .kind = .merkle_data_chained, .merkle_count = 0 },
        .slot = 1,
        .slot_idx = 0,
        .version = version,
        .fec_set_idx = 0,
        .code_or_data = .{
            .data = .{
                .parent_offset = 1,
                .flags = .{
                    .reference_tick = 0,
                    .data_complete = false,
                    .last_shred_in_slot = false,
                },
                .size = @offsetOf(Shred, "code_or_data") + @sizeOf(Shred.DataHeader),
            },
        },
    };
}

fn signTestDataPacket(packet: *Packet, keypair: *const lib.gossip.KeyPair) !void {
    const shred: *Shred = @ptrCast(packet);
    var merkle_root: Hash = undefined;
    try shred.merkleRoot(&merkle_root);
    shred.signature = try keypair.sign(&merkle_root.data);
}

test "shred.receiver: empty packet" {
    const allocator = std.testing.allocator;

    var receiver: Receiver = try .init(allocator, 1, 1);
    defer receiver.deinit(allocator);

    var packet: Packet = undefined;
    packet.len = 0;

    const leader_schedule: *const lib.solana.LeaderSchedule = undefined;
    var deshred_writer: DeshredRing.Iterator(.writer) = undefined;

    try std.testing.expectError(
        error.PacketUnderMinHeaderSize,
        receiver.processPacket(
            leader_schedule,
            0,
            &packet,
            &deshred_writer,
            .noop,
        ),
    );
}

test "shred.receiver: shred version mismatch" {
    const allocator = std.testing.allocator;

    var receiver: Receiver = try .init(allocator, 1, 1);
    defer receiver.deinit(allocator);

    var packet: Packet = undefined;
    initTestDataPacket(&packet, 1);

    const leader_schedule: *const lib.solana.LeaderSchedule = undefined;
    var deshred_writer: DeshredRing.Iterator(.writer) = undefined;

    try std.testing.expectError(
        error.ShredVersionMismatch,
        receiver.processPacket(
            leader_schedule,
            2,
            &packet,
            &deshred_writer,
            .noop,
        ),
    );
}

test "shred.receiver: one shred (unfinished fec set)" {
    const allocator = std.testing.allocator;

    var receiver: Receiver = try .init(allocator, 1, 1);
    defer receiver.deinit(allocator);

    const std_keypair = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(1));
    const keypair: lib.gossip.KeyPair = .fromKeyPair(std_keypair);

    const leader_schedule = try allocator.create(lib.solana.LeaderSchedule);
    defer allocator.destroy(leader_schedule);
    leader_schedule.base_slot = 1;
    leader_schedule.leaders[0] = keypair.pubkey;

    var packet: Packet = undefined;
    _ = initTestDataPacket(&packet, 1);
    try signTestDataPacket(&packet, &keypair);

    var deshred_writer: DeshredRing.Iterator(.writer) = undefined;

    const result = try receiver.processPacket(
        leader_schedule,
        1,
        &packet,
        &deshred_writer,
        .noop,
    );
    switch (result) {
        .unfinished_fec_set => |unfinished| {
            try std.testing.expectEqual(1, unfinished.total_shreds_received);
        },
        else => try std.testing.expect(false),
    }
}

test "shred.receiver: duplicate shred" {
    const allocator = std.testing.allocator;

    var receiver: Receiver = try .init(allocator, 1, 1);
    defer receiver.deinit(allocator);

    const std_keypair = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(1));
    const keypair: lib.gossip.KeyPair = .fromKeyPair(std_keypair);

    const leader_schedule = try allocator.create(lib.solana.LeaderSchedule);
    defer allocator.destroy(leader_schedule);
    leader_schedule.base_slot = 1;
    leader_schedule.leaders[0] = keypair.pubkey;

    var packet: Packet = undefined;
    _ = initTestDataPacket(&packet, 1);
    try signTestDataPacket(&packet, &keypair);

    var deshred_writer: DeshredRing.Iterator(.writer) = undefined;

    const first_result = try receiver.processPacket(
        leader_schedule,
        1,
        &packet,
        &deshred_writer,
        .noop,
    );
    switch (first_result) {
        .unfinished_fec_set => |unfinished| {
            try std.testing.expectEqual(1, unfinished.total_shreds_received);
        },
        else => try std.testing.expect(false),
    }

    const second_result = try receiver.processPacket(
        leader_schedule,
        1,
        &packet,
        &deshred_writer,
        .noop,
    );
    try std.testing.expectEqual(.shred_already_seen, std.meta.activeTag(second_result));
}

test "InProgressSets basic usage" {
    const allocator = std.testing.allocator;
    const set_signature: Signature = .ZEROES;
    const set_id: FecSetId = .{ .slot = 123, .fec_set_idx = 32 };

    var in_progress: InProgressSets = try .init(allocator, 16);
    defer in_progress.deinit(allocator);

    // doesn't contain anything yet
    try std.testing.expect(!in_progress.containsId(set_id));
    try std.testing.expectEqual(null, in_progress.getFecSetCtx(&Signature.ZEROES));
    try std.testing.expectEqual(null, in_progress.getCtxById(set_id));

    // add set
    const ctx = try in_progress.createFecSetCtx(set_id, &set_signature);

    // find set
    const found_ctx = in_progress.getFecSetCtx(&set_signature) orelse unreachable;
    try std.testing.expectEqual(ctx, found_ctx);
    try std.testing.expect(in_progress.containsId(set_id));
    try std.testing.expectEqual(ctx, in_progress.getCtxById(set_id));

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

    /// Returns the set to its post-init state without freeing any heap memory.
    /// Preserves the existing capacities of `done_pool`, `done_map`, and
    /// `eviction`.
    fn reset(self: *DoneSets) void {
        self.done_pool.reset();
        self.done_map.clearRetainingCapacity();
        self.eviction.items.len = 0;
    }

    // This signature+id must not be inside DoneSet already - any shred inside DoneSets should be
    // dropped early, so setDone should be unreachable in this case.
    fn setDone(
        self: *DoneSets,
        signature: *const Signature,
        id: FecSetId,
        merkle_root: *const Hash,
        chained_merkle_root: *const Hash,
    ) void {
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
        new_done.* = .{
            .id = id,
            .signature_hashed = hashSignature(signature),
            .merkle_root = merkle_root.*,
            .chained_merkle_root = chained_merkle_root.*,
        };
        self.eviction.add(new_pool_id) catch unreachable;
        const entry = self.done_map.getOrPutAssumeCapacityAdapted(&id, done_ctx);
        std.debug.assert(!entry.found_existing);
        entry.value_ptr.* = new_done;
    }

    fn lookupStatus(
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

    /// `(merkle_root, chained_merkle_root)` pinned for a completed FEC set,
    /// or null if `id` is unknown. Used by `Receiver.lookupFecSetRoots` for
    /// the cross-FEC chain check.
    fn getRoots(self: *const DoneSets, id: FecSetId) ?FecSetRoots {
        const done_ctx: DoneContext = .{ .done_map = &self.done_map };
        const entry = self.done_map.getAdapted(&id, done_ctx) orelse return null;
        return .{
            .merkle_root = entry.merkle_root,
            .chained_merkle_root = entry.chained_merkle_root,
        };
    }

    fn assertCounts(self: *const DoneSets) void {
        std.debug.assert(self.eviction.items.len == self.done_map.count());
        tracy.plot(u32, "done FEC sets", @intCast(self.eviction.items.len));
    }

    const DoneItem = extern struct {
        signature_hashed: u32,
        id: FecSetId,
        merkle_root: Hash,
        chained_merkle_root: Hash,
    };
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

    done_sets.setDone(&sig_1, id_1, &Hash.ZEROES, &Hash.ZEROES);

    try std.testing.expectEqual(.matching_signature, done_sets.lookupStatus(id_1, &sig_1));
    try std.testing.expectEqual(.missing, done_sets.lookupStatus(id_2, &sig_2));
    try std.testing.expectEqual(.missing, done_sets.lookupStatus(id_3, &sig_3));

    done_sets.setDone(&sig_2, id_2, &Hash.ZEROES, &Hash.ZEROES);

    try std.testing.expectEqual(.matching_signature, done_sets.lookupStatus(id_1, &sig_1));
    try std.testing.expectEqual(.matching_signature, done_sets.lookupStatus(id_2, &sig_2));
    try std.testing.expectEqual(.missing, done_sets.lookupStatus(id_3, &sig_3));

    done_sets.setDone(&sig_3, id_3, &Hash.ZEROES, &Hash.ZEROES);

    try std.testing.expectEqual(.missing, done_sets.lookupStatus(id_1, &sig_1)); // 1 was evicted
    try std.testing.expectEqual(.matching_signature, done_sets.lookupStatus(id_2, &sig_2));
    try std.testing.expectEqual(.matching_signature, done_sets.lookupStatus(id_3, &sig_3));
}

test "DoneSets reset clears state without freeing" {
    const allocator = std.testing.allocator;

    var done_sets: DoneSets = try .init(allocator, 2);
    defer done_sets.deinit(allocator);

    const sig_1: Signature = .parse(
        \\3NyXqg7XjPBX5eW2zpExpAJTdXCHpVt4RR2uPPc6XUzTCVeAphwzpNBxHtYPpipE1gne2NW6ELW6HVdaB7oV9DEn
    );
    const sig_2: Signature = .parse(
        \\2RUa9Sv3T2vwxeubSwJUS63W7N2wT9RaMcaoGJS6a28zGmSvpdArZMcDe7n3JTeBtuh1BkSgaJ8eN3WF7TBMjkG6
    );

    const id_1: FecSetId = .{ .slot = 1, .fec_set_idx = 0 };
    const id_2: FecSetId = .{ .slot = 2, .fec_set_idx = 0 };

    done_sets.setDone(&sig_1, id_1, &Hash.ZEROES, &Hash.ZEROES);
    done_sets.setDone(&sig_2, id_2, &Hash.ZEROES, &Hash.ZEROES);
    try std.testing.expectEqual(.matching_signature, done_sets.lookupStatus(id_1, &sig_1));
    try std.testing.expectEqual(.matching_signature, done_sets.lookupStatus(id_2, &sig_2));

    done_sets.reset();

    // After reset both lookups must miss.
    try std.testing.expectEqual(.missing, done_sets.lookupStatus(id_1, &sig_1));
    try std.testing.expectEqual(.missing, done_sets.lookupStatus(id_2, &sig_2));

    // Capacity is retained — refilling to the original size must not allocate
    // (eviction.allocator is the testing failing allocator after init).
    done_sets.setDone(&sig_1, id_1, &Hash.ZEROES, &Hash.ZEROES);
    done_sets.setDone(&sig_2, id_2, &Hash.ZEROES, &Hash.ZEROES);
    try std.testing.expectEqual(.matching_signature, done_sets.lookupStatus(id_1, &sig_1));
    try std.testing.expectEqual(.matching_signature, done_sets.lookupStatus(id_2, &sig_2));
}

test "DoneSets.getRoots returns the pinned roots" {
    const allocator = std.testing.allocator;

    var done_sets: DoneSets = try .init(allocator, 4);
    defer done_sets.deinit(allocator);

    const sig_1: Signature = .ZEROES;
    const id_1: FecSetId = .{ .slot = 7, .fec_set_idx = 0 };

    const merkle: Hash = .{ .data = @splat(0xAA) };
    const chained: Hash = .{ .data = @splat(0xBB) };

    try std.testing.expectEqual(null, done_sets.getRoots(id_1));

    done_sets.setDone(&sig_1, id_1, &merkle, &chained);

    const got = done_sets.getRoots(id_1) orelse return error.TestUnexpectedNull;
    try std.testing.expect(got.merkle_root.eql(&merkle));
    try std.testing.expect(got.chained_merkle_root.eql(&chained));

    // Unknown id still misses.
    try std.testing.expectEqual(
        null,
        done_sets.getRoots(.{ .slot = 7, .fec_set_idx = 32 }),
    );
}
