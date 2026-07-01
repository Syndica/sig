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
const FecSetId = lib.shred.FecSetId;
const Shred = lib.shred.Shred;

/// Takes in shreds, and writes out deshredded fec sets.
/// For full docs see `services/shred_receiver.zig`.
pub fn Receiver(comptime Effects: type) type {
    lib.util.assertInterface(Effects, struct {
        pub fn reportShredParseResult(self: Effects, parses_as_chained: bool) void {
            _ = .{ self, parses_as_chained };
        }

        pub fn reportFecSetCompleted(
            self: Effects,
            completed: *const DeshreddedFecSet,
            ctx: *const FecSetCtx,
        ) void {
            _ = .{ self, completed, ctx };
        }

        pub fn writeCompletedFecSet(self: Effects) *DeshreddedFecSet {
            _ = self;
            return undefined;
        }

        pub fn flushCompletedFecSet(self: Effects) void {
            _ = self;
        }

        pub fn reportReceiverPacketResult(self: Effects, result: PacketResult) void {
            _ = .{ self, result };
        }

        pub fn reportChainConflict(self: Effects, slot: Slot) void {
            _ = .{ self, slot };
        }
    });

    return struct {
        const Self = @This();

        /// Per-feature activation slots. A feature is enforced for shreds
        /// whose slot is `>= activation_slot`; the default `maxInt(Slot)`
        /// keeps every feature inactive.
        pub const Features = struct {
            discard_unexpected_data_complete_shreds: Slot = std.math.maxInt(Slot),
        };

        effects: Effects,

        /// Borrowed from `init`'s caller; used only to grow `dead_slots`.
        allocator: std.mem.Allocator,

        // We will ignore shreds outside of this range, as they're not useful to us
        root_slot: Slot,
        max_slot: Slot,

        features: Features,

        in_progress: InProgressSets,
        done: DoneSets,

        /// Slots that hit a fatal protocol violation (chain conflict,
        /// malformed recovered shred, etc.). This is a *downstream signal*:
        /// the deshred-ring emission step at the end of `processPacketInner`
        /// suppresses output for any slot in the set, telling replay (and
        /// the conformance harness) that the slot is unrecoverable.
        /// Per-shred admission stays governed by `slot_parents` and the
        /// within/cross-FEC chained-merkle checks — `dead_slots` does not
        /// gate insertion, so the FEC accumulator's record of which shreds
        /// arrived for the slot still matches the blockstore row Agave
        /// keeps even for dead slots. Pruned in `updateSlotRange` once the
        /// root advances past the slot.
        dead_slots: std.AutoHashMapUnmanaged(Slot, void),

        /// First-seen `parent_slot` (i.e. `shred.slot - parent_offset`) for
        /// every slot we have accepted a data shred from. A non-genesis slot
        /// has a single parent in the canonical fork tree, so any later data
        /// shred declaring a different parent is a protocol violation and
        /// marks the slot dead. Agave enforces the same invariant in
        /// `should_insert_data_shred` via `slot_meta.parent_slot` (agave
        /// `ledger/src/blockstore.rs`); without it, fuzz-crafted shreds with
        /// identical merkle roots but mismatched `parent_offset` slip past
        /// the merkle/chained-merkle checks. Pruned in `updateSlotRange`.
        slot_parents: std.AutoHashMapUnmanaged(Slot, Slot),

        pub fn init(
            allocator: std.mem.Allocator,
            in_progress_capacity: u32,
            done_capacity: u32,
            effects: Effects,
        ) !Self {
            var in_progress: InProgressSets = try .init(allocator, in_progress_capacity);
            errdefer in_progress.deinit(allocator);

            var done: DoneSets = try .init(allocator, done_capacity);
            errdefer done.deinit(allocator);

            return .{
                .effects = effects,
                .allocator = allocator,
                .in_progress = in_progress,
                .done = done,
                .dead_slots = .empty,
                .slot_parents = .empty,

                .root_slot = 0,
                .max_slot = std.math.maxInt(Slot),
                .features = .{},
            };
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.in_progress.deinit(allocator);
            self.done.deinit(allocator);
            self.dead_slots.deinit(allocator);
            self.slot_parents.deinit(allocator);
        }

        /// Reset to the post-init state without freeing any heap memory. Intended
        /// for callers that reuse a single Receiver across many independent
        /// inputs (e.g. the conformance shred-parse harness, which runs one
        /// fixture per invocation and must not leak state between them).
        ///
        /// Does not touch `effects` — the caller is responsible for resetting
        /// any Effects state it owns.
        pub fn reset(self: *Self) void {
            self.in_progress.reset();
            self.done.reset();
            self.dead_slots.clearRetainingCapacity();
            self.slot_parents.clearRetainingCapacity();
            self.root_slot = 0;
            self.max_slot = std.math.maxInt(Slot);
            self.features = .{};
        }

        pub fn updateSlotRange(self: *Self, root_slot: Slot, max_slot: Slot) void {
            self.root_slot = root_slot;
            self.max_slot = max_slot;

            // Dead-slot entries below the new root are unreachable; drop them.
            // Bounded scratch: anything above this in a single advance is a
            // pathological state we surface as a missed cleanup, not a crash.
            var stale_buf: [64]Slot = undefined;
            var stale_len: usize = 0;
            var it = self.dead_slots.iterator();
            while (it.next()) |entry| {
                if (entry.key_ptr.* < root_slot) {
                    if (stale_len == stale_buf.len) break;
                    stale_buf[stale_len] = entry.key_ptr.*;
                    stale_len += 1;
                }
            }
            for (stale_buf[0..stale_len]) |slot| _ = self.dead_slots.remove(slot);

            // Same bounded prune for `slot_parents`.
            stale_len = 0;
            var pit = self.slot_parents.iterator();
            while (pit.next()) |entry| {
                if (entry.key_ptr.* < root_slot) {
                    if (stale_len == stale_buf.len) break;
                    stale_buf[stale_len] = entry.key_ptr.*;
                    stale_len += 1;
                }
            }
            for (stale_buf[0..stale_len]) |slot| _ = self.slot_parents.remove(slot);

            // TODO: this is where we would add code to prune entries outside of the new range.
        }

        /// Mark `slot` as dead. The dead-slot flag is a *downstream signal*:
        /// it tells consumers of `state.effects` (replay, the conformance
        /// harness) that the slot is unrecoverable, and the deshred-ring
        /// emission step suppresses output for the slot. The FEC
        /// accumulator's record of which shreds arrived for `slot` is left
        /// untouched — insertion-layer protocol invariants
        /// (`slot_parents`, chained-merkle equality) are what gate further
        /// shreds, not this flag. In-progress ctxs for dead slots are
        /// reclaimed by normal pool eviction and the root-advance prune.
        /// OOM growing the dead-slot set is silently dropped: the slot
        /// failed once; downstream callers already saw the originating error.
        pub fn markSlotDead(self: *Self, slot: Slot) void {
            self.dead_slots.put(self.allocator, slot, {}) catch {};
        }

        /// `(merkle_root, chained_merkle_root)` pinned for some FEC set, or
        /// null if neither `in_progress` nor `done` has seen it. Used by the
        /// cross-FEC chain check.
        fn lookupFecSetRoots(self: *const Self, id: FecSetId) ?FecSetRoots {
            if (self.in_progress.getCtxById(id)) |ctx| return .{
                .merkle_root = ctx.merkle_root,
                .chained_merkle_root = ctx.chained_merkle_root,
            };
            return self.done.getRoots(id);
        }

        // TODO: report return values to observability
        // TODO: report back equivocating shreds, so that we can construct and send out duplicate proofs
        pub fn processPacket(
            state: *Self,
            leader_schedule: *const lib.solana.LeaderSchedule,
            network_shred_version: u16,
            packet: *const Packet,
            logger: lib.telemetry.Logger("processPacket"),
        ) ProcessPacketError!PacketSuccess {
            const result = state.processPacketInner(
                leader_schedule,
                network_shred_version,
                packet,
                logger,
            ) catch |err| {
                switch (err) {
                    error.NoSpaceLeft => {
                        logger.fatal().logf("no space left while processing shred packet", .{});
                        return err;
                    },
                    else => |packet_err| {
                        logger.warn().logf("packet failed with {}", .{packet_err});
                        state.effects.reportReceiverPacketResult(.{ .failed = packet_err });
                        return packet_err;
                    },
                }
            };
            state.effects.reportReceiverPacketResult(.{ .success = result });
            return result;
        }

        fn processPacketInner(
            state: *Self,
            leader_schedule: *const lib.solana.LeaderSchedule,
            network_shred_version: u16,
            packet: *const Packet,
            logger: lib.telemetry.Logger("processPacket"),
        ) ProcessPacketError!PacketSuccess {
            const zone = tracy.Zone.init(@src(), .{ .name = "processPacket" });
            defer zone.deinit();

            // check that the shred variant is supported and the header is valid
            const shred = Shred.fromPacketChecked(packet) catch |err| {
                state.effects.reportShredParseResult(false);
                return err;
            };
            state.effects.reportShredParseResult(true);

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
                }

                if (shred.fec_set_idx % FecSetCtx.fec_shred_count != 0) {
                    return error.InvalidFecSetIdx;
                }
                if (in_type_idx >= FecSetCtx.fec_shred_count) return error.ShredIdxTooLarge;

                const merkle_layer_count = 7;
                if (shred.variant.merkle_count > merkle_layer_count - 1) {
                    return error.MerkleCountTooLarge;
                }
            }

            // Per-slot `parent_slot` consistency. Every data shred in a slot
            // must declare the same parent (`shred.slot - parent_offset`);
            // the slot has a single position in the fork tree. Agave enforces
            // this in `Blockstore::should_insert_data_shred` (the
            // `meta_parent_slot != shred_parent` branch in
            // `ledger/src/blockstore.rs`): a mismatch returns InvalidShred,
            // which causes `mark_slot_dead_if_not_full`. Without this check,
            // fuzz-crafted shreds whose proof bytes collide on a single
            // merkle root can still smuggle in mismatched parents and slip
            // past the merkle / chained-merkle equality checks above.
            if (shred.variant.isData()) {
                const parent_slot = shred.slot - shred.code_or_data.data.parent_offset;
                // [agave] Drop data shreds whose declared parent is older
                // than the current root: agave's
                // `ShredFilterContext::should_discard_shred` rejects these
                // at the layout level via `verify_shred_slots` (in
                // `ledger/src/shred/filter.rs`) before they ever reach
                // `insert_shreds`, so they never participate in the
                // slot-meta `meta_parent_slot != shred_parent` check
                // below and never trigger `mark_slot_dead_if_not_full`.
                // Without this gate, a fuzz-crafted shred whose
                // `parent_offset` chains to a pre-root slot would be
                // treated here as a slot_parents conflict and incorrectly
                // mark the slot dead, diverging from agave.
                if (parent_slot < state.root_slot) return error.ShredParentBeforeRoot;
                const gop = state.slot_parents.getOrPut(state.allocator, shred.slot) catch {
                    // OOM: skip the bookkeeping rather than fail-closed. The
                    // worst case is missing this check on a later shred,
                    // which mirrors agave's behavior when its slot meta
                    // lookup encounters allocator pressure.
                    return error.NoSpaceLeft;
                };
                if (gop.found_existing) {
                    if (gop.value_ptr.* != parent_slot) {
                        state.markSlotDead(shred.slot);
                        return error.ParentSlotMismatch;
                    }
                } else {
                    gop.value_ptr.* = parent_slot;
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
                // fec set is already being built. This branch will be taken for 31/64 shreds (assuming
                // zero packet loss).

                // variant should match that of the first recorded shred in the fec set
                if ((shred.variant.isData() and !shred.variant.eql(fec_set_ctx.data_variant)) or
                    (shred.variant.isCode() and !shred.variant.eql(fec_set_ctx.code_variant)))
                {
                    return error.VariantMismatchFromFecSet;
                }

                // The signature of a shred protects its merkle root. We now have a shred that matches a
                // signature that we verified against a merkle root earlier - we just need to check if
                // the merkle root is the same.
                //
                // Checking the signature again requires calculating the merkle root anyway, and is much
                // more expensive (37us vs 1us on my CPU, as of writing).
                //
                // NOTE: firedancer optimises "inserting" shreds into fec sets using
                // fd_bmtree_commitp_insert_with_proof, which may be of interest.
                var shred_merkle_root: Hash = undefined;
                try shred.merkleRoot(&shred_merkle_root);
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

                switch (state.done.lookupStatus(fec_set_id, &shred.signature)) {
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
                    .mismatching_signature => {
                        return error.EquivocationDifferentHashForSameFecSetId;
                    },
                }

                // if we have this FecSetId with a different signature, this means equivocation has occured
                if (state.in_progress.containsId(fec_set_id)) {
                    // NOTE: see above note.
                    return error.EquivocationFecSetIdAlreadyInProgress;
                }

                // This is the first shred of a new in-progress fec set.

                // The shred's merkle root must be calculated unconditionally.
                const shred_merkle_root: Hash = blk: {
                    var shred_merkle_root: Hash = undefined;

                    if (!build_options.debug_skip_shred_sig_verify) {
                        const slot_leader = leader_schedule.get(shred.slot) orelse {
                            logger.warn().logf("slot {} missing?\n", .{shred.slot});
                            return error.UnknownLeader;
                        };

                        try shred.merkleRoot(&shred_merkle_root);

                        shred.signature.verify(
                            slot_leader,
                            &shred_merkle_root.data,
                        ) catch return error.SignatureVerificationFailed;
                    } else {
                        // debug purposes only
                        try shred.merkleRoot(&shred_merkle_root);
                    }

                    break :blk shred_merkle_root;
                };

                const fec_set_ctx = state.in_progress.createFecSetCtx(
                    fec_set_id,
                    &shred.signature,
                );

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

            // Cross-FEC `chained_merkle_root` chain. With set N's roots pinned
            // (commit `pin chained_merkle_root per FEC set`), a single shred
            // from either side of a chain break is enough to expose it; we no
            // longer need to wait for both sets to complete. agave catches the
            // same condition in `Blockstore::check_chained_merkle_root_consistency`,
            // which records a `ChainedMerkleRootConflict` duplicate-shred event
            // but still inserts the shred — the conflict invalidates the block
            // as a whole, but individual FEC sets stay independently valid and
            // must keep accumulating so the downstream consumer sees the same
            // completed FEC sets either implementation would emit.
            if (state.lookupFecSetRoots(.{
                .slot = shred.slot,
                .fec_set_idx = shred.fec_set_idx + FecSetCtx.fec_shred_count,
            })) |next| {
                if (!fec_set_ctx.merkle_root.eql(&next.chained_merkle_root)) {
                    state.effects.reportChainConflict(shred.slot);
                }
            }
            if (shred.fec_set_idx >= FecSetCtx.fec_shred_count) {
                if (state.lookupFecSetRoots(.{
                    .slot = shred.slot,
                    .fec_set_idx = shred.fec_set_idx - FecSetCtx.fec_shred_count,
                })) |prev| {
                    if (!prev.merkle_root.eql(&fec_set_ctx.chained_merkle_root)) {
                        state.effects.reportChainConflict(shred.slot);
                    }
                }
            }

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
            // retransmitter sig) and the leading signature untouched, so we
            // can only re-check invariants derivable from the recovered
            // bytes: structural layout, slot/fec_set_idx vs the pinned ctx,
            // variant consistency, and positional `slot_idx`. The merkle and
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
                const recovered = Shred.fromPacketChecked(&recovered_packet) catch {
                    state.markSlotDead(shred.slot);
                    return error.RecoveredShredMalformed;
                };
                if (recovered.slot != shred.slot or
                    recovered.fec_set_idx != shred.fec_set_idx or
                    !recovered.variant.isData() or
                    !recovered.variant.eql(fec_set_ctx.data_variant) or
                    recovered.slot_idx != shred.fec_set_idx + idx)
                {
                    state.markSlotDead(shred.slot);
                    return error.RecoveredShredMalformed;
                }
            }

            // Dead-slot gate: insertion + RS recovery + re-validation have
            // run unconditionally (the FEC accumulator's record matches the
            // blockstore row Agave keeps even for dead slots). Production
            // emission to the deshred ring is suppressed for dead slots so
            // replay receives no further data for the unrecoverable slot;
            // the ctx is left in `in_progress` and reclaimed by normal pool
            // eviction / root-advance prune.
            if (state.dead_slots.contains(shred.slot)) {
                return .fec_set_finished;
            }

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

                const finished: *DeshreddedFecSet = state.effects.writeCompletedFecSet();
                defer state.effects.flushCompletedFecSet();

                finished.* = .{
                    .merkle_root = fec_set_ctx.merkle_root,
                    .chained_merkle_root = fec_set_ctx.chained_merkle_root,
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

                    if (Shred.fromBufferUnchecked(buffer)
                        .code_or_data.data.flags.data_complete) break;
                }

                std.debug.assert(bytes_written == total_payload_len);
                state.effects.reportFecSetCompleted(finished, fec_set_ctx);
            }

            state.done.setDone(
                &shred.signature,
                fec_set_id,
                &fec_set_ctx.merkle_root,
                &fec_set_ctx.chained_merkle_root,
            );
            state.in_progress.removeFinishedSet(fec_set_ctx);

            tracy.frameMarkNamed("finished FEC sets");

            return .fec_set_finished;
        }
    };
}

pub const PacketError = error{
    PacketUnderMinHeaderSize,
    UnsupportedVariant,
    PacketUnderHeaderSize,
    DataSmallerThanHeader,
    DataPacketUnderMinSize,
    DataEffectiveSizeTooSmall,
    CodeShredOverMaxSize,
    PacketSizeUnderExpected3,
    DataShredMarkedCompleteIsNotLastInSet,
    BadOffset,
    BadSlotOrParentOffset,
    BadSlotIdx,
    BadCodeShredIdx,
    NoCodeOrDataCount,
    CodeOrDataCountTooLarge,
    InvalidMerkleProof,
    ShredOlderThanRoot,
    ShredTooNew,
    ShredVersionMismatch,
    FecSetIndexTooHigh,
    SlotIndexTooHigh,
    BadDataShredCount,
    BadCodeShredCount,
    InvalidFecSetIdx,
    ShredIdxTooLarge,
    MerkleCountTooLarge,
    UnexpectedDataCompleteShred,
    VariantMismatchFromFecSet,
    MismatchedMerkleRoot,
    MismatchedChainedMerkleRoot,
    EquivocationDifferentHashForSameFecSetId,
    EquivocationFecSetIdAlreadyInProgress,
    ParentSlotMismatch,
    ShredParentBeforeRoot,
    UnknownLeader,
    SignatureVerificationFailed,
    RecoveredShredMalformed,
};

pub const PacketSuccess = union(enum) {
    unfinished_fec_set: struct { total_shreds_received: u8 },
    fec_set_finished,
    fec_set_already_finished,
    shred_already_seen,
};

/// Pair of roots pinned for a single FEC set. Returned by neighbor lookup
/// during the cross-FEC chain check.
pub const FecSetRoots = struct {
    merkle_root: Hash,
    chained_merkle_root: Hash,
};

pub const PacketResult = union(enum) {
    success: PacketSuccess,
    failed: PacketError,
};

const ProcessPacketError = PacketError || error{NoSpaceLeft};

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
    pub const data_shreds_max = 32;
    pub const code_shreds_max = 32;
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
    ) *FecSetCtx {
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

    fn getCtxById(self: *const InProgressSets, id: FecSetId) ?*FecSetCtx {
        return for (self.signature_map.values()) |fec_set_ctx| {
            const pool_id = self.ctx_pool.ptrToIndex(fec_set_ctx);
            const idx = pool_id.index().?;

            if (self.ids[idx].eql(&id)) break fec_set_ctx;
        } else null;
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
    try std.testing.expectEqual(null, in_progress.getCtxById(set_id));

    // add set
    const ctx = in_progress.createFecSetCtx(set_id, &set_signature);

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
    try std.testing.expectEqual(null, in_progress.getCtxById(set_id));
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

    // Capacity must be retained \u2014 we must be able to refill to the original
    // size without any allocation (eviction.allocator is the testing failing
    // allocator after init).
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
