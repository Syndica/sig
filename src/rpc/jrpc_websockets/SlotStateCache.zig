//! Tracks slot lifecycle and per-slot modified accounts so websocket delivery can
//! derive commitment-specific notifications from minimal producer events.
const std = @import("std");
const sig = @import("../../sig.zig");

const types = @import("types.zig");

const Slot = sig.core.Slot;
const Reward = sig.ledger.transaction_status.Reward;
const TransactionError = sig.ledger.transaction_status.TransactionError;
const InnerInstructions = sig.ledger.transaction_status.InnerInstructions;
const InnerInstruction = sig.ledger.transaction_status.InnerInstruction;
const TransactionTokenBalance = sig.ledger.transaction_status.TransactionTokenBalance;
const TransactionReturnData = sig.ledger.transaction_status.TransactionReturnData;
const SlotFrozenEvent = types.SlotFrozenEvent;
const SlotTransactionBatch = types.SlotTransactionBatch;
const TransactionEntry = types.TransactionEntry;
const SlotModifiedAccounts = types.SlotModifiedAccounts;
const DistributedRewards = sig.replay.freeze.DistributedRewards;
const SlotTrackerReference = sig.replay.trackers.SlotTracker.Reference;
const Logger = sig.trace.Logger("rpc.jrpc_websockets.slot_state_cache");
pub const SlotReadContext = types.SlotReadContext;

/// Max tracked slots retained, used to avoid unbounded memory growth if we receive unexpected
/// event patterns. Under normal operation eviction should occur when slots are rooted.
const MAX_CACHED_SLOTS: usize = 512;

const SlotStateCache = @This();

logger: Logger,
/// Tracked latest processed tip slot number.
processed_tip: Slot = 0,
/// Cached latest processed tip slot info (for ancestor information).
processed_tip_info: ?SlotTrackerReference = null,
cached_slots: std.AutoArrayHashMapUnmanaged(Slot, CachedSlot) = .empty,

// TODO: we currently track everything just by slot number, this is brittle to replay over same
// slot. E.g. hypothetical sequences that would lead to wrong confirmed notifications:
// frozen(123'a) -> confirmed(123) -> frozen(123'b)
// confirmed(123) -> frozen(123'a) -> frozen(123'b)
//
// Version a and b are different, same slot number (replayed over same slot), confirmation doesn't
// tell us if it was a or b that was confirmed. This is a problem in Agave as well.
pub const CachedSlot = struct {
    parent: ?Slot = null,
    root: ?Slot = null,
    state: StateFlags = .{},
    published: PublishedFlags = .{},
    /// Final account states for the accounts modified in this slot, captured at freeze time.
    modified_accounts: SlotModifiedAccounts = .empty(),
    /// Rich transaction batches for this slot.
    transaction_batches: std.ArrayListUnmanaged(SlotTransactionBatch) = .empty,

    // Block-level metadata (populated on freeze)
    blockhash: ?sig.core.Hash = null,
    previous_blockhash: ?sig.core.Hash = null,
    block_height: ?u64 = null,
    block_time: ?i64 = null,
    /// Rewards and partitions for this slot. Owns an arena
    /// that backs the rewards slice; freed in `deinit`.
    distributed_rewards: DistributedRewards = DistributedRewards.empty(),

    pub const StateFlags = packed struct {
        frozen: bool = false,
        confirmed: bool = false,
        rooted: bool = false,
    };

    /// Tracks which commitment levels have been published for this slot
    pub const PublishedFlags = packed struct {
        processed: bool = false,
        confirmed: bool = false,
        finalized: bool = false,
    };

    pub const TransactionBatchIterator = struct {
        tx_batches: []const SlotTransactionBatch = &.{},
        tx_batch_idx: usize = 0,
        entry_idx: usize = 0,

        pub const View = struct {
            signature: sig.core.Signature,
            err: ?sig.ledger.transaction_status.TransactionError,
            is_vote: bool,
            logs: []const []const u8,
            mentioned_pubkeys: []const sig.core.Pubkey,

            pub fn toOwnedLogsNotification(
                self: *const View,
                allocator: std.mem.Allocator,
                slot: u64,
            ) !types.LogsNotificationData {
                const cloned_logs = try types.cloneLogLines(allocator, self.logs);
                errdefer {
                    for (cloned_logs) |l| allocator.free(l);
                    allocator.free(cloned_logs);
                }

                const cloned_pubkeys = if (self.mentioned_pubkeys.len > 0)
                    try allocator.dupe(sig.core.Pubkey, self.mentioned_pubkeys)
                else
                    &.{};
                errdefer if (cloned_pubkeys.len > 0)
                    allocator.free(cloned_pubkeys);

                const cloned_err: ?TransactionError = if (self.err) |err|
                    try err.clone(allocator)
                else
                    null;

                return .{
                    .slot = slot,
                    .signature = self.signature,
                    .err = cloned_err,
                    .is_vote = self.is_vote,
                    .logs = cloned_logs,
                    .mentioned_pubkeys = cloned_pubkeys,
                };
            }
        };

        pub fn next(self: *TransactionBatchIterator) ?View {
            while (self.tx_batch_idx < self.tx_batches.len) {
                const b = &self.tx_batches[self.tx_batch_idx];
                if (self.entry_idx < b.entries.len) {
                    const e = &b.entries[self.entry_idx];
                    self.entry_idx += 1;
                    return .{
                        .signature = e.signature,
                        .err = e.err,
                        .is_vote = e.is_vote,
                        .logs = e.log_messages orelse &.{},
                        .mentioned_pubkeys = e.mentioned_pubkeys,
                    };
                }
                self.tx_batch_idx += 1;
                self.entry_idx = 0;
            }
            return null;
        }
    };

    /// Deep-copy all cached transaction and block data into `arena`, producing a standalone
    /// `VersionedConfirmedBlock` that can be handed to a worker thread. Returns `null` when block
    /// metadata is incomplete (not yet frozen).
    pub fn buildConfirmedBlock(
        self: *const CachedSlot,
        arena: std.mem.Allocator,
        parent_slot: Slot,
    ) !?sig.ledger.Reader.VersionedConfirmedBlock {
        const blockhash = self.blockhash orelse return null;
        const prev_blockhash = self.previous_blockhash orelse return null;

        // Count total transactions.
        var tx_count: usize = 0;
        for (self.transaction_batches.items) |batch| {
            tx_count += batch.entries.len;
        }

        // Collect entry pointers and sort by transaction_index to restore canonical ordering.
        // The async replay path may commit batches out of order since independent transactions
        // execute on different threads. Sorting is safer than scatter-by-index because it avoids
        // uninitialized memory if any batch event was dropped.
        const entry_ptrs = try arena.alloc(*const TransactionEntry, tx_count);
        var idx: usize = 0;
        for (self.transaction_batches.items) |batch| {
            for (batch.entries) |*entry| {
                entry_ptrs[idx] = entry;
                idx += 1;
            }
        }
        std.mem.sortUnstable(*const TransactionEntry, entry_ptrs, {}, struct {
            fn order(_: void, a: *const TransactionEntry, b: *const TransactionEntry) bool {
                return a.transaction_index < b.transaction_index;
            }
        }.order);

        const txns = try arena.alloc(
            sig.ledger.Reader.VersionedTransactionWithStatusMeta,
            tx_count,
        );
        for (entry_ptrs, 0..) |entry, i| {
            txns[i] = try buildTxWithMeta(arena, entry);
        }

        return .{
            .allocator = arena,
            .previous_blockhash = prev_blockhash,
            .blockhash = blockhash,
            .parent_slot = parent_slot,
            .transactions = txns,
            .rewards = try arena.dupe(Reward, self.distributed_rewards.rewards),
            .num_partitions = self.distributed_rewards.num_partitions,
            .block_time = self.block_time,
            .block_height = self.block_height,
        };
    }

    pub fn deinit(self: *CachedSlot, allocator: std.mem.Allocator) void {
        self.modified_accounts.deinit(allocator);
        for (self.transaction_batches.items) |*batch| {
            batch.deinit(allocator);
        }
        self.transaction_batches.deinit(allocator);
        self.distributed_rewards.deinit(allocator);
    }

    pub fn transactionBatchIterator(self: *const CachedSlot) TransactionBatchIterator {
        return .{
            .tx_batches = self.transaction_batches.items,
        };
    }
};

fn buildTxWithMeta(
    arena: std.mem.Allocator,
    entry: *const TransactionEntry,
) !sig.ledger.Reader.VersionedTransactionWithStatusMeta {
    return .{
        .transaction = try entry.transaction.clone(arena),
        .meta = .{
            .status = if (entry.err) |e| try e.clone(arena) else null,
            .fee = entry.fee,
            .pre_balances = try arena.dupe(u64, entry.pre_balances),
            .post_balances = try arena.dupe(u64, entry.post_balances),
            .inner_instructions = try cloneInners(arena, entry.inner_instructions),
            .log_messages = try cloneLogs(arena, entry.log_messages),
            .pre_token_balances = try cloneTokenBals(arena, entry.pre_token_balances),
            .post_token_balances = try cloneTokenBals(arena, entry.post_token_balances),
            // Per-transaction rewards are always empty in Agave.
            // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/transaction_status_service.rs#L190
            .rewards = &.{},
            .loaded_addresses = .{
                .writable = try arena.dupe(sig.core.Pubkey, entry.loaded_addresses.writable),
                .readonly = try arena.dupe(sig.core.Pubkey, entry.loaded_addresses.readonly),
            },
            .return_data = try cloneRetData(arena, entry.return_data),
            .compute_units_consumed = entry.compute_units_consumed,
            .cost_units = entry.cost_units,
        },
    };
}

fn cloneInners(
    arena: std.mem.Allocator,
    maybe_inners: ?[]const InnerInstructions,
) !?[]const InnerInstructions {
    const inners = maybe_inners orelse return null;
    const out = try arena.alloc(InnerInstructions, inners.len);
    for (inners, 0..) |inner, i| {
        const ixs = try arena.alloc(InnerInstruction, inner.instructions.len);
        for (inner.instructions, 0..) |ix, j| {
            ixs[j] = .{
                .instruction = .{
                    .program_id_index = ix.instruction.program_id_index,
                    .accounts = try arena.dupe(u8, ix.instruction.accounts),
                    .data = try arena.dupe(u8, ix.instruction.data),
                },
                .stack_height = ix.stack_height,
            };
        }
        out[i] = .{
            .index = inner.index,
            .instructions = ixs,
        };
    }
    return out;
}

fn cloneLogs(arena: std.mem.Allocator, maybe_logs: ?[]const []const u8) !?[]const []const u8 {
    const logs = maybe_logs orelse return null;
    const out = try arena.alloc([]const u8, logs.len);
    for (logs, 0..) |msg, i| {
        out[i] = try arena.dupe(u8, msg);
    }
    return out;
}

fn cloneTokenBals(
    arena: std.mem.Allocator,
    maybe_bals: ?[]const TransactionTokenBalance,
) !?[]const TransactionTokenBalance {
    const bals = maybe_bals orelse return null;
    const out = try arena.alloc(TransactionTokenBalance, bals.len);
    for (bals, 0..) |bal, i| {
        out[i] = .{
            .account_index = bal.account_index,
            .mint = bal.mint,
            .ui_token_amount = .{
                .ui_amount = bal.ui_token_amount.ui_amount,
                .decimals = bal.ui_token_amount.decimals,
                .amount = try arena.dupe(u8, bal.ui_token_amount.amount),
                .ui_amount_string = try arena.dupe(u8, bal.ui_token_amount.ui_amount_string),
            },
            .owner = bal.owner,
            .program_id = bal.program_id,
        };
    }
    return out;
}

fn cloneRetData(
    arena: std.mem.Allocator,
    maybe_rd: ?TransactionReturnData,
) !?TransactionReturnData {
    const rd = maybe_rd orelse return null;
    return .{
        .program_id = rd.program_id,
        .data = try arena.dupe(u8, rd.data),
    };
}

pub const NotificationCommitments = packed struct {
    processed: bool = false,
    confirmed: bool = false,
    finalized: bool = false,
};

/// Returned from event methods to indicate what commitment-specific notifications should
/// be emitted, which slot payload can be published immediately, and if cached slots should
/// be evicted.
pub const Transition = struct {
    publishable_slot: ?*const CachedSlot = null,
    notify_commitments: NotificationCommitments = .{},
    evict_through: ?Slot = null,
};

// Parent-chain item used for iterating ancestors of a slot.
pub const AncestorItem = struct {
    slot: Slot,
    cached_slot: *CachedSlot,
};

/// Iterator over slot ancestors using the cached slot parent links.
pub const AncestorIterator = struct {
    state: *SlotStateCache,
    next_slot: ?Slot,

    pub fn next(self: *AncestorIterator) ?AncestorItem {
        const slot = self.next_slot orelse return null;
        const cached_slot = self.state.cached_slots.getPtr(slot) orelse {
            self.next_slot = null;
            return null;
        };
        self.next_slot = cached_slot.parent;
        return .{ .slot = slot, .cached_slot = cached_slot };
    }
};

pub fn init(slot_read_ctx: SlotReadContext, logger: Logger) SlotStateCache {
    const processed_tip = slot_read_ctx.commitments.get(.processed);
    const processed_tip_info = slot_read_ctx.slot_tracker.get(processed_tip);
    return .{
        .logger = logger,
        .processed_tip = processed_tip,
        .processed_tip_info = processed_tip_info,
    };
}

pub fn deinit(self: *SlotStateCache, allocator: std.mem.Allocator) void {
    if (self.processed_tip_info) |tip_info| {
        tip_info.release();
    }
    for (self.cached_slots.values()) |*slot_state| {
        slot_state.deinit(allocator);
    }
    self.cached_slots.deinit(allocator);
}

/// On tip changed event updates the processed tip and its info, and is used to trigger
/// processed commitment notifications.
pub fn onTipChanged(
    self: *SlotStateCache,
    slot_read_ctx: SlotReadContext,
    new_tip: Slot,
) Transition {
    if (self.processed_tip == new_tip) {
        // should never happen, log it
        self.logger.err().logf(
            "received tip_changed for slot tip we already have set: {}",
            .{new_tip},
        );
    }

    // refresh tip info
    if (self.processed_tip_info) |tip_info| {
        tip_info.release();
    }
    self.processed_tip = new_tip;
    self.processed_tip_info = slot_read_ctx.slot_tracker.get(new_tip);
    if (self.processed_tip_info == null) {
        // should never happen, log it
        self.logger.err().logf(
            "received tip_changed for slot {} but it was not found in slot tracker",
            .{new_tip},
        );
    }

    // Check if slot is frozen and ready to publish as processed
    const slot_state = self.cached_slots.getPtr(new_tip) orelse return .{};
    if (!self.tryMarkProcessedPublished(new_tip, slot_state)) {
        self.logger.err().logf(
            "tip changed to slot {} but it is not frozen yet, this is unexpected ordering",
            .{new_tip},
        );
        return .{};
    }

    // tip changed to slot that is frozen, it can be pub
    return .{
        .publishable_slot = slot_state,
        .notify_commitments = .{ .processed = true },
    };
}

/// Freeze is the first point where the slot's final modified accounts are stable,
/// so cache them once here and reuse them for later confirmed/finalized publication.
pub fn onSlotFrozen(
    self: *SlotStateCache,
    allocator: std.mem.Allocator,
    slot_data: *SlotFrozenEvent,
) !Transition {
    const slot_state = try self.getOrPutSlot(allocator, slot_data.slot);
    const duplicate_frozen = slot_state.state.frozen;
    if (duplicate_frozen) {
        // TODO: what about repair/replay over same slot? Could be frozen twice for same
        // slot number. For now just overwrite the cached data and log it.
        self.logger.err().logf(
            "received duplicate slot_frozen for slot {}",
            .{slot_data.slot},
        );
        slot_state.modified_accounts.deinit(allocator);
        slot_state.distributed_rewards.deinit(allocator);
    }

    // Transfer ownership of accounts.
    slot_state.parent = slot_data.parent;
    slot_state.root = slot_data.root;
    slot_state.state.frozen = true;
    slot_state.modified_accounts = slot_data.accounts;
    slot_data.accounts = .empty();

    // Transfer block-level metadata.
    slot_state.blockhash = slot_data.blockhash;
    slot_state.previous_blockhash = slot_data.previous_blockhash;
    slot_state.block_height = slot_data.block_height;
    slot_state.block_time = slot_data.block_time;

    // Transfer ownership of distributed rewards (arena + slice).
    slot_state.distributed_rewards = slot_data.distributed_rewards;
    slot_data.distributed_rewards = sig.replay.freeze.DistributedRewards.empty();

    if (duplicate_frozen) {
        // TODO: for now just not emitting anything, this needs to be addressed by tracking more
        // than just slot numbers as a larger refactor in Sig
        return .{};
    }

    // Maybe other commitments for slot were waiting for frozen, so try all of them.
    const notify_commitments: NotificationCommitments = .{
        .processed = self.tryMarkProcessedPublished(slot_data.slot, slot_state),
        .confirmed = needsConfirmedFlush(slot_state),
        .finalized = tryMarkFinalizedPublished(slot_state),
    };
    return .{
        .publishable_slot = slot_state,
        .notify_commitments = notify_commitments,
    };
}

pub fn onTransactionBatchEvent(
    self: *SlotStateCache,
    allocator: std.mem.Allocator,
    batch_event: *SlotTransactionBatch,
) !void {
    if (batch_event.entries.len == 0) {
        batch_event.deinit(allocator);
        return;
    }

    const slot_state = try self.getOrPutSlot(allocator, batch_event.slot);
    // TODO: what about repair/replay over same slot? We can receive multiple tx batches for the
    // same slot during normal execution and append them, but if the slot is replayed with
    // different contents we still only key by slot number and do not handle that case.
    try slot_state.transaction_batches.append(allocator, batch_event.*);
    batch_event.* = SlotTransactionBatch.empty();
}

pub fn onSlotConfirmed(
    self: *SlotStateCache,
    allocator: std.mem.Allocator,
    slot: Slot,
) (std.mem.Allocator.Error || error{DuplicateSlotConfirmed})!Transition {
    const slot_state = self.getOrPutSlot(allocator, slot) catch |err| switch (err) {
        error.IncomingSlotTooOld => return .{},
        error.OutOfMemory => return error.OutOfMemory,
    };
    if (slot_state.state.confirmed) {
        return error.DuplicateSlotConfirmed;
    }
    slot_state.state.confirmed = true;
    var transition: Transition = .{ .notify_commitments = .{ .confirmed = true } };
    if (slot_state.state.frozen) {
        transition.publishable_slot = slot_state;
    }
    return transition;
}

pub fn onSlotRooted(
    self: *SlotStateCache,
    allocator: std.mem.Allocator,
    slot: Slot,
) (std.mem.Allocator.Error || error{DuplicateSlotRooted})!Transition {
    const slot_state = self.getOrPutSlot(allocator, slot) catch |err| switch (err) {
        error.IncomingSlotTooOld => return .{},
        error.OutOfMemory => return error.OutOfMemory,
    };
    if (slot_state.state.rooted) {
        return error.DuplicateSlotRooted;
    }
    slot_state.state.confirmed = true;
    slot_state.state.rooted = true;

    var transition: Transition = .{
        .notify_commitments = .{ .confirmed = !slot_state.published.confirmed, .finalized = true },
        .evict_through = slot,
    };
    if (tryMarkFinalizedPublished(slot_state)) {
        transition.publishable_slot = slot_state;
    }
    return transition;
}

/// Once a slot has rooted and we have delivered anything derived from it, older cached
/// account data is no longer needed for future commitment transitions.
/// Uses strict < so that the rooted slot itself survives until `onSlotFrozen` can
/// populate it (for the case where root arrives before freeze).
pub fn evictFinalizedThrough(
    self: *SlotStateCache,
    allocator: std.mem.Allocator,
    rooted_slot: Slot,
) void {
    var index: usize = 0;
    while (index < self.cached_slots.count()) {
        if (self.cached_slots.keys()[index] < rooted_slot) {
            // TODO(perf): Offload cached frozen-account teardown off the loop thread.
            self.cached_slots.values()[index].deinit(allocator);
            _ = self.cached_slots.swapRemoveAt(index);
        } else {
            index += 1;
        }
    }
}

pub fn ancestorIterator(self: *SlotStateCache, start_slot: Slot) AncestorIterator {
    return .{ .state = self, .next_slot = start_slot };
}

/// Walk newest->oldest from `start_slot`, mark the walked chain confirmed, and
/// return the unpublished frozen prefix for runtime to emit (returned in newest->oldest order).
/// If we encounter a non-frozen slot it means we have to wait for the frozen event and an empty
/// list is returned (cannot publish at confirmed commitment yet).
pub fn collectPublishableConfirmedSlots(
    self: *SlotStateCache,
    allocator: std.mem.Allocator,
    start_slot: Slot,
) !std.ArrayList(AncestorItem) {
    var slots: std.ArrayList(AncestorItem) = .{};
    errdefer slots.deinit(allocator);

    var ancestors = self.ancestorIterator(start_slot);
    while (ancestors.next()) |ancestor| {
        if (ancestor.cached_slot.published.confirmed) {
            break;
        }
        ancestor.cached_slot.state.confirmed = true;
        if (!ancestor.cached_slot.state.frozen) {
            // Confirmed but not frozen, just yield no slots as we have to wait for the frozen
            // event to ensure we have all the data required to be able to publish notifications
            // in slot order. We will try again on the next frozen event and eventually be able
            // to flush the confirmed slots in slot order.
            slots.clearRetainingCapacity();
            break;
        }
        try slots.append(allocator, ancestor);
    }

    // Mark all the collected slots published for confirmed
    for (slots.items) |item| {
        item.cached_slot.published.confirmed = true;
    }
    return slots;
}

fn getOrPutSlot(
    self: *SlotStateCache,
    allocator: std.mem.Allocator,
    slot: Slot,
) (std.mem.Allocator.Error || error{IncomingSlotTooOld})!*CachedSlot {
    if (self.cached_slots.getPtr(slot)) |slot_state| {
        return slot_state;
    }
    if (self.cached_slots.count() >= MAX_CACHED_SLOTS) {
        try self.evictMinimumSlot(allocator, slot);
    }

    const gop = try self.cached_slots.getOrPut(allocator, slot);
    gop.value_ptr.* = .{};
    return gop.value_ptr;
}

fn evictMinimumSlot(
    self: *SlotStateCache,
    allocator: std.mem.Allocator,
    incoming_slot: Slot,
) error{IncomingSlotTooOld}!void {
    var min_index: usize = 0;
    var min_slot = self.cached_slots.keys()[0];
    for (self.cached_slots.keys()[1..], 1..) |cached_slot, index| {
        if (cached_slot < min_slot) {
            min_slot = cached_slot;
            min_index = index;
        }
    }

    if (incoming_slot < min_slot) {
        self.logger.warn().logf(
            "slot state cache reached capacity of {}; dropping incoming slot {} " ++
                "because minimum cached slot is {}",
            .{ MAX_CACHED_SLOTS, incoming_slot, min_slot },
        );
        return error.IncomingSlotTooOld;
    }

    self.logger.warn().logf(
        "slot state cache reached capacity of {}; evicting minimum slot {} to insert slot {}",
        .{ MAX_CACHED_SLOTS, min_slot, incoming_slot },
    );
    // TODO(perf): Offload cached frozen-account teardown off the loop thread.
    self.cached_slots.values()[min_index].deinit(allocator);
    _ = self.cached_slots.swapRemoveAt(min_index);
}

fn needsConfirmedFlush(slot_state: *const CachedSlot) bool {
    return slot_state.state.confirmed and !slot_state.published.confirmed;
}

fn tryMarkProcessedPublished(self: *const SlotStateCache, slot: Slot, slot_state: *CachedSlot) bool {
    if (!slot_state.state.frozen or !self.isSlotOnCurrentFork(slot)) {
        return false;
    }
    if (slot_state.published.processed) {
        return false;
    }
    slot_state.published.processed = true;
    return true;
}

fn tryMarkFinalizedPublished(slot_state: *CachedSlot) bool {
    if (!slot_state.state.frozen or !slot_state.state.rooted) {
        return false;
    }
    if (slot_state.published.finalized) {
        return false;
    }
    slot_state.published.finalized = true;
    return true;
}

fn isSlotOnCurrentFork(self: *const SlotStateCache, slot: Slot) bool {
    if (slot == self.processed_tip) {
        return true;
    }
    const tip_info = self.processed_tip_info orelse return false;
    return tip_info.constants().ancestors.containsSlot(slot);
}

// --- unit tests ---

fn testSlotConstants(
    allocator: std.mem.Allocator,
    parent_slot: Slot,
    ancestor_slots: []const Slot,
) !sig.core.SlotConstants {
    return .{
        .parent_slot = parent_slot,
        .parent_hash = .ZEROES,
        .parent_lt_hash = .IDENTITY,
        .block_height = 0,
        .collector_id = .ZEROES,
        .max_tick_height = 0,
        .fee_rate_governor = .DEFAULT,
        .ancestors = try sig.core.Ancestors.initWithSlots(allocator, ancestor_slots),
        .feature_set = .ALL_DISABLED,
        .reserved_accounts = .empty,
        .inflation = .DEFAULT,
        .rent_collector = .DEFAULT,
    };
}

fn testAddTrackedSlot(
    allocator: std.mem.Allocator,
    slot_tracker: *sig.replay.trackers.SlotTracker,
    slot: Slot,
    parent_slot: Slot,
    ancestor_slots: []const Slot,
) !void {
    const gop = try slot_tracker.getOrPut(allocator, slot, .{
        .constants = try testSlotConstants(allocator, parent_slot, ancestor_slots),
        .state = .GENESIS,
        .allocator = allocator,
    });
    gop.reference.release();
}

var test_status_cache: sig.core.StatusCache = .DEFAULT;

fn testSlotReadCtx(
    slot_tracker: *sig.replay.trackers.SlotTracker,
    commitments: *sig.replay.trackers.CommitmentTracker,
) SlotReadContext {
    return .{
        .slot_tracker = slot_tracker,
        .commitments = commitments,
        .account_reader = .noop,
        .status_cache = &test_status_cache,
    };
}

fn testSlotFrozenEvent(slot: Slot, parent: Slot, root: Slot) SlotFrozenEvent {
    return .{ .slot = slot, .parent = parent, .root = root };
}

fn testOnSlotFrozen(
    state: *SlotStateCache,
    allocator: std.mem.Allocator,
    slot: Slot,
    parent: Slot,
    root: Slot,
) !Transition {
    var slot_data = testSlotFrozenEvent(slot, parent, root);
    return try state.onSlotFrozen(allocator, &slot_data);
}

fn testSlotTransactionBatch(
    allocator: std.mem.Allocator,
    slot: Slot,
    log_lines: []const []const u8,
) !SlotTransactionBatch {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const aa = arena.allocator();

    const entries = try aa.alloc(TransactionEntry, 1);
    const owned_logs = try aa.alloc([]const u8, log_lines.len);
    for (log_lines, 0..) |line, i| {
        owned_logs[i] = try aa.dupe(u8, line);
    }
    entries[0] = .{
        .signature = sig.core.Signature.ZEROES,
        .transaction = sig.core.Transaction.EMPTY,
        .is_vote = false,
        .transaction_index = 0,
        .err = null,
        .fee = 0,
        .compute_units_consumed = null,
        .cost_units = 0,
        .pre_balances = &.{},
        .post_balances = &.{},
        .pre_token_balances = null,
        .post_token_balances = null,
        .inner_instructions = null,
        .log_messages = owned_logs,
        .return_data = null,
        .loaded_addresses = .{},
        .mentioned_pubkeys = &.{},
    };

    return .{
        .slot = slot,
        .entries = entries,
        .arena_state = arena.state,
    };
}

test "slot frozen returns transition and marks state" {
    const allocator = std.testing.allocator;
    var slot_tracker = try sig.replay.trackers.SlotTracker.initEmpty(allocator, 0);
    defer slot_tracker.deinit(allocator);

    var commitments = sig.replay.trackers.CommitmentTracker.init(allocator, 0);
    defer commitments.deinit(allocator);

    try testAddTrackedSlot(allocator, &slot_tracker, 10, 9, &.{10});
    commitments.update(.processed, 10);

    const ctx = testSlotReadCtx(&slot_tracker, &commitments);
    var state = SlotStateCache.init(ctx, .FOR_TESTS);
    defer state.deinit(allocator);

    const transition = try testOnSlotFrozen(&state, allocator, 10, 9, 5);
    try std.testing.expect(transition.publishable_slot != null);
    try std.testing.expect(transition.notify_commitments.processed);
    try std.testing.expect(!transition.notify_commitments.confirmed);
    try std.testing.expect(!transition.notify_commitments.finalized);
    try std.testing.expect(transition.evict_through == null);

    const cached = transition.publishable_slot.?;
    try std.testing.expect(cached.state.frozen);
    try std.testing.expectEqual(9, cached.parent);
    try std.testing.expectEqual(5, cached.root);
    try std.testing.expect(cached.published.processed);
}

test "duplicate frozen overwrites cached slot data" {
    const allocator = std.testing.allocator;
    var slot_tracker = try sig.replay.trackers.SlotTracker.initEmpty(allocator, 0);
    defer slot_tracker.deinit(allocator);

    var commitments = sig.replay.trackers.CommitmentTracker.init(allocator, 0);
    defer commitments.deinit(allocator);

    const ctx = testSlotReadCtx(&slot_tracker, &commitments);
    var state = SlotStateCache.init(ctx, .noop);
    defer state.deinit(allocator);

    const first = try testOnSlotFrozen(&state, allocator, 10, 9, 5);
    try std.testing.expect(first.publishable_slot != null);

    const second = try testOnSlotFrozen(&state, allocator, 10, 8, 4);
    try std.testing.expect(second.publishable_slot == null);
    try std.testing.expectEqual(NotificationCommitments{}, second.notify_commitments);

    const cached = state.cached_slots.getPtr(10).?;
    try std.testing.expectEqual(8, cached.parent);
    try std.testing.expectEqual(4, cached.root);
}

test "transaction batch ownership transfers into cache" {
    const allocator = std.testing.allocator;
    var slot_tracker = try sig.replay.trackers.SlotTracker.initEmpty(allocator, 0);
    defer slot_tracker.deinit(allocator);

    var commitments = sig.replay.trackers.CommitmentTracker.init(allocator, 0);
    defer commitments.deinit(allocator);

    const ctx = testSlotReadCtx(&slot_tracker, &commitments);
    var state = SlotStateCache.init(ctx, .FOR_TESTS);
    defer state.deinit(allocator);

    var batch = try testSlotTransactionBatch(allocator, 10, &.{"Program log: cached"});
    defer batch.deinit(allocator);

    try state.onTransactionBatchEvent(allocator, &batch);
    try std.testing.expectEqual(0, batch.entries.len);

    const cached = state.cached_slots.getPtr(10).?;
    try std.testing.expectEqual(1, cached.transaction_batches.items.len);
    try std.testing.expectEqual(1, cached.transaction_batches.items[0].entries.len);
    try std.testing.expectEqualStrings(
        "Program log: cached",
        cached.transaction_batches.items[0].entries[0].log_messages.?[0],
    );
}

test "repeated transaction batches append" {
    const allocator = std.testing.allocator;
    var slot_tracker = try sig.replay.trackers.SlotTracker.initEmpty(allocator, 0);
    defer slot_tracker.deinit(allocator);

    var commitments = sig.replay.trackers.CommitmentTracker.init(allocator, 0);
    defer commitments.deinit(allocator);

    const ctx = testSlotReadCtx(&slot_tracker, &commitments);
    var state = SlotStateCache.init(ctx, .noop);
    defer state.deinit(allocator);

    var first_batch = try testSlotTransactionBatch(allocator, 10, &.{"Program log: first"});
    defer first_batch.deinit(allocator);
    var second_batch = try testSlotTransactionBatch(allocator, 10, &.{"Program log: second"});
    defer second_batch.deinit(allocator);

    try state.onTransactionBatchEvent(allocator, &first_batch);
    try std.testing.expectEqual(0, first_batch.entries.len);

    try state.onTransactionBatchEvent(allocator, &second_batch);
    try std.testing.expectEqual(0, second_batch.entries.len);

    const cached = state.cached_slots.getPtr(10).?;
    try std.testing.expectEqual(2, cached.transaction_batches.items.len);
    try std.testing.expectEqualStrings(
        "Program log: first",
        cached.transaction_batches.items[0].entries[0].log_messages.?[0],
    );
    try std.testing.expectEqualStrings(
        "Program log: second",
        cached.transaction_batches.items[1].entries[0].log_messages.?[0],
    );
}

test "transaction batch iterator spans all batches" {
    const allocator = std.testing.allocator;
    var slot_tracker = try sig.replay.trackers.SlotTracker.initEmpty(allocator, 0);
    defer slot_tracker.deinit(allocator);

    var commitments = sig.replay.trackers.CommitmentTracker.init(allocator, 0);
    defer commitments.deinit(allocator);

    const ctx = testSlotReadCtx(&slot_tracker, &commitments);
    var state = SlotStateCache.init(ctx, .FOR_TESTS);
    defer state.deinit(allocator);

    var first_batch = try testSlotTransactionBatch(allocator, 10, &.{"Program log: first"});
    defer first_batch.deinit(allocator);
    var second_batch = try testSlotTransactionBatch(allocator, 10, &.{"Program log: second"});
    defer second_batch.deinit(allocator);

    try state.onTransactionBatchEvent(allocator, &first_batch);
    try state.onTransactionBatchEvent(allocator, &second_batch);

    const cached = state.cached_slots.getPtr(10).?;
    var iterator = cached.transactionBatchIterator();
    try std.testing.expectEqualStrings(
        "Program log: first",
        iterator.next().?.logs[0],
    );
    try std.testing.expectEqualStrings(
        "Program log: second",
        iterator.next().?.logs[0],
    );
    try std.testing.expect(iterator.next() == null);
}

test "confirmed before frozen caches then freeze populates" {
    const allocator = std.testing.allocator;
    var slot_tracker = try sig.replay.trackers.SlotTracker.initEmpty(allocator, 0);
    defer slot_tracker.deinit(allocator);

    var commitments = sig.replay.trackers.CommitmentTracker.init(allocator, 0);
    defer commitments.deinit(allocator);

    try testAddTrackedSlot(allocator, &slot_tracker, 10, 9, &.{10});
    commitments.update(.processed, 10);

    const ctx = testSlotReadCtx(&slot_tracker, &commitments);
    var state = SlotStateCache.init(ctx, .FOR_TESTS);
    defer state.deinit(allocator);

    // Confirm arrives before freeze: creates an empty CachedSlot with confirmed=true.
    const confirm_t = try state.onSlotConfirmed(allocator, 10);
    try std.testing.expect(confirm_t.publishable_slot == null);
    try std.testing.expect(confirm_t.notify_commitments.confirmed);

    // Slot IS in cached_slots now (unfrozen).
    const entry = state.cached_slots.getPtr(10).?;
    try std.testing.expect(entry.state.confirmed);
    try std.testing.expect(!entry.state.frozen);

    // Freeze populates the existing entry.
    const frozen_t = try testOnSlotFrozen(&state, allocator, 10, 9, 5);
    try std.testing.expect(frozen_t.notify_commitments.processed);
    try std.testing.expect(frozen_t.notify_commitments.confirmed);
    try std.testing.expect(!frozen_t.notify_commitments.finalized);

    const cached = state.cached_slots.getPtr(10).?;
    try std.testing.expect(cached.state.confirmed);
    try std.testing.expect(cached.state.frozen);
    try std.testing.expect(!cached.published.confirmed);
}

test "onSlotConfirmed marks confirmed transition only when actionable" {
    const allocator = std.testing.allocator;
    var slot_tracker = try sig.replay.trackers.SlotTracker.initEmpty(allocator, 0);
    defer slot_tracker.deinit(allocator);

    var commitments = sig.replay.trackers.CommitmentTracker.init(allocator, 0);
    defer commitments.deinit(allocator);

    try testAddTrackedSlot(allocator, &slot_tracker, 11, 10, &.{11});
    commitments.update(.processed, 11);

    const ctx = testSlotReadCtx(&slot_tracker, &commitments);
    var state = SlotStateCache.init(ctx, .FOR_TESTS);
    defer state.deinit(allocator);

    const first = try state.onSlotConfirmed(allocator, 10);
    try std.testing.expect(first.notify_commitments.confirmed);

    _ = try testOnSlotFrozen(&state, allocator, 11, 10, 0);
    const second = try state.onSlotConfirmed(allocator, 11);
    try std.testing.expect(!second.notify_commitments.processed);
    try std.testing.expect(second.notify_commitments.confirmed);
    try std.testing.expect(!second.notify_commitments.finalized);

    try std.testing.expectError(
        error.DuplicateSlotConfirmed,
        state.onSlotConfirmed(allocator, 11),
    );
}

test "onSlotRooted marks confirmed finalized and eviction" {
    const allocator = std.testing.allocator;
    var slot_tracker = try sig.replay.trackers.SlotTracker.initEmpty(allocator, 0);
    defer slot_tracker.deinit(allocator);

    var commitments = sig.replay.trackers.CommitmentTracker.init(allocator, 0);
    defer commitments.deinit(allocator);

    const ctx = testSlotReadCtx(&slot_tracker, &commitments);
    var state = SlotStateCache.init(ctx, .FOR_TESTS);
    defer state.deinit(allocator);

    _ = try testOnSlotFrozen(&state, allocator, 10, 9, 0);
    const transition = try state.onSlotRooted(allocator, 10);
    try std.testing.expect(transition.publishable_slot != null);
    try std.testing.expect(!transition.notify_commitments.processed);
    try std.testing.expect(transition.notify_commitments.confirmed);
    try std.testing.expect(transition.notify_commitments.finalized);
    try std.testing.expectEqual(10, transition.evict_through);

    const cached = transition.publishable_slot.?;
    try std.testing.expect(cached.state.confirmed);
    try std.testing.expect(cached.state.rooted);
    try std.testing.expect(!cached.published.confirmed);
    try std.testing.expect(cached.published.finalized);
}

test "duplicate rooted returns error" {
    const allocator = std.testing.allocator;
    var slot_tracker = try sig.replay.trackers.SlotTracker.initEmpty(allocator, 0);
    defer slot_tracker.deinit(allocator);

    var commitments = sig.replay.trackers.CommitmentTracker.init(allocator, 0);
    defer commitments.deinit(allocator);

    const ctx = testSlotReadCtx(&slot_tracker, &commitments);
    var state = SlotStateCache.init(ctx, .noop);
    defer state.deinit(allocator);

    const first = try state.onSlotRooted(allocator, 10);
    try std.testing.expect(first.publishable_slot == null);
    try std.testing.expect(first.notify_commitments.confirmed);
    try std.testing.expect(first.notify_commitments.finalized);

    try std.testing.expectError(
        error.DuplicateSlotRooted,
        state.onSlotRooted(allocator, 10),
    );
}

test "eviction removes slots below rooted slot" {
    const allocator = std.testing.allocator;
    var slot_tracker = try sig.replay.trackers.SlotTracker.initEmpty(allocator, 0);
    defer slot_tracker.deinit(allocator);

    var commitments = sig.replay.trackers.CommitmentTracker.init(allocator, 0);
    defer commitments.deinit(allocator);

    const ctx = testSlotReadCtx(&slot_tracker, &commitments);
    var state = SlotStateCache.init(ctx, .FOR_TESTS);
    defer state.deinit(allocator);

    _ = try testOnSlotFrozen(&state, allocator, 5, 4, 0);
    _ = try testOnSlotFrozen(&state, allocator, 10, 9, 0);
    _ = try testOnSlotFrozen(&state, allocator, 15, 14, 0);

    try std.testing.expect(state.cached_slots.getPtr(5) != null);
    try std.testing.expect(state.cached_slots.getPtr(10) != null);
    try std.testing.expect(state.cached_slots.getPtr(15) != null);

    // Uses strict <, so slot 10 survives.
    state.evictFinalizedThrough(allocator, 10);

    try std.testing.expect(state.cached_slots.getPtr(5) == null);
    try std.testing.expect(state.cached_slots.getPtr(10) != null);
    try std.testing.expect(state.cached_slots.getPtr(15) != null);
}

test "capacity eviction removes minimum slot" {
    const allocator = std.testing.allocator;
    var slot_tracker = try sig.replay.trackers.SlotTracker.initEmpty(allocator, 0);
    defer slot_tracker.deinit(allocator);

    var commitments = sig.replay.trackers.CommitmentTracker.init(allocator, 0);
    defer commitments.deinit(allocator);

    const ctx = testSlotReadCtx(&slot_tracker, &commitments);
    var state = SlotStateCache.init(ctx, .noop);
    defer state.deinit(allocator);

    // Fill main cache to capacity via frozen events.
    const slot_limit: Slot = MAX_CACHED_SLOTS;
    var slot: Slot = 1;
    while (slot <= slot_limit) : (slot += 1) {
        _ = try testOnSlotFrozen(&state, allocator, slot, slot - 1, 0);
    }

    try std.testing.expectEqual(MAX_CACHED_SLOTS, state.cached_slots.count());
    try std.testing.expect(state.cached_slots.getPtr(1) != null);

    // One more frozen event should evict the minimum slot (1).
    _ = try testOnSlotFrozen(&state, allocator, slot_limit + 1, slot_limit, 0);

    try std.testing.expectEqual(MAX_CACHED_SLOTS, state.cached_slots.count());
    try std.testing.expect(state.cached_slots.getPtr(1) == null);
    try std.testing.expect(state.cached_slots.getPtr(slot_limit + 1) != null);
}

test "capacity drop keeps minimum slot when incoming is lower" {
    const allocator = std.testing.allocator;
    var slot_tracker = try sig.replay.trackers.SlotTracker.initEmpty(allocator, 0);
    defer slot_tracker.deinit(allocator);

    var commitments = sig.replay.trackers.CommitmentTracker.init(allocator, 0);
    defer commitments.deinit(allocator);

    const ctx = testSlotReadCtx(&slot_tracker, &commitments);
    var state = SlotStateCache.init(ctx, .noop);
    defer state.deinit(allocator);

    // Fill main cache to capacity starting from slot 2.
    const slot_limit: Slot = MAX_CACHED_SLOTS + 1;
    var slot: Slot = 2;
    while (slot <= slot_limit) : (slot += 1) {
        _ = try testOnSlotFrozen(&state, allocator, slot, slot - 1, 0);
    }

    try std.testing.expectEqual(MAX_CACHED_SLOTS, state.cached_slots.count());
    try std.testing.expect(state.cached_slots.getPtr(2) != null);

    // Freezing slot 1 (lower than all cached) should fail.
    try std.testing.expectError(
        error.IncomingSlotTooOld,
        testOnSlotFrozen(&state, allocator, 1, 0, 0),
    );

    try std.testing.expectEqual(MAX_CACHED_SLOTS, state.cached_slots.count());
    try std.testing.expect(state.cached_slots.getPtr(1) == null);
    try std.testing.expect(state.cached_slots.getPtr(2) != null);
}

test "tip change updates processed_tip and fork membership" {
    const allocator = std.testing.allocator;
    var slot_tracker = try sig.replay.trackers.SlotTracker.initEmpty(allocator, 0);
    defer slot_tracker.deinit(allocator);

    var commitments = sig.replay.trackers.CommitmentTracker.init(allocator, 0);
    defer commitments.deinit(allocator);

    try testAddTrackedSlot(allocator, &slot_tracker, 1, 0, &.{1});
    try testAddTrackedSlot(allocator, &slot_tracker, 2, 1, &.{ 1, 2 });
    try testAddTrackedSlot(allocator, &slot_tracker, 3, 2, &.{ 1, 2, 3 });
    try testAddTrackedSlot(allocator, &slot_tracker, 4, 1, &.{ 1, 4 });
    try testAddTrackedSlot(allocator, &slot_tracker, 5, 4, &.{ 1, 4, 5 });

    const ctx = testSlotReadCtx(&slot_tracker, &commitments);
    var state = SlotStateCache.init(ctx, .FOR_TESTS);
    defer state.deinit(allocator);

    _ = try testOnSlotFrozen(&state, allocator, 2, 1, 0);
    _ = try testOnSlotFrozen(&state, allocator, 3, 2, 0);
    _ = try testOnSlotFrozen(&state, allocator, 4, 1, 0);
    _ = try testOnSlotFrozen(&state, allocator, 5, 4, 0);

    const first = state.onTipChanged(ctx, 3);
    try std.testing.expect(first.publishable_slot != null);
    try std.testing.expectEqual(2, first.publishable_slot.?.parent.?);
    try std.testing.expect(first.notify_commitments.processed);
    try std.testing.expect(!first.notify_commitments.confirmed);
    try std.testing.expect(!first.notify_commitments.finalized);
    try std.testing.expect(state.isSlotOnCurrentFork(2));
    try std.testing.expect(state.isSlotOnCurrentFork(3));
    try std.testing.expect(!state.isSlotOnCurrentFork(4));
    try std.testing.expect(!state.isSlotOnCurrentFork(5));
    try std.testing.expect(!state.cached_slots.getPtr(2).?.published.processed);
    try std.testing.expect(state.cached_slots.getPtr(3).?.published.processed);
    try std.testing.expectEqual(3, state.processed_tip);

    const second = state.onTipChanged(ctx, 5);
    try std.testing.expect(second.publishable_slot != null);
    try std.testing.expectEqual(4, second.publishable_slot.?.parent.?);
    try std.testing.expectEqual(5, state.processed_tip);
    try std.testing.expect(second.notify_commitments.processed);
    try std.testing.expect(!state.isSlotOnCurrentFork(2));
    try std.testing.expect(!state.isSlotOnCurrentFork(3));
    try std.testing.expect(state.isSlotOnCurrentFork(4));
    try std.testing.expect(state.isSlotOnCurrentFork(5));
    try std.testing.expect(!state.cached_slots.getPtr(4).?.published.processed);
    try std.testing.expect(state.cached_slots.getPtr(5).?.published.processed);
    try std.testing.expectEqual(5, state.processed_tip);
}

test "off-fork frozen slot is not on current fork" {
    const allocator = std.testing.allocator;
    var slot_tracker = try sig.replay.trackers.SlotTracker.initEmpty(allocator, 0);
    defer slot_tracker.deinit(allocator);

    var commitments = sig.replay.trackers.CommitmentTracker.init(allocator, 0);
    defer commitments.deinit(allocator);

    try testAddTrackedSlot(allocator, &slot_tracker, 1, 0, &.{1});
    try testAddTrackedSlot(allocator, &slot_tracker, 2, 1, &.{ 1, 2 });
    try testAddTrackedSlot(allocator, &slot_tracker, 3, 1, &.{ 1, 3 });

    const ctx = testSlotReadCtx(&slot_tracker, &commitments);
    var state = SlotStateCache.init(ctx, .FOR_TESTS);
    defer state.deinit(allocator);

    commitments.update(.processed, 2);
    _ = state.onTipChanged(ctx, 2);

    const on_fork = try testOnSlotFrozen(&state, allocator, 2, 1, 0);
    const off_fork = try testOnSlotFrozen(&state, allocator, 3, 1, 0);

    try std.testing.expect(state.isSlotOnCurrentFork(2));
    try std.testing.expect(!state.isSlotOnCurrentFork(3));
    try std.testing.expect(on_fork.notify_commitments.processed);
    try std.testing.expect(!off_fork.notify_commitments.processed);
}

test "ancestor iterator walks cached parents" {
    const allocator = std.testing.allocator;
    var slot_tracker = try sig.replay.trackers.SlotTracker.initEmpty(allocator, 0);
    defer slot_tracker.deinit(allocator);

    var commitments = sig.replay.trackers.CommitmentTracker.init(allocator, 0);
    defer commitments.deinit(allocator);

    const ctx = testSlotReadCtx(&slot_tracker, &commitments);
    var state = SlotStateCache.init(ctx, .FOR_TESTS);
    defer state.deinit(allocator);

    _ = try testOnSlotFrozen(&state, allocator, 1, 0, 0);
    _ = try testOnSlotFrozen(&state, allocator, 2, 1, 0);
    _ = try testOnSlotFrozen(&state, allocator, 3, 2, 0);

    var ancestors = state.ancestorIterator(3);
    const first = ancestors.next().?;
    try std.testing.expectEqual(3, first.slot);
    try std.testing.expectEqual(2, first.cached_slot.parent);

    const second = ancestors.next().?;
    try std.testing.expectEqual(2, second.slot);
    try std.testing.expectEqual(1, second.cached_slot.parent);

    const third = ancestors.next().?;
    try std.testing.expectEqual(1, third.slot);
    try std.testing.expectEqual(0, third.cached_slot.parent);

    try std.testing.expect(ancestors.next() == null);
}

test "collectPublishableConfirmedSlots returns newest first and marks published" {
    const allocator = std.testing.allocator;
    var slot_tracker = try sig.replay.trackers.SlotTracker.initEmpty(allocator, 0);
    defer slot_tracker.deinit(allocator);

    var commitments = sig.replay.trackers.CommitmentTracker.init(allocator, 0);
    defer commitments.deinit(allocator);

    const ctx = testSlotReadCtx(&slot_tracker, &commitments);
    var state = SlotStateCache.init(ctx, .FOR_TESTS);
    defer state.deinit(allocator);

    _ = try testOnSlotFrozen(&state, allocator, 1, 0, 0);
    _ = try testOnSlotFrozen(&state, allocator, 2, 1, 0);
    _ = try testOnSlotFrozen(&state, allocator, 3, 2, 0);
    _ = try state.onSlotConfirmed(allocator, 3);

    var slots = try state.collectPublishableConfirmedSlots(allocator, 3);
    defer slots.deinit(allocator);

    try std.testing.expectEqual(3, slots.items.len);
    try std.testing.expectEqual(3, slots.items[0].slot);
    try std.testing.expectEqual(2, slots.items[1].slot);
    try std.testing.expectEqual(1, slots.items[2].slot);
    try std.testing.expect(state.cached_slots.getPtr(1).?.published.confirmed);
    try std.testing.expect(state.cached_slots.getPtr(2).?.published.confirmed);
    try std.testing.expect(state.cached_slots.getPtr(3).?.published.confirmed);
}

test "root jump over multiple slots" {
    const allocator = std.testing.allocator;
    var slot_tracker = try sig.replay.trackers.SlotTracker.initEmpty(allocator, 0);
    defer slot_tracker.deinit(allocator);

    var commitments = sig.replay.trackers.CommitmentTracker.init(allocator, 0);
    defer commitments.deinit(allocator);

    const ctx = testSlotReadCtx(&slot_tracker, &commitments);
    var state = SlotStateCache.init(ctx, .FOR_TESTS);
    defer state.deinit(allocator);

    _ = try testOnSlotFrozen(&state, allocator, 5, 4, 0);
    _ = try testOnSlotFrozen(&state, allocator, 6, 5, 0);
    _ = try testOnSlotFrozen(&state, allocator, 7, 6, 0);
    _ = try testOnSlotFrozen(&state, allocator, 8, 7, 0);

    for ([_]Slot{ 5, 6, 7, 8 }) |slot| {
        const transition = try state.onSlotRooted(allocator, slot);
        try std.testing.expect(transition.publishable_slot != null);
        try std.testing.expect(transition.notify_commitments.finalized);
        try std.testing.expectEqual(slot, transition.evict_through);
    }

    state.evictFinalizedThrough(allocator, 7);
    try std.testing.expect(state.cached_slots.getPtr(5) == null);
    try std.testing.expect(state.cached_slots.getPtr(6) == null);
    try std.testing.expect(state.cached_slots.getPtr(7) != null);
    try std.testing.expect(state.cached_slots.getPtr(8) != null);
}

test "buildTxWithMeta deep-copies all TransactionEntry fields" {
    const allocator = std.testing.allocator;

    // Source data owned by a separate arena (simulates producer batch).
    var source_arena = std.heap.ArenaAllocator.init(allocator);
    defer source_arena.deinit();
    const sa = source_arena.allocator();

    const pre_bals = try sa.dupe(u64, &.{ 100, 200 });
    const post_bals = try sa.dupe(u64, &.{ 90, 210 });

    const log_lines: []const []const u8 = try sa.dupe(
        []const u8,
        &.{ "log line 1", "log line 2" },
    );

    const inner_ix_accounts = try sa.dupe(u8, &.{ 0, 1 });
    const inner_ix_data = try sa.dupe(u8, &.{0xAB});
    const inner_ixs = try sa.alloc(InnerInstruction, 1);
    inner_ixs[0] = .{
        .instruction = .{
            .program_id_index = 2,
            .accounts = inner_ix_accounts,
            .data = inner_ix_data,
        },
        .stack_height = 1,
    };
    const inners = try sa.alloc(InnerInstructions, 1);
    inners[0] = .{ .index = 0, .instructions = inner_ixs };

    var mint_pk: sig.core.Pubkey = undefined;
    @memset(&mint_pk.data, 0x11);
    var owner_pk: sig.core.Pubkey = undefined;
    @memset(&owner_pk.data, 0x22);
    var program_pk: sig.core.Pubkey = undefined;
    @memset(&program_pk.data, 0x33);

    const token_bal: TransactionTokenBalance = .{
        .account_index = 1,
        .mint = mint_pk,
        .ui_token_amount = .{
            .ui_amount = 1.5,
            .decimals = 6,
            .amount = "1500000",
            .ui_amount_string = "1.5",
        },
        .owner = owner_pk,
        .program_id = program_pk,
    };
    const pre_token_bals = try sa.dupe(
        TransactionTokenBalance,
        &.{token_bal},
    );
    const post_token_bals = try sa.dupe(
        TransactionTokenBalance,
        &.{token_bal},
    );

    var ret_program_id: sig.core.Pubkey = undefined;
    @memset(&ret_program_id.data, 0x44);
    const ret_data_bytes = try sa.dupe(u8, &.{ 0xDE, 0xAD });

    var writable_pk: sig.core.Pubkey = undefined;
    @memset(&writable_pk.data, 0x55);
    var readonly_pk: sig.core.Pubkey = undefined;
    @memset(&readonly_pk.data, 0x66);

    const entry = TransactionEntry{
        .signature = sig.core.Signature.ZEROES,
        .transaction = sig.core.Transaction.EMPTY,
        .is_vote = false,
        .transaction_index = 0,
        .err = .{ .InstructionError = .{
            3,
            .{ .BorshIoError = try sa.dupe(u8, "borsh error") },
        } },
        .fee = 5000,
        .compute_units_consumed = 42,
        .cost_units = 10000,
        .pre_balances = pre_bals,
        .post_balances = post_bals,
        .pre_token_balances = pre_token_bals,
        .post_token_balances = post_token_bals,
        .inner_instructions = inners,
        .log_messages = log_lines,
        .return_data = .{
            .program_id = ret_program_id,
            .data = ret_data_bytes,
        },
        .loaded_addresses = .{
            .writable = try sa.dupe(sig.core.Pubkey, &.{writable_pk}),
            .readonly = try sa.dupe(sig.core.Pubkey, &.{readonly_pk}),
        },
        .mentioned_pubkeys = &.{},
    };

    // Clone into a fresh allocator — the test allocator will
    // catch any leaks if we forget to deinit.
    const result = try buildTxWithMeta(allocator, &entry);
    defer result.deinit(allocator);

    // Scalar fields.
    try std.testing.expectEqual(@as(u64, 5000), result.meta.fee);
    try std.testing.expectEqual(@as(?u64, 42), result.meta.compute_units_consumed);
    try std.testing.expectEqual(@as(usize, 0), result.meta.rewards.?.len);
    try std.testing.expectEqual(@as(u64, 10000), result.meta.cost_units.?);

    // Balances are equal but are distinct allocations.
    try std.testing.expectEqualSlices(u64, &.{ 100, 200 }, result.meta.pre_balances);
    try std.testing.expectEqualSlices(u64, &.{ 90, 210 }, result.meta.post_balances);
    try std.testing.expect(result.meta.pre_balances.ptr != pre_bals.ptr);
    try std.testing.expect(result.meta.post_balances.ptr != post_bals.ptr);

    // Log messages deep-copied.
    const logs = result.meta.log_messages.?;
    try std.testing.expectEqual(@as(usize, 2), logs.len);
    try std.testing.expectEqualStrings("log line 1", logs[0]);
    try std.testing.expectEqualStrings("log line 2", logs[1]);
    try std.testing.expect(logs.ptr != log_lines.ptr);

    // Inner instructions deep-copied.
    const cloned_inners = result.meta.inner_instructions.?;
    try std.testing.expectEqual(@as(usize, 1), cloned_inners.len);
    try std.testing.expectEqual(@as(u8, 0), cloned_inners[0].index);
    try std.testing.expectEqual(@as(usize, 1), cloned_inners[0].instructions.len);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0, 1 },
        cloned_inners[0].instructions[0].instruction.accounts,
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{0xAB},
        cloned_inners[0].instructions[0].instruction.data,
    );
    try std.testing.expect(
        cloned_inners[0].instructions[0].instruction.accounts.ptr != inner_ix_accounts.ptr,
    );

    // Token balances deep-copied.
    const cloned_pre_tok = result.meta.pre_token_balances.?;
    try std.testing.expectEqual(@as(usize, 1), cloned_pre_tok.len);
    try std.testing.expectEqualStrings(
        "1500000",
        cloned_pre_tok[0].ui_token_amount.amount,
    );
    try std.testing.expectEqualStrings("1.5", cloned_pre_tok[0].ui_token_amount.ui_amount_string);
    try std.testing.expect(
        cloned_pre_tok[0].ui_token_amount.amount.ptr != token_bal.ui_token_amount.amount.ptr,
    );

    const cloned_post_tok = result.meta.post_token_balances.?;
    try std.testing.expectEqual(@as(usize, 1), cloned_post_tok.len);

    // Return data deep-copied.
    const cloned_ret = result.meta.return_data.?;
    try std.testing.expect(cloned_ret.program_id.equals(&ret_program_id));
    try std.testing.expectEqualSlices(u8, &.{ 0xDE, 0xAD }, cloned_ret.data);
    try std.testing.expect(cloned_ret.data.ptr != ret_data_bytes.ptr);

    // Loaded addresses deep-copied.
    try std.testing.expectEqual(@as(usize, 1), result.meta.loaded_addresses.writable.len);
    try std.testing.expectEqual(@as(usize, 1), result.meta.loaded_addresses.readonly.len);
    try std.testing.expect(result.meta.loaded_addresses.writable[0].equals(&writable_pk));
    try std.testing.expect(result.meta.loaded_addresses.readonly[0].equals(&readonly_pk));

    // Error deep-copied (BorshIoError string).
    const cloned_err = result.meta.status.?;
    try std.testing.expect(cloned_err == .InstructionError);
    const ix_err = cloned_err.InstructionError;
    try std.testing.expectEqual(@as(u8, 3), ix_err.@"0");
    try std.testing.expectEqualStrings("borsh error", ix_err.@"1".BorshIoError);
}

test "buildTxWithMeta handles null optional fields" {
    const allocator = std.testing.allocator;

    const entry = TransactionEntry{
        .signature = sig.core.Signature.ZEROES,
        .transaction = sig.core.Transaction.EMPTY,
        .is_vote = false,
        .transaction_index = 0,
        .err = null,
        .fee = 0,
        .compute_units_consumed = null,
        .cost_units = 0,
        .pre_balances = &.{},
        .post_balances = &.{},
        .pre_token_balances = null,
        .post_token_balances = null,
        .inner_instructions = null,
        .log_messages = null,
        .return_data = null,
        .loaded_addresses = .{},
        .mentioned_pubkeys = &.{},
    };

    const result = try buildTxWithMeta(allocator, &entry);
    defer result.deinit(allocator);

    try std.testing.expect(result.meta.status == null);
    try std.testing.expectEqual(@as(?u64, null), result.meta.compute_units_consumed);
    try std.testing.expect(result.meta.inner_instructions == null);
    try std.testing.expect(result.meta.log_messages == null);
    try std.testing.expect(result.meta.pre_token_balances == null);
    try std.testing.expect(result.meta.post_token_balances == null);
    try std.testing.expect(result.meta.return_data == null);
    try std.testing.expectEqual(@as(usize, 0), result.meta.pre_balances.len);
    try std.testing.expectEqual(@as(usize, 0), result.meta.post_balances.len);
}

test "slot frozen stores producer-owned modified accounts" {
    const allocator = std.testing.allocator;
    var slot_tracker = try sig.replay.trackers.SlotTracker.initEmpty(allocator, 0);
    defer slot_tracker.deinit(allocator);

    var commitments = sig.replay.trackers.CommitmentTracker.init(allocator, 0);
    defer commitments.deinit(allocator);

    var pk: sig.core.Pubkey = undefined;
    @memset(&pk.data, 0xAA);
    var owner_pk: sig.core.Pubkey = undefined;
    @memset(&owner_pk.data, 0xBB);

    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const arena_allocator = arena.allocator();

    const accounts = try arena_allocator.alloc(types.AccountWithPubkey, 1);
    accounts[0] = .{
        .pubkey = pk,
        .account = .{
            .lamports = 42_000,
            .data = .{ .owned_allocation = try arena_allocator.dupe(u8, &.{ 0xDE, 0xAD }) },
            .owner = owner_pk,
            .executable = false,
            .rent_epoch = 0,
        },
    };

    const ctx = testSlotReadCtx(&slot_tracker, &commitments);
    var state = SlotStateCache.init(ctx, .FOR_TESTS);
    defer state.deinit(allocator);

    var slot_data: SlotFrozenEvent = .{
        .slot = 5,
        .parent = 4,
        .root = 0,
        .accounts = .{
            .accounts = accounts,
            .arena_state = arena.state,
        },
    };
    const transition = try state.onSlotFrozen(allocator, &slot_data);

    const cached = transition.publishable_slot.?;
    try std.testing.expectEqual(1, cached.modified_accounts.accounts.len);
    try std.testing.expect(cached.modified_accounts.accounts[0].pubkey.equals(&pk));
    try std.testing.expectEqual(42_000, cached.modified_accounts.accounts[0].account.lamports);
}

test "gossip confirmations create unfrozen cache entries" {
    const allocator = std.testing.allocator;
    var slot_tracker = try sig.replay.trackers.SlotTracker.initEmpty(allocator, 0);
    defer slot_tracker.deinit(allocator);

    var commitments = sig.replay.trackers.CommitmentTracker.init(allocator, 0);
    defer commitments.deinit(allocator);

    const ctx = testSlotReadCtx(&slot_tracker, &commitments);
    var state = SlotStateCache.init(ctx, .FOR_TESTS);
    defer state.deinit(allocator);

    // Freeze a few replay slots into the main cache.
    _ = try testOnSlotFrozen(&state, allocator, 1, 0, 0);
    _ = try testOnSlotFrozen(&state, allocator, 2, 1, 0);

    // Simulate gossip confirmations for ahead slots.
    var slot: Slot = 1000;
    while (slot < 1000 + 200) : (slot += 1) {
        _ = try state.onSlotConfirmed(allocator, slot);
    }

    // Cache holds frozen + confirmed entries (202 total).
    try std.testing.expectEqual(@as(usize, 202), state.cached_slots.count());
    // Frozen slots still present.
    try std.testing.expect(state.cached_slots.getPtr(1) != null);
    try std.testing.expect(state.cached_slots.getPtr(2) != null);
    // Confirmed-only slot is present but not frozen.
    const entry = state.cached_slots.getPtr(1000).?;
    try std.testing.expect(entry.state.confirmed);
    try std.testing.expect(!entry.state.frozen);
}

test "rooted before frozen caches then freeze populates" {
    const allocator = std.testing.allocator;
    var slot_tracker = try sig.replay.trackers.SlotTracker.initEmpty(allocator, 0);
    defer slot_tracker.deinit(allocator);

    var commitments = sig.replay.trackers.CommitmentTracker.init(allocator, 0);
    defer commitments.deinit(allocator);

    try testAddTrackedSlot(allocator, &slot_tracker, 20, 19, &.{20});
    commitments.update(.processed, 20);

    const ctx = testSlotReadCtx(&slot_tracker, &commitments);
    var state = SlotStateCache.init(ctx, .FOR_TESTS);
    defer state.deinit(allocator);

    // Root arrives before freeze: creates an empty CachedSlot with confirmed+rooted flags.
    const root_t = try state.onSlotRooted(allocator, 20);
    try std.testing.expect(root_t.publishable_slot == null);
    try std.testing.expect(root_t.notify_commitments.confirmed);
    try std.testing.expect(root_t.notify_commitments.finalized);
    try std.testing.expectEqual(@as(?Slot, 20), root_t.evict_through);

    // Slot IS in cached_slots (unfrozen, with flags set).
    const entry = state.cached_slots.getPtr(20).?;
    try std.testing.expect(entry.state.confirmed);
    try std.testing.expect(entry.state.rooted);
    try std.testing.expect(!entry.state.frozen);

    // Freeze populates the existing entry.
    const frozen_t = try testOnSlotFrozen(&state, allocator, 20, 19, 5);
    try std.testing.expect(frozen_t.notify_commitments.processed);
    try std.testing.expect(frozen_t.notify_commitments.confirmed);
    try std.testing.expect(frozen_t.notify_commitments.finalized);

    const cached = state.cached_slots.getPtr(20).?;
    try std.testing.expect(cached.state.confirmed);
    try std.testing.expect(cached.state.rooted);
    try std.testing.expect(cached.state.frozen);
}
