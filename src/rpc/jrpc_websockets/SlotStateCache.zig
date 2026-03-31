//! Tracks slot lifecycle and per-slot modified accounts so websocket delivery can
//! derive commitment-specific notifications from minimal producer events.
const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../../sig.zig");

const types = @import("types.zig");

const Slot = sig.core.Slot;
const SlotTrackerReference = sig.replay.trackers.SlotTracker.Reference;
const Logger = sig.trace.Logger("rpc.jrpc_websockets.slot_state_cache");
pub const SlotReadContext = types.SlotReadContext;

/// Max tracked slots retained, used to avoid unbounded memory growth if we receive unexpected
/// event patterns. Under normal operation eviction should occur when slots are rooted.
const MAX_CACHED_SLOTS: usize = 64;
const SlotStateCache = @This();

logger: Logger,
/// Tracked latest processed tip slot number.
processed_tip: Slot = 0,
/// Cached latest processed tip slot info (for ancestor information).
processed_tip_info: ?SlotTrackerReference = null,
cached_slots: std.AutoArrayHashMapUnmanaged(Slot, CachedSlot) = .empty,

pub const CachedSlot = struct {
    parent: ?Slot = null,
    root: ?Slot = null,
    state: StateFlags = .{},
    published: PublishedFlags = .{},
    /// Final account states for the accounts modified in this slot, captured at freeze time.
    modified_accounts: types.SlotModifiedAccounts = types.SlotModifiedAccounts.empty(),

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

    pub fn deinit(self: *CachedSlot) void {
        self.modified_accounts.deinit();
    }
};

pub const NotificationCommitments = packed struct {
    processed: bool = false,
    confirmed: bool = false,
    finalized: bool = false,
};

/// Returned from event methods to indicate what commitment-specific notifications should
/// be emitted and if any cached slots should be evicted.
pub const Transition = struct {
    cached_slot: ?*const CachedSlot = null,
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
    const processed_tip = slot_read_ctx.slot_tracker.commitments.get(.processed);
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
        slot_state.deinit();
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

    return .{ .notify_commitments = .{ .processed = true } };
}

/// Freeze is the first point where the slot's final modified accounts are stable,
/// so cache them once here and reuse them for later confirmed/finalized publication.
pub fn onSlotFrozen(
    self: *SlotStateCache,
    allocator: std.mem.Allocator,
    slot_data: *types.SlotFrozenEvent,
) !Transition {
    if (self.cached_slots.getPtr(slot_data.slot)) |slot_state| {
        // TODO: what about repair? Could it have frozen twice for same slot number?
        if (slot_state.state.frozen) {
            if (!builtin.is_test) {
                self.logger.err().logf(
                    "received duplicate slot_frozen for slot {}",
                    .{slot_data.slot},
                );
            }
            slot_data.accounts.deinit();
            return .{};
        }
    }

    const slot_state = try self.getOrPutSlot(allocator, slot_data.slot);
    slot_state.parent = slot_data.parent;
    slot_state.root = slot_data.root;
    slot_state.state.frozen = true;
    slot_state.modified_accounts = slot_data.accounts;
    slot_data.accounts = types.SlotModifiedAccounts.empty();

    // Maybe other commitments for slot were waiting for frozen, so try all of them.
    const notify_commitments: NotificationCommitments = .{
        .processed = self.tryMarkProcessedPublished(slot_data.slot, slot_state),
        .confirmed = needsConfirmedFlush(slot_state),
        .finalized = tryMarkFinalizedPublished(slot_state),
    };
    return .{
        .cached_slot = slot_state,
        .notify_commitments = notify_commitments,
    };
}

pub fn onSlotConfirmed(
    self: *SlotStateCache,
    allocator: std.mem.Allocator,
    slot: Slot,
) !Transition {
    const slot_state = try self.getOrPutSlot(allocator, slot);
    if (slot_state.state.confirmed) {
        return .{};
    }

    slot_state.state.confirmed = true;

    var transition: Transition = .{ .notify_commitments = .{ .confirmed = true } };
    if (slot_state.state.frozen) {
        transition.cached_slot = slot_state;
    }
    return transition;
}

pub fn onSlotRooted(
    self: *SlotStateCache,
    allocator: std.mem.Allocator,
    slot: Slot,
) !Transition {
    const slot_state = try self.getOrPutSlot(allocator, slot);
    if (slot_state.state.rooted) {
        return .{};
    }

    slot_state.state.confirmed = true;
    slot_state.state.rooted = true;

    var transition: Transition = .{
        .notify_commitments = .{
            .confirmed = !slot_state.published.confirmed,
            .finalized = true,
        },
        .evict_through = slot,
    };
    if (!tryMarkFinalizedPublished(slot_state)) {
        // should never happen, log it
        self.logger.err().logf(
            "received slot_rooted for slot {} in unexpected state: " ++
                "frozen={} confirmed={} rooted={} published_finalized={}",
            .{
                slot,
                slot_state.state.frozen,
                slot_state.state.confirmed,
                slot_state.state.rooted,
                slot_state.published.finalized,
            },
        );
        return transition;
    }
    transition.cached_slot = slot_state;
    return transition;
}

/// Once a slot has rooted and we have delivered anything derived from it, older cached
/// account data is no longer needed for future commitment transitions.
pub fn evictFinalizedThrough(
    self: *SlotStateCache,
    rooted_slot: Slot,
) void {
    var index: usize = 0;
    while (index < self.cached_slots.count()) {
        if (self.cached_slots.keys()[index] <= rooted_slot) {
            // TODO(perf): Offload cached frozen-account teardown off the loop thread.
            self.cached_slots.values()[index].deinit();
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
            // event to have the modified accounts and be able to publish in slot order.
            // We will try again on the next frozen event and eventually be able to flush the
            // confirmed in slot order.
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
        try self.evictMinimumSlot(slot);
    }

    const gop = try self.cached_slots.getOrPut(allocator, slot);
    gop.value_ptr.* = .{};
    return gop.value_ptr;
}

fn evictMinimumSlot(self: *SlotStateCache, incoming_slot: Slot) error{IncomingSlotTooOld}!void {
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
    self.cached_slots.values()[min_index].deinit();
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

fn testSlotReadCtx(slot_tracker: *sig.replay.trackers.SlotTracker) SlotReadContext {
    return .{
        .slot_tracker = slot_tracker,
        .account_reader = .noop,
    };
}

fn testSlotFrozenEvent(slot: Slot, parent: Slot, root: Slot) types.SlotFrozenEvent {
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

test "SlotStateCache: slot frozen returns transition and marks state" {
    const allocator = std.testing.allocator;
    var slot_tracker = try sig.replay.trackers.SlotTracker.initEmpty(allocator, 0);
    defer slot_tracker.deinit(allocator);

    try testAddTrackedSlot(allocator, &slot_tracker, 10, 9, &.{10});
    slot_tracker.commitments.update(.processed, 10);

    const ctx = testSlotReadCtx(&slot_tracker);
    var state = SlotStateCache.init(ctx, .FOR_TESTS);
    defer state.deinit(allocator);

    const transition = try testOnSlotFrozen(&state, allocator, 10, 9, 5);
    try std.testing.expect(transition.cached_slot != null);
    try std.testing.expect(transition.notify_commitments.processed);
    try std.testing.expect(!transition.notify_commitments.confirmed);
    try std.testing.expect(!transition.notify_commitments.finalized);
    try std.testing.expect(transition.evict_through == null);

    const cached = transition.cached_slot.?;
    try std.testing.expect(cached.state.frozen);
    try std.testing.expectEqual(@as(?Slot, 9), cached.parent);
    try std.testing.expectEqual(@as(?Slot, 5), cached.root);
    try std.testing.expect(cached.published.processed);
}

test "SlotStateCache: duplicate frozen is ignored" {
    const allocator = std.testing.allocator;
    var slot_tracker = try sig.replay.trackers.SlotTracker.initEmpty(allocator, 0);
    defer slot_tracker.deinit(allocator);

    const ctx = testSlotReadCtx(&slot_tracker);
    var state = SlotStateCache.init(ctx, .noop);
    defer state.deinit(allocator);

    const first = try testOnSlotFrozen(&state, allocator, 10, 9, 5);
    try std.testing.expect(first.cached_slot != null);

    const second = try testOnSlotFrozen(&state, allocator, 10, 9, 5);
    try std.testing.expect(second.cached_slot == null);
    try std.testing.expectEqual(NotificationCommitments{}, second.notify_commitments);
}

test "SlotStateCache: confirmed before frozen buffers state" {
    const allocator = std.testing.allocator;
    var slot_tracker = try sig.replay.trackers.SlotTracker.initEmpty(allocator, 0);
    defer slot_tracker.deinit(allocator);

    try testAddTrackedSlot(allocator, &slot_tracker, 10, 9, &.{10});
    slot_tracker.commitments.update(.processed, 10);

    const ctx = testSlotReadCtx(&slot_tracker);
    var state = SlotStateCache.init(ctx, .FOR_TESTS);
    defer state.deinit(allocator);

    const confirm_transition = try state.onSlotConfirmed(allocator, 10);
    try std.testing.expect(confirm_transition.cached_slot == null);
    try std.testing.expect(confirm_transition.notify_commitments.confirmed);

    const cached_before = state.cached_slots.getPtr(10).?;
    try std.testing.expect(cached_before.state.confirmed);
    try std.testing.expect(!cached_before.state.frozen);

    const frozen_transition = try testOnSlotFrozen(&state, allocator, 10, 9, 5);
    try std.testing.expect(frozen_transition.notify_commitments.processed);
    try std.testing.expect(frozen_transition.notify_commitments.confirmed);
    try std.testing.expect(!frozen_transition.notify_commitments.finalized);

    const cached_after = state.cached_slots.getPtr(10).?;
    try std.testing.expect(cached_after.state.confirmed);
    try std.testing.expect(cached_after.state.frozen);
    try std.testing.expect(!cached_after.published.confirmed);
}

test "SlotStateCache: onSlotConfirmed marks confirmed transition only when actionable" {
    const allocator = std.testing.allocator;
    var slot_tracker = try sig.replay.trackers.SlotTracker.initEmpty(allocator, 0);
    defer slot_tracker.deinit(allocator);

    try testAddTrackedSlot(allocator, &slot_tracker, 11, 10, &.{11});
    slot_tracker.commitments.update(.processed, 11);

    const ctx = testSlotReadCtx(&slot_tracker);
    var state = SlotStateCache.init(ctx, .FOR_TESTS);
    defer state.deinit(allocator);

    const first = try state.onSlotConfirmed(allocator, 10);
    try std.testing.expect(first.notify_commitments.confirmed);

    _ = try testOnSlotFrozen(&state, allocator, 11, 10, 0);
    const second = try state.onSlotConfirmed(allocator, 11);
    try std.testing.expect(!second.notify_commitments.processed);
    try std.testing.expect(second.notify_commitments.confirmed);
    try std.testing.expect(!second.notify_commitments.finalized);

    const duplicate = try state.onSlotConfirmed(allocator, 11);
    try std.testing.expectEqual(NotificationCommitments{}, duplicate.notify_commitments);
}

test "SlotStateCache: onSlotRooted marks confirmed finalized and eviction" {
    const allocator = std.testing.allocator;
    var slot_tracker = try sig.replay.trackers.SlotTracker.initEmpty(allocator, 0);
    defer slot_tracker.deinit(allocator);

    const ctx = testSlotReadCtx(&slot_tracker);
    var state = SlotStateCache.init(ctx, .FOR_TESTS);
    defer state.deinit(allocator);

    _ = try testOnSlotFrozen(&state, allocator, 10, 9, 0);
    const transition = try state.onSlotRooted(allocator, 10);
    try std.testing.expect(transition.cached_slot != null);
    try std.testing.expect(!transition.notify_commitments.processed);
    try std.testing.expect(transition.notify_commitments.confirmed);
    try std.testing.expect(transition.notify_commitments.finalized);
    try std.testing.expectEqual(@as(?Slot, 10), transition.evict_through);

    const cached = transition.cached_slot.?;
    try std.testing.expect(cached.state.confirmed);
    try std.testing.expect(cached.state.rooted);
    try std.testing.expect(!cached.published.confirmed);
    try std.testing.expect(cached.published.finalized);
}

test "SlotStateCache: duplicate rooted returns empty transition" {
    const allocator = std.testing.allocator;
    var slot_tracker = try sig.replay.trackers.SlotTracker.initEmpty(allocator, 0);
    defer slot_tracker.deinit(allocator);

    const ctx = testSlotReadCtx(&slot_tracker);
    var state = SlotStateCache.init(ctx, .noop);
    defer state.deinit(allocator);

    const first = try state.onSlotRooted(allocator, 10);
    try std.testing.expect(first.cached_slot == null);
    try std.testing.expect(first.notify_commitments.confirmed);
    try std.testing.expect(first.notify_commitments.finalized);

    const second = try state.onSlotRooted(allocator, 10);
    try std.testing.expect(second.cached_slot == null);
    try std.testing.expectEqual(NotificationCommitments{}, second.notify_commitments);
    try std.testing.expect(second.evict_through == null);
}

test "SlotStateCache: eviction removes slots at or below rooted slot" {
    const allocator = std.testing.allocator;
    var slot_tracker = try sig.replay.trackers.SlotTracker.initEmpty(allocator, 0);
    defer slot_tracker.deinit(allocator);

    const ctx = testSlotReadCtx(&slot_tracker);
    var state = SlotStateCache.init(ctx, .FOR_TESTS);
    defer state.deinit(allocator);

    _ = try testOnSlotFrozen(&state, allocator, 5, 4, 0);
    _ = try testOnSlotFrozen(&state, allocator, 10, 9, 0);
    _ = try testOnSlotFrozen(&state, allocator, 15, 14, 0);

    try std.testing.expect(state.cached_slots.getPtr(5) != null);
    try std.testing.expect(state.cached_slots.getPtr(10) != null);
    try std.testing.expect(state.cached_slots.getPtr(15) != null);

    state.evictFinalizedThrough(10);

    try std.testing.expect(state.cached_slots.getPtr(5) == null);
    try std.testing.expect(state.cached_slots.getPtr(10) == null);
    try std.testing.expect(state.cached_slots.getPtr(15) != null);
}

test "SlotStateCache: capacity eviction removes minimum slot" {
    const allocator = std.testing.allocator;
    var slot_tracker = try sig.replay.trackers.SlotTracker.initEmpty(allocator, 0);
    defer slot_tracker.deinit(allocator);

    const ctx = testSlotReadCtx(&slot_tracker);
    var state = SlotStateCache.init(ctx, .noop);
    defer state.deinit(allocator);

    const slot_limit: Slot = MAX_CACHED_SLOTS;
    var slot: Slot = 1;
    while (slot <= slot_limit) : (slot += 1) {
        _ = try state.onSlotConfirmed(allocator, slot);
    }

    try std.testing.expectEqual(MAX_CACHED_SLOTS, state.cached_slots.count());
    try std.testing.expect(state.cached_slots.getPtr(1) != null);

    _ = try state.onSlotConfirmed(allocator, slot_limit + 1);

    try std.testing.expectEqual(MAX_CACHED_SLOTS, state.cached_slots.count());
    try std.testing.expect(state.cached_slots.getPtr(1) == null);
    try std.testing.expect(state.cached_slots.getPtr(slot_limit + 1) != null);
}

test "SlotStateCache: capacity drop keeps minimum slot when incoming is lower" {
    const allocator = std.testing.allocator;
    var slot_tracker = try sig.replay.trackers.SlotTracker.initEmpty(allocator, 0);
    defer slot_tracker.deinit(allocator);

    const ctx = testSlotReadCtx(&slot_tracker);
    var state = SlotStateCache.init(ctx, .noop);
    defer state.deinit(allocator);

    const slot_limit: Slot = MAX_CACHED_SLOTS + 1;
    var slot: Slot = 2;
    while (slot <= slot_limit) : (slot += 1) {
        _ = try state.onSlotConfirmed(allocator, slot);
    }

    try std.testing.expectEqual(MAX_CACHED_SLOTS, state.cached_slots.count());
    try std.testing.expect(state.cached_slots.getPtr(2) != null);

    try std.testing.expectError(error.IncomingSlotTooOld, state.onSlotConfirmed(allocator, 1));

    try std.testing.expectEqual(MAX_CACHED_SLOTS, state.cached_slots.count());
    try std.testing.expect(state.cached_slots.getPtr(1) == null);
    try std.testing.expect(state.cached_slots.getPtr(2) != null);
}

test "SlotStateCache: tip change updates processed_tip and fork membership" {
    const allocator = std.testing.allocator;
    var slot_tracker = try sig.replay.trackers.SlotTracker.initEmpty(allocator, 0);
    defer slot_tracker.deinit(allocator);

    try testAddTrackedSlot(allocator, &slot_tracker, 1, 0, &.{1});
    try testAddTrackedSlot(allocator, &slot_tracker, 2, 1, &.{ 1, 2 });
    try testAddTrackedSlot(allocator, &slot_tracker, 3, 2, &.{ 1, 2, 3 });
    try testAddTrackedSlot(allocator, &slot_tracker, 4, 1, &.{ 1, 4 });
    try testAddTrackedSlot(allocator, &slot_tracker, 5, 4, &.{ 1, 4, 5 });

    const ctx = testSlotReadCtx(&slot_tracker);
    var state = SlotStateCache.init(ctx, .FOR_TESTS);
    defer state.deinit(allocator);

    _ = try testOnSlotFrozen(&state, allocator, 2, 1, 0);
    _ = try testOnSlotFrozen(&state, allocator, 3, 2, 0);
    _ = try testOnSlotFrozen(&state, allocator, 4, 1, 0);
    _ = try testOnSlotFrozen(&state, allocator, 5, 4, 0);

    const first = state.onTipChanged(ctx, 3);
    try std.testing.expect(first.notify_commitments.processed);
    try std.testing.expect(!first.notify_commitments.confirmed);
    try std.testing.expect(!first.notify_commitments.finalized);
    try std.testing.expect(state.isSlotOnCurrentFork(2));
    try std.testing.expect(state.isSlotOnCurrentFork(3));
    try std.testing.expect(!state.isSlotOnCurrentFork(4));
    try std.testing.expect(!state.isSlotOnCurrentFork(5));
    try std.testing.expectEqual(3, state.processed_tip);

    const second = state.onTipChanged(ctx, 5);
    try std.testing.expect(second.notify_commitments.processed);
    try std.testing.expect(!state.isSlotOnCurrentFork(2));
    try std.testing.expect(!state.isSlotOnCurrentFork(3));
    try std.testing.expect(state.isSlotOnCurrentFork(4));
    try std.testing.expect(state.isSlotOnCurrentFork(5));
    try std.testing.expectEqual(5, state.processed_tip);
}

test "SlotStateCache: off-fork frozen slot is not on current fork" {
    const allocator = std.testing.allocator;
    var slot_tracker = try sig.replay.trackers.SlotTracker.initEmpty(allocator, 0);
    defer slot_tracker.deinit(allocator);

    try testAddTrackedSlot(allocator, &slot_tracker, 1, 0, &.{1});
    try testAddTrackedSlot(allocator, &slot_tracker, 2, 1, &.{ 1, 2 });
    try testAddTrackedSlot(allocator, &slot_tracker, 3, 1, &.{ 1, 3 });

    const ctx = testSlotReadCtx(&slot_tracker);
    var state = SlotStateCache.init(ctx, .FOR_TESTS);
    defer state.deinit(allocator);

    slot_tracker.commitments.update(.processed, 2);
    _ = state.onTipChanged(ctx, 2);

    const on_fork = try testOnSlotFrozen(&state, allocator, 2, 1, 0);
    const off_fork = try testOnSlotFrozen(&state, allocator, 3, 1, 0);

    try std.testing.expect(state.isSlotOnCurrentFork(2));
    try std.testing.expect(!state.isSlotOnCurrentFork(3));
    try std.testing.expect(on_fork.notify_commitments.processed);
    try std.testing.expect(!off_fork.notify_commitments.processed);
}

test "SlotStateCache: ancestor iterator walks cached parents" {
    const allocator = std.testing.allocator;
    var slot_tracker = try sig.replay.trackers.SlotTracker.initEmpty(allocator, 0);
    defer slot_tracker.deinit(allocator);

    const ctx = testSlotReadCtx(&slot_tracker);
    var state = SlotStateCache.init(ctx, .FOR_TESTS);
    defer state.deinit(allocator);

    _ = try testOnSlotFrozen(&state, allocator, 1, 0, 0);
    _ = try testOnSlotFrozen(&state, allocator, 2, 1, 0);
    _ = try testOnSlotFrozen(&state, allocator, 3, 2, 0);

    var ancestors = state.ancestorIterator(3);
    const first = ancestors.next().?;
    try std.testing.expectEqual(3, first.slot);
    try std.testing.expectEqual(@as(?Slot, 2), first.cached_slot.parent);

    const second = ancestors.next().?;
    try std.testing.expectEqual(2, second.slot);
    try std.testing.expectEqual(@as(?Slot, 1), second.cached_slot.parent);

    const third = ancestors.next().?;
    try std.testing.expectEqual(1, third.slot);
    try std.testing.expectEqual(@as(?Slot, 0), third.cached_slot.parent);

    try std.testing.expect(ancestors.next() == null);
}

test "SlotStateCache: collectPublishableConfirmedSlots returns newest first and marks published" {
    const allocator = std.testing.allocator;
    var slot_tracker = try sig.replay.trackers.SlotTracker.initEmpty(allocator, 0);
    defer slot_tracker.deinit(allocator);

    const ctx = testSlotReadCtx(&slot_tracker);
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

test "SlotStateCache: root jump over multiple slots" {
    const allocator = std.testing.allocator;
    var slot_tracker = try sig.replay.trackers.SlotTracker.initEmpty(allocator, 0);
    defer slot_tracker.deinit(allocator);

    const ctx = testSlotReadCtx(&slot_tracker);
    var state = SlotStateCache.init(ctx, .FOR_TESTS);
    defer state.deinit(allocator);

    _ = try testOnSlotFrozen(&state, allocator, 5, 4, 0);
    _ = try testOnSlotFrozen(&state, allocator, 6, 5, 0);
    _ = try testOnSlotFrozen(&state, allocator, 7, 6, 0);
    _ = try testOnSlotFrozen(&state, allocator, 8, 7, 0);

    for ([_]Slot{ 5, 6, 7, 8 }) |slot| {
        const transition = try state.onSlotRooted(allocator, slot);
        try std.testing.expect(transition.cached_slot != null);
        try std.testing.expect(transition.notify_commitments.finalized);
        try std.testing.expectEqual(@as(?Slot, slot), transition.evict_through);
    }

    state.evictFinalizedThrough(7);
    try std.testing.expect(state.cached_slots.getPtr(5) == null);
    try std.testing.expect(state.cached_slots.getPtr(6) == null);
    try std.testing.expect(state.cached_slots.getPtr(7) == null);
    try std.testing.expect(state.cached_slots.getPtr(8) != null);
}

test "SlotStateCache: slot frozen stores producer-owned modified accounts" {
    const allocator = std.testing.allocator;
    var slot_tracker = try sig.replay.trackers.SlotTracker.initEmpty(allocator, 0);
    defer slot_tracker.deinit(allocator);

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

    const ctx = testSlotReadCtx(&slot_tracker);
    var state = SlotStateCache.init(ctx, .FOR_TESTS);
    defer state.deinit(allocator);

    var slot_data: types.SlotFrozenEvent = .{
        .slot = 5,
        .parent = 4,
        .root = 0,
        .accounts = .{
            .accounts = accounts,
            .arena = arena,
        },
    };
    const transition = try state.onSlotFrozen(allocator, &slot_data);

    const cached = transition.cached_slot.?;
    try std.testing.expectEqual(@as(usize, 1), cached.modified_accounts.accounts.len);
    try std.testing.expect(cached.modified_accounts.accounts[0].pubkey.equals(&pk));
    try std.testing.expectEqual(
        @as(u64, 42_000),
        cached.modified_accounts.accounts[0].account.lamports,
    );
}
