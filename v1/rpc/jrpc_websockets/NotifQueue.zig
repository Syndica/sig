//! Fixed-capacity ring of serialized notifications.
//!
//! Commit path is configured at `init` and does not change afterward.
//!
//! Commit paths:
//! - `.reserved`: reserve -> ready -> in-order commit-prefix.
//! - `.direct`: append as already committed.
//!
//! `reserved` allows producers to reserve position in queue to maintain ordering
//! before serialization on another thread.
//! `direct` allows producers to skip reservation and commit in a single step.
//!
//! Index model:
//! - Logical indexes are monotonically increasing; storage is `index % capacity`.
//! - `head`: index of most recently committed notification.
//! - `tail`: oldest retained committed index, or `head + 1` when empty.
//! - `next_reserve`: next index to reserve for uncommitted entries.
//! - `tail..head` is a frontier window, not a guaranteed contiguous retained set.
//! - Capacity must be a power of two for efficient modulo via bitmask (rounded up
//!   to next power of 2 if needed).
//!
//! All operations are single-threaded (IO loop thread only).
const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../../sig.zig");

const JRPCHandler = @import("handler.zig").JRPCHandler;

const NotifPayload = sig.sync.RcSlice(u8);

const NotifQueue = @This();
// Invariants:
// - Empty committed set iff `tail == head + 1`.
// - Non-empty committed set iff `tail <= head`.
// - `.ready` and `.committed` entries always hold valid payload refs.
// - `next_reserve > head` always.
// - Logical indexes in `[tail, head]` may be absent (dropped/overwritten).
entries: []Entry,
capacity: u64,
mod_mask: u64,
head: u64,
tail: u64,
next_reserve: u64,
/// Reserved or committed terminal notification index, if this queue has one.
final_index: ?u64,
/// Selected commit behavior mode for this queue (set at init).
commit_path: CommitPath,
allocator: std.mem.Allocator,
/// True when this queue has newly committed notifications that still need
/// a subscriber wake pass in the current loop-drain cycle.
wake_pending: bool,
/// Unordered list of current subscribers to this queue.
subscribers: std.ArrayList(*JRPCHandler),

/// Queue commit behavior mode.
pub const CommitPath = enum {
    /// Reserve -> ready -> in-order prefix commit.
    reserved,
    /// Reserve + commit in one step (no reservation index in commit message).
    direct,
};

/// One physical ring slot.
pub const Entry = struct {
    state: State = .empty,
    /// Valid only when state is .ready or .committed.
    payload: NotifPayload = undefined,
    /// Number of subscribers that still need this committed entry.
    remaining: u32 = 0,

    /// Slot lifecycle state.
    pub const State = enum {
        /// Unused (or skipped) slot.
        empty,
        /// Reserved index, payload not attached yet.
        reserved,
        /// Payload attached, waiting for in-order commit.
        ready,
        /// Visible to subscribers.
        committed,
    };
};

pub const CommittedNotif = struct {
    payload: NotifPayload,
    /// If true then this is the last entry for this NotifQueue (subscriber can expect no more
    /// notifications after this one unless reset)
    is_final: bool,
};

/// `IndexOverwritten`: index is older than retained `tail`.
/// `IndexSkipped`: index is inside `[tail, head]` but explicitly skipped.
/// Only used when using reserved commit path when reservation rollback occurs.
pub const GetError = error{ IndexOverwritten, IndexSkipped };
pub const ReserveError = error{FinalNotificationExists};
pub const CommitError = error{
    ExpectedIndexForReservedPath,
    UnexpectedIndexForDirectPath,
    FinalNotificationExists,
    InvalidState,
    InvalidFinalIndex,
};

/// Allocate queue storage and start with an empty committed set.
///
/// `capacity` must be non-zero or this returns `error.ZeroCapacity`.
/// `capacity` is rounded up to the next power of two for mask-based indexing.
pub fn init(allocator: std.mem.Allocator, capacity: u64, commit_path: CommitPath) !NotifQueue {
    // Disallow zero capacity to avoid needing to deal with it in operations.
    // The capacity is fixed so it's unusable if set to zero, and it's not a generic container
    // so there isn't any utility gained as a generic "unused" fallback.
    if (capacity == 0) return error.ZeroCapacity;
    const pow2 = try std.math.ceilPowerOfTwo(u64, capacity);
    const entries = try allocator.alloc(Entry, @intCast(pow2));
    for (entries) |*e| {
        e.* = .{};
    }
    return .{
        .entries = entries,
        .capacity = pow2,
        .mod_mask = pow2 - 1,
        .head = 0,
        .tail = 1,
        .next_reserve = 1,
        .final_index = null,
        .commit_path = commit_path,
        .allocator = allocator,
        .wake_pending = false,
        .subscribers = .{},
    };
}

/// Release all retained payload refs and owned allocations.
pub fn deinit(self: *NotifQueue) void {
    self.clearAllSlots();

    self.allocator.free(self.entries);
    self.subscribers.deinit(self.allocator);
}

pub fn finalNotificationIndex(self: *const NotifQueue) ?u64 {
    return self.final_index;
}

/// Reserve the next ordered slot. Returns the reserved index.
///
/// Reserved-path only. Panics if called on a direct-path queue.
pub fn reserveUncommitted(self: *NotifQueue) ReserveError!u64 {
    defer self.assertInvariants();

    self.requireMode(.reserved);
    if (self.final_index != null) {
        return error.FinalNotificationExists;
    }

    return self.reserveIndex();
}

/// Reserve the terminal notification index for this queue.
///
/// Reserved-path only. Panics if called on a direct-path queue.
pub fn reserveFinalUncommitted(self: *NotifQueue) ReserveError!u64 {
    defer self.assertInvariants();

    self.requireMode(.reserved);
    if (self.final_index != null) {
        return error.FinalNotificationExists;
    }

    const index = self.reserveIndex();
    self.final_index = index;
    return index;
}

/// Commit payload through the queue's configured commit path.
///
/// `.reserved` requires a non-null index and performs mark-ready +
/// commit-prefix progression.
/// `.direct` requires a null index and commits immediately.
///
/// Returns the number of notifications newly committed by this call.
/// Returns `0` when there are no subscribers (payload is dropped).
pub fn commitSerialized(
    self: *NotifQueue,
    index: ?u64,
    payload: NotifPayload,
    is_final: bool,
) CommitError!usize {
    if (self.subscriberCount() == 0) {
        payload.deinit(self.allocator);
        return 0;
    }

    return switch (self.commit_path) {
        .reserved => {
            const ready_index = index orelse return error.ExpectedIndexForReservedPath;
            const matches_final_index = self.final_index == ready_index;
            if (matches_final_index != is_final) {
                return error.InvalidFinalIndex;
            }
            try self.markReady(ready_index, payload);
            return self.commitReadyPrefix();
        },
        .direct => {
            if (index != null) {
                return error.UnexpectedIndexForDirectPath;
            }
            try self.appendCommitted(payload, is_final);
            return 1;
        },
    };
}

/// Cancel a reserved entry when serialization cannot be submitted.
///
/// Reserved-path only. Panics if called on a direct-path queue.
///
/// No-op when `index` is stale/outside the retained reservation window
/// or the slot is no longer `.reserved`.
pub fn cancelReservation(self: *NotifQueue, index: u64) void {
    defer self.assertInvariants();

    self.requireMode(.reserved);

    if (!self.isReservedWindowIndex(index)) {
        return;
    }

    const slot = self.slotFor(index);
    const entry = &self.entries[slot];
    if (entry.state != .reserved) {
        return;
    }

    self.clearEntryAtIndex(index, entry);
}

/// Read a committed entry for a subscriber cursor.
///
/// On success returns a cloned payload (caller must `deinit`). Non-final
/// entries consume one subscriber reference for that entry. Final entries are
/// sticky and remain retained until the queue is reset or they roll off the ring.
/// NOTE: not expected final entries would roll off the ring since it should be final.
/// Returns `null` when `index > head`, `error.IndexOverwritten` when
/// `index < tail`, and `error.IndexSkipped` when the index is within
/// `[tail, head]` but is skipped/canceled and will not be populated.
pub fn get(self: *NotifQueue, index: u64) GetError!?CommittedNotif {
    if (index < self.tail) {
        return error.IndexOverwritten;
    }
    if (index > self.head) {
        return null;
    }

    const slot = self.slotFor(index);
    const entry = &self.entries[slot];

    if (entry.state != .committed) {
        return error.IndexSkipped;
    }

    const clone = entry.payload.acquire();
    const is_final = self.final_index == index;
    if (!is_final) {
        self.consumeSubscriberRef(slot, index);
    }
    return .{ .payload = clone, .is_final = is_final };
}

/// Number of currently registered subscribers.
pub fn subscriberCount(self: *const NotifQueue) usize {
    return self.subscribers.items.len;
}

/// Register a subscriber.
///
/// Callers must not register the same handler pointer more than once.
/// Returns `error.TooManySubscribers` when count exceeds `u32`.
pub fn addSubscriber(self: *NotifQueue, ptr: *JRPCHandler) !void {
    if (self.subscribers.items.len == std.math.maxInt(u32)) {
        return error.TooManySubscribers;
    }
    try self.subscribers.append(self.allocator, ptr);
}

/// Unregister a subscriber and release that subscriber's pending refs.
///
/// `next_index` is the first index this subscriber had not consumed yet.
/// Committed entries in `[max(next_index, tail), head]` are decremented once
/// on behalf of the removed subscriber.
pub fn removeSubscriber(self: *NotifQueue, subscriber: *JRPCHandler, next_index: u64) void {
    defer self.assertInvariants();

    const remove_idx = for (self.subscribers.items, 0..) |item, i| {
        if (item == subscriber) {
            break i;
        }
    } else {
        return;
    };
    _ = self.subscribers.swapRemove(remove_idx);

    if (self.subscriberCount() == 0) {
        self.resetForNoSubscribers();
        return;
    }

    if (next_index > self.head) {
        return;
    }

    var idx = @max(next_index, self.tail);
    while (idx <= self.head) : (idx += 1) {
        const slot = self.slotFor(idx);
        if (self.entries[slot].state != .committed) {
            continue;
        }
        self.consumeSubscriberRef(slot, idx);
    }
}

/// Attach serialized payload to a reserved entry (reserved -> ready).
///
/// Reserved-path only. Panics if called on a direct-path queue.
///
/// Returns `error.InvalidState` when `index` is outside the retained
/// reservation window or the slot is not currently `.reserved`.
fn markReady(self: *NotifQueue, index: u64, p: NotifPayload) CommitError!void {
    defer self.assertInvariants();

    self.requireMode(.reserved);

    if (!self.isReservedWindowIndex(index)) {
        return error.InvalidState;
    }

    const slot = self.slotFor(index);
    const entry = &self.entries[slot];
    if (entry.state != .reserved) {
        return error.InvalidState;
    }
    entry.* = .{ .state = .ready, .payload = p };
}

/// Commit the maximal in-order `.ready` prefix after `head`.
///
/// Reserved-path only. Panics if called on a direct-path queue.
///
/// If the commit frontier lags behind the retained window, it is advanced
/// to the first representable index before scanning.
///
/// Stops at the first `.reserved` hole, skips dropped/overwritten indexes,
/// and returns the number of newly committed entries.
/// Requires at least one subscriber.
fn commitReadyPrefix(self: *NotifQueue) usize {
    defer self.assertInvariants();

    self.requireMode(.reserved);
    self.clampCommitFrontierToRetainedWindow();

    var count: usize = 0;

    while (self.head + 1 < self.next_reserve) {
        const index = self.head + 1;
        const slot = self.slotFor(index);
        const entry = &self.entries[slot];

        switch (entry.state) {
            .ready => {
                // transition ready to committed
                const subscriber_count = self.beginCommit(index);
                entry.state = .committed;
                // final entries are sticky and do not track subscriber refs
                entry.remaining = if (self.final_index == index) 0 else subscriber_count;
                count += 1;
            },
            .reserved => {
                break;
            },
            .empty => {
                // just skip this index and move frontier forward
                self.head = index;
                if (self.tail == index) {
                    self.tail = index + 1;
                }
            },
            .committed => unreachable, // not possible due to invariants
        }
    }

    return count;
}

/// Reserve the next slot and commit a payload in one step.
///
/// Direct-path only. Panics if called on a reserved-path queue.
///
/// Internal helper used by direct-path commit flow.
/// Requires at least one subscriber.
fn appendCommitted(self: *NotifQueue, p: NotifPayload, is_final: bool) CommitError!void {
    defer self.assertInvariants();

    self.requireMode(.direct);
    if (self.final_index != null) {
        return error.FinalNotificationExists;
    }

    const reservation = self.reserveNextSlot();
    if (is_final) {
        self.final_index = reservation.index;
    }
    const subscriber_count = self.beginCommit(reservation.index);
    self.entries[reservation.slot] = .{
        .state = .committed,
        .payload = p,
        // final entries are sticky and do not track subscriber refs
        .remaining = if (self.final_index == reservation.index) 0 else subscriber_count,
    };
}

/// Get physical slot index for a logical index.
fn slotFor(self: *const NotifQueue, index: u64) usize {
    return @intCast(index & self.mod_mask);
}

/// Enforce that a mode-specific API is called only for its commit path.
fn requireMode(self: *const NotifQueue, expected: CommitPath) void {
    if (self.commit_path != expected) {
        @panic("queue API called with wrong commit mode");
    }
}

/// Oldest logical index that can still be represented by ring storage.
fn oldestRetainedIndex(self: *const NotifQueue) u64 {
    if (self.next_reserve > self.capacity) {
        return self.next_reserve - self.capacity;
    }
    return 1;
}

/// Check if index is within the window of still-representable reservations.
fn isReservedWindowIndex(self: *const NotifQueue, index: u64) bool {
    const oldest = self.oldestRetainedIndex();
    return index >= oldest and index < self.next_reserve;
}

/// Refresh head and tail to be within the retained window.
fn clampCommitFrontierToRetainedWindow(self: *NotifQueue) void {
    const oldest = self.oldestRetainedIndex();
    if (self.head + 1 >= oldest) {
        return;
    }

    const had_committed_before = self.tail <= self.head;
    self.head = oldest - 1;

    if (had_committed_before) {
        if (self.tail < oldest) {
            self.tail = oldest;
        }
    } else {
        self.tail = self.head + 1;
    }
}

fn reserveIndex(self: *NotifQueue) u64 {
    const reservation = self.reserveNextSlot();
    self.entries[reservation.slot] = .{ .state = .reserved };
    return reservation.index;
}

fn reserveNextSlot(self: *NotifQueue) struct { slot: usize, index: u64 } {
    const index = self.next_reserve;
    const slot = self.slotFor(index);

    self.releaseOccupiedSlot(slot, index);
    self.next_reserve = index + 1;

    return .{ .slot = slot, .index = index };
}

/// Move commit frontier to `index` and return current subscriber count.
/// Used to prepare for commit.
/// Requires at least one subscriber.
fn beginCommit(self: *NotifQueue, index: u64) u32 {
    // Sanity checks for invariants
    const sub_count = self.subscriberCount();
    std.debug.assert(sub_count > 0);
    std.debug.assert(sub_count <= std.math.maxInt(u32));

    self.head = index;
    const had_committed_before = self.tail <= self.head;
    if (!had_committed_before) {
        // no commits before, advance the tail
        self.tail = index;
    }

    return @intCast(sub_count);
}

/// Consume one subscriber reference; clear slot when the last ref is consumed.
fn consumeSubscriberRef(self: *NotifQueue, slot: usize, index: u64) void {
    const entry = &self.entries[slot];
    if (self.final_index == index) {
        return;
    }
    entry.remaining -= 1;
    if (entry.remaining == 0) {
        self.clearEntryAtIndex(index, entry);
        self.onCommittedRemoved(index);
    }
}

/// Clear one slot and release payload if present.
fn clearEntry(self: *NotifQueue, entry: *Entry) void {
    if (entry.state == .ready or entry.state == .committed) {
        entry.payload.deinit(self.allocator);
    }
    entry.* = .{};
}

fn clearEntryAtIndex(self: *NotifQueue, index: u64, entry: *Entry) void {
    self.clearEntry(entry);
    if (self.final_index == index) {
        self.final_index = null;
    }
}

fn clearAllSlots(self: *NotifQueue) void {
    for (self.entries) |*entry| {
        self.clearEntry(entry);
    }
    self.final_index = null;
}

/// Reclaim a slot before reusing it for `new_index`.
///
/// Ready entries are dropped. Committed entries are removed from retention,
/// which may advance `tail`.
///
/// A `.committed` state here implies wrap reuse, so the evicted logical index
/// is derived as `new_index - capacity`.
fn releaseOccupiedSlot(self: *NotifQueue, slot: usize, new_index: u64) void {
    const entry = &self.entries[slot];
    const prior_state = entry.state;

    if (prior_state == .empty) {
        return;
    }

    // should not be releasing an occupied slot before reaching `capacity` reservations
    std.debug.assert(new_index > self.capacity);
    const released_index = new_index - self.capacity;
    self.clearEntryAtIndex(released_index, entry);

    if (prior_state == .committed) {
        self.onCommittedRemoved(released_index);
    }
}

/// Update `tail` after removing a committed index from retention.
///
/// Only removals at current `tail` can move the frontier; find the next
/// retained committed index or mark committed set empty.
fn onCommittedRemoved(self: *NotifQueue, released_index: u64) void {
    if (released_index != self.tail) {
        return;
    }

    var idx = released_index + 1;
    while (idx <= self.head) : (idx += 1) {
        const entry = self.entries[self.slotFor(idx)];
        if (entry.state == .committed) {
            self.tail = idx;
            return;
        }
    }

    self.tail = self.head + 1;
}

/// Drop all retained payloads when last subscriber disconnects.
///
/// Keeps reservation progress (`next_reserve`) but resets committed state to empty.
fn resetForNoSubscribers(self: *NotifQueue) void {
    self.clearAllSlots();

    self.head = self.next_reserve - 1;
    self.tail = self.head + 1;
}

fn assertInvariants(self: *const NotifQueue) void {
    // A lot of checks in here so just enable for debug builds
    if (builtin.mode != .Debug) {
        return;
    }

    std.debug.assert(self.next_reserve > self.head);
    std.debug.assert(self.tail == self.head + 1 or self.tail <= self.head);

    if (self.commit_path == .direct) {
        for (self.entries) |entry| {
            std.debug.assert(entry.state != .reserved);
            std.debug.assert(entry.state != .ready);
        }
    }

    if (self.final_index) |final_index| {
        std.debug.assert(final_index >= self.oldestRetainedIndex());
        std.debug.assert(final_index < self.next_reserve);
        std.debug.assert(self.entries[self.slotFor(final_index)].state != .empty);
    }

    if (self.tail <= self.head) {
        std.debug.assert(self.tail >= self.oldestRetainedIndex());

        const tail_entry = self.entries[self.slotFor(self.tail)];
        std.debug.assert(tail_entry.state == .committed);
    }
}

fn allocPayload(allocator: std.mem.Allocator, s: []const u8) !NotifPayload {
    const p = try NotifPayload.alloc(allocator, s.len);
    @memcpy(p.payload(), s);
    return p;
}

fn reserveReady(q: *NotifQueue, allocator: std.mem.Allocator, msg: []const u8) !u64 {
    const idx = try q.reserveUncommitted();
    try q.markReady(idx, try allocPayload(allocator, msg));
    return idx;
}

fn mustGetNotif(q: *NotifQueue, index: u64) !CommittedNotif {
    return (try q.get(index)) orelse error.TestUnexpectedResult;
}

fn mustGet(q: *NotifQueue, index: u64) !NotifPayload {
    const notif = try mustGetNotif(q, index);
    return notif.payload;
}

fn committedCount(q: *const NotifQueue) u64 {
    var count: u64 = 0;
    for (q.entries) |entry| {
        if (entry.state == .committed) {
            count += 1;
        }
    }
    return count;
}

test "invariant: empty committed set uses tail == head + 1" {
    const allocator = std.testing.allocator;

    var q = try NotifQueue.init(allocator, 8, .reserved);
    defer q.deinit();

    try std.testing.expectEqual(q.head + 1, q.tail);

    var sub: JRPCHandler = undefined;
    try q.addSubscriber(&sub);

    const idx = try reserveReady(&q, allocator, "msg");
    try std.testing.expectEqual(1, q.commitReadyPrefix());

    const got = try mustGet(&q, idx);
    defer got.deinit(allocator);

    try std.testing.expectEqual(q.head + 1, q.tail);
}

test "basic reserve, ready, commit, get" {
    const allocator = std.testing.allocator;

    var q = try NotifQueue.init(allocator, 8, .reserved);
    defer q.deinit();

    var sub: JRPCHandler = undefined;
    try q.addSubscriber(&sub);

    const idx1 = try reserveReady(&q, allocator, "msg1");
    try std.testing.expectEqual(1, idx1);

    const committed = q.commitReadyPrefix();
    try std.testing.expectEqual(1, committed);
    try std.testing.expectEqual(1, q.head);

    const got = try mustGet(&q, 1);
    defer got.deinit(allocator);
    try std.testing.expectEqualStrings("msg1", got.payload());
}

test "commitSerialized reserved path requires index" {
    const allocator = std.testing.allocator;

    var q = try NotifQueue.init(allocator, 8, .reserved);
    defer q.deinit();

    var sub: JRPCHandler = undefined;
    try q.addSubscriber(&sub);

    const p = try allocPayload(allocator, "x");
    try std.testing.expectError(
        error.ExpectedIndexForReservedPath,
        q.commitSerialized(null, p, false),
    );
    p.deinit(allocator);
}

test "commitSerialized direct path rejects index" {
    const allocator = std.testing.allocator;

    var q = try NotifQueue.init(allocator, 8, .direct);
    defer q.deinit();

    var sub: JRPCHandler = undefined;
    try q.addSubscriber(&sub);

    const p = try allocPayload(allocator, "x");
    try std.testing.expectError(error.UnexpectedIndexForDirectPath, q.commitSerialized(1, p, false));
    p.deinit(allocator);
}

test "init with zero capacity returns error" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.ZeroCapacity, NotifQueue.init(allocator, 0, .reserved));
    try std.testing.expectError(error.ZeroCapacity, NotifQueue.init(allocator, 0, .direct));
}

test "capacity 1 reserved path: commit, get, wraparound" {
    const allocator = std.testing.allocator;

    var q = try NotifQueue.init(allocator, 1, .reserved);
    defer q.deinit();

    try std.testing.expectEqual(1, q.capacity);
    try std.testing.expectEqual(0, q.mod_mask);

    var sub: JRPCHandler = undefined;
    try q.addSubscriber(&sub);

    // Single slot: reserve, ready, commit, get.
    const idx1 = try reserveReady(&q, allocator, "first");
    try std.testing.expectEqual(1, q.commitReadyPrefix());
    try std.testing.expectEqual(idx1, q.head);
    try std.testing.expectEqual(idx1, q.tail);

    const got1 = try mustGet(&q, idx1);
    defer got1.deinit(allocator);
    try std.testing.expectEqualStrings("first", got1.payload());
    try std.testing.expectEqual(q.head + 1, q.tail); // empty after consumption

    // Second entry wraps into the same slot, evicting nothing (already consumed).
    const idx2 = try reserveReady(&q, allocator, "second");
    try std.testing.expectEqual(1, q.commitReadyPrefix());

    const got2 = try mustGet(&q, idx2);
    defer got2.deinit(allocator);
    try std.testing.expectEqualStrings("second", got2.payload());
    try std.testing.expectError(NotifQueue.GetError.IndexOverwritten, q.get(idx1));

    // Third entry wraps while previous is unconsumed (subscriber lag).
    const idx3 = try reserveReady(&q, allocator, "third");
    try std.testing.expectEqual(1, q.commitReadyPrefix());

    // idx3 evicted idx2's committed entry via wrap.
    try std.testing.expectError(NotifQueue.GetError.IndexOverwritten, q.get(idx2));

    const got3 = try mustGet(&q, idx3);
    defer got3.deinit(allocator);
    try std.testing.expectEqualStrings("third", got3.payload());
}

test "capacity 1 direct path: commit, get, wraparound" {
    const allocator = std.testing.allocator;

    var q = try NotifQueue.init(allocator, 1, .direct);
    defer q.deinit();

    var sub: JRPCHandler = undefined;
    try q.addSubscriber(&sub);

    try q.appendCommitted(try allocPayload(allocator, "a"), false);
    try std.testing.expectEqual(1, q.head);

    const got_a = try mustGet(&q, 1);
    defer got_a.deinit(allocator);
    try std.testing.expectEqualStrings("a", got_a.payload());
    try std.testing.expectEqual(q.head + 1, q.tail);

    // Wrap into same slot.
    try q.appendCommitted(try allocPayload(allocator, "b"), false);
    try std.testing.expectEqual(2, q.head);
    try std.testing.expectError(NotifQueue.GetError.IndexOverwritten, q.get(1));

    const got_b = try mustGet(&q, 2);
    defer got_b.deinit(allocator);
    try std.testing.expectEqualStrings("b", got_b.payload());

    // Wrap while unconsumed (lag eviction).
    try q.appendCommitted(try allocPayload(allocator, "c"), false);
    try q.appendCommitted(try allocPayload(allocator, "d"), false);
    try std.testing.expectEqual(4, q.head);
    try std.testing.expectError(NotifQueue.GetError.IndexOverwritten, q.get(3));

    const got_d = try mustGet(&q, 4);
    defer got_d.deinit(allocator);
    try std.testing.expectEqualStrings("d", got_d.payload());
}

test "markReady rejects stale index after slot reuse" {
    const allocator = std.testing.allocator;

    var q = try NotifQueue.init(allocator, 1, .reserved);
    defer q.deinit();

    const idx1 = try q.reserveUncommitted();
    const idx2 = try q.reserveUncommitted();

    const stale = try allocPayload(allocator, "stale");
    try std.testing.expectError(error.InvalidState, q.markReady(idx1, stale));
    stale.deinit(allocator);

    try q.markReady(idx2, try allocPayload(allocator, "fresh"));
}

test "out-of-order ready with in-order commit" {
    const allocator = std.testing.allocator;

    var q = try NotifQueue.init(allocator, 8, .reserved);
    defer q.deinit();

    var sub: JRPCHandler = undefined;
    try q.addSubscriber(&sub);

    const idx1 = try q.reserveUncommitted();
    const idx2 = try q.reserveUncommitted();
    const idx3 = try q.reserveUncommitted();

    try q.markReady(idx3, try allocPayload(allocator, "msg3"));
    try std.testing.expectEqual(0, q.commitReadyPrefix());

    try q.markReady(idx1, try allocPayload(allocator, "msg1"));
    try std.testing.expectEqual(1, q.commitReadyPrefix());

    try q.markReady(idx2, try allocPayload(allocator, "msg2"));
    try std.testing.expectEqual(2, q.commitReadyPrefix());
    try std.testing.expectEqual(3, q.head);

    const m1 = try mustGet(&q, 1);
    defer m1.deinit(allocator);
    try std.testing.expectEqualStrings("msg1", m1.payload());

    const m2 = try mustGet(&q, 2);
    defer m2.deinit(allocator);
    try std.testing.expectEqualStrings("msg2", m2.payload());

    const m3 = try mustGet(&q, 3);
    defer m3.deinit(allocator);
    try std.testing.expectEqualStrings("msg3", m3.payload());
}

test "rollback gap is skipped and later ready commits" {
    const allocator = std.testing.allocator;

    var q = try NotifQueue.init(allocator, 8, .reserved);
    defer q.deinit();

    var sub: JRPCHandler = undefined;
    try q.addSubscriber(&sub);

    const idx1 = try q.reserveUncommitted();
    const idx2 = try q.reserveUncommitted();

    q.cancelReservation(idx1);

    try q.markReady(idx2, try allocPayload(allocator, "msg2"));

    try std.testing.expectEqual(1, q.commitReadyPrefix());
    try std.testing.expectEqual(idx2, q.head);
    try std.testing.expectEqual(idx2, q.tail);
    try std.testing.expectError(NotifQueue.GetError.IndexOverwritten, q.get(idx1));

    const got = try mustGet(&q, idx2);
    defer got.deinit(allocator);
    try std.testing.expectEqualStrings("msg2", got.payload());
}

test "rollback keeps committed backlog before rollback point" {
    const allocator = std.testing.allocator;

    var q = try NotifQueue.init(allocator, 8, .reserved);
    defer q.deinit();

    var sub: JRPCHandler = undefined;
    try q.addSubscriber(&sub);

    const idx1 = try reserveReady(&q, allocator, "old");
    try std.testing.expectEqual(1, q.commitReadyPrefix());

    const old = try mustGet(&q, idx1);
    defer old.deinit(allocator);
    try std.testing.expectEqualStrings("old", old.payload());

    const idx2 = try q.reserveUncommitted();
    const idx3 = try q.reserveUncommitted();
    q.cancelReservation(idx3);

    try q.markReady(idx2, try allocPayload(allocator, "new"));
    try std.testing.expectEqual(1, q.commitReadyPrefix());

    const got = try mustGet(&q, idx2);
    defer got.deinit(allocator);
    try std.testing.expectEqualStrings("new", got.payload());
}

test "get returns IndexSkipped for dropped index in tail-head window" {
    const allocator = std.testing.allocator;

    var q = try NotifQueue.init(allocator, 8, .reserved);
    defer q.deinit();

    var sub: JRPCHandler = undefined;
    try q.addSubscriber(&sub);

    const idx1 = try reserveReady(&q, allocator, "1");
    try std.testing.expectEqual(1, q.commitReadyPrefix());

    const idx2 = try q.reserveUncommitted();
    const idx3 = try q.reserveUncommitted();
    q.cancelReservation(idx2);
    try q.markReady(idx3, try allocPayload(allocator, "3"));

    try std.testing.expectEqual(1, q.commitReadyPrefix());
    try std.testing.expectEqual(idx1, q.tail);
    try std.testing.expectEqual(idx3, q.head);
    try std.testing.expectError(NotifQueue.GetError.IndexSkipped, q.get(idx2));
}

test "wraparound tail transitions with gaps and slot reuse" {
    const allocator = std.testing.allocator;

    var q = try NotifQueue.init(allocator, 4, .reserved);
    defer q.deinit();

    var sub: JRPCHandler = undefined;
    try q.addSubscriber(&sub);

    const idx1 = try reserveReady(&q, allocator, "1");
    try std.testing.expectEqual(1, q.commitReadyPrefix());
    try std.testing.expectEqual(idx1, q.tail);

    const idx2 = try q.reserveUncommitted();
    const idx3 = try q.reserveUncommitted();
    const idx4 = try q.reserveUncommitted();
    const idx5 = try q.reserveUncommitted(); // wraps and evicts idx1
    const idx6 = try q.reserveUncommitted(); // middle slot

    // idx1 was evicted by wrap; no committed entries are retained.
    try std.testing.expectEqual(q.head + 1, q.tail);

    q.cancelReservation(idx2);
    q.cancelReservation(idx3);
    q.cancelReservation(idx4);
    q.cancelReservation(idx5);
    try q.markReady(idx6, try allocPayload(allocator, "6"));

    try std.testing.expectEqual(1, q.commitReadyPrefix());
    try std.testing.expectEqual(idx6, q.head);
    try std.testing.expectEqual(idx6, q.tail);

    // Consume to return to empty committed set before the next wraparound commit.
    const got6 = try mustGet(&q, idx6);
    defer got6.deinit(allocator);
    try std.testing.expectEqual(q.head + 1, q.tail);

    const idx7 = try q.reserveUncommitted();
    const idx8 = try q.reserveUncommitted(); // slot 0
    try q.markReady(idx8, try allocPayload(allocator, "8"));
    q.cancelReservation(idx7);

    try std.testing.expectEqual(1, q.commitReadyPrefix());
    try std.testing.expectEqual(idx8, q.tail);

    const got8 = try mustGet(&q, idx8);
    defer got8.deinit(allocator);
    try std.testing.expectEqual(q.head + 1, q.tail);

    const idx9 = try q.reserveUncommitted(); // slot 1
    try q.markReady(idx9, try allocPayload(allocator, "9"));
    try std.testing.expectEqual(1, q.commitReadyPrefix());
    try std.testing.expectEqual(idx9, q.tail);

    try std.testing.expectError(NotifQueue.GetError.IndexOverwritten, q.get(idx1));
    try std.testing.expectError(NotifQueue.GetError.IndexOverwritten, q.get(idx2));
    try std.testing.expectError(NotifQueue.GetError.IndexOverwritten, q.get(idx3));
    try std.testing.expectError(NotifQueue.GetError.IndexOverwritten, q.get(idx4));
    try std.testing.expectError(NotifQueue.GetError.IndexOverwritten, q.get(idx5));
}

test "reserved gap blocks commit and keeps empty tail" {
    const allocator = std.testing.allocator;

    var q = try NotifQueue.init(allocator, 4, .reserved);
    defer q.deinit();

    var sub: JRPCHandler = undefined;
    try q.addSubscriber(&sub);

    _ = try reserveReady(&q, allocator, "1");
    try std.testing.expectEqual(1, q.commitReadyPrefix());

    _ = try q.reserveUncommitted();
    _ = try q.reserveUncommitted();
    _ = try q.reserveUncommitted();
    const idx5 = try q.reserveUncommitted();

    // idx1 was evicted by wrap; no committed entries are retained.
    try std.testing.expectEqual(q.head + 1, q.tail);

    try q.markReady(idx5, try allocPayload(allocator, "5"));

    // Commit cannot pass the still-reserved idx2 gap.
    try std.testing.expectEqual(0, q.commitReadyPrefix());
    try std.testing.expectEqual(1, q.head);
    try std.testing.expectEqual(q.head + 1, q.tail);
}

test "commitReadyPrefix clamps frontier when lagging retained window" {
    const allocator = std.testing.allocator;

    var q = try NotifQueue.init(allocator, 4, .reserved);
    defer q.deinit();

    var sub: JRPCHandler = undefined;
    try q.addSubscriber(&sub);

    const idx1 = try reserveReady(&q, allocator, "1");
    try std.testing.expectEqual(1, q.commitReadyPrefix());

    const idx2 = try q.reserveUncommitted();
    _ = try q.reserveUncommitted();
    const idx4 = try q.reserveUncommitted();
    const idx5 = try q.reserveUncommitted();
    const idx6 = try q.reserveUncommitted();
    const idx7 = try q.reserveUncommitted();

    q.cancelReservation(idx4);
    q.cancelReservation(idx5);
    q.cancelReservation(idx6);
    try q.markReady(idx7, try allocPayload(allocator, "7"));

    try std.testing.expectEqual(1, q.commitReadyPrefix());
    try std.testing.expectEqual(idx7, q.head);
    try std.testing.expectEqual(idx7, q.tail);
    try std.testing.expectError(NotifQueue.GetError.IndexOverwritten, q.get(idx1));
    try std.testing.expectError(NotifQueue.GetError.IndexOverwritten, q.get(idx2));

    const got = try mustGet(&q, idx7);
    defer got.deinit(allocator);
    try std.testing.expectEqualStrings("7", got.payload());
}

test "overwrite beyond retention returns IndexOverwritten" {
    const allocator = std.testing.allocator;

    var q = try NotifQueue.init(allocator, 4, .reserved);
    defer q.deinit();

    var sub: JRPCHandler = undefined;
    try q.addSubscriber(&sub);

    for (0..4) |i| {
        var buf: [16]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "msg{d}", .{i}) catch unreachable;
        _ = try reserveReady(&q, allocator, msg);
    }
    try std.testing.expectEqual(4, q.commitReadyPrefix());
    try std.testing.expectEqual(4, q.head);

    _ = try q.reserveUncommitted();
    try std.testing.expectError(NotifQueue.GetError.IndexOverwritten, q.get(1));
}

test "get returns null when not committed" {
    const allocator = std.testing.allocator;

    var q = try NotifQueue.init(allocator, 8, .reserved);
    defer q.deinit();

    var sub: JRPCHandler = undefined;
    try q.addSubscriber(&sub);

    _ = try q.reserveUncommitted();
    try std.testing.expectEqual(null, try q.get(1));
}

test "ring wrap evicts .ready entry and frees payload" {
    const allocator = std.testing.allocator;

    var q = try NotifQueue.init(allocator, 2, .reserved);
    defer q.deinit();

    var sub: JRPCHandler = undefined;
    try q.addSubscriber(&sub);

    // idx1 reserved, idx2 reserved+ready (blocks commit of idx2 because idx1 is still reserved).
    const idx1 = try q.reserveUncommitted();
    _ = try reserveReady(&q, allocator, "will_be_evicted");

    // idx3 wraps to slot for idx1 (empty/reserved — no payload to free).
    // idx4 wraps to slot for idx2 (.ready — payload must be freed).
    _ = try q.reserveUncommitted();
    const idx4 = try q.reserveUncommitted();

    // idx1's slot is now idx3 (reserved), idx2's slot is now idx4 (reserved).
    // The .ready payload from idx2 was freed by releaseOccupiedSlot.
    try q.markReady(idx4, try allocPayload(allocator, "fresh"));

    q.cancelReservation(idx1);
    // idx3 is still reserved, so commit cannot pass it.
    try std.testing.expectEqual(0, q.commitReadyPrefix());
}

test "clampCommitFrontierToRetainedWindow advances empty committed set" {
    const allocator = std.testing.allocator;

    var q = try NotifQueue.init(allocator, 2, .reserved);
    defer q.deinit();

    var sub: JRPCHandler = undefined;
    try q.addSubscriber(&sub);

    // Reserve 3 slots without ever committing. next_reserve=4, head=0, tail=1.
    _ = try q.reserveUncommitted(); // idx1, slot 1
    const idx2 = try q.reserveUncommitted(); // idx2, slot 0 (wraps, idx1 was reserved)
    const idx3 = try q.reserveUncommitted(); // idx3, slot 1 (wraps, idx2 was reserved)

    // oldest = next_reserve - capacity = 4 - 2 = 2.
    // head + 1 = 1 < oldest = 2 → clamp triggers.
    // had_committed_before: tail(1) <= head(0) → false → else branch.
    q.cancelReservation(idx2);
    try q.markReady(idx3, try allocPayload(allocator, "3"));
    const committed = q.commitReadyPrefix();

    try std.testing.expectEqual(1, committed);
    try std.testing.expectEqual(idx3, q.head);
    try std.testing.expectEqual(idx3, q.tail);
}

test "refcount: early free on consumption" {
    const allocator = std.testing.allocator;

    var q = try NotifQueue.init(allocator, 8, .reserved);
    defer q.deinit();

    var sub: JRPCHandler = undefined;
    try q.addSubscriber(&sub);

    const idx = try reserveReady(&q, allocator, "msg");
    try std.testing.expectEqual(1, q.commitReadyPrefix());

    const got = try mustGet(&q, idx);
    defer got.deinit(allocator);

    const slot = q.slotFor(idx);
    try std.testing.expectEqual(q.head + 1, q.tail);
    try std.testing.expect(q.entries[slot].state == .empty);
    try std.testing.expectEqual(0, committedCount(&q));
}

test "refcount: partial consumption" {
    const allocator = std.testing.allocator;

    var q = try NotifQueue.init(allocator, 8, .reserved);
    defer q.deinit();

    var sub_a: JRPCHandler = undefined;
    var sub_b: JRPCHandler = undefined;
    try q.addSubscriber(&sub_a);
    try q.addSubscriber(&sub_b);

    const idx = try reserveReady(&q, allocator, "msg");
    try std.testing.expectEqual(1, q.commitReadyPrefix());

    const a_msg = try mustGet(&q, idx);
    defer a_msg.deinit(allocator);

    const slot = q.slotFor(idx);
    try std.testing.expectEqual(1, q.entries[slot].remaining);
    try std.testing.expect(q.entries[slot].state == .committed);

    const b_msg = try mustGet(&q, idx);
    defer b_msg.deinit(allocator);

    try std.testing.expect(q.entries[slot].state == .empty);
    try std.testing.expectEqual(0, committedCount(&q));
}

test "refcount: clone on read survives slot reuse" {
    const allocator = std.testing.allocator;

    var q = try NotifQueue.init(allocator, 2, .reserved);
    defer q.deinit();

    var sub: JRPCHandler = undefined;
    try q.addSubscriber(&sub);

    const idx1 = try reserveReady(&q, allocator, "keep");
    try std.testing.expectEqual(1, q.commitReadyPrefix());

    const held = try mustGet(&q, idx1);
    defer held.deinit(allocator);

    _ = try reserveReady(&q, allocator, "new1");
    try std.testing.expectEqual(1, q.commitReadyPrefix());

    _ = try reserveReady(&q, allocator, "new2");
    try std.testing.expectEqual(1, q.commitReadyPrefix());

    try std.testing.expectEqualStrings("keep", held.payload());
}

test "refcount: subscriber disconnect cleanup" {
    const allocator = std.testing.allocator;

    var q = try NotifQueue.init(allocator, 8, .reserved);
    defer q.deinit();

    var sub_a: JRPCHandler = undefined;
    var sub_b: JRPCHandler = undefined;
    try q.addSubscriber(&sub_a);
    try q.addSubscriber(&sub_b);

    const idx1 = try reserveReady(&q, allocator, "1");
    const idx2 = try reserveReady(&q, allocator, "2");
    const idx3 = try reserveReady(&q, allocator, "3");
    try std.testing.expectEqual(3, q.commitReadyPrefix());

    const a1 = try mustGet(&q, idx1);
    defer a1.deinit(allocator);
    const a2 = try mustGet(&q, idx2);
    defer a2.deinit(allocator);

    q.removeSubscriber(&sub_b, idx1);

    const slot1 = q.slotFor(idx1);
    const slot2 = q.slotFor(idx2);
    const slot3 = q.slotFor(idx3);

    try std.testing.expect(q.entries[slot1].state == .empty);
    try std.testing.expect(q.entries[slot2].state == .empty);
    try std.testing.expect(q.entries[slot3].state == .committed);
    try std.testing.expectEqual(1, q.entries[slot3].remaining);
}

test "remove last subscriber resets queued state" {
    const allocator = std.testing.allocator;

    var q = try NotifQueue.init(allocator, 8, .reserved);
    defer q.deinit();

    var sub: JRPCHandler = undefined;
    try q.addSubscriber(&sub);

    const idx1 = try reserveReady(&q, allocator, "committed");
    try std.testing.expectEqual(1, q.commitReadyPrefix());

    const idx2 = try q.reserveUncommitted();
    try q.markReady(idx2, try allocPayload(allocator, "ready"));
    const idx3 = try q.reserveUncommitted();

    q.removeSubscriber(&sub, idx1);

    try std.testing.expectEqual(0, q.subscriberCount());
    try std.testing.expectEqual(q.next_reserve - 1, q.head);
    try std.testing.expectEqual(q.head + 1, q.tail);
    try std.testing.expectEqual(0, committedCount(&q));

    const slot1 = q.slotFor(idx1);
    const slot2 = q.slotFor(idx2);
    const slot3 = q.slotFor(idx3);
    try std.testing.expect(q.entries[slot1].state == .empty);
    try std.testing.expect(q.entries[slot2].state == .empty);
    try std.testing.expect(q.entries[slot3].state == .empty);

    try std.testing.expectError(NotifQueue.GetError.IndexOverwritten, q.get(idx1));
    try std.testing.expectError(NotifQueue.GetError.IndexOverwritten, q.get(idx2));
    try std.testing.expectError(NotifQueue.GetError.IndexOverwritten, q.get(idx3));
}

test "refcount: subscriber join mid-stream" {
    const allocator = std.testing.allocator;

    var q = try NotifQueue.init(allocator, 8, .reserved);
    defer q.deinit();

    var sub_a: JRPCHandler = undefined;
    var sub_b: JRPCHandler = undefined;
    try q.addSubscriber(&sub_a);

    const idx1 = try reserveReady(&q, allocator, "before");
    try std.testing.expectEqual(1, q.commitReadyPrefix());

    const slot1 = q.slotFor(idx1);
    try std.testing.expectEqual(1, q.entries[slot1].remaining);

    try q.addSubscriber(&sub_b);
    try std.testing.expectEqual(1, q.entries[slot1].remaining);

    const idx2 = try reserveReady(&q, allocator, "after");
    try std.testing.expectEqual(1, q.commitReadyPrefix());

    const slot2 = q.slotFor(idx2);
    try std.testing.expectEqual(2, q.entries[slot2].remaining);
}

test "refcount: subscribers at different speeds" {
    const allocator = std.testing.allocator;

    var q = try NotifQueue.init(allocator, 8, .reserved);
    defer q.deinit();

    var fast: JRPCHandler = undefined;
    var slow: JRPCHandler = undefined;
    try q.addSubscriber(&fast);
    try q.addSubscriber(&slow);

    const idx1 = try reserveReady(&q, allocator, "1");
    const idx2 = try reserveReady(&q, allocator, "2");
    const idx3 = try reserveReady(&q, allocator, "3");
    try std.testing.expectEqual(3, q.commitReadyPrefix());

    const f1 = try mustGet(&q, idx1);
    defer f1.deinit(allocator);
    const f2 = try mustGet(&q, idx2);
    defer f2.deinit(allocator);

    const s1 = try mustGet(&q, idx1);
    defer s1.deinit(allocator);

    const slot1 = q.slotFor(idx1);
    const slot2 = q.slotFor(idx2);
    const slot3 = q.slotFor(idx3);

    try std.testing.expect(q.entries[slot1].state == .empty);
    try std.testing.expectEqual(1, q.entries[slot2].remaining);
    try std.testing.expectEqual(2, q.entries[slot3].remaining);
}

test "removeSubscriber with unknown pointer is a no-op" {
    const allocator = std.testing.allocator;

    var q = try NotifQueue.init(allocator, 8, .reserved);
    defer q.deinit();

    var sub: JRPCHandler = undefined;
    var unknown: JRPCHandler = undefined;
    try q.addSubscriber(&sub);

    const idx = try reserveReady(&q, allocator, "msg");
    try std.testing.expectEqual(1, q.commitReadyPrefix());

    q.removeSubscriber(&unknown, 1);

    try std.testing.expectEqual(1, q.subscriberCount());
    try std.testing.expectEqual(1, committedCount(&q));

    const got = try mustGet(&q, idx);
    defer got.deinit(allocator);
    try std.testing.expectEqualStrings("msg", got.payload());
}

test "removeSubscriber with next_index past head skips ref cleanup" {
    const allocator = std.testing.allocator;

    var q = try NotifQueue.init(allocator, 8, .reserved);
    defer q.deinit();

    var sub_a: JRPCHandler = undefined;
    var sub_b: JRPCHandler = undefined;
    try q.addSubscriber(&sub_a);
    try q.addSubscriber(&sub_b);

    const idx1 = try reserveReady(&q, allocator, "1");
    const idx2 = try reserveReady(&q, allocator, "2");
    try std.testing.expectEqual(2, q.commitReadyPrefix());

    // sub_b has already consumed everything; cursor is past head.
    q.removeSubscriber(&sub_b, q.head + 1);

    try std.testing.expectEqual(1, q.subscriberCount());

    // Entries still retain their original remaining count minus zero (no cleanup ran).
    const slot1 = q.slotFor(idx1);
    const slot2 = q.slotFor(idx2);
    try std.testing.expectEqual(2, q.entries[slot1].remaining);
    try std.testing.expectEqual(2, q.entries[slot2].remaining);
}

test "commitSerialized reserved path commits ready prefix" {
    const allocator = std.testing.allocator;

    var q = try NotifQueue.init(allocator, 8, .reserved);
    defer q.deinit();

    var sub: JRPCHandler = undefined;
    try q.addSubscriber(&sub);

    const idx1 = try q.reserveUncommitted();
    const idx2 = try q.reserveUncommitted();

    try std.testing.expectEqual(
        0,
        try q.commitSerialized(idx2, try allocPayload(allocator, "msg2"), false),
    );
    try std.testing.expectEqual(
        2,
        try q.commitSerialized(idx1, try allocPayload(allocator, "msg1"), false),
    );

    const m1 = try mustGet(&q, idx1);
    defer m1.deinit(allocator);
    try std.testing.expectEqualStrings("msg1", m1.payload());

    const m2 = try mustGet(&q, idx2);
    defer m2.deinit(allocator);
    try std.testing.expectEqualStrings("msg2", m2.payload());
}

test "commitSerialized direct path commits immediately" {
    const allocator = std.testing.allocator;

    var q = try NotifQueue.init(allocator, 8, .direct);
    defer q.deinit();

    var sub: JRPCHandler = undefined;
    try q.addSubscriber(&sub);

    try std.testing.expectEqual(
        1,
        try q.commitSerialized(null, try allocPayload(allocator, "direct"), false),
    );

    const got = try mustGet(&q, 1);
    defer got.deinit(allocator);
    try std.testing.expectEqualStrings("direct", got.payload());
}

test "commitSerialized preserves final metadata" {
    const allocator = std.testing.allocator;

    var q = try NotifQueue.init(allocator, 8, .reserved);
    defer q.deinit();

    var sub: JRPCHandler = undefined;
    try q.addSubscriber(&sub);

    const idx = try q.reserveFinalUncommitted();
    try std.testing.expectEqual(idx, q.finalNotificationIndex().?);
    try std.testing.expect(q.finalNotificationIndex() != null);
    try std.testing.expectEqual(
        1,
        try q.commitSerialized(idx, try allocPayload(allocator, "final"), true),
    );

    const notif = try mustGetNotif(&q, idx);
    defer notif.payload.deinit(allocator);
    try std.testing.expect(notif.is_final);
    try std.testing.expectEqualStrings("final", notif.payload.payload());
}

test "final committed entries stay retained for late readers" {
    const allocator = std.testing.allocator;

    var q = try NotifQueue.init(allocator, 8, .reserved);
    defer q.deinit();

    var sub_a: JRPCHandler = undefined;
    try q.addSubscriber(&sub_a);

    const idx = try q.reserveFinalUncommitted();
    try std.testing.expectEqual(
        1,
        try q.commitSerialized(idx, try allocPayload(allocator, "final"), true),
    );

    const notif_a = try mustGetNotif(&q, idx);
    defer notif_a.payload.deinit(allocator);
    try std.testing.expect(notif_a.is_final);
    try std.testing.expectEqual(idx, q.tail);
    try std.testing.expectEqual(idx, q.head);

    const notif_b = try mustGetNotif(&q, idx);
    defer notif_b.payload.deinit(allocator);
    try std.testing.expect(notif_b.is_final);
    try std.testing.expectEqualStrings("final", notif_b.payload.payload());
    try std.testing.expectEqual(idx, q.tail);
}

test "final reservations reject later enqueue attempts" {
    const allocator = std.testing.allocator;

    var q = try NotifQueue.init(allocator, 8, .reserved);
    defer q.deinit();

    var sub: JRPCHandler = undefined;
    try q.addSubscriber(&sub);

    const idx = try q.reserveFinalUncommitted();
    try std.testing.expectEqual(idx, q.finalNotificationIndex().?);
    try std.testing.expectError(error.FinalNotificationExists, q.reserveUncommitted());
    q.cancelReservation(idx);
    try std.testing.expectEqual(@as(?u64, null), q.finalNotificationIndex());

    _ = try q.reserveUncommitted();
}

test "remove last subscriber clears final state" {
    const allocator = std.testing.allocator;

    var q = try NotifQueue.init(allocator, 8, .reserved);
    defer q.deinit();

    var sub: JRPCHandler = undefined;
    try q.addSubscriber(&sub);

    const idx = try q.reserveFinalUncommitted();
    try std.testing.expect(q.finalNotificationIndex() != null);

    q.removeSubscriber(&sub, idx);

    try std.testing.expectEqual(0, q.subscriberCount());
    try std.testing.expectEqual(@as(?u64, null), q.finalNotificationIndex());
}

test "commitSerialized direct path drops payload when no subscribers" {
    const allocator = std.testing.allocator;

    var q = try NotifQueue.init(allocator, 8, .direct);
    defer q.deinit();

    try std.testing.expectEqual(
        0,
        try q.commitSerialized(null, try allocPayload(allocator, "drop"), false),
    );
    try std.testing.expectEqual(0, committedCount(&q));
}

test "commitSerialized reserved path drops payload when no subscribers" {
    const allocator = std.testing.allocator;

    var q = try NotifQueue.init(allocator, 8, .reserved);
    defer q.deinit();

    const idx = try q.reserveUncommitted();
    try std.testing.expectEqual(
        0,
        try q.commitSerialized(idx, try allocPayload(allocator, "drop"), false),
    );
    try std.testing.expectEqual(0, committedCount(&q));
}

test "appendCommitted multiple appends" {
    const allocator = std.testing.allocator;

    var q = try NotifQueue.init(allocator, 8, .direct);
    defer q.deinit();

    var sub: JRPCHandler = undefined;
    try q.addSubscriber(&sub);

    try q.appendCommitted(try allocPayload(allocator, "a"), false);
    try q.appendCommitted(try allocPayload(allocator, "b"), false);
    try q.appendCommitted(try allocPayload(allocator, "c"), false);

    try std.testing.expectEqual(3, q.head);
    try std.testing.expectEqual(3, committedCount(&q));

    const m1 = try mustGet(&q, 1);
    defer m1.deinit(allocator);
    try std.testing.expectEqualStrings("a", m1.payload());

    const m2 = try mustGet(&q, 2);
    defer m2.deinit(allocator);
    try std.testing.expectEqualStrings("b", m2.payload());

    const m3 = try mustGet(&q, 3);
    defer m3.deinit(allocator);
    try std.testing.expectEqualStrings("c", m3.payload());
}

test "appendCommitted ring wrap with overwrite" {
    const allocator = std.testing.allocator;

    var q = try NotifQueue.init(allocator, 2, .direct);
    defer q.deinit();

    var sub: JRPCHandler = undefined;
    try q.addSubscriber(&sub);

    try q.appendCommitted(try allocPayload(allocator, "first"), false);
    try q.appendCommitted(try allocPayload(allocator, "second"), false);

    // Both consumed so refs drop.
    const m1 = try mustGet(&q, 1);
    defer m1.deinit(allocator);
    const m2 = try mustGet(&q, 2);
    defer m2.deinit(allocator);

    // Third wraps around, overwriting slot for index 1.
    try q.appendCommitted(try allocPayload(allocator, "third"), false);

    try std.testing.expectEqual(3, q.head);
    try std.testing.expectError(NotifQueue.GetError.IndexOverwritten, q.get(1));

    const m3 = try mustGet(&q, 3);
    defer m3.deinit(allocator);
    try std.testing.expectEqualStrings("third", m3.payload());
}

test "appendCommitted subscriber lag recovery" {
    const allocator = std.testing.allocator;

    var q = try NotifQueue.init(allocator, 2, .direct);
    defer q.deinit();

    var sub: JRPCHandler = undefined;
    try q.addSubscriber(&sub);

    // Fill and don't consume — subscriber is lagging.
    try q.appendCommitted(try allocPayload(allocator, "old1"), false);
    try q.appendCommitted(try allocPayload(allocator, "old2"), false);

    // Wrap around: overwrites old committed entries.
    try q.appendCommitted(try allocPayload(allocator, "new1"), false);
    try q.appendCommitted(try allocPayload(allocator, "new2"), false);

    try std.testing.expectEqual(4, q.head);

    // Old entries are gone.
    try std.testing.expectError(NotifQueue.GetError.IndexOverwritten, q.get(1));
    try std.testing.expectError(NotifQueue.GetError.IndexOverwritten, q.get(2));

    // New entries are available.
    const m3 = try mustGet(&q, 3);
    defer m3.deinit(allocator);
    try std.testing.expectEqualStrings("new1", m3.payload());

    const m4 = try mustGet(&q, 4);
    defer m4.deinit(allocator);
    try std.testing.expectEqualStrings("new2", m4.payload());
}
