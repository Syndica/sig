//! A database which stores unrooted account modifications.
//!
//! Design notes:
//! - This design assumes that the slots provided are never more than
//! 4096 apart from each other.
//!

const std = @import("std");
const sig = @import("../../sig.zig");

const Atomic = std.atomic.Value;

const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const Ancestors = sig.core.Ancestors;
const Account = sig.core.Account;
const AccountSharedData = sig.runtime.AccountSharedData;

pub const MAX_SLOTS = 4096;

const Unrooted = @This();

slots: []SlotIndex,

pub const SlotIndex = struct {
    // TODO: it's possible for us to pre-populate a SlotIndex with pubkeys (and null values) in
    // advance of replaying the slot, which would let us drop this mutex entirely.
    lock: std.Thread.RwLock,
    slot: Slot,
    is_empty: Atomic(bool),
    entries: sig.utils.collections.PubkeyMap(AccountSharedData),

    const empty: SlotIndex = .{
        .lock = .{},
        .entries = .empty,
        .is_empty = .init(true),
        .slot = 0,
    };
};

pub fn init(allocator: std.mem.Allocator) !Unrooted {
    const slots = try allocator.alloc(SlotIndex, MAX_SLOTS);
    errdefer allocator.free(slots);
    @memset(slots, .empty);

    return .{ .slots = slots };
}

pub fn deinit(self: *Unrooted, allocator: std.mem.Allocator) void {
    for (self.slots) |*slot| {
        for (slot.entries.values()) |*data| data.deinit(allocator);
        slot.entries.deinit(allocator);
    }
    allocator.free(self.slots);
}

/// - For each unique (`slot`, `address`) pair, there will only ever be one concurrent writer.
/// There can be multiple concurrent readers.
/// - For each unique `address`, there can be multiple concurrent writers, however each
/// one will have a different `slot`.
///
/// It is unlikely to have multiple writers on the same account for different slots,
/// as this only happens during concurrent forked execution.
pub fn put(
    self: *Unrooted,
    allocator: std.mem.Allocator,
    slot: Slot,
    address: Pubkey,
    data: AccountSharedData,
) !void {
    const index = slot % MAX_SLOTS;
    const entry = &self.slots[index];

    entry.lock.lock();
    defer entry.lock.unlock();

    if (entry.slot != slot) {
        // If consensus fails to root a slot after executing MAX_SLOTS - 1 other slots
        // this will panic. It should be reasonable to assume that doesn't happen in
        // a real-world situation.
        std.debug.assert(entry.is_empty.load(.acquire));
        entry.entries.clearRetainingCapacity();
        entry.slot = slot;
    }

    const gop = try entry.entries.getOrPut(allocator, address);
    if (gop.found_existing) gop.value_ptr.deinit(allocator);
    gop.value_ptr.* = data;
    entry.is_empty.store(false, .release);
}

/// Gets the latest state of the account keyed by `address` visible to the given ancestor set.
pub fn get(
    self: *Unrooted,
    address: Pubkey,
    ancestors: *const Ancestors,
) ?Account {
    var best_slot: Slot = 0;
    var result: ?Account = null;

    for (self.slots) |*index| {
        if (index.is_empty.load(.acquire)) continue;

        index.lock.lockShared();
        defer index.lock.unlockShared();

        if (index.slot >= best_slot and ancestors.containsSlot(index.slot)) {
            const data = index.entries.get(address) orelse continue;
            result = data.asAccount();
            best_slot = index.slot;
        }
    }

    return result;
}

test "sanity check" {
    const allocator = std.testing.allocator;
    var db: Unrooted = try .init(allocator);
    defer db.deinit(allocator);

    const account_a: Pubkey = .parse("GBuP6xK2zcUHbQuUWM4gbBjom46AomsG8JzSp1bzJyn8");
    const account_b: Pubkey = .parse("Fd7btgySsrjuo25CJCj7oE7VPMyezDhnx7pZkj2v69Nk");

    try db.put(
        allocator,
        1, // slot
        account_a, // address
        .{ // data
            .data = &.{},
            .executable = true,
            .lamports = 1_000_000,
            .owner = account_b,
            .rent_epoch = 30,
        },
    );

    try db.put(
        allocator,
        2, // slot
        account_a, // address
        .{ // data
            .data = &.{},
            .executable = true,
            .lamports = 500_000,
            .owner = account_b,
            .rent_epoch = 30,
        },
    );

    try db.put(
        allocator,
        3, // slot
        account_a, // address
        .{ // data
            .data = &.{},
            .executable = true,
            .lamports = 250_000,
            .owner = account_b,
            .rent_epoch = 30,
        },
    );

    var ancestors: Ancestors = try .initWithSlots(allocator, &.{ 1, 3 });
    defer ancestors.deinit(allocator);

    const result = db.get(account_a, &ancestors).?;
    try std.testing.expectEqual(result.lamports, 250_000); // should return slot 3
}

test "forked behaviour" {
    const allocator = std.testing.allocator;
    var db: Unrooted = try .init(allocator);
    defer db.deinit(allocator);

    const account_a: Pubkey = .parse("GBuP6xK2zcUHbQuUWM4gbBjom46AomsG8JzSp1bzJyn8");
    const account_b: Pubkey = .parse("Fd7btgySsrjuo25CJCj7oE7VPMyezDhnx7pZkj2v69Nk");

    // write a slot 1
    try db.put(
        allocator,
        1,
        account_a,
        .{
            .data = &.{},
            .executable = true,
            .lamports = 1_000_000,
            .owner = account_b,
            .rent_epoch = 30,
        },
    );

    try db.put(
        allocator,
        2,
        account_a,
        .{
            .data = &.{},
            .executable = true,
            .lamports = 500_000,
            .owner = account_b,
            .rent_epoch = 30,
        },
    );
    // allowed to write to same slot multiple times
    try db.put(
        allocator,
        2,
        account_a,
        .{
            .data = &.{},
            .executable = true,
            .lamports = 750_000,
            .owner = account_b,
            .rent_epoch = 30,
        },
    );

    var ancestors: Ancestors = try .initWithSlots(allocator, &.{ 1, 2 });
    defer ancestors.deinit(allocator);

    const result = db.get(account_a, &ancestors).?;
    try std.testing.expectEqual(result.lamports, 750_000);
}

test "account not in ancestor set" {
    const allocator = std.testing.allocator;
    var db: Unrooted = try .init(allocator);
    defer db.deinit(allocator);

    const account_a: Pubkey = .parse("GBuP6xK2zcUHbQuUWM4gbBjom46AomsG8JzSp1bzJyn8");
    const account_b: Pubkey = .parse("Fd7btgySsrjuo25CJCj7oE7VPMyezDhnx7pZkj2v69Nk");

    // Write to slot 5
    try db.put(
        allocator,
        5,
        account_a,
        .{
            .data = &.{},
            .executable = true,
            .lamports = 1_000_000,
            .owner = account_b,
            .rent_epoch = 30,
        },
    );

    var ancestors: Ancestors = try .initWithSlots(allocator, &.{ 1, 2, 3 });
    defer ancestors.deinit(allocator);

    const result = db.get(account_a, &ancestors);
    try std.testing.expectEqual(result, null);
}

test "multiple accounts across slots" {
    const allocator = std.testing.allocator;
    var db: Unrooted = try .init(allocator);
    defer db.deinit(allocator);

    const account_a: Pubkey = .parse("GBuP6xK2zcUHbQuUWM4gbBjom46AomsG8JzSp1bzJyn8");
    const account_b: Pubkey = .parse("Fd7btgySsrjuo25CJCj7oE7VPMyezDhnx7pZkj2v69Nk");
    const account_c: Pubkey = .parse("7EqfdGiB5UZgLWc1U9xYbKdy9Ky9NoYcMbEwUq9aAWR6");

    try db.put(
        allocator,
        1,
        account_a,
        .{
            .data = &.{},
            .executable = true,
            .lamports = 1_000_000,
            .owner = account_b,
            .rent_epoch = 30,
        },
    );

    try db.put(
        allocator,
        2,
        account_b,
        .{
            .data = &.{},
            .executable = false,
            .lamports = 2_000_000,
            .owner = account_c,
            .rent_epoch = 20,
        },
    );

    try db.put(
        allocator,
        3,
        account_a,
        .{
            .data = &.{},
            .executable = true,
            .lamports = 500_000,
            .owner = account_b,
            .rent_epoch = 30,
        },
    );

    try db.put(
        allocator,
        3,
        account_c,
        .{
            .data = &.{},
            .executable = false,
            .lamports = 3_000_000,
            .owner = account_b,
            .rent_epoch = 15,
        },
    );

    {
        var ancestors: Ancestors = try .initWithSlots(allocator, &.{ 1, 2, 3 });
        defer ancestors.deinit(allocator);

        const result_a = db.get(account_a, &ancestors).?;
        try std.testing.expectEqual(result_a.lamports, 500_000);

        const result_b = db.get(account_b, &ancestors).?;
        try std.testing.expectEqual(result_b.lamports, 2_000_000);

        const result_c = db.get(account_c, &ancestors).?;
        try std.testing.expectEqual(result_c.lamports, 3_000_000);
    }
    {
        var ancestors: Ancestors = try .initWithSlots(allocator, &.{ 1, 2 });
        defer ancestors.deinit(allocator);

        const result_a = db.get(account_a, &ancestors).?;
        try std.testing.expectEqual(result_a.lamports, 1_000_000);
    }
}
