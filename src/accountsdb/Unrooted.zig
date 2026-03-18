//! A database which stores unrooted account modifications.
//!
//! Design notes:
//! - This design assumes that the slots provided are never more than
//! 4096 apart from each other.
//!

const std = @import("std");
const tracy = @import("tracy");
const sig = @import("../sig.zig");

const Atomic = std.atomic.Value;

const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const Ancestors = sig.core.Ancestors;
const Account = sig.core.Account;
const AccountSharedData = sig.runtime.AccountSharedData;
const PubkeyMap = sig.utils.collections.PubkeyMap;
const ids = sig.runtime.ids;

pub const MAX_SLOTS = 4096;

const Unrooted = @This();

slots: []SlotIndex,

pub const SlotIndex = struct {
    // TODO: it's possible for us to pre-populate a SlotIndex with pubkeys (and null values) in
    // advance of replaying the slot, which would let us drop this mutex entirely.
    lock: sig.sync.RwLock,
    slot: Slot,
    is_empty: Atomic(bool),
    entries: PubkeyMap(AccountSharedData),

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
    const zone = tracy.Zone.init(@src(), .{ .name = "Unrooted.put" });
    defer zone.deinit();

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

/// Like `get`, but returns an account with caller-owned data (allocates and
/// copies out the account).
///
/// Uses a two-phase approach to avoid cloning on every candidate slot:
/// 1. Scan all indices to find the best (highest) slot containing the address.
/// 2. Re-lock the winning index and clone once.
///
/// If the winning index was modified between phases (e.g. pruned by
/// `onSlotRooted`), the scan is retried. Retries are bounded to avoid
/// unbounded looping. If exhausted, returns `error.RetryLimitExceeded`
/// because the account exists but could not be read.
pub fn getOwned(
    self: *Unrooted,
    allocator: std.mem.Allocator,
    address: Pubkey,
    ancestors: *const Ancestors,
) error{ OutOfMemory, UnrootedGetOwnedMaxRetries }!?Account {
    const zone = tracy.Zone.init(@src(), .{ .name = "Unrooted.getOwned" });
    defer zone.deinit();

    var retries: u32 = 0;
    defer zone.value(retries);

    for (0..10) |_| {
        var best_slot: Slot = 0;
        var best_index: ?*SlotIndex = null;

        // Scan to find which index has the best slot (same as get()).
        for (self.slots) |*index| {
            if (index.is_empty.load(.acquire)) continue;

            index.lock.lockShared();
            defer index.lock.unlockShared();

            if (index.slot >= best_slot and ancestors.containsSlot(index.slot)) {
                if (index.entries.contains(address)) {
                    best_index = index;
                    best_slot = index.slot;
                }
            }
        }

        // re-lock the winner and clone.
        const index = best_index orelse return null;
        index.lock.lockShared();
        defer index.lock.unlockShared();

        // If the slot was pruned/reused between phases, retry the scan.
        if (index.is_empty.load(.acquire) or index.slot != best_slot) {
            retries += 1;
            continue;
        }
        const data = index.entries.get(address) orelse {
            retries += 1;
            continue;
        };
        return (try data.clone(allocator)).toOwnedAccount();
    }

    // Exhausted retries, slot keeps getting pruned/reused underneath us.
    // Returning null would incorrectly indicate the account doesn't exist.
    return error.UnrootedGetOwnedMaxRetries;
}

/// Gets the latest state of the account keyed by `address` visible to the given ancestor set.
pub fn get(
    self: *Unrooted,
    address: Pubkey,
    ancestors: *const Ancestors,
) ?Account {
    const zone = tracy.Zone.init(@src(), .{ .name = "Unrooted.get" });
    defer zone.deinit();

    var n_gets: u32 = 0;
    defer zone.value(n_gets);

    var best_slot: Slot = 0;
    var result: ?Account = null;

    for (self.slots) |*index| {
        if (index.is_empty.load(.acquire)) continue;

        index.lock.lockShared();
        defer index.lock.unlockShared();

        if (index.slot >= best_slot and ancestors.containsSlot(index.slot)) {
            n_gets += 1;
            const data = index.entries.get(address) orelse continue;
            result = data.asAccount();
            best_slot = index.slot;
        }
    }

    return result;
}

pub const OwnerEntry = struct { Slot, Account };

/// Returns a map of accounts owned by `owner` visible to the given ancestor set.
/// Account data is cloned so the caller owns all returned data and is responsible
/// for deallocating  when done.
pub fn getByOwnerOwned(
    self: *Unrooted,
    allocator: std.mem.Allocator,
    owner: Pubkey,
    ancestors: *const Ancestors,
) !PubkeyMap(OwnerEntry) {
    var map: PubkeyMap(OwnerEntry) = .empty;
    errdefer {
        for (map.values()) |*entry| entry[1].deinit(allocator);
        map.deinit(allocator);
    }

    for (self.slots) |*index| {
        if (index.is_empty.load(.acquire)) continue;
        if (!ancestors.containsSlot(index.slot)) continue;

        index.lock.lockShared();
        defer index.lock.unlockShared();

        for (index.entries.values(), index.entries.keys()) |*acc, pk| {
            if (!acc.owner.equals(&owner)) continue;
            if (acc.lamports == 0) continue;

            // Same pubkey can appear in multiple unrooted slots; keep only the latest (highest slot).
            const gop = try map.getOrPut(allocator, pk);
            if (gop.found_existing and index.slot <= gop.value_ptr[0]) continue;
            if (gop.found_existing) gop.value_ptr[1].deinit(allocator);

            const cloned = try acc.asAccount().cloneOwned(allocator);
            gop.value_ptr.* = .{ index.slot, cloned };
        }
    }

    return map;
}

/// Returns a map of SPL token accounts where the token-level owner (data bytes 32..64)
/// matches `token_owner`, visible to the given ancestor set. Only considers accounts
/// owned by the SPL Token or Token-2022 programs with sufficient data length.
/// Account data is cloned; the caller owns all returned data.
pub fn getBySplTokenOwner(
    self: *Unrooted,
    allocator: std.mem.Allocator,
    token_owner: Pubkey,
    ancestors: *const Ancestors,
) !PubkeyMap(OwnerEntry) {
    var map: PubkeyMap(OwnerEntry) = .empty;
    errdefer {
        for (map.values()) |*entry| entry[1].deinit(allocator);
        map.deinit(allocator);
    }

    for (self.slots) |*index| {
        if (index.is_empty.load(.acquire)) continue;
        if (!ancestors.containsSlot(index.slot)) continue;

        index.lock.lockShared();
        defer index.lock.unlockShared();

        for (index.entries.values(), index.entries.keys()) |*acc, pk| {
            if (acc.lamports == 0) continue;
            if (!acc.owner.equals(&ids.TOKEN_PROGRAM_ID) and
                !acc.owner.equals(&ids.TOKEN_2022_PROGRAM_ID)) continue;
            if (acc.data.len < 64) continue;
            if (!std.mem.eql(u8, acc.data[32..64], &token_owner.data)) continue;

            const gop = try map.getOrPut(allocator, pk);
            if (gop.found_existing and index.slot <= gop.value_ptr[0]) continue;
            if (gop.found_existing) gop.value_ptr[1].deinit(allocator);

            const cloned = try acc.asAccount().cloneOwned(allocator);
            gop.value_ptr.* = .{ index.slot, cloned };
        }
    }

    return map;
}

/// Returns a map of SPL token accounts where the token-level owner (data bytes 32..64)
/// matches `token_owner`, visible to the given ancestor set. Only considers accounts
/// owned by the SPL Token or Token-2022 programs with sufficient data length.
/// Account data is cloned; the caller owns all returned data.
pub fn getBySplTokenOwner(
    self: *Unrooted,
    allocator: std.mem.Allocator,
    token_owner: Pubkey,
    ancestors: *const Ancestors,
) !PubkeyMap(OwnerEntry) {
    var map: PubkeyMap(OwnerEntry) = .empty;
    errdefer {
        for (map.values()) |*entry| entry[1].deinit(allocator);
        map.deinit(allocator);
    }

    for (self.slots) |*index| {
        if (index.is_empty.load(.acquire)) continue;
        if (!ancestors.containsSlot(index.slot)) continue;

        index.lock.lockShared();
        defer index.lock.unlockShared();

        for (index.entries.values(), index.entries.keys()) |*acc, pk| {
            if (acc.lamports == 0) continue;
            if (!acc.owner.equals(&ids.TOKEN_PROGRAM_ID) and
                !acc.owner.equals(&ids.TOKEN_2022_PROGRAM_ID)) continue;
            if (acc.data.len < 64) continue;
            if (!std.mem.eql(u8, acc.data[32..64], &token_owner.data)) continue;

            const gop = try map.getOrPut(allocator, pk);
            if (gop.found_existing and index.slot <= gop.value_ptr[0]) continue;
            if (gop.found_existing) gop.value_ptr[1].deinit(allocator);

            const cloned = try acc.clone(allocator);
            gop.value_ptr.* = .{
                index.slot,
                .{
                    .lamports = cloned.lamports,
                    .data = .{ .owned_allocation = cloned.data },
                    .owner = cloned.owner,
                    .executable = cloned.executable,
                    .rent_epoch = cloned.rent_epoch,
                },
            };
        }
    }

    return map;
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
    const result_owned = (try db.getOwned(allocator, account_a, &ancestors)).?;
    try std.testing.expectEqual(result.lamports, 250_000); // should return slot 3
    try std.testing.expectEqual(result_owned.lamports, 250_000); // should return slot 3
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
    const result_owned = (try db.getOwned(allocator, account_a, &ancestors)).?;
    try std.testing.expectEqual(result.lamports, 750_000);
    try std.testing.expectEqual(result_owned.lamports, 750_000);
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
    const result_owned = try db.getOwned(
        allocator,
        account_a,
        &ancestors,
    );
    try std.testing.expectEqual(result, null);
    try std.testing.expectEqual(result_owned, null);
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
        const result_a_owned = (try db.getOwned(
            allocator,
            account_a,
            &ancestors,
        )).?;
        try std.testing.expectEqual(result_a.lamports, 500_000);
        try std.testing.expectEqual(result_a_owned.lamports, 500_000);

        const result_b = db.get(account_b, &ancestors).?;
        const result_b_owned = (try db.getOwned(
            allocator,
            account_b,
            &ancestors,
        )).?;
        try std.testing.expectEqual(result_b.lamports, 2_000_000);
        try std.testing.expectEqual(result_b_owned.lamports, 2_000_000);

        const result_c = db.get(account_c, &ancestors).?;
        const result_c_owned = (try db.getOwned(
            allocator,
            account_c,
            &ancestors,
        )).?;
        try std.testing.expectEqual(result_c.lamports, 3_000_000);
        try std.testing.expectEqual(result_c_owned.lamports, 3_000_000);
    }
    {
        var ancestors: Ancestors = try .initWithSlots(allocator, &.{ 1, 2 });
        defer ancestors.deinit(allocator);

        const result_a = db.get(account_a, &ancestors).?;
        const result_a_owned = (try db.getOwned(
            allocator,
            account_a,
            &ancestors,
        )).?;
        try std.testing.expectEqual(result_a.lamports, 1_000_000);
        try std.testing.expectEqual(result_a_owned.lamports, 1_000_000);
    }
}
