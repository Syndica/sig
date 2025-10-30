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
    lock: std.Thread.RwLock,
    slot: Slot,
    entries: std.AutoArrayHashMapUnmanaged(Pubkey, AccountSharedData),

    const empty: SlotIndex = .{
        .lock = .{},
        .entries = .empty,
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
    for (self.slots) |*slot| slot.entries.deinit(allocator);
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
        entry.entries.clearRetainingCapacity();
        entry.slot = slot;
    }

    try entry.entries.put(allocator, address, data);
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
        index.lock.lockShared();
        defer index.lock.unlockShared();

        if (ancestors.containsSlot(index.slot)) {
            if (index.slot < best_slot) continue;
            const data = index.entries.get(address) orelse continue;
            result = data.asAccount();
            best_slot = index.slot;
        }
    }

    return result;
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

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
    std.debug.print("result: {d}\n", .{result.lamports});
}
