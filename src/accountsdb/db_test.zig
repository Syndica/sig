//! includes the main database struct `AccountsDB`

const std = @import("std");
const sig = @import("../sig.zig");
const builtin = @import("builtin");

const AccountsDb = sig.accounts_db.AccountsDB;

const Account = sig.core.Account;
const Ancestors = sig.core.Ancestors;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;

const AccountSharedData = sig.runtime.AccountSharedData;

const TestAccountsDb = struct {
    accounts: std.AutoArrayHashMapUnmanaged(Pubkey, std.ArrayListUnmanaged(Entry)),

    pub const Entry = struct {
        slot: Slot,
        account: AccountSharedData,

        pub fn sortCmp(_: void, a: Entry, b: Entry) bool {
            return b.slot < a.slot;
        }

        pub fn searchCmp(key: Slot, mid_item: Entry) std.math.Order {
            return std.math.order(mid_item.slot, key);
        }
    };

    pub fn init() !TestAccountsDb {
        return .{ .accounts = .{} };
    }

    pub fn deinit(self: TestAccountsDb, allocator: std.mem.Allocator) void {
        for (self.accounts.values()) |*entries| {
            for (entries.items) |entry| allocator.free(entry.account.data);
            entries.deinit(allocator);
        }
        var accounts = self.accounts;
        accounts.deinit(allocator);
    }

    pub fn putAccount(self: *TestAccountsDb, allocator: std.mem.Allocator, slot: Slot, pubkey: Pubkey, account: AccountSharedData) !void {
        if (self.accounts.getPtr(pubkey)) |entries| {
            const index = std.sort.lowerBound(Entry, entries.items, slot, Entry.searchCmp);
            if (index < entries.items.len and entries.items[index].slot == slot) {
                allocator.free(entries.items[index].account.data);
                entries.items[index].account = account;
            } else {
                try entries.insert(allocator, index, .{ .slot = slot, .account = account });
            }
        } else {
            var entries = std.ArrayListUnmanaged(Entry){};
            try entries.append(allocator, .{ .slot = slot, .account = account });
            try self.accounts.put(allocator, pubkey, entries);
        }
    }

    pub fn getAccount(self: *const TestAccountsDb, pubkey: Pubkey, ancestors: *const Ancestors) ?AccountSharedData {
        if (self.accounts.get(pubkey)) |entries|
            for (entries.items) |entry| if (ancestors.containsSlot(entry.slot)) return entry.account;
        return null;
    }

    pub fn getAccountSlots(self: *const TestAccountsDb, allocator: std.mem.Allocator, pubkey: Pubkey) ![]const Slot {
        if (self.accounts.get(pubkey)) |entries| {
            var slots = try allocator.alloc(Slot, entries.items.len);
            for (entries.items, 0..) |entry, i| slots[i] = entry.slot;
            return slots;
        }
        return &.{};
    }
};

pub const TestDbOptions = struct {
    require_sequential_slot_inserts: bool,
};

pub fn testDb(options: TestDbOptions) !void {
    const allocator = std.heap.c_allocator;
    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    var db, var tmp_dir = try AccountsDb.initForTest(allocator);
    defer tmp_dir.cleanup();
    defer db.deinit();

    var test_db = try TestAccountsDb.init();
    defer test_db.deinit(allocator);

    // Testing Accounts Db
    //   - Insertion
    //      - accounts can be inserted for any slot greater than last rooted slot
    //      - account insertion at a slot less than or equal to last rooted slot returns an error
    //      - accounts can be inserted for slots out of sequence. i.e 3, 5, 1, 4, 2 is a valid insertion order
    //   - Deletion
    //      - accounts with zero lamports are treated as 'deleted' accounts
    //      - accounts with zero lamports are removed from rooted storage on cleanup
    //      - accounts with zero lamports are not removed from unrooted storage on cleanup
    //      - Example:
    //        - fork 1: {1}
    //        - fork 2: {2, 1}
    //        - fork 3: {3, 1}
    //        - unrooted:
    //           - account @ slot 3, lamports 0
    //           - account @ slot 2, lamports 1
    //        - rooted:
    //           - account @ slot 0, lamports 0
    //        - getAccountWithAncestors(account, fork_1) => null
    //        - getAccountWithAncestors(account, fork_2) => account @ slot 2, lamports 1
    //        - getAccountWithAncestors(account, fork_3) => null
    //   - Forking
    //      - return the correct account version across competing forks
    //      - return the rooted account if there is no unrooted account in ancestors
    //      - Example:
    //        - fork 1: {1}
    //        - fork 2: {2, 1}
    //        - fork 3: {3, 1}
    //        - rooted:
    //           - account @ slot 0
    //        - unrooted:
    //           - account @ slot 3
    //           - account @ slot 2
    //        - getAccountWithAncestors(account, fork_1) => account @ slot 0
    //        - getAccountWithAncestors(account, fork_2) => account @ slot 2
    //        - getAccountWithAncestors(account, fork_3) => account @ slot 3
    //
    // NOTE: to check for data corruption lets always insert new random account data for a given pubkey

    // Insert a bunch of accounts
    for (0..1000) |_| {
        const pubkey = Pubkey.initRandom(random);
        const account = try createRandomAccount(allocator, random);
        defer allocator.free(account.data);
        for (1..random.intRangeAtMost(usize, 2, 5)) |i| {
            const slots = try test_db.getAccountSlots(allocator, pubkey);
            defer allocator.free(slots);
            const slot = if (options.require_sequential_slot_inserts) i else random.intRangeAtMost(usize, 0, 10);
            try db.putAccount(slot, pubkey, account);
            try test_db.putAccount(allocator, slot, pubkey, try account.clone(allocator));
        }
    }

    // Check that the test database matches the original database
    for (test_db.accounts.keys()) |pubkey| {
        const slots = try test_db.getAccountSlots(allocator, pubkey);
        defer allocator.free(slots);

        for (slots) |slot| {
            var ancestors = Ancestors{};
            defer ancestors.deinit(allocator);
            try ancestors.addSlot(allocator, slot);

            const expected_account = test_db.getAccount(pubkey, &ancestors).?;
            const actual_account = (try db.getAccountWithAncestors(&pubkey, &ancestors)).?;

            try expectedAccountSharedDataEqualsAccount(expected_account, actual_account, false);
        }
    }
}

fn createRandomAccount(
    allocator: std.mem.Allocator,
    random: std.Random,
) !sig.runtime.AccountSharedData {
    if (!builtin.is_test) @compileError("only for testing");

    const data_size = random.uintAtMost(u64, 1_024);
    const data = try allocator.alloc(u8, data_size);
    random.bytes(data);

    return .{
        .lamports = random.uintAtMost(u64, 1_000_000),
        .data = data,
        .owner = Pubkey.initRandom(random),
        .executable = random.boolean(),
        .rent_epoch = random.uintAtMost(u64, 1_000_000),
    };
}

fn expectedAccountSharedDataEqualsAccount(
    expected: sig.runtime.AccountSharedData,
    account: Account,
    print_instead_of_expect: bool,
) !void {
    if (!builtin.is_test) @compileError("only for testing");

    if (print_instead_of_expect) {
        std.debug.print("expected: {any}\n", .{expected});
        std.debug.print("actual:   {any}\n\n", .{account});
    } else {
        // we know where this data came from (not from the disk), so we can take its slice directly
        std.debug.assert(account.data == .owned_allocation);

        try std.testing.expectEqual(expected.lamports, account.lamports);
        try std.testing.expectEqualSlices(u8, expected.data, account.data.owned_allocation);
        try std.testing.expectEqualSlices(u8, &expected.owner.data, &account.owner.data);
        try std.testing.expectEqual(expected.executable, account.executable);
        try std.testing.expectEqual(expected.rent_epoch, account.rent_epoch);
    }
}

test "testDb" {
    try testDb(.{ .require_sequential_slot_inserts = false });
    try testDb(.{ .require_sequential_slot_inserts = true });
}
