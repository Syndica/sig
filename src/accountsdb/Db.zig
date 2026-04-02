//! Thin wrapper around Rooted and Unrooted that ties everything together to be used by the account store.

const std = @import("std");
const sig = @import("../sig.zig");
pub const Rooted = @import("Rooted.zig");
pub const Unrooted = @import("Unrooted.zig");

const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const Ancestors = sig.core.Ancestors;
const Account = sig.core.Account;
const AccountSharedData = sig.runtime.AccountSharedData;
const PubkeyMap = sig.utils.collections.PubkeyMap;

const Db = @This();

allocator: std.mem.Allocator,
rooted: Rooted,
unrooted: Unrooted,

pub fn init(allocator: std.mem.Allocator, rooted: Rooted) !Db {
    var unrooted: Unrooted = try .init(allocator);
    errdefer unrooted.deinit(allocator);

    return .{
        .allocator = allocator,
        .rooted = rooted,
        .unrooted = unrooted,
    };
}

pub const TestContext = struct {
    db: Db,
    tmp: std.testing.TmpDir,

    pub fn deinit(self: *TestContext) void {
        Rooted.deinitThreadLocals();
        self.db.deinit();
        self.tmp.cleanup();
    }
};

/// Initializes a temporary empty rooted storage. Call tmp.cleanup() when done with it.
pub fn initTest(allocator: std.mem.Allocator) !TestContext {
    const tmp = std.testing.tmpDir(.{});
    var tmp_dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const tmp_path = try tmp.dir.realpath(".", &tmp_dir_buffer);

    var buffer: [std.fs.max_path_bytes + 1]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&buffer, "{s}/accounts.db", .{tmp_path});

    var rooted: Rooted = try .init(path, false, false);
    errdefer rooted.deinit();

    const db: @This() = try .init(allocator, rooted);
    return .{ .db = db, .tmp = tmp };
}

pub fn deinit(self: *Db) void {
    const allocator = self.allocator;
    self.rooted.deinit();
    self.unrooted.deinit(allocator);
}

/// Clones the account shared data.
pub fn put(self: *Db, slot: Slot, address: Pubkey, data: AccountSharedData) !void {
    if (self.rooted.largest_rooted_slot) |lrs|
        if (lrs >= slot) return error.CannotWriteRootedSlot;

    const cloned = try data.clone(self.allocator);
    errdefer cloned.deinit(self.allocator);
    try self.unrooted.put(self.allocator, slot, address, cloned);
}

// TODO: this should be trivial to put on another thread; this currently blocks the main replay
// thread for 30-40ms per slot on testnet.
pub fn updateRoot(self: *Db, newly_rooted_slot: Slot, ancestors: *const Ancestors) void {
    self.rooted.beginTransaction();
    defer {
        self.rooted.commitTransaction();
        self.rooted.largest_rooted_slot = newly_rooted_slot;
    }

    // Ancestors are kept in a way where the "head" slot is stored.
    std.debug.assert(ancestors.containsSlot(newly_rooted_slot));
    // This assert is satifisied via the implementation of ancestors, however
    // we want to show that we'll never need to iterate over more than MAX_SLOTs cases.
    std.debug.assert(ancestors.ancestors.count() < Unrooted.MAX_SLOTS);

    const start_slot = if (self.rooted.largest_rooted_slot) |lrs| lrs + 1 else 0;
    const range = newly_rooted_slot - start_slot + 1;

    for (0..range) |i| {
        const slot = start_slot + i;
        const index = &self.unrooted.slots[slot % Unrooted.MAX_SLOTS];

        if (index.is_empty.load(.acquire)) continue;
        if (index.slot != slot) continue;

        index.lock.lock();
        defer index.lock.unlock();

        if (ancestors.containsSlot(index.slot)) {
            // TODO: batch put() into rooted
            var entries = index.entries.iterator();
            while (entries.next()) |entry| {
                self.rooted.put(entry.key_ptr.*, index.slot, entry.value_ptr.*);
            }
        }

        for (index.entries.values()) |data| data.deinit(self.allocator);
        index.entries.clearRetainingCapacity();
        index.is_empty.store(true, .release);
    }
}

pub fn get(
    self: *Db,
    allocator: std.mem.Allocator,
    address: Pubkey,
    ancestors: *const Ancestors,
) !?Account {
    // first try finding it in the unrooted storage
    if (self.unrooted.get(address, ancestors)) |data| {
        return data;
    }
    // then try finding it in the rooted storage
    if (try self.rooted.get(allocator, address)) |data| {
        return data.toOwnedAccount();
    }
    // doesn't exist
    return null;
}

/// Like `get`, but returns an account with caller-owned data (allocates and copies out the account from both Unrooted and Rooted lookups).
pub fn getOwned(
    self: *Db,
    allocator: std.mem.Allocator,
    address: Pubkey,
    ancestors: *const Ancestors,
) !?Account {
    if (try self.unrooted.getOwned(allocator, address, ancestors)) |data| {
        return data;
    }
    if (try self.rooted.get(allocator, address)) |data| {
        return data.toOwnedAccount();
    }
    return null;
}

/// Returns the top `limit` accounts by lamport balance (descending).
/// Snapshots the rooted tracker then applies unrooted overrides for
/// processed/confirmed commitment levels.
pub fn getLargest(
    self: *Db,
    allocator: std.mem.Allocator,
    ancestors: *const Ancestors,
    limit: u32,
) ![]const struct { Pubkey, u64 } {
    const Tracker = Rooted.LargestTracker;
    var buf: [Tracker.CAPACITY]Tracker.Entry = undefined;
    const len = self.rooted.largest_tracker.snapshot(&buf);

    // Override rooted balances with unrooted versions where they exist.
    for (buf[0..len]) |*entry| {
        if (self.unrooted.get(entry[0], ancestors)) |account| {
            entry[1] = account.lamports;
        }
    }

    // Sort descending by lamports.
    std.mem.sortUnstable(Tracker.Entry, buf[0..len], {}, struct {
        pub fn lessThan(_: void, a: Tracker.Entry, b: Tracker.Entry) bool {
            return a[1] > b[1];
        }
    }.lessThan);

    const result_len = @min(len, limit);
    const result = try allocator.alloc(Tracker.Entry, result_len);
    @memcpy(result, buf[0..result_len]);
    return result;
}

pub const SlotModifiedIterator = struct {
    slot: *Unrooted.SlotIndex,
    cursor: u64,

    pub fn unlock(self: *SlotModifiedIterator) void {
        self.cursor = std.math.maxInt(u64);
        self.slot.lock.unlockShared();
    }

    pub fn len(self: *SlotModifiedIterator) usize {
        return self.slot.entries.count();
    }

    pub fn next(
        self: *SlotModifiedIterator,
        allocator: std.mem.Allocator,
    ) !?struct { Pubkey, Account } {
        defer self.cursor += 1;
        if (self.cursor >= self.len()) return null;

        const pubkey = self.slot.entries.keys()[self.cursor];
        const acc = self.slot.entries.values()[self.cursor];

        var account = acc.asAccount();
        account.data = .{ .owned_allocation = try allocator.dupe(u8, acc.data) };

        return .{ pubkey, account };
    }
};

pub fn slotModifiedIterator(self: *Db, slot: Slot) ?SlotModifiedIterator {
    const index = slot % Unrooted.MAX_SLOTS;
    const entry = &self.unrooted.slots[index];
    if (entry.is_empty.load(.acquire)) return null;
    entry.lock.lockShared();
    return .{
        .slot = entry,
        .cursor = 0,
    };
}

pub const OwnerQuery = struct {
    rooted_iter: Rooted.OwnerIterator,
    unrooted_map: PubkeyMap(Unrooted.OwnerEntry),
    allocator: std.mem.Allocator,
    unrooted_index: usize = 0,

    pub fn next(self: *OwnerQuery) !?struct { Pubkey, Account } {
        // drain rooted iterator, replacing with unrooted where newer.
        while (self.rooted_iter.next()) |entry| {
            const pubkey, const account = entry;
            if (self.unrooted_map.fetchSwapRemove(pubkey)) |kv| {
                return .{ pubkey, kv.value[1] };
            }
            return .{ pubkey, account };
        }

        // remaining unrooted-only entries.
        const values = self.unrooted_map.values();
        const keys = self.unrooted_map.keys();
        while (self.unrooted_index < keys.len) {
            const pubkey = keys[self.unrooted_index];
            const account = values[self.unrooted_index][1];
            self.unrooted_index += 1;
            return .{ pubkey, account };
        }
        return null;
    }

    pub fn deinit(self: *OwnerQuery) void {
        self.rooted_iter.deinit();
        // Only free entries not yet yielded (some entries were already removed from the map via fetchSwapRemove).
        for (self.unrooted_map.values()[self.unrooted_index..]) |*entry|
            entry[1].deinit(self.allocator);
        self.unrooted_map.deinit(self.allocator);
    }
};

pub fn ownerQueryOwned(self: *Db, owner: *const Pubkey, ancestors: *const Ancestors) !OwnerQuery {
    var unrooted_map = try self.unrooted.getByOwnerOwned(
        self.allocator,
        owner.*,
        ancestors,
    );
    errdefer {
        for (unrooted_map.values()) |*entry| entry[1].deinit(self.allocator);
        unrooted_map.deinit(self.allocator);
    }

    const rooted_iter = self.rooted.getByOwner(owner);
    return .{
        .rooted_iter = rooted_iter,
        .unrooted_map = unrooted_map,
        .allocator = self.allocator,
    };
}

pub fn splTokenOwnerQuery(
    self: *Db,
    token_owner: *const Pubkey,
    ancestors: *const Ancestors,
) !OwnerQuery {
    var unrooted_map = try self.unrooted.getBySplTokenOwner(
        self.allocator,
        token_owner.*,
        ancestors,
    );
    errdefer {
        for (unrooted_map.values()) |*entry| entry[1].deinit(self.allocator);
        unrooted_map.deinit(self.allocator);
    }

    const rooted_iter = self.rooted.getBySplTokenOwner(token_owner);
    return .{
        .rooted_iter = rooted_iter,
        .unrooted_map = unrooted_map,
        .allocator = self.allocator,
    };
}

const testing = struct {
    fn convert(account: Account) AccountSharedData {
        return .{
            .data = account.data.owned_allocation,
            .executable = account.executable,
            .lamports = account.lamports,
            .owner = account.owner,
            .rent_epoch = account.rent_epoch,
        };
    }
};

test "many slots, many accounts" {
    const allocator = std.testing.allocator;

    var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const random = prng.random();

    var test_state = try Db.initTest(allocator);
    defer test_state.deinit();
    const db = &test_state.db;

    var ancestors: Ancestors = .EMPTY;
    defer ancestors.deinit(allocator);

    for (0..Unrooted.MAX_SLOTS * 2) |i| {
        defer if (i > 50) db.updateRoot(i, &ancestors); // start rooting after 50 slots

        const random_account = try Account.initRandom(allocator, random, 30);
        defer random_account.deinit(allocator);
        const random_pubkey = Pubkey.initRandom(random);

        try ancestors.addSlot(allocator, i);
        ancestors.cleanup();

        try db.put(i, random_pubkey, testing.convert(random_account));
    }
    // Ensure we end up with a clean slate, not leaking any entries.
    try ancestors.addSlot(allocator, Unrooted.MAX_SLOTS * 2);
    ancestors.cleanup();
    db.updateRoot(Unrooted.MAX_SLOTS * 2, &ancestors);
    for (db.unrooted.slots) |entry| {
        std.debug.assert(entry.is_empty.load(.acquire));
    }
}

test "many slots, same account" {
    const allocator = std.testing.allocator;

    var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const random = prng.random();

    var test_state = try Db.initTest(allocator);
    defer test_state.deinit();
    const db = &test_state.db;

    var ancestors: Ancestors = .EMPTY;
    defer ancestors.deinit(allocator);

    const random_pubkey = Pubkey.initRandom(random);
    for (0..Unrooted.MAX_SLOTS * 2) |i| {
        defer if (i % 64 == 0) db.updateRoot(i, &ancestors); // root every 64 slots

        const random_account = try Account.initRandom(allocator, random, 30);
        defer random_account.deinit(allocator);

        try ancestors.addSlot(allocator, i);
        ancestors.cleanup();

        try db.put(i, random_pubkey, testing.convert(random_account));
    }
    try ancestors.addSlot(allocator, Unrooted.MAX_SLOTS * 2);
    ancestors.cleanup();
    db.updateRoot(Unrooted.MAX_SLOTS * 2, &ancestors);
    for (db.unrooted.slots) |entry| {
        std.debug.assert(entry.is_empty.load(.acquire));
    }
}

test "rooting must handle wraparound and non-consecutive roots" {
    const allocator = std.testing.allocator;

    var test_state = try Db.initTest(allocator);
    defer test_state.deinit();
    const db = &test_state.db;

    var ancestors = Ancestors.EMPTY;
    defer ancestors.deinit(allocator);

    for (0..Unrooted.MAX_SLOTS * 2) |slot| {
        try ancestors.addSlot(allocator, slot);
        ancestors.cleanup();

        try db.put(slot, .ZEROES, .{
            .lamports = slot * 10,
            .data = &.{},
            .owner = .ZEROES,
            .executable = false,
            .rent_epoch = 0,
        });

        {
            const account = try db.get(allocator, .ZEROES, &ancestors);
            defer account.?.deinit(allocator);
            try std.testing.expectEqual(slot * 10, account.?.lamports);
        }

        if (slot % 2 == 0) {
            db.updateRoot(slot, &ancestors);
            const account = try db.get(allocator, .ZEROES, &ancestors);
            defer account.?.deinit(allocator);
            try std.testing.expectEqual(slot * 10, account.?.lamports);
        }
    }
}

test "accounts_db: owner query" {
    const allocator = std.testing.allocator;
    var test_state = try Db.initTest(allocator);
    defer test_state.deinit();
    const db = &test_state.db;
    const owner_x: Pubkey = .parse("GBuP6xK2zcUHbQuUWM4gbBjom46AomsG8JzSp1bzJyn8");
    const owner_y: Pubkey = .parse("Fd7btgySsrjuo25CJCj7oE7VPMyezDhnx7pZkj2v69Nk");
    const addr_a: Pubkey = .parse("7EqfdGiB5UZgLWc1U9xYbKdy9Ky9NoYcMbEwUq9aAWR6");
    const addr_b: Pubkey = .parse("9W959DqEETiGZocYWCQPaJ6sBmUzgfxXfqGeTEdp3aQP");
    const addr_c: Pubkey = .parse("HN7cABqLq46Es1jh92dQQisAq662SmxELLLsHHe4YWrH");
    var ancestors: Ancestors = .EMPTY;
    defer ancestors.deinit(allocator);

    // Slot 1, addr_a with owner_x (unrooted)
    try ancestors.addSlot(allocator, 1);
    ancestors.cleanup();
    try db.put(1, addr_a, .{
        .lamports = 100,
        .data = &.{},
        .owner = owner_x,
        .executable = false,
        .rent_epoch = 0,
    });

    // Slot 2, addr_b with owner_x and addr_c with owner_y (both get rooted)
    try ancestors.addSlot(allocator, 2);
    ancestors.cleanup();
    try db.put(2, addr_b, .{
        .lamports = 200,
        .data = &.{},
        .owner = owner_x,
        .executable = false,
        .rent_epoch = 0,
    });
    try db.put(2, addr_c, .{
        .lamports = 300,
        .data = &.{},
        .owner = owner_y,
        .executable = false,
        .rent_epoch = 0,
    });

    // Root slots 1 and 2
    db.updateRoot(2, &ancestors);

    // Slot 3, addr_a updated, still owned by owner_x (stays unrooted)
    try ancestors.addSlot(allocator, 3);
    ancestors.cleanup();
    try db.put(3, addr_a, .{
        .lamports = 150,
        .data = &.{},
        .owner = owner_x,
        .executable = false,
        .rent_epoch = 0,
    });

    // Query for owner_x
    {
        var query = try db.ownerQueryOwned(&owner_x, &ancestors);
        defer query.deinit();
        // The unified iterator should yield 3 accounts for owner_x:
        // - addr_a (resolved from unrooted, slot 3 version with lamports=150)
        // - addr_b (from rooted, lamports=200)
        // The rooted also has addr_a at lamports=100, but the iterator
        // deduplicates it in favor of the unrooted version.
        var count: usize = 0;
        var found_a = false;
        var found_b = false;
        while (try query.next()) |entry| {
            const pubkey, const account = entry;
            defer account.deinit(allocator);
            count += 1;
            if (pubkey.equals(&addr_a)) {
                try std.testing.expectEqual(150, account.lamports);
                found_a = true;
            } else if (pubkey.equals(&addr_b)) {
                try std.testing.expectEqual(200, account.lamports);
                found_b = true;
            } else {
                return error.UnexpectedAccount;
            }
        }
        try std.testing.expectEqual(2, count);
        try std.testing.expect(found_a);
        try std.testing.expect(found_b);
    }

    // Query for owner_y
    {
        var query = try db.ownerQueryOwned(&owner_y, &ancestors);
        defer query.deinit();
        // Should yield just addr_c (rooted, lamports=300)
        const entry = (try query.next()).?;
        const pubkey, const account = entry;
        defer account.deinit(allocator);
        try std.testing.expectEqual(300, account.lamports);
        try std.testing.expect(pubkey.equals(&addr_c));
        try std.testing.expectEqual(null, try query.next());
    }
}

test "accounts_db: spl token owner query" {
    const allocator = std.testing.allocator;

    const tmp = std.testing.tmpDir(.{});
    var tmp_dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const tmp_path = try tmp.dir.realpath(".", &tmp_dir_buffer);
    var path_buffer: [std.fs.max_path_bytes + 1]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&path_buffer, "{s}/accounts.db", .{tmp_path});

    const rooted: Rooted = try .init(path, false, true);
    var db: Db = try .init(allocator, rooted);
    defer {
        Rooted.deinitThreadLocals();
        db.deinit();
    }

    const token_owner_x: Pubkey = .parse("GBuP6xK2zcUHbQuUWM4gbBjom46AomsG8JzSp1bzJyn8");
    const token_owner_y: Pubkey = .parse("Fd7btgySsrjuo25CJCj7oE7VPMyezDhnx7pZkj2v69Nk");
    const addr_a: Pubkey = .parse("7EqfdGiB5UZgLWc1U9xYbKdy9Ky9NoYcMbEwUq9aAWR6");
    const addr_b: Pubkey = .parse("9W959DqEETiGZocYWCQPaJ6sBmUzgfxXfqGeTEdp3aQP");
    const addr_c: Pubkey = .parse("HN7cABqLq46Es1jh92dQQisAq662SmxELLLsHHe4YWrH");
    var ancestors: Ancestors = .EMPTY;
    defer ancestors.deinit(allocator);

    // Build fake SPL token account data (165 bytes, standard token account size).
    // Bytes 32..64 hold the token owner pubkey.
    const make_token_data = struct {
        fn f(token_owner: Pubkey) [165]u8 {
            var data: [165]u8 = .{0} ** 165;
            @memcpy(data[32..64], &token_owner.data);
            return data;
        }
    }.f;
    var data_x = make_token_data(token_owner_x);
    var data_y = make_token_data(token_owner_y);

    // Slot 1: addr_a with token_owner_x (unrooted)
    try ancestors.addSlot(allocator, 1);
    ancestors.cleanup();
    try db.put(1, addr_a, .{
        .lamports = 100,
        .data = &data_x,
        .owner = sig.runtime.ids.TOKEN_PROGRAM_ID,
        .executable = false,
        .rent_epoch = 0,
    });

    // Slot 2: addr_b with token_owner_x, addr_c with token_owner_y (both get rooted)
    try ancestors.addSlot(allocator, 2);
    ancestors.cleanup();
    try db.put(2, addr_b, .{
        .lamports = 200,
        .data = &data_x,
        .owner = sig.runtime.ids.TOKEN_PROGRAM_ID,
        .executable = false,
        .rent_epoch = 0,
    });
    try db.put(2, addr_c, .{
        .lamports = 300,
        .data = &data_y,
        .owner = sig.runtime.ids.TOKEN_2022_PROGRAM_ID,
        .executable = false,
        .rent_epoch = 0,
    });

    // Root slots 1 and 2
    db.updateRoot(2, &ancestors);

    // Slot 3: addr_a updated, still token_owner_x (stays unrooted)
    try ancestors.addSlot(allocator, 3);
    ancestors.cleanup();
    try db.put(3, addr_a, .{
        .lamports = 150,
        .data = &data_x,
        .owner = sig.runtime.ids.TOKEN_PROGRAM_ID,
        .executable = false,
        .rent_epoch = 0,
    });

    // Query for token_owner_x: expect addr_a (150, unrooted wins) and addr_b (200, rooted)
    {
        var query = try db.splTokenOwnerQuery(&token_owner_x, &ancestors);
        defer query.deinit();
        var count: usize = 0;
        var found_a = false;
        var found_b = false;
        while (try query.next()) |entry| {
            const pubkey, const account = entry;
            defer account.deinit(allocator);
            count += 1;
            if (pubkey.equals(&addr_a)) {
                try std.testing.expectEqual(150, account.lamports);
                found_a = true;
            } else if (pubkey.equals(&addr_b)) {
                try std.testing.expectEqual(200, account.lamports);
                found_b = true;
            } else {
                return error.UnexpectedAccount;
            }
        }
        try std.testing.expectEqual(2, count);
        try std.testing.expect(found_a);
        try std.testing.expect(found_b);
    }

    // Query for token_owner_y: expect only addr_c (300, rooted)
    {
        var query = try db.splTokenOwnerQuery(&token_owner_y, &ancestors);
        defer query.deinit();
        const entry = (try query.next()).?;
        const pubkey, const account = entry;
        defer account.deinit(allocator);
        try std.testing.expectEqual(300, account.lamports);
        try std.testing.expect(pubkey.equals(&addr_c));
        try std.testing.expectEqual(null, try query.next());
    }
}
