//! Thin wrapper around Rooted and Unrooted that ties everything together to be used by the account store.

const std = @import("std");
const builtin = @import("builtin");
const sig = @import("../../sig.zig");
pub const Rooted = @import("Rooted.zig");
pub const Unrooted = @import("Unrooted.zig");

const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const Ancestors = sig.core.Ancestors;
const Account = sig.core.Account;
const AccountSharedData = sig.runtime.AccountSharedData;

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
    if (!builtin.is_test) @compileError("only used in tests");

    const tmp = std.testing.tmpDir(.{});
    var tmp_dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const tmp_path = try tmp.dir.realpath(".", &tmp_dir_buffer);

    var buffer: [std.fs.max_path_bytes + 1]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&buffer, "{s}/accounts.db", .{tmp_path});

    var rooted: Rooted = try .init(path);
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
pub fn onSlotRooted(self: *Db, newly_rooted_slot: Slot) void {
    // The previous slot we rooted (or 0, if we haven't rooted one).
    const old_rooted_slot = self.rooted.largest_rooted_slot orelse 0;
    // Seperate condition to the one above, since we only want to assert this after the first slot rooted.
    if (self.rooted.largest_rooted_slot) |slot| std.debug.assert(newly_rooted_slot >= slot);

    for (self.unrooted.slots) |*index| {
        if (index.is_empty.load(.acquire)) continue;
        if (index.slot > newly_rooted_slot) continue; // not ready to be rooted yet!

        // If this is the precise slot that we're rooting, then we can move it to the permanent storage.
        if (index.slot == newly_rooted_slot) {
            // Get read lock on unrooted slot, commit to db
            index.lock.lockShared();
            defer index.lock.unlockShared();

            self.rooted.beginTransaction();
            var entries = index.entries.iterator();
            while (entries.next()) |entry| {
                self.rooted.put(entry.key_ptr.*, newly_rooted_slot, entry.value_ptr.*);
            }
            self.rooted.commitTransaction();

            // Update the latest known rooted slot, to be used next rooting round.
            self.rooted.largest_rooted_slot = @max(newly_rooted_slot, old_rooted_slot);
        }

        if (index.slot >= old_rooted_slot) {
            // Get write lock on unrooted slot, remove from unrooted. There should be no contention on this
            // lock, no other threads are running right now. In the future when we offload rooting to a seperate
            // async unit, then it might come into play.
            index.lock.lock();
            defer index.lock.unlock();

            for (index.entries.values()) |data| data.deinit(self.allocator);
            index.entries.clearRetainingCapacity();
            index.is_empty.store(true, .release);
        }
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

test "rooting edge cases" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const S = struct {
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

    // many slots, many accounts
    {
        var test_state = try Db.initTest(allocator);
        defer test_state.deinit();
        const db = &test_state.db;

        for (0..Unrooted.MAX_SLOTS * 2) |i| {
            defer if (i > 50) db.onSlotRooted(i); // start rooting after 50 slots
            const random_account = try Account.initRandom(allocator, random, 30);
            defer random_account.deinit(allocator);
            const random_pubkey = Pubkey.initRandom(random);
            try db.put(i, random_pubkey, S.convert(random_account));
        }
        // Ensure we end up with a clean slate, not leaking any entries.
        db.onSlotRooted(Unrooted.MAX_SLOTS * 2);
        for (db.unrooted.slots) |entry| {
            std.debug.assert(entry.is_empty.load(.acquire));
        }
    }
    // many slot, same account
    {
        var test_state = try Db.initTest(allocator);
        defer test_state.deinit();
        const db = &test_state.db;

        const random_pubkey = Pubkey.initRandom(random);
        for (0..Unrooted.MAX_SLOTS * 2) |i| {
            defer if (i % 64 == 0) db.onSlotRooted(i); // root every 64 slots
            const random_account = try Account.initRandom(allocator, random, 30);
            defer random_account.deinit(allocator);
            try db.put(i, random_pubkey, S.convert(random_account));
        }
        db.onSlotRooted(Unrooted.MAX_SLOTS * 2);
        for (db.unrooted.slots) |entry| {
            std.debug.assert(entry.is_empty.load(.acquire));
        }
    }
}
