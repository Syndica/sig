const std = @import("std");
const sig = @import("../../sig.zig");
const rocks_hybrid = @import("lib.zig");

const Allocator = std.mem.Allocator;
const ArrayMap = std.AutoArrayHashMapUnmanaged;

const Ancestors = sig.core.Ancestors;
const Epoch = sig.core.Epoch;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;

const RwMux = sig.sync.RwMux;

const UnrootedDB = rocks_hybrid.unrooted.UnrootedDB;
const RootedDB = rocks_hybrid.rooted.RootedDB;

const Logger = sig.trace.Logger("accountsdb.rocks.db");

pub const AccountsDB = struct {
    allocator: Allocator,
    unrooted: UnrootedDB,
    rooted: RootedDB,

    pub fn init(
        allocator: Allocator,
        logger: Logger,
        path: []const u8,
    ) !RootedDB {
        return .{
            .allocator = allocator,
            .unrooted = .init(allocator),
            .rooted = try .init(allocator, logger, path),
        };
    }

    pub fn accountStore(self: *AccountsDB) sig.accounts_db.AccountStore {
        return .{ .rocks_hybrid = self };
    }

    pub fn get(
        self: *AccountsDB,
        address: Pubkey,
        ancestors: *const Ancestors,
    ) !?sig.core.Account {
        if (self.unrooted.get(address, ancestors)) |account| {
            return .init(account.fields, .{ .rc_slice = account.data });
        }
        if (try self.rooted.get(address)) |account| {
            return .init(account.fields, .{ .rocksdb = account.data });
        }
        return null;
    }

    pub fn put(
        self: *AccountsDB,
        slot: Slot,
        address: Pubkey,
        account: rocks_hybrid.unrooted.InputAccount,
    ) error{ Deleted, OutOfMemory }!void {
        try self.unrooted.put(slot, address, account);
    }
};
