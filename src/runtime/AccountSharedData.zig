//! `AccountSharedData` holds account information with a shared reference to the account data field
//! `AccountSharedData`'s are loaded from `accounts_db` during the transaction loading phase
//!
//! TODO: move to `accounts_db` after implementing account loading?
//!
//! [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/account.rs#L118

const std = @import("std");
const sig = @import("../sig.zig");
const AccountSharedData = @This();

const Pubkey = sig.core.Pubkey;
const Epoch = sig.core.Epoch;

/// lamports in the account
lamports: u64,
/// data held in this account
data: []u8,
/// the program that owns this account. If executable, the program that loads this account.
owner: Pubkey,
/// this account's data contains a loaded program (and is now read-only)
executable: bool,
/// the epoch at which this account will next owe rent
rent_epoch: Epoch,

pub const EMPTY: AccountSharedData = .{
    .lamports = 0,
    .data = &.{},
    .owner = Pubkey.ZEROES,
    .executable = false,
    .rent_epoch = 0,
};

pub const NEW: AccountSharedData = .{
    .lamports = 0,
    .data = &.{},
    .owner = Pubkey.ZEROES,
    .executable = false,
    .rent_epoch = sig.core.rent_collector.RENT_EXEMPT_RENT_EPOCH,
};

pub fn isZeroed(self: AccountSharedData) bool {
    return std.mem.allEqual(u8, self.data, 0);
}

pub fn isDeleted(self: AccountSharedData) bool {
    return self.lamports == 0; // TODO: any other conditions for this?
}

pub fn deinit(self: *const AccountSharedData, allocator: std.mem.Allocator) void {
    allocator.free(self.data);
}

pub fn clone(
    self: AccountSharedData,
    allocator: std.mem.Allocator,
) std.mem.Allocator.Error!AccountSharedData {
    return .{
        .lamports = self.lamports,
        .data = try allocator.dupe(u8, self.data),
        .owner = self.owner,
        .executable = self.executable,
        .rent_epoch = self.rent_epoch,
    };
}

pub fn equals(self: *const AccountSharedData, other: *const AccountSharedData) bool {
    return self.lamports == other.lamports and
        std.mem.eql(u8, self.data, other.data) and
        self.owner.equals(&other.owner) and
        self.executable == other.executable and
        self.rent_epoch == other.rent_epoch;
}

/// Copy the old data into the new memory
/// If the new size is less than the old size, truncate the data
pub fn resize(
    self: *AccountSharedData,
    allocator: std.mem.Allocator,
    new_size: usize,
) error{OutOfMemory}!void {
    if (allocator.resize(self.data, new_size)) {
        const old_len = self.data.len;
        self.data.len = new_size;
        @memset(self.data[@min(old_len, self.data.len)..], 0);
    } else {
        const new_memory = try allocator.alloc(u8, new_size);
        @memset(new_memory, 0);
        @memcpy(new_memory.ptr, self.data[0..@min(self.data.len, new_size)]);
        allocator.free(self.data);
        self.data = new_memory;
    }
}

/// Returns `self` as an account, without transferring ownership of the data.
pub fn asAccount(self: AccountSharedData) sig.core.Account {
    return .{
        .lamports = self.lamports,
        .data = .{ .unowned_allocation = self.data },
        .owner = self.owner,
        .executable = self.executable,
        .rent_epoch = self.rent_epoch,
    };
}

/// Returns `self` as an account, while transferring ownership of the data.
pub fn toOwnedAccount(self: AccountSharedData) sig.core.Account {
    return .{
        .lamports = self.lamports,
        .data = .{ .owned_allocation = self.data },
        .owner = self.owner,
        .executable = self.executable,
        .rent_epoch = self.rent_epoch,
    };
}

pub fn fromAccount(
    allocator: std.mem.Allocator,
    account: *const sig.core.Account,
) !AccountSharedData {
    return .{
        .lamports = account.lamports,
        .data = try account.data.readAllAllocate(allocator),
        .owner = account.owner,
        .executable = account.executable,
        .rent_epoch = account.rent_epoch,
    };
}
