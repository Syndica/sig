const std = @import("std");
const sig = @import("../sig.zig");

const Account = sig.core.Account;
const AccountSharedData = @import("AccountSharedData.zig");

/// Returns `account` as shared data with owned account data.
pub fn fromAccount(
    allocator: std.mem.Allocator,
    account: *const Account,
) !AccountSharedData {
    return .{
        .lamports = account.lamports,
        .data = try account.data.readAllAllocate(allocator),
        .owner = account.owner,
        .executable = account.executable,
        .rent_epoch = account.rent_epoch,
    };
}

/// Returns `account` without transferring ownership of the data.
pub fn asAccount(account: AccountSharedData) Account {
    return .{
        .lamports = account.lamports,
        .data = .{ .unowned_allocation = account.data },
        .owner = account.owner,
        .executable = account.executable,
        .rent_epoch = account.rent_epoch,
    };
}

/// Returns `account` while transferring ownership of the data.
pub fn toOwnedAccount(account: AccountSharedData) Account {
    return .{
        .lamports = account.lamports,
        .data = .{ .owned_allocation = account.data },
        .owner = account.owner,
        .executable = account.executable,
        .rent_epoch = account.rent_epoch,
    };
}
