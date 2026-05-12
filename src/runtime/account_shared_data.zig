const std = @import("std");
const sig = @import("../sig.zig");

pub const AccountSharedData = sig.shared.runtime.AccountSharedData;

/// Returns `account` as a core account, without transferring ownership of the data.
pub fn asAccount(account: AccountSharedData) sig.core.Account {
    return .{
        .lamports = account.lamports,
        .data = .{ .unowned_allocation = account.data },
        .owner = account.owner,
        .executable = account.executable,
        .rent_epoch = account.rent_epoch,
    };
}

/// Returns `account` as a core account, while transferring ownership of the data.
pub fn toOwnedAccount(account: AccountSharedData) sig.core.Account {
    return .{
        .lamports = account.lamports,
        .data = .{ .owned_allocation = account.data },
        .owner = account.owner,
        .executable = account.executable,
        .rent_epoch = account.rent_epoch,
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
