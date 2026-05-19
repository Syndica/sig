const std = @import("std");
const sig = @import("../sig.zig");

const Account = sig.core.Account;
const AccountReader = sig.runtime.execution_interfaces.AccountReader;
const AccountLoadError = sig.runtime.execution_interfaces.AccountLoadError;
const AccountSharedData = sig.runtime.AccountSharedData;
const Pubkey = sig.core.Pubkey;
const SlotAccountReader = sig.accounts_db.SlotAccountReader;

pub const SlotAccountReaderAdapter = struct {
    reader: SlotAccountReader,

    pub fn accountReader(self: *const SlotAccountReaderAdapter) AccountReader {
        return .{ .ctx = self, .getFn = get };
    }

    fn get(
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
        pubkey: Pubkey,
    ) AccountLoadError!?AccountSharedData {
        const adapter: *const SlotAccountReaderAdapter = @ptrCast(@alignCast(ctx));
        const account = adapter.reader.get(allocator, pubkey) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.AccountsDBError,
        } orelse return null;
        defer account.deinit(allocator);

        if (account.lamports == 0) return null;

        return AccountSharedData.fromAccount(allocator, &account) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
        };
    }
};
