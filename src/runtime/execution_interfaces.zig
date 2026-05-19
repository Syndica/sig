const std = @import("std");
const sig = @import("../sig.zig");

const AccountSharedData = @import("AccountSharedData.zig");
const Pubkey = sig.core.Pubkey;

pub const AccountLoadError = error{ OutOfMemory, AccountsDBError };

pub const AccountReader = struct {
    ctx: *const anyopaque,
    getFn: *const fn (
        *const anyopaque,
        std.mem.Allocator,
        Pubkey,
    ) AccountLoadError!?AccountSharedData,

    /// Returns caller-owned account data for a live account. The caller must
    /// deinitialize returned `AccountSharedData.data` with the same allocator.
    /// Missing accounts and dead accounts return null.
    pub fn get(
        self: AccountReader,
        allocator: std.mem.Allocator,
        pubkey: Pubkey,
    ) AccountLoadError!?AccountSharedData {
        return self.getFn(self.ctx, allocator, pubkey);
    }
};
