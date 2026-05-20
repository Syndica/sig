const std = @import("std");
const sig = @import("../sig.zig");

const AccountReader = sig.runtime.execution_interfaces.AccountReader;
const AccountLoadError = sig.runtime.execution_interfaces.AccountLoadError;
const AccountSharedData = sig.runtime.AccountSharedData;
const Ancestors = sig.core.Ancestors;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const SlotAccountReader = sig.accounts_db.SlotAccountReader;
const StatusCache = sig.core.StatusCache;
const StatusChecker = sig.runtime.execution_interfaces.StatusChecker;
const TransactionError = sig.ledger.transaction_status.TransactionError;

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

pub const StatusCacheStatusCheckerAdapter = struct {
    ancestors: *const Ancestors,
    status_cache: *StatusCache,

    pub fn statusChecker(self: *const StatusCacheStatusCheckerAdapter) StatusChecker {
        return .{ .ctx = self, .checkFn = check };
    }

    /// [agave] https://github.com/firedancer-io/agave/blob/403d23b809fc513e2c4b433125c127cf172281a2/runtime/src/bank/check_transactions.rs#L186
    fn check(
        ctx: *const anyopaque,
        msg_hash: *const Hash,
        recent_blockhash: *const Hash,
    ) ?TransactionError {
        const adapter: *const StatusCacheStatusCheckerAdapter = @ptrCast(@alignCast(ctx));
        return switch (adapter.status_cache.getStatus(
            &msg_hash.data,
            recent_blockhash,
            adapter.ancestors,
        )) {
            .pending => null,
            .failed, .succeeded => .AlreadyProcessed,
        };
    }
};

test "StatusCacheStatusCheckerAdapter" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    var ancestors = Ancestors{};
    defer ancestors.deinit(allocator);

    var status_cache: StatusCache = .DEFAULT;
    defer status_cache.deinit(allocator);

    const adapter = StatusCacheStatusCheckerAdapter{
        .ancestors = &ancestors,
        .status_cache = &status_cache,
    };
    const status_checker = adapter.statusChecker();

    const msg_hash = Hash.init("msg hash");
    const recent_blockhash = Hash.init("recent blockhash");

    try std.testing.expectEqual(null, status_checker.check(&msg_hash, &recent_blockhash));

    try ancestors.ancestors.put(allocator, 0, {});
    try status_cache.insert(allocator, prng.random(), &recent_blockhash, &msg_hash.data, 0, null);

    try std.testing.expectEqual(
        TransactionError.AlreadyProcessed,
        status_checker.check(&msg_hash, &recent_blockhash),
    );
}
