const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../../sig.zig");

const Allocator = std.mem.Allocator;

const Epoch = sig.core.Epoch;
const Pubkey = sig.core.Pubkey;

/// [agave] https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/sysvar/src/stake_history.rs#L67
pub const StakeHistory = struct {
    entries: std.ArrayListUnmanaged(Entry),

    pub const Entry = struct {
        epoch: Epoch,
        /// Effective stake at this epoch
        effective: u64,
        /// Sum of portion of stakes not fully warmed up
        activating: u64,
        /// Requested to be cooled down, not fully deactivated yet
        deactivating: u64,
    };

    pub const ID =
        Pubkey.parseBase58String("SysvarStakeHistory1111111111111111111111111") catch unreachable;

    pub const MAX_ENTRIES: u64 = 512;

    pub const SIZE_OF: u64 = 16_392;

    pub fn default(allocator: Allocator) Allocator.Error!StakeHistory {
        return .{
            .entries = try std.ArrayListUnmanaged(Entry).initCapacity(
                allocator,
                MAX_ENTRIES,
            ),
        };
    }

    pub fn deinit(self: StakeHistory, allocator: Allocator) void {
        allocator.free(self.entries.allocatedSlice());
    }

    pub fn isEmpty(self: StakeHistory) bool {
        return self.entries.items.len == 0;
    }

    pub fn initWithEntries(
        allocator: Allocator,
        entries: []const Entry,
    ) Allocator.Error!StakeHistory {
        if (!builtin.is_test) @compileError("only available in test mode");
        std.debug.assert(entries.len <= MAX_ENTRIES);
        var self = try StakeHistory.default(allocator);
        for (entries) |entry| self.entries.appendAssumeCapacity(entry);
        return self;
    }
};
