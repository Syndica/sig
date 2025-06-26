const std = @import("std");
const sig = @import("../../sig.zig");

const Epoch = sig.core.Epoch;
const Pubkey = sig.core.Pubkey;

/// [agave] https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/sysvar/src/stake_history.rs#L67
pub const StakeHistory = struct {
    entries: std.BoundedArray(Entry, MAX_ENTRIES) = .{},

    pub const Entry = struct {
        Epoch,
        struct {
            /// Effective stake at this epoch
            effective: u64,
            /// Sum of portion of stakes not fully warmed up
            activating: u64,
            /// Requested to be cooled down, not fully deactivated yet
            deactivating: u64,
        },
    };

    pub const ID =
        Pubkey.parseBase58String("SysvarStakeHistory1111111111111111111111111") catch unreachable;

    pub const DEFAULT: StakeHistory = .{ .entries = .{} };

    pub const MAX_ENTRIES: u64 = 512;

    pub const SIZE_OF: u64 = 16_392;

    pub fn initWithEntries(entries: []const Entry) StakeHistory {
        std.debug.assert(entries.len <= MAX_ENTRIES);
        var self = StakeHistory.DEFAULT;
        for (entries) |entry| self.entries.appendAssumeCapacity(entry);
        return self;
    }
};
