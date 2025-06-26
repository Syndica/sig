const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../../sig.zig");

const Allocator = std.mem.Allocator;

const Epoch = sig.core.Epoch;
const Pubkey = sig.core.Pubkey;

/// [agave] https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/sysvar/src/stake_history.rs#L67
pub const StakeHistory = struct {
    entries: std.BoundedArray(Entry, MAX_ENTRIES) = .{},

    pub fn default(allocator: Allocator) Allocator.Error!StakeHistory {
        return .{
            .entries = try std.ArrayListUnmanaged(Entry).initCapacity(
                allocator,
                MAX_ENTRIES,
            ),
        };
    }

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

test "serialize and deserialize" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    {
        var stake_history = try StakeHistory.initRandom(allocator, random);
        defer stake_history.deinit(allocator);

        const serialized = try bincode.writeAlloc(allocator, stake_history, .{});
        defer allocator.free(serialized);

        const deserialized = try bincode.readFromSlice(allocator, StakeHistory, serialized, .{});
        defer deserialized.deinit(allocator);

        try std.testing.expectEqual(StakeHistory.MAX_ENTRIES, deserialized.entries.capacity());
        try std.testing.expectEqualSlices(
            StakeHistory.Entry,
            stake_history.entries.constSlice(),
            deserialized.entries.constSlice(),
        );
    }

    {
        var stake_history = try StakeHistory.init(allocator);
        defer stake_history.deinit(allocator);
        stake_history.entries.appendAssumeCapacity(.{
            .epoch = random.int(Epoch),
            .stake = .{
                .effective = random.int(u64),
                .activating = random.int(u64),
                .deactivating = random.int(u64),
            },
        });

        const serialized = try bincode.writeAlloc(allocator, stake_history, .{});
        defer allocator.free(serialized);

        const deserialized = try bincode.readFromSlice(allocator, StakeHistory, serialized, .{});
        defer deserialized.deinit(allocator);

        try std.testing.expectEqual(StakeHistory.MAX_ENTRIES, deserialized.entries.capacity());
        try std.testing.expectEqualSlices(
            StakeHistory.Entry,
            stake_history.entries.constSlice(),
            deserialized.entries.constSlice(),
        );
    }
}
