const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../../sig.zig");

const Allocator = std.mem.Allocator;

const bincode = sig.bincode;

const Epoch = sig.core.Epoch;
const Pubkey = sig.core.Pubkey;

/// [agave] https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/sysvar/src/stake_history.rs#L67
pub const StakeHistory = struct {
    entries: *std.BoundedArray(Entry, MAX_ENTRIES),

    pub const Entry = struct {
        epoch: Epoch,
        stake: StakeState,

        pub fn sortCmp(_: void, a: Entry, b: Entry) bool {
            return b.epoch < a.epoch; // Sort by descending epoch
        }

        pub fn searchCmp(epoch: u64, b: Entry) std.math.Order {
            return std.math.order(b.epoch, epoch);
        }

        pub fn initRandom(random: std.Random) Entry {
            if (!builtin.is_test) @compileError("only for testing");
            return .{
                .epoch = random.int(Epoch),
                .stake = .{
                    .effective = random.int(u64),
                    .activating = random.int(u64),
                    .deactivating = random.int(u64),
                },
            };
        }
    };

    pub const StakeState = struct {
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

    pub const STORAGE_SIZE: u64 = 16_392;

    pub fn init(allocator: Allocator) Allocator.Error!StakeHistory {
        const entries = try allocator.create(std.BoundedArray(Entry, MAX_ENTRIES));
        entries.* = std.BoundedArray(Entry, MAX_ENTRIES){};
        return .{ .entries = entries };
    }

    pub fn deinit(self: StakeHistory, allocator: Allocator) void {
        allocator.destroy(self.entries);
    }

    pub fn clone(self: StakeHistory, allocator: Allocator) Allocator.Error!StakeHistory {
        const cloned = try StakeHistory.init(allocator);
        cloned.entries.* = self.entries.*;
        return cloned;
    }

    pub fn clone(self: StakeHistory, allocator: Allocator) Allocator.Error!StakeHistory {
        return .{ .entries = try self.entries.clone(allocator) };
    }

    pub fn isEmpty(self: StakeHistory) bool {
        return self.entries.len == 0;
    }

    pub fn getEntry(self: StakeHistory, epoch: Epoch) ?Entry {
        return if (std.sort.binarySearch(
            Entry,
            self.entries.constSlice(),
            epoch,
            Entry.searchCmp,
        )) |index| self.entries.buffer[index] else null;
    }

    pub fn initWithEntries(
        allocator: Allocator,
        entries: []const Entry,
    ) Allocator.Error!StakeHistory {
        std.debug.assert(entries.len <= MAX_ENTRIES);
        var self = try StakeHistory.init(allocator);
        self.entries.appendSliceAssumeCapacity(entries);
        std.sort.heap(Entry, self.entries.slice(), {}, Entry.sortCmp);
        return self;
    }

    pub fn initRandom(allocator: Allocator, random: std.Random) Allocator.Error!StakeHistory {
        if (!builtin.is_test) @compileError("only available in test mode");
        var self = try StakeHistory.init(allocator);
        for (0..random.intRangeAtMost(Epoch, 1, 1_000)) |epoch|
            self.entries.appendAssumeCapacity(.{ .epoch = epoch, .stake = .{
                .effective = random.int(u64),
                .activating = random.int(u64),
                .deactivating = random.int(u64),
            } });
        std.sort.heap(Entry, self.entries.slice(), {}, Entry.sortCmp);
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
