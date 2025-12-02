const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../../sig.zig");

const bincode = sig.bincode;

const Epoch = sig.core.Epoch;
const Pubkey = sig.core.Pubkey;

/// [agave] https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/sysvar/src/stake_history.rs#L67
pub const StakeHistory = struct {
    entries: std.BoundedArray(Entry, MAX_ENTRIES),

    pub const INIT: StakeHistory = .{ .entries = .{} };

    pub const Entry = extern struct {
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

    pub const StakeState = extern struct {
        /// Effective stake at this epoch
        effective: u64 = 0,
        /// Sum of portion of stakes not fully warmed up
        activating: u64 = 0,
        /// Requested to be cooled down, not fully deactivated yet
        deactivating: u64 = 0,
    };

    pub const ID: Pubkey = .parse("SysvarStakeHistory1111111111111111111111111");

    pub const MAX_ENTRIES: u64 = 512;

    pub const STORAGE_SIZE: u64 = 16_392;

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

    pub fn initWithEntries(entries: []const Entry) StakeHistory {
        sig.trace.assert(entries.len <= MAX_ENTRIES);
        var self: StakeHistory = .INIT;
        self.entries.appendSliceAssumeCapacity(entries);
        std.sort.heap(Entry, self.entries.slice(), {}, Entry.sortCmp);
        return self;
    }

    pub fn initRandom(random: std.Random) StakeHistory {
        // TODO: Uncomment once not required by bank init random
        // if (!builtin.is_test) @compileError("only for testing");
        var self: StakeHistory = .INIT;
        for (0..random.uintLessThan(Epoch, MAX_ENTRIES)) |_|
            self.entries.appendAssumeCapacity(.{
                .epoch = random.int(u64),
                .stake = .{
                    .effective = random.int(u64),
                    .activating = random.int(u64),
                    .deactivating = random.int(u64),
                },
            });
        std.sort.heap(Entry, self.entries.slice(), {}, Entry.sortCmp);
        return self;
    }
};

test "serialize and deserialize" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    {
        var stake_history = StakeHistory.initRandom(random);

        const serialized = try bincode.writeAlloc(allocator, stake_history, .{});
        defer allocator.free(serialized);

        const deserialized = try bincode.readFromSlice(allocator, StakeHistory, serialized, .{});

        try std.testing.expectEqual(StakeHistory.MAX_ENTRIES, deserialized.entries.capacity());
        try std.testing.expectEqualSlices(
            StakeHistory.Entry,
            stake_history.entries.constSlice(),
            deserialized.entries.constSlice(),
        );
    }

    {
        var stake_history: StakeHistory = .INIT;
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

        try std.testing.expectEqual(StakeHistory.MAX_ENTRIES, deserialized.entries.capacity());
        try std.testing.expectEqualSlices(
            StakeHistory.Entry,
            stake_history.entries.constSlice(),
            deserialized.entries.constSlice(),
        );
    }
}
