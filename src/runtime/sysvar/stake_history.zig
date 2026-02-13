const builtin = @import("builtin");
const std = @import("std");
const std14 = @import("std14");
const sig = @import("../../sig.zig");

const bincode = sig.bincode;

const Epoch = sig.core.Epoch;
const Pubkey = sig.core.Pubkey;

/// [agave] https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/sysvar/src/stake_history.rs#L67
pub const StakeHistory = struct {
    entries: std14.BoundedArray(Entry, MAX_ENTRIES),

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

        pub const DEFAULT: StakeState = .{
            .effective = 0,
            .activating = 0,
            .deactivating = 0,
        };

        pub fn add(self: *StakeState, other: StakeState) void {
            self.effective += other.effective;
            self.activating += other.activating;
            self.deactivating += other.deactivating;
        }
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

    pub fn insertEntry(self: *StakeHistory, epoch: Epoch, entry: StakeState) !void {
        const index = std.sort.lowerBound(
            Entry,
            self.entries.constSlice(),
            epoch,
            Entry.searchCmp,
        );

        if (self.entries.len == MAX_ENTRIES) {
            if (epoch < self.entries.buffer[MAX_ENTRIES - 1].epoch) return;
            _ = self.entries.orderedRemove(MAX_ENTRIES - 1);
        }

        if (index < self.entries.len and self.entries.buffer[index].epoch == epoch) {
            return error.DuplicateEpoch;
        }

        try self.entries.insert(index, .{ .epoch = epoch, .stake = entry });
    }

    pub fn initWithEntries(entries_slice: []const Entry) StakeHistory {
        std.debug.assert(entries_slice.len <= MAX_ENTRIES);
        var self: StakeHistory = .INIT;
        self.entries.appendSliceAssumeCapacity(entries_slice);
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

test "insert and add" {
    var stake_history: StakeHistory = .INIT;

    try stake_history.insertEntry(1, .{ .effective = 10, .activating = 5, .deactivating = 2 });
    try stake_history.insertEntry(3, .{ .effective = 20, .activating = 10, .deactivating = 4 });
    try stake_history.insertEntry(2, .{ .effective = 15, .activating = 7, .deactivating = 3 });

    try std.testing.expectEqual(3, stake_history.entries.len);

    const entry_2 = stake_history.getEntry(2) orelse unreachable;
    try std.testing.expectEqual(15, entry_2.stake.effective);
    try std.testing.expectEqual(7, entry_2.stake.activating);
    try std.testing.expectEqual(3, entry_2.stake.deactivating);

    var stake_2 = entry_2.stake;
    stake_2.add(.{
        .effective = 10,
        .activating = 5,
        .deactivating = 1,
    });
    try std.testing.expectEqual(25, stake_2.effective);
    try std.testing.expectEqual(12, stake_2.activating);
    try std.testing.expectEqual(4, stake_2.deactivating);
}
