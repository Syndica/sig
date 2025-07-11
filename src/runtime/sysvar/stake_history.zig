const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../../sig.zig");

const Allocator = std.mem.Allocator;

const bincode = sig.bincode;

const Epoch = sig.core.Epoch;
const Pubkey = sig.core.Pubkey;

/// [agave] https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/sysvar/src/stake_history.rs#L67
pub const StakeHistory = struct {
    entries: std.ArrayListUnmanaged(Entry) = .{},

    pub const @"!bincode-config" = bincode.FieldConfig(StakeHistory){
        .deserializer = deserialize,
    };

    pub const Entry = struct {
        epoch: Epoch,
        stake: ClusterStake,

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

    pub const ClusterStake = struct {
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

    pub const EMPTY: StakeHistory = .{ .entries = .{} };

    pub fn default(allocator: Allocator) Allocator.Error!StakeHistory {
        return .{ .entries = try .initCapacity(allocator, MAX_ENTRIES) };
    }

    pub fn deinit(self: StakeHistory, allocator: Allocator) void {
        allocator.free(self.entries.allocatedSlice());
    }

    pub fn clone(self: StakeHistory, allocator: Allocator) Allocator.Error!StakeHistory {
        return .{ .entries = try self.entries.clone(allocator) };
    }

    pub fn isEmpty(self: StakeHistory) bool {
        return self.entries.items.len == 0;
    }

    pub fn getEntry(self: StakeHistory, epoch: Epoch) ?Entry {
        return if (std.sort.binarySearch(
            Entry,
            self.entries.items,
            epoch,
            Entry.searchCmp,
        )) |index| self.entries.items[index] else null;
    }

    pub fn initWithEntries(
        allocator: Allocator,
        entries: []const Entry,
    ) Allocator.Error!StakeHistory {
        std.debug.assert(entries.len <= MAX_ENTRIES);
        var self = try StakeHistory.default(allocator);
        self.entries.appendSliceAssumeCapacity(entries);
        std.sort.heap(Entry, self.entries.items, {}, Entry.sortCmp);
        return self;
    }

    pub fn initRandom(allocator: Allocator, random: std.Random) Allocator.Error!StakeHistory {
        // TODO: Uncomment once not required by bank init random
        // if (!builtin.is_test) @compileError("only for testing");
        var self = try StakeHistory.default(allocator);
        for (0..random.intRangeAtMost(Epoch, 1, MAX_ENTRIES)) |_|
            self.entries.appendAssumeCapacity(.{
                .epoch = random.int(u64),
                .stake = .{
                    .effective = random.int(u64),
                    .activating = random.int(u64),
                    .deactivating = random.int(u64),
                },
            });
        std.sort.heap(Entry, self.entries.items, {}, Entry.sortCmp);
        return self;
    }

    pub fn deserialize(allocator: Allocator, reader: anytype, _: bincode.Params) !StakeHistory {
        var entries = try bincode.read(allocator, std.ArrayListUnmanaged(Entry), reader, .{});
        try entries.ensureTotalCapacityPrecise(allocator, MAX_ENTRIES);
        return .{ .entries = entries };
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

        try std.testing.expectEqual(StakeHistory.MAX_ENTRIES, deserialized.entries.capacity);
        try std.testing.expectEqualSlices(
            StakeHistory.Entry,
            stake_history.entries.items,
            deserialized.entries.items,
        );
    }

    {
        var stake_history = StakeHistory{ .entries = try .initCapacity(allocator, 1) };
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

        try std.testing.expectEqual(StakeHistory.MAX_ENTRIES, deserialized.entries.capacity);
        try std.testing.expectEqualSlices(
            StakeHistory.Entry,
            stake_history.entries.items,
            deserialized.entries.items,
        );
    }
}
