const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../../sig.zig");

const Allocator = std.mem.Allocator;

const bincode = sig.bincode;

const BlockhashQueue = sig.core.BlockhashQueue;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;

/// A list of entries ordered by descending block height.
/// The first entry holds the most recent blockhash.
/// [agave] https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/sysvar/src/recent_blockhashes.rs#L99
pub const RecentBlockhashes = struct {
    /// A list of entries ordered by descending block height. The first
    /// entry holds the most recent blockhash.
    entries: std.BoundedArray(Entry, MAX_ENTRIES),

    pub const Entry = extern struct {
        blockhash: Hash,
        lamports_per_signature: u64,
    };

    pub const ID: Pubkey = .parse("SysvarRecentB1ockHashes11111111111111111111");

    pub const DEFAULT: RecentBlockhashes = .{ .entries = .{} };

    pub const MAX_ENTRIES: u64 = 150;

    pub const SIZE_OF: u64 = 6_008;

    pub fn initWithSingleEntry(entry: Entry) RecentBlockhashes {
        var self = RecentBlockhashes.DEFAULT;
        self.entries.appendAssumeCapacity(entry);
        return self;
    }

    pub fn last(self: RecentBlockhashes) ?Entry {
        if (self.entries.len == 0) return null;
        return self.entries.slice()[self.entries.len - 1];
    }

    pub fn isEmpty(self: RecentBlockhashes) bool {
        return self.entries.len == 0;
    }

    // pub fn getFirst(self: *const RecentBlockhashes) ?Entry {
    //     if (self.entries.len == 0) return null;
    //     return self.entries.buffer[0];
    // }

    pub fn fromBlockhashQueue(
        allocator: Allocator,
        queue: *const BlockhashQueue,
    ) Allocator.Error!RecentBlockhashes {
        const IndexAndEntry = struct {
            index: u64,
            entry: Entry,

            pub fn compareFn(_: void, a: @This(), b: @This()) bool {
                return a.index > b.index;
            }
        };

        var entries = try std.ArrayListUnmanaged(IndexAndEntry).initCapacity(
            allocator,
            queue.hash_infos.count(),
        );
        defer entries.deinit(allocator);

        for (queue.hash_infos.keys(), queue.hash_infos.values()) |hash, info| {
            entries.appendAssumeCapacity(.{
                .index = info.index,
                .entry = .{
                    .blockhash = hash,
                    .lamports_per_signature = info.lamports_per_signature,
                },
            });
        }

        std.sort.heap(IndexAndEntry, entries.items, {}, IndexAndEntry.compareFn);

        var self = try RecentBlockhashes.init(allocator);
        errdefer self.deinit(allocator);

        const num_entries = @min(entries.items.len, MAX_ENTRIES);
        for (entries.items[0..num_entries]) |entry| self.entries.appendAssumeCapacity(entry.entry);

        return self;
    }

    pub fn initWithEntries(
        allocator: Allocator,
        entries: []const Entry,
    ) Allocator.Error!RecentBlockhashes {
        if (!builtin.is_test) @compileError("only for tests");
        std.debug.assert(entries.len <= MAX_ENTRIES);
        var self = try RecentBlockhashes.init(allocator);
        self.entries.appendSliceAssumeCapacity(entries);
        return self;
    }

    pub fn initRandom(allocator: Allocator, random: std.Random) Allocator.Error!RecentBlockhashes {
        if (!builtin.is_test) @compileError("only for tests");
        var self = try RecentBlockhashes.init(allocator);
        for (0..random.intRangeAtMost(u64, 1, MAX_ENTRIES)) |_| {
            self.entries.appendAssumeCapacity(.{
                .blockhash = Hash.initRandom(random),
                .lamports_per_signature = random.int(u64),
            });
        }
        return self;
    }
};

test "from blockhash queue" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);

    const queue = try BlockhashQueue.initRandom(allocator, prng.random(), 1000);
    defer queue.deinit(allocator);

    const recent_blockhashes = try RecentBlockhashes.fromBlockhashQueue(allocator, &queue);
    defer recent_blockhashes.deinit(allocator);

    for (recent_blockhashes.entries.constSlice(), 0..) |entry, i| {
        const info = queue.hash_infos.get(entry.blockhash) orelse unreachable;
        try std.testing.expectEqual(info.index, queue.last_hash_index - i);
    }

    try std.testing.expect(!recent_blockhashes.isEmpty());
}

test "serialize and deserialize" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    {
        var blockhashes = try RecentBlockhashes.initRandom(allocator, random);
        defer blockhashes.deinit(allocator);

        const serialized = try bincode.writeAlloc(allocator, blockhashes, .{});
        defer allocator.free(serialized);

        const deserialized =
            try bincode.readFromSlice(allocator, RecentBlockhashes, serialized, .{});
        defer deserialized.deinit(allocator);

        try std.testing.expectEqual(RecentBlockhashes.MAX_ENTRIES, deserialized.entries.capacity());
        try std.testing.expectEqualSlices(
            RecentBlockhashes.Entry,
            blockhashes.entries.constSlice(),
            deserialized.entries.constSlice(),
        );
    }

    {
        var blockhashes = try RecentBlockhashes.init(allocator);
        defer blockhashes.deinit(allocator);
        blockhashes.entries.appendAssumeCapacity(.{
            .blockhash = Hash.initRandom(random),
            .lamports_per_signature = random.int(u64),
        });

        const serialized = try bincode.writeAlloc(allocator, blockhashes, .{});
        defer allocator.free(serialized);

        const deserialized = try bincode.readFromSlice(
            allocator,
            RecentBlockhashes,
            serialized,
            .{},
        );
        defer deserialized.deinit(allocator);

        try std.testing.expectEqual(RecentBlockhashes.MAX_ENTRIES, deserialized.entries.capacity());
        try std.testing.expectEqualSlices(
            RecentBlockhashes.Entry,
            blockhashes.entries.constSlice(),
            deserialized.entries.constSlice(),
        );
    }
}
