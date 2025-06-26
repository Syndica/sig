const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../../sig.zig");

const Allocator = std.mem.Allocator;

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
        return self.entries.items.len == 0;
    }

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

        const entries = try allocator.alloc(IndexAndEntry, MAX_ENTRIES);
        defer allocator.free(entries);

        var i: usize = 0;
        for (queue.hash_infos.keys(), queue.hash_infos.values()) |hash, info| {
            if (queue.last_hash_index - info.index >= MAX_ENTRIES) continue;
            entries[i] = .{
                .index = info.index,
                .entry = .{
                    .blockhash = hash,
                    .lamports_per_signature = info.lamports_per_signature,
                },
            };
            i += 1;
        }

        std.sort.heap(IndexAndEntry, entries, {}, IndexAndEntry.compareFn);

        var self = try RecentBlockhashes.default(allocator);
        errdefer self.deinit(allocator);

        for (entries) |entry| self.entries.appendAssumeCapacity(entry.entry);

        return self;
    }

    pub fn initWithEntries(
        allocator: Allocator,
        entries: []const Entry,
    ) Allocator.Error!RecentBlockhashes {
        if (!builtin.is_test) @compileError("only for tests");
        std.debug.assert(entries.len <= MAX_ENTRIES);
        var self = try RecentBlockhashes.default(allocator);
        for (entries) |entry| self.entries.appendAssumeCapacity(entry);
        return self;
    }

    pub fn initRandom(allocator: Allocator, random: std.Random) Allocator.Error!RecentBlockhashes {
        if (!builtin.is_test) @compileError("only for tests");
        var self = try RecentBlockhashes.default(allocator);
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

    for (recent_blockhashes.entries.items, 0..) |entry, i| {
        const info = queue.hash_infos.get(entry.blockhash) orelse unreachable;
        try std.testing.expectEqual(info.index, queue.last_hash_index - i);
    }

    try std.testing.expect(!recent_blockhashes.isEmpty());
}
