const builtin = @import("builtin");
const std = @import("std");
const std14 = @import("std14");
const sig = @import("../../component.zig");
const solana = @import("lib").solana;

const bincode = sig.bincode;

const Hash = solana.Hash;
const Pubkey = solana.Pubkey;

/// A list of entries ordered by descending block height.
/// The first entry holds the most recent blockhash.
/// [agave] https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/sysvar/src/recent_blockhashes.rs#L99
pub const RecentBlockhashes = struct {
    entries: std14.BoundedArray(Entry, MAX_ENTRIES),

    pub const INIT: RecentBlockhashes = .{ .entries = .{} };

    pub const Entry = extern struct {
        blockhash: Hash,
        lamports_per_signature: u64,
    };

    pub const ID: Pubkey = .parse("SysvarRecentB1ockHashes11111111111111111111");

    pub const MAX_ENTRIES: u64 = 150;

    pub const STORAGE_SIZE: u64 = 6_008;

    pub fn isEmpty(self: RecentBlockhashes) bool {
        return self.entries.len == 0;
    }

    // pub fn getFirst(self: *const RecentBlockhashes) ?Entry {
    //     if (self.entries.len == 0) return null;
    //     return self.entries.buffer[0];
    // }

    pub fn initWithEntries(entries: []const Entry) RecentBlockhashes {
        if (!builtin.is_test) @compileError("only for tests");
        std.debug.assert(entries.len <= MAX_ENTRIES);

        var self: RecentBlockhashes = .INIT;
        self.entries.appendSliceAssumeCapacity(entries);
        return self;
    }

    pub fn initRandom(random: std.Random) RecentBlockhashes {
        if (!builtin.is_test) @compileError("only for tests");

        var self: RecentBlockhashes = .INIT;
        for (0..random.intRangeAtMost(u64, 1, MAX_ENTRIES)) |_| {
            self.entries.appendAssumeCapacity(.{
                .blockhash = Hash.initRandom(random),
                .lamports_per_signature = random.int(u64),
            });
        }
        return self;
    }
};

test "serialize and deserialize" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    {
        var blockhashes = RecentBlockhashes.initRandom(random);

        const serialized = try bincode.writeAlloc(allocator, blockhashes, .{});
        defer allocator.free(serialized);

        const deserialized =
            try bincode.readFromSlice(allocator, RecentBlockhashes, serialized, .{});

        try std.testing.expectEqualSlices(
            RecentBlockhashes.Entry,
            blockhashes.entries.constSlice(),
            deserialized.entries.constSlice(),
        );
    }

    {
        var blockhashes: RecentBlockhashes = .INIT;
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

        try std.testing.expectEqualSlices(
            RecentBlockhashes.Entry,
            blockhashes.entries.constSlice(),
            deserialized.entries.constSlice(),
        );
    }
}
