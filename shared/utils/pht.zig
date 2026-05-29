const std = @import("std");
const sig = @import("../sig.zig");
const Pubkey = sig.core.Pubkey;

/// Compile-time perfect hash table.
/// Based off of: https://cmph.sourceforge.net/papers/esa09.pdf.
/// Meant for low key amounts (<= ~32).
pub fn pht(V: type, entries: []const struct { Pubkey, V }) type {
    const LAMBDA = 5;
    const table_len = entries.len;
    const bucket_len = (table_len + LAMBDA - 1) / LAMBDA;

    const window = 4;
    const length = 32;
    const unique = outer: for (0..length - window + 1) |i| {
        const first = entries[0][0].data[i..][0..window];
        for (entries[1..]) |entry| {
            if (std.mem.eql(u8, entry[0].data[i..][0..window], first)) continue :outer;
        }
        break i;
    } else @compileError("keys have no unique window");

    const Generator = struct {
        hashes: [table_len]Hash,
        buckets: [bucket_len]Bucket,
        disps: [bucket_len]struct { u32, u32 },
        map: [table_len]?usize,
        try_map: [table_len]u64,

        const empty: @This() = .{
            .hashes = undefined,
            .buckets = buckets: {
                var arr: [bucket_len]Bucket = undefined;
                for (0..bucket_len) |i| {
                    arr[i] = .{
                        .index = i,
                        .keys = &.{},
                    };
                }
                break :buckets arr;
            },
            .disps = @splat(.{ 0, 0 }),
            .map = @splat(null),
            .try_map = @splat(0),
        };

        const Hash = struct {
            g: u32,
            f1: u32,
        };

        const Bucket = struct {
            index: usize,
            keys: []const usize,

            fn greaterThan(_: void, a: Bucket, b: Bucket) bool {
                return a.keys.len > b.keys.len;
            }
        };

        fn hash(x: *const Pubkey, key: u8) Hash {
            const int: u32 = @bitCast(x.data[unique..][0..window].*);
            const result = @as(u64, key) *% int;
            return .{
                .g = @intCast(result >> 32),
                .f1 = @truncate(result),
            };
        }

        fn displace(f1: u32, d1: u32, d2: u32) u32 {
            return (f1 *% d1) +% d2;
        }

        fn generate(g: *@This()) bool {
            for (g.hashes, 0..) |h, i| {
                const keys = &g.buckets[h.g % bucket_len].keys;
                keys.* = keys.* ++ .{i};
            }
            std.mem.sortUnstable(Bucket, &g.buckets, {}, Bucket.greaterThan);
            var generation = 0;
            buckets: for (g.buckets) |bucket| {
                for (0..table_len) |d1| {
                    disps: for (0..table_len) |d2| {
                        var vta: []const struct { usize, usize } = &.{};
                        generation += 1;
                        for (bucket.keys) |key| {
                            const index = displace(g.hashes[key].f1, d1, d2) % table_len;
                            if (g.map[index] != null or g.try_map[index] == generation) {
                                continue :disps;
                            }
                            g.try_map[index] = generation;
                            vta = vta ++ .{.{ index, key }};
                        }
                        g.disps[bucket.index] = .{ d1, d2 };
                        for (vta) |entry| g.map[entry[0]] = entry[1];
                        continue :buckets;
                    }
                }
                return false;
            }
            return true;
        }
    };

    var prng: std.Random.DefaultPrng = .init(0);
    const random = prng.random();

    @setEvalBranchQuota(100_000);
    const key, const disps, const data = for (0..100) |_| {
        const key = random.int(u8);
        var generator: Generator = .empty;
        for (entries, 0..) |entry, i| {
            generator.hashes[i] = Generator.hash(&entry[0], key);
        }

        if (!generator.generate()) continue;

        var data: [table_len]struct { Pubkey, V } = undefined;
        for (generator.map, 0..) |e, i| {
            data[i] = entries[e.?];
        }
        break .{ key, generator.disps, data };
    } else @compileError("could not compute pft");

    return struct {
        pub fn get(target: *const Pubkey) ?V {
            const hashes = Generator.hash(target, key);
            const d1, const d2 = disps[hashes.g % disps.len];
            const index = Generator.displace(hashes.f1, d1, d2) % table_len;
            const entry = data[index];
            if (!entry[0].equals(target)) {
                @branchHint(.unlikely);
                return null;
            }
            return entry[1];
        }
    };
}
