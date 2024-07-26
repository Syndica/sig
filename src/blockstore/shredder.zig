const std = @import("std");
const sig = @import("../lib.zig");

const Allocator = std.mem.Allocator;

const Lru = sig.common.lru.LruCacheCustom;
const ReedSolomon = sig.blockstore.reed_solomon.ReedSolomon;

const DATA_SHREDS_PER_FEC_BLOCK = sig.shred_collector.shred.DATA_SHREDS_PER_FEC_BLOCK;

pub const ReedSolomonCache = struct {
    cache: Cache,
    const Cache = Lru(
        .locking,
        struct { data: usize, parity: usize },
        ReedSolomon,
        void,
        ReedSolomon.deinit,
    );

    const Self = @This();

    pub fn init(allocator: Allocator) Allocator.Error!Self {
        return .{ .cache = try Cache.init(allocator, 4 * DATA_SHREDS_PER_FEC_BLOCK) };
    }

    pub fn deinit(self: *Self) void {
        self.cache.deinit();
    }

    /// Caller owns the ReedSolomon. Call `ReedSolomon.deinit` when done.
    pub fn get(self: *Self, data_shards: usize, parity_shards: usize) ReedSolomon {
        if (self.cache.get(.{ .data = data_shards, .parity = parity_shards })) |rs| {
            if (rs.acquire()) {
                return rs;
            }
        }
        const rs = try ReedSolomon.init(self.cache.allocator, data_shards, parity_shards);
        _ = rs.acquire();
        self.cache.put(.{ .data = data_shards, .parity = parity_shards }, rs);
        return rs;
    }
};
