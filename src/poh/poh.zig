const std = @import("std");
const sig = @import("../sig.zig");

const Hash = sig.core.Hash;

/// Tracks the latest hash value and tick counts, and updates it with new hashes
pub const Poh = struct {
    /// Latest hash value
    hash: Hash,
    /// Number of hashes since the last entry
    num_hashes: u64 = 0,
    /// Static number of hashes expected between tick entries
    hashes_per_tick: u64,
    /// Current remaining number of hashes until the next tick
    remaining_hashes: u64,
    /// Counter for the number of ticks that happened so far
    tick_number: u64 = 0,
    // slot_start_time: sig.time.Instant,

    const Self = @This();

    pub fn init(start_hash: Hash, hashes_per_tick: u64) Self {
        return Self{
            .hash = start_hash,
            .hashes_per_tick = hashes_per_tick,
            .remaining_hashes = hashes_per_tick,
        };
    }

    /// re-hash the existing hash repeatedly without any mixin hashes.
    ///
    /// stops hashing when it hashes up to as many times as either:
    /// - state `self.remaining_hashes - 1`
    /// - parameter `max_num_hashes`
    pub fn runHash(self: *Self, max_num_hashes: u64) bool {
        const num_hashes = @min(self.remaining_hashes -| 1, max_num_hashes);
        for (0..num_hashes) |_| {
            rehash(&self.hash, null);
        }
        self.num_hashes += num_hashes;
        self.remaining_hashes -= num_hashes;

        if (self.remaining_hashes == 0) {
            @panic("hashed too many times");
        }
        return self.remaining_hashes == 1;
    }

    /// Calculate the hash for an entry containing a mixin hash, such as a
    /// transaction record
    ///
    /// If this returns null, that means you need to tick first and then try /
    //processing this record again.
    pub fn record(self: *Self, mixin: Hash) ?PohEntry {
        if (self.remaining_hashes == 1) {
            return null; // needs a tick first
        }

        rehash(&self.hash, mixin);
        const num_hashes = self.num_hashes + 1;
        self.num_hashes = 0;
        self.remaining_hashes -= 1;

        return PohEntry{
            .num_hashes = num_hashes,
            .hash = self.hash,
        };
    }

    /// Calculate the hash for a tick entry, without a mixin hash, and increment
    /// the tick counter
    pub fn tick(self: *Self) ?PohEntry {
        rehash(&self.hash, null);
        self.num_hashes += 1;
        self.remaining_hashes -= 1;

        // not addressing low power mode
        if (self.remaining_hashes != 0) {
            return null;
        }

        const num_hashes = self.num_hashes;
        self.remaining_hashes = self.hashes_per_tick;
        self.num_hashes = 0;
        self.tick_number += 1;

        return PohEntry{
            .num_hashes = num_hashes,
            .hash = self.hash,
        };
    }
};

/// The output from a sequence of hashes
pub const PohEntry = struct {
    /// Number of hashes since the previous entry this is derived from
    num_hashes: u64,
    /// The final resulting hash from this sequence
    hash: Hash,
};

/// Overwrites the current hash value with the hash of itself plus a mixin (if provided)
pub fn rehash(prior: *Hash, maybe_mixin: ?Hash) void {
    prior.* = if (maybe_mixin) |mixin|
        Hash.extendAndHash(prior.*, &mixin.data)
    else
        Hash.generateSha256Hash(&prior.data);
}
