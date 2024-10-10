const std = @import("std");
const sig = @import("../sig.zig");

const AtomicBool = std.atomic.Value(bool);
const AtomicU64 = std.atomic.Value(u64);

const ShredId = sig.ledger.shred.ShredId;
const Duration = sig.time.Duration;
const Deduper = sig.utils.deduper.Deduper;

/// ShredDedupResult is an enum representing the result of deduplicating a shred.
pub const ShredDedupResult = enum {
    ByteDuplicate,
    ShredIdDuplicate,
    NotDuplicate,
};

/// ShredDeduper is a deduplicator which filters out duplicate shreds based
/// on their raw bytes, and also filters out shreds based on their ShredId
/// up to a maximum number of duplicates.
pub fn ShredDeduper(comptime K: usize) type {
    return struct {
        byte_filter: BytesFilter,
        shred_id_filter: ShredIdFilter,

        const BytesFilter = Deduper(K, []const u8);
        const ShredIdFilter = Deduper(K, ShredIdFilterKey);
        const ShredIdFilterKey = struct { id: ShredId, index: usize };

        pub fn init(allocator: std.mem.Allocator, rand: std.rand.Random, num_bits: u64) !ShredDeduper(K) {
            return .{
                .byte_filter = try BytesFilter.init(allocator, rand, num_bits),
                .shred_id_filter = try ShredIdFilter.init(allocator, rand, num_bits),
            };
        }

        pub fn deinit(self: *ShredDeduper(K)) void {
            self.byte_filter.deinit();
            self.shred_id_filter.deinit();
        }

        /// Reset the deduper filters if they are saturated or have reached their reset cycle.
        /// Return a tuple of booleans indicating whether the byte_filter and the shred_id_filter
        /// were saturated respectively.
        pub fn maybeReset(self: *ShredDeduper(K), rand: std.rand.Random, false_positive_rate: f64, reset_cycle: Duration) struct { bool, bool } {
            const byte_filter_saturated = self.byte_filter
                .maybeReset(rand, false_positive_rate, reset_cycle);
            const shred_id_filter_saturated = self.shred_id_filter
                .maybeReset(rand, false_positive_rate, reset_cycle);
            return .{ byte_filter_saturated, shred_id_filter_saturated };
        }

        /// Deduplicate a shred based on its raw bytes and ShredId up to a maximum number of duplicates.
        /// Return a tuple of booleans, the first indicating whether the shred was a duplicated, and the second
        /// indicating if it was a shred id duplicate
        pub fn dedup(self: *ShredDeduper(K), shred_id: *const ShredId, shred_bytes: []const u8, max_duplicate_count: usize) ShredDedupResult {
            if (self.byte_filter.dedup(&shred_bytes)) return .ByteDuplicate;
            for (0..max_duplicate_count) |i| {
                if (!self.shred_id_filter.dedup(&.{ .id = shred_id.*, .index = i })) return .NotDuplicate;
            }
            return .ShredIdDuplicate;
        }
    };
}

// TODO: Testing
