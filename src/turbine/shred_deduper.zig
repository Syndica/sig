const std = @import("std");
const sig = @import("../sig.zig");

const AtomicBool = std.atomic.Value(bool);
const AtomicU64 = std.atomic.Value(u64);

const ShredId = sig.ledger.shred.ShredId;
const Duration = sig.time.Duration;
const Deduper = sig.utils.deduper.Deduper;

pub fn ShredDeduper(comptime K: usize) type {
    return struct {
        bytes_filter: BytesFilter,
        shred_id_filter: ShredIdFilter,

        const BytesFilter = Deduper(K, []const u8);
        const ShredIdFilter = Deduper(K, ShredIdFilterKey);
        const ShredIdFilterKey = struct { id: ShredId, index: usize };

        pub fn init(allocator: std.mem.Allocator, rand: std.rand.Random, num_bits: u64) !ShredDeduper(K) {
            return .{
                .bytes_filter = try BytesFilter.init(allocator, rand, num_bits),
                .shred_id_filter = try ShredIdFilter.init(allocator, rand, num_bits),
            };
        }

        pub fn deinit(self: *ShredDeduper(K)) void {
            self.bytes_filter.deinit();
            self.shred_id_filter.deinit();
        }

        pub fn maybeReset(self: *ShredDeduper(K), rand: std.rand.Random, false_positive_rate: f64, reset_cycle: Duration) void {
            _ = self.bytes_filter
                .maybeReset(rand, false_positive_rate, reset_cycle);
            _ = self.shred_id_filter
                .maybeReset(rand, false_positive_rate, reset_cycle);
        }

        pub fn dedup(self: *ShredDeduper(K), shred_id: *const ShredId, shred_bytes: []const u8, max_duplicate_count: usize) bool {
            if (self.bytes_filter.dedup(&shred_bytes)) return true;
            for (0..max_duplicate_count) |i| {
                if (!self.shred_id_filter.dedup(&.{ .id = shred_id.*, .index = i })) return false;
            }
            return true;
        }
    };
}

// TODO: Testing
