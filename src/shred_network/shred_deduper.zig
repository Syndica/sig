// const std = @import("std");
// const sig = @import("../sig.zig");

// const AtomicBool = std.atomic.Value(bool);
// const AtomicU64 = std.atomic.Value(u64);

// const ChaCha = sig.crypto.ChaCha(.twenty);
// const ShredId = sig.ledger.shred.ShredId;
// const Duration = sig.time.Duration;
// const Deduper = sig.utils.deduper.Deduper;

// const uintLessThanRust = sig.rand.weighted_shuffle.uintLessThanRust;

// /// ShredDedupResult is an enum representing the result of deduplicating a shred.
// pub const ShredDedupResult = enum {
//     byte_duplicate,
//     shred_id_duplicate,
//     not_duplicate,
// };

// /// ShredDeduper is a deduplicator which filters out duplicate shreds based
// /// on their raw bytes, and also filters out shreds based on their ShredId
// /// up to a maximum number of duplicates.
// pub const ShredDeduper = struct {
//     byte_filter: BytesFilter,
//     shred_id_filter: ShredIdFilter,

//     const BytesFilter = Deduper([]const u8);
//     const ShredIdFilter = Deduper(ShredIdFilterKey);
//     const ShredIdFilterKey = struct { id: ShredId, index: usize };

//     pub fn init(
//         allocator: std.mem.Allocator,
//         chacha: *ChaCha,
//         num_bits: u64,
//     ) !ShredDeduper {
//         return .{
//             .byte_filter = try .init(allocator, chacha, num_bits),
//             .shred_id_filter = try .init(allocator, chacha, num_bits),
//         };
//     }

//     pub fn deinit(self: *ShredDeduper, allocator: std.mem.Allocator) void {
//         self.byte_filter.deinit(allocator);
//         self.shred_id_filter.deinit(allocator);
//     }

//     /// Reset the deduper filters if they are saturated or have reached their reset cycle.
//     /// Return a tuple of booleans indicating whether the byte_filter and the shred_id_filter
//     /// were saturated respectively.
//     pub fn maybeReset(
//         self: *ShredDeduper,
//         chacha: *ChaCha,
//         false_positive_rate: f64,
//         reset_cycle: Duration,
//     ) struct { bool, bool } {
//         return .{
//             self.byte_filter.maybeReset(chacha, false_positive_rate, reset_cycle),
//             self.shred_id_filter.maybeReset(chacha, false_positive_rate, reset_cycle),
//         };
//     }

//     /// Deduplicate a shred based on its raw bytes and ShredId up to a maximum number of duplicates.
//     /// Return a tuple of booleans, the first indicating whether the shred was a duplicated, and the second
//     /// indicating if it was a shred id duplicate
//     pub fn dedup(
//         self: *ShredDeduper,
//         shred_id: *const ShredId,
//         shred_bytes: []const u8,
//         max_duplicate_count: usize,
//     ) ShredDedupResult {
//         if (self.byte_filter.dedup(&shred_bytes)) return .byte_duplicate;
//         for (0..max_duplicate_count) |i| {
//             if (!self.shred_id_filter.dedup(&.{ .id = shred_id.*, .index = i }))
//                 return .not_duplicate;
//         }
//         return .shred_id_duplicate;
//     }
// };

// /// Test method from agave.
// /// Checks that the deduper produces the expected number of duplicates and popcount
// /// when seeded with a specific seed.
// fn testDedupSeeded(
//     seed: [32]u8,
//     num_bits: u64,
//     num_shreds: usize,
//     num_dups: usize,
//     bytes_popcount: u64,
//     shred_id_popcount: u64,
//     max_duplicate_count: usize,
// ) !void {
//     var chacha: ChaCha = .init(seed);

//     var deduper = try ShredDeduper(2).init(std.testing.allocator, &chacha, num_bits);
//     defer deduper.deinit();

//     var dup_count: usize = 0;
//     for (0..num_shreds) |_| {
//         const slot = chacha.roll(.shift, 1000);
//         const index: u32 = @truncate(chacha.roll(.shift, 10));

//         var payload = [_]u8{0} ** 16;
//         rng.bytes(&payload);

//         const shred_id = ShredId{ .slot = slot, .index = index, .shred_type = .data };
//         if (.not_duplicate != deduper.dedup(
//             &shred_id,
//             &payload,
//             max_duplicate_count,
//         )) dup_count += 1;
//     }

//     try std.testing.expectEqual(num_dups, dup_count);
//     try std.testing.expectEqual(
//         bytes_popcount,
//         deduper.byte_filter.masked_count.load(.monotonic),
//     );
//     try std.testing.expectEqual(
//         shred_id_popcount,
//         deduper.shred_id_filter.masked_count.load(.monotonic),
//     );
// }

// test "agave: dedup seeded" {
//     try testDedupSeeded([_]u8{0xf9} ** 32, 3_199_997, 51_414, 15_429, 101_207, 71_197, 4);
//     if (sig.build_options.long_tests) {
//         try testDedupSeeded([_]u8{0xdc} ** 32, 3_200_003, 51_414, 15_452, 101_259, 71_103, 4);
//         try testDedupSeeded([_]u8{0xa5} ** 32, 6_399_971, 102_828, 62_932, 202_433, 79_334, 4);
//         try testDedupSeeded([_]u8{0xdb} ** 32, 6_400_013, 102_828, 82_830, 202_356, 39_874, 2);
//         try testDedupSeeded([_]u8{0xcd} ** 32, 12_799_987, 404_771, 384_771, 784_600, 39_936, 2);
//         try testDedupSeeded([_]u8{0xc3} ** 32, 12_800_009, 404_771, 384_771, 784_563, 39_932, 2);
//     }
// }

// test "agave: test already received" {
//     const MAX_DUPLICATE_COUNT = 2;

//     var chacha = ChaChaRng.fromSeed([_]u8{0xa5} ** 32);
//     const rng = chacha.random();

//     var deduper = try ShredDeduper(2).init(std.testing.allocator, rng, 640_007);
//     defer deduper.deinit();

//     const data_shred_id = ShredId{ .slot = 1, .index = 5, .shred_type = .data };
//     var data_payload = [_]u8{0} ** 16;
//     rng.bytes(&data_payload);

//     // unique data shred for (1, 5) should pass
//     try std.testing.expectEqual(.not_duplicate, deduper.dedup(
//         &data_shred_id,
//         &data_payload,
//         MAX_DUPLICATE_COUNT,
//     ));

//     // duplicate bytes blocked
//     try std.testing.expectEqual(.byte_duplicate, deduper.dedup(
//         &data_shred_id,
//         &data_payload,
//         MAX_DUPLICATE_COUNT,
//     ));

//     // first duplicate data shred for (1, 5) passed
//     rng.bytes(&data_payload);
//     try std.testing.expectEqual(.not_duplicate, deduper.dedup(
//         &data_shred_id,
//         &data_payload,
//         MAX_DUPLICATE_COUNT,
//     ));
//     // duplicate bytes blocked
//     try std.testing.expectEqual(.byte_duplicate, deduper.dedup(
//         &data_shred_id,
//         &data_payload,
//         MAX_DUPLICATE_COUNT,
//     ));

//     // second duplicate data shred for (1, 5) blocked
//     rng.bytes(&data_payload);
//     try std.testing.expectEqual(.shred_id_duplicate, deduper.dedup(
//         &data_shred_id,
//         &data_payload,
//         MAX_DUPLICATE_COUNT,
//     ));

//     const code_shred_id = ShredId{ .slot = 1, .index = 5, .shred_type = .code };
//     var code_payload = [_]u8{0} ** 16;
//     rng.bytes(&code_payload);

//     // unique code shred at (1, 5) passes
//     try std.testing.expectEqual(.not_duplicate, deduper.dedup(
//         &code_shred_id,
//         &code_payload,
//         MAX_DUPLICATE_COUNT,
//     ));
//     // duplicate bytes blocked
//     try std.testing.expectEqual(.byte_duplicate, deduper.dedup(
//         &code_shred_id,
//         &code_payload,
//         MAX_DUPLICATE_COUNT,
//     ));

//     // first duplicate code shred for (1, 5) passed
//     rng.bytes(&code_payload);
//     try std.testing.expectEqual(.not_duplicate, deduper.dedup(
//         &code_shred_id,
//         &code_payload,
//         MAX_DUPLICATE_COUNT,
//     ));
//     // duplicate bytes blocked
//     try std.testing.expectEqual(.byte_duplicate, deduper.dedup(
//         &code_shred_id,
//         &code_payload,
//         MAX_DUPLICATE_COUNT,
//     ));

//     // second duplicate code shred for (1, 5) blocked
//     rng.bytes(&code_payload);
//     try std.testing.expectEqual(.shred_id_duplicate, deduper.dedup(
//         &code_shred_id,
//         &code_payload,
//         MAX_DUPLICATE_COUNT,
//     ));
// }
