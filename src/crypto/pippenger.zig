//! Implements fast multiscalar multiplication via Pippenger's algorithm
//!
//! See Section 4. of <https://eprint.iacr.org/2012/549.pdf>

const std = @import("std");
const sig = @import("../sig.zig");
const Ed25519 = std.crypto.ecc.Edwards25519;
const CompressedScalar = Ed25519.scalar.CompressedScalar;

const ExtendedPoint = sig.crypto.ExtendedPoint;
const CachedPoint = sig.crypto.CachedPoint;

const u32x8 = @Vector(8, u32);
const i32x8 = @Vector(8, i32);
const u64x4 = @Vector(4, u64);

pub fn mulMulti(
    comptime max_elements: comptime_int,
    compressed_scalars: []const CompressedScalar,
    ed_points: []const Ed25519,
) Ed25519 {
    std.debug.assert(compressed_scalars.len == ed_points.len);
    std.debug.assert(compressed_scalars.len <= max_elements);

    const w: u6 = if (max_elements < 500)
        6
    else if (max_elements < 800)
        7
    else
        8;

    const max_digit = @as(u64, 1) << w;
    const digits_count = radixSizeHint(w);
    const buckets_count = max_digit / 2;

    var scalars: std.BoundedArray([64]i8, max_elements) = .{};
    var points: std.BoundedArray(CachedPoint, max_elements) = .{};

    for (compressed_scalars) |s| {
        scalars.appendAssumeCapacity(asRadix(s, w));
    }
    for (ed_points) |p| {
        points.appendAssumeCapacity(.fromExtended(.fromPoint(p)));
    }

    var columns: [digits_count]ExtendedPoint = undefined;
    var buckets: [buckets_count]ExtendedPoint = @splat(.identityElement);

    for (0..digits_count, &columns) |fwd, *column| {
        const digit_index = digits_count - 1 - fwd;
        @memset(&buckets, .identityElement);

        for (scalars.constSlice(), points.constSlice()) |digits, pt| {
            const digit = digits[digit_index];

            switch (std.math.order(digit, 0)) {
                .gt => {
                    const b: u64 = @intCast(digit - 1);
                    buckets[b] = buckets[b].addCached(pt);
                },
                .lt => {
                    const b: u64 = @intCast(-digit - 1);
                    buckets[b] = buckets[b].subCached(pt);
                },
                .eq => {},
            }
        }

        var buckets_interm_sum = buckets[buckets_count - 1];
        var buckets_sum = buckets[buckets_count - 1];
        for (0..buckets_count - 1) |bucket_fwd| {
            const i = buckets_count - 2 - bucket_fwd;
            buckets_interm_sum = buckets_interm_sum.addCached(.fromExtended(buckets[i]));
            buckets_sum = buckets_sum.addCached(.fromExtended(buckets_interm_sum));
        }

        column.* = buckets_sum;
    }

    var hi_column = columns[0];
    for (columns[1..]) |p| {
        hi_column = mulByPow2(hi_column, w).addCached(.fromExtended(p));
    }
    return hi_column.toPoint();
}

inline fn mulByPow2(p: ExtendedPoint, k: u32) ExtendedPoint {
    var s = p;
    for (0..k) |_| s = s.dbl();
    return s;
}

inline fn radixSizeHint(w: u64) u64 {
    return switch (w) {
        4...7 => (@as(u64, 256) + w - 1) / w,
        8 => (@as(u64, 256) + w - 1) / w + 1,
        else => unreachable,
    };
}

fn asRadix(c: CompressedScalar, w: u6) [64]i8 {
    var scalars: [4]u64 = @splat(0);
    @memcpy(scalars[0..4], std.mem.bytesAsSlice(u64, &c));

    const radix = @as(u64, 1) << w;
    const window_mask = radix - 1;

    var carry: u64 = 0;
    var digits: [64]i8 = @splat(0);
    const digits_count = (@as(u64, 256) + w - 1) / w;

    for (0..digits_count) |i| {
        const bit_offset = i * w;
        const u64_idx = bit_offset / 64;
        const bit_idx: u6 = @truncate(bit_offset);
        const shifted = scalars[u64_idx] >> bit_idx;

        const bit_buf: u64 = if (bit_idx < @as(u64, 64) - w or u64_idx == 3)
            shifted
        else
            shifted | (scalars[1 + u64_idx] << @intCast(@as(u64, 64) - bit_idx));

        const coef = carry + (bit_buf & window_mask);
        carry = (coef + (radix / 2)) >> w;
        const signed_coef: i64 = @bitCast(coef);
        digits[i] = @truncate(signed_coef - @as(i64, @bitCast(carry << w)));
    }
    switch (w) {
        8 => digits[digits_count] += @intCast(@as(i64, @bitCast(carry))),
        else => digits[digits_count - 1] += @intCast(@as(i64, @bitCast(carry << w))),
    }

    return digits;
}
