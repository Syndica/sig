//! Implements fast multiscalar multiplication via Pippenger's algorithm
//!
//! See Section 4. of <https://eprint.iacr.org/2012/549.pdf>

const std = @import("std");
const sig = @import("../sig.zig");
const crypto = std.crypto;
const Ed25519 = crypto.ecc.Edwards25519;
const CompressedScalar = Ed25519.scalar.CompressedScalar;

const ExtendedPoint = sig.crypto.ExtendedPoint;
const CachedPoint = sig.crypto.CachedPoint;

pub fn mulMulti(
    comptime max_elements: comptime_int,
    comptime encoded: bool,
    ed_points: []const if (encoded) Ed25519 else [32]u8,
    compressed_scalars: []const CompressedScalar,
) if (encoded) Ed25519 else crypto.errors.EncodingError!Ed25519 {
    std.debug.assert(compressed_scalars.len == ed_points.len);
    std.debug.assert(compressed_scalars.len <= max_elements);

    const w: u6 = if (max_elements < 500)
        6
    else if (max_elements < 800)
        7
    else
        8;

    const max_digit = @as(u64, 1) << w;
    const buckets_count = max_digit / 2;
    const digits_count = (@as(u64, 256) + w - 1) / switch (w) {
        4...7 => w,
        8 => w + 1,
        else => unreachable,
    };

    var scalars: std.BoundedArray([64]i8, max_elements) = .{};
    var points: std.BoundedArray(CachedPoint, max_elements) = .{};

    for (compressed_scalars) |s| {
        scalars.appendAssumeCapacity(asRadix(s, w));
    }
    for (ed_points) |l| {
        const decompressed = switch (encoded) {
            true => l,
            else => try Ed25519.fromBytes(l),
        };
        points.appendAssumeCapacity(.fromExtended(.fromPoint(decompressed)));
    }

    var columns: [digits_count]ExtendedPoint = undefined;
    var buckets: [buckets_count]ExtendedPoint = @splat(.identityElement);

    for (0..digits_count, &columns) |fwd, *column| {
        const digit_index = digits_count - 1 - fwd;
        @memset(&buckets, .identityElement);

        for (scalars.constSlice(), points.constSlice()) |digits, pt| {
            const digit: i16 = digits[digit_index]; // avoid issues when w is 8
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

        var interm_sum = buckets[buckets_count - 1];
        var sum = buckets[buckets_count - 1];
        for (0..buckets_count - 1) |bucket_fwd| {
            const i = buckets_count - 2 - bucket_fwd;
            interm_sum = interm_sum.addCached(.fromExtended(buckets[i]));
            sum = sum.addCached(.fromExtended(interm_sum));
        }

        column.* = sum;
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

fn asRadix(c: CompressedScalar, w: u6) [64]i8 {
    var scalars: [4]u64 = @splat(0);
    @memcpy(scalars[0..4], std.mem.bytesAsSlice(u64, &c));

    const radix = @as(u64, 1) << w;
    const window_mask = radix - 1;

    var carry: u64 = 0;
    const digits_count = (@as(u64, 256) + w - 1) / w;
    var digits: [64]i8 = @splat(0);

    for (0..digits_count) |i| {
        const bit_offset = i * w;
        const u64_idx = bit_offset / 64;
        const bit_idx: u6 = @truncate(bit_offset);
        const element = scalars[u64_idx] >> bit_idx;

        const below = bit_idx < @as(u64, 64) - w or u64_idx == 3;
        const bit_buf: u64 = switch (below) {
            true => element,
            else => element | (scalars[1 + u64_idx] << @intCast(@as(u64, 64) - bit_idx)),
        };

        const coef = carry + (bit_buf & window_mask);
        carry = (coef + (radix / 2)) >> w;
        const signed_coef: i64 = @bitCast(coef);
        const cindex: i64 = @bitCast(carry << w);
        digits[i] = @truncate(signed_coef - cindex);
    }

    switch (w) {
        8 => digits[digits_count] += @intCast(@as(i64, @bitCast(carry))),
        else => digits[digits_count - 1] += @intCast(@as(i64, @bitCast(carry << w))),
    }

    return digits;
}
