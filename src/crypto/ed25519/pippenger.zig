//! Implements fast multiscalar multiplication via Pippenger's algorithm
//!
//! See Section 4. of <https://eprint.iacr.org/2012/549.pdf>

const std = @import("std");
const std14 = @import("std14");
const sig = @import("../../sig.zig");
const crypto = std.crypto;
const Ed25519 = crypto.ecc.Edwards25519;
const Ristretto255 = crypto.ecc.Ristretto255;
const CompressedScalar = Ed25519.scalar.CompressedScalar;

const ExtendedPoint = sig.crypto.ed25519.ExtendedPoint;
const CachedPoint = sig.crypto.ed25519.CachedPoint;

fn ReturnType(encoded: bool, ristretto: bool) type {
    const Base = if (ristretto) Ristretto255 else Ed25519;
    return if (encoded) (error{NonCanonical} || crypto.errors.EncodingError)!Base else Base;
}

fn PointType(encoded: bool, ristretto: bool) type {
    if (encoded) return [32]u8;
    return if (ristretto) Ristretto255 else Ed25519;
}

fn asRadix2w(c: CompressedScalar, w: u6) [64]i8 {
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

pub fn mulMultiRuntime(
    comptime max_elements: comptime_int,
    comptime encoded: bool,
    comptime ristretto: bool,
    ed_points: []const PointType(encoded, ristretto),
    compressed_scalars: []const CompressedScalar,
) ReturnType(encoded, ristretto) {
    std.debug.assert(compressed_scalars.len == ed_points.len);
    std.debug.assert(compressed_scalars.len <= max_elements);

    const w: u6 = switch (max_elements) {
        0...499 => 6,
        500...799 => 7,
        else => 8,
    };

    const max_digit = @as(u64, 1) << w;
    const buckets_count = max_digit / 2;
    const digits_count = (@as(u64, 256) + w - 1) / switch (w) {
        4...7 => w,
        8 => w + 1,
        else => unreachable,
    };

    var scalars: std14.BoundedArray([64]i8, max_elements) = .{};
    var points: std14.BoundedArray(CachedPoint, max_elements) = .{};

    for (compressed_scalars) |s| {
        scalars.appendAssumeCapacity(asRadix2w(s, w));
    }
    for (ed_points) |l| {
        // Translate from whatever the input format is to a decompressed Ed25519 point.
        const decompressed = switch (encoded) {
            true => switch (ristretto) {
                true => (try Ristretto255.fromBytes(l)).p,
                else => try Ed25519.fromBytes(l),
            },
            else => switch (ristretto) {
                true => l.p,
                else => l,
            },
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
            interm_sum = interm_sum.add(buckets[i]);
            sum = sum.add(interm_sum);
        }

        column.* = sum;
    }

    var hi_column = columns[0];
    for (columns[1..]) |p| {
        hi_column = hi_column.mulByPow2(w).add(p);
    }

    return switch (ristretto) {
        true => .{ .p = hi_column.toPoint() },
        else => hi_column.toPoint(),
    };
}
