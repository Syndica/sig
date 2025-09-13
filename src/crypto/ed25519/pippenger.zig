//! Implements fast multiscalar multiplication via Pippenger's algorithm
//!
//! See Section 4. of <https://eprint.iacr.org/2012/549.pdf>

const std = @import("std");
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

pub fn mulMulti(
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

    var scalars: std.BoundedArray([64]i8, max_elements) = .{};
    var points: std.BoundedArray(CachedPoint, max_elements) = .{};

    for (compressed_scalars) |s| {
        scalars.appendAssumeCapacity(sig.crypto.ed25519.asRadix2w(s, w));
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
