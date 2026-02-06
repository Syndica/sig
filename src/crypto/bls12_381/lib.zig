const std = @import("std");
const c = @import("blst").c;
pub const tests = @import("tests.zig");

/// We do not need to provide any more granular errors than a simple pass/fail.
const Error = error{Failed};

const Scalar = struct {
    scalar: c.scalar,

    fn fromBytes(bytes: *const [32]u8, endian: std.builtin.Endian) Error!Scalar {
        var scalar: c.scalar = undefined;
        switch (endian) {
            .little => c.scalar_from_lendian(&scalar, bytes),
            .big => c.scalar_from_bendian(&scalar, bytes),
        }
        if (!c.scalar_fr_check(&scalar)) return error.Failed;
        return .{ .scalar = scalar };
    }
};

pub const G1 = Definition(
    c.p1,
    c.p1_affine,
    c.fp,
    96,
    .{
        .uncompress = c.p1_uncompress,
        .deserialize = c.p1_deserialize,
        .serialize = c.p1_serialize,
        .affine_in_group = c.p1_affine_in_g1,
        .affine_serialize = c.p1_affine_serialize,
        .from_affine = c.p1_from_affine,
        .add = c.p1_add_or_double_affine,
        .cneg = c.fp_cneg,
        .mult = c.p1_mult,
    },
);

pub const G2 = Definition(
    c.p2,
    c.p2_affine,
    c.fp2,
    192,
    .{
        .uncompress = c.p2_uncompress,
        .deserialize = c.p2_deserialize,
        .serialize = c.p2_serialize,
        .affine_in_group = c.p2_affine_in_g2,
        .affine_serialize = c.p2_affine_serialize,
        .from_affine = c.p2_from_affine,
        .add = c.p2_add_or_double_affine,
        .cneg = c.fp2_cneg,
        .mult = c.p2_mult,
    },
);

fn Definition(
    Point: type,
    Aff: type,
    Fp: type,
    size: u32,
    comptime api: struct {
        uncompress: fn (*Aff, [*]const u8) callconv(.c) u32,
        deserialize: fn (*Aff, [*]const u8) callconv(.c) u32,
        serialize: fn ([*]u8, *const Point) callconv(.c) void,
        affine_in_group: fn (*const Aff) callconv(.c) bool,
        affine_serialize: fn ([*]u8, *const Aff) callconv(.c) void,
        from_affine: fn (*Point, *const Aff) callconv(.c) void,
        add: fn (*Point, *const Point, *const Aff) callconv(.c) void,
        cneg: fn (*Fp, *const Fp, bool) callconv(.c) void,
        mult: fn (*Point, *const Point, [*]const u8, u64) callconv(.c) void,
    },
) type {
    return struct {
        p: Point,

        const Self = @This();

        const Affine = struct {
            p: Aff,

            fn fromBytesUnchecked(bytes: *const [size]u8, endian: std.builtin.Endian) Error!Affine {
                const in = switch (endian) {
                    .little => bswap(bytes),
                    .big => bytes.*,
                };
                var r: Aff = undefined;
                if (api.deserialize(&r, &in) != c.SUCCESS) return error.Failed;
                return .{ .p = r };
            }
            fn fromBytes(bytes: *const [size]u8, endian: std.builtin.Endian) Error!Affine {
                const a = try fromBytesUnchecked(bytes, endian);
                if (!api.affine_in_group(&a.p)) return error.Failed;
                return a;
            }
        };

        pub fn validate(in: *const [size]u8, endian: std.builtin.Endian) Error!void {
            _ = try Affine.fromBytes(in, endian);
        }

        pub fn decompress(
            bytes: *const [size / 2]u8,
            out: *[size]u8,
            endian: std.builtin.Endian,
        ) Error!void {
            const in = switch (endian) {
                .little => bswapElement(bytes),
                .big => bytes.*,
            };

            var r: Aff = undefined;
            // Decompress the element and serialize.
            if (api.uncompress(&r, &in) != c.SUCCESS) return error.Failed;
            if (!api.affine_in_group(&r)) return error.Failed;
            api.affine_serialize(out, &r);

            if (endian == .little) out.* = bswap(out);
        }

        pub fn add(
            out: *[size]u8,
            a: *const [size]u8,
            b: *const [size]u8,
            endian: std.builtin.Endian,
        ) Error!void {
            // As per SIMD-0388, points x and y remain unchecked.
            const x = try Affine.fromBytesUnchecked(a, endian);
            const y = try Affine.fromBytesUnchecked(b, endian);
            const p: Self = .fromAffine(x);

            var r: Self = .{ .p = undefined };
            api.add(&r.p, &p.p, &y.p);
            r.toBytes(out, endian);
        }

        pub fn subtract(
            out: *[size]u8,
            a: *const [size]u8,
            b: *const [size]u8,
            endian: std.builtin.Endian,
        ) Error!void {
            // As per SIMD-0388, points x and y remain unchecked.
            const x = try Affine.fromBytesUnchecked(a, endian);
            var y = try Affine.fromBytesUnchecked(b, endian);
            const p: Self = .fromAffine(x);

            api.cneg(&y.p.y, &y.p.y, true); // Negate y

            var r: Self = .{ .p = undefined };
            api.add(&r.p, &p.p, &y.p);
            r.toBytes(out, endian);
        }

        pub fn multiply(
            out: *[size]u8,
            n: *const [32]u8,
            a: *const [size]u8,
            endian: std.builtin.Endian,
        ) Error!void {
            // Both `x` and `y` are validated per SIMD-0388.
            const x = try Affine.fromBytes(a, endian);
            const y = try Scalar.fromBytes(n, endian);
            const p: Self = .fromAffine(x);

            var r: Self = .{ .p = undefined };
            api.mult(&r.p, &p.p, &y.scalar.b, 255);
            r.toBytes(out, endian);
        }

        fn bswapElement(in: *const [size / 2]u8) [size / 2]u8 {
            const p: std.meta.Int(.unsigned, size * 4) = @bitCast(in.*);
            return @bitCast(@byteSwap(p));
        }

        fn bswap(in: *const [size]u8) [size]u8 {
            const x = bswapElement(in[0 .. size / 2]);
            const y = bswapElement(in[size / 2 .. size]);
            return x ++ y;
        }

        fn fromAffine(a: Affine) Self {
            var r: Point = undefined;
            api.from_affine(&r, &a.p);
            return .{ .p = r };
        }

        fn toBytes(p: *const Self, out: *[size]u8, endian: std.builtin.Endian) void {
            api.serialize(out, &p.p);
            if (endian == .little) out.* = bswap(out);
        }
    };
}

const BATCH_SIZE = 8;

pub fn pairingSyscall(
    out: *[48 * 12]u8,
    a: []const u8,
    b: []const u8,
    n: u64,
    endian: std.builtin.Endian,
) Error!void {
    if (n > BATCH_SIZE) return error.Failed; // hard limit on number of pairings allowed

    var g1: [BATCH_SIZE]c.p1_affine = undefined;
    var g2: [BATCH_SIZE]c.p2_affine = undefined;
    var g1_ptr: [BATCH_SIZE]*const c.p1_affine = undefined;
    var g2_ptr: [BATCH_SIZE]*const c.p2_affine = undefined;

    for (0..n) |i| {
        const w = try G1.Affine.fromBytes(a[96 * i ..][0..96], endian);
        const z = try G2.Affine.fromBytes(b[96 * 2 * i ..][0..192], endian);
        g1[i] = w.p;
        g2[i] = z.p;
        g1_ptr[i] = &g1[i];
        g2_ptr[i] = &g2[i];
    }

    var r: c.fp12 = c.fp12_one().*;
    if (n > 0) {
        @branchHint(.likely);
        c.miller_loop_n(&r, &g2_ptr, &g1_ptr, n);
        c.final_exp(&r, &r);
    }

    for (0..12) |i| {
        const offset = switch (endian) {
            .little => i,
            .big => (12 - 1 - i),
        };
        const func = &switch (endian) {
            .little => c.lendian_from_fp,
            .big => c.bendian_from_fp,
        };
        func(out[48 * offset ..][0..48], &r.fp6[i / 6].fp2[(i / 2) % 3].fp[i % 2]);
    }
}
