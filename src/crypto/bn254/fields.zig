const std = @import("std");
const fiat = @import("bn254_64.zig");
const bn254 = @import("lib.zig");

pub const Flags = packed struct(u8) {
    _padding: u6,
    is_inf: bool,
    is_neg: bool,

    pub const INF: u8 = 1 << 6;
    pub const NEG: u8 = 1 << 7;
    pub const MASK: u8 = 0b00111111;
};

pub const Fp = struct {
    limbs: [4]u64,

    pub const zero: Fp = .{ .limbs = @splat(0) };
    pub const one = one: {
        var fp: Fp = undefined;
        fiat.setOne(&fp.limbs);
        break :one fp;
    };

    pub const constants = struct {
        /// Field order of the curve.
        const p: u256 = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;
        const p_limbs: [4]u64 = @bitCast(p);

        const p_minus_2: u256 = p - 2;
        const p_minus_1_half = (p - 1) / 2;
        const sqrt_exp: u256 = (p - 3) / 4;

        pub const b_mont: Fp = fromInt(3);
        const p_minus_one_mont: Fp = fromInt(p - 1);

        pub const frob_gamma2_mont: [5]Fp = .{
            .{ .limbs = .{
                0xca8d800500fa1bf2,
                0xf0c5d61468b39769,
                0x0e201271ad0d4418,
                0x04290f65bad856e6,
            } },
            .{ .limbs = .{
                0x3350c88e13e80b9c,
                0x7dce557cdb5e56b9,
                0x6001b4b8b615564a,
                0x2682e617020217e0,
            } },
            .{ .limbs = .{
                0x68c3488912edefaa,
                0x8d087f6872aabf4f,
                0x51e1a24709081231,
                0x2259d6b14729c0fa,
            } },
            .{ .limbs = .{
                0x71930c11d782e155,
                0xa6bb947cffbe3323,
                0xaa303344d4741444,
                0x2c3b3f0d26594943,
            } },
            .{ .limbs = .{
                0x08cfc388c494f1ab,
                0x19b315148d1373d4,
                0x584e90fdcb6c0213,
                0x09e1685bdf2f8849,
            } },
        };

        pub const x: u256 = 0x44e992b44a6909f1;
    };

    /// Int to mont form.
    /// NOTE: only used for testing and generating constants, doesn't perform any checks
    fn fromInt(comptime v: u256) Fp {
        var bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &bytes, v, .little);

        var limbs_z: [4]u64 = undefined;
        fiat.fromBytes(&limbs_z, bytes);
        var limbs: [4]u64 = undefined;
        fiat.toMontgomery(&limbs, limbs_z);

        return .{ .limbs = limbs };
    }

    pub fn fromBytes(
        input: *const [32]u8,
        endian: std.builtin.Endian,
        maybe_flags: ?*Flags,
    ) !Fp {
        if (maybe_flags) |flags| {
            const offset: u32 = switch (endian) {
                .big => 0,
                .little => 31,
            };
            flags.* = @bitCast(input[offset]);
            // If both flags are set, return an error.
            // https://github.com/arkworks-rs/algebra/blob/v0.4.2/ec/src/models/short_weierstrass/serialization_flags.rs#L75
            if (flags.is_inf and flags.is_neg) return error.BothFlags;
        }

        var limbs: [32]u8 = switch (endian) {
            .big => byteSwap(input.*),
            .little => input.*,
        };
        // NOTE: We perform the mask *after* the byteSwap, so we don't need to select the offset for the mask again.
        if (maybe_flags != null) limbs[31] &= Flags.MASK;

        // Check that we've decoded a valid field element.
        const integer: u256 = @bitCast(limbs);
        if (integer >= constants.p) return error.TooLarge;

        return .{ .limbs = @bitCast(limbs) };
    }

    pub fn toBytes(f: Fp, out: *[32]u8, endian: std.builtin.Endian) void {
        out.* = switch (endian) {
            .little => @bitCast(f.limbs),
            .big => byteSwap(@bitCast(f.limbs)),
        };
    }

    pub fn byteSwap(a: [32]u8) [32]u8 {
        const limbs: [4]u64 = @bitCast(a);
        const array: [4]u64 = .{
            @byteSwap(limbs[3]),
            @byteSwap(limbs[2]),
            @byteSwap(limbs[1]),
            @byteSwap(limbs[0]),
        };
        return @bitCast(array);
    }

    /// Well-defined for both montgomery and normal form.
    pub fn isZero(f: Fp) bool {
        return f.eql(.zero);
    }

    pub fn isOne(f: Fp) bool {
        return f.eql(.one);
    }

    pub fn isNegative(f: Fp) bool {
        const x: u256 = @bitCast(f.limbs);
        return x > constants.p_minus_1_half;
    }

    pub fn eql(a: Fp, b: Fp) bool {
        const p: @Vector(4, u64) = a.limbs;
        const q: @Vector(4, u64) = b.limbs;
        return @reduce(.And, p == q);
    }

    pub fn add(a: Fp, b: Fp) Fp {
        var r: Fp = undefined;
        fiat.add(&r.limbs, a.limbs, b.limbs);
        return r;
    }

    pub fn sub(a: Fp, b: Fp) Fp {
        var r: Fp = undefined;
        fiat.sub(&r.limbs, a.limbs, b.limbs);
        return r;
    }

    pub fn mul(a: Fp, b: Fp) Fp {
        var r: Fp = undefined;
        fiat.mul(&r.limbs, a.limbs, b.limbs);
        return r;
    }

    pub fn dbl(a: Fp) Fp {
        return a.add(a);
    }

    pub fn triple(a: Fp) Fp {
        return a.dbl().add(a);
    }

    pub fn sq(a: Fp) Fp {
        return a.mul(a);
    }

    pub fn halve(a: Fp) Fp {
        const is_odd = a.limbs[0] & 0x1 != 0;
        const b: u256 = @bitCast(a.limbs);
        var limbs: [4]u64 = @bitCast(b + if (is_odd) constants.p else 0);
        limbs = @bitCast(b + if (is_odd) constants.p else 0);
        limbs[0] = (limbs[0] >> 1) | (limbs[1] << 63);
        limbs[1] = (limbs[1] >> 1) | (limbs[2] << 63);
        limbs[2] = (limbs[2] >> 1) | (limbs[3] << 63);
        limbs[3] >>= 1;
        return .{ .limbs = @bitCast(limbs) };
    }

    pub fn pow(a: Fp, comptime n: u256) Fp {
        const limbs: [4]u64 = @bitCast(n);
        var r = one;
        var i: u8 = 255 - @clz(n);
        while (true) {
            r = r.sq();
            if (bn254.bit(limbs, i)) r = r.mul(a);
            if (i == 0) break;
            i -= 1;
        }
        return r;
    }

    pub fn inverse(a: Fp) Fp {
        return a.pow(constants.p_minus_2);
    }

    /// Alg. 2, https://eprint.iacr.org/2012/685
    pub fn sqrt(a: Fp) !Fp {
        const c1: Fp = a.pow(constants.sqrt_exp);
        const c0 = c1.sq().mul(a);
        if (c0.eql(constants.p_minus_one_mont)) return error.NotSquare;
        return c1.mul(a);
    }

    pub fn toMont(r: *Fp) void {
        fiat.toMontgomery(&r.limbs, r.limbs);
    }

    pub fn fromMont(r: *Fp) void {
        fiat.fromMontgomery(&r.limbs, r.limbs);
    }

    pub fn negate(a: Fp) Fp {
        var r: Fp = undefined;
        fiat.opp(&r.limbs, a.limbs);
        return r;
    }

    pub fn negateNotMontgomery(r: *Fp, a: Fp) void {
        if (a.isZero()) {
            r.* = .zero;
            return;
        }
        // compute p - a
        var cy: u64 = 0;
        for (0..4) |i| {
            const p = constants.p_limbs[i];
            var b = a.limbs[i];
            b += cy;
            cy = @intFromBool(b < cy);
            cy += @intFromBool(p < b);
            r.limbs[i] = p -% b;
        }
    }

    pub fn format(
        f: Fp,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        const int: u256 = @bitCast(f.limbs);
        try writer.print("0x{x:0>64}", .{int});
    }

    test isZero {
        try std.testing.expect(zero.isZero());
        try std.testing.expect(!one.isZero());
    }

    test eql {
        try std.testing.expect(zero.eql(.zero));
        try std.testing.expect(!zero.eql(.one));
    }

    test add {
        inline for (@as([2][3]Fp, .{
            .{ .zero, .zero, .zero },
            .{ .zero, .one, .one },
        })) |entry| {
            const a, const b, const expected = entry;
            const r = a.add(b);
            try std.testing.expect(r.eql(expected));
        }
    }

    test mul {
        inline for (@as([3][3]Fp, .{
            .{ .zero, .zero, .zero },
            .{ .one, .one, .one },
            .{ .zero, .one, .zero },
        })) |entry| {
            const a, const b, const expected = entry;
            const r = a.mul(b);
            try std.testing.expect(r.eql(expected));
        }
    }
};

pub const Fp2 = struct {
    c0: Fp,
    c1: Fp,

    pub const zero: Fp2 = .{
        .c0 = .zero,
        .c1 = .zero,
    };

    pub const one: Fp2 = .{
        .c0 = .one,
        .c1 = .zero,
    };

    pub const constants = struct {
        /// B=3/(i + 9), in twist curve equation y^2 = x^3 + b'
        pub const twist_b_mont: Fp2 = .{
            // Computed with,
            // coeff_b = 3
            // twist = Fp2(9, 1)
            // twist_b_mont = coeff_b * twist.inverse()
            .c0 = .{ .limbs = .{
                0x3bf938e377b802a8,
                0x020b1b273633535d,
                0x26b7edf049755260,
                0x2514c6324384a86d,
            } },
            .c1 = .{ .limbs = .{
                0x38e7ecccd1dcff67,
                0x65f0b37d93ce0d3e,
                0xd749d0dd22ac00aa,
                0x0141b9ce4a688d4d,
            } },
        };

        pub const frob_gamma1_mont: [5]Fp2 = .{ .{
            .c0 = .{ .limbs = .{
                0xaf9ba69633144907,
                0xca6b1d7387afb78a,
                0x11bded5ef08a2087,
                0x02f34d751a1f3a7c,
            } },
            .c1 = .{ .limbs = .{
                0xa222ae234c492d72,
                0xd00f02a4565de15b,
                0xdc2ff3a253dfc926,
                0x10a75716b3899551,
            } },
        }, .{
            .c0 = .{ .limbs = .{
                0xb5773b104563ab30,
                0x347f91c8a9aa6454,
                0x7a007127242e0991,
                0x1956bcd8118214ec,
            } },
            .c1 = .{ .limbs = .{
                0x6e849f1ea0aa4757,
                0xaa1c7b6d89f89141,
                0xb6e713cdfae0ca3a,
                0x26694fbb4e82ebc3,
            } },
        }, .{
            .c0 = .{ .limbs = .{
                0xe4bbdd0c2936b629,
                0xbb30f162e133bacb,
                0x31a9d1b6f9645366,
                0x253570bea500f8dd,
            } },
            .c1 = .{ .limbs = .{
                0xa1d77ce45ffe77c7,
                0x07affd117826d1db,
                0x6d16bd27bb7edc6b,
                0x2c87200285defecc,
            } },
        }, .{
            .c0 = .{ .limbs = .{
                0x7361d77f843abe92,
                0xa5bb2bd3273411fb,
                0x9c941f314b3e2399,
                0x15df9cddbb9fd3ec,
            } },
            .c1 = .{ .limbs = .{
                0x5dddfd154bd8c949,
                0x62cb29a5a4445b60,
                0x37bc870a0c7dd2b9,
                0x24830a9d3171f0fd,
            } },
        }, .{
            .c0 = .{ .limbs = .{
                0xc970692f41690fe7,
                0xe240342127694b0b,
                0x32bee66b83c459e8,
                0x12aabced0ab08841,
            } },
            .c1 = .{ .limbs = .{
                0x0d485d2340aebfa9,
                0x05193418ab2fcc57,
                0xd3b0a40b8a4910f5,
                0x2f21ebb535d2925a,
            } },
        } };
    };

    pub fn fromBytes(input: *const [64]u8, endian: std.builtin.Endian, maybe_flags: ?*Flags) !Fp2 {
        const el0: u32, const el1: u32 = switch (endian) {
            .little => .{ 0, 32 },
            .big => .{ 32, 0 },
        };
        return .{
            .c0 = try .fromBytes(input[el0..][0..32], endian, null),
            .c1 = try .fromBytes(input[el1..][0..32], endian, maybe_flags),
        };
    }

    pub fn toBytes(f: Fp2, out: *[64]u8, endian: std.builtin.Endian) void {
        const el0: u32, const el1: u32 = switch (endian) {
            .little => .{ 0, 32 },
            .big => .{ 32, 0 },
        };
        f.c0.toBytes(out[el0..][0..32], endian);
        f.c1.toBytes(out[el1..][0..32], endian);
    }

    pub fn isZero(f: Fp2) bool {
        return f.c0.isZero() and f.c1.isZero();
    }

    pub fn isOne(f: Fp2) bool {
        return f.c0.isOne() and f.c1.isZero();
    }

    pub fn isNegative(f: Fp2) bool {
        if (f.c1.isZero()) return f.c0.isNegative();
        return f.c1.isNegative();
    }

    fn isMinusOne(f: Fp2) bool {
        return f.c0.eql(Fp.constants.p_minus_one_mont) and f.c1.isZero();
    }

    pub fn toMont(f: *Fp2) void {
        f.c0.toMont();
        f.c1.toMont();
    }

    pub fn fromMont(f: *Fp2) void {
        f.c0.fromMont();
        f.c1.fromMont();
    }

    pub fn eql(a: Fp2, b: Fp2) bool {
        return a.c0.eql(b.c0) and a.c1.eql(b.c1);
    }

    pub fn add(a: Fp2, b: Fp2) Fp2 {
        return .{
            .c0 = a.c0.add(b.c0),
            .c1 = a.c1.add(b.c1),
        };
    }

    /// Returns `2 * a`
    pub fn dbl(a: Fp2) Fp2 {
        return add(a, a);
    }

    /// Returns `3 * a`
    pub fn triple(a: Fp2) Fp2 {
        return add(a, add(a, a));
    }

    pub fn sub(a: Fp2, b: Fp2) Fp2 {
        return .{
            .c0 = a.c0.sub(b.c0),
            .c1 = a.c1.sub(b.c1),
        };
    }

    /// Returns `a / 2`
    pub fn halve(a: Fp2) Fp2 {
        return .{
            .c0 = a.c0.halve(),
            .c1 = a.c1.halve(),
        };
    }

    pub fn mul(a: Fp2, b: Fp2) Fp2 {
        const a0 = a.c0;
        const a1 = a.c1;
        const b0 = b.c0;
        const b1 = b.c1;

        const sa = a0.add(a1);
        const sb = b0.add(b1);

        const a0b0 = a0.mul(b0);
        const a1b1 = a1.mul(b1);

        return .{
            .c0 = a0b0.sub(a1b1),
            .c1 = sa.mul(sb).sub(a0b0).sub(a1b1),
        };
    }

    pub fn mulBroad(a: Fp2, b: Fp) Fp2 {
        return .{
            .c0 = a.c0.mul(b),
            .c1 = a.c1.mul(b),
        };
    }

    pub fn sq(a: Fp2) Fp2 {
        const p = a.c0.add(a.c1);
        const m = a.c0.sub(a.c1);

        return .{
            // r0 = (c0-c1)*(c0+c1)
            .c0 = p.mul(m),
            // r1 = 2 c0*c1
            .c1 = a.c0.mul(a.c1).dbl(),
        };
    }

    pub fn negate(a: Fp2) Fp2 {
        return .{
            .c0 = a.c0.negate(),
            .c1 = a.c1.negate(),
        };
    }

    pub fn negateNotMontgomery(r: *Fp2, a: Fp2) void {
        r.c0.negateNotMontgomery(a.c0);
        r.c1.negateNotMontgomery(a.c1);
    }

    fn pow(a: Fp2, comptime n: u256) Fp2 {
        const limbs: [4]u64 = @bitCast(n);
        var r = one;
        var i: u8 = 255 - @clz(n);
        while (true) {
            r = r.sq();
            if (bn254.bit(limbs, i)) r = r.mul(a);
            if (i == 0) break;
            i -= 1;
        }
        return r;
    }

    /// https://eprint.iacr.org/2012/685, Alg. 9
    ///
    /// Note: this function can return *either* r or -r, both are valid answers.
    ///
    /// Returns an error if `a` isn't a square.
    pub fn sqrt(a: Fp2) !Fp2 {
        const a1 = a.pow(Fp.constants.sqrt_exp);

        const alpha = a1.sq().mul(a);
        const a0 = alpha.conj().mul(alpha);
        if (a0.isMinusOne()) return error.NotSquare;

        const x0 = a1.mul(a);
        if (alpha.isMinusOne()) {
            // As firedancer notes, it shouldn't be possible to hit this... I think.
            return x0.conj();
        } else {
            const x1 = alpha.add(.one).pow(Fp.constants.p_minus_1_half);
            return x1.mul(x0);
        }
    }

    /// https://eprint.iacr.org/2010/354.pdf, Alg. 8
    fn inverse(a: Fp2) Fp2 {
        // t0 ← a0^2
        var t0 = a.c0.sq();
        // t1 ← a1^2
        var t1 = a.c1.sq();
        // t0 ← t0 − β · t1;
        t0 = t0.add(t1);
        t1 = t0.inverse();
        // c0 ← a0 · t1;
        const c0 = a.c0.mul(t1);
        // c1 ← −1 · a1 · t1;
        const c1 = a.c1.mul(t1).negate();

        return .{
            .c0 = c0,
            .c1 = c1,
        };
    }

    /// Computes the conjugate of the field extension
    pub fn conj(a: Fp2) Fp2 {
        return .{
            .c0 = a.c0,
            .c1 = a.c1.negate(),
        };
    }

    /// Computes r = a * (9 + i)
    fn mulByXi(a: Fp2) Fp2 {
        const r0 = a.c0.dbl().dbl().dbl().add(a.c0).sub(a.c1);
        const r1 = a.c1.dbl().dbl().dbl().add(a.c1).add(a.c0);
        return .{
            .c0 = r0,
            .c1 = r1,
        };
    }

    pub fn format(
        f: Fp2,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.print("({}, {})", .{ f.c0, f.c1 });
    }
};

const Fp6 = struct {
    c0: Fp2,
    c1: Fp2,
    c2: Fp2,

    const zero: Fp6 = .{
        .c0 = .zero,
        .c1 = .zero,
        .c2 = .zero,
    };

    const one: Fp6 = .{
        .c0 = .one,
        .c1 = .zero,
        .c2 = .zero,
    };

    fn isZero(f: Fp6) bool {
        return f.c0.isZero() and
            f.c1.isZero() and
            f.c2.isZero();
    }

    pub fn isOne(f: Fp6) bool {
        return f.c0.isOne() and
            f.c1.isZero() and
            f.c2.isZero();
    }

    fn add(a: Fp6, b: Fp6) Fp6 {
        return .{
            .c0 = a.c0.add(b.c0),
            .c1 = a.c1.add(b.c1),
            .c2 = a.c2.add(b.c2),
        };
    }

    pub fn dbl(a: Fp6) Fp6 {
        return a.add(a);
    }

    fn sub(a: Fp6, b: Fp6) Fp6 {
        return .{
            .c0 = a.c0.sub(b.c0),
            .c1 = a.c1.sub(b.c1),
            .c2 = a.c2.sub(b.c2),
        };
    }

    /// https://eprint.iacr.org/2010/354, Alg. 13
    fn mul(a: Fp6, b: Fp6) Fp6 {
        const a0 = a.c0;
        const a1 = a.c1;
        const a2 = a.c2;
        const b0 = b.c0;
        const b1 = b.c1;
        const b2 = b.c2;

        const t0 = a0.mul(b0);
        const t1 = a1.mul(b1);
        const t2 = a2.mul(b2);

        // c0 ← [(a1 + a2) · (b1 + b2) − t1 − t2] · ξ + t0;
        const c0 = a1.add(a2).mul(b1.add(b2)).sub(t1).sub(t2).mulByXi().add(t0);
        // c1 ← (a0 + a1) · (b0 + b1) − t0 − t1 + ξ · t2;
        const c1 = a0.add(a1).mul(b0.add(b1)).sub(t0).sub(t1).add(t2.mulByXi());
        // c2 ← (a0 + a2) · (b0 + b2) − t0 − t2 + t1;
        const c2 = a0.add(a2).mul(b0.add(b2)).sub(t0).sub(t2).add(t1);

        return .{
            .c0 = c0,
            .c1 = c1,
            .c2 = c2,
        };
    }

    /// https://eprint.iacr.org/2010/354, Alg. 12
    fn mulByGamma(a: Fp6) Fp6 {
        return .{
            .c0 = a.c2.mulByXi(),
            .c1 = a.c0,
            .c2 = a.c1,
        };
    }

    fn negate(a: Fp6) Fp6 {
        return .{
            .c0 = a.c0.negate(),
            .c1 = a.c1.negate(),
            .c2 = a.c2.negate(),
        };
    }

    /// https://eprint.iacr.org/2010/354, Alg. 16
    fn sq(a: Fp6) Fp6 {
        const a0 = a.c0;
        const a1 = a.c1;
        const a2 = a.c2;

        // c4 ← 2(a0 · a1);
        var c4 = a0.mul(a1).dbl();
        // c5 ← a2^2
        var c5 = a2.sq();
        // c1 ← c5 · ξ + c4;
        const c1 = c5.mulByXi().add(c4);
        // c2 ← c4 − c5;
        var c2 = c4.sub(c5);
        // c3 ← a0^2
        const c3 = a0.sq();
        // c4 ← a0 − a1 + a2;
        c4 = a0.sub(a1).add(a2);
        // c5 ← 2(a1 · a2);
        c5 = a1.mul(a2).dbl();
        // c4 ← c4^2
        c4 = c4.sq();
        // c0 ← c5 · ξ + c3;
        const c0 = c5.mulByXi().add(c3);

        return .{
            .c0 = c0,
            .c1 = c1,
            // c2 ← c2 + c4 + c5 − c3;
            .c2 = c2.add(c4).add(c5).sub(c3),
        };
    }

    /// https://eprint.iacr.org/2010/354, Alg. 17
    fn inverse(a: Fp6) Fp6 {
        const t0 = a.c0.sq();
        const t1 = a.c1.sq();
        const t2 = a.c2.sq();
        const t3 = a.c0.mul(a.c1);
        const t4 = a.c0.mul(a.c2);
        const t5 = a.c1.mul(a.c2);

        // c0 ← t0 − ξ · t5;
        const c0 = t0.sub(t5.mulByXi());
        // c1 ← ξ · t2 − t3;
        const c1 = t2.mulByXi().sub(t3);
        // c2 ← t1 − t4; NOTE: paper says t1 · t4, but that's a misprint
        const c2 = t1.sub(t4);
        // t6 ← a0 · c0;
        var t6 = a.c0.mul(c0);
        // t6 ← t6 + ξ · a2 · c1;
        t6 = t6.add(a.c2.mulByXi().mul(c1));
        // t6 ← t6 + ξ · a1 · c2;
        t6 = t6.add(a.c1.mulByXi().mul(c2));
        // t6 ← t6^-1;
        t6 = t6.inverse();

        return .{
            .c0 = c0.mul(t6),
            .c1 = c1.mul(t6),
            .c2 = c2.mul(t6),
        };
    }

    pub fn format(
        f: Fp6,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.print("[{}, {}, {}]", .{ f.c0, f.c1, f.c2 });
    }
};

/// Represented using a 2/3/2 tower so we can re-use Fp2 impl.
pub const Fp12 = struct {
    c0: Fp6,
    c1: Fp6,

    pub const one: Fp12 = .{
        .c0 = .one,
        .c1 = .zero,
    };

    pub fn isOne(f: Fp12) bool {
        return f.c0.isOne() and f.c1.isZero();
    }

    /// https://eprint.iacr.org/2010/354, Alg. 20
    pub fn mul(a: Fp12, b: Fp12) Fp12 {
        const a0 = a.c0;
        const a1 = a.c1;
        const b0 = b.c0;
        const b1 = b.c1;

        // t0 ← a0 · b0;
        const t0 = a0.mul(b0);
        // t1 ← a1 · b1;
        const t1 = a1.mul(b1);
        // c0 ← t0 + t1 · γ;
        const c0 = t0.add(t1.mulByGamma());
        // c1 ← (a0 + a1) · (b0 + b1) − t0 − t1;
        const c1 = a0.add(a1).mul(b0.add(b1)).sub(t0).sub(t1);

        return .{
            .c0 = c0,
            .c1 = c1,
        };
    }

    /// https://eprint.iacr.org/2010/354, Alg. 22
    pub fn sq(a: Fp12) Fp12 {
        const c3 = a.c0.sub(a.c1.mulByGamma());
        const c2 = a.c0.mul(a.c1);
        const c0 = a.c0.sub(a.c1).mul(c3).add(c2);

        return .{
            .c0 = c2.mulByGamma().add(c0),
            .c1 = c2.dbl(),
        };
    }

    pub fn conj(a: Fp12) Fp12 {
        return .{
            .c0 = a.c0,
            .c1 = a.c1.negate(),
        };
    }

    /// https://eprint.iacr.org/2010/354, Alg. 23
    pub fn inverse(a: Fp12) Fp12 {
        // t0 ← a0^2
        var t0 = a.c0.sq();
        // t1 ← a1^2
        var t1 = a.c1.sq();
        // t0 ← t0 − γ · t1;
        t0 = t0.sub(t1.mulByGamma());
        // t1 ← t0^-1
        t1 = t0.inverse();
        // c0 ← a0 · t1;
        const c0 = a.c0.mul(t1);
        // c1 ← −1 · a1 · t1;
        const c1 = a.c1.mul(t1).negate();

        return .{
            .c0 = c0,
            .c1 = c1,
        };
    }

    /// https://eprint.iacr.org/2010/354, Alg. 28
    pub fn frob(a: Fp12) Fp12 {
        return .{
            .c0 = .{
                .c0 = a.c0.c0.conj(),
                .c1 = a.c0.c1.conj().mul(Fp2.constants.frob_gamma1_mont[1]),
                .c2 = a.c0.c2.conj().mul(Fp2.constants.frob_gamma1_mont[3]),
            },
            .c1 = .{
                .c0 = a.c1.c0.conj().mul(Fp2.constants.frob_gamma1_mont[0]),
                .c1 = a.c1.c1.conj().mul(Fp2.constants.frob_gamma1_mont[2]),
                .c2 = a.c1.c2.conj().mul(Fp2.constants.frob_gamma1_mont[4]),
            },
        };
    }

    /// https://eprint.iacr.org/2010/354, Alg. 29
    pub fn frob2(a: Fp12) Fp12 {
        return .{
            .c0 = .{
                .c0 = a.c0.c0,
                .c1 = .{
                    // g1 * gamma_2,2 */
                    .c0 = a.c0.c1.c0.mul(Fp.constants.frob_gamma2_mont[1]),
                    .c1 = a.c0.c1.c1.mul(Fp.constants.frob_gamma2_mont[1]),
                },
                .c2 = .{
                    // g2 * gamma_2,4 */
                    .c0 = a.c0.c2.c0.mul(Fp.constants.frob_gamma2_mont[3]),
                    .c1 = a.c0.c2.c1.mul(Fp.constants.frob_gamma2_mont[3]),
                },
            },
            .c1 = .{
                .c0 = .{
                    // h0 * gamma_2,1 */
                    .c0 = a.c1.c0.c0.mul(Fp.constants.frob_gamma2_mont[0]),
                    .c1 = a.c1.c0.c1.mul(Fp.constants.frob_gamma2_mont[0]),
                },
                .c1 = .{
                    // h1 * gamma_2,3 */
                    .c0 = a.c1.c1.c0.mul(Fp.constants.frob_gamma2_mont[2]),
                    .c1 = a.c1.c1.c1.mul(Fp.constants.frob_gamma2_mont[2]),
                },
                .c2 = .{
                    // h2 * gamma_2,5 */
                    .c0 = a.c1.c2.c0.mul(Fp.constants.frob_gamma2_mont[4]),
                    .c1 = a.c1.c2.c1.mul(Fp.constants.frob_gamma2_mont[4]),
                },
            },
        };
    }

    /// Cyclotomic square root, https://eprint.iacr.org/2009/565, Sec. 3.2
    pub fn sqFast(a: Fp12) Fp12 {
        const t0 = a.c1.c1.sq();
        const t1 = a.c0.c0.sq();
        const t6 = a.c1.c1.add(a.c0.c0).sq().sub(t0).sub(t1);

        const t2 = a.c0.c2.sq();
        const t3 = a.c1.c0.sq();
        const t7 = a.c0.c2.add(a.c1.c0).sq().sub(t2).sub(t3);

        const t4 = a.c1.c2.sq();
        const t5 = a.c0.c1.sq();
        const t8 = a.c1.c2.add(a.c0.c1).sq().sub(t4).sub(t5).mulByXi();

        const r0 = t0.mulByXi().add(t1);
        const r2 = t2.mulByXi().add(t3);
        const r4 = t4.mulByXi().add(t5);

        return .{
            .c0 = .{
                .c0 = r0.sub(a.c0.c0).dbl().add(r0),
                .c1 = r2.sub(a.c0.c1).dbl().add(r2),
                .c2 = r4.sub(a.c0.c2).dbl().add(r4),
            },
            .c1 = .{
                .c0 = t8.add(a.c1.c0).dbl().add(t8),
                .c1 = t6.add(a.c1.c1).dbl().add(t6),
                .c2 = t7.add(a.c1.c2).dbl().add(t7),
            },
        };
    }

    /// Raise `a` to `x^t mod q^12` where t is the generator of the curve.
    ///
    /// https://github.com/Consensys/gnark-crypto/blob/v0.12.1/ecc/bn254/internal/fptower/e12_pairing.go#L16
    pub fn powX(a: Fp12) Fp12 {
        // t3 = x^0x2
        var t3 = a.sqFast();
        // t5 = x^0x4
        var t5 = t3.sqFast();
        // result = x^0x8
        const result = t5.sqFast();
        // t0 = x^0x10
        var t0 = result.sqFast();
        // t2 = x^0x11
        var t2 = a.mul(t0);
        // t0 = x^0x13
        t0 = t3.mul(t2);
        // t1 = x^0x14
        var t1 = a.mul(t0);
        // t4 = x^0x19
        var t4 = result.mul(t2);
        // t6 = x^0x22
        var t6 = t2.sqFast();
        // t1 = x^0x27
        t1 = t0.mul(t1);
        // t0 = x^0x29
        t0 = t3.mul(t1);
        // t6 = x^0x880
        for (0..6) |_| t6 = t6.sqFast();
        // t5 = x^0x884
        t5 = t5.mul(t6);
        // t5 = x^0x89d
        t5 = t5.mul(t4);
        // t5 = x^0x44e80
        for (0..7) |_| t5 = t5.sqFast();
        // t4 = x^0x44e99
        t4 = t4.mul(t5);
        // t4 = x^0x44e9900
        for (0..8) |_| t4 = t4.sqFast();
        // t4 = x^0x44e9929
        t4 = t4.mul(t0);
        // t3 = x^0x44e992b
        t3 = t3.mul(t4);
        // t3 = x^0x113a64ac0
        for (0..6) |_| t3 = t3.sqFast();
        // t2 = x^0x113a64ad1
        t2 = t2.mul(t3);
        // t2 = x^0x113a64ad100
        for (0..8) |_| t2 = t2.sqFast();
        // t2 = x^0x113a64ad129
        t2 = t2.mul(t0);
        // t2 = x^0x44e992b44a40
        for (0..6) |_| t2 = t2.sqFast();
        // t2 = x^0x44e992b44a69
        t2 = t2.mul(t0);
        // t2 = x^0x113a64ad129a400
        for (0..10) |_| t2 = t2.sqFast();
        // t1 = x^0x113a64ad129a427
        t1 = t1.mul(t2);
        // t1 = x^0x44e992b44a6909c0
        for (0..6) |_| t1 = t1.sqFast();
        // t0 = x^0x44e992b44a6909e9
        t0 = t0.mul(t1);
        // result = x^0x44e992b44a6909f1
        return result.mul(t0);
    }

    pub fn format(
        f: Fp12,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.print("{{{}, {}}}", .{ f.c0, f.c1 });
    }
};
