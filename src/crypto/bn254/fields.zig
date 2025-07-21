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
        const p_minus_1_half = 0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea3;

        pub const b_mont: Fp = fromInt(3);
        const p_minus_one_mont: Fp = fromInt(p - 1);

        /// (p-3)/4
        const sqrt_exp: u256 = 0x0c19139cb84c680a6e14116da060561765e05aa45a1c72a34f082305b61f3f51;

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
        maybe_flags: ?*Flags,
    ) !Fp {
        if (maybe_flags) |flags| {
            flags.* = @bitCast(input[0]);
            // If both flags are set, return an error.
            // https://github.com/arkworks-rs/algebra/blob/v0.4.2/ec/src/models/short_weierstrass/serialization_flags.rs#L75
            if (flags.is_inf and flags.is_neg) return error.BothFlags;
        }

        var limbs: [32]u8 = byteSwap(input.*);
        if (maybe_flags != null) limbs[31] &= Flags.MASK;

        // Check that we've decoded a valid field element.
        const integer: u256 = @bitCast(limbs);
        if (integer >= constants.p) return error.TooLarge;

        return .{ .limbs = @bitCast(limbs) };
    }

    pub fn toBytes(f: Fp, out: *[32]u8) void {
        out.* = byteSwap(@bitCast(f.limbs));
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

    pub fn add(r: *Fp, a: Fp, b: Fp) void {
        fiat.add(&r.limbs, a.limbs, b.limbs);
    }

    pub fn sub(r: *Fp, a: Fp, b: Fp) void {
        fiat.sub(&r.limbs, a.limbs, b.limbs);
    }

    pub fn mul(r: *Fp, a: Fp, b: Fp) void {
        fiat.mul(&r.limbs, a.limbs, b.limbs);
    }

    pub fn sq(r: *Fp, a: Fp) void {
        r.mul(a, a);
    }

    pub fn halve(r: *Fp, a: Fp) void {
        const is_odd = r.limbs[0] & 0x1 != 0;
        const b: u256 = @bitCast(a.limbs);
        r.limbs = @bitCast(b + if (is_odd) constants.p else 0);
        r.limbs[0] = (r.limbs[0] >> 1) | (r.limbs[1] << 63);
        r.limbs[1] = (r.limbs[1] >> 1) | (r.limbs[2] << 63);
        r.limbs[2] = (r.limbs[2] >> 1) | (r.limbs[3] << 63);
        r.limbs[3] >>= 1;
    }

    pub fn pow(a: Fp, comptime n: u256) Fp {
        const limbs: [4]u64 = @bitCast(n);
        var r = one;
        var i: u8 = 255 - @clz(n);
        while (true) {
            r.sq(r);
            if (bn254.bit(limbs, i)) r.mul(r, a);
            if (i == 0) break;
            i -= 1;
        }
        return r;
    }

    pub fn inverse(r: *Fp, a: Fp) void {
        r.* = a.pow(constants.p_minus_2);
    }

    /// Alg. 2, https://eprint.iacr.org/2012/685
    pub fn sqrt(r: *Fp, a: Fp) !void {
        const c1: Fp = a.pow(constants.sqrt_exp);

        var c0: Fp = undefined;
        c0.sq(c1);
        c0.mul(c0, a);
        if (c0.eql(constants.p_minus_one_mont)) return error.NotSquare;

        r.mul(c1, a);
    }

    pub fn toMont(r: *Fp) void {
        fiat.toMontgomery(&r.limbs, r.limbs);
    }

    pub fn fromMont(r: *Fp) void {
        fiat.fromMontgomery(&r.limbs, r.limbs);
    }

    pub fn negate(r: *Fp, a: Fp) void {
        fiat.opp(&r.limbs, a.limbs);
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
            var r: Fp = undefined;
            r.add(a, b);
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
            var r: Fp = undefined;
            r.mul(a, b);
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

    pub fn fromBytes(input: *const [64]u8, maybe_flags: ?*Flags) !Fp2 {
        return .{
            .c0 = try .fromBytes(input[32..64], null),
            .c1 = try .fromBytes(input[0..32], maybe_flags),
        };
    }

    pub fn toBytes(f: Fp2, out: *[64]u8) void {
        f.c0.toBytes(out[32..64]);
        f.c1.toBytes(out[0..32]);
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

    pub fn add(r: *Fp2, a: Fp2, b: Fp2) void {
        r.c0.add(a.c0, b.c0);
        r.c1.add(a.c1, b.c1);
    }

    pub fn sub(r: *Fp2, a: Fp2, b: Fp2) void {
        r.c0.sub(a.c0, b.c0);
        r.c1.sub(a.c1, b.c1);
    }

    pub fn halve(r: *Fp2, a: Fp2) void {
        r.c0.halve(a.c0);
        r.c1.halve(a.c1);
    }

    pub fn mul(r: *Fp2, a: Fp2, b: Fp2) void {
        const a0 = a.c0;
        const a1 = a.c1;
        const b0 = b.c0;
        const b1 = b.c1;

        var sa: Fp = undefined;
        var sb: Fp = undefined;
        sa.add(a0, a1);
        sb.add(b0, b1);

        var a0b0: Fp = undefined;
        var a1b1: Fp = undefined;
        a0b0.mul(a0, b0);
        a1b1.mul(a1, b1);
        r.c1.mul(sa, sb);

        r.c0.sub(a0b0, a1b1);
        r.c1.sub(r.c1, a0b0);
        r.c1.sub(r.c1, a1b1);
    }

    pub fn sq(r: *Fp2, a: Fp2) void {
        var p: Fp = undefined;
        var m: Fp = undefined;
        p.add(a.c0, a.c1);
        m.sub(a.c0, a.c1);

        // r1 = 2 c0*c1
        r.c1.mul(a.c0, a.c1);
        r.c1.add(r.c1, r.c1);
        // r0 = (c0-c1)*(c0+c1)
        r.c0.mul(p, m);
    }

    pub fn negate(r: *Fp2, a: Fp2) void {
        r.c0.negate(a.c0);
        r.c1.negate(a.c1);
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
            r.sq(r);
            if (bn254.bit(limbs, i)) r.mul(r, a);
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
    pub fn sqrt(r: *Fp2, a: Fp2) !void {
        const a1 = a.pow(Fp.constants.sqrt_exp);

        var alpha: Fp2 = undefined;
        alpha.sq(a1);
        alpha.mul(alpha, a);

        var a0: Fp2 = undefined;
        a0.conj(alpha);
        a0.mul(a0, alpha);

        if (a0.isMinusOne()) return error.NotSquare;

        var x0: Fp2 = undefined;
        x0.mul(a1, a);
        if (alpha.isMinusOne()) {
            // As firedancer notes, I'm not sure of an input that would hit this code.
            // If we find such an input, add it as a unit test!
            var t: Fp = undefined;
            t.negate(x0.c1);
            r.c1 = x0.c0;
            r.c0 = t;
        } else {
            a0.add(alpha, .one);
            const x1 = a0.pow(Fp.constants.p_minus_1_half);
            r.mul(x1, x0);
        }
    }

    fn inverse(r: *Fp2, a: Fp2) void {
        var t0: Fp = undefined;
        var t1: Fp = undefined;

        t0.sq(a.c0);
        t1.sq(a.c1);

        t0.add(t0, t1);
        t1.inverse(t0);

        r.c0.mul(a.c0, t1);
        r.c1.mul(a.c1, t1);
        r.c1.negate(r.c1);
    }

    /// Computes the conjugate of the field extension
    pub fn conj(r: *Fp2, a: Fp2) void {
        r.c0 = a.c0;
        r.c1.negate(a.c1);
    }

    /// Computes r = a * (9 + i)
    fn mulByXi(r: *Fp2, a: Fp2) void {
        var r0: Fp = undefined;
        var r1: Fp = undefined;

        r0.add(a.c0, a.c0);
        r0.add(r0, r0);
        r0.add(r0, r0);
        r0.add(r0, a.c0);
        r0.sub(r0, a.c1);

        r1.add(a.c1, a.c1);
        r1.add(r1, r1);
        r1.add(r1, r1);
        r1.add(r1, a.c1);

        r.c1.add(r1, a.c0);
        r.c0 = r0;
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

    fn add(r: *Fp6, a: Fp6, b: Fp6) void {
        r.c0.add(a.c0, b.c0);
        r.c1.add(a.c1, b.c1);
        r.c2.add(a.c2, b.c2);
    }

    fn sub(r: *Fp6, a: Fp6, b: Fp6) void {
        r.c0.sub(a.c0, b.c0);
        r.c1.sub(a.c1, b.c1);
        r.c2.sub(a.c2, b.c2);
    }

    /// https://eprint.iacr.org/2010/354, Alg. 13
    fn mul(r: *Fp6, a: Fp6, b: Fp6) void {
        const a0 = a.c0;
        const a1 = a.c1;
        const a2 = a.c2;
        const b0 = b.c0;
        const b1 = b.c1;
        const b2 = b.c2;

        var a0b0: Fp2 = undefined;
        var a1b1: Fp2 = undefined;
        var a2b2: Fp2 = undefined;
        a0b0.mul(a0, b0);
        a1b1.mul(a1, b1);
        a2b2.mul(a2, b2);

        var sa: Fp2 = undefined;
        var sb: Fp2 = undefined;
        sa.add(a1, a2);
        sb.add(b1, b2);

        var r0: Fp2 = undefined;
        r0.mul(sa, sb);
        r0.sub(r0, a1b1);
        r0.sub(r0, a2b2);
        r0.mulByXi(r0);
        r0.add(r0, a0b0);

        var r2: Fp2 = undefined;
        sa.add(a0, a2);
        sb.add(b0, b2);
        r2.mul(sa, sb);
        r2.sub(r2, a0b0);
        r2.sub(r2, a2b2);
        r2.add(r2, a1b1);

        var r1: Fp2 = undefined;
        sa.add(a0, a1);
        sb.add(b0, b1);
        r1.mul(sa, sb);
        r1.sub(r1, a0b0);
        r1.sub(r1, a1b1);
        a2b2.mulByXi(a2b2);
        r1.add(r1, a2b2);

        r.c0 = r0;
        r.c1 = r1;
        r.c2 = r2;
    }

    /// https://eprint.iacr.org/2010/354, Alg. 12
    fn mulByGamma(r: *Fp6, a: Fp6) void {
        var t: Fp2 = undefined;
        t.mulByXi(a.c2);
        r.c2 = a.c1;
        r.c1 = a.c0;
        r.c0 = t;
    }

    fn negate(r: *Fp6, a: Fp6) void {
        r.c0.negate(a.c0);
        r.c1.negate(a.c1);
        r.c2.negate(a.c2);
    }

    /// https://eprint.iacr.org/2010/354, Alg. 16
    fn sq(r: *Fp6, a: Fp6) void {
        const a0 = a.c0;
        const a1 = a.c1;
        const a2 = a.c2;

        var c0: Fp2 = undefined;
        var c1: Fp2 = undefined;
        var c2: Fp2 = undefined;
        var c3: Fp2 = undefined;
        var c4: Fp2 = undefined;
        var c5: Fp2 = undefined;

        c4.mul(a0, a1);
        c4.add(c4, c4);
        c5.sq(a2);

        c2.sub(c4, c5);
        c5.mulByXi(c5);
        c1.add(c4, c5);

        c3.sq(a0);
        c4.sub(a0, a1);
        c4.add(c4, a2);

        c5.mul(a1, a2);
        c5.add(c5, c5);
        c4.sq(c4);

        c2.add(c2, c4);
        c2.add(c2, c5);
        c2.sub(c2, c3);
        c5.mulByXi(c5);
        c0.add(c3, c5);

        r.c0 = c0;
        r.c1 = c1;
        r.c2 = c2;
    }

    /// https://eprint.iacr.org/2010/354, Alg. 17
    fn inverse(r: *Fp6, a: Fp6) void {
        var t: [6]Fp2 = undefined;

        t[0].sq(a.c0);
        t[1].sq(a.c1);
        t[2].sq(a.c2);
        t[3].mul(a.c0, a.c1);
        t[4].mul(a.c0, a.c2);
        t[5].mul(a.c1, a.c2);

        // t0 := c0 = t0 - xi * t5 */
        t[5].mulByXi(t[5]);
        t[0].sub(t[0], t[5]);
        // t2 := c1 = xi * t2 - t3 */
        t[2].mulByXi(t[2]);
        t[2].sub(t[2], t[3]);
        // t1 := c2 = t1 - t4 (NOTE: paper says t1*t4, but that's a misprint) */
        t[1].sub(t[1], t[4]);
        // t3 := t6 = a0 * c0 */
        t[3].mul(a.c0, t[0]);
        // t3 := t6 = t6 + (xi * a2 * c1 =: t4) */
        t[4].mul(a.c2, t[2]);
        t[4].mulByXi(t[4]);
        t[3].add(t[3], t[4]);
        // t3 := t6 = t6 + (xi * a2 * c1 =: t4) */
        t[5].mul(a.c1, t[1]);
        t[5].mulByXi(t[5]);
        t[3].add(t[3], t[5]);
        // t4 := t6^-1 */
        t[4].inverse(t[3]);

        r.c0.mul(t[0], t[4]);
        r.c1.mul(t[2], t[4]);
        r.c2.mul(t[1], t[4]);
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
    pub fn mul(r: *Fp12, a: Fp12, b: Fp12) void {
        const a0 = a.c0;
        const a1 = a.c1;
        const b0 = b.c0;
        const b1 = b.c1;

        var sa: Fp6 = undefined;
        var sb: Fp6 = undefined;
        sa.add(a0, a1);
        sb.add(b0, b1);

        var a0b0: Fp6 = undefined;
        var a1b1: Fp6 = undefined;
        a0b0.mul(a0, b0);
        a1b1.mul(a1, b1);
        r.c1.mul(sa, sb);

        r.c1.sub(r.c1, a0b0);
        r.c1.sub(r.c1, a1b1);

        a1b1.mulByGamma(a1b1);
        r.c0.add(a0b0, a1b1);
    }

    /// https://eprint.iacr.org/2010/354, Alg. 22
    pub fn sq(r: *Fp12, a: Fp12) void {
        var c0: Fp6 = undefined;
        var c2: Fp6 = undefined;
        var c3: Fp6 = undefined;

        c0.sub(a.c0, a.c1);
        c3.mulByGamma(a.c1);
        c3.sub(a.c0, c3);
        c2.mul(a.c0, a.c1);
        c0.mul(c0, c3);
        c0.add(c0, c2);
        r.c1.add(c2, c2);
        r.c0.mulByGamma(c2);
        r.c0.add(r.c0, c0);
    }

    pub fn conj(r: *Fp12, a: Fp12) void {
        r.c0 = a.c0;
        r.c1.negate(a.c1);
    }

    /// https://eprint.iacr.org/2010/354, Alg. 23
    pub fn inverse(r: *Fp12, a: Fp12) void {
        var t0: Fp6 = undefined;
        var t1: Fp6 = undefined;
        t0.sq(a.c0);
        t1.sq(a.c1);
        t1.mulByGamma(t1);
        t0.sub(t0, t1);
        t1.inverse(t0);
        r.c0.mul(a.c0, t1);
        r.c1.mul(a.c1, t1);
        r.c1.negate(r.c1);
    }

    /// https://eprint.iacr.org/2010/354, Alg. 28
    pub fn frob(r: *Fp12, a: Fp12) void {
        var t: [5]Fp2 = undefined;

        r.c0.c0.conj(a.c0.c0);
        t[0].conj(a.c0.c1);
        t[1].conj(a.c0.c2);
        t[2].conj(a.c1.c0);
        t[3].conj(a.c1.c1);
        t[4].conj(a.c1.c2);

        r.c0.c1.mul(t[0], Fp2.constants.frob_gamma1_mont[1]);
        r.c0.c2.mul(t[1], Fp2.constants.frob_gamma1_mont[3]);
        r.c1.c0.mul(t[2], Fp2.constants.frob_gamma1_mont[0]);
        r.c1.c1.mul(t[3], Fp2.constants.frob_gamma1_mont[2]);
        r.c1.c2.mul(t[4], Fp2.constants.frob_gamma1_mont[4]);
    }

    pub fn frob2(r: *Fp12, a: Fp12) void {
        // g0
        r.c0.c0 = a.c0.c0;

        // g1 * gamma_2,2 */
        r.c0.c1.c0.mul(a.c0.c1.c0, Fp.constants.frob_gamma2_mont[1]);
        r.c0.c1.c1.mul(a.c0.c1.c1, Fp.constants.frob_gamma2_mont[1]);

        // g2 * gamma_2,4 */
        r.c0.c2.c0.mul(a.c0.c2.c0, Fp.constants.frob_gamma2_mont[3]);
        r.c0.c2.c1.mul(a.c0.c2.c1, Fp.constants.frob_gamma2_mont[3]);

        // h0 * gamma_2,1 */
        r.c1.c0.c0.mul(a.c1.c0.c0, Fp.constants.frob_gamma2_mont[0]);
        r.c1.c0.c1.mul(a.c1.c0.c1, Fp.constants.frob_gamma2_mont[0]);

        // h1 * gamma_2,3 */
        r.c1.c1.c0.mul(a.c1.c1.c0, Fp.constants.frob_gamma2_mont[2]);
        r.c1.c1.c1.mul(a.c1.c1.c1, Fp.constants.frob_gamma2_mont[2]);

        // h2 * gamma_2,5 */
        r.c1.c2.c0.mul(a.c1.c2.c0, Fp.constants.frob_gamma2_mont[4]);
        r.c1.c2.c1.mul(a.c1.c2.c1, Fp.constants.frob_gamma2_mont[4]);
    }

    /// Cyclotomic sqr, https://eprint.iacr.org/2009/565, Sec. 3.2
    pub fn sqFast(r: *Fp12, a: Fp12) void {
        var t: [9]Fp2 = undefined;

        t[0].sq(a.c1.c1);
        t[1].sq(a.c0.c0);
        t[6].add(a.c1.c1, a.c0.c0);
        t[6].sq(t[6]);
        t[6].sub(t[6], t[0]);
        t[6].sub(t[6], t[1]);

        t[2].sq(a.c0.c2);
        t[3].sq(a.c1.c0);
        t[7].add(a.c0.c2, a.c1.c0);
        t[7].sq(t[7]);
        t[7].sub(t[7], t[2]);
        t[7].sub(t[7], t[3]);

        t[4].sq(a.c1.c2);
        t[5].sq(a.c0.c1);
        t[8].add(a.c1.c2, a.c0.c1);
        t[8].sq(t[8]);
        t[8].sub(t[8], t[4]);
        t[8].sub(t[8], t[5]);
        t[8].mulByXi(t[8]);

        t[0].mulByXi(t[0]);
        t[0].add(t[0], t[1]);
        t[2].mulByXi(t[2]);
        t[2].add(t[2], t[3]);
        t[4].mulByXi(t[4]);
        t[4].add(t[4], t[5]);

        r.c0.c0.sub(t[0], a.c0.c0);
        r.c0.c0.add(r.c0.c0, r.c0.c0);
        r.c0.c0.add(r.c0.c0, t[0]);
        r.c0.c1.sub(t[2], a.c0.c1);
        r.c0.c1.add(r.c0.c1, r.c0.c1);
        r.c0.c1.add(r.c0.c1, t[2]);
        r.c0.c2.sub(t[4], a.c0.c2);
        r.c0.c2.add(r.c0.c2, r.c0.c2);
        r.c0.c2.add(r.c0.c2, t[4]);

        r.c1.c0.add(t[8], a.c1.c0);
        r.c1.c0.add(r.c1.c0, r.c1.c0);
        r.c1.c0.add(r.c1.c0, t[8]);
        r.c1.c1.add(t[6], a.c1.c1);
        r.c1.c1.add(r.c1.c1, r.c1.c1);
        r.c1.c1.add(r.c1.c1, t[6]);
        r.c1.c2.add(t[7], a.c1.c2);
        r.c1.c2.add(r.c1.c2, r.c1.c2);
        r.c1.c2.add(r.c1.c2, t[7]);
    }

    /// https://github.com/Consensys/gnark-crypto/blob/v0.12.1/ecc/bn254/internal/fptower/e12_pairing.go#L16
    pub fn powX(r: *Fp12, a: Fp12) void {
        var t: [7]Fp12 = undefined;

        t[3].sqFast(a);
        t[5].sqFast(t[3]);
        r.sqFast(t[5]);
        t[0].sqFast(r.*);
        t[2].mul(t[0], a);
        t[0].mul(t[2], t[3]);
        t[1].mul(t[0], a);
        t[4].mul(t[2], r.*);
        t[6].sqFast(t[2]);
        t[1].mul(t[1], t[0]);
        t[0].mul(t[1], t[3]);
        for (0..6) |_| t[6].sqFast(t[6]);
        t[5].mul(t[5], t[6]);
        t[5].mul(t[5], t[4]);
        for (0..7) |_| t[5].sqFast(t[5]);
        t[4].mul(t[4], t[5]);
        for (0..8) |_| t[4].sqFast(t[4]);
        t[4].mul(t[4], t[0]);
        t[3].mul(t[3], t[4]);
        for (0..6) |_| t[3].sqFast(t[3]);
        t[2].mul(t[2], t[3]);
        for (0..8) |_| t[2].sqFast(t[2]);
        t[2].mul(t[2], t[0]);
        for (0..6) |_| t[2].sqFast(t[2]);
        t[2].mul(t[2], t[0]);
        for (0..10) |_| t[2].sqFast(t[2]);
        t[1].mul(t[1], t[2]);
        for (0..6) |_| t[1].sqFast(t[1]);
        t[0].mul(t[0], t[1]);
        r.mul(r.*, t[0]);
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
