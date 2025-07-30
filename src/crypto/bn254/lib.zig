//! Inspired by Firedancer's code; it contains a lot of interesting optimizations ported over.
//! https://github.com/firedancer-io/firedancer/blob/9068496fbf7d211a01b535039e876ffbf84fcc6e/src/ballet/bn254/

const std = @import("std");
pub const fields = @import("fields.zig");
pub const pairing = @import("pairing.zig");
pub const tests = @import("tests.zig");

const Flags = fields.Flags;
const Fp = fields.Fp;
const Fp2 = fields.Fp2;
const Fp12 = fields.Fp12;

pub fn bit(v: [4]u64, b: u8) bool {
    return v[b / 64] & (@as(u64, 1) << @intCast(b % 64)) != 0;
}

pub const G1 = struct {
    x: Fp,
    y: Fp,
    z: Fp,

    const zero: G1 = .{
        .x = .zero,
        .y = .zero,
        .z = .zero,
    };

    fn fromBytesInternal(input: *const [64]u8) !G1 {
        if (std.mem.allEqual(u8, input, 0)) return .zero;

        var flags: Flags = undefined;
        return .{
            .x = try .fromBytes(input[0..32], null),
            .y = try .fromBytes(input[32..64], &flags),
            .z = if (flags.is_inf) .zero else .one,
        };
    }

    fn isWellFormed(p: G1) !void {
        // zero-point always well formed, no matter what X and Y are
        if (p.isZero()) return;

        // Check that y^2 = x^3 + b
        var y2: Fp = undefined;
        var x3b: Fp = undefined;
        // y^2
        y2.sq(p.y);
        // x^3 + b
        x3b.sq(p.x);
        x3b.mul(x3b, p.x);
        x3b.add(x3b, Fp.constants.b_mont);
        if (!y2.eql(x3b)) return error.NotWellFormed;

        // G1 has prime order so we do not need a subgroup membership check.
    }

    pub fn fromBytes(input: *const [64]u8) !G1 {
        var g1 = try fromBytesInternal(input);
        if (g1.isZero()) return g1;

        g1.x.toMont();
        g1.y.toMont();
        g1.z = .one;

        try g1.isWellFormed();

        return g1;
    }

    fn toBytes(p: G1, out: *[64]u8) void {
        if (p.isZero()) {
            // no flags
            @memset(out, 0);
            return;
        }

        var r: G1 = undefined;

        r.toAffine(p);
        r.x.fromMont();
        r.y.fromMont();

        r.x.toBytes(out[0..32]);
        r.y.toBytes(out[32..64]);
    }

    fn isZero(p: G1) bool {
        return p.z.isZero();
    }

    fn toAffine(r: *G1, p: G1) void {
        if (p.z.isZero() or p.z.isOne()) {
            // nothing to do
            r.* = p;
            return;
        }

        // if Z is neither zero nor one, need to flatten down
        var iz: Fp = undefined;
        var iz2: Fp = undefined;
        iz.inverse(p.z);
        iz2.sq(iz);

        // x / z^2, y / z^3
        r.x.mul(p.x, iz2);
        r.y.mul(p.y, iz2);
        r.y.mul(r.y, iz);
        r.z = .one;
    }

    pub fn compress(out: *[32]u8, input: *const [64]u8) !void {
        const p: G1 = try .fromBytesInternal(input);

        const is_inf = p.isZero();
        const flag_inf = input[32] & Flags.INF;

        // If the infinity flag is set, return point at infinity
        // Else, copy x and set the neg_y flag
        if (is_inf) {
            @memset(out, 0);
            out[0] |= flag_inf;
            return;
        }

        const is_neg = p.y.isNegative();
        @memcpy(out, input[0..32]);
        if (is_neg) out[0] |= Flags.NEG;
        return;
    }

    pub fn decompress(out: *[64]u8, input: *const [32]u8) !void {
        // All zeroes input, all zeroes out, no flags.
        if (std.mem.allEqual(u8, input, 0)) return @memset(out, 0);

        var flags: Flags = undefined;
        var x: Fp = try .fromBytes(input, &flags);

        // If the point at infinity flag is set, return the point at infinity without any
        // checks on the coordinates (X, Y) and no flags set.
        if (flags.is_inf) return @memset(out, 0);

        var x2: Fp = undefined;
        var x3b: Fp = undefined;
        var y: Fp = undefined;

        x.toMont();
        x2.sq(x);
        x3b.mul(x2, x);
        x3b.add(x3b, Fp.constants.b_mont);
        try y.sqrt(x3b);

        y.fromMont();
        if (flags.is_neg != y.isNegative()) {
            y.negateNotMontgomery(y);
        }

        @memcpy(out[0..32], input);
        out[0] &= Flags.MASK;
        y.toBytes(out[32..64]);
        // no flags on y
    }

    /// Compute a + b.
    ///
    /// Both a and b are affine (Z == 1).
    pub fn affineAdd(a: G1, b: G1) G1 {
        // if a == 0, return b
        if (a.isZero()) return b;
        // if b == 0, return a
        if (b.isZero()) return a;

        var x: Fp = undefined;
        var y: Fp = undefined;
        var lambda: Fp = undefined;

        // if X coord is equal, means either the points are the same (on the top)
        // or they're opposite (one on the top, other one on the bottom).
        if (a.x.eql(b.x)) {
            if (a.y.eql(b.y)) {
                // a == b => point double: lambda = 3 * x1^2 / (2 * y1)
                x.sq(a.x); // x = x1 ^ 2
                y.add(x, x); // y = (2 * x1) ^ 2
                x.add(x, y); // x = (3 * x1) ^ 2
                y.add(a.y, a.y);
                lambda.inverse(y);
                lambda.mul(lambda, x);
            } else {
                // a == -b => 0
                return .zero;
            }
        } else {
            // point add: lambda = (y1 - y2) / (x1 - x2)
            x.sub(a.x, b.x);
            y.sub(a.y, b.y);
            lambda.inverse(x);
            lambda.mul(lambda, y);
        }

        // x3 = lambda^2 - x1 - x2
        x.sq(lambda);
        x.sub(x, a.x);
        x.sub(x, b.x);

        // y3 = lambda * (x1 - x3) - y1
        y.sub(a.x, x);
        y.mul(y, lambda);
        y.sub(y, a.y);

        return .{
            .x = x,
            .y = y,
            .z = .one,
        };
    }

    /// https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2007-bl
    fn dbl(p: G1) G1 {
        if (p.isZero()) return .zero;

        var xx: Fp = undefined;
        var yy: Fp = undefined;
        var zz: Fp = undefined;

        var y4: Fp = undefined;
        var s: Fp = undefined;
        var m: Fp = undefined;

        var r: G1 = undefined;

        // xx = x1^2
        xx.sq(p.x);
        // yy = y1^2
        yy.sq(p.y);
        // yyyy = yy^2
        y4.sq(yy);
        // zz = z1^2
        zz.sq(p.z);
        // S = 2 * ((X1 + YY)^2 - XX - YYYY)
        s.add(p.x, yy);
        s.sq(s);
        s.sub(s, xx);
        s.sub(s, y4);
        s.add(s, s);
        // M = 3 * XX + a * ZZ^2, a = 0
        m.add(xx, xx);
        m.add(m, xx);
        // T = M^2 - 2*S
        // X3 = T
        r.x.sq(m);
        r.x.sub(r.x, s);
        r.x.sub(r.x, s);
        // Z3 = (Y1 + Z1)^2 - YY - ZZ
        r.z.add(p.z, p.y);
        r.z.sq(r.z);
        r.z.sub(r.z, yy);
        r.z.sub(r.z, zz);
        // Y3 = M*(S - T) - 8*YYYY
        r.y.sub(s, r.x);
        r.y.mul(r.y, m);
        y4.add(y4, y4);
        y4.add(y4, y4);
        y4.add(y4, y4);
        r.y.sub(r.y, y4);

        return r;
    }

    /// http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-madd-2007-bl
    ///
    /// Assumes b.z == 1
    fn addMixed(a: G1, b: G1) G1 {
        // a==0, return b
        if (a.isZero()) return b;

        var zz: Fp = undefined;
        var u_2: Fp = undefined;
        var s2: Fp = undefined;

        var h: Fp = undefined;
        var hh: Fp = undefined;

        var i: Fp = undefined;
        var j: Fp = undefined;

        var rr: Fp = undefined;
        var v: Fp = undefined;

        var r: G1 = undefined;

        // Z1Z1 = Z1^2
        zz.sq(a.z);
        // U2 = X2 * Z1Z1
        u_2.mul(b.x, zz);
        // S2 = Y2*Z1*Z1Z1
        s2.mul(b.y, a.z);
        s2.mul(s2, zz);

        // if a == b, use dbl()
        if (u_2.eql(a.x) and s2.eql(a.y)) return a.dbl();

        // H = U2-X1
        h.sub(u_2, a.x);
        // HH = H^2
        hh.sq(h);
        // I = 4*HH
        i.add(hh, hh);
        i.add(i, i);
        // J = H*I
        j.mul(h, i);
        // r = 2*(S2-Y1)
        rr.sub(s2, a.y);
        rr.add(rr, rr);
        // V = X1*I
        v.mul(a.x, i);
        // X3 = r^2 - J - 2*V
        r.x.sq(rr);
        r.x.sub(r.x, j);
        r.x.sub(r.x, v);
        r.x.sub(r.x, v);
        // Y3 = r*(V - V3) - 2*Y1*J
        // re-use `i`, it isn't used anymore
        i.mul(a.y, j);
        i.add(i, i);
        r.y.sub(v, r.x);
        r.y.mul(r.y, rr);
        r.y.sub(r.y, i);
        // Z3 = (Z1 + H)^2 - Z1Z1 - HH
        r.z.add(a.z, h);
        r.z.sq(r.z);
        r.z.sub(r.z, zz);
        r.z.sub(r.z, hh);

        return r;
    }

    /// Assumes that `a` is affine.
    ///
    /// https://encrypt.a41.io/primitives/abstract-algebra/elliptic-curve/scalar-multiplication/double-and-add
    /// https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Double-and-add
    fn mulScalar(a: G1, scalar: [4]u64) G1 {
        // TODO: can be further optimized with GLV and wNAF
        const leading = @clz(@as(u256, @bitCast(scalar)));
        if (leading == 256) return .zero;
        var i: u8 = @intCast(256 - 1 - leading);
        var r = a;
        while (i > 0) {
            i -= 1;
            r = r.dbl();
            if (bit(scalar, i)) {
                r = addMixed(r, a);
            }
        }
        return r;
    }
};

pub const G2 = struct {
    x: Fp2,
    y: Fp2,
    z: Fp2,

    const zero: G2 = .{
        .x = .zero,
        .y = .zero,
        .z = .zero,
    };

    fn fromBytesInternal(input: *const [128]u8) !G2 {
        if (std.mem.allEqual(u8, input, 0)) return .zero;

        var flags: Flags = undefined;
        return .{
            .x = try .fromBytes(input[0..64], null),
            .y = try .fromBytes(input[64..128], &flags),
            .z = if (flags.is_inf) .zero else .one,
        };
    }

    fn isWellFormed(p: G2) !void {
        // zero-point always well formed, no matter what X and Y are
        if (p.isZero()) return;

        // Check that y^2 = x^3 + b
        var y2: Fp2 = undefined;
        var x3b: Fp2 = undefined;
        // y^2
        y2.sq(p.y);
        // x^3 + b
        x3b.sq(p.x);
        x3b.mul(x3b, p.x);
        x3b.add(x3b, Fp2.constants.twist_b_mont);
        if (!y2.eql(x3b)) return error.NotWellFormed;

        // G2 does *not* have prime order, so we need to perform a secondary subgroup membership check.
        // https://eprint.iacr.org/2022/348, Sec 3.1.
        // [r]P == 0 <==> [x+1]P + ψ([x]P) + ψ²([x]P) = ψ³([2x]P)
        const xp: G2 = mulScalar(p, Fp.constants.x);
        var l: G2 = undefined;
        var psi: G2 = undefined;

        l.addMixed(xp, p);
        psi.frob(xp);
        l.add(l, psi);

        psi.frob2(xp);
        l.add(l, psi);
        psi.frob(psi);

        psi.dbl(psi);
        if (!l.eql(psi)) return error.NotWellFormed;
    }

    fn fromBytes(input: *const [128]u8) !G2 {
        var g2: G2 = try .fromBytesInternal(input);
        if (g2.isZero()) return g2;

        g2.x.toMont();
        g2.y.toMont();
        g2.z = .one;

        try g2.isWellFormed();

        return g2;
    }

    fn isZero(p: G2) bool {
        return p.z.isZero();
    }

    pub fn compress(out: *[64]u8, input: *const [128]u8) !void {
        const p: G2 = try .fromBytesInternal(input);

        const is_inf = p.isZero();
        const flag_inf = input[64] & Flags.INF;

        if (is_inf) {
            @memset(out, 0);
            // The infinity point in the result is set if and only if the infinity flag is set in the Y coordinate.
            out[0] |= flag_inf;
            return;
        }

        const is_neg = p.y.isNegative();
        @memcpy(out, input[0..64]);
        if (is_neg) out[0] |= Flags.NEG;
        return;
    }

    pub fn decompress(out: *[128]u8, input: *const [64]u8) !void {
        if (std.mem.allEqual(u8, input, 0)) return @memset(out, 0);

        var flags: Flags = undefined;
        var x: Fp2 = try .fromBytes(input, &flags);

        // no flags
        if (flags.is_inf) return @memset(out, 0);

        var x2: Fp2 = undefined;
        var x3b: Fp2 = undefined;
        var y: Fp2 = undefined;

        x.toMont();
        x2.sq(x);
        x3b.mul(x2, x);
        x3b.add(x3b, Fp2.constants.twist_b_mont);
        try y.sqrt(x3b);

        y.fromMont();
        if (flags.is_neg != y.isNegative()) {
            y.negateNotMontgomery(y);
        }

        @memcpy(out[0..64], input);
        out[0] &= Flags.MASK;
        y.toBytes(out[64..128]);
    }

    fn eql(a: G2, b: G2) bool {
        if (a.isZero()) return b.isZero();
        if (b.isZero()) return false;

        var pz2: Fp2 = undefined;
        var qz2: Fp2 = undefined;
        var l: Fp2 = undefined;
        var r: Fp2 = undefined;

        pz2.sq(a.z);
        qz2.sq(b.z);

        l.mul(a.x, qz2);
        r.mul(b.x, pz2);
        if (!l.eql(r)) return false;

        l.mul(a.y, qz2);
        l.mul(l, b.z);
        r.mul(b.y, pz2);
        r.mul(r, a.z);
        return l.eql(r);
    }

    /// http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-2007-bl
    fn add(r: *G2, a: G2, b: G2) void {
        if (a.isZero()) {
            r.* = b;
            return;
        }

        var zz1: Fp2 = undefined;
        var zz2: Fp2 = undefined;
        var u_1: Fp2 = undefined;
        var s1: Fp2 = undefined;
        var u_2: Fp2 = undefined;
        var s2: Fp2 = undefined;
        var h: Fp2 = undefined;
        var i: Fp2 = undefined;
        var j: Fp2 = undefined;
        var rr: Fp2 = undefined;
        var v: Fp2 = undefined;

        zz1.sq(a.z);
        zz2.sq(b.z);
        u_1.mul(a.x, zz2);
        u_2.mul(b.x, zz1);
        s1.mul(a.y, b.z);
        s1.mul(s1, zz2);
        s2.mul(b.y, a.z);
        s2.mul(s2, zz1);

        // if a==b, return dbl(a)
        if (u_2.eql(a.x) and s2.eql(a.y)) {
            return r.dbl(a);
        }

        h.sub(u_2, u_1);
        i.add(h, h);
        i.sq(i);
        j.mul(h, i);
        rr.sub(s2, s1);
        rr.add(rr, rr);
        v.mul(u_1, i);
        r.x.sq(rr);
        r.x.sub(r.x, j);
        r.x.sub(r.x, v);
        r.x.sub(r.x, v);
        i.mul(s1, j);
        i.add(i, i);
        r.y.sub(v, r.x);
        r.y.mul(r.y, rr);
        r.y.sub(r.y, i);
        r.z.add(a.z, b.z);
        r.z.sq(r.z);
        r.z.sub(r.z, zz1);
        r.z.sub(r.z, zz2);
        r.z.mul(r.z, h);
    }

    fn mulScalar(a: G2, comptime integer: u256) G2 {
        const limbs: [4]u64 = @bitCast(integer);
        var i = 255 - @clz(integer);
        var r = a;
        while (i > 0) {
            i -= 1;
            r.dbl(r);
            if (bit(limbs, @intCast(i))) {
                r.addMixed(r, a);
            }
        }
        return r;
    }

    pub fn frob(r: *G2, p: G2) void {
        r.x.conj(p.x);
        r.x.mul(r.x, Fp2.constants.frob_gamma1_mont[1]);
        r.y.conj(p.y);
        r.y.mul(r.y, Fp2.constants.frob_gamma1_mont[2]);
        r.z.conj(p.z);
    }

    pub fn frob2(r: *G2, p: G2) void {
        r.x.c0.mul(p.x.c0, Fp.constants.frob_gamma2_mont[1]);
        r.x.c1.mul(p.x.c1, Fp.constants.frob_gamma2_mont[1]);

        r.y.c0.mul(p.y.c0, Fp.constants.frob_gamma2_mont[2]);
        r.y.c1.mul(p.y.c1, Fp.constants.frob_gamma2_mont[2]);

        r.z = p.z;
    }

    pub fn negate(r: *G2, a: G2) void {
        r.x = a.x;
        r.y.negate(a.y);
        r.z = a.z;
    }

    /// https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2007-bl
    fn dbl(r: *G2, p: G2) void {
        if (p.isZero()) {
            r.* = p;
            return;
        }

        var xx: Fp2 = undefined;
        var yy: Fp2 = undefined;
        var zz: Fp2 = undefined;

        var y4: Fp2 = undefined;
        var s: Fp2 = undefined;
        var m: Fp2 = undefined;

        xx.sq(p.x);
        yy.sq(p.y);
        y4.sq(yy);
        zz.sq(p.z);
        s.add(p.x, yy);
        s.sq(s);
        s.sub(s, xx);
        s.sub(s, y4);
        s.add(s, s);
        m.add(xx, xx);
        m.add(m, xx);

        r.x.sq(m);
        r.x.sub(r.x, s);
        r.x.sub(r.x, s);
        r.z.add(p.z, p.y);
        r.z.sq(r.z);
        r.z.sub(r.z, yy);
        r.z.sub(r.z, zz);
        r.y.sub(s, r.x);
        r.y.mul(r.y, m);
        y4.add(y4, y4);
        y4.add(y4, y4);
        y4.add(y4, y4);
        r.y.sub(r.y, y4);
    }

    fn addMixed(r: *G2, a: G2, b: G2) void {
        // a==b, return b
        if (a.isZero()) {
            r.* = b;
            return;
        }

        var zz: Fp2 = undefined;
        var u_2: Fp2 = undefined;
        var s2: Fp2 = undefined;

        var h: Fp2 = undefined;
        var hh: Fp2 = undefined;

        var i: Fp2 = undefined;
        var j: Fp2 = undefined;

        var rr: Fp2 = undefined;
        var v: Fp2 = undefined;

        zz.sq(a.z);
        u_2.mul(b.x, zz);
        s2.mul(b.y, a.z);
        s2.mul(s2, zz);

        // if a==b, return dbl(a)
        if (u_2.eql(a.x) and s2.eql(a.y)) {
            return r.dbl(a);
        }

        h.sub(u_2, a.x);
        hh.sq(h);

        i.add(hh, hh);
        i.add(i, i);

        j.mul(h, i);

        rr.sub(s2, a.y);
        rr.add(rr, rr);

        v.mul(a.x, i);

        r.x.sq(rr);
        r.x.sub(r.x, j);
        r.x.sub(r.x, v);
        r.x.sub(r.x, v);

        i.mul(a.y, j);
        i.add(i, i);
        r.y.sub(v, r.x);
        r.y.mul(r.y, rr);
        r.y.sub(r.y, i);

        r.z.add(a.z, h);
        r.z.sq(r.z);
        r.z.sub(r.z, zz);
        r.z.sub(r.z, hh);
    }
};

pub fn addSyscall(out: *[64]u8, input: *const [128]u8) !void {
    const x: G1 = try .fromBytes(input[0..64]);
    const y: G1 = try .fromBytes(input[64..128]);
    const result = x.affineAdd(y);
    result.toBytes(out);
}

pub fn mulSyscall(out: *[64]u8, input: *const [96]u8) !void {
    const a: G1 = try .fromBytes(input[0..64]);
    // Scalar is provided in big-endian and we do *not* validate it.
    const b: [4]u64 = @bitCast(Fp.byteSwap(input[64..][0..32].*));
    const result = a.mulScalar(b);
    result.toBytes(out);
}

pub fn pairingSyscall(out: *[32]u8, input: []const u8) !void {
    const num_elements = input.len / 192;

    var p: std.BoundedArray(G1, pairing.BATCH_SIZE) = .{};
    var q: std.BoundedArray(G2, pairing.BATCH_SIZE) = .{};

    var r: Fp12 = .one;
    for (0..num_elements) |i| {
        const a: G1 = try .fromBytes(input[i * 192 ..][0..64]);
        const b: G2 = try .fromBytes(input[i * 192 ..][64..][0..128]);

        // Skip any pair where either A or B are points at infinity.
        if (a.isZero() or b.isZero()) continue;

        p.appendAssumeCapacity(a);
        q.appendAssumeCapacity(b);

        // Trigger batch when we're either on the last element or we're at the max batch size.
        if (p.len == pairing.BATCH_SIZE or i == num_elements - 1) {
            const tmp = pairing.millerLoop(p.constSlice(), q.constSlice());
            r.mul(r, tmp);
            p.clear();
            q.clear();
        }
    }

    r = pairing.finalExp(r);
    // Output is 0 or 1 as a big-endian u256.
    @memset(out, 0);
    if (r.isOne()) out[31] = 1;
}
