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

    fn fromBytesInternal(input: *const [64]u8, endian: std.builtin.Endian) !G1 {
        if (std.mem.allEqual(u8, input, 0)) return .zero;
        var flags: Flags = undefined;
        return .{
            .x = try .fromBytes(input[0..32], endian, null),
            .y = try .fromBytes(input[32..64], endian, &flags),
            .z = if (flags.is_inf) .zero else .one,
        };
    }

    fn isWellFormed(p: G1) !void {
        // zero-point always well formed, no matter what X and Y are
        if (p.isZero()) return;

        // Check that y^2 = x^3 + b
        const y2 = p.y.sq();
        const x3b = p.x.sq().mul(p.x).add(Fp.constants.b_mont);
        if (!y2.eql(x3b)) return error.NotWellFormed;

        // G1 has prime order so we do not need a subgroup membership check.
    }

    pub fn fromBytes(input: *const [64]u8, endian: std.builtin.Endian) !G1 {
        var g1 = try fromBytesInternal(input, endian);
        if (g1.isZero()) return g1;

        g1.x.toMont();
        g1.y.toMont();
        g1.z = .one;

        try g1.isWellFormed();

        return g1;
    }

    fn toBytes(p: G1, out: *[64]u8, endian: std.builtin.Endian) void {
        if (p.isZero()) {
            @memset(out, 0); // no flags
            return;
        }

        var r = shared.toAffine(p);
        r.x.fromMont();
        r.y.fromMont();
        r.x.toBytes(out[0..32], endian);
        r.y.toBytes(out[32..64], endian);
    }

    fn isZero(p: G1) bool {
        return p.z.isZero();
    }

    pub fn compress(out: *[32]u8, input: *const [64]u8, endian: std.builtin.Endian) !void {
        const p: G1 = try .fromBytesInternal(input, endian);

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
        const offset: u32 = switch (endian) {
            .little => 31,
            .big => 0,
        };
        if (is_neg) out[offset] |= Flags.NEG;
        return;
    }

    pub fn decompress(out: *[64]u8, input: *const [32]u8, endian: std.builtin.Endian) !void {
        // All zeroes input, all zeroes out, no flags.
        if (std.mem.allEqual(u8, input, 0)) return @memset(out, 0);

        var flags: Flags = undefined;
        const x: Fp = try .fromBytes(input, endian, &flags);

        // If the point at infinity flag is set, return the point at infinity without any
        // checks on the coordinates (X, Y) and no flags set.
        if (flags.is_inf) return @memset(out, 0);

        var xm = x;
        xm.toMont();
        // y^2 = x^3+b
        const x3b = xm.sq().mul(xm).add(Fp.constants.b_mont);
        var y = try x3b.sqrt();
        y.fromMont();
        if (flags.is_neg != y.isNegative()) {
            y.negateNotMontgomery(y); // correct the sign to the requested one
        }

        x.toBytes(out[0..32], endian);
        y.toBytes(out[32..64], endian);
        // no flags on y
    }

    pub fn addSyscall(out: *[64]u8, input: *const [128]u8, endian: std.builtin.Endian) !void {
        const x: G1 = try .fromBytes(input[0..64], endian);
        const y: G1 = try .fromBytes(input[64..128], endian);
        const result = shared.affineAdd(x, y);
        result.toBytes(out, endian);
    }

    pub fn mulSyscall(out: *[64]u8, input: *const [96]u8, endian: std.builtin.Endian) !void {
        const a: G1 = try .fromBytes(input[0..64], endian);
        // Scalar is provided in big-endian and we do *not* validate it.
        const b: u256 = @bitCast(switch (endian) {
            .big => Fp.byteSwap(input[64..][0..32].*),
            .little => input[64..][0..32].*,
        });
        const result = shared.mulScalar(a, b);
        result.toBytes(out, endian);
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

    fn fromBytesInternal(input: *const [128]u8, endian: std.builtin.Endian) !G2 {
        if (std.mem.allEqual(u8, input, 0)) return .zero;

        var flags: Flags = undefined;
        return .{
            .x = try .fromBytes(input[0..64], endian, null),
            .y = try .fromBytes(input[64..128], endian, &flags),
            .z = if (flags.is_inf) .zero else .one,
        };
    }

    fn isWellFormed(p: G2) !void {
        // zero-point always well formed, no matter what X and Y are
        if (p.isZero()) return;

        // Check that y^2 = x^3 + b
        const y2 = p.y.sq();
        const x3b = p.x.sq().mul(p.x).add(Fp2.constants.twist_b_mont);
        if (!y2.eql(x3b)) return error.NotWellFormed;

        // G2 does *not* have prime order, so we need to perform a secondary subgroup membership check.
        // https://eprint.iacr.org/2022/348, Sec 3.1.
        // [r]P == 0 <==> [x+1]P + ψ([x]P) + ψ²([x]P) = ψ³([2x]P)
        const xp: G2 = shared.mulScalar(p, Fp.constants.x);

        const psi = xp.frob();
        const psi2 = xp.frob2();

        const l = shared.addMixed(xp, p).add(psi).add(psi2);
        const r = shared.dbl(psi2.frob());

        if (!l.eql(r)) return error.NotWellFormed;
    }

    fn fromBytes(input: *const [128]u8, endian: std.builtin.Endian) !G2 {
        var g2: G2 = try .fromBytesInternal(input, endian);
        if (g2.isZero()) return g2;

        g2.x.toMont();
        g2.y.toMont();
        g2.z = .one;

        try g2.isWellFormed();

        return g2;
    }

    fn toBytes(p: G2, out: *[128]u8, endian: std.builtin.Endian) void {
        if (p.isZero()) {
            @memset(out, 0); // no flags
            return;
        }

        var r = shared.toAffine(p);
        r.x.fromMont();
        r.y.fromMont();
        r.x.toBytes(out[0..64], endian);
        r.y.toBytes(out[64..128], endian);
    }

    fn isZero(p: G2) bool {
        return p.z.isZero();
    }

    pub fn compress(out: *[64]u8, input: *const [128]u8, endian: std.builtin.Endian) !void {
        const p: G2 = try .fromBytesInternal(input, endian);

        const is_inf = p.isZero();
        const flag_inf = input[64] & Flags.INF;

        if (is_inf) {
            @memset(out, 0);
            // The infinity point in the result is set if and only if the infinity flag is set in the Y coordinate.
            out[0] |= flag_inf;
            return;
        }

        const is_neg = p.y.isNegative();
        p.x.toBytes(out, endian);
        const offset: u32 = switch (endian) {
            .little => 63,
            .big => 0,
        };
        if (is_neg) out[offset] |= Flags.NEG;
        return;
    }

    pub fn decompress(out: *[128]u8, input: *const [64]u8, endian: std.builtin.Endian) !void {
        if (std.mem.allEqual(u8, input, 0)) return @memset(out, 0);

        var flags: Flags = undefined;
        const x: Fp2 = try .fromBytes(input, endian, &flags);

        // no flags
        if (flags.is_inf) return @memset(out, 0);

        // y^2 = x^3+b
        var xm = x;
        xm.toMont();
        const x3b = xm.sq().mul(xm).add(Fp2.constants.twist_b_mont);
        var y = try x3b.sqrt();

        y.fromMont();
        if (flags.is_neg != y.isNegative()) {
            y.negateNotMontgomery(y);
        }

        x.toBytes(out[0..64], endian);
        y.toBytes(out[64..128], endian);
    }

    fn eql(a: G2, b: G2) bool {
        if (a.isZero()) return b.isZero();
        if (b.isZero()) return false;

        const l = a.z.sq();
        const r = b.z.sq();

        const rx = r.mul(a.x);
        const lx = l.mul(b.x);
        if (!lx.eql(rx)) return false;

        const r2 = r.mul(a.y).mul(b.z);
        const l2 = l.mul(b.y).mul(a.z);

        return l2.eql(r2);
    }

    /// http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-2007-bl
    fn add(a: G2, b: G2) G2 {
        // if a==0, return b
        if (a.isZero()) return b;

        // Z1Z1 = Z1^2
        const z1z1 = a.z.sq();
        // Z2Z2 = Z2^2
        const z2z2 = b.z.sq();
        // U1 = X1*Z2Z2
        const u_1 = a.x.mul(z2z2);
        // U2 = X2*Z1Z1
        const u_2 = b.x.mul(z1z1);
        // S1 = Y1*Z2*Z2Z2
        const s1 = a.y.mul(b.z).mul(z2z2);
        // S2 = Y2*Z1*Z1Z1
        const s2 = b.y.mul(a.z).mul(z1z1);

        // if a==b, return dbl(a)
        if (u_2.eql(a.x) and s2.eql(a.y)) return shared.dbl(a);

        // H = U2-U1
        const h = u_2.sub(u_1);
        // I = (2*H)^2
        const i = h.dbl().sq();
        // J = H*I
        const j = h.mul(i);
        // r = 2*(S2-S1)
        const r = s2.sub(s1).dbl();
        // V = U1*I
        const v = u_1.mul(i);

        // X3 = r^2-J-2*V
        const x3 = r.sq().sub(j).sub(v.dbl());
        // Y3 = r*(V-X3)-2*S1*J
        const y3 = v.sub(x3).mul(r).sub(s1.mul(j).dbl());
        // Z3 = ((Z1+Z2)^2-Z1Z1-Z2Z2)*H
        const z3 = a.z.add(b.z).sq().sub(z1z1).sub(z2z2).mul(h);

        return .{
            .x = x3,
            .y = y3,
            .z = z3,
        };
    }

    pub fn frob(p: G2) G2 {
        return .{
            .x = p.x.conj().mul(Fp2.constants.frob_gamma1_mont[1]),
            .y = p.y.conj().mul(Fp2.constants.frob_gamma1_mont[2]),
            .z = p.z.conj(),
        };
    }

    pub fn frob2(p: G2) G2 {
        return .{
            .x = .{
                .c0 = p.x.c0.mul(Fp.constants.frob_gamma2_mont[1]),
                .c1 = p.x.c1.mul(Fp.constants.frob_gamma2_mont[1]),
            },
            .y = .{
                .c0 = p.y.c0.mul(Fp.constants.frob_gamma2_mont[2]),
                .c1 = p.y.c1.mul(Fp.constants.frob_gamma2_mont[2]),
            },
            .z = p.z,
        };
    }

    pub fn negate(a: G2) G2 {
        return .{
            .x = a.x,
            .y = a.y.negate(),
            .z = a.z,
        };
    }

    pub fn addSyscall(out: *[128]u8, input: *const [256]u8, endian: std.builtin.Endian) !void {
        const x: G2 = try .fromBytes(input[0..128], endian);
        const y: G2 = try .fromBytes(input[128..256], endian);
        const result = shared.affineAdd(x, y);
        result.toBytes(out, endian);
    }

    pub fn mulSyscall(out: *[128]u8, input: *const [160]u8, endian: std.builtin.Endian) !void {
        const a: G2 = try .fromBytes(input[0..128], endian);
        const scalar = input[128..][0..32].*;
        const b: u256 = @bitCast(switch (endian) {
            .big => Fp.byteSwap(scalar),
            .little => scalar,
        });
        const result = shared.mulScalar(a, b);
        result.toBytes(out, endian);
    }
};

const shared = struct {
    fn toAffine(p: anytype) @TypeOf(p) {
        if (p.z.isZero() or p.z.isOne()) {
            // nothing to do
            return p;
        }

        // if Z is neither zero nor one, need to flatten down
        const iz = p.z.inverse();
        const iz2 = iz.sq();

        // x / z^2, y / z^3
        return .{
            .x = p.x.mul(iz2),
            .y = p.y.mul(iz2).mul(iz),
            .z = .one,
        };
    }

    /// Implementation is shared between G1 and G2.
    /// https://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-madd-2007-bl
    /// Assumes b is affine (Z2 == 1).
    fn addMixed(a: anytype, b: anytype) @TypeOf(a, b) {
        // a==0, return b
        if (a.isZero()) return b;

        // Z1Z1 = Z1^2
        const z1z1 = a.z.sq();
        // U2 = X2*Z1Z1
        const u_2 = b.x.mul(z1z1);
        // S2 = Y2*Z1*Z1Z1
        const s2 = b.y.mul(a.z).mul(z1z1);

        if (u_2.eql(a.x) and s2.eql(a.y)) return dbl(a);

        // H = U2-X1
        const h = u_2.sub(a.x);
        // HH = H^2
        const hh = h.sq();
        // I = 4*HH
        const i = hh.dbl().dbl();
        // J = H*I
        const j = h.mul(i);
        // r = 2*(S2-Y1)
        const rr = s2.sub(a.y).dbl();
        // V = X1*I
        const v = a.x.mul(i);
        // X3 = r^2 - J - 2*V
        const x3 = rr.sq().sub(j).sub(v).sub(v);
        // Y3 = r*(V - V3) - 2*Y1*J
        const y3 = v.sub(x3).mul(rr).sub(a.y.mul(j).dbl());
        // Z3 = (Z1 + H)^2 - Z1Z1 - HH
        const z3 = a.z.add(h).sq().sub(z1z1).sub(hh);

        return .{
            .x = x3,
            .y = y3,
            .z = z3,
        };
    }

    /// Compute a + b.
    ///
    /// Both a and b are affine (Z1 == 1, Z2 == 1).
    /// https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-mmadd-2007-bl
    fn affineAdd(a: anytype, b: anytype) @TypeOf(a, b) {
        // if a == 0, return b
        if (a.isZero()) return b;
        // if b == 0, return a
        if (b.isZero()) return a;

        // if X coord is equal, means either the points are the same (same side)
        // or they're opposite (one on the top, other one on the bottom).
        const lambda = if (a.x.eql(b.x)) r: {
            if (a.y.eql(b.y)) {
                // a == b => point double: lambda = 3 * x1^2 / (2 * y1)
                const x = a.x.sq().triple();
                const y = a.y.dbl(); // y = 2 * y1
                break :r y.inverse().mul(x);
            } else {
                // a == -b => 0
                return .zero;
            }
        } else r: {
            // point add: lambda = (y1 - y2) / (x1 - x2)
            const x = a.x.sub(b.x);
            const y = a.y.sub(b.y);
            break :r x.inverse().mul(y);
        };

        // x3 = lambda^2 - x1 - x2
        const x = lambda.sq().sub(a.x).sub(b.x);
        // y3 = lambda * (x1 - x3) - y1
        const y = a.x.sub(x).mul(lambda).sub(a.y);

        return .{
            .x = x,
            .y = y,
            .z = .one,
        };
    }

    /// Implementation shared between G1 and G2.
    /// https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2007-bl
    fn dbl(p: anytype) @TypeOf(p) {
        if (p.isZero()) return .zero;

        // XX = X1^2
        const xx = p.x.sq();
        // YY = Y1^2
        const yy = p.y.sq();
        // ZZ = Z1^2
        const zz = p.z.sq();
        // YYYY = YY^2
        const y4 = yy.sq();
        // S = 2*((X1+YY)^2-XX-YYYY)
        const s = p.x.add(yy).sq().sub(xx).sub(y4).dbl();
        // M = 3*XX + a*ZZ^2, but a = 0
        const m = xx.triple();

        // T = M^2-2*S
        const t = m.sq().sub(s).sub(s);
        // Y3 = M*(S-T)-8*YYYY
        const y3 = s.sub(t).mul(m).sub(y4.dbl().dbl().dbl());
        // Z3 = (Y1+Z1)^2-YY-ZZ
        const z3 = p.y.add(p.z).sq().sub(yy).sub(zz);

        return .{
            .x = t,
            .y = y3,
            .z = z3,
        };
    }

    /// Assumes that `a` is affine.
    ///
    /// https://encrypt.a41.io/primitives/abstract-algebra/elliptic-curve/scalar-multiplication/double-and-add
    /// https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Double-and-add
    fn mulScalar(a: anytype, scalar: u256) @TypeOf(a) {
        // TODO: can be further optimized with GLV and wNAF
        const limbs: [4]u64 = @bitCast(scalar);
        const leading = @clz(scalar);
        if (leading == 256) return .zero;
        var i: u8 = @intCast(256 - 1 - leading);
        var r = a;
        while (i > 0) {
            i -= 1;
            r = dbl(r);
            if (bit(limbs, i)) r = addMixed(r, a);
        }
        return r;
    }
};

pub fn pairingSyscall(out: *[32]u8, input: []const u8, endian: std.builtin.Endian) !void {
    const num_elements = input.len / 192;

    var p: std.BoundedArray(G1, pairing.BATCH_SIZE) = .{};
    var q: std.BoundedArray(G2, pairing.BATCH_SIZE) = .{};

    var r: Fp12 = .one;
    for (0..num_elements) |i| {
        const a: G1 = try .fromBytes(input[i * 192 ..][0..64], endian);
        const b: G2 = try .fromBytes(input[i * 192 ..][64..][0..128], endian);

        // Skip any pair where either A or B are points at infinity.
        if (a.isZero() or b.isZero()) continue;

        p.appendAssumeCapacity(a);
        q.appendAssumeCapacity(b);

        // Trigger batch when we're either on the last element or we're at the max batch size.
        if (p.len == pairing.BATCH_SIZE or i == num_elements - 1) {
            const tmp = pairing.millerLoop(p.constSlice(), q.constSlice());
            r = r.mul(tmp);
            p.clear();
            q.clear();
        }
    }

    r = pairing.finalExp(r);
    // Output is 0 or 1 as a u256.
    @memset(out, 0);
    const offset: u32 = switch (endian) {
        .little => 0,
        .big => 31,
    };
    if (r.isOne()) out[offset] = 1;
}
