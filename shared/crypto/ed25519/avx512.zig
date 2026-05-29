//! This implementation takes inspiration from:
//! https://github.com/dalek-cryptography/curve25519-dalek/tree/c3f91f762042debf7c516c21ad9b9a2a9f4ef3b8/curve25519-dalek/src/backend/vector/ifma

const std = @import("std");
const Ed25519 = std.crypto.ecc.Edwards25519;
const Fe = Ed25519.Fe;

const u32x8 = @Vector(8, u32);
const i32x8 = @Vector(8, i32);
const u64x4 = @Vector(4, u64);
const u52x4 = @Vector(4, u52);

// TODO: there's no inherent limitation from using inline assembly instead,
// however this currently (Zig 0.14.1) crashes both LLVM and the self-hosted backend.
// Also, should investigate whether directly using LLVM intrinsics leads to potentially
// better codegen as opposed to inline assembly.
extern fn @"llvm.x86.avx512.vpmadd52l.uq.256"(u64x4, u64x4, u64x4) u64x4;
extern fn @"llvm.x86.avx512.vpmadd52h.uq.256"(u64x4, u64x4, u64x4) u64x4;

inline fn madd52lo(x: u64x4, y: u64x4, z: u64x4) u64x4 {
    if (@inComptime()) {
        const V = @Vector(4, u128);
        const tsrc2: u52x4 = @truncate(z);
        const temp128 = @as(V, @as(u52x4, @truncate(y))) * @as(V, tsrc2);
        return x + @as(u52x4, @truncate(temp128));
    } else {
        return @"llvm.x86.avx512.vpmadd52l.uq.256"(x, y, z);
    }
}

inline fn madd52hi(x: u64x4, y: u64x4, z: u64x4) u64x4 {
    if (@inComptime()) {
        const V = @Vector(4, u128);
        const tsrc2: u52x4 = @truncate(z);
        const temp128 = @as(V, @as(u52x4, @truncate(y))) * @as(V, tsrc2);
        return x + @as(u52x4, @truncate(temp128 >> @splat(52)));
    } else {
        return @"llvm.x86.avx512.vpmadd52h.uq.256"(x, y, z);
    }
}

/// A vector of four field elements.
pub const ExtendedPoint = struct {
    /// [ X0, Y0, Z0, T0 ]
    /// [ X1, Y1, Z1, T1 ]
    /// [ X2, Y2, Z2, T2 ]
    /// [ X3, Y3, Z3, T3 ]
    /// [ X4, Y4, Z4, T4 ]
    limbs: [5]u64x4,

    const zero: ExtendedPoint = .{ .limbs = @splat(@splat(0)) };
    pub const identityElement: ExtendedPoint = .{ .limbs = .{
        .{ 0, 1, 1, 0 },
        .{ 0, 0, 0, 0 },
        .{ 0, 0, 0, 0 },
        .{ 0, 0, 0, 0 },
        .{ 0, 0, 0, 0 },
    } };

    pub fn init(x0: Fe, x1: Fe, x2: Fe, x3: Fe) ExtendedPoint {
        return .{ .limbs = .{
            .{ x0.limbs[0], x1.limbs[0], x2.limbs[0], x3.limbs[0] },
            .{ x0.limbs[1], x1.limbs[1], x2.limbs[1], x3.limbs[1] },
            .{ x0.limbs[2], x1.limbs[2], x2.limbs[2], x3.limbs[2] },
            .{ x0.limbs[3], x1.limbs[3], x2.limbs[3], x3.limbs[3] },
            .{ x0.limbs[4], x1.limbs[4], x2.limbs[4], x3.limbs[4] },
        } };
    }

    fn splat(x: Fe) ExtendedPoint {
        return init(x, x, x, x);
    }

    fn fromCached(cp: CachedPoint) ExtendedPoint {
        return .{ .limbs = cp.limbs };
    }

    pub fn fromPoint(ed: Ed25519) ExtendedPoint {
        return init(ed.x, ed.y, ed.z, ed.t);
    }

    pub fn toPoint(self: ExtendedPoint) Ed25519 {
        const reduced = self.reduce();
        const splits = fromCached(reduced).split();
        return .{
            .x = splits[0],
            .y = splits[1],
            .z = splits[2],
            .t = splits[3],
        };
    }

    fn split(self: ExtendedPoint) [4]Fe {
        const limbs = self.limbs;
        return .{
            .{ .limbs = .{ limbs[0][0], limbs[1][0], limbs[2][0], limbs[3][0], limbs[4][0] } },
            .{ .limbs = .{ limbs[0][1], limbs[1][1], limbs[2][1], limbs[3][1], limbs[4][1] } },
            .{ .limbs = .{ limbs[0][2], limbs[1][2], limbs[2][2], limbs[3][2], limbs[4][2] } },
            .{ .limbs = .{ limbs[0][3], limbs[1][3], limbs[2][3], limbs[3][3], limbs[4][3] } },
        };
    }

    fn reduce(self: ExtendedPoint) CachedPoint {
        const mask: u64x4 = @splat((1 << 51) - 1);
        const r19: u64x4 = @splat(19);

        const c0 = self.limbs[0] >> @splat(51);
        const c1 = self.limbs[1] >> @splat(51);
        const c2 = self.limbs[2] >> @splat(51);
        const c3 = self.limbs[3] >> @splat(51);
        const c4 = self.limbs[4] >> @splat(51);

        return .{ .limbs = .{
            madd52lo(self.limbs[0] & mask, c4, r19),
            (self.limbs[1] & mask) + c0,
            (self.limbs[2] & mask) + c1,
            (self.limbs[3] & mask) + c2,
            (self.limbs[4] & mask) + c3,
        } };
    }

    pub fn add(self: ExtendedPoint, other: ExtendedPoint) ExtendedPoint {
        return self.addCached(.fromExtended(other));
    }

    fn addLimbs(self: ExtendedPoint, other: ExtendedPoint) ExtendedPoint {
        return .{ .limbs = .{
            self.limbs[0] + other.limbs[0],
            self.limbs[1] + other.limbs[1],
            self.limbs[2] + other.limbs[2],
            self.limbs[3] + other.limbs[3],
            self.limbs[4] + other.limbs[4],
        } };
    }

    pub fn addCached(self: ExtendedPoint, cp: CachedPoint) ExtendedPoint {
        var tmp = self;
        tmp = tmp.blend(tmp.diffSum(), .AB);
        tmp = tmp.reduce().mul(cp);
        tmp = tmp.shuffle(.ABDC);

        const reduced = tmp.diffSum().reduce();
        const t0 = reduced.shuffle(.ADDA);
        const t1 = reduced.shuffle(.CBCB);

        return t0.mul(t1);
    }

    pub fn subCached(self: ExtendedPoint, cp: CachedPoint) ExtendedPoint {
        return self.addCached(cp.neg());
    }

    fn shuffle(self: ExtendedPoint, comptime control: Shuffle) ExtendedPoint {
        return .{ .limbs = .{
            shuffleLanes(control, self.limbs[0]),
            shuffleLanes(control, self.limbs[1]),
            shuffleLanes(control, self.limbs[2]),
            shuffleLanes(control, self.limbs[3]),
            shuffleLanes(control, self.limbs[4]),
        } };
    }

    fn blend(self: ExtendedPoint, other: ExtendedPoint, comptime control: Lanes) ExtendedPoint {
        return .{ .limbs = .{
            blendLanes(control, self.limbs[0], other.limbs[0]),
            blendLanes(control, self.limbs[1], other.limbs[1]),
            blendLanes(control, self.limbs[2], other.limbs[2]),
            blendLanes(control, self.limbs[3], other.limbs[3]),
            blendLanes(control, self.limbs[4], other.limbs[4]),
        } };
    }

    fn diffSum(self: ExtendedPoint) ExtendedPoint {
        const tmp1 = self.shuffle(.BADC);
        const tmp2 = self.blend(self.negateLazy(), .AC);
        return tmp1.addLimbs(tmp2);
    }

    fn negateLazy(self: ExtendedPoint) ExtendedPoint {
        const lo: u64x4 = @splat(0x7FFFFFFFFFFED0);
        const hi: u64x4 = @splat(0x7FFFFFFFFFFFF0);
        return .{ .limbs = .{
            lo - self.limbs[0],
            hi - self.limbs[1],
            hi - self.limbs[2],
            hi - self.limbs[3],
            hi - self.limbs[4],
        } };
    }

    pub fn dbl(self: ExtendedPoint) ExtendedPoint {
        var tmp0 = self.shuffle(.BADC);
        var tmp1 = self.addLimbs(tmp0).shuffle(.ABAB);

        tmp0 = self.blend(tmp1, .D);
        tmp1 = tmp0.reduce().square();

        const S1_S1_S1_S1 = tmp1.shuffle(.AAAA);
        const S2_S2_S2_S2 = tmp1.shuffle(.BBBB);

        const S2_S2_S2_S4 = S2_S2_S2_S2.blend(tmp1, .D).negateLazy();

        tmp0 = S1_S1_S1_S1.addLimbs(zero.blend(tmp1.addLimbs(tmp1), .C));
        tmp0 = tmp0.addLimbs(zero.blend(S2_S2_S2_S2, .AD));
        tmp0 = tmp0.addLimbs(zero.blend(S2_S2_S2_S4, .BCD));

        const tmp2 = tmp0.reduce();
        return tmp2.shuffle(.DBBD).mul(tmp2.shuffle(.CACA));
    }

    pub fn mulByPow2(self: ExtendedPoint, comptime k: u32) ExtendedPoint {
        var s = self;
        for (0..k) |_| s = s.dbl();
        return s;
    }
};

pub const CachedPoint = struct {
    limbs: [5]u64x4,

    // zig fmt: off
    pub const identityElement: CachedPoint = .{ .limbs = .{
        .{ 121647,           121666, 243332, 2251799813685229 },
        .{ 2251799813685248, 0,      0,      2251799813685247 },
        .{ 2251799813685247, 0,      0,      2251799813685247 },
        .{ 2251799813685247, 0,      0,      2251799813685247 },
        .{ 2251799813685247, 0,      0,      2251799813685247 },
    } };
    // zig fmt: on

    fn mul(self: CachedPoint, b: CachedPoint) ExtendedPoint {
        const x = self.limbs;
        const y = b.limbs;

        // Accumulators for terms with coeff 1
        var z0_1: u64x4 = @splat(0);
        var z1_1: u64x4 = @splat(0);
        var z2_1: u64x4 = @splat(0);
        var z3_1: u64x4 = @splat(0);
        var z4_1: u64x4 = @splat(0);
        var z5_1: u64x4 = @splat(0);
        var z6_1: u64x4 = @splat(0);
        var z7_1: u64x4 = @splat(0);
        var z8_1: u64x4 = @splat(0);

        // Accumulators for terms with coeff 2
        var z0_2: u64x4 = @splat(0);
        var z1_2: u64x4 = @splat(0);
        var z2_2: u64x4 = @splat(0);
        var z3_2: u64x4 = @splat(0);
        var z4_2: u64x4 = @splat(0);
        var z5_2: u64x4 = @splat(0);
        var z6_2: u64x4 = @splat(0);
        var z7_2: u64x4 = @splat(0);
        var z8_2: u64x4 = @splat(0);
        var z9_2: u64x4 = @splat(0);

        // Wave 0
        z4_1 = madd52lo(z4_1, x[2], y[2]);
        z5_2 = madd52hi(z5_2, x[2], y[2]);
        z5_1 = madd52lo(z5_1, x[4], y[1]);
        z6_2 = madd52hi(z6_2, x[4], y[1]);
        z6_1 = madd52lo(z6_1, x[4], y[2]);
        z7_2 = madd52hi(z7_2, x[4], y[2]);
        z7_1 = madd52lo(z7_1, x[4], y[3]);
        z8_2 = madd52hi(z8_2, x[4], y[3]);

        // Wave 1
        z4_1 = madd52lo(z4_1, x[3], y[1]);
        z5_2 = madd52hi(z5_2, x[3], y[1]);
        z5_1 = madd52lo(z5_1, x[3], y[2]);
        z6_2 = madd52hi(z6_2, x[3], y[2]);
        z6_1 = madd52lo(z6_1, x[3], y[3]);
        z7_2 = madd52hi(z7_2, x[3], y[3]);
        z7_1 = madd52lo(z7_1, x[3], y[4]);
        z8_2 = madd52hi(z8_2, x[3], y[4]);

        // Wave 2
        z8_1 = madd52lo(z8_1, x[4], y[4]);
        z9_2 = madd52hi(z9_2, x[4], y[4]);
        z4_1 = madd52lo(z4_1, x[4], y[0]);
        z5_2 = madd52hi(z5_2, x[4], y[0]);
        z5_1 = madd52lo(z5_1, x[2], y[3]);
        z6_2 = madd52hi(z6_2, x[2], y[3]);
        z6_1 = madd52lo(z6_1, x[2], y[4]);
        z7_2 = madd52hi(z7_2, x[2], y[4]);

        const z8 = z8_1 + z8_2 + z8_2;
        const z9 = z9_2 + z9_2;

        // Wave 3
        z3_1 = madd52lo(z3_1, x[3], y[0]);
        z4_2 = madd52hi(z4_2, x[3], y[0]);
        z4_1 = madd52lo(z4_1, x[1], y[3]);
        z5_2 = madd52hi(z5_2, x[1], y[3]);
        z5_1 = madd52lo(z5_1, x[1], y[4]);
        z6_2 = madd52hi(z6_2, x[1], y[4]);
        z2_1 = madd52lo(z2_1, x[2], y[0]);
        z3_2 = madd52hi(z3_2, x[2], y[0]);

        const z6 = z6_1 + z6_2 + z6_2;
        const z7 = z7_1 + z7_2 + z7_2;

        // Wave 4
        z3_1 = madd52lo(z3_1, x[2], y[1]);
        z4_2 = madd52hi(z4_2, x[2], y[1]);
        z4_1 = madd52lo(z4_1, x[0], y[4]);
        z5_2 = madd52hi(z5_2, x[0], y[4]);
        z1_1 = madd52lo(z1_1, x[1], y[0]);
        z2_2 = madd52hi(z2_2, x[1], y[0]);
        z2_1 = madd52lo(z2_1, x[1], y[1]);
        z3_2 = madd52hi(z3_2, x[1], y[1]);

        const z5 = z5_1 + z5_2 + z5_2;

        // Wave 5
        z3_1 = madd52lo(z3_1, x[1], y[2]);
        z4_2 = madd52hi(z4_2, x[1], y[2]);
        z0_1 = madd52lo(z0_1, x[0], y[0]);
        z1_2 = madd52hi(z1_2, x[0], y[0]);
        z1_1 = madd52lo(z1_1, x[0], y[1]);
        z2_1 = madd52lo(z2_1, x[0], y[2]);
        z2_2 = madd52hi(z2_2, x[0], y[1]);
        z3_2 = madd52hi(z3_2, x[0], y[2]);

        var t0: u64x4 = @splat(0);
        var t1: u64x4 = @splat(0);
        const r19: u64x4 = @splat(19);

        // Wave 6
        t0 = madd52hi(t0, r19, z9);
        t1 = madd52lo(t1, r19, z9 >> @splat(52));
        z3_1 = madd52lo(z3_1, x[0], y[3]);
        z4_2 = madd52hi(z4_2, x[0], y[3]);
        z1_2 = madd52lo(z1_2, r19, z5 >> @splat(52));
        z2_2 = madd52lo(z2_2, r19, z6 >> @splat(52));
        z3_2 = madd52lo(z3_2, r19, z7 >> @splat(52));
        z0_1 = madd52lo(z0_1, r19, z5);

        // Wave 7
        z4_1 = madd52lo(z4_1, r19, z9);
        z1_1 = madd52lo(z1_1, r19, z6);
        z0_2 = madd52lo(z0_2, r19, t0 + t1);
        z4_2 = madd52hi(z4_2, r19, z8);
        z2_1 = madd52lo(z2_1, r19, z7);
        z1_2 = madd52hi(z1_2, r19, z5);
        z2_2 = madd52hi(z2_2, r19, z6);
        z3_2 = madd52hi(z3_2, r19, z7);

        // Wave 8
        z3_1 = madd52lo(z3_1, r19, z8);
        z4_2 = madd52lo(z4_2, r19, z8 >> @splat(52));

        return .{ .limbs = .{
            z0_1 + z0_2 + z0_2,
            z1_1 + z1_2 + z1_2,
            z2_1 + z2_2 + z2_2,
            z3_1 + z3_2 + z3_2,
            z4_1 + z4_2 + z4_2,
        } };
    }

    fn mulConstants(self: CachedPoint, scalars: [4]u32) ExtendedPoint {
        const x = self.limbs;
        const y: u64x4 = scalars;

        const r19: u64x4 = @splat(19);
        var z0_1: u64x4 = @splat(0);
        var z1_1: u64x4 = @splat(0);
        var z2_1: u64x4 = @splat(0);
        var z3_1: u64x4 = @splat(0);
        var z4_1: u64x4 = @splat(0);
        var z1_2: u64x4 = @splat(0);
        var z2_2: u64x4 = @splat(0);
        var z3_2: u64x4 = @splat(0);
        var z4_2: u64x4 = @splat(0);
        var z5_2: u64x4 = @splat(0);

        // Wave 0
        z4_2 = madd52hi(z4_2, y, x[3]);
        z5_2 = madd52hi(z5_2, y, x[4]);
        z4_1 = madd52lo(z4_1, y, x[4]);
        z0_1 = madd52lo(z0_1, y, x[0]);
        z3_1 = madd52lo(z3_1, y, x[3]);
        z2_1 = madd52lo(z2_1, y, x[2]);
        z1_1 = madd52lo(z1_1, y, x[1]);
        z3_2 = madd52hi(z3_2, y, x[2]);

        // Wave 2
        z2_2 = madd52hi(z2_2, y, x[1]);
        z1_2 = madd52hi(z1_2, y, x[0]);
        z0_1 = madd52lo(z0_1, z5_2 + z5_2, r19);

        return .{ .limbs = .{
            z0_1,
            z1_1 + z1_2 + z1_2,
            z2_1 + z2_2 + z2_2,
            z3_1 + z3_2 + z3_2,
            z4_1 + z4_2 + z4_2,
        } };
    }

    fn square(self: CachedPoint) ExtendedPoint {
        const x = self.limbs;

        // Represent values with coeff. 2
        var z0_2: u64x4 = @splat(0);
        var z1_2: u64x4 = @splat(0);
        var z2_2: u64x4 = @splat(0);
        var z3_2: u64x4 = @splat(0);
        var z4_2: u64x4 = @splat(0);
        var z5_2: u64x4 = @splat(0);
        var z6_2: u64x4 = @splat(0);
        var z7_2: u64x4 = @splat(0);
        var z9_2: u64x4 = @splat(0);

        // Represent values with coeff. 4
        var z2_4: u64x4 = @splat(0);
        var z3_4: u64x4 = @splat(0);
        var z4_4: u64x4 = @splat(0);
        var z5_4: u64x4 = @splat(0);
        var z6_4: u64x4 = @splat(0);
        var z7_4: u64x4 = @splat(0);
        var z8_4: u64x4 = @splat(0);

        var z0_1: u64x4 = @splat(0);
        z0_1 = madd52lo(z0_1, x[0], x[0]);

        var z1_1: u64x4 = @splat(0);
        z1_2 = madd52lo(z1_2, x[0], x[1]);
        z1_2 = madd52hi(z1_2, x[0], x[0]);

        z2_4 = madd52hi(z2_4, x[0], x[1]);
        var z2_1 = z2_4 << @splat(2);
        z2_2 = madd52lo(z2_2, x[0], x[2]);
        z2_1 = madd52lo(z2_1, x[1], x[1]);

        z3_4 = madd52hi(z3_4, x[0], x[2]);
        var z3_1 = z3_4 << @splat(2);
        z3_2 = madd52lo(z3_2, x[1], x[2]);
        z3_2 = madd52lo(z3_2, x[0], x[3]);
        z3_2 = madd52hi(z3_2, x[1], x[1]);

        z4_4 = madd52hi(z4_4, x[1], x[2]);
        z4_4 = madd52hi(z4_4, x[0], x[3]);
        var z4_1 = z4_4 << @splat(2);
        z4_2 = madd52lo(z4_2, x[1], x[3]);
        z4_2 = madd52lo(z4_2, x[0], x[4]);
        z4_1 = madd52lo(z4_1, x[2], x[2]);

        z5_4 = madd52hi(z5_4, x[1], x[3]);
        z5_4 = madd52hi(z5_4, x[0], x[4]);
        var z5_1 = z5_4 << @splat(2);
        z5_2 = madd52lo(z5_2, x[2], x[3]);
        z5_2 = madd52lo(z5_2, x[1], x[4]);
        z5_2 = madd52hi(z5_2, x[2], x[2]);

        z6_4 = madd52hi(z6_4, x[2], x[3]);
        z6_4 = madd52hi(z6_4, x[1], x[4]);
        var z6_1 = z6_4 << @splat(2);
        z6_2 = madd52lo(z6_2, x[2], x[4]);
        z6_1 = madd52lo(z6_1, x[3], x[3]);

        z7_4 = madd52hi(z7_4, x[2], x[4]);
        var z7_1 = z7_4 << @splat(2);
        z7_2 = madd52lo(z7_2, x[3], x[4]);
        z7_2 = madd52hi(z7_2, x[3], x[3]);

        z8_4 = madd52hi(z8_4, x[3], x[4]);
        var z8_1 = z8_4 << @splat(2);
        z8_1 = madd52lo(z8_1, x[4], x[4]);

        var z9_1: u64x4 = @splat(0);
        z9_2 = madd52hi(z9_2, x[4], x[4]);

        z5_1 += z5_2 << @splat(1);
        z6_1 += z6_2 << @splat(1);
        z7_1 += z7_2 << @splat(1);
        z9_1 += z9_2 << @splat(1);

        var t0: u64x4 = @splat(0);
        var t1: u64x4 = @splat(0);
        const r19: u64x4 = @splat(19);

        t0 = madd52hi(t0, r19, z9_1);
        t1 = madd52lo(t1, r19, z9_1 >> @splat(52));

        z4_2 = madd52lo(z4_2, r19, z8_1 >> @splat(52));
        z3_2 = madd52lo(z3_2, r19, z7_1 >> @splat(52));
        z2_2 = madd52lo(z2_2, r19, z6_1 >> @splat(52));
        z1_2 = madd52lo(z1_2, r19, z5_1 >> @splat(52));

        z0_2 = madd52lo(z0_2, r19, t0 + t1);
        z1_2 = madd52hi(z1_2, r19, z5_1);
        z2_2 = madd52hi(z2_2, r19, z6_1);
        z3_2 = madd52hi(z3_2, r19, z7_1);
        z4_2 = madd52hi(z4_2, r19, z8_1);

        z0_1 = madd52lo(z0_1, r19, z5_1);
        z1_1 = madd52lo(z1_1, r19, z6_1);
        z2_1 = madd52lo(z2_1, r19, z7_1);
        z3_1 = madd52lo(z3_1, r19, z8_1);
        z4_1 = madd52lo(z4_1, r19, z9_1);

        return .{ .limbs = .{
            z0_1 + z0_2 + z0_2,
            z1_1 + z1_2 + z1_2,
            z2_1 + z2_2 + z2_2,
            z3_1 + z3_2 + z3_2,
            z4_1 + z4_2 + z4_2,
        } };
    }

    fn shuffle(self: CachedPoint, comptime control: Shuffle) CachedPoint {
        return .{ .limbs = .{
            shuffleLanes(control, self.limbs[0]),
            shuffleLanes(control, self.limbs[1]),
            shuffleLanes(control, self.limbs[2]),
            shuffleLanes(control, self.limbs[3]),
            shuffleLanes(control, self.limbs[4]),
        } };
    }

    fn blend(self: CachedPoint, other: CachedPoint, comptime control: Lanes) CachedPoint {
        return .{ .limbs = .{
            blendLanes(control, self.limbs[0], other.limbs[0]),
            blendLanes(control, self.limbs[1], other.limbs[1]),
            blendLanes(control, self.limbs[2], other.limbs[2]),
            blendLanes(control, self.limbs[3], other.limbs[3]),
            blendLanes(control, self.limbs[4], other.limbs[4]),
        } };
    }

    pub fn neg(self: CachedPoint) CachedPoint {
        const swapped = self.shuffle(.BACD);
        const negated = ExtendedPoint.fromCached(self).negateLazy().reduce();
        return swapped.blend(negated, .D);
    }

    pub fn fromExtended(fe: ExtendedPoint) CachedPoint {
        var x = fe;
        x = x.blend(x.diffSum(), .AB);
        x = x.reduce().mulConstants(.{ 121666, 121666, 2 * 121666, 2 * 121665 });
        x = x.blend(x.negateLazy(), .D);
        return x.reduce();
    }
};

pub const Shuffle = enum {
    AAAA,
    BBBB,
    BADC,
    BACD,
    ADDA,
    CBCB,
    ABDC,
    ABAB,
    DBBD,
    CACA,
};

pub const Lanes = enum {
    D,
    C,
    AB,
    AC,
    AD,
    BCD,
};

inline fn shuffleLanes(comptime control: Shuffle, x: u64x4) u64x4 {
    const c: u32 = switch (control) {
        .AAAA => 0b00_00_00_00,
        .BBBB => 0b01_01_01_01,
        .BADC => 0b10_11_00_01,
        .BACD => 0b11_10_00_01,
        .ADDA => 0b00_11_11_00,
        .CBCB => 0b01_10_01_10,
        .ABDC => 0b10_11_01_00,
        .ABAB => 0b01_00_01_00,
        .DBBD => 0b11_01_01_11,
        .CACA => 0b00_10_00_10,
    };
    return @shuffle(
        u64,
        x,
        undefined,
        @Vector(4, i32){
            c & 0b11,
            (c >> 2) & 0b11,
            (c >> 4) & 0b11,
            (c >> 6) & 0b11,
        },
    );
}

fn blendLanes(comptime control: Lanes, x: u64x4, y: u64x4) u64x4 {
    const c: u32 = switch (control) {
        .D => 0b11_00_00_00,
        .C => 0b00_11_00_00,
        .AB => 0b00_00_11_11,
        .AC => 0b00_11_00_11,
        .AD => 0b11_00_00_11,
        .BCD => 0b11_11_11_00,
    };
    // zig fmt: off
    return @bitCast(@shuffle(
        u32,
        @as(u32x8, @bitCast(x)),
        @as(u32x8, @bitCast(y)),
        @Vector(8, i32){
            @as([4]i32, .{ 0, ~@as(i32, 0), 0,            ~@as(i32, 0) })[c & 0b11],
            @as([4]i32, .{ 1, 1,            ~@as(i32, 1), ~@as(i32, 1) })[c & 0b11],
            @as([4]i32, .{ 2, ~@as(i32, 2), 2,            ~@as(i32, 2) })[(c >> 2) & 0b11],
            @as([4]i32, .{ 3, 3,            ~@as(i32, 3), ~@as(i32, 3) })[(c >> 2) & 0b11],
            @as([4]i32, .{ 4, ~@as(i32, 4), 4,            ~@as(i32, 4) })[(c >> 4) & 0b11],
            @as([4]i32, .{ 5, 5,            ~@as(i32, 5), ~@as(i32, 5) })[(c >> 4) & 0b11],
            @as([4]i32, .{ 6, ~@as(i32, 6), 6,            ~@as(i32, 6) })[(c >> 6) & 0b11],
            @as([4]i32, .{ 7, 7,            ~@as(i32, 7), ~@as(i32, 7) })[(c >> 6) & 0b11],
        },
    ));
    // zig fmt: on
}

test "vpmadd52luq" {
    const x: u64x4 = @splat(2);
    const y: u64x4 = @splat(3);
    const z: u64x4 = @splat(5);

    try std.testing.expectEqual(
        madd52lo(x, y, z),
        @as(u64x4, @splat(2 + 3 * 5)),
    );
}

test "split round trip on reduced input" {
    var a: Fe = .{ .limbs = .{ 2438, 24, 243, 0, 0 } };
    a = a.invert();

    const ax4 = ExtendedPoint.init(a, a, a, a);
    const split = ax4.split();

    for (split) |s| {
        try std.testing.expectEqual(s, a);
    }
}

test "split round trip on unreduced input" {
    var a: Fe = .{ .limbs = .{ 2438, 24, 243, 0, 0 } };
    a = a.invert();
    // multiply by 16 without reducing
    const a16: Fe = .{ .limbs = .{
        a.limbs[0] << 4,
        a.limbs[1] << 4,
        a.limbs[2] << 4,
        a.limbs[3] << 4,
        a.limbs[4] << 4,
    } };

    const ax4 = ExtendedPoint.init(a16, a16, a16, a16);
    const split = ax4.split();

    for (split) |s| {
        try std.testing.expectEqual(s, a16);
    }
}

test "reduction" {
    var a: Fe = .{ .limbs = .{ 2438, 24, 243, 0, 0 } };
    a = a.invert();
    const abig: Fe = .{ .limbs = .{
        a.limbs[0] << 4,
        a.limbs[1] << 4,
        a.limbs[2] << 4,
        a.limbs[3] << 4,
        a.limbs[4] << 4,
    } };

    const abigx4 = ExtendedPoint.splat(abig);
    const splits = ExtendedPoint.fromCached(abigx4.reduce()).split();
    const c = a.mul(.{ .limbs = .{ 1 << 4, 0, 0, 0, 0 } });

    for (splits) |split| {
        try std.testing.expectEqual(c, split);
    }
}

test "mul vs serial" {
    var a: Fe = .{ .limbs = .{ 2438, 24, 243, 0, 0 } };
    var b: Fe = .{ .limbs = .{ 98098, 87987897, 0, 1, 0 } };
    a = a.invert();
    b = b.invert();

    const c = a.mul(b);

    const ax4 = ExtendedPoint.splat(a).reduce();
    const bx4 = ExtendedPoint.splat(b).reduce();
    const cx4 = ax4.mul(bx4);

    for (cx4.split()) |split| {
        try std.testing.expectEqual(c.toBytes(), split.toBytes());
    }
}

test "iterated mul vs serial" {
    var a: Fe = .{ .limbs = .{ 2438, 24, 243, 0, 0 } };
    var b: Fe = .{ .limbs = .{ 98098, 87987897, 0, 1, 0 } };
    a = a.invert();
    b = b.invert();

    var c = a.mul(b);
    for (0..1024) |_| {
        c = a.mul(c);
        c = b.mul(c);
    }

    const ax4 = ExtendedPoint.splat(a).reduce();
    const bx4 = ExtendedPoint.splat(b).reduce();
    var cx4 = ax4.mul(bx4);
    for (0..1024) |_| {
        cx4 = ax4.mul(cx4.reduce());
        cx4 = bx4.mul(cx4.reduce());
    }

    for (cx4.split()) |split| {
        try std.testing.expectEqual(c.toBytes(), split.toBytes());
    }
}

test "square matches mul" {
    var a: Fe = .{ .limbs = .{ 2438, 24, 243, 0, 0 } };
    a = a.invert();

    const ax4 = ExtendedPoint.splat(a).reduce();
    const cx4 = ax4.mul(ax4);
    const cx4_sq = ax4.square();

    for (cx4.split(), cx4_sq.split()) |mul, sq| {
        try std.testing.expectEqual(mul.toBytes(), sq.toBytes());
    }
}

test "iterated square matches serial" {
    var a: Fe = .{ .limbs = .{ 2438, 24, 243, 0, 0 } };
    a = a.invert();
    var ax4 = ExtendedPoint.splat(a);
    for (0..1024) |_| {
        a = a.sq();
        ax4 = ax4.reduce().square();
        for (ax4.split()) |split| {
            try std.testing.expectEqual(a.toBytes(), split.toBytes());
        }
    }
}

test "iterated u32 mul matches serial" {
    var a: Fe = .{ .limbs = .{ 2438, 24, 243, 0, 0 } };
    var b: Fe = .{ .limbs = .{ 121665, 0, 0, 0, 0 } };
    a = a.invert();
    var c = a.mul(b);
    for (0..1024) |_| {
        c = b.mul(c);
    }

    const ax4 = ExtendedPoint.splat(a);
    const bx4: [4]u32 = .{ 121665, 121665, 121665, 121665 };
    var cx4 = ax4.reduce().mulConstants(bx4);
    for (0..1024) |_| {
        cx4 = cx4.reduce().mulConstants(bx4);
    }
    for (cx4.split()) |split| {
        try std.testing.expectEqual(c.toBytes(), split.toBytes());
    }
}

test "shuffle AAAA" {
    const x0 = Fe.fromBytes(@splat(0x10));
    const x1 = Fe.fromBytes(@splat(0x11));
    const x2 = Fe.fromBytes(@splat(0x12));
    const x3 = Fe.fromBytes(@splat(0x13));

    const x = ExtendedPoint.init(x0, x1, x2, x3);

    const y = x.shuffle(.AAAA);
    const splits = y.split();

    try std.testing.expectEqual(splits[0], x0);
    try std.testing.expectEqual(splits[1], x0);
    try std.testing.expectEqual(splits[2], x0);
    try std.testing.expectEqual(splits[3], x0);
}

test "blend AB" {
    const x0 = Fe.fromBytes(@splat(0x10));
    const x1 = Fe.fromBytes(@splat(0x11));
    const x2 = Fe.fromBytes(@splat(0x12));
    const x3 = Fe.fromBytes(@splat(0x13));

    const x = ExtendedPoint.init(x0, x1, x2, x3);
    const z = ExtendedPoint.init(x3, x2, x1, x0);

    const y = x.blend(z, .AB);
    const splits = y.split();

    try std.testing.expectEqual(splits[0], x3);
    try std.testing.expectEqual(splits[1], x2);
    try std.testing.expectEqual(splits[2], x2);
    try std.testing.expectEqual(splits[3], x3);
}
