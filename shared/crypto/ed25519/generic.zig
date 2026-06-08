//! Implements parallel operations over 25519 finite field
//!
//! Contains a AVX2 based implementation which has been generalized with
//! Zig's `@Vector` type to work on all platforms.

const std = @import("std");
const Ed25519 = std.crypto.ecc.Edwards25519;
const Fe = Ed25519.Fe;

const u32x8 = @Vector(8, u32);
const i32x8 = @Vector(8, i32);
const u64x4 = @Vector(4, u64);

const P_TIMES_2_LO: u32x8 = .{
    0x3FFFFED << 1,
    0x3FFFFED << 1,
    0x1FFFFFF << 1,
    0x1FFFFFF << 1,
    0x3FFFFED << 1,
    0x3FFFFED << 1,
    0x1FFFFFF << 1,
    0x1FFFFFF << 1,
};

const P_TIMES_2_HI: u32x8 = .{
    0x3FFFFFF << 1,
    0x3FFFFFF << 1,
    0x1FFFFFF << 1,
    0x1FFFFFF << 1,
    0x3FFFFFF << 1,
    0x3FFFFFF << 1,
    0x1FFFFFF << 1,
    0x1FFFFFF << 1,
};

const P_TIMES_16_LO: u32x8 = .{
    0x3FFFFED << 4,
    0x3FFFFED << 4,
    0x1FFFFFF << 4,
    0x1FFFFFF << 4,
    0x3FFFFED << 4,
    0x3FFFFED << 4,
    0x1FFFFFF << 4,
    0x1FFFFFF << 4,
};

const P_TIMES_16_HI: u32x8 = .{
    0x3FFFFFF << 4,
    0x3FFFFFF << 4,
    0x1FFFFFF << 4,
    0x1FFFFFF << 4,
    0x3FFFFFF << 4,
    0x3FFFFFF << 4,
    0x1FFFFFF << 4,
    0x1FFFFFF << 4,
};

const LOW_25_BITS: u64x4 = @splat((@as(u64, 1) << 25) - 1);
const LOW_26_BITS: u64x4 = @splat((@as(u64, 1) << 26) - 1);

/// A vector of four field elements.
pub const ExtendedPoint = struct {
    limbs: [5]u32x8,

    const zero: ExtendedPoint = .{ .limbs = @splat(@splat(0)) };
    pub const identityElement: ExtendedPoint = .{ .limbs = .{
        .{ 0, 1, 0, 0, 1, 0, 0, 0 },
        @splat(0),
        @splat(0),
        @splat(0),
        @splat(0),
    } };

    fn init(x0: Fe, x1: Fe, x2: Fe, x3: Fe) ExtendedPoint {
        var buffer: [5]u32x8 = @splat(@splat(0));
        const low_26_bits = (@as(u64, 1) << 26) - 1;

        for (0..5) |i| {
            const a_2i: u32 = @truncate(x0.limbs[i] & low_26_bits);
            const a_2i_1: u32 = @truncate(x0.limbs[i] >> 26);

            const b_2i: u32 = @truncate(x1.limbs[i] & low_26_bits);
            const b_2i_1: u32 = @truncate(x1.limbs[i] >> 26);

            const c_2i: u32 = @truncate(x2.limbs[i] & low_26_bits);
            const c_2i_1: u32 = @truncate(x2.limbs[i] >> 26);

            const d_2i: u32 = @truncate(x3.limbs[i] & low_26_bits);
            const d_2i_1: u32 = @truncate(x3.limbs[i] >> 26);

            buffer[i] = .{
                a_2i,   b_2i,
                a_2i_1, b_2i_1,
                c_2i,   d_2i,
                c_2i_1, d_2i_1,
            };
        }

        var element: ExtendedPoint = .{ .limbs = buffer };
        return element.reduce();
    }

    pub fn fromPoint(p: Ed25519) ExtendedPoint {
        return init(p.x, p.y, p.z, p.t);
    }

    pub fn toPoint(self: ExtendedPoint) Ed25519 {
        const splits = self.split();
        return .{
            .x = splits[0],
            .y = splits[1],
            .z = splits[2],
            .t = splits[3],
        };
    }

    fn reduce(self: ExtendedPoint) ExtendedPoint {
        const masks: u32x8 = .{
            (@as(u32, 1) << 26) - 1,
            (@as(u32, 1) << 26) - 1,
            (@as(u32, 1) << 25) - 1,
            (@as(u32, 1) << 25) - 1,
            (@as(u32, 1) << 26) - 1,
            (@as(u32, 1) << 26) - 1,
            (@as(u32, 1) << 25) - 1,
            (@as(u32, 1) << 25) - 1,
        };

        var v = self.limbs;

        const c10 = rotatedCarryout(v[0]);
        v[0] = (v[0] & masks) + combine(@splat(0), c10);

        const c32 = rotatedCarryout(v[1]);
        v[1] = (v[1] & masks) + combine(c10, c32);

        const c54 = rotatedCarryout(v[2]);
        v[2] = (v[2] & masks) + combine(c32, c54);

        const v76 = rotatedCarryout(v[3]);
        v[3] = (v[3] & masks) + combine(c54, v76);

        const c98 = rotatedCarryout(v[4]);
        v[4] = (v[4] & masks) + combine(v76, c98);

        const c9_spread = @shuffle(u32, c98, undefined, i32x8{ 0, 2, 1, 3, 4, 6, 5, 7 });
        const v19: u32x8 = @bitCast(@as(u64x4, @splat(19)));
        const c9_19_spread: u32x8 = @bitCast(mul32(c9_spread, v19));
        const c9_19 = @shuffle(u32, c9_19_spread, undefined, i32x8{ 0, 2, 1, 3, 4, 6, 5, 7 });

        v[0] += c9_19;

        return .{ .limbs = v };
    }

    fn reduce64(input: [10]u64x4) ExtendedPoint {
        const S = struct {
            inline fn carry(z: *[10]u64x4, i: u64) void {
                std.debug.assert(i < 9);
                if (i % 2 == 0) {
                    // Even limbs have 26 bits
                    z[i + 1] += z[i] >> @splat(26);
                    z[i] &= LOW_26_BITS;
                } else {
                    // Odd limbs have 25 bits
                    z[i + 1] += z[i] >> @splat(25);
                    z[i] &= LOW_25_BITS;
                }
            }
        };

        var z = input;

        // Formatted to show how the two halves could execute in parallel.
        // zig fmt: off
        S.carry(&z, 0); S.carry(&z, 4);
        S.carry(&z, 1); S.carry(&z, 5);
        S.carry(&z, 2); S.carry(&z, 6);
        S.carry(&z, 3); S.carry(&z, 7);
        S.carry(&z, 4); S.carry(&z, 8);
        // zig fmt: on

        const c = z[9] >> @splat(25);
        z[9] &= LOW_25_BITS;
        var c0 = c & LOW_26_BITS;
        var c1 = c >> @splat(26);

        const x19: u64x4 = @splat(19);
        c0 = mul32(@bitCast(c0), @bitCast(x19));
        c1 = mul32(@bitCast(c1), @bitCast(x19));

        z[0] += c0;
        z[1] += c1;
        S.carry(&z, 0);

        return .{ .limbs = .{
            repackPair(@bitCast(z[0]), @bitCast(z[1])),
            repackPair(@bitCast(z[2]), @bitCast(z[3])),
            repackPair(@bitCast(z[4]), @bitCast(z[5])),
            repackPair(@bitCast(z[6]), @bitCast(z[7])),
            repackPair(@bitCast(z[8]), @bitCast(z[9])),
        } };
    }

    fn splat(fe: Fe) ExtendedPoint {
        return init(fe, fe, fe, fe);
    }

    /// Unpack 32-bit lanes into 64-bit lanes:
    /// ```ascii,no_run
    /// (a0, b0, a1, b1, c0, d0, c1, d1)
    /// ```
    /// into
    /// ```ascii,no_run
    /// (a0, 0, b0, 0, c0, 0, d0, 0)
    /// (a1, 0, b1, 0, c1, 0, d1, 0)
    /// ```
    fn unpackPair(src: u32x8) struct { u32x8, u32x8 } {
        const a = @shuffle(
            u32,
            src,
            u32x8{
                0,         0,
                undefined, undefined,
                0,         0,
                undefined, undefined,
            },
            i32x8{
                0, ~@as(i32, 0),
                1, ~@as(i32, 1),
                4, ~@as(i32, 4),
                5, ~@as(i32, 5),
            },
        );
        const b = @shuffle(
            u32,
            src,
            u32x8{
                undefined, undefined,
                0,         0,
                undefined, undefined,
                0,         0,
            },
            i32x8{
                2, ~@as(i32, 2),
                3, ~@as(i32, 3),
                6, ~@as(i32, 6),
                7, ~@as(i32, 7),
            },
        );
        return .{ a, b };
    }

    /// Repack 64-bit lanes into 32-bit lanes:
    /// ```ascii,no_run
    /// (a0, 0, b0, 0, c0, 0, d0, 0)
    /// (a1, 0, b1, 0, c1, 0, d1, 0)
    /// ```
    /// into
    /// ```ascii,no_run
    /// (a0, b0, a1, b1, c0, d0, c1, d1)
    /// ```
    fn repackPair(x: u32x8, y: u32x8) u32x8 {
        return combine(
            @shuffle(u32, x, undefined, i32x8{ 0, 2, 1, 3, 4, 6, 5, 7 }),
            @shuffle(u32, y, undefined, i32x8{ 1, 3, 0, 2, 5, 7, 4, 6 }),
        );
    }

    fn rotatedCarryout(v: u32x8) u32x8 {
        const shifts: u32x8 = .{ 26, 26, 25, 25, 26, 26, 25, 25 };
        const c = v >> shifts;
        return @shuffle(u32, c, undefined, i32x8{ 2, 3, 0, 1, 6, 7, 4, 5 });
    }

    fn combine(v_lo: u32x8, v_hi: u32x8) u32x8 {
        return @shuffle(u32, v_lo, v_hi, i32x8{
            0,            1,
            ~@as(i32, 2), ~@as(i32, 3),
            4,            5,
            ~@as(i32, 6), ~@as(i32, 7),
        });
    }

    fn mul32(a: u32x8, b: u32x8) u64x4 {
        const a_wide: u64x4 = @bitCast(a);
        const b_wide: u64x4 = @bitCast(b);
        const mask: u64x4 = @splat(std.math.maxInt(u32));
        return (a_wide & mask) * (b_wide & mask);
    }

    fn mulConstants(self: ExtendedPoint, scalars: [4]u32) ExtendedPoint {
        const constants: u32x8 = .{ scalars[0], 0, scalars[1], 0, scalars[2], 0, scalars[3], 0 };

        const b0, const b1 = unpackPair(self.limbs[0]);
        const b2, const b3 = unpackPair(self.limbs[1]);
        const b4, const b5 = unpackPair(self.limbs[2]);
        const b6, const b7 = unpackPair(self.limbs[3]);
        const b8, const b9 = unpackPair(self.limbs[4]);

        return reduce64(.{
            mul32(b0, constants),
            mul32(b1, constants),
            mul32(b2, constants),
            mul32(b3, constants),
            mul32(b4, constants),
            mul32(b5, constants),
            mul32(b6, constants),
            mul32(b7, constants),
            mul32(b8, constants),
            mul32(b9, constants),
        });
    }

    fn mul(self: ExtendedPoint, other: ExtendedPoint) ExtendedPoint {
        const x0, const x1 = unpackPair(self.limbs[0]);
        const x2, const x3 = unpackPair(self.limbs[1]);
        const x4, const x5 = unpackPair(self.limbs[2]);
        const x6, const x7 = unpackPair(self.limbs[3]);
        const x8, const x9 = unpackPair(self.limbs[4]);

        const y0, const y1 = unpackPair(other.limbs[0]);
        const y2, const y3 = unpackPair(other.limbs[1]);
        const y4, const y5 = unpackPair(other.limbs[2]);
        const y6, const y7 = unpackPair(other.limbs[3]);
        const y8, const y9 = unpackPair(other.limbs[4]);

        const v19: u32x8 = .{ 19, 0, 19, 0, 19, 0, 19, 0 };

        const y1_19: u32x8 = @bitCast(mul32(v19, y1));
        const y2_19: u32x8 = @bitCast(mul32(v19, y2));
        const y3_19: u32x8 = @bitCast(mul32(v19, y3));
        const y4_19: u32x8 = @bitCast(mul32(v19, y4));
        const y5_19: u32x8 = @bitCast(mul32(v19, y5));
        const y6_19: u32x8 = @bitCast(mul32(v19, y6));
        const y7_19: u32x8 = @bitCast(mul32(v19, y7));
        const y8_19: u32x8 = @bitCast(mul32(v19, y8));
        const y9_19: u32x8 = @bitCast(mul32(v19, y9));

        const x1_2 = x1 + x1;
        const x3_2 = x3 + x3;
        const x5_2 = x5 + x5;
        const x7_2 = x7 + x7;
        const x9_2 = x9 + x9;

        // zig fmt: off
        const z0 = mul32(x0, y0) + mul32(x1_2, y9_19) + mul32(x2, y8_19) + mul32(x3_2, y7_19) + mul32(x4, y6_19) + mul32(x5_2, y5_19) + mul32(x6, y4_19) + mul32(x7_2, y3_19) + mul32(x8, y2_19) + mul32(x9_2, y1_19);
        const z1 = mul32(x0, y1) + mul32(x1,      y0) + mul32(x2, y9_19) + mul32(x3,   y8_19) + mul32(x4, y7_19) + mul32(x5,   y6_19) + mul32(x6, y5_19) + mul32(x7,   y4_19) + mul32(x8, y3_19) + mul32(x9,   y2_19);
        const z2 = mul32(x0, y2) + mul32(x1_2,    y1) + mul32(x2,    y0) + mul32(x3_2, y9_19) + mul32(x4, y8_19) + mul32(x5_2, y7_19) + mul32(x6, y6_19) + mul32(x7_2, y5_19) + mul32(x8, y4_19) + mul32(x9_2, y3_19);
        const z3 = mul32(x0, y3) + mul32(x1,      y2) + mul32(x2,    y1) + mul32(x3,      y0) + mul32(x4, y9_19) + mul32(x5,   y8_19) + mul32(x6, y7_19) + mul32(x7,   y6_19) + mul32(x8, y5_19) + mul32(x9,   y4_19);
        const z4 = mul32(x0, y4) + mul32(x1_2,    y3) + mul32(x2,    y2) + mul32(x3_2,    y1) + mul32(x4,    y0) + mul32(x5_2, y9_19) + mul32(x6, y8_19) + mul32(x7_2, y7_19) + mul32(x8, y6_19) + mul32(x9_2, y5_19);
        const z5 = mul32(x0, y5) + mul32(x1,      y4) + mul32(x2,    y3) + mul32(x3,      y2) + mul32(x4,    y1) + mul32(x5,      y0) + mul32(x6, y9_19) + mul32(x7,   y8_19) + mul32(x8, y7_19) + mul32(x9,   y6_19);
        const z6 = mul32(x0, y6) + mul32(x1_2,    y5) + mul32(x2,    y4) + mul32(x3_2,    y3) + mul32(x4,    y2) + mul32(x5_2,    y1) + mul32(x6,    y0) + mul32(x7_2, y9_19) + mul32(x8, y8_19) + mul32(x9_2, y7_19);
        const z7 = mul32(x0, y7) + mul32(x1,      y6) + mul32(x2,    y5) + mul32(x3,      y4) + mul32(x4,    y3) + mul32(x5,      y2) + mul32(x6,    y1) + mul32(x7,      y0) + mul32(x8, y9_19) + mul32(x9,   y8_19);
        const z8 = mul32(x0, y8) + mul32(x1_2,    y7) + mul32(x2,    y6) + mul32(x3_2,    y5) + mul32(x4,    y4) + mul32(x5_2,    y3) + mul32(x6,    y2) + mul32(x7_2,    y1) + mul32(x8,    y0) + mul32(x9_2, y9_19);
        const z9 = mul32(x0, y9) + mul32(x1,      y8) + mul32(x2,    y7) + mul32(x3,      y6) + mul32(x4,    y5) + mul32(x5,      y4) + mul32(x6,    y3) + mul32(x7,      y2) + mul32(x8,    y1) + mul32(x9,      y0);
        // zig fmt: on

        return reduce64(.{ z0, z1, z2, z3, z4, z5, z6, z7, z8, z9 });
    }

    pub fn dbl(self: ExtendedPoint) ExtendedPoint {
        var tmp0 = self.shuffle(.ABAB);
        var tmp1 = tmp0.shuffle(.BADC);

        tmp0 = self.blend(tmp0.addLimbs(tmp1), .D);
        tmp1 = tmp0.squareAndNegateD();

        const S_1 = tmp1.shuffle(.AAAA);
        const S_2 = tmp1.shuffle(.BBBB);

        tmp0 = zero.blend(tmp1.addLimbs(tmp1), .C);
        tmp0 = tmp0.blend(tmp1, .D);
        tmp0 = tmp0.addLimbs(S_1);
        tmp0 = tmp0.addLimbs(zero.blend(S_2, .AD));
        tmp0 = tmp0.addLimbs(zero.blend(S_2.negateLazy(), .BC));

        tmp1 = tmp0.shuffle(.DBBD);
        tmp0 = tmp0.shuffle(.CACA);

        return tmp0.mul(tmp1);
    }

    /// Splits the vector into four field elements.
    fn split(self: ExtendedPoint) [4]Fe {
        var out: [4]Fe = @splat(.zero);
        for (0..5) |i| {
            // zig fmt: off
            const a_2i  : u64 = self.limbs[i][0];
            const b_2i  : u64 = self.limbs[i][1];
            const a_2i_1: u64 = self.limbs[i][2];
            const b_2i_1: u64 = self.limbs[i][3];
            const c_2i  : u64 = self.limbs[i][4];
            const d_2i  : u64 = self.limbs[i][5];
            const c_2i_1: u64 = self.limbs[i][6];
            const d_2i_1: u64 = self.limbs[i][7];
            // zig fmt: on

            out[0].limbs[i] = a_2i + (a_2i_1 << 26);
            out[1].limbs[i] = b_2i + (b_2i_1 << 26);
            out[2].limbs[i] = c_2i + (c_2i_1 << 26);
            out[3].limbs[i] = d_2i + (d_2i_1 << 26);
        }

        return out;
    }

    const Shuffle = enum {
        AAAA,
        BBBB,
        CACA,
        DBBD,
        ADDA,
        CBCB,
        ABAB,
        BADC,
        BACD,
        ABDC,
    };

    fn shuffle(self: ExtendedPoint, comptime control: Shuffle) ExtendedPoint {
        const S = struct {
            fn permd(x: u32x8, v: u32x8) u32x8 {
                var result: u32x8 = undefined;
                for (0..8) |i| {
                    // should be masked with 0x7 here,
                    // but LLVM then misses the transformation to vpermps
                    result[i] = x[v[i]];
                }
                return result;
            }

            inline fn shuffleLanes(x: u32x8) u32x8 {
                const c: u32x8 = switch (control) {
                    .AAAA => .{ 0, 0, 2, 2, 0, 0, 2, 2 },
                    .BBBB => .{ 1, 1, 3, 3, 1, 1, 3, 3 },
                    .CACA => .{ 4, 0, 6, 2, 4, 0, 6, 2 },
                    .DBBD => .{ 5, 1, 7, 3, 1, 5, 3, 7 },
                    .ADDA => .{ 0, 5, 2, 7, 5, 0, 7, 2 },
                    .CBCB => .{ 4, 1, 6, 3, 4, 1, 6, 3 },
                    .ABAB => .{ 0, 1, 2, 3, 0, 1, 2, 3 },
                    .BADC => .{ 1, 0, 3, 2, 5, 4, 7, 6 },
                    .BACD => .{ 1, 0, 3, 2, 4, 5, 6, 7 },
                    .ABDC => .{ 0, 1, 2, 3, 5, 4, 7, 6 },
                };
                return permd(x, c);
            }
        };

        return .{ .limbs = .{
            S.shuffleLanes(self.limbs[0]),
            S.shuffleLanes(self.limbs[1]),
            S.shuffleLanes(self.limbs[2]),
            S.shuffleLanes(self.limbs[3]),
            S.shuffleLanes(self.limbs[4]),
        } };
    }

    const Lanes = enum {
        C,
        D,
        AB,
        AC,
        CD,
        AD,
        BC,
        ABCD,
    };

    const A_LANES: u8 = 0b0000_0101;
    const B_LANES: u8 = 0b0000_1010;
    const C_LANES: u8 = 0b0101_0000;
    const D_LANES: u8 = 0b1010_0000;

    fn blend(self: ExtendedPoint, other: ExtendedPoint, comptime control: Lanes) ExtendedPoint {
        const S = struct {
            fn blendLanes(x: u32x8, y: u32x8) u32x8 {
                const c = switch (control) {
                    .C => C_LANES,
                    .D => D_LANES,
                    .AD => A_LANES | D_LANES,
                    .AB => A_LANES | B_LANES,
                    .AC => A_LANES | C_LANES,
                    .CD => C_LANES | D_LANES,
                    .BC => B_LANES | C_LANES,
                    .ABCD => A_LANES | B_LANES | C_LANES | D_LANES,
                };
                comptime var indices: [8]i32 = undefined;
                inline for (0..8) |i| {
                    const s: i32 = @intCast(i);
                    const predicate = (c >> @intCast(i % 8)) & 0x1;
                    indices[i] = if (predicate == 1) ~s else s;
                }
                return @shuffle(u32, x, y, indices);
            }
        };

        return .{ .limbs = .{
            S.blendLanes(self.limbs[0], other.limbs[0]),
            S.blendLanes(self.limbs[1], other.limbs[1]),
            S.blendLanes(self.limbs[2], other.limbs[2]),
            S.blendLanes(self.limbs[3], other.limbs[3]),
            S.blendLanes(self.limbs[4], other.limbs[4]),
        } };
    }

    /// Given `(A, B, C, D)` computes `(-A, -B, -C, -D)` without performing a reduction.
    fn negateLazy(self: ExtendedPoint) ExtendedPoint {
        return .{ .limbs = .{
            P_TIMES_2_LO - self.limbs[0],
            P_TIMES_2_HI - self.limbs[1],
            P_TIMES_2_HI - self.limbs[2],
            P_TIMES_2_HI - self.limbs[3],
            P_TIMES_2_HI - self.limbs[4],
        } };
    }

    fn neg(self: ExtendedPoint) ExtendedPoint {
        const element: ExtendedPoint = .{ .limbs = .{
            P_TIMES_16_LO - self.limbs[0],
            P_TIMES_16_HI - self.limbs[1],
            P_TIMES_16_HI - self.limbs[2],
            P_TIMES_16_HI - self.limbs[3],
            P_TIMES_16_HI - self.limbs[4],
        } };
        return element.reduce();
    }

    pub fn add(self: ExtendedPoint, other: ExtendedPoint) ExtendedPoint {
        return self.addCached(.fromExtended(other));
    }

    pub fn addLimbs(self: ExtendedPoint, other: ExtendedPoint) ExtendedPoint {
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
        tmp = tmp.mul(cp.element);
        tmp = tmp.shuffle(.ABDC);
        tmp = tmp.diffSum();

        const t0 = tmp.shuffle(.ADDA);
        const t1 = tmp.shuffle(.CBCB);

        return t0.mul(t1);
    }

    pub fn subCached(self: ExtendedPoint, cp: CachedPoint) ExtendedPoint {
        const negated = cp.neg();
        return self.addCached(negated);
    }

    /// Given `self = (A, B, C, D)`, compute `(B - A, B + A, D - C, D + C)`
    fn diffSum(self: ExtendedPoint) ExtendedPoint {
        // tmp = (B, A, D, C)
        const tmp1 = self.shuffle(.BADC);
        // tmp2 = (-A, B, -C, D)
        const tmp2 = self.blend(self.negateLazy(), .AC);
        // (B - A, B + A, D - C, D + C)
        return tmp1.addLimbs(tmp2);
    }

    /// Square the field element and negate the result's `D` value.
    fn squareAndNegateD(self: ExtendedPoint) ExtendedPoint {
        const v19: u32x8 = .{ 19, 0, 19, 0, 19, 0, 19, 0 };

        const x0, const x1 = unpackPair(self.limbs[0]);
        const x2, const x3 = unpackPair(self.limbs[1]);
        const x4, const x5 = unpackPair(self.limbs[2]);
        const x6, const x7 = unpackPair(self.limbs[3]);
        const x8, const x9 = unpackPair(self.limbs[4]);

        const x0_2 = x0 << @splat(1);
        const x1_2 = x1 << @splat(1);
        const x2_2 = x2 << @splat(1);
        const x3_2 = x3 << @splat(1);
        const x4_2 = x4 << @splat(1);
        const x5_2 = x5 << @splat(1);
        const x6_2 = x6 << @splat(1);
        const x7_2 = x7 << @splat(1);

        const x5_19: u32x8 = @bitCast(mul32(v19, x5));
        const x6_19: u32x8 = @bitCast(mul32(v19, x6));
        const x7_19: u32x8 = @bitCast(mul32(v19, x7));
        const x8_19: u32x8 = @bitCast(mul32(v19, x8));
        const x9_19: u32x8 = @bitCast(mul32(v19, x9));

        // zig fmt: off
        var z0 = mul32(x0,   x0) + mul32(x2_2, x8_19) + mul32(x4_2, x6_19) + ((mul32(x1_2, x9_19) +   mul32(x3_2, x7_19) +    mul32(x5,   x5_19)) << @splat(1));
        var z1 = mul32(x0_2, x1) + mul32(x3_2, x8_19) + mul32(x5_2, x6_19) +                        ((mul32(x2,   x9_19) +    mul32(x4,   x7_19)) << @splat(1));
        var z2 = mul32(x0_2, x2) + mul32(x1_2,    x1) + mul32(x4_2, x8_19) +   mul32(x6,   x6_19) + ((mul32(x3_2, x9_19) +    mul32(x5_2, x7_19)) << @splat(1));
        var z3 = mul32(x0_2, x3) + mul32(x1_2,    x2) + mul32(x5_2, x8_19) +                        ((mul32(x4,   x9_19) +    mul32(x6,   x7_19)) << @splat(1));
        var z4 = mul32(x0_2, x4) + mul32(x1_2,  x3_2) + mul32(x2,      x2) +   mul32(x6_2, x8_19) + ((mul32(x5_2, x9_19) +    mul32(x7,   x7_19)) << @splat(1));
        var z5 = mul32(x0_2, x5) + mul32(x1_2,    x4) + mul32(x2_2,    x3) +   mul32(x7_2, x8_19)                        +  ((mul32(x6,   x9_19)) << @splat(1));
        var z6 = mul32(x0_2, x6) + mul32(x1_2,  x5_2) + mul32(x2_2,    x4) +   mul32(x3_2,    x3) +   mul32(x8,   x8_19) +  ((mul32(x7_2, x9_19)) << @splat(1));
        var z7 = mul32(x0_2, x7) + mul32(x1_2,    x6) + mul32(x2_2,    x5) +   mul32(x3_2,    x4)                        +  ((mul32(x8,   x9_19)) << @splat(1));
        var z8 = mul32(x0_2, x8) + mul32(x1_2,  x7_2) + mul32(x2_2,    x6) +   mul32(x3_2,  x5_2) +   mul32(x4,      x4) +  ((mul32(x9,   x9_19)) << @splat(1));
        var z9 = mul32(x0_2, x9) + mul32(x1_2,    x8) + mul32(x2_2,    x7) +   mul32(x3_2,    x6) +   mul32(x4_2,    x5)                                       ;
        // zig fmt: on

        const low__p37: u64x4 = @splat(0x3ffffed << 37);
        const even_p37: u64x4 = @splat(0x3ffffff << 37);
        const odd__p37: u64x4 = @splat(0x1ffffff << 37);

        const S = struct {
            fn negateD(x: u64x4, p: u64x4) u64x4 {
                return @bitCast(@shuffle(
                    u32,
                    @as(u32x8, @bitCast(x)),
                    @as(u32x8, @bitCast(p - x)),
                    i32x8{ 0, 1, 2, 3, 4, 5, ~@as(i32, 6), ~@as(i32, 7) },
                ));
            }
        };

        z0 = S.negateD(z0, low__p37);
        z1 = S.negateD(z1, odd__p37);
        z2 = S.negateD(z2, even_p37);
        z3 = S.negateD(z3, odd__p37);
        z4 = S.negateD(z4, even_p37);
        z5 = S.negateD(z5, odd__p37);
        z6 = S.negateD(z6, even_p37);
        z7 = S.negateD(z7, odd__p37);
        z8 = S.negateD(z8, even_p37);
        z9 = S.negateD(z9, odd__p37);

        return reduce64(.{ z0, z1, z2, z3, z4, z5, z6, z7, z8, z9 });
    }

    pub fn mulByPow2(self: ExtendedPoint, comptime k: u32) ExtendedPoint {
        var s = self;
        for (0..k) |_| s = s.dbl();
        return s;
    }
};

pub const CachedPoint = struct {
    element: ExtendedPoint,

    // zig fmt: off
    pub const identityElement: CachedPoint = .{ .element = .{ .limbs = .{
        .{ 121647,   121666, 0,        0, 243332, 67108845, 0, 33554431 },
        .{ 67108864, 0,      33554431, 0, 0,      67108863, 0, 33554431 },
        .{ 67108863, 0,      33554431, 0, 0,      67108863, 0, 33554431 },
        .{ 67108863, 0,      33554431, 0, 0,      67108863, 0, 33554431 },
        .{ 67108863, 0,      33554431, 0, 0,      67108863, 0, 33554431 },
    } } };
    // zig fmt: on

    pub fn fromExtended(p: ExtendedPoint) CachedPoint {
        var x = p;

        x = x.blend(x.diffSum(), .AB);
        x = x.mulConstants(.{ 121666, 121666, 2 * 121666, 2 * 121665 });
        x = x.blend(x.neg(), .D);

        return .{ .element = x };
    }

    pub fn neg(self: CachedPoint) CachedPoint {
        const swapped = self.element.shuffle(.BACD);
        const element = swapped.blend(swapped.negateLazy(), .D);
        return .{ .element = element };
    }
};

test "scale by curve constants" {
    const x = ExtendedPoint.splat(Fe.one);
    const y = x.mulConstants(.{ 121666, 121666, 2 * 121666, 2 * 121665 });
    const xs = y.split();

    try std.testing.expectEqual([_]u64{ 121666, 0, 0, 0, 0 }, xs[0].limbs);
    try std.testing.expectEqual([_]u64{ 121666, 0, 0, 0, 0 }, xs[1].limbs);
    try std.testing.expectEqual([_]u64{ 2 * 121666, 0, 0, 0, 0 }, xs[2].limbs);
    try std.testing.expectEqual([_]u64{ 2 * 121665, 0, 0, 0, 0 }, xs[3].limbs);
}

test "diff sum vs serial" {
    const x0: Fe = .{ .limbs = .{ 10000, 10001, 10002, 10003, 10004 } };
    const x1: Fe = .{ .limbs = .{ 10100, 10101, 10102, 10103, 10104 } };
    const x2: Fe = .{ .limbs = .{ 10200, 10201, 10202, 10203, 10204 } };
    const x3: Fe = .{ .limbs = .{ 10300, 10301, 10302, 10303, 10304 } };

    const vec = ExtendedPoint.init(x0, x1, x2, x3).diffSum();
    const splits = vec.split();

    try std.testing.expectEqual(x1.sub(x0), splits[0]);
    try std.testing.expectEqual(x1.add(x0), splits[1]);
    try std.testing.expectEqual(x3.sub(x2), splits[2]);
    try std.testing.expectEqual(x3.add(x2), splits[3]);
}

test "square vs serial" {
    const x0: Fe = .{ .limbs = .{ 10000, 10001, 10002, 10003, 10004 } };
    const x1: Fe = .{ .limbs = .{ 10100, 10101, 10102, 10103, 10104 } };
    const x2: Fe = .{ .limbs = .{ 10200, 10201, 10202, 10203, 10204 } };
    const x3: Fe = .{ .limbs = .{ 10300, 10301, 10302, 10303, 10304 } };

    const vec = ExtendedPoint.init(x0, x1, x2, x3);

    const result = vec.squareAndNegateD().split();

    // Zig stdlib allows `limbs` to be un-reduced after neg(), which is fine, but to
    // get a valid test, we need to compare against the reduced state.
    const x3_bytes = x3.mul(x3).neg().toBytes();
    const x3_expected = Fe.fromBytes(x3_bytes);

    try std.testing.expectEqual(x0.mul(x0), result[0]);
    try std.testing.expectEqual(x1.mul(x1), result[1]);
    try std.testing.expectEqual(x2.mul(x2), result[2]);
    try std.testing.expectEqual(x3_expected, result[3]);
}

test "multiply vs serial" {
    const x0: Fe = .{ .limbs = .{ 10000, 10001, 10002, 10003, 10004 } };
    const x1: Fe = .{ .limbs = .{ 10100, 10101, 10102, 10103, 10104 } };
    const x2: Fe = .{ .limbs = .{ 10200, 10201, 10202, 10203, 10204 } };
    const x3: Fe = .{ .limbs = .{ 10300, 10301, 10302, 10303, 10304 } };

    const vec = ExtendedPoint.init(x0, x1, x2, x3);
    const vecprime = vec;

    const result = vec.mul(vecprime).split();

    try std.testing.expectEqual(x0.mul(x0), result[0]);
    try std.testing.expectEqual(x1.mul(x1), result[1]);
    try std.testing.expectEqual(x2.mul(x2), result[2]);
    try std.testing.expectEqual(x3.mul(x3), result[3]);
}

test "add vs serial" {
    const x0: Fe = .{ .limbs = .{ 10000, 10001, 10002, 10003, 10004 } };
    const x1: Fe = .{ .limbs = .{ 10100, 10101, 10102, 10103, 10104 } };
    const x2: Fe = .{ .limbs = .{ 10200, 10201, 10202, 10203, 10204 } };
    const x3: Fe = .{ .limbs = .{ 10300, 10301, 10302, 10303, 10304 } };

    const vec = ExtendedPoint.init(x0, x1, x2, x3);
    const vecprime = vec;

    const result = vec.addLimbs(vecprime).split();

    try std.testing.expectEqual(x0.add(x0), result[0]);
    try std.testing.expectEqual(x1.add(x1), result[1]);
    try std.testing.expectEqual(x2.add(x2), result[2]);
    try std.testing.expectEqual(x3.add(x3), result[3]);
}

test "split roundtrip" {
    const x0 = Fe.fromBytes(@splat(0x10));
    const x1 = Fe.fromBytes(@splat(0x11));
    const x2 = Fe.fromBytes(@splat(0x12));
    const x3 = Fe.fromBytes(@splat(0x13));

    const vec = ExtendedPoint.init(x0, x1, x2, x3);
    const splits = vec.split();

    try std.testing.expectEqual(x0, splits[0]);
    try std.testing.expectEqual(x1, splits[1]);
    try std.testing.expectEqual(x2, splits[2]);
    try std.testing.expectEqual(x3, splits[3]);
}
