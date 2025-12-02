//! Mostly copied from https://github.com/firedancer-io/firedancer/blob/9068496fbf7d211a01b535039e876ffbf84fcc6e/src/ballet/bn254/fd_bn254_pairing.c#L68

const bn254 = @import("lib.zig");
const fields = @import("fields.zig");
const sig = @import("../../sig.zig");

const G1 = bn254.G1;
const G2 = bn254.G2;

const Fp2 = fields.Fp2;
const Fp12 = fields.Fp12;

pub const BATCH_SIZE = 16;

pub fn millerLoop(a: []const G1, b: []const G2) Fp12 {
    sig.trace.assert(a.len == b.len);
    const size = a.len;

    var t: [BATCH_SIZE]G2 = undefined;
    var l: Fp12 = undefined;

    var f: Fp12 = .one;
    for (0..size) |i| t[i] = b[i];

    for (0..size) |i| {
        projDbl(&l, &t[i], a[i]);
        f = f.mul(l);
    }
    f = f.sq();

    for (0..size) |i| {
        projAddSub(&l, &t[i], a[i], b[i], false, false);
        f = f.mul(l);

        projAddSub(&l, &t[i], a[i], b[i], true, true);
        f = f.mul(l);
    }

    // zig fmt: off
    const s = [_]i2{
        0,  0,  0,  1,  0,  1,  0, -1,
        0,  0, -1,  0,  0,  0,  1,  0,
        0, -1,  0, -1,  0,  0,  0,  1,
        0, -1,  0,  0,  0,  0, -1,  0,
        0,  1,  0, -1,  0,  0,  1,  0,
        0,  0,  0,  0, -1,  0,  0, -1,
        0,  1,  0, -1,  0,  0,  0, -1,
        0, -1,  0,  0,  0,  1,  0, -1,
    };
    // zig fmt: on

    for (0..63) |fwd| {
        const i = 63 - fwd - 1;
        f = f.sq();

        for (0..size) |j| {
            projDbl(&l, &t[j], a[j]);
            f = f.mul(l);
        }

        if (s[i] != 0) for (0..size) |j| {
            projAddSub(&l, &t[j], a[j], b[j], s[i] > 0, true);
            f = f.mul(l);
        };
    }

    var frob: G2 = undefined;
    for (0..size) |i| {
        frob = b[i].frob(); // frob(b)
        projAddSub(&l, &t[i], a[i], frob, true, true);
        f = f.mul(l);

        frob = b[i].frob2(); // -frob^2(q)
        frob = frob.negate();
        projAddSub(&l, &t[i], a[i], frob, true, false);
        f = f.mul(l);
    }

    return f;
}

pub fn finalExp(x: Fp12) Fp12 {
    var t1 = x.inverse();
    var t0 = x.conj().mul(t1);
    var t2 = t0.frob2();
    var s = t0.mul(t2);

    t0 = s.powX().conj().sqFast();
    t1 = t0.sqFast().mul(t0);

    t2 = t1.powX().conj();
    t1 = t1.conj().mul(t2);

    var t3 = t2.sqFast();
    var t4 = t3.powX().mul(t1);
    t3 = t4.mul(t0);
    t0 = t4.mul(t2).mul(s);

    t2 = t3.frob();
    t0 = t0.mul(t2);
    t2 = t4.frob2();
    t0 = t0.mul(t2);

    // frob3 => frob2 \dot frob
    t2 = s.conj().mul(t3).frob2().frob();

    return t0.mul(t2);
}

/// Doubles a point in homogenous projective coordinates and evaluates the line in the Miller loop.
/// https://eprint.iacr.org/2013/722.pdf (Section 4.3)
fn projDbl(r: *Fp12, t: *G2, p: G1) void {

    // A=X1*Y1/2
    const a = t.x.mul(t.y).halve();
    // B=Y1^2
    const b = t.y.sq();
    // C=Z1^2
    const c = t.z.sq();
    // D=3C
    const d = c.add(c).add(c);
    // E=b'*D
    const e = d.mul(Fp2.constants.twist_b_mont);
    // F=3E
    const f = e.add(e).add(e);
    // G=(B+F)/2
    const g = b.add(f).halve();
    // H= (Y1+Z1)^2 − (B+C)
    const h = t.y.add(t.z).sq().sub(b.add(c));

    // g(P) = (H * -y) + (X^2 * 3 * x)w + (E−B)w^3
    r.* = .{
        .c0 = .{
            // el[0][0] = -(H * y)
            .c0 = h.negate().mulBroad(p.y),
            // el[0][1] = 0
            .c1 = .zero,
            // el[0][2] = 0
            .c2 = .zero,
        },
        .c1 = .{
            // el[1][0] = (3 * X^2 * x)
            .c0 = t.x.sq().mulBroad(p.x.triple()),
            // el[1][0] = (E−B)
            .c1 = e.sub(b),
            // el[1][2] = 0
            .c2 = .zero,
        },
    };

    // update `t`
    t.* = .{
        // A * (B−F)
        .x = b.sub(f).mul(a),
        // Y3 = G^2 − 3*E^2
        .y = g.sq().sub(e.sq().triple()),
        // Z3 = B*H
        .z = b.mul(h),
    };
}

/// https://eprint.iacr.org/2012/408, Sec 4.2.
fn projAddSub(r: *Fp12, t: *G2, p: G1, q: G2, is_add: bool, add_point: bool) void {
    const y = p.y;
    const x = p.x;
    const X2 = q.x;

    const Y2 = if (is_add) q.y else q.y.negate();

    const a = Y2.mul(t.z);
    const b = X2.mul(t.z);
    const o = t.y.sub(a);
    const l = t.x.sub(b);

    const j = o.mul(X2);
    const k = l.mul(Y2);

    r.* = .{
        .c0 = .{
            // el[0][0] = (l * y)
            .c0 = l.mulBroad(y),
            // el[0][1] = 0
            .c1 = .zero,
            // el[0][2] = 0
            .c2 = .zero,
        },
        .c1 = .{
            // el[1][0] = -(o * x), term in w
            .c0 = o.negate().mulBroad(x),
            // el[1][1] = j-k
            .c1 = j.sub(k),
            // el[1][2] = 0
            .c2 = .zero,
        },
    };

    if (add_point) {
        const c = o.sq();
        const d = l.sq();
        const e = d.mul(l);
        const f = t.z.mul(c);
        const g = t.x.mul(d);
        const h = e.add(f).sub(g).sub(g);
        const i = t.y.mul(e);

        t.* = .{
            .x = l.mul(h),
            .y = g.sub(h).mul(o).sub(i),
            .z = t.z.mul(e),
        };
    }
}
