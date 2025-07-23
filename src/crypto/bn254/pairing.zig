//! Mostly copied from https://github.com/firedancer-io/firedancer/blob/9068496fbf7d211a01b535039e876ffbf84fcc6e/src/ballet/bn254/fd_bn254_pairing.c#L68

const std = @import("std");
const bn254 = @import("lib.zig");
const fields = @import("fields.zig");

const G1 = bn254.G1;
const G2 = bn254.G2;

const Fp = fields.Fp;
const Fp2 = fields.Fp2;
const Fp12 = fields.Fp12;

pub const BATCH_SIZE = 16;

pub fn millerLoop(a: []const G1, b: []const G2) Fp12 {
    std.debug.assert(a.len == b.len);
    const size = a.len;

    var t: [BATCH_SIZE]G2 = undefined;
    var l: Fp12 = undefined;

    var f: Fp12 = .one;
    for (0..size) |i| t[i] = b[i];

    for (0..size) |i| {
        projDbl(&l, &t[i], a[i]);
        f.mul(f, l);
    }
    f.sq(f);

    for (0..size) |i| {
        projAddSub(&l, &t[i], a[i], b[i], false, false);
        f.mul(f, l);

        projAddSub(&l, &t[i], a[i], b[i], true, true);
        f.mul(f, l);
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
        f.sq(f);

        for (0..size) |j| {
            projDbl(&l, &t[j], a[j]);
            f.mul(f, l);
        }

        if (s[i] != 0) for (0..size) |j| {
            projAddSub(&l, &t[j], a[j], b[j], s[i] > 0, true);
            f.mul(f, l);
        };
    }

    var frob: G2 = undefined;
    for (0..size) |i| {
        frob.frob(b[i]); // frob(b)
        projAddSub(&l, &t[i], a[i], frob, true, true);
        f.mul(f, l);

        frob.frob2(b[i]); // -frob^2(q)
        frob.negate(frob);
        projAddSub(&l, &t[i], a[i], frob, true, false);
        f.mul(f, l);
    }

    return f;
}

pub fn finalExp(x: Fp12) Fp12 {
    var t: [5]Fp12 = undefined;
    var s: Fp12 = undefined;

    t[0].conj(x);
    t[1].inverse(x);
    t[0].mul(t[0], t[1]);
    t[2].frob2(t[0]);
    s.mul(t[0], t[2]);

    t[0].powX(s);
    t[0].conj(t[0]);
    t[0].sqFast(t[0]);
    t[1].sqFast(t[0]);
    t[1].mul(t[1], t[0]);

    t[2].powX(t[1]);
    t[2].conj(t[2]);
    t[3].conj(t[1]);
    t[1].mul(t[2], t[3]);

    t[3].sqFast(t[2]);
    t[4].powX(t[3]);
    t[4].mul(t[1], t[4]);
    t[3].mul(t[0], t[4]);
    t[0].mul(t[2], t[4]);
    t[0].mul(t[0], s);

    t[2].frob(t[3]);
    t[0].mul(t[0], t[2]);
    t[2].frob2(t[4]);
    t[0].mul(t[0], t[2]);

    t[2].conj(s);
    t[2].mul(t[2], t[3]);
    // frob3 => frob2 \dot frob
    t[2].frob2(t[2]);
    t[2].frob(t[2]);

    var r: Fp12 = undefined;
    r.mul(t[0], t[2]);

    return r;
}

/// Doubles a point in Homogenous projective coordinates and evaluates the line in the Miller loop.
/// https://eprint.iacr.org/2013/722.pdf (Section 4.3)
fn projDbl(r: *Fp12, t: *G2, p: G1) void {
    var a: Fp2 = undefined;
    var b: Fp2 = undefined;
    var c: Fp2 = undefined;
    var d: Fp2 = undefined;

    var e: Fp2 = undefined;
    var f: Fp2 = undefined;
    var g: Fp2 = undefined;
    var h: Fp2 = undefined;

    var x3: Fp = undefined;

    // A=X1*Y1/2
    a.mul(t.x, t.y);
    a.halve(a);
    // B=Y1^2
    b.sq(t.y);
    // C=Z1^2
    c.sq(t.z);
    // D=3C
    d.add(c, c);
    d.add(d, c);
    // E=b'*D
    e.mul(d, Fp2.constants.twist_b_mont);
    // F=3E
    f.add(e, e);
    f.add(f, e);
    // G=(B+F)/2
    g.add(b, f);
    g.halve(g);
    // H= (Y1+Z1)^2 − (B+C)
    h.add(t.y, t.z);
    h.sq(h);
    h.sub(h, b);
    h.sub(h, c);

    // g(P) = (H * -y) + (X^2 * 3 * x)w + (E−B)w^3

    // el[0][0] = -(H * y)
    r.c0.c0.negate(h);
    r.c0.c0.c0.mul(r.c0.c0.c0, p.y);
    r.c0.c0.c1.mul(r.c0.c0.c1, p.y);
    // el[0][1] = 0
    r.c0.c1 = .zero;
    // el[0][2] = 0
    r.c0.c2 = .zero;
    // el[1][0] = (3 * X^2 * x)
    r.c1.c0.sq(t.x);
    x3.add(p.x, p.x);
    x3.add(x3, p.x);
    r.c1.c0.c0.mul(r.c1.c0.c0, x3);
    r.c1.c0.c1.mul(r.c1.c0.c1, x3);
    // el[1][0] = (E−B)
    r.c1.c1.sub(e, b);
    // el[1][2] = 0
    r.c1.c2 = .zero;

    // update `t`
    // X3 = A * (B−F)
    t.x.sub(b, f);
    t.x.mul(t.x, a);
    // Y3 = G^2 − 3*E^2 (reusing var c, d)
    t.y.sq(g);
    c.sq(e);
    d.add(c, c);
    d.add(d, c);
    t.y.sub(t.y, d);
    // Z3 = B*H
    t.z.mul(b, h);
}

/// https://eprint.iacr.org/2012/408, Sec 4.2.
fn projAddSub(r: *Fp12, t: *G2, p: G1, q: G2, is_add: bool, add_point: bool) void {
    const y = p.y;
    const x = p.x;
    const X2 = q.x;
    var Y2: Fp2 = undefined;
    if (is_add) {
        Y2 = q.y;
    } else {
        Y2.negate(q.y);
    }

    var a: Fp2 = undefined;
    var b: Fp2 = undefined;
    var c: Fp2 = undefined;
    var d: Fp2 = undefined;

    var e: Fp2 = undefined;
    var f: Fp2 = undefined;
    var g: Fp2 = undefined;
    var h: Fp2 = undefined;

    var i: Fp2 = undefined;
    var j: Fp2 = undefined;
    var k: Fp2 = undefined;

    var o: Fp2 = undefined;
    var l: Fp2 = undefined;

    a.mul(Y2, t.z);
    b.mul(X2, t.z);
    o.sub(t.y, a);
    l.sub(t.x, b);

    j.mul(o, X2);
    k.mul(l, Y2);

    // el[0][0] = (l * y)
    r.c0.c0.c0.mul(l.c0, y);
    r.c0.c0.c1.mul(l.c1, y);
    // el[0][1] = 0
    r.c0.c1 = .zero;
    // el[0][2] = 0
    r.c0.c2 = .zero;
    // el[1][0] = -(o * x), term in w
    r.c1.c0.negate(o);
    r.c1.c0.c0.mul(r.c1.c0.c0, x);
    r.c1.c0.c1.mul(r.c1.c0.c1, x);
    // el[1][1] = j-k
    r.c1.c1.sub(j, k);
    // el[1][2] = 0
    r.c1.c2 = .zero;

    if (add_point) {
        c.sq(o);
        d.sq(l);
        e.mul(d, l);
        f.mul(t.z, c);
        g.mul(t.x, d);
        h.add(e, f);
        h.sub(h, g);
        h.sub(h, g);
        i.mul(t.y, e);

        // update t
        t.x.mul(l, h);
        t.y.sub(g, h);
        t.y.mul(t.y, o);
        t.y.sub(t.y, i);
        t.z.mul(t.z, e);
    }
}
