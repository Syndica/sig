const std = @import("std");

pub const CurveId = enum(u64) {
    edwards = 0,
    ristretto = 1,

    bls12_381_be = 4 | 0x80,
    bls12_381_le = 4,
    bls12_381_g1_be = 5 | 0x80,
    bls12_381_g1_le = 5,
    bls12_381_g2_be = 6 | 0x80,
    bls12_381_g2_le = 6,

    fn wrap(id: u64) ?CurveId {
        return std.meta.intToEnum(CurveId, id) catch null;
    }
};

pub const GroupOp = enum(u64) {
    add = 0,
    subtract = 1,
    multiply = 2,

    fn wrap(id: u64) ?GroupOp {
        if (id > 2) return null;
        return @enumFromInt(id);
    }
};
