const std = @import("std");
const sig = @import("../lib.zig");

const bincode = sig.bincode;

pub fn VarIntConfig(comptime VarInt: type) bincode.FieldConfig(VarInt) {
    const S = struct {
        pub fn serialize(writer: anytype, data: anytype, params: bincode.Params) !void {
            _ = params;
            var v = data;
            while (v >= 0x80) {
                const byte = @as(u8, @intCast(((v & 0x7F) | 0x80)));
                v >>= 7;
                try writer.writeByte(byte);
            }
            try writer.writeByte(@as(u8, @intCast(v)));
        }

        pub fn deserialize(allocator: std.mem.Allocator, reader: anytype, params: bincode.Params) !VarInt {
            _ = params;
            _ = allocator;

            var out: VarInt = 0;

            const t_bits: u8 = switch (VarInt) {
                u16 => 16,
                u32 => 32,
                u64 => 64,
                else => {
                    return error.InvalidType;
                },
            };

            const ShiftT: type = switch (VarInt) {
                u16 => u4,
                u32 => u5,
                u64 => u6,
                else => unreachable,
            };

            var shift: u32 = 0;
            while (shift < t_bits) {
                const byte: u8 = try reader.readByte();
                out |= @as(VarInt, @intCast((byte & 0x7F))) << @as(ShiftT, @intCast(shift));
                if (byte & 0x80 == 0) {
                    if (@as(u8, @intCast(out >> @as(ShiftT, @intCast(shift)))) != byte) {
                        return error.TruncatedLastByte;
                    }
                    if (byte == 0 and (shift != 0 or out != 0)) {
                        return error.NotValidTrailingZeros;
                    }
                    return out;
                }
                shift += 7;
            }
            return error.ShiftOverflows;
        }
    };

    return bincode.FieldConfig(VarInt){
        .serializer = S.serialize,
        .deserializer = S.deserialize,
    };
}

pub const var_int_config_u16 = VarIntConfig(u16);
pub const var_int_config_u64 = VarIntConfig(u64);

pub fn serialize_short_u16(writer: anytype, data: u16, _: bincode.Params) !void {
    var value = data;
    while (true) {
        var elem = @as(u8, @intCast((value & 0x7f)));
        value >>= 7;
        if (value == 0) {
            try writer.writeByte(elem);
            break;
        } else {
            elem |= 0x80;
            try writer.writeByte(elem);
        }
    }
}

pub fn deserialize_short_u16(reader: anytype, _: bincode.Params) !u16 {
    var val: u16 = 0;
    for (0..MAX_ENCODING_LENGTH) |n| {
        const elem: u8 = try reader.readByte();
        switch (try visit_byte_2(elem, val, n)) {
            .Done => |v| {
                return v;
            },
            .More => |v| {
                val = v;
            },
        }
    }

    return error.ByteThreeContinues;
}

const DoneOrMore = union(enum) {
    Done: u16,
    More: u16,
};

const U32_MAX: u32 = 4_294_967_295;
const MAX_ENCODING_LENGTH = 3;

pub fn visit_byte_2(elem: u8, val: u16, nth_byte: usize) !DoneOrMore {
    if (elem == 0 and nth_byte != 0) {
        return error.VisitError;
    }

    const value = @as(u32, val);
    const element = @as(u32, elem);
    var elem_val: u32 = element & 0x7f;
    const elem_done = (element & 0x80) == 0;

    if (nth_byte >= MAX_ENCODING_LENGTH) {
        return error.TooLong;
    } else if (nth_byte == (MAX_ENCODING_LENGTH -| 1) and !elem_done) {
        return error.ByteThreeContinues;
    }

    const shift: u32 = (std.math.cast(u32, nth_byte) orelse U32_MAX) *| 7;

    const shift_res = @shlWithOverflow(elem_val, @as(u3, @intCast(shift)));
    const result = shift_res.@"0";
    const overflow_bit = shift_res.@"1";
    if (overflow_bit == 1) {
        elem_val = U32_MAX;
    } else {
        elem_val = result;
    }

    const new_val = value | elem_val;
    const out_val = std.math.cast(u16, new_val) orelse return error.Overflow;

    if (elem_done) {
        return .{ .Done = out_val };
    } else {
        return .{ .More = out_val };
    }
}
