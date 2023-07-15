const std = @import("std");
const bincode = @import("bincode-zig");

pub const varint_config = bincode.FieldConfig{
    .serializer = serilaize_varint,
    .deserializer = deserialize_varint,
};

pub fn serilaize_varint(writer: anytype, data: anytype, _: bincode.Params) !void {
    var v = data;
    while (v >= 0x80) {
        var byte = @as(u8, @intCast(((v & 0x7F) | 0x80)));
        v >>= 7;
        try writer.writeByte(byte);
    }
    try writer.writeByte(@as(u8, @intCast(v)));
    return;
}

pub fn deserialize_varint(_: std.mem.Allocator, comptime T: type, reader: anytype, _: bincode.Params) !T {
    var out: T = 0;

    var t_bits: u8 = switch (T) {
        u16 => 16,
        u32 => 32,
        u64 => 64,
        else => {
            return error.InvalidType;
        },
    };

    const ShiftT: type = switch (T) {
        u16 => u4,
        u32 => u5,
        u64 => u6,
        else => unreachable,
    };

    var shift: u32 = 0;
    while (shift < t_bits) {
        const byte: u8 = try reader.readByte();
        out |= @as(T, @intCast((byte & 0x7F))) << @as(ShiftT, @intCast(shift));
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

pub fn serialize_short_u16(writer: anytype, data: anytype, _: bincode.Params) !void {
    var val: u16 = data;
    while (true) {
        var elem = @as(u8, @intCast((val & 0x7f)));
        val >>= 7;
        if (val == 0) {
            try writer.writeByte(elem);
            break;
        } else {
            elem |= 0x80;
            try writer.writeByte(elem);
        }
    }
}

pub fn deserialize_short_u16(_: std.mem.Allocator, comptime T: type, reader: anytype, _: bincode.Params) !T {
    var val: u16 = 0;
    for (0..MAX_ENCODING_LENGTH) |n| {
        var elem: u8 = try reader.readByte();
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

pub fn visit_byte(elem: u8, val: u16, nth_byte: usize) !DoneOrMore {
    if (elem == 0 and nth_byte != 0) {
        return error.VisitError;
    }

    var value = @as(u32, val);
    var element = @as(u32, elem);
    var elem_val: u8 = @as(u8, @intCast(element & 0x7f));
    var elem_done = (element & 0x80) == 0;

    if (nth_byte >= MAX_ENCODING_LENGTH) {
        return error.TooLong;
    } else if (nth_byte == (MAX_ENCODING_LENGTH - 1) and !elem_done) {
        return error.ByteThreeContinues;
    }

    var shift: u32 = (std.math.cast(u32, nth_byte) orelse U32_MAX) *| 7;

    var shift_res = @shlWithOverflow(elem_val, @as(u3, @intCast(shift)));
    if (shift_res.@"1" == 1) {
        elem_val = U32_MAX;
    } else {
        elem_val = shift_res.@"0".Int.bits;
    }

    var new_val = value | elem_val;
    value = std.math.cast(u16, new_val) catch return error.Overflow;

    if (elem_done) {
        return .{ .Done = value };
    } else {
        return .{ .More = value };
    }
}

pub fn visit_byte_2(elem: u8, val: u16, nth_byte: usize) !DoneOrMore {
    if (elem == 0 and nth_byte != 0) {
        return error.VisitError;
    }

    var value = @as(u32, val);
    var element = @as(u32, elem);
    var elem_val: u32 = element & 0x7f;
    var elem_done = (element & 0x80) == 0;

    if (nth_byte >= MAX_ENCODING_LENGTH) {
        return error.TooLong;
    } else if (nth_byte == (MAX_ENCODING_LENGTH -| 1) and !elem_done) {
        return error.ByteThreeContinues;
    }

    var shift: u32 = (std.math.cast(u32, nth_byte) orelse U32_MAX) *| 7;

    var shift_res = @shlWithOverflow(elem_val, @as(u3, @intCast(shift)));
    var result = shift_res.@"0";
    var overflow_bit = shift_res.@"1";
    if (overflow_bit == 1) {
        elem_val = U32_MAX;
    } else {
        elem_val = result;
    }

    var new_val = value | elem_val;
    var out_val = std.math.cast(u16, new_val) orelse return error.Overflow;

    if (elem_done) {
        return .{ .Done = out_val };
    } else {
        return .{ .More = out_val };
    }
}
