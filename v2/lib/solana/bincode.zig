const std = @import("std");

pub const Deprecated = void; // noreturn here crashes the compiler
const read_func_overload = "bincodeRead";
const write_func_overload = "bincodeWrite";

pub fn read(fba: *std.heap.FixedBufferAllocator, reader: *std.Io.Reader, comptime T: type) !T {
    switch (@typeInfo(T)) {
        .int => return try reader.takeInt(T, .little),
        .optional => |info| switch (try reader.takeByte()) {
            0 => return null,
            1 => return try read(fba, reader, info.child),
            else => return error.InvalidOptional,
        },
        .array => |info| {
            comptime std.debug.assert(@typeInfo(info.child) == .int);
            return @bitCast((try reader.takeArray(@sizeOf(info.child) * info.len)).*);
        },
        .@"enum" => |info| {
            const tag = try reader.takeInt(info.tag_type, .little);
            return try std.meta.intToEnum(T, tag);
        },
        .@"union" => |info| {
            if (@hasDecl(T, read_func_overload))
                return @field(T, read_func_overload)(fba, reader);

            switch (try read(fba, reader, info.tag_type.?)) {
                inline else => |tag| {
                    const Variant = @FieldType(T, @tagName(tag));
                    const value = if (Variant == void) {} else try read(fba, reader, Variant);
                    return @unionInit(T, @tagName(tag), value);
                },
            }
        },
        .@"struct" => |info| {
            if (@hasDecl(T, read_func_overload))
                return @field(T, read_func_overload)(fba, reader);

            var value: T = undefined;
            inline for (info.fields) |f| @field(value, f.name) = try read(fba, reader, f.type);
            return value;
        },
        .void => return error.Deprecated,
        else => @compileError("unsupported type: " ++ @typeName(T)),
    }
}

pub fn write(writer: *std.Io.Writer, value: anytype) !void {
    const T = @TypeOf(value);

    switch (@typeInfo(T)) {
        .int => try writer.writeInt(T, value, .little),
        .optional => {
            try writer.writeByte(@intFromBool(value != null));
            if (value) |v| try write(writer, v);
        },
        .array => |info| {
            comptime std.debug.assert(@typeInfo(info.child) == .int);
            try writer.writeAll(std.mem.asBytes(&value));
        },
        .@"enum" => try write(writer, @intFromEnum(value)),
        .@"union" => {
            if (@hasDecl(T, write_func_overload))
                return @field(T, write_func_overload)(&value, writer);
                
            switch (std.meta.activeTag(value)) {
                inline else => |tag| {
                    try write(writer, tag);
                    if (@FieldType(T, @tagName(tag)) != void)
                        try write(writer, @field(value, @tagName(tag)));
                },
            }
        },
        .@"struct" => |info| {
            if (@hasDecl(T, write_func_overload))
                return @field(T, write_func_overload)(&value, writer);
            inline for (info.fields) |f| try write(writer, @field(value, f.name));
        },
        .void => return error.Deprecated,
        else => @compileError("unsupported type: " ++ @typeName(T)),
    }
}

pub fn VarInt(comptime T: type) type {
    return struct {
        value: T,

        const Self = @This();

        pub fn bincodeRead(_: *std.heap.FixedBufferAllocator, reader: *std.Io.Reader) !Self {
            return .{ .value = try reader.takeLeb128(T) };
        }

        pub fn bincodeWrite(self: *const Self, writer: *std.Io.Writer) !void {
            try writer.writeLeb128(self.value);
        }
    };
}

pub fn Vec(comptime T: type) type {
    return struct {
        items: []const T,

        const Self = @This();

        pub fn bincodeRead(fba: *std.heap.FixedBufferAllocator, reader: *std.Io.Reader) !Self {
            const n = try reader.takeInt(u64, .little);
            const slice = try fba.allocator().alloc(T, n);
            if (@typeInfo(T) == .int) {
                try reader.readSliceAll(std.mem.sliceAsBytes(slice));
            } else {
                for (slice) |*v| v.* = try read(fba, reader, T);
            }
            return .{ .items = slice };
        }

        pub fn bincodeWrite(self: *const Self, writer: *std.Io.Writer) !void {
            try writer.writeInt(u64, self.items.len, .little);
            if (@typeInfo(T) == .int) {
                try writer.writeAll(std.mem.sliceAsBytes(self.items));
            } else {
                for (self.items) |v| try write(writer, v);
            }
        }
    };
}

pub fn ShortVec(comptime T: type) type {
    return struct {
        items: []const T,

        const Self = @This();

        pub fn bincodeRead(fba: *std.heap.FixedBufferAllocator, reader: *std.Io.Reader) !Self {
            const n = try read(fba, reader, VarInt(u16));
            const slice = try fba.allocator().alloc(T, n.value);
            if (@typeInfo(T) == .int) {
                try reader.readSliceAll(std.mem.sliceAsBytes(slice));
            } else {
                for (slice) |*v| v.* = try read(fba, reader, T);
            }
            return .{ .items = slice };
        }

        pub fn bincodeWrite(self: *const Self, writer: *std.Io.Writer) !void {
            try write(writer, VarInt(u16){ .value = @intCast(self.items.len) });
            if (@typeInfo(T) == .int) {
                try writer.writeAll(std.mem.sliceAsBytes(self.items));
            } else {
                for (self.items) |v| try write(writer, v);
            }
        }
    };
}

pub fn BitVec(comptime T: type) type {
    return struct {
        words: []T,
        capacity: u64,

        const Self = @This();

        pub fn bincodeRead(fba: *std.heap.FixedBufferAllocator, reader: *std.Io.Reader) !Self {
            const maybe_vec = try read(fba, reader, ?Vec(T));
            const capacity = try reader.takeInt(u64, .little);

            const words: []T = if (maybe_vec) |vec| @constCast(vec.items) else &.{};
            if (capacity > words.len * @bitSizeOf(T)) return error.InvalidBitCapacity;
            return .{ .words = words, .capacity = capacity };
        }

        pub fn bincodeWrite(self: *const Self, writer: *std.Io.Writer) !void {
            const maybe_vec: ?Vec(T) =
                if (self.words.len > 0) Vec(T){ .items = self.words } else null;
            try write(writer, maybe_vec);
            try writer.writeInt(u64, self.capacity, .little);
        }

        pub fn get(self: *const Self, bit: usize) u1 {
            return @truncate(self.words[bit / @bitSizeOf(T)] >> @intCast(bit % @bitSizeOf(T)));
        }

        pub fn set(self: *Self, bit: usize) u1 {
            const mask = @as(T, 1) << @intCast(bit % @bitSizeOf(T));
            const word = &self.words[bit / @bitSizeOf(T)];
            defer word.* |= mask;
            return @intFromBool(word.* & mask > 0);
        }
    };
}
