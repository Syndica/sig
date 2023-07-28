const std = @import("std");
pub const getty = @import("getty");

pub const Params = struct {
    pub const legacy: Params = .{
        .endian = .Little,
        .int_encoding = .fixed,
        .include_fixed_array_length = true,
    };

    pub const standard: Params = .{
        .endian = .Little,
        .int_encoding = .fixed,
        .include_fixed_array_length = false,
    };

    endian: std.builtin.Endian = .Little,
    int_encoding: enum { variable, fixed } = .fixed,
    include_fixed_array_length: bool = false,
};

pub fn deserializer(r: anytype, params: Params) blk: {
    break :blk Deserializer(@TypeOf(r));
} {
    return Deserializer(@TypeOf(r)).init(r, params);
}

pub fn Deserializer(comptime Reader: type) type {
    return struct {
        reader: Reader,
        params: Params,

        const Self = @This();
        const Error = getty.de.Error || error{
            IO,
        };

        const De = Self.@"getty.Deserializer";

        pub fn init(reader: Reader, params: Params) Self {
            std.debug.assert(params.int_encoding == .fixed);
            return Self{ .reader = reader, .params = params };
        }

        pub usingnamespace getty.Deserializer(
            *Self,
            Error,
            custom_dser,
            null,
            .{
                .deserializeBool = deserializeBool,
                .deserializeInt = deserializeInt,
                .deserializeEnum = deserializeEnum,
                .deserializeOptional = deserializeOptional,
                .deserializeVoid = deserializeVoid,
                .deserializeSeq = deserializeSeq,
            },
        );

        fn deserializeSeq(self: *Self, allocator: ?std.mem.Allocator, visitor: anytype) Error!@TypeOf(visitor).Value {
            // var len = if (self.params.include_fixed_array_length) try self.deserializeInt(allocator, getty.de.blocks.Int.Visitor(u64)) else null;

            const tmp: @TypeOf(visitor).Value = undefined; // TODO: fix without stack alloc?
            const len = tmp.len;

            var s = SeqAccess(Self){ .d = self, .len = len };
            const result = try visitor.visitSeq(allocator.?, De, s.seqAccess());
            errdefer getty.de.free(allocator.?, De, result);

            return result;
        }

        pub fn deserializeVoid(self: *Self, ally: ?std.mem.Allocator, visitor: anytype) Error!@TypeOf(visitor).Value {
            _ = self;
            return try visitor.visitVoid(ally, De);
        }

        pub fn deserializeOptional(self: *Self, ally: ?std.mem.Allocator, visitor: anytype) Error!@TypeOf(visitor).Value {
            const byte = self.reader.readByte() catch {
                return Error.IO;
            };
            return switch (byte) {
                0 => try visitor.visitNull(ally, De),
                1 => try visitor.visitSome(ally, self.deserializer()),
                else => getty.de.Error.InvalidValue,
            };
        }

        pub fn deserializeEnum(self: *Self, ally: ?std.mem.Allocator, visitor: anytype) Error!@TypeOf(visitor).Value {
            const T = u32; // enum size
            const tag = switch (self.params.endian) {
                .Little => self.reader.readIntLittle(T),
                .Big => self.reader.readIntBig(T),
            } catch {
                return Error.IO;
            };
            return try visitor.visitInt(ally, De, tag);
        }

        pub fn deserializeInt(self: *Self, ally: ?std.mem.Allocator, visitor: anytype) Error!@TypeOf(visitor).Value {
            const T = @TypeOf(visitor).Value;

            const value = switch (self.params.endian) {
                .Little => self.reader.readIntLittle(T),
                .Big => self.reader.readIntBig(T),
            } catch {
                return Error.IO;
            };

            return try visitor.visitInt(ally, De, value);
        }

        pub fn deserializeBool(self: *Self, ally: ?std.mem.Allocator, visitor: anytype) Error!@TypeOf(visitor).Value {
            const byte = self.reader.readByte() catch {
                return Error.IO;
            };
            const value = switch (byte) {
                0 => false,
                1 => true,
                else => return getty.de.Error.InvalidValue,
            };

            return try visitor.visitBool(ally, De, value);
        }

        const custom_dser = struct {
            pub fn is(comptime T: type) bool {
                return switch (@typeInfo(T)) {
                    .Union => true,
                    .Struct => true,
                    .Pointer => |*info| {
                        if (info.size == .Many) {
                            return true;
                        }
                        return info.size == .Slice;
                    },
                    else => false,
                };
            }

            pub fn Visitor(comptime Value: type) type {
                return struct {
                    pub usingnamespace getty.de.Visitor(
                        @This(),
                        Value,
                        .{},
                    );
                };
            }

            pub fn free(
                allocator: std.mem.Allocator,
                comptime d: type,
                value: anytype,
            ) void {
                const T = @TypeOf(value);
                switch (@typeInfo(T)) {
                    .Union => |*info| {
                        inline for (info.fields) |field| {
                            if (value == @field(T, field.name)) {
                                return getty.de.free(allocator, d, @field(value, field.name));
                            }
                        }
                    },
                    .Struct => |*info| {
                        inline for (info.fields) |field| {
                            if (!field.is_comptime) {
                                getty.de.free(allocator, d, @field(value, field.name));
                            }
                        }
                    },
                    .Pointer => |*info| {
                        if (info.size == .Many) {
                            return;
                        }

                        std.debug.assert(info.size == .Slice);
                        for (value) |item| {
                            getty.de.free(allocator, d, item);
                        }
                        allocator.free(value);
                    },
                    else => {},
                }
            }

            pub fn deserialize(
                alloc: ?std.mem.Allocator,
                comptime T: type,
                dd: anytype,
                visitor: anytype,
            ) Error!@TypeOf(visitor).Value {
                switch (@typeInfo(T)) {
                    .Union => |*info| {
                        const tag_type = info.tag_type orelse @compileError("unions must have a tag type");
                        const raw_tag = try getty.deserialize(alloc, tag_type, dd);

                        inline for (info.fields) |field| {
                            if (raw_tag == @field(tag_type, field.name)) {
                                const payload = try getty.deserialize(alloc, field.type, dd);
                                return @unionInit(T, field.name, payload);
                            }
                        }
                        return getty.de.Error.InvalidValue;
                    },
                    .Struct => |*info| {
                        const reader = dd.context.reader;
                        const params = dd.context.params;
                        var data: T = undefined;

                        if (getStructSerializer(T)) |deser_fcn| {
                            data = try deser_fcn(alloc, T, reader, params);
                            return data;
                        }

                        inline for (info.fields) |field| {
                            if (!field.is_comptime) {
                                if (shouldUseDefaultValue(T, field)) |val| {
                                    @field(data, field.name) = @as(*const field.type, @ptrCast(@alignCast(val))).*;
                                } else if (getFieldDeserializer(T, field)) |deser_fcn| {
                                    @field(data, field.name) = try (deser_fcn(alloc, field.type, reader, params) catch getty.de.Error.InvalidValue);
                                } else {
                                    @field(data, field.name) = try getty.deserialize(alloc, field.type, dd);
                                }
                            }
                        }
                        return data;
                    },
                    .Pointer => |*info| {
                        if (info.size == .Many) {
                            std.debug.print("{any}\n", .{info});
                        }
                        std.debug.assert(info.size == .Slice);

                        const len = try getty.deserialize(alloc, u64, dd);
                        const ally = alloc.?;

                        const entries = try ally.alloc(info.child, len);
                        errdefer ally.free(entries);

                        for (entries) |*entry| {
                            entry.* = try getty.deserialize(alloc, info.child, dd);
                        }

                        return entries;
                    },
                    else => unreachable,
                }
            }
        };

        fn SeqAccess(comptime D: type) type {
            return struct {
                d: *D,
                len: usize,
                idx: usize = 0,

                const Seq = @This();

                pub usingnamespace getty.de.SeqAccess(
                    *Seq,
                    Error,
                    .{ .nextElementSeed = nextElementSeed },
                );

                fn nextElementSeed(self: *Seq, ally: ?std.mem.Allocator, seed: anytype) Error!?@TypeOf(seed).Value {
                    if (self.idx == self.len) {
                        return null;
                    }
                    const element = try seed.deserialize(ally, self.d.deserializer());
                    self.idx += 1;

                    return element;
                }
            };
        }
    };
}

pub fn free(
    ally: std.mem.Allocator,
    v: anytype,
) void {
    const D = Deserializer(
        std.io.FixedBufferStream([]u8).Reader,
    );
    return getty.de.free(ally, D.De, v);
}

// for ref: https://github.com/getty-zig/json/blob/a5c4d9f996dc3f472267f6210c30f96c39da576b/src/ser/serializer.zig
pub fn serializer(w: anytype, params: Params) blk: {
    break :blk Serializer(@TypeOf(w));
} {
    return Serializer(@TypeOf(w)).init(w, params);
}

pub fn Serializer(
    comptime Writer: type,
) type {
    return struct {
        writer: Writer,
        params: Params,

        const Self = @This();
        const Ok = void;
        const Error = getty.ser.Error || error{IO};

        pub fn init(w: Writer, params: Params) Self {
            std.debug.assert(params.int_encoding == .fixed);
            return .{ .writer = w, .params = params };
        }

        pub usingnamespace getty.Serializer(
            *Self,
            Ok,
            Error,
            custom_ser,
            null,
            null,
            Aggregate,
            null,
            .{
                .serializeBool = serializeBool,
                .serializeInt = serializeInt,
                .serializeEnum = serializeEnum,
                .serializeSome = serializeSome,
                .serializeNull = serializeNull,
                .serializeSeq = serializeSeq,
                .serializeVoid = serializeVoid,
            },
        );

        fn serializeSeq(self: *Self, len: ?usize) Error!Aggregate {
            if (self.params.include_fixed_array_length) {
                try self.serializeInt(@as(u64, len.?));
            }
            return try self.serializeMap(len);
        }

        fn serializeVoid(self: *Self) Error!Ok {
            _ = self;
        }

        fn serializeNull(self: *Self) Error!Ok {
            try (self.writer.writeByte(0) catch Error.IO);
        }

        fn serializeSome(self: *Self, value: anytype) Error!Ok {
            try (self.writer.writeByte(1) catch Error.IO);
            const ss = self.serializer();
            return try getty.serialize(null, value, ss);
        }

        fn serializeMap(self: *Self, len: ?usize) Error!Aggregate {
            _ = len;
            return Aggregate{ .ser = self };
        }

        fn serializeBool(self: *Self, value: bool) Error!Ok {
            try (self.writer.writeByte(@intFromBool(value)) catch Error.IO);
        }

        fn serializeInt(self: *Self, value: anytype) Error!Ok {
            const T = @TypeOf(value);
            switch (@typeInfo(T)) {
                .ComptimeInt => {
                    if (value < 0) {
                        @compileError("Signed comptime integers can not be serialized.");
                    }
                    try self.serializeInt(@as(u64, value));
                },
                .Int => |info| {
                    if ((info.bits & (info.bits - 1)) != 0 or info.bits < 8 or info.bits > 256) {
                        @compileError("Only i{8, 16, 32, 64, 128, 256}, u{8, 16, 32, 64, 128, 256} integers may be serialized, but attempted to serialize " ++ @typeName(T) ++ ".");
                    }

                    switch (self.params.int_encoding) {
                        .fixed => {
                            try (switch (self.params.endian) {
                                .Little => self.writer.writeIntLittle(T, value),
                                .Big => self.writer.writeIntBig(T, value),
                            } catch Error.IO);
                        },
                        else => unreachable,
                    }
                },
                else => {
                    unreachable;
                },
            }
        }

        fn serializeEnum(self: *Self, index: anytype, name: []const u8) Error!Ok {
            _ = name;
            switch (self.params.int_encoding) {
                .fixed => {
                    return try self.serializeInt(@as(u32, index));
                },
                .variable => {
                    unreachable;
                },
            }
        }

        const custom_ser = struct {
            pub fn is(comptime T: type) bool {
                return switch (@typeInfo(T)) {
                    .Union => true,
                    .Struct => true,
                    .Pointer => |*info| {
                        return info.size == .Slice;
                    },
                    else => false,
                };
            }

            pub fn serialize(alloc: ?std.mem.Allocator, value: anytype, ss: anytype) Error!Ok {
                const T = @TypeOf(value);
                switch (@typeInfo(T)) {
                    .Union => |*info| {
                        try getty.serialize(alloc, @as(u32, @intFromEnum(value)), ss);
                        inline for (info.fields) |field| {
                            if (value == @field(T, field.name)) {
                                return try getty.serialize(alloc, @field(value, field.name), ss);
                            }
                        }
                    },
                    .Struct => |*info| {
                        var params = ss.context.params;
                        var writer = ss.context.writer;

                        if (getStructSerializer(T)) |ser_fcn| {
                            return ser_fcn(writer, value, params);
                        }

                        inline for (info.fields) |field| {
                            if (!field.is_comptime) {
                                if (!shouldSkipSerializingField(T, field)) {
                                    if (getFieldSerializer(T, field)) |ser_fcn| {
                                        try (ser_fcn(writer, @field(value, field.name), params) catch Error.IO);
                                    } else {
                                        try getty.serialize(alloc, @field(value, field.name), ss);
                                    }
                                }
                            }
                        }
                    },
                    .Pointer => |*info| {
                        std.debug.assert(info.size == .Slice);

                        try getty.serialize(alloc, @as(u64, value.len), ss);
                        for (value) |element| {
                            try getty.serialize(alloc, element, ss);
                        }
                    },
                    else => unreachable,
                }
            }
        };

        const Aggregate = struct {
            ser: *Self,

            const A = @This();

            pub usingnamespace getty.ser.Seq(
                *A,
                Ok,
                Error,
                .{
                    .serializeElement = serializeElement,
                    .end = end,
                },
            );

            fn serializeElement(self: *A, value: anytype) Error!Ok {
                const ss = self.ser.serializer();
                try getty.serialize(null, value, ss);
            }

            fn end(self: *A) Error!Ok {
                _ = self;
            }
        };
    };
}

pub inline fn shouldUseDefaultValue(comptime parent_type: type, comptime struct_field: std.builtin.Type.StructField) ?*const anyopaque {
    const parent_type_name = @typeName(parent_type);

    if (@hasDecl(parent_type, "!bincode-config:" ++ struct_field.name)) {
        const config = @field(parent_type, "!bincode-config:" ++ struct_field.name);
        if (config.skip and struct_field.default_value == null) {
            @compileError("┓\n|\n|--> Invalid config: cannot skip field '" ++ parent_type_name ++ "." ++ struct_field.name ++ "' deserialization if no default value set\n\n");
        }
        return struct_field.default_value;
    }

    return null;
}

pub fn getFieldDeserializer(comptime parent_type: type, comptime struct_field: std.builtin.Type.StructField) ?DeserializeFunction {
    if (@hasDecl(parent_type, "!bincode-config:" ++ struct_field.name)) {
        const config = @field(parent_type, "!bincode-config:" ++ struct_field.name);
        return config.deserializer;
    }
    return null;
}

pub const SerializeFunction = fn (writer: anytype, data: anytype, params: Params) anyerror!void;
pub const DeserializeFunction = fn (alloc: ?std.mem.Allocator, comptime T: type, reader: anytype, params: Params) anyerror!void;

pub const FieldConfig = struct {
    serializer: ?SerializeFunction = null,
    deserializer: ?DeserializeFunction = null,
    skip: bool = false,
};

pub const StructConfig = struct {
    serializer: ?SerializeFunction = null,
    deserializer: ?DeserializeFunction = null,
};

pub fn getStructSerializer(comptime parent_type: type) ?SerializeFunction {
    if (@hasDecl(parent_type, "!bincode-config")) {
        const config = @field(parent_type, "!bincode-config");
        return config.serializer;
    }
    return null;
}

pub fn getFieldSerializer(comptime parent_type: type, comptime struct_field: std.builtin.Type.StructField) ?SerializeFunction {
    if (@hasDecl(parent_type, "!bincode-config:" ++ struct_field.name)) {
        const config = @field(parent_type, "!bincode-config:" ++ struct_field.name);
        return config.serializer;
    }
    return null;
}

pub inline fn shouldSkipSerializingField(comptime parent_type: type, comptime struct_field: std.builtin.Type.StructField) bool {
    const parent_type_name = @typeName(parent_type);

    if (@hasDecl(parent_type, "!bincode-config:" ++ struct_field.name)) {
        const config = @field(parent_type, "!bincode-config:" ++ struct_field.name);
        if (config.skip and struct_field.default_value == null) {
            @compileError("┓\n|\n|--> Invalid config: cannot skip field '" ++ parent_type_name ++ "." ++ struct_field.name ++ "' serialization if no default value set\n\n");
        }
        return config.skip;
    }

    return false;
}

pub fn writeToSlice(slice: []u8, data: anytype, params: Params) ![]u8 {
    var stream = std.io.fixedBufferStream(slice);
    var writer = stream.writer();
    var s = serializer(writer, params);
    const ss = s.serializer();
    try getty.serialize(null, data, ss);
    return stream.getWritten();
}

pub fn write(alloc: ?std.mem.Allocator, writer: anytype, data: anytype, params: Params) !void {
    var s = serializer(writer, params);
    const ss = s.serializer();
    try getty.serialize(alloc, data, ss);
}

// can call if dont require an allocator
pub fn readFromSlice(alloc: ?std.mem.Allocator, comptime T: type, slice: []const u8, params: Params) !T {
    var stream = std.io.fixedBufferStream(slice);
    var reader = stream.reader();
    var d = deserializer(reader, params);
    const dd = d.deserializer();
    const v = try getty.deserialize(alloc, T, dd);
    errdefer getty.de.free(alloc, @TypeOf(dd), v); // !

    return v;
}

pub fn read(alloc: ?std.mem.Allocator, comptime T: type, reader: anytype, params: Params) !T {
    var d = deserializer(reader, params);
    const dd = d.deserializer();
    const v = try getty.deserialize(alloc, T, dd);
    errdefer getty.de.free(alloc, @TypeOf(dd), v);

    return v;
}

test "getty: test serialization" {
    var buf: [1]u8 = undefined;

    {
        var out = try writeToSlice(&buf, true, Params.standard);
        try std.testing.expect(out.len == 1);
        try std.testing.expect(out[0] == 1);
    }

    {
        var out = try readFromSlice(null, bool, &buf, Params{});
        try std.testing.expect(out == true);
    }

    {
        var out = try writeToSlice(&buf, false, Params.standard);
        try std.testing.expect(out.len == 1);
        try std.testing.expect(out[0] == 0);
    }

    var buf2: [8]u8 = undefined; // u64 default
    _ = try writeToSlice(&buf2, 300, Params.standard);

    var buf3: [4]u8 = undefined;
    var v: u32 = 200;
    _ = try writeToSlice(&buf3, v, Params.standard);

    {
        var out = try readFromSlice(null, u32, &buf3, Params{});
        try std.testing.expect(out == 200);
    }

    const Foo = enum { A, B };
    var out = try writeToSlice(&buf3, Foo.B, Params.standard);
    var e = [_]u8{ 1, 0, 0, 0 };
    try std.testing.expectEqualSlices(u8, &e, out);

    var read_out = try readFromSlice(null, Foo, &buf3, Params{});
    try std.testing.expectEqual(read_out, Foo.B);

    const Foo2 = union(enum(u8)) { A: u32, B: u32, C: u32 };
    const expected = [_]u8{ 1, 0, 0, 0, 1, 1, 1, 1 };
    const value = Foo2{ .B = 16843009 };
    // Map keys
    // .A = 65 = 1000001 (7 bits)
    // .B = 66 = 1000010
    // .B = 67 = 1000011
    var out2 = try writeToSlice(&buf2, value, Params.standard);
    try std.testing.expectEqualSlices(u8, &expected, out2);

    var read_out2 = try readFromSlice(null, Foo2, &buf2, Params{});
    try std.testing.expectEqual(read_out2, value);

    const Bar = struct { a: u32, b: u32, c: Foo2 };
    const b = Bar{ .a = 65, .b = 66, .c = Foo2{ .B = 16843009 } };
    var buf4: [100]u8 = undefined;
    var out3 = try writeToSlice(&buf4, b, Params.standard);
    var expected2 = [_]u8{ 65, 0, 0, 0, 66, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1 };
    try std.testing.expectEqualSlices(u8, &expected2, out3);

    const s = struct {
        a: u32,
        b: ?u16,
        c: Bar,
    };
    const _s = s{
        .a = 65,
        .b = null,
        .c = Bar{ .a = 66, .b = 67, .c = Foo2{ .B = 16843009 } },
    };
    var buf6: [100]u8 = undefined;
    var out4 = try writeToSlice(&buf6, _s, Params.standard);
    var result = try readFromSlice(null, s, out4, Params{});
    try std.testing.expectEqual(result, _s);
}
