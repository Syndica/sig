const std = @import("std");
const sig = @import("../sig.zig");
const FileId = sig.accounts_db.accounts_file.FileId;

pub fn FileIdConfig() sig.bincode.FieldConfig(FileId) {
    const S = struct {
        fn serialize(writer: anytype, data: anytype, params: sig.bincode.Params) anyerror!void {
            try sig.bincode.write(writer, @as(usize, data.toInt()), params);
        }

        fn deserialize(_: std.mem.Allocator, reader: anytype, params: sig.bincode.Params) anyerror!FileId {
            const int = try sig.bincode.readInt(usize, reader, params);
            if (int > std.math.maxInt(FileId.Int)) return error.IdOverflow;
            return FileId.fromInt(@intCast(int));
        }
    };

    return .{
        .serializer = S.serialize,
        .deserializer = S.deserialize,
    };
}
