const std = @import("std");
const sig = @import("../sig.zig");
const build_options = @import("build-options");

const version = build_options.version;

pub const ClientVersion = struct {
    major: u16,
    minor: u16,
    patch: u16,
    commit: u32, // first 4 bytes of the sha1 commit hash
    feature_set: u32, // first 4 bytes of the FeatureSet identifier
    client: Clients,

    pub const CURRENT: ClientVersion = .{
        .major = version.major,
        .minor = version.minor,
        .patch = version.patch,
        .commit = std.fmt.parseInt(u32, version.build orelse "0", 16) catch
            @compileError("failed to parse build"),
        .feature_set = 0,
        .client = .sig,
    };

    const Clients = enum(u16) {
        solana_labs = 0,
        jito_labs = 1,
        frankendancer = 2,
        agave = 3,
        agave_paladin = 4,
        agave_bam = 5,
        sig = 6,
        firedancer = 7,
        _,

        pub fn serialize(writer: anytype, data: anytype, _: sig.bincode.Params) !void {
            try std.leb.writeUleb128(writer, @intFromEnum(data));
        }

        pub fn deserialize(
            _: *sig.bincode.LimitAllocator,
            reader: anytype,
            _: sig.bincode.Params,
        ) !Clients {
            return @enumFromInt(try std.leb.readUleb128(u16, reader));
        }
    };

    pub const @"!bincode-config:major" = sig.bincode.VarIntConfig(u16);
    pub const @"!bincode-config:minor" = sig.bincode.VarIntConfig(u16);
    pub const @"!bincode-config:patch" = sig.bincode.VarIntConfig(u16);
    pub const @"!bincode-config:client" = sig.bincode.FieldConfig(Clients){
        .serializer = Clients.serialize,
        .deserializer = Clients.deserialize,
    };
};
