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
    client: u16,

    pub const CURRENT: ClientVersion = .{
        .major = version.major,
        .minor = version.minor,
        .patch = version.patch,
        .commit = std.fmt.parseInt(u32, version.build orelse "0", 16) catch
            @compileError("failed to parse build"),
        .feature_set = 0,
        .client = 1,
    };

    pub const @"!bincode-config:major" = sig.bincode.VarIntConfig(u16);
    pub const @"!bincode-config:minor" = sig.bincode.VarIntConfig(u16);
    pub const @"!bincode-config:patch" = sig.bincode.VarIntConfig(u16);
    pub const @"!bincode-config:client" = sig.bincode.VarIntConfig(u16);
};
