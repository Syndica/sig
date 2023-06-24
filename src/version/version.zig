const varint_config = @import("../utils/varint.zig").varint_config;

pub const CURRENT_VERSION: Version = Version.new(0, 1, 0, 0, 0, 4);

pub const Version = struct {
    major: u16,
    minor: u16,
    patch: u16,
    commit: u32, // first 4 bytes of the sha1 commit hash
    feature_set: u32, // first 4 bytes of the FeatureSet identifier
    client: u16,

    const Self = @This();

    pub fn default() Self {
        return CURRENT_VERSION;
    }

    pub fn new(
        major: u16,
        minor: u16,
        patch: u16,
        commit: u32, // first 4 bytes of the sha1 commit hash
        feature_set: u32,
        client: u16,
    ) Self {
        return Self{
            .major = major,
            .minor = minor,
            .patch = patch,
            .commit = commit, // first 4 bytes of the sha1 commit hash
            .feature_set = feature_set,
            .client = client,
        };
    }

    pub const @"!bincode-config:major" = varint_config;
    pub const @"!bincode-config:minor" = varint_config;
    pub const @"!bincode-config:patch" = varint_config;
    pub const @"!bincode-config:client" = varint_config;
};
