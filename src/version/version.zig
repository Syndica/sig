const var_int_config_u16 = @import("../utils/varint.zig").var_int_config_u16;

pub const CURRENT_CLIENT_VERSION: ClientVersion = ClientVersion.new(0, 1, 0, 0, 0, 4);

pub const ClientVersion = struct {
    major: u16,
    minor: u16,
    patch: u16,
    commit: u32, // first 4 bytes of the sha1 commit hash
    feature_set: u32, // first 4 bytes of the FeatureSet identifier
    client: u16,

    const Self = @This();

    pub fn default() Self {
        return CURRENT_CLIENT_VERSION;
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

    pub const @"!bincode-config:major" = var_int_config_u16;
    pub const @"!bincode-config:minor" = var_int_config_u16;
    pub const @"!bincode-config:patch" = var_int_config_u16;
    pub const @"!bincode-config:client" = var_int_config_u16;
};
