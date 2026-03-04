//! Types for parsing config accounts for RPC responses using the `jsonParsed` encoding.
//! [agave]: https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_config.rs
const std = @import("std");
const sig = @import("../../sig.zig");

const account_codec = sig.rpc.account_codec;
const bincode = sig.bincode;
const ids = sig.runtime.ids;
const shortvec = bincode.shortvec;

const Allocator = std.mem.Allocator;
const ParseError = account_codec.ParseError;
const Pubkey = sig.core.Pubkey;
const RyuF64 = account_codec.RyuF64;

/// [agave]: https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/validator_info.rs#L7
const VALIDATOR_INFO_ID: Pubkey = .parse("Va1idator1nfo111111111111111111111111111111");

/// Parse a config account by its pubkey.
/// Returns null if the config type is unknown (not StakeConfig or ValidatorInfo).
/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_config.rs#L14-L33
pub fn parseConfig(
    allocator: Allocator,
    pubkey: Pubkey,
    reader: anytype,
    data_len: u32,
) ParseError!?ConfigAccountType {
    // Read all data into buffer for simpler offset calculations
    const data = try allocator.alloc(u8, data_len);
    defer allocator.free(data);
    reader.readNoEof(data) catch return ParseError.InvalidAccountData;
    if (pubkey.equals(&ids.STAKE_CONFIG_PROGRAM_ID)) {
        return parseStakeConfig(allocator, data);
    } else {
        return parseValidatorInfo(allocator, data);
    }
}

fn parseStakeConfig(allocator: Allocator, data: []const u8) ParseError!?ConfigAccountType {
    // First, deserialize ConfigKeys to find its serialized size
    const config_keys = bincode.readFromSlice(allocator, ConfigKeys, data, .{}) catch
        return ParseError.InvalidAccountData;
    defer allocator.free(config_keys.keys);
    // Calculate offset: ConfigKeys serialized size
    const keys_size = getConfigKeysSerializedSize(config_keys.keys.len);
    if (keys_size > data.len) return ParseError.InvalidAccountData;
    const config_data = data[keys_size..];
    // Deserialize StakeConfig
    const stake_config = bincode.readFromSlice(allocator, StakeConfig, config_data, .{}) catch
        return ParseError.InvalidAccountData;
    return ConfigAccountType{
        .stake_config = UiStakeConfig{
            .warmupCooldownRate = RyuF64.init(stake_config.warmup_cooldown_rate),
            .slashPenalty = stake_config.slash_penalty,
        },
    };
}

fn parseValidatorInfo(allocator: Allocator, data: []const u8) ParseError!?ConfigAccountType {
    // Deserialize ConfigKeys
    const config_keys = bincode.readFromSlice(allocator, ConfigKeys, data, .{}) catch
        return ParseError.InvalidAccountData;
    defer allocator.free(config_keys.keys);
    // Check if this is a ValidatorInfo config
    if (config_keys.keys.len == 0) return null;
    if (!config_keys.keys[0].pubkey.equals(&VALIDATOR_INFO_ID)) return null;
    // Calculate offset to skip ConfigKeys
    const keys_size = getConfigKeysSerializedSize(config_keys.keys.len);
    if (keys_size > data.len) return ParseError.InvalidAccountData;
    const config_data = data[keys_size..];
    // Deserialize ValidatorInfo (length-prefixed string)
    const validator_info = bincode.readFromSlice(allocator, ValidatorInfo, config_data, .{}) catch
        return ParseError.InvalidAccountData;
    defer allocator.free(validator_info.info);
    // Build UI keys array
    const ui_keys = try allocator.alloc(UiConfigKey, config_keys.keys.len);
    errdefer allocator.free(ui_keys);
    for (config_keys.keys, 0..) |key, i| {
        ui_keys[i] = UiConfigKey{
            .pubkey = key.pubkey,
            .signer = key.is_signer,
        };
    }
    // Copy the info string (we need to own it since we're freeing validator_info)
    const info_copy = try allocator.dupe(u8, validator_info.info);
    errdefer allocator.free(info_copy);
    return ConfigAccountType{
        .validator_info = UiConfig{
            .keys = ui_keys,
            .configData = info_copy,
        },
    };
}

/// Calculate the serialized size of ConfigKeys.
/// Format: short_vec length (1-3 bytes) + keys_count * (32 + 1) bytes
fn getConfigKeysSerializedSize(keys_count: usize) usize {
    const key_size = 32 + 1; // Pubkey (32) + bool (1)
    const len_u16: u16 = @intCast(keys_count);
    const short_vec_len = shortVecEncodedLen(len_u16);
    return short_vec_len + keys_count * key_size;
}

/// Calculate how many bytes a u16 takes when LEB128 encoded.
fn shortVecEncodedLen(value: u16) usize {
    if (value < 0x80) return 1;
    if (value < 0x4000) return 2;
    return 3;
}

/// A key entry in ConfigKeys: (Pubkey, is_signer)
/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/programs/config/src/lib.rs#L35
const ConfigKey = struct {
    pubkey: Pubkey,
    is_signer: bool,
};

/// The keys header for config accounts, uses short_vec encoding.
/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/programs/config/src/lib.rs#L38-L42
const ConfigKeys = struct {
    keys: []ConfigKey,
    pub const @"!bincode-config:keys" = shortvec.sliceConfig([]ConfigKey);
};

/// StakeConfig data stored after ConfigKeys.
/// [agave] https://github.com/anza-xyz/solana-sdk/blob/v1.18.0/program/src/stake/config.rs
const StakeConfig = struct {
    warmup_cooldown_rate: f64,
    slash_penalty: u8,
};

/// ValidatorInfo data stored after ConfigKeys.
/// The `info` field is a JSON string containing validator metadata.
/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/validator_info.rs#L17-L20
const ValidatorInfo = struct {
    info: []const u8,
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_config.rs#L59-L63
pub const UiStakeConfig = struct {
    warmupCooldownRate: RyuF64,
    slashPenalty: u8,
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_config.rs#L65-L70
pub const UiConfigKey = struct {
    pubkey: Pubkey,
    signer: bool,
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_config.rs#L77-L81
pub const UiConfig = struct {
    keys: []UiConfigKey,
    configData: []const u8, // Raw JSON string, written verbatim

    pub fn jsonStringify(self: UiConfig, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("keys");
        try jw.write(self.keys);
        try jw.objectField("configData");
        // Write raw JSON verbatim (no quotes, no escaping)
        try jw.beginWriteRaw();
        try jw.writer.writeAll(self.configData);
        jw.endWriteRaw();
        try jw.endObject();
    }
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_config.rs#L35-L38
pub const ConfigAccountType = union(enum) {
    stake_config: UiStakeConfig,
    validator_info: UiConfig,

    pub fn jsonStringify(self: ConfigAccountType, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("type");
        switch (self) {
            inline else => |v, tag| {
                try jw.write(typeNameFromTag(tag));
                try jw.objectField("info");
                try jw.write(v);
            },
        }
        try jw.endObject();
    }

    fn typeNameFromTag(comptime tag: std.meta.Tag(ConfigAccountType)) []const u8 {
        return switch (tag) {
            .stake_config => "stakeConfig",
            .validator_info => "validatorInfo",
        };
    }
};

// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_config.rs#L97
test "rpc.account_codec.parse_config: parse config accounts" {
    const allocator = std.testing.allocator;

    // Test StakeConfig
    {
        // Build ConfigKeys + StakeConfig data
        const keys = [_]ConfigKey{
            .{ .pubkey = ids.STAKE_CONFIG_PROGRAM_ID, .is_signer = false },
        };
        const config_keys = ConfigKeys{ .keys = @constCast(&keys) };
        const stake_config = StakeConfig{
            .warmup_cooldown_rate = 0.25,
            .slash_penalty = 12,
        };

        // Serialize: ConfigKeys + StakeConfig
        const keys_data = try bincode.writeAlloc(allocator, config_keys, .{});
        defer allocator.free(keys_data);

        const config_data = try bincode.writeAlloc(allocator, stake_config, .{});
        defer allocator.free(config_data);

        const full_data = try std.mem.concat(allocator, u8, &.{ keys_data, config_data });
        defer allocator.free(full_data);

        var stream = std.io.fixedBufferStream(full_data);
        const result = try parseConfig(
            allocator,
            ids.STAKE_CONFIG_PROGRAM_ID,
            stream.reader(),
            @intCast(full_data.len),
        );
        try std.testing.expect(result != null);
        try std.testing.expect(result.? == .stake_config);

        const ui_stake = result.?.stake_config;
        try std.testing.expectEqual(@as(f64, 0.25), ui_stake.warmupCooldownRate.value);
        try std.testing.expectEqual(@as(u8, 12), ui_stake.slashPenalty);
    }

    // Test ValidatorInfo
    {
        const validator_pubkey = Pubkey{ .data = [_]u8{1} ** 32 };
        const keys = [_]ConfigKey{
            .{ .pubkey = VALIDATOR_INFO_ID, .is_signer = false },
            .{ .pubkey = validator_pubkey, .is_signer = true },
        };
        const config_keys = ConfigKeys{ .keys = @constCast(&keys) };
        const info_json = "{\"name\":\"Test Validator\"}";
        const validator_info = ValidatorInfo{ .info = info_json };

        const keys_data = try bincode.writeAlloc(allocator, config_keys, .{});
        defer allocator.free(keys_data);

        const info_data = try bincode.writeAlloc(allocator, validator_info, .{});
        defer allocator.free(info_data);

        const full_data = try std.mem.concat(allocator, u8, &.{ keys_data, info_data });
        defer allocator.free(full_data);

        // Use a random pubkey (not StakeConfig) to trigger ValidatorInfo path
        const random_pubkey = Pubkey{ .data = [_]u8{0xAB} ** 32 };
        var stream = std.io.fixedBufferStream(full_data);
        const result = try parseConfig(
            allocator,
            random_pubkey,
            stream.reader(),
            @intCast(full_data.len),
        );
        try std.testing.expect(result != null);
        try std.testing.expect(result.? == .validator_info);

        const ui_config = result.?.validator_info;
        defer allocator.free(ui_config.keys);
        defer allocator.free(ui_config.configData);

        try std.testing.expectEqual(@as(usize, 2), ui_config.keys.len);
        try std.testing.expectEqual(VALIDATOR_INFO_ID, ui_config.keys[0].pubkey);
        try std.testing.expectEqual(false, ui_config.keys[0].signer);
        try std.testing.expectEqual(true, ui_config.keys[1].signer);
        try std.testing.expectEqualStrings(info_json, ui_config.configData);
    }

    // Test unknown config type (first key is not ValidatorInfo ID)
    {
        const random_key = Pubkey{ .data = [_]u8{0xFF} ** 32 };
        const keys = [_]ConfigKey{
            .{ .pubkey = random_key, .is_signer = false },
        };
        const config_keys = ConfigKeys{ .keys = @constCast(&keys) };
        const keys_data = try bincode.writeAlloc(allocator, config_keys, .{});
        defer allocator.free(keys_data);

        const random_pubkey = Pubkey{ .data = [_]u8{0xAB} ** 32 };
        var stream = std.io.fixedBufferStream(keys_data);
        const result = try parseConfig(
            allocator,
            random_pubkey,
            stream.reader(),
            @intCast(keys_data.len),
        );
        try std.testing.expect(result == null);
    }

    // Test invalid data
    {
        const bad_data = [_]u8{ 0xFF, 0xFF, 0xFF, 0xFF };
        var stream = std.io.fixedBufferStream(&bad_data);
        const result = parseConfig(
            allocator,
            ids.STAKE_CONFIG_PROGRAM_ID,
            stream.reader(),
            bad_data.len,
        );

        try std.testing.expectError(ParseError.InvalidAccountData, result);
    }
}
