const std = @import("std");
const sig = @import("../sig.zig");

const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;

const ZonInfo = struct {
    name: [:0]const u8,
    pubkey: [:0]const u8,
    activated_on_all_clusters: bool = false,
    reverted: bool = false,
};
pub const features: []const ZonInfo = @import("features.zon");
pub const NUM_FEATURES = features.len;

pub const Feature = @Type(.{ .@"enum" = .{
    .tag_type = u64,
    .fields = f: {
        var fields: []const std.builtin.Type.EnumField = &.{};
        for (features, 0..) |feature, i| {
            fields = fields ++ .{std.builtin.Type.EnumField{
                .name = feature.name,
                .value = i,
            }};
        }
        break :f fields;
    },
    .decls = &.{},
    .is_exhaustive = true,
} });

const Info = struct {
    key: Pubkey,
    activated_on_all_clusters: bool,
    reverted: bool,

    /// Returns the `id` of a feature, aka. the first 8 bytes of the public key.
    pub fn id(self: Info) u64 {
        return @bitCast(self.key.data[0..8].*);
    }
};

pub const map: std.EnumArray(Feature, Info) = map: {
    @setEvalBranchQuota(NUM_FEATURES * 1000);
    var s: std.enums.EnumFieldStruct(Feature, Info, null) = undefined;
    for (@typeInfo(Feature).@"enum".fields, features) |field, feature| {
        @field(s, field.name) = .{
            .key = .parse(feature.pubkey),
            .activated_on_all_clusters = feature.activated_on_all_clusters,
            .reverted = feature.reverted,
        };
    }
    break :map .init(s);
};

/// Represents the set of currently enabled feature flags.
///
/// [agave] https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/feature-set/src/lib.rs#L1188
pub const Set = struct {
    array: std.EnumArray(Feature, Slot),

    const TERMINATOR = std.math.maxInt(Slot);
    pub const ALL_DISABLED: Set = .{ .array = .initFill(TERMINATOR) };
    pub const ALL_ENABLED_AT_GENESIS: Set = .{ .array = .initFill(0) };

    /// Check whether `feature` is enabled at or before the provided slot. The `slot` cannot be
    /// `TERMINATOR`, since that's used to indicate a disabled slot.
    pub fn active(self: Set, feature: Feature, slot: Slot) bool {
        std.debug.assert(slot != TERMINATOR);
        return slot >= self.array.get(feature);
    }

    /// Updates the set to update the feature whos pubkey was provided. Possible input values for
    /// the slot look can be:
    ///
    /// - `0` to indicate that this feature is enabled for all slots.
    /// - an actual slot number to indicate that this feature is enabled/active after this slot
    /// - `maxInt(Slot)` to indicate that this feature is disabled in the set. `active` and
    /// `activeSlot` will now always return false for this feature.
    ///
    /// If the provided pubkey doesn't match with any of the known feature gates, `InvalidPubkey`
    /// is returned.
    pub fn setSlotPubkey(self: *Set, pubkey: Pubkey, slot: Slot) !void {
        for (&self.array.values, 0..) |*destination, i| {
            const feature: Feature = @enumFromInt(i);
            const info = map.get(feature);
            if (!info.pubkey.equals(&pubkey)) continue;
            destination.* = slot;
            return;
        }
        return error.InvalidPubkey;
    }

    /// Has identical behaviour to `setSlot`, however it works on the "id" of public keys, aka
    /// the first 8 bytes. Useful in the conformance harnesses where the features allowed to be
    /// enabled are provided as `u64`s instead of full public keys.
    pub fn setSlotId(self: *Set, id: u64, slot: Slot) !void {
        for (&self.array.values, 0..) |*destination, i| {
            const feature: Feature = @enumFromInt(i);
            const pubkey = map.get(feature).key;
            const feature_id: u64 = @bitCast(pubkey.data[0..8].*);
            if (feature_id == id) {
                destination.* = slot;
                return;
            }
        }
        return error.InvalidPubkey;
    }

    pub fn setSlot(self: *Set, feature: Feature, slot: Slot) void {
        self.array.set(feature, slot);
    }

    pub fn disable(self: *Set, feature: Feature) void {
        self.array.set(feature, TERMINATOR);
    }

    const FullInflationFeatures = struct {
        mainnet: bool,
        devnet_and_testnet: bool,

        pub fn enabled(self: FullInflationFeatures, set: Set, slot: Slot) bool {
            if (self.mainnet and set.active(.full_inflation_mainnet_enable, slot)) return true;
            if (self.devnet_and_testnet and
                set.active(.full_inflation_devnet_and_testnet, slot)) return true;
            return false;
        }
    };

    pub fn fullInflationFeatures(self: *const Set, slot: Slot) FullInflationFeatures {
        return .{
            .mainnet = self.active(.full_inflation_mainnet_vote, slot) and
                self.active(.full_inflation_mainnet_enable, slot),
            .devnet_and_testnet = self.active(.full_inflation_devnet_and_testnet, slot),
        };
    }

    pub fn iterator(set: *const Set, slot: Slot) Iterator {
        return .{
            .set = set,
            .slot = slot,
            .index = 0,
        };
    }

    const Iterator = struct {
        set: *const Set,
        slot: Slot,
        index: std.math.IntFittingRange(0, NUM_FEATURES),

        pub fn next(self: *Iterator) ?Feature {
            while (true) : (self.index += 1) {
                if (self.index == NUM_FEATURES - 1) return null;
                const feature: Feature = @enumFromInt(self.index);
                if (self.set.active(feature, self.slot)) {
                    self.index += 1;
                    return feature;
                }
            }
        }
    };
};

test "full inflation on mainnet" {
    var feature_set: Set = .ALL_DISABLED;
    {
        const inflation_features = feature_set.fullInflationFeatures(0);
        try std.testing.expect(!inflation_features.mainnet);
        try std.testing.expect(!inflation_features.devnet_and_testnet);
    }
    feature_set.setSlot(.full_inflation_mainnet_vote, 0);
    {
        const inflation_features = feature_set.fullInflationFeatures(0);
        try std.testing.expect(!inflation_features.mainnet);
        try std.testing.expect(!inflation_features.devnet_and_testnet);
    }
    feature_set.setSlot(.full_inflation_mainnet_enable, 0);
    {
        const inflation_features = feature_set.fullInflationFeatures(0);
        try std.testing.expect(inflation_features.mainnet);
        try std.testing.expect(!inflation_features.devnet_and_testnet);
    }

    feature_set = .ALL_DISABLED;
    {
        const inflation_features = feature_set.fullInflationFeatures(0);
        try std.testing.expect(!inflation_features.mainnet);
        try std.testing.expect(!inflation_features.devnet_and_testnet);
    }
    feature_set.setSlot(.full_inflation_mainnet_enable, 0);
    {
        const inflation_features = feature_set.fullInflationFeatures(0);
        try std.testing.expect(!inflation_features.mainnet);
        try std.testing.expect(!inflation_features.devnet_and_testnet);
    }
    feature_set.setSlot(.full_inflation_mainnet_vote, 0);
    {
        const inflation_features = feature_set.fullInflationFeatures(0);
        try std.testing.expect(inflation_features.mainnet);
        try std.testing.expect(!inflation_features.devnet_and_testnet);
    }
}

test "full inflation on devnet" {
    var feature_set: Set = .ALL_DISABLED;
    {
        const inflation_features = feature_set.fullInflationFeatures(0);
        try std.testing.expect(!inflation_features.mainnet);
        try std.testing.expect(!inflation_features.devnet_and_testnet);
    }
    feature_set.setSlot(.full_inflation_devnet_and_testnet, 0);
    {
        const inflation_features = feature_set.fullInflationFeatures(0);
        try std.testing.expect(!inflation_features.mainnet);
        try std.testing.expect(inflation_features.devnet_and_testnet);
    }
}
