const std = @import("std");
const sig = @import("../sig.zig");
const build_options = @import("build-options");

const version = build_options.version;

const feature_set = sig.core.features.FEATURE_SET_ID;

pub const ClientVersion = struct {
    major: u16,
    minor: u16,
    patch: u16,
    commit: u32, // first 4 bytes of the sha1 commit hash
    feature_set: u32, // first 4 bytes of the FeatureSet identifier
    client: ClientId,
    prerelease: PreRelease,

    pub const CURRENT: ClientVersion = .{
        .major = version.major,
        .minor = version.minor,
        .patch = version.patch,
        .commit = std.fmt.parseInt(u32, version.build orelse "0", 16) catch
            @compileError("failed to parse build"),
        .feature_set = feature_set,
        .client = .sig,
        .prerelease = PreRelease.fromSemanticVersionPre(version.pre),
    };

    /// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/version/src/lib.rs#L83
    pub const API_VERSION = std.fmt.comptimePrint(
        "{}.{}.{}",
        .{
            CURRENT.major,
            CURRENT.minor,
            CURRENT.patch,
        },
    );

    /// Keep up to date with: https://github.com/solana-foundation/solana-validator-client-ids/blob/main/client-ids.csv
    /// Currently based on: https://github.com/solana-foundation/solana-validator-client-ids/blob/0fff9f8e016972ff55680d011a4f81922c452f72/client-ids.csv
    const ClientId = enum(u16) {
        solana_labs = 0,
        jito_labs = 1,
        frankendancer = 2,
        agave = 3,
        agave_paladin = 4,
        firedancer = 5,
        agave_bam = 6,
        sig = 7,
        _,

        pub fn serialize(writer: anytype, data: anytype, _: sig.bincode.Params) !void {
            try std.leb.writeUleb128(writer, @intFromEnum(data));
        }

        pub fn deserialize(
            _: *sig.bincode.LimitAllocator,
            reader: anytype,
            _: sig.bincode.Params,
        ) !ClientId {
            return @enumFromInt(try std.leb.readUleb128(u16, reader));
        }
    };

    pub const PreRelease = union(enum) {
        stable,
        release_candidate: u16,
        beta: u16,
        alpha: u16,

        pub fn patchIsValid(self: PreRelease, patch: u16) bool {
            return switch (self) {
                .stable => true,
                .release_candidate, .beta, .alpha => patch == 0,
            };
        }

        pub fn fromSemanticVersionPre(comptime maybe_pre: ?[]const u8) PreRelease {
            const pre = maybe_pre orelse return .stable;
            if (pre.len == 0) return .stable;

            var parts = std.mem.splitScalar(u8, pre, '.');
            const identifier = parts.first();
            const numeric_part = parts.next() orelse return .stable;
            if (parts.next() != null) return .stable;

            const number = std.fmt.parseInt(u16, numeric_part, 10) catch return .stable;

            if (std.mem.eql(u8, identifier, "rc")) return .{ .release_candidate = number };
            if (std.mem.eql(u8, identifier, "beta")) return .{ .beta = number };
            if (std.mem.eql(u8, identifier, "alpha")) return .{ .alpha = number };
            return .stable;
        }

        pub fn format(self: PreRelease, writer: *std.Io.Writer) !void {
            switch (self) {
                .stable => {},
                .release_candidate => |rc| try writer.print("rc.{d}", .{rc}),
                .beta => |beta| try writer.print("beta.{d}", .{beta}),
                .alpha => |alpha| try writer.print("alpha.{d}", .{alpha}),
            }
        }
    };

    const PRERELEASE_BITS_OFFSET: u4 = 14;
    const PRERELEASE_MASK_BITS: u4 = 2;
    const PRERELEASE_FIRST_UNMASKED_BIT: u16 = 1 << PRERELEASE_MASK_BITS;
    const PRERELEASE_MASK: u16 = PRERELEASE_FIRST_UNMASKED_BIT - 1;
    const PRERELEASE_MINOR_MAX: u16 = (1 << PRERELEASE_BITS_OFFSET) - 1;

    const PackedMinorAndPatch = struct {
        minor: u16,
        patch: u16,
        prerelease: PreRelease,
    };

    const PackedMinorError = error{
        MinorTooLarge,
        InvalidPatchForPrerelease,
        ReservedBitsSet,
    };

    fn packMinorAndPatch(minor: u16, patch: u16, prerelease: PreRelease) PackedMinorError!struct {
        packed_minor: u16,
        packed_patch: u16,
    } {
        if (minor > PRERELEASE_MINOR_MAX) {
            return error.MinorTooLarge;
        }
        if (!prerelease.patchIsValid(patch)) {
            return error.InvalidPatchForPrerelease;
        }

        const prerelease_tag: u16, const packed_patch: u16 = switch (prerelease) {
            .stable => .{ 0, patch },
            .release_candidate => |rc| .{ 1, rc },
            .beta => |beta| .{ 2, beta },
            .alpha => |alpha| .{ 3, alpha },
        };

        const packed_minor = minor | (prerelease_tag << PRERELEASE_BITS_OFFSET);
        return .{
            .packed_minor = packed_minor,
            .packed_patch = packed_patch,
        };
    }

    fn unpackMinorAndPatch(
        packed_minor: u16,
        packed_patch: u16,
    ) PackedMinorError!PackedMinorAndPatch {
        const shifted_prerelease_bits = packed_minor >> PRERELEASE_BITS_OFFSET;
        const reserved_bits = shifted_prerelease_bits & ~PRERELEASE_MASK;
        if (reserved_bits != 0) {
            return error.ReservedBitsSet;
        }

        const prerelease_variant = shifted_prerelease_bits & PRERELEASE_MASK;
        const minor = packed_minor & ~(PRERELEASE_MASK << PRERELEASE_BITS_OFFSET);

        const patch: u16, const prerelease: PreRelease = switch (prerelease_variant) {
            0 => .{ packed_patch, .stable },
            1 => .{ 0, .{ .release_candidate = packed_patch } },
            2 => .{ 0, .{ .beta = packed_patch } },
            3 => .{ 0, .{ .alpha = packed_patch } },
            else => unreachable,
        };

        return .{
            .minor = minor,
            .patch = patch,
            .prerelease = prerelease,
        };
    }

    pub fn serialize(writer: anytype, data: anytype, params: sig.bincode.Params) !void {
        const packed_values = try packMinorAndPatch(data.minor, data.patch, data.prerelease);
        try std.leb.writeUleb128(writer, data.major);
        try std.leb.writeUleb128(writer, packed_values.packed_minor);
        try std.leb.writeUleb128(writer, packed_values.packed_patch);
        try sig.bincode.write(writer, data.commit, params);
        try sig.bincode.write(writer, data.feature_set, params);
        try ClientId.serialize(writer, data.client, params);
    }

    pub fn deserialize(
        limit_allocator: *sig.bincode.LimitAllocator,
        reader: anytype,
        params: sig.bincode.Params,
    ) !ClientVersion {
        const major = try std.leb.readUleb128(u16, reader);
        const packed_minor = try std.leb.readUleb128(u16, reader);
        const packed_patch = try std.leb.readUleb128(u16, reader);
        const commit = try sig.bincode.readWithLimit(limit_allocator, u32, reader, params);
        const feature_set_value = try sig.bincode.readWithLimit(
            limit_allocator,
            u32,
            reader,
            params,
        );
        const client = try ClientId.deserialize(limit_allocator, reader, params);

        const unpacked = try unpackMinorAndPatch(packed_minor, packed_patch);
        return .{
            .major = major,
            .minor = unpacked.minor,
            .patch = unpacked.patch,
            .commit = commit,
            .feature_set = feature_set_value,
            .client = client,
            .prerelease = unpacked.prerelease,
        };
    }

    pub const @"!bincode-config" = sig.bincode.FieldConfig(ClientVersion){
        .serializer = serialize,
        .deserializer = deserialize,
    };

    pub fn format(self: ClientVersion, writer: *std.Io.Writer) !void {
        const sep = if (self.prerelease == .stable) "" else "-";
        try writer.print("{}.{}.{}{s}{f}", .{
            self.major,
            self.minor,
            self.patch,
            sep,
            self.prerelease,
        });
    }
};

test "ClientVersion.PreRelease parses semantic version pre-release" {
    try std.testing.expectEqual(
        ClientVersion.PreRelease.stable,
        comptime ClientVersion.PreRelease.fromSemanticVersionPre(null),
    );
    try std.testing.expectEqual(
        ClientVersion.PreRelease.stable,
        comptime ClientVersion.PreRelease.fromSemanticVersionPre(""),
    );
    try std.testing.expectEqual(
        ClientVersion.PreRelease{ .release_candidate = 7 },
        comptime ClientVersion.PreRelease.fromSemanticVersionPre("rc.7"),
    );
    try std.testing.expectEqual(
        ClientVersion.PreRelease{ .beta = 2 },
        comptime ClientVersion.PreRelease.fromSemanticVersionPre("beta.2"),
    );
    try std.testing.expectEqual(
        ClientVersion.PreRelease{ .alpha = 42 },
        comptime ClientVersion.PreRelease.fromSemanticVersionPre("alpha.42"),
    );
    try std.testing.expectEqual(
        ClientVersion.PreRelease.stable,
        comptime ClientVersion.PreRelease.fromSemanticVersionPre("dev.10"),
    );
}

test "ClientVersion bincode roundtrip for stable and prerelease" {
    const stable: ClientVersion = .{
        .major = 1,
        .minor = 2,
        .patch = 3,
        .commit = 0x01020304,
        .feature_set = 0xAABBCCDD,
        .client = .sig,
        .prerelease = .stable,
    };

    const rc: ClientVersion = .{
        .major = 1,
        .minor = 2,
        .patch = 0,
        .commit = 0x01020304,
        .feature_set = 0xAABBCCDD,
        .client = .sig,
        .prerelease = .{ .release_candidate = 3 },
    };

    var stable_buf: [64]u8 = undefined;
    const stable_written = try sig.bincode.writeToSlice(stable_buf[0..], stable, .{});
    const decoded_stable = try sig.bincode.readFromSlice(
        std.testing.allocator,
        ClientVersion,
        stable_written,
        .{},
    );
    try std.testing.expectEqualDeep(stable, decoded_stable);

    var rc_buf: [64]u8 = undefined;
    const rc_written = try sig.bincode.writeToSlice(rc_buf[0..], rc, .{});
    const decoded_rc = try sig.bincode.readFromSlice(
        std.testing.allocator,
        ClientVersion,
        rc_written,
        .{},
    );
    try std.testing.expectEqualDeep(rc, decoded_rc);
}

test "ClientVersion rejects invalid patch for prerelease" {
    const invalid: ClientVersion = .{
        .major = 1,
        .minor = 2,
        .patch = 5,
        .commit = 0,
        .feature_set = 0,
        .client = .sig,
        .prerelease = .{ .beta = 1 },
    };

    var buf: [64]u8 = undefined;
    try std.testing.expectError(
        error.InvalidPatchForPrerelease,
        sig.bincode.writeToSlice(buf[0..], invalid, .{}),
    );
}
