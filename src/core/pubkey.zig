const std = @import("std");
const base58 = @import("base58-zig");
const bincode = @import("../bincode/bincode.zig");
const Ed25519 = std.crypto.sign.Ed25519;
const encoder = base58.Encoder.init(.{});
const decoder = base58.Decoder.init(.{});

pub const Pubkey = struct {
    data: [32]u8,
    cached_str: ?[44]u8 = null,

    const Self = @This();

    /// ***fromString*** takea a base58 encoded string and decodes the value. It also caches
    /// the `str` for future calls to string() method.
    /// If `bytes`, it wil automatically encode so that it's able to call string() method.
    ///
    pub fn fromString(str: []const u8) !Self {
        if (str.len != 44) {
            return Error.InvalidEncodedLength;
        }
        var out: [32]u8 = .{
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        };
        var written = decoder.decode(str, &out) catch return Error.InvalidEncodedValue;
        if (written != 32) {
            @panic("written is not 32");
        }
        return Self{ .data = out, .cached_str = str[0..44].* };
    }

    /// ***fromBytes*** will automatically base58 decode the value. It will also cache the decoded string
    /// for future calls to string() method.
    ///
    /// Options:
    /// - `skip_encoding`: If (in the unlikely scenario) you will never call the string() method, you can
    /// set this option to true and it will not decode & cache the encoded value. This can be helpful in
    /// scenarios where you plan to only use the bytes and want to save on expensive base58 encoding.
    ///
    pub fn fromBytes(bytes: []const u8, opts: struct { skip_encoding: bool = false }) !Self {
        if (bytes.len != 32) {
            return Error.InvalidBytesLength;
        }
        if (opts.skip_encoding) {
            return Self{ .data = bytes[0..32].*, .cached_str = null };
        }
        var dest: [44]u8 = .{
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        };

        var written = encoder.encode(bytes, &dest) catch @panic("could not encode pubkey");
        if (written != 44) {
            @panic("written is not 44");
        }
        return Self{ .data = bytes[0..32].*, .cached_str = dest[0..44].* };
    }

    pub fn string(self: *const Self) []const u8 {
        if (self.cached_str) |_| {
            return &self.cached_str.?[0..].*;
        }
        @panic("call to Pubkey.string() after opt `skip_encoding` asserted");
    }

    /// ***random*** generates a random pubkey. Optionally set `skip_encoding` to skip expensive base58 encoding.
    pub fn random(options: struct { skip_encoding: bool = false, seed: ?u64 = null }) Self {
        var bytes: [32]u8 = undefined;
        var seed = options.seed orelse @as(u64, @intCast(std.time.milliTimestamp()));
        var rand = std.rand.DefaultPrng.init(seed);
        rand.fill(&bytes);
        var dest: [44]u8 = .{
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        };
        if (options.skip_encoding) {
            return Self{ .data = bytes[0..32].*, .cached_str = null };
        }
        var written = encoder.encode(&bytes, &dest) catch @panic("could not encode pubkey");
        if (written > 44) {
            std.debug.panic("written is > 44, written: {}, dest: {any}, bytes: {any}", .{ written, dest, bytes });
        }
        return Self{ .data = bytes[0..32].*, .cached_str = dest[0..44].* };
    }

    pub fn equals(self: *const Self, other: *Pubkey) bool {
        return std.mem.eql(u8, &self.data, &other.data);
    }

    pub fn fromPublicKey(public_key: *const Ed25519.PublicKey, skip_bs58_encoding: bool) Self {
        return Self.fromBytes(public_key.bytes[0..], .{ .skip_encoding = skip_bs58_encoding }) catch unreachable;
    }

    pub const @"!bincode-config:cached_str" = bincode.FieldConfig{ .skip = true };

    pub const @"getty.sb" = struct {
        pub const attributes = .{
            .cached_str = .{ .skip = true },
        };
    };
};

const Error = error{ InvalidBytesLength, InvalidEncodedLength, InvalidEncodedValue };
