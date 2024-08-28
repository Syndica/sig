const std = @import("std");
const sig = @import("../sig.zig");
const core = @import("lib.zig");

const Ed25519 = std.crypto.sign.Ed25519;
const Verifier = std.crypto.sign.Ed25519.Verifier;
const e = std.crypto.errors;

const Pubkey = core.Pubkey;

pub const Signature = struct {
    data: [size]u8 = [_]u8{0} ** size,

    pub const size: usize = 64;

    const base58 = sig.crypto.base58.Base58Sized(size);
    const Self = @This();

    pub fn default() Self {
        return .{ .data = [_]u8{0} ** size };
    }

    pub fn init(bytes: [size]u8) Self {
        return .{ .data = bytes };
    }

    pub fn fromString(str: []const u8) !Self {
        return .{ .data = try base58.decode(str) };
    }

    pub fn verify(self: Self, pubkey: Pubkey, msg: []const u8) bool {
        const signature = Ed25519.Signature.fromBytes(self.data);
        signature.verify(msg, Ed25519.PublicKey.fromBytes(pubkey.data) catch unreachable) catch
            return false;
        return true;
    }

    pub fn verifier(
        self: Self,
        pubkey: Pubkey,
    ) (e.NonCanonicalError || e.EncodingError || e.IdentityElementError)!Verifier {
        const signature = Ed25519.Signature.fromBytes(self.data);
        return signature.verifier(Ed25519.PublicKey.fromBytes(pubkey.data) catch unreachable);
    }

    pub fn eql(self: *const Self, other: *const Self) bool {
        return std.mem.eql(u8, self.data[0..], other.data[0..]);
    }

    pub fn base58String(self: Signature) std.BoundedArray(u8, 88) {
        return base58.encode(self.data);
    }

    pub fn format(
        self: Signature,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        return base58.format(self.data, writer);
    }

    // METHODS TO BE REFACTORED

    const base58Zig = @import("base58-zig");
    const BASE58_ENCODER = base58Zig.Encoder.init(.{});
    const BASE58_DECODER = base58Zig.Decoder.init(.{});
    pub const BYTES_LENGTH: usize = 64;
    pub const BASE58_MAX_LENGTH: usize = 88;

    pub fn toStringAlloc(self: *const Self, allocator: std.mem.Allocator) ![]u8 {
        var dest: [BASE58_MAX_LENGTH]u8 = undefined;
        @memset(&dest, 0);
        const written = BASE58_ENCODER.encode(&self.data, &dest) catch return error.EncodingError;
        if (written > BASE58_MAX_LENGTH) {
            std.debug.panic("written is > {}, written: {}, dest: {any}, bytes: {any}", .{ BASE58_MAX_LENGTH, written, dest, self.data });
        }
        return try allocator.dupe(u8, dest[0..written]);
    }

    pub fn toString(self: *const Self) error{EncodingError}![BASE58_MAX_LENGTH]u8 {
        var dest: [BASE58_MAX_LENGTH]u8 = undefined;
        @memset(&dest, 0);
        const written = BASE58_ENCODER.encode(&self.data, &dest) catch return error.EncodingError;
        if (written > BASE58_MAX_LENGTH) {
            std.debug.panic("written is > {}, written: {}, dest: {any}, bytes: {any}", .{ BASE58_MAX_LENGTH, written, dest, self.data });
        }
        return dest;
    }
};
