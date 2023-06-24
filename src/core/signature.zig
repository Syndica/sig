const std = @import("std");
const Pubkey = @import("pubkey.zig").Pubkey;
const Ed25519 = std.crypto.sign.Ed25519;

pub const SIGNATURE_LENGTH: usize = 64;

pub const Signature = struct {
    data: [SIGNATURE_LENGTH]u8 = [_]u8{0} ** SIGNATURE_LENGTH,

    const Self = @This();

    pub fn init(bytes: [SIGNATURE_LENGTH]u8) Self {
        return Self{
            .data = bytes,
        };
    }

    pub fn verify(self: Self, pubkey: Pubkey, msg: []u8) !bool {
        const sig = Ed25519.Signature.fromBytes(self.data);
        sig.verify(msg, Ed25519.PublicKey.fromBytes(pubkey.data) catch unreachable) catch return false;
        return true;
    }

    pub fn eql(self: *const Self, other: *const Self) bool {
        return std.mem.eql(u8, self.data[0..], other.data[0..]);
    }
};
