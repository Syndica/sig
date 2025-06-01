//! Provides utilities for Merlin transcripts, message framing, etc.
//!
//! https://merlin.cool/use/protocol.html

const std = @import("std");
const sig = @import("../sig.zig");
const Keccak1600 = std.crypto.core.keccak.KeccakF(1600);
const Ed25519 = std.crypto.ecc.Edwards25519;
const Scalar = Ed25519.scalar.Scalar;
const Ristretto255 = std.crypto.ecc.Ristretto255;

pub const Strobe128 = struct {
    state: Keccak1600,
    position: u8,
    begin: u8,
    flags: Flags,

    pub const Flags = packed struct(u8) {
        I: bool = false,
        A: bool = false,
        C: bool = false,
        T: bool = false,
        M: bool = false,
        K: bool = false,
        _padding: u2 = 0,
    };

    /// Hardcodes security level 128.
    pub const R = 166;

    pub fn init(label: []const u8) Strobe128 {
        const initial_state = state: {
            var state: [200]u8 = .{0} ** 200;
            state[0..6].* = .{ 1, R + 2, 1, 0, 1, 96 };
            state[6..18].* = "STROBEv1.0.2".*;

            var k = Keccak1600.init(state);
            k.permute();

            break :state k;
        };

        var strobe: Strobe128 = .{
            .state = initial_state,
            .position = 0,
            .begin = 0,
            .flags = .{},
        };
        strobe.metaAd(label, false);

        return strobe;
    }

    pub fn beginOp(self: *Strobe128, flags: Flags, more: bool) void {
        // Check if we're continuing a previous operation.
        if (more) {
            // TODO(0.14) Switch to compare the packed structs instead of bitcasting.
            std.debug.assert(@as(u8, @bitCast(self.flags)) == @as(u8, @bitCast(flags)));
            return;
        }

        // Skip adjusting direction information.
        std.debug.assert(!flags.T);

        const old_begin = self.begin;
        self.begin = self.position + 1;
        self.flags = flags;

        self.absorb(&.{ old_begin, @bitCast(flags) });

        // Force permute if C or K are set.
        const force_f = flags.C or flags.K;
        if (force_f and self.position != 0) {
            self.permuteState();
        }
    }

    fn permuteState(self: *Strobe128) void {
        const state: *[200]u8 = @ptrCast(&self.state.st);
        state[self.position] ^= self.begin;
        state[self.position + 1] ^= 0x04;
        state[R + 1] ^= 0x80;

        self.state.permute();
        self.position = 0;
        self.begin = 0;
    }

    fn absorb(self: *Strobe128, data: []const u8) void {
        const state: *[200]u8 = @ptrCast(&self.state.st);
        for (data) |byte| {
            state[self.position] ^= byte;
            self.position += 1;
            if (self.position == R) {
                self.permuteState();
            }
        }
    }

    fn squeeze(self: *Strobe128, destination: []u8) void {
        const state: *[200]u8 = @ptrCast(&self.state.st);
        for (destination) |*byte| {
            byte.* = state[self.position];
            state[self.position] = 0;
            self.position += 1;
            if (self.position == R) {
                self.permuteState();
            }
        }
    }

    fn overwrite(self: *Strobe128, destination: []const u8) void {
        const state: *[200]u8 = @ptrCast(&self.state.st);
        for (destination) |byte| {
            state[self.position] = byte;
            self.position += 1;
            if (self.position == R) {
                self.permuteState();
            }
        }
    }

    pub fn metaAd(self: *Strobe128, data: []const u8, more: bool) void {
        self.beginOp(.{ .M = true, .A = true }, more);
        self.absorb(data);
    }

    pub fn ad(self: *Strobe128, data: []const u8, more: bool) void {
        self.beginOp(.{ .A = true }, more);
        self.absorb(data);
    }

    pub fn prf(self: *Strobe128, destination: []u8, more: bool) void {
        self.beginOp(.{ .I = true, .A = true, .C = true }, more);
        self.squeeze(destination);
    }

    pub fn key(self: *Strobe128, destination: []u8, more: bool) void {
        self.beginOp(.{ .A = true, .C = true }, more);
        self.overwrite(destination);
    }

    test "conformance" {
        var s1 = Strobe128.init("Conformance Test Protocol");
        const msg: [1024]u8 = .{99} ** 1024;

        s1.metaAd("ms", false);
        s1.metaAd("g", true);
        s1.ad(&msg, false);

        var prf1: [32]u8 = .{0} ** 32;
        s1.metaAd("prf", false);
        s1.prf(&prf1, false);

        try std.testing.expectEqualSlices(
            u8,
            &.{
                0xb4, 0x8e, 0x64, 0x5c, 0xa1, 0x7c, 0x66, 0x7f,
                0xd5, 0x20, 0x6b, 0xa5, 0x7a, 0x6a, 0x22, 0x8d,
                0x72, 0xd8, 0xe1, 0x90, 0x38, 0x14, 0xd3, 0xf1,
                0x7f, 0x62, 0x29, 0x96, 0xd7, 0xcf, 0xef, 0xb0,
            },
            &prf1,
        );

        s1.metaAd("key", false);
        s1.key(&prf1, false);

        @memset(&prf1, 0);

        s1.metaAd("prf", false);
        s1.prf(&prf1, false);

        try std.testing.expectEqualSlices(
            u8,
            &.{
                0x7,  0xe4, 0x5c, 0xce, 0x80, 0x78, 0xce, 0xe2,
                0x59, 0xe3, 0xe3, 0x75, 0xbb, 0x85, 0xd7, 0x56,
                0x10, 0xe2, 0xd1, 0xe1, 0x20, 0x1c, 0x5f, 0x64,
                0x50, 0x45, 0xa1, 0x94, 0xed, 0xd4, 0x9f, 0xf8,
            },
            &prf1,
        );
    }
};

pub const Transcript = struct {
    strobe: Strobe128,

    pub fn init(comptime label: []const u8) Transcript {
        var transcript: Transcript = .{
            .strobe = Strobe128.init("Merlin v1.0"),
        };
        transcript.appendMessage("dom-sep", label);

        return transcript;
    }

    /// NOTE: be very careful with this function, there are only a specific few
    /// usages of it. generally speaking, use the a helper function if it exists.
    pub fn appendMessage(
        t: *Transcript,
        comptime label: []const u8,
        message: []const u8,
    ) void {
        var data_len: [4]u8 = undefined;
        std.mem.writeInt(u32, &data_len, @intCast(message.len), .little);
        t.strobe.metaAd(label, false);
        t.strobe.metaAd(&data_len, true);
        t.strobe.ad(message, false);
    }

    pub fn appendDomSep(t: *Transcript, comptime label: []const u8) void {
        t.appendMessage("dom-sep", label);
    }

    pub fn challengeBytes(
        t: *Transcript,
        comptime label: []const u8,
        destination: []u8,
    ) void {
        var data_len: [4]u8 = undefined;
        std.mem.writeInt(u32, &data_len, @intCast(destination.len), .little);

        t.strobe.metaAd(label, false);
        t.strobe.metaAd(&data_len, true);
        t.strobe.prf(destination, false);
    }

    pub fn challengeScalar(
        t: *Transcript,
        comptime label: []const u8,
    ) Scalar {
        var buffer: [64]u8 = .{0} ** 64;
        t.challengeBytes(label, &buffer);
        // Specifically need reduce64 instead of Scalar.fromBytes64, since
        // we need the Barret reduction to be done with 10 limbs, not 5.
        const compressed = Ed25519.scalar.reduce64(buffer);
        return Scalar.fromBytes(compressed);
    }

    pub fn validateAndAppendPoint(
        t: *Transcript,
        comptime label: []const u8,
        point: Ristretto255,
    ) !void {
        try point.rejectIdentity();
        t.appendPoint(label, point);
    }

    // helper functions

    pub fn appendPoint(t: *Transcript, comptime label: []const u8, point: Ristretto255) void {
        t.appendMessage(label, &point.toBytes());
    }

    pub fn appendScalar(t: *Transcript, comptime label: []const u8, scalar: Scalar) void {
        t.appendMessage(label, &scalar.toBytes());
    }

    pub fn appendPubkey(
        t: *Transcript,
        comptime label: []const u8,
        pubkey: sig.zksdk.ElGamalPubkey,
    ) void {
        t.appendPoint(label, pubkey.point);
    }

    pub fn appendCiphertext(
        t: *Transcript,
        comptime label: []const u8,
        ciphertext: sig.zksdk.ElGamalCiphertext,
    ) void {
        var buffer: [64]u8 = .{0} ** 64;
        @memcpy(buffer[0..32], &ciphertext.commitment.point.toBytes());
        @memcpy(buffer[32..64], &ciphertext.handle.point.toBytes());
        t.appendMessage(label, &buffer);
    }

    pub fn appendCommitment(
        t: *Transcript,
        comptime label: []const u8,
        commitment: sig.zksdk.pedersen.Commitment,
    ) void {
        t.appendMessage(label, &commitment.point.toBytes());
    }

    pub fn appendU64(t: *Transcript, comptime label: []const u8, x: u64) void {
        var buffer: [8]u8 = .{0} ** 8;
        std.mem.writeInt(u64, &buffer, x, .little);
        t.appendMessage(label, &buffer);
    }
};

test "equivalence" {
    var transcript = Transcript.init("test protocol");

    transcript.appendMessage("some label", "some data");

    var bytes: [32]u8 = undefined;
    transcript.challengeBytes("challenge", &bytes);

    try std.testing.expectEqualSlices(u8, &.{
        0xd5, 0xa2, 0x19, 0x72, 0xd0, 0xd5, 0xfe, 0x32,
        0xc,  0xd,  0x26, 0x3f, 0xac, 0x7f, 0xff, 0xb8,
        0x14, 0x5a, 0xa6, 0x40, 0xaf, 0x6e, 0x9b, 0xca,
        0x17, 0x7c, 0x3,  0xc7, 0xef, 0xcf, 0x6,  0x15,
    }, &bytes);
}
