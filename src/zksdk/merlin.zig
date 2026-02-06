//! Provides utilities for Merlin transcripts, message framing, etc.
//!
//! https://merlin.cool/use/protocol.html

const std = @import("std");
const builtin = @import("builtin");
const sig = @import("../sig.zig");

const zksdk = sig.zksdk;

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
            std.debug.assert(self.flags == flags);
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

    const DomainSeperator = enum {
        @"zero-ciphertext-instruction",
        @"zero-ciphertext-proof",
        @"pubkey-validity-instruction",
        @"pubkey-proof",
        @"percentage-with-cap-proof",
        @"percentage-with-cap-instruction",
        @"ciphertext-commitment-equality-proof",
        @"ciphertext-commitment-equality-instruction",
        @"ciphertext-ciphertext-equality-proof",
        @"ciphertext-ciphertext-equality-instruction",

        @"inner-product",
        @"range-proof",
        @"batched-range-proof-instruction",

        @"validity-proof",
        @"batched-validity-proof",

        @"grouped-ciphertext-validity-2-handles-instruction",
        @"batched-grouped-ciphertext-validity-2-handles-instruction",

        @"grouped-ciphertext-validity-3-handles-instruction",
        @"batched-grouped-ciphertext-validity-3-handles-instruction",
    };

    const TranscriptInput = struct {
        label: []const u8,
        message: Message,
    };

    const Message = union(enum) {
        bytes: []const u8,

        point: Ristretto255,
        pubkey: zksdk.elgamal.Pubkey,
        scalar: Scalar,
        ciphertext: zksdk.elgamal.Ciphertext,
        commitment: zksdk.pedersen.Commitment,
        u64: u64,
        domsep: DomainSeperator,

        grouped_2: zksdk.elgamal.GroupedElGamalCiphertext(2),
        grouped_3: zksdk.elgamal.GroupedElGamalCiphertext(3),
    };

    /// [agave] https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/lib.rs#L36
    const TRANSCRIPT_DOMAIN = "solana-zk-elgamal-proof-program-v1";

    pub fn init(comptime seperator: DomainSeperator) Transcript {
        var transcript: Transcript = .{ .strobe = Strobe128.init("Merlin v1.0") };
        transcript.appendBytes("dom-sep", TRANSCRIPT_DOMAIN);
        transcript.appendBytes("dom-sep", @tagName(seperator));
        return transcript;
    }

    pub fn initTest(label: []const u8) Transcript {
        comptime if (!builtin.is_test) @compileError("should only be used during tests");
        var transcript: Transcript = .{ .strobe = Strobe128.init("Merlin v1.0") };
        transcript.appendBytes("dom-sep", TRANSCRIPT_DOMAIN);
        transcript.appendBytes("dom-sep", label);
        return transcript;
    }

    fn appendBytes(self: *Transcript, label: []const u8, bytes: []const u8) void {
        var data_len: [4]u8 = undefined;
        std.mem.writeInt(u32, &data_len, @intCast(bytes.len), .little);
        self.strobe.metaAd(label, false);
        self.strobe.metaAd(&data_len, true);
        self.strobe.ad(bytes, false);
    }

    fn appendMessage(self: *Transcript, label: []const u8, message: Message) void {
        var buffer: [64]u8 = @splat(0);
        const bytes: []const u8 = switch (message) {
            .bytes => |b| b,
            .point => |*point| &point.toBytes(),
            .pubkey => |*pubkey| &pubkey.toBytes(),
            .scalar => |*scalar| &scalar.toBytes(),
            .domsep => |t| @tagName(t),
            .ciphertext => |*ct| b: {
                @memcpy(buffer[0..32], &ct.commitment.point.toBytes());
                @memcpy(buffer[32..64], &ct.handle.point.toBytes());
                break :b &buffer;
            },
            .commitment => |*c| &c.toBytes(),
            .u64 => |x| b: {
                std.mem.writeInt(u64, buffer[0..8], x, .little);
                break :b buffer[0..8];
            },
            inline .grouped_2, .grouped_3 => |*g| &g.toBytes(),
        };
        self.appendBytes(label, bytes);
    }

    pub inline fn append(
        self: *Transcript,
        comptime session: *Session,
        comptime t: Input.Type,
        comptime label: []const u8,
        data: @FieldType(Message, @tagName(t.base())),
    ) if (t.validates()) error{IdentityElement}!void else void {
        // If validate_point fails to validate, we no longer want to check the contract
        // because the function calling append will now return early.
        errdefer session.cancel();

        if (t == .bytes and !builtin.is_test)
            @compileError("message type `bytes` only allowed in tests");

        // Get the next expected input, and inside we verify that it matches
        // the type we're about to append to the transcript.
        const input = comptime session.nextInput(t, label);
        // If the input requires validation, we perform it here.
        if (comptime t.validates()) try data.rejectIdentity();
        // Ensure that the domain seperators are added with the correct label.
        // They should always be added through the `appendDomSep` helper function.
        switch (t) {
            .domsep => comptime {
                std.debug.assert(input.seperator.? == data);
                std.debug.assert(std.mem.eql(u8, label, "dom-sep"));
            },
            else => {},
        }

        self.appendMessage(input.label, @unionInit(
            Message,
            @tagName(t.base()),
            data,
        ));
    }

    /// Helper function to be used in proof creation. We often need to test what will
    /// happen if points are zeroed, and to make sure that the verification fails.
    /// Shouldn't be used outside of the `init` functions.
    pub inline fn appendNoValidate(
        self: *Transcript,
        comptime session: *Session,
        comptime t: Input.Type,
        comptime label: []const u8,
        data: @FieldType(Message, @tagName(t.base())),
    ) void {
        const input = comptime session.nextInput(
            @field(Input.Type, "validate_" ++ @tagName(t)),
            label,
        );
        data.rejectIdentity() catch {}; // ignore the error
        self.appendMessage(input.label, @unionInit(Message, @tagName(t), data));
    }

    fn challengeBytes(
        self: *Transcript,
        label: []const u8,
        destination: []u8,
    ) void {
        var data_len: [4]u8 = undefined;
        std.mem.writeInt(u32, &data_len, @intCast(destination.len), .little);
        self.strobe.metaAd(label, false);
        self.strobe.metaAd(&data_len, true);
        self.strobe.prf(destination, false);
    }

    pub inline fn challengeScalar(
        self: *Transcript,
        comptime session: *Session,
        comptime label: []const u8,
    ) Scalar {
        const input = comptime session.nextInput(.challenge, label);
        var buffer: [64]u8 = @splat(0);
        self.challengeBytes(input.label, &buffer);
        // Specifically need reduce64 instead of Scalar.fromBytes64, since
        // we need the Barret reduction to be done with 10 limbs, not 5.
        const compressed = Ed25519.scalar.reduce64(buffer);
        return Scalar.fromBytes(compressed);
    }

    // domain seperation helpers

    pub inline fn appendDomSep(
        self: *Transcript,
        comptime session: *Session,
        comptime seperator: DomainSeperator,
    ) void {
        self.append(session, .domsep, "dom-sep", seperator);
    }

    pub inline fn appendRangeProof(
        self: *Transcript,
        comptime session: *Session,
        comptime mode: enum { range, inner },
        n: comptime_int,
    ) void {
        self.appendDomSep(session, switch (mode) {
            .range => .@"range-proof",
            .inner => .@"inner-product",
        });
        self.append(session, .u64, "n", n);
    }

    // sessions

    pub const Input = struct {
        label: []const u8,
        type: Type,
        seperator: ?DomainSeperator = null,

        const Type = enum {
            bytes,
            scalar,
            u64,

            point,
            pubkey,
            ciphertext,
            commitment,
            grouped_2,
            grouped_3,

            validate_point,
            validate_pubkey,
            validate_ciphertext,
            validate_commitment,
            validate_grouped_2,
            validate_grouped_3,

            domsep,
            challenge,

            /// Returns whether this input type performs identity validation.
            fn validates(t: Type) bool {
                return switch (t) {
                    .validate_point,
                    .validate_pubkey,
                    .validate_ciphertext,
                    .validate_commitment,
                    .validate_grouped_2,
                    .validate_grouped_3,
                    => true,
                    else => false,
                };
            }

            /// For a given input type, returns the base type.
            /// E.g. `validate_point` -> `point`
            /// E.g. `point` -> `point`
            fn base(t: Type) Type {
                if (t.validates()) {
                    return @field(Type, @tagName(t)["validate_".len..]);
                }
                return t;
            }
        };

        pub fn domain(sep: DomainSeperator) Input {
            return .{ .label = "dom-sep", .type = .domsep, .seperator = sep };
        }

        fn check(self: Input, t: Type, label: []const u8) void {
            if (self.type != t) {
                @compileError("expected: " ++ @tagName(self.type) ++ ", found: " ++ @tagName(t));
            }
            std.debug.assert(std.mem.eql(u8, self.label, label));
        }
    };

    pub const Contract = []const Input;

    pub const Session = struct {
        i: u8,
        contract: Contract,
        // If an identity validation errors, we skip the finish() check.
        err: bool,

        pub inline fn nextInput(comptime self: *Session, t: Input.Type, label: []const u8) Input {
            comptime {
                defer self.i += 1;
                const input = self.contract[self.i];
                input.check(t, label);
                return input;
            }
        }

        pub inline fn finish(comptime self: *Session) void {
            // For performance, we have certain computations (specifically in `init` functions)
            // which skip the last parts of transcript when they aren't needed (i.e ciphertext_ciphertext proof).
            //
            // By performing this check, we still ensure that they do those extra computations when in Debug mode,
            // but are allowed to skip them in a release build.
            if (builtin.mode == .Debug and !self.err and self.i != self.contract.len) {
                @compileError("contract unfulfilled");
            }
        }

        inline fn cancel(comptime self: *Session) void {
            comptime self.err = true;
        }
    };

    pub inline fn getSession(comptime contract: []const Input) Session {
        comptime {
            // contract should always end in a challenge
            const last_contract = contract[contract.len - 1];
            std.debug.assert(last_contract.type == .challenge);
            return .{ .i = 0, .contract = contract, .err = false };
        }
    }

    /// The same as `getSession`, but does not check that it ends with a challenge.
    /// Only used in certain cases when we need an "init" contract, such as `percentage_with_cap`.
    pub inline fn getInitSession(comptime contract: []const Input) Session {
        comptime {
            return .{ .i = 0, .contract = contract, .err = false };
        }
    }
};

test "equivalence" {
    var transcript = Transcript.initTest("test protocol");

    comptime var session = Transcript.getSession(&.{
        .{ .label = "some label", .type = .bytes },
        .{ .label = "challenge", .type = .challenge },
    });
    transcript.append(&session, .bytes, "some label", "some data");

    var bytes: [32]u8 = undefined;
    transcript.challengeBytes("challenge", &bytes);

    try std.testing.expectEqualSlices(u8, &.{
        159, 115, 74,  116, 119, 227, 89,  42,
        108, 83,  69,  218, 43,  29,  11,  79,
        117, 141, 121, 172, 163, 50,  123, 92,
        25,  21,  111, 177, 11,  232, 4,   35,
    }, &bytes);
}
