const std = @import("std");
const sig = @import("../../sig.zig");

const Edwards25519 = std.crypto.ecc.Edwards25519;
const pedersen = sig.zksdk.pedersen;
const ElGamalKeypair = sig.zksdk.ElGamalKeypair;
const ElGamalPubkey = sig.zksdk.ElGamalPubkey;
const Ristretto255 = std.crypto.ecc.Ristretto255;
const Scalar = std.crypto.ecc.Edwards25519.scalar.Scalar;
const Transcript = sig.zksdk.Transcript;
const weak_mul = sig.vm.syscalls.ecc.weak_mul;
const ProofType = sig.runtime.program.zk_elgamal.ProofType;

pub const Proof = struct {
    Y: Ristretto255,
    z: Scalar,

    pub fn init(
        kp: *const ElGamalKeypair,
        transcript: *Transcript,
    ) Proof {
        transcript.appendDomSep("pubkey-proof");

        const s = kp.secret.scalar;
        std.debug.assert(!s.isZero());
        const s_inv = s.invert();

        var y = Scalar.random();
        defer std.crypto.utils.secureZero(u64, &y.limbs);

        // Scalar.random() cannot return zero, and H isn't an identity
        const Y = pedersen.H.mul(y.toBytes()) catch unreachable;

        transcript.appendPoint("Y", Y);
        const c = transcript.challengeScalar("c");

        const z = c.mul(s_inv).add(y);

        return .{
            .Y = Y,
            .z = z,
        };
    }

    pub fn verify(
        self: Proof,
        pubkey: *const ElGamalPubkey,
        transcript: *Transcript,
    ) !void {
        transcript.appendDomSep("pubkey-proof");

        try transcript.validateAndAppendPoint("Y", self.Y);
        const c = transcript.challengeScalar("c");

        //     points  scalars
        // 0   H        z
        // 1   P       -c
        // ----------------------- MSM
        //     Y

        const check = weak_mul.mulMulti(2, .{
            pedersen.H.p,
            pubkey.p.p,
        }, .{
            self.z.toBytes(),
            Edwards25519.scalar.neg(c.toBytes()),
        });

        if (!self.Y.equivalent(.{ .p = check })) {
            return error.AlgebraicRelation;
        }
    }

    pub fn fromBytes(bytes: [64]u8) !Proof {
        const Y = try Ristretto255.fromBytes(bytes[0..32].*);
        const z = Scalar.fromBytes(bytes[32..64].*);
        try Edwards25519.scalar.rejectNonCanonical(z.toBytes());
        return .{
            .Y = Y,
            .z = z,
        };
    }

    pub fn fromBase64(string: []const u8) !Proof {
        const base64 = std.base64.standard;
        var buffer: [64]u8 = .{0} ** 64;
        const decoded_length = try base64.Decoder.calcSizeForSlice(string);
        try std.base64.standard.Decoder.decode(
            buffer[0..decoded_length],
            string,
        );
        return fromBytes(buffer);
    }

    pub fn toBytes(self: Proof) [64]u8 {
        return self.Y.toBytes() ++ self.z.toBytes();
    }
};

pub const Data = struct {
    context: Context,
    proof: Proof,

    pub const TYPE: ProofType = .pubkey_validity;
    pub const BYTE_LEN = 96;

    pub const Context = struct {
        pubkey: ElGamalPubkey,

        pub const BYTE_LEN = 32;

        pub fn fromBytes(bytes: [32]u8) !Context {
            return .{ .pubkey = try ElGamalPubkey.fromBytes(bytes[0..32].*) };
        }

        pub fn toBytes(self: Context) [32]u8 {
            return self.pubkey.toBytes();
        }

        fn newTranscript(self: Context) Transcript {
            var transcript = Transcript.init("pubkey-validity-instruction");
            transcript.appendPubkey("pubkey", self.pubkey);
            return transcript;
        }
    };

    pub fn init(kp: *const ElGamalKeypair) Data {
        const context: Context = .{ .pubkey = kp.public };
        var transcript = context.newTranscript();
        const proof = Proof.init(
            kp,
            &transcript,
        );
        return .{ .context = context, .proof = proof };
    }

    pub fn fromBytes(data: []const u8) !Data {
        if (data.len != BYTE_LEN) return error.InvalidLength;
        return .{
            .context = try Context.fromBytes(data[0..32].*),
            .proof = try Proof.fromBytes(data[32..][0..64].*),
        };
    }

    pub fn toBytes(self: Data) [BYTE_LEN]u8 {
        return self.context.toBytes() ++ self.proof.toBytes();
    }

    pub fn verify(self: Data) !void {
        var transcript = self.context.newTranscript();
        try self.proof.verify(
            &self.context.pubkey,
            &transcript,
        );
    }

    test "correctness" {
        const kp = ElGamalKeypair.random();
        const pubkey_validity_data = Data.init(&kp);
        try pubkey_validity_data.verify();
    }
};

test "correctness" {
    const kp = ElGamalKeypair.random();

    var prover_transcript = Transcript.init("test");
    var verifier_transcript = Transcript.init("test");

    const proof = Proof.init(&kp, &prover_transcript);
    try proof.verify(&kp.public, &verifier_transcript);
}

test "proof string" {
    const pubkey_string = "XKF3GnFDX4HBoBEj04yDTr6Lqx+0qp9pQyPzFjyVmXY=";
    const pubkey = try ElGamalPubkey.fromBase64(pubkey_string);

    // zig fmt: off
    const proof_string = "5hmM4uVtfJ2JfCcjWpo2dEbg22n4CdzHYQF4oBgWSGeYAh5d91z4emkjeXq9ihtmqAR+7BYCv44TqQWoMQrECA==";
    const proof = try Proof.fromBase64(proof_string);
    // zig fmt: on

    var verifier_transcript = Transcript.init("test");
    try proof.verify(&pubkey, &verifier_transcript);
}
