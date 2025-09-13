const std = @import("std");
const sig = @import("../sig.zig");

const Ed25519 = std.crypto.sign.Ed25519;

pub const Benchmark = struct {
    pub const min_iterations = 100;
    pub const max_iterations = 1_000;

    pub fn naiveBatchVerify() !sig.time.Duration {
        const message = "test!";

        const keypair = Ed25519.KeyPair.generate();
        const signature = try keypair.sign(message, null);

        const inputs: [100]Ed25519.Signature = @splat(signature);

        var start = try sig.time.Timer.start();
        for (inputs) |s| {
            std.mem.doNotOptimizeAway(try s.verify(message, keypair.public_key));
        }
        return start.read();
    }

    pub fn stdBatchVerify() !sig.time.Duration {
        const message = "test!";

        const keypair = Ed25519.KeyPair.generate();
        const signature = try keypair.sign(message, null);

        const inputs: [100]Ed25519.Signature = @splat(signature);

        var batch: [100]Ed25519.BatchElement = undefined;
        for (&batch, inputs) |*element, input| {
            element.* = .{
                .public_key = keypair.public_key,
                .msg = message,
                .sig = input,
            };
        }

        var start = try sig.time.Timer.start();
        std.mem.doNotOptimizeAway(Ed25519.verifyBatch(100, batch));
        return start.read();
    }

    pub fn sigBatchVerify() !sig.time.Duration {
        const message = "test!";

        const keypair = Ed25519.KeyPair.generate();
        const signature = try keypair.sign(message, null);

        const signatures: [100]sig.core.Signature = @splat(.fromSignature(signature));
        const pubkey: [100]sig.core.Pubkey = @splat(.{ .data = keypair.public_key.toBytes() });

        var start = try sig.time.Timer.start();
        std.mem.doNotOptimizeAway(sig.crypto.ed25519.verifyBatchOverSingleMessage(
            100,
            &signatures,
            &pubkey,
            message,
        ));
        return start.read();
    }
};
