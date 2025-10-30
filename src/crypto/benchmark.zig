const std = @import("std");
const sig = @import("../sig.zig");

const Ed25519 = std.crypto.sign.Ed25519;

pub const Benchmark = struct {
    pub const min_iterations = 5;
    pub const max_iterations = 1_000;
    pub const name = "crypto";

    pub const BenchmarkInputs = struct {
        num_signatures: u64,
        name: []const u8,
    };

    pub const inputs = [_]BenchmarkInputs{
        .{ .num_signatures = 1, .name = "1 signature" },
        .{ .num_signatures = 100, .name = "100 signatures" },
        .{ .num_signatures = 1_000, .name = "1k signatures" },
        // .{ .num_signatures = 100_000 },
    };

    pub fn naiveBatchVerify(args: BenchmarkInputs) !sig.time.Duration {
        const message = "test!";

        const keypair = Ed25519.KeyPair.generate();
        const signature = try keypair.sign(message, null);

        switch (args.num_signatures) {
            inline 1, 100, 1_000 => |N| {
                const signatures: [N]Ed25519.Signature = @splat(signature);
                var start = try sig.time.Timer.start();
                for (signatures, 0..) |s, i| {
                    std.mem.doNotOptimizeAway(i);
                    std.mem.doNotOptimizeAway(s.verify(
                        message,
                        keypair.public_key,
                    ));
                }
                return start.read().div(N);
            },
            else => unreachable,
        }
    }

    pub fn stdBatchVerify(args: BenchmarkInputs) !sig.time.Duration {
        const message = "test!";

        const keypair = Ed25519.KeyPair.generate();
        const signature = try keypair.sign(message, null);

        switch (args.num_signatures) {
            inline 1, 100, 1_000 => |N| {
                const signatures: [N]Ed25519.Signature = @splat(signature);
                var batch: [N]Ed25519.BatchElement = undefined;
                for (&batch, signatures) |*element, input| {
                    element.* = .{
                        .public_key = keypair.public_key,
                        .msg = message,
                        .sig = input,
                    };
                }
                var start = try sig.time.Timer.start();
                std.mem.doNotOptimizeAway(Ed25519.verifyBatch(N, batch));
                return start.read().div(N);
            },
            else => unreachable,
        }
    }

    pub fn sigBatchVerify(args: BenchmarkInputs) !sig.time.Duration {
        const message = "test!";

        const keypair = Ed25519.KeyPair.generate();
        const signature = try keypair.sign(message, null);

        switch (args.num_signatures) {
            inline 1, 100, 1_000 => |N| {
                const signatures: [N]sig.core.Signature = @splat(.fromSignature(signature));
                const pubkey: [N]sig.core.Pubkey = @splat(.fromPublicKey(&keypair.public_key));

                var start = try sig.time.Timer.start();
                std.mem.doNotOptimizeAway(sig.crypto.ed25519.verifyBatchOverSingleMessage(
                    N,
                    &signatures,
                    &pubkey,
                    message,
                ));
                return start.read().div(N);
            },
            else => unreachable,
        }
    }
};
