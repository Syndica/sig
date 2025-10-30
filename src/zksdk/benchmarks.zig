const std = @import("std");
const sig = @import("../sig.zig");

const zksdk = sig.zksdk;
const pedersen = zksdk.pedersen;

pub const Benchmark = struct {
    pub const min_iterations = 100;
    pub const max_iterations = 1_000;
    pub const name = "zksdk";

    pub fn pubkeyValidity() !sig.time.Duration {
        const kp = zksdk.ElGamalKeypair.random();
        const proof_data = zksdk.PubkeyProofData.init(&kp);

        var start = sig.time.Timer.start();
        std.mem.doNotOptimizeAway(proof_data.verify());
        return start.read();
    }

    pub fn zeroCiphertext() !sig.time.Duration {
        const kp = zksdk.ElGamalKeypair.random();
        const ciphertext = zksdk.el_gamal.encrypt(u64, 0, &kp.public);
        const proof_data = zksdk.ZeroCiphertextData.init(&kp, &ciphertext);

        var start = sig.time.Timer.start();
        std.mem.doNotOptimizeAway(proof_data.verify());
        return start.read();
    }

    pub fn rangeProofU64() !sig.time.Duration {
        const amount_1: u64 = std.math.maxInt(u8);
        const amount_2: u64 = 77;
        const amount_3: u64 = 99;
        const amount_4: u64 = 99;
        const amount_5: u64 = 11;
        const amount_6: u64 = 33;
        const amount_7: u64 = 99;
        const amount_8: u64 = 99;

        const commitment_1, const opening_1 = pedersen.initValue(u64, amount_1);
        const commitment_2, const opening_2 = pedersen.initValue(u64, amount_2);
        const commitment_3, const opening_3 = pedersen.initValue(u64, amount_3);
        const commitment_4, const opening_4 = pedersen.initValue(u64, amount_4);
        const commitment_5, const opening_5 = pedersen.initValue(u64, amount_5);
        const commitment_6, const opening_6 = pedersen.initValue(u64, amount_6);
        const commitment_7, const opening_7 = pedersen.initValue(u64, amount_7);
        const commitment_8, const opening_8 = pedersen.initValue(u64, amount_8);

        const proof_data = try zksdk.RangeProofU64Data.init(&.{
            commitment_1, commitment_2, commitment_3, commitment_4,
            commitment_5, commitment_6, commitment_7, commitment_8,
        }, &.{
            amount_1, amount_2, amount_3, amount_4,
            amount_5, amount_6, amount_7, amount_8,
        }, &.{ 8, 8, 8, 8, 8, 8, 8, 8 }, &.{
            opening_1, opening_2, opening_3, opening_4,
            opening_5, opening_6, opening_7, opening_8,
        });

        var start = sig.time.Timer.start();
        std.mem.doNotOptimizeAway(proof_data.verify());
        return start.read();
    }

    pub fn rangeProofU256() !sig.time.Duration {
        const amount_1: u64 = std.math.maxInt(u32);
        const amount_2: u64 = 77;
        const amount_3: u64 = 99;
        const amount_4: u64 = 99;
        const amount_5: u64 = 11;
        const amount_6: u64 = 33;
        const amount_7: u64 = 99;
        const amount_8: u64 = 99;

        const commitment_1, const opening_1 = pedersen.initValue(u64, amount_1);
        const commitment_2, const opening_2 = pedersen.initValue(u64, amount_2);
        const commitment_3, const opening_3 = pedersen.initValue(u64, amount_3);
        const commitment_4, const opening_4 = pedersen.initValue(u64, amount_4);
        const commitment_5, const opening_5 = pedersen.initValue(u64, amount_5);
        const commitment_6, const opening_6 = pedersen.initValue(u64, amount_6);
        const commitment_7, const opening_7 = pedersen.initValue(u64, amount_7);
        const commitment_8, const opening_8 = pedersen.initValue(u64, amount_8);

        const proof_data = try zksdk.RangeProofU256Data.init(&.{
            commitment_1, commitment_2, commitment_3, commitment_4,
            commitment_5, commitment_6, commitment_7, commitment_8,
        }, &.{
            amount_1, amount_2, amount_3, amount_4,
            amount_5, amount_6, amount_7, amount_8,
        }, &.{ 32, 32, 32, 32, 32, 32, 32, 32 }, &.{
            opening_1, opening_2, opening_3, opening_4,
            opening_5, opening_6, opening_7, opening_8,
        });

        var start = sig.time.Timer.start();
        std.mem.doNotOptimizeAway(proof_data.verify());
        return start.read();
    }
};
