const std = @import("std");
const sig = @import("../sig.zig");

const Edwards25519 = std.crypto.ecc.Edwards25519;

const zksdk = sig.zksdk;
const elgamal = zksdk.elgamal;
const pedersen = zksdk.pedersen;
const Keypair = zksdk.ElGamalKeypair;
const Opening = pedersen.Opening;

pub const Benchmark = struct {
    pub const min_iterations = 100;
    pub const max_iterations = 1_000;
    pub const name = "zksdk";

    pub fn pubkeyValidity() !sig.time.Duration {
        const kp = Keypair.random();
        const proof_data = zksdk.PubkeyProofData.init(&kp);

        var start = sig.time.Timer.start();
        std.mem.doNotOptimizeAway(proof_data.verify());
        return start.read();
    }

    pub fn zeroCiphertext() !sig.time.Duration {
        const kp = Keypair.random();
        const ciphertext = elgamal.encrypt(u64, 0, &kp.public);
        const proof_data = zksdk.ZeroCiphertextData.init(&kp, &ciphertext);

        var start = sig.time.Timer.start();
        std.mem.doNotOptimizeAway(proof_data.verify());
        return start.read();
    }

    pub fn groupedCiphertext2Handles() !sig.time.Duration {
        const destination_keypair = Keypair.random();
        const destination_pubkey = destination_keypair.public;

        const auditor_keypair = Keypair.random();
        const auditor_pubkey = auditor_keypair.public;

        const amount: u64 = 55;
        const opening = Opening.random();
        const grouped_ciphertext = zksdk.GroupedElGamalCiphertext(2).encryptWithOpening(
            .{ destination_pubkey, auditor_pubkey },
            amount,
            &opening,
        );

        const proof_data = zksdk.GroupedCiphertext2HandlesData.init(
            &destination_pubkey,
            &auditor_pubkey,
            &grouped_ciphertext,
            amount,
            &opening,
        );

        var start = sig.time.Timer.start();
        std.mem.doNotOptimizeAway(proof_data.verify());
        return start.read();
    }

    pub fn groupedCiphertext3Handles() !sig.time.Duration {
        const source_keypair = Keypair.random();
        const source_pubkey = source_keypair.public;

        const destination_keypair = Keypair.random();
        const destination_pubkey = destination_keypair.public;

        const auditor_keypair = Keypair.random();
        const auditor_pubkey = auditor_keypair.public;

        const amount: u64 = 55;
        const opening = Opening.random();
        const grouped_ciphertext = zksdk.GroupedElGamalCiphertext(3).encryptWithOpening(
            .{ source_pubkey, destination_pubkey, auditor_pubkey },
            amount,
            &opening,
        );

        const proof_data = zksdk.GroupedCiphertext3HandlesData.init(
            &source_pubkey,
            &destination_pubkey,
            &auditor_pubkey,
            &grouped_ciphertext,
            amount,
            &opening,
        );

        var start = sig.time.Timer.start();
        std.mem.doNotOptimizeAway(proof_data.verify());
        return start.read();
    }

    pub fn ciphertextCommitmentEquality() !sig.time.Duration {
        const keypair = Keypair.random();
        const amount: u64 = 55;
        const ciphertext = elgamal.encrypt(u64, amount, &keypair.public);
        const commitment, const opening = pedersen.initValue(u64, amount);

        const proof_data = zksdk.CiphertextCommitmentData.init(
            &keypair,
            &ciphertext,
            &commitment,
            &opening,
            amount,
        );

        var start = sig.time.Timer.start();
        std.mem.doNotOptimizeAway(proof_data.verify());
        return start.read();
    }

    pub fn ciphertextCiphertextEquality() !sig.time.Duration {
        const source_keypair = Keypair.random();
        const destination_keypair = Keypair.random();

        const amount: u64 = 0;
        const source_ciphertext = elgamal.encrypt(u64, amount, &source_keypair.public);

        const destination_opening = Opening.random();
        const destination_ciphertext = elgamal.encryptWithOpening(
            u64,
            amount,
            &destination_keypair.public,
            &destination_opening,
        );

        const proof_data = zksdk.CiphertextCiphertextData.init(
            &source_keypair,
            &destination_keypair.public,
            &source_ciphertext,
            &destination_ciphertext,
            &destination_opening,
            amount,
        );

        var start = sig.time.Timer.start();
        std.mem.doNotOptimizeAway(proof_data.verify());
        return start.read();
    }

    pub fn batchedGroupedCiphertext2Handles() !sig.time.Duration {
        const destination_keypair = Keypair.random();
        const destination_pubkey = destination_keypair.public;

        const auditor_keypair = Keypair.random();
        const auditor_pubkey = auditor_keypair.public;

        const amount_lo: u64 = 11;
        const amount_hi: u64 = 22;

        const opening_lo = Opening.random();
        const opening_hi = Opening.random();

        const grouped_ciphertext_lo = zksdk.GroupedElGamalCiphertext(2).encryptWithOpening(
            .{ destination_pubkey, auditor_pubkey },
            amount_lo,
            &opening_lo,
        );

        const grouped_ciphertext_hi = zksdk.GroupedElGamalCiphertext(2).encryptWithOpening(
            .{ destination_pubkey, auditor_pubkey },
            amount_hi,
            &opening_hi,
        );

        const proof_data = zksdk.BatchedGroupedCiphertext2HandlesData.init(
            &destination_pubkey,
            &auditor_pubkey,
            &grouped_ciphertext_lo,
            &grouped_ciphertext_hi,
            amount_lo,
            amount_hi,
            &opening_lo,
            &opening_hi,
        );

        var start = sig.time.Timer.start();
        std.mem.doNotOptimizeAway(proof_data.verify());
        return start.read();
    }

    pub fn batchedGroupedCiphertext3Handles() !sig.time.Duration {
        const source_keypair = Keypair.random();
        const source_pubkey = source_keypair.public;

        const destination_keypair = Keypair.random();
        const destination_pubkey = destination_keypair.public;

        const auditor_keypair = Keypair.random();
        const auditor_pubkey = auditor_keypair.public;

        const amount_lo: u64 = 11;
        const amount_hi: u64 = 22;

        const opening_lo = Opening.random();
        const opening_hi = Opening.random();

        const grouped_ciphertext_lo = zksdk.GroupedElGamalCiphertext(3).encryptWithOpening(
            .{ source_pubkey, destination_pubkey, auditor_pubkey },
            amount_lo,
            &opening_lo,
        );

        const grouped_ciphertext_hi = zksdk.GroupedElGamalCiphertext(3).encryptWithOpening(
            .{ source_pubkey, destination_pubkey, auditor_pubkey },
            amount_hi,
            &opening_hi,
        );

        const proof_data = zksdk.BatchedGroupedCiphertext3HandlesData.init(
            &source_pubkey,
            &destination_pubkey,
            &auditor_pubkey,
            &grouped_ciphertext_lo,
            &grouped_ciphertext_hi,
            amount_lo,
            amount_hi,
            &opening_lo,
            &opening_hi,
        );

        var start = sig.time.Timer.start();
        std.mem.doNotOptimizeAway(proof_data.verify());
        return start.read();
    }

    pub fn percentageWithCap() !sig.time.Duration {
        const transfer_amount: u64 = 1;
        const max_fee: u64 = 3;

        const fee_rate: u16 = 400;
        const fee_amount: u64 = 1;
        const delta_fee: u64 = 9600;

        const transfer_commitment, //
        const transfer_opening = pedersen.initValue(u64, transfer_amount);
        const fee_commitment, //
        const fee_opening = pedersen.initValue(u64, fee_amount);

        const scalar_rate = pedersen.scalarFromInt(u64, fee_rate);
        const ten_thousand = pedersen.scalarFromInt(u64, 10_000);

        const delta_commitment: pedersen.Commitment = d: {
            const a = try fee_commitment.point.mul(ten_thousand.toBytes());
            const b = try transfer_commitment.point.mul(scalar_rate.toBytes());
            break :d .{ .point = .{ .p = a.p.sub(b.p) } };
        };
        const delta_opening: pedersen.Opening = d: {
            const a = fee_opening.scalar.mul(ten_thousand);
            const b = transfer_opening.scalar.mul(scalar_rate);
            const c = Edwards25519.scalar.sub(a.toBytes(), b.toBytes());
            break :d .{ .scalar = .fromBytes(c) };
        };

        const claimed_commitment, const claimed_opening = pedersen.initValue(u64, delta_fee);

        const proof_data = zksdk.PercentageWithCapData.init(
            &fee_commitment,
            &fee_opening,
            fee_amount,
            &delta_commitment,
            &delta_opening,
            delta_fee,
            &claimed_commitment,
            &claimed_opening,
            max_fee,
        );

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

    pub fn rangeProofU128() !sig.time.Duration {
        const amount_1: u64 = std.math.maxInt(u16);
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

        const proof_data = try zksdk.RangeProofU128Data.init(&.{
            commitment_1, commitment_2, commitment_3, commitment_4,
            commitment_5, commitment_6, commitment_7, commitment_8,
        }, &.{
            amount_1, amount_2, amount_3, amount_4,
            amount_5, amount_6, amount_7, amount_8,
        }, &.{ 16, 16, 16, 16, 16, 16, 16, 16 }, &.{
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
