const std = @import("std");
const tracy = @import("tracy");
const sig = @import("../../../sig.zig");

const zksdk = sig.zksdk;
const zk_elgamal = sig.runtime.program.zk_elgamal;
const InstructionError = sig.core.instruction.InstructionError;
const InstructionContext = sig.runtime.InstructionContext;

pub fn execute(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    const zone = tracy.Zone.init(@src(), .{ .name = "zk_elgamal: entrypoint" });
    defer zone.deinit();

    const tc = ic.tc;
    const instruction_data = ic.ixn_info.instruction_data;

    if (instruction_data.len < 1) return InstructionError.InvalidInstructionData;
    const instruction = std.meta.intToEnum(
        zk_elgamal.ProofInstruction,
        instruction_data[0],
    ) catch return InstructionError.InvalidInstructionData;

    switch (instruction) {
        .close_context_state => {
            try tc.consumeCompute(zk_elgamal.CLOSE_CONTEXT_STATE_COMPUTE_UNITS);
            try tc.log("CloseContextState", .{});
            try processCloseContextState(allocator, ic);
        },
        .verify_zero_ciphertext => {
            try tc.consumeCompute(zk_elgamal.VERIFY_ZERO_CIPHERTEXT_COMPUTE_UNITS);
            try tc.log("VerifyZeroBalance", .{});
            try processVerifyProof(zksdk.ZeroCiphertextData, allocator, ic);
        },
        .verify_ciphertext_ciphertext_equality => {
            try tc.consumeCompute(zk_elgamal.VERIFY_CIPHERTEXT_CIPHERTEXT_EQUALITY_COMPUTE_UNITS);
            try tc.log("VerifyCiphertextCiphertextEquality", .{});
            try processVerifyProof(zksdk.CiphertextCiphertextData, allocator, ic);
        },
        .verify_ciphertext_commitment_equality => {
            try tc.consumeCompute(zk_elgamal.VERIFY_CIPHERTEXT_COMMITMENT_EQUALITY_COMPUTE_UNITS);
            try tc.log("VerifyCiphertextCommitmentEquality", .{});
            try processVerifyProof(zksdk.CiphertextCommitmentData, allocator, ic);
        },
        .verify_pubkey_validity => {
            try tc.consumeCompute(zk_elgamal.VERIFY_PUBKEY_VALIDITY_COMPUTE_UNITS);
            try tc.log("VerifyPubkeyValidity", .{});
            try processVerifyProof(zksdk.PubkeyProofData, allocator, ic);
        },
        .verify_batched_range_proof_u64 => {
            try tc.consumeCompute(zk_elgamal.VERIFY_BATCHED_RANGE_PROOF_U64_COMPUTE_UNITS);
            try tc.log("VerifyBatchedRangeProofU64", .{});
            try processVerifyProof(zksdk.RangeProofU64Data, allocator, ic);
        },
        .verify_batched_range_proof_u128 => {
            try tc.consumeCompute(zk_elgamal.VERIFY_BATCHED_RANGE_PROOF_U128_COMPUTE_UNITS);
            try tc.log("VerifyBatchedRangeProofU128", .{});
            try processVerifyProof(zksdk.RangeProofU128Data, allocator, ic);
        },
        .verify_batched_range_proof_u256 => {
            try tc.consumeCompute(zk_elgamal.VERIFY_BATCHED_RANGE_PROOF_U256_COMPUTE_UNITS);
            try tc.log("VerifyBatchedRangeProofU256", .{});
            try processVerifyProof(zksdk.RangeProofU256Data, allocator, ic);
        },
        .verify_grouped_ciphertext2_handles_validity => {
            try tc.consumeCompute(
                zk_elgamal.VERIFY_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY_COMPUTE_UNITS,
            );
            try tc.log("VerifyGroupedCiphertext2HandlesValidity", .{});
            try processVerifyProof(zksdk.GroupedCiphertext2HandlesData, allocator, ic);
        },
        .verify_batched_grouped_ciphertext2_handles_validity => {
            try tc.consumeCompute(
                zk_elgamal.VERIFY_BATCHED_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY_COMPUTE_UNITS,
            );
            try tc.log("VerifyBatchedGroupedCiphertext2HandlesValidity", .{});
            try processVerifyProof(zksdk.BatchedGroupedCiphertext2HandlesData, allocator, ic);
        },
        .verify_grouped_ciphertext3_handles_validity => {
            try tc.consumeCompute(
                zk_elgamal.VERIFY_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_COMPUTE_UNITS,
            );
            try tc.log("VerifyGroupedCiphertext3HandlesValidity", .{});
            try processVerifyProof(zksdk.GroupedCiphertext3HandlesData, allocator, ic);
        },
        .verify_batched_grouped_ciphertext3_handles_validity => {
            try tc.consumeCompute(
                zk_elgamal.VERIFY_BATCHED_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_COMPUTE_UNITS,
            );
            try tc.log("VerifyBatchedGroupedCiphertext3HandlesValidity", .{});
            try processVerifyProof(zksdk.BatchedGroupedCiphertext3HandlesData, allocator, ic);
        },
        .verify_percentage_with_cap => {
            try tc.consumeCompute(
                zk_elgamal.VERIFY_PERCENTAGE_WITH_CAP_COMPUTE_UNITS,
            );
            try tc.log("VerifyPercentageWithCap", .{});
            try processVerifyProof(zksdk.PercentageWithCapData, allocator, ic);
        },
    }
}

fn processVerifyProof(
    comptime Proof: type,
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    const tc = ic.tc;
    const instruction_data = ic.ixn_info.instruction_data;

    var accessed_accounts: u16 = 0;

    // if instruction data is exactly 5 bytes, then read proof from an account,
    // first byte is the instruction enum, next 4 bytes make up a u32 for the byte offset
    // into the proof data account which contains the proof itself.
    const context_data: Proof.Context = if (instruction_data.len == 5) cd: {
        const proof_data_account = try ic.borrowInstructionAccount(accessed_accounts);
        defer proof_data_account.release();

        const proof_data_len = proof_data_account.constAccountData().len;
        accessed_accounts += 1;

        const start: u32 = @bitCast(instruction_data[1..5].*);
        const end = @as(u64, start) + Proof.BYTE_LEN;

        if (start >= proof_data_len) return InstructionError.InvalidAccountData;
        if (end > proof_data_len) return InstructionError.InvalidAccountData;
        const proof_data_slice = proof_data_account.constAccountData()[start..end];

        const proof_data = Proof.fromBytes(proof_data_slice) catch {
            try tc.log("invalid proof data", .{});
            return InstructionError.InvalidInstructionData;
        };
        proof_data.verify() catch {
            // TODO: log error as well
            // [fd] https://github.com/firedancer-io/firedancer/blob/e0de87d2f58547b69ba980b3c88f35094b34561e/src/flamenco/runtime/program/zksdk/fd_zksdk.c#L209-L210
            try tc.log("proof_verification failed", .{});
            return InstructionError.InvalidInstructionData;
        };

        break :cd proof_data.context;
    } else cd: {
        const proof_data = Proof.fromBytes(instruction_data[1..]) catch {
            try tc.log("invalid proof data", .{});
            return InstructionError.InvalidInstructionData;
        };
        proof_data.verify() catch {
            // TODO: log error as well
            // [fd] https://github.com/firedancer-io/firedancer/blob/e0de87d2f58547b69ba980b3c88f35094b34561e/src/flamenco/runtime/program/zksdk/fd_zksdk.c#L209-L210
            try tc.log("proof_verification failed", .{});
            return InstructionError.InvalidInstructionData;
        };

        break :cd proof_data.context;
    };

    // create context state if additional accounts are provided with the instruction
    if (ic.ixn_info.account_metas.items.len >= accessed_accounts + 2) {
        const context_authority_key = blk: {
            const context_state_authority = try ic.borrowInstructionAccount(accessed_accounts + 1);
            defer context_state_authority.release();
            break :blk context_state_authority.pubkey;
        };

        const proof_context_account = try ic.borrowInstructionAccount(accessed_accounts);
        defer proof_context_account.release();

        if (!proof_context_account.isOwnedByCurrentProgram()) {
            return InstructionError.InvalidAccountOwner;
        }
        const proof_context_data = proof_context_account.constAccountData();

        const proof_context_meta = sig.bincode.readFromSlice(
            allocator,
            zk_elgamal.ProofContextStateMeta,
            proof_context_data,
            .{},
        ) catch return InstructionError.InvalidAccountData;
        defer sig.bincode.free(allocator, proof_context_meta);

        if (proof_context_meta.proof_type != .uninitialized) {
            return InstructionError.AccountAlreadyInitialized;
        }

        var context_state: zk_elgamal.ProofContextState(Proof.Context) = .{
            .proof_type = Proof.TYPE,
            .context = context_data.toBytes(),
            .context_state_authority = context_authority_key,
        };
        if (proof_context_data.len != @sizeOf(@TypeOf(context_state))) {
            return InstructionError.InvalidAccountData;
        }

        try proof_context_account.setDataFromSlice(
            allocator,
            &tc.accounts_resize_delta,
            std.mem.asBytes(&context_state),
        );
    }
}

/// [agave] https://github.com/anza-xyz/agave/blob/93699947720534741b2b4d9b6e1696d81e386dcc/programs/zk-elgamal-proof/src/lib.rs#L129
fn processCloseContextState(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    const tc = ic.tc;
    const owner_pubkey = pubkey: {
        const owner_account = try ic.borrowInstructionAccount(2);
        defer owner_account.release();
        if (!owner_account.context.is_signer) {
            return InstructionError.MissingRequiredSignature;
        }
        break :pubkey owner_account.pubkey;
    };

    const proof_context_pubkey = pubkey: {
        const proof_context_account = try ic.borrowInstructionAccount(0);
        defer proof_context_account.release();
        break :pubkey proof_context_account.pubkey;
    };
    const destination_account_pubkey = pubkey: {
        const destination_account = try ic.borrowInstructionAccount(1);
        defer destination_account.release();
        break :pubkey destination_account.pubkey;
    };
    if (proof_context_pubkey.equals(&destination_account_pubkey)) {
        return InstructionError.InvalidInstructionData;
    }

    const proof_context_account = try ic.borrowInstructionAccount(0);
    defer proof_context_account.release();
    if (!proof_context_account.account.owner.equals(&zk_elgamal.ID)) {
        return InstructionError.InvalidAccountOwner;
    }

    const proof_context_data = proof_context_account.constAccountData();
    const proof_context_meta = sig.bincode.readFromSlice(
        allocator,
        zk_elgamal.ProofContextStateMeta,
        proof_context_data,
        .{},
    ) catch return InstructionError.InvalidAccountData;
    defer sig.bincode.free(allocator, proof_context_meta);
    if (proof_context_meta.proof_type == .uninitialized) {
        return InstructionError.UninitializedAccount;
    }

    const expected_owner_pubkey = proof_context_meta.context_state_authority;
    if (!expected_owner_pubkey.equals(&owner_pubkey)) {
        return InstructionError.InvalidAccountOwner;
    }

    const destination_account = try ic.borrowInstructionAccount(1);
    defer destination_account.release();
    try destination_account.addLamports(proof_context_account.account.lamports);
    try proof_context_account.setLamports(0);
    try proof_context_account.setDataLength(
        allocator,
        &tc.accounts_resize_delta,
        0,
    );
    try proof_context_account.setOwner(sig.runtime.program.system.ID);
}
