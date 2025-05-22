const std = @import("std");
const sig = @import("../sig.zig");

const Hash = sig.core.Hash;
const Ancestors = sig.core.status_cache.Ancestors;
const BlockhashQueue = sig.core.bank.BlockhashQueue;
const Pubkey = sig.core.Pubkey;

const TransactionError = sig.ledger.transaction_status.TransactionError;

const RuntimeTransaction = sig.runtime.transaction_execution.RuntimeTransaction;
const BatchAccountCache = sig.runtime.account_loader.BatchAccountCache;
const CachedAccount = sig.runtime.account_loader.CachedAccount;
const TransactionResult = sig.runtime.transaction_execution.TransactionResult;
const AccountSharedData = sig.runtime.AccountSharedData;

pub const CheckResult = ?error{ AlreadyProcessed, BlockhashNotFound };

const NONCED_TX_MARKER_IX_INDEX = 0;

pub fn checkStatusCache(
    msg_hash: *const Hash,
    recent_blockhash: *const Hash,
    ancestors: *const Ancestors,
    status_cache: *const sig.core.StatusCache,
) ?TransactionError {
    if (isTransactionAlreadyProcessed(msg_hash, recent_blockhash, ancestors, status_cache))
        return .AlreadyProcessed;
    return null;
}

pub fn checkAge(
    transaction: *const RuntimeTransaction,
    batch_account_cache: *BatchAccountCache,
    blockhash_queue: *const BlockhashQueue,
    max_age: u64,
    last_blockhash: *const Hash,
    next_durable_nonce: *const Hash,
    next_lamports_per_signature: u64,
) TransactionResult(?CachedAccount) {
    if (blockhash_queue.getHashInfoIfValid(last_blockhash, max_age)) |hash_info| {
        _ = hash_info;
        return .{ .ok = null };
    }

    if (checkLoadAndAdvanceMessageNonceAccount(
        transaction,
        next_durable_nonce,
        next_lamports_per_signature,
        batch_account_cache,
    )) |nonce| {
        const nonce_account, const previous_lamports_per_signature = nonce;
        _ = previous_lamports_per_signature;
        return .{ .ok = nonce_account };
    }

    return .{ .err = .BlockhashNotFound };
}

fn checkLoadAndAdvanceMessageNonceAccount(
    transaction: *const RuntimeTransaction,
    next_durable_nonce: *const Hash,
    next_lamports_per_signature: u64,
    batch_account_cache: *BatchAccountCache,
) ?struct { CachedAccount, u64 } {
    const nonce_is_advanceable = !transaction.recent_blockhash.eql(next_durable_nonce.*);
    if (!nonce_is_advanceable) return null;

    const cached_account, const nonce_data = loadMessageNonceAccount(
        transaction,
        batch_account_cache,
    ) orelse return null;

    const previous_lamports_per_signature = nonce_data.lamports_per_signature;
    const next_nonce_state = NonceVersions{
        .Current = NonceState{
            .Initialized = .{
                .authority = nonce_data.authority,
                .durable_nonce = next_durable_nonce.*,
                .lamports_per_signature = next_lamports_per_signature,
            },
        },
    };

    // could probably be smaller
    var serialize_buf: [@sizeOf(NonceData) * 2]u8 = undefined;
    const new_data = sig.bincode.writeToSlice(&serialize_buf, next_nonce_state, .{}) catch
        return null;

    @memcpy(cached_account.account.data, new_data);

    return .{ cached_account, previous_lamports_per_signature };
}

fn loadMessageNonceAccount(
    transaction: *const RuntimeTransaction,
    batch_account_cache: *BatchAccountCache,
) ?struct { CachedAccount, NonceData } {
    const nonce_address = getDurableNonce(transaction) orelse
        return null;
    const nonce_account = batch_account_cache.account_cache.getPtr(nonce_address) orelse
        return null;
    const nonce_data = verifyNonceAccount(nonce_account.*, &transaction.recent_blockhash) orelse
        return null;

    const signers = transaction.instruction_infos[
        NONCED_TX_MARKER_IX_INDEX
    ].getSigners();

    // check nonce is authorised
    for (signers.slice()) |signer| {
        if (signer.equals(&nonce_data.authority)) break;
    } else return null;

    return .{
        .{ .pubkey = nonce_address, .account = nonce_account },
        nonce_data,
    };
}

const NonceData = struct {
    authority: Pubkey,
    durable_nonce: Hash,
    lamports_per_signature: u64,
};

const NonceState = union(enum) {
    Uninitialized,
    Initialized: NonceData,
};

const NonceVersions = union(enum) {
    Legacy: NonceState,
    Current: NonceState,

    fn verifyRecentBlockHash(
        self: *const NonceVersions,
        recent_blockhash: *const Hash,
    ) ?*const NonceData {
        return switch (self.*) {
            .Legacy => null,
            .Current => |state| switch (state) {
                .Uninitialized => null,
                .Initialized => |*data| if (recent_blockhash.eql(data.durable_nonce))
                    data
                else
                    null,
            },
        };
    }
};

fn verifyNonceAccount(account: AccountSharedData, recent_blockhash: *const Hash) ?NonceData {
    if (!account.owner.equals(&sig.runtime.program.system_program.ID)) return null;

    // could probably be smaller
    var deserialize_buf: [@sizeOf(NonceData) * 2]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&deserialize_buf);

    const nonce = sig.bincode.readFromSlice(fba.allocator(), NonceVersions, account.data, .{}) catch
        return null;

    const nonce_data = nonce.verifyRecentBlockHash(recent_blockhash) orelse
        return null;

    return nonce_data.*;
}

// [agave] https://github.com/anza-xyz/agave/blob/eb416825349ca376fa13249a0267cf7b35701938/svm-transaction/src/svm_message.rs#L84
/// If the message uses a durable nonce, return the pubkey of the nonce account
fn getDurableNonce(transaction: *const RuntimeTransaction) ?Pubkey {
    if (transaction.instruction_infos.len <= 0) return null;
    const instruction = transaction.instruction_infos[NONCED_TX_MARKER_IX_INDEX];

    const serialized_size = 4;
    if (instruction.instruction_data.len < serialized_size) return null;

    const account_keys = transaction.accounts.items(.pubkey);
    if (account_keys.len == 0) return null;

    const program_account_idx = instruction.program_meta.index_in_transaction;
    if (program_account_idx >= account_keys.len) return null;
    const program_key = account_keys[program_account_idx];

    if (!program_key.equals(&sig.runtime.program.system_program.ID)) return null;

    // Serialized value of [`SystemInstruction::AdvanceNonceAccount`].
    const serialized_advance_nonce_account: [serialized_size]u8 = @bitCast(
        std.mem.nativeToLittle(u32, 4),
    );

    if (instruction.instruction_data[0..4] != &serialized_advance_nonce_account) return null;
    if (!instruction.account_metas.get(0).is_writable) return null;

    const nonce_meta = instruction.account_metas.get(0);
    if (!nonce_meta.is_writable) return null;
    if (nonce_meta.index_in_transaction >= account_keys.len) return null;
    return account_keys[nonce_meta.index_in_transaction];
}

fn isTransactionAlreadyProcessed(
    msg_hash: *const Hash,
    recent_blockhash: *const Hash,
    ancestors: *const sig.core.status_cache.Ancestors,
    status_cache: *const sig.core.StatusCache,
) bool {
    return status_cache.getStatus(&msg_hash.data, recent_blockhash, ancestors) != null;
}
