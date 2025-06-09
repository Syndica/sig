const std = @import("std");
const sig = @import("../sig.zig");

const Hash = sig.core.Hash;
const Ancestors = sig.core.status_cache.Ancestors;
const BlockhashQueue = sig.core.bank.BlockhashQueue;
const Pubkey = sig.core.Pubkey;

const TransactionError = sig.ledger.transaction_status.TransactionError;

const AccountSharedData = sig.runtime.AccountSharedData;
const BatchAccountCache = sig.runtime.account_loader.BatchAccountCache;
const CachedAccount = sig.runtime.account_loader.CachedAccount;
const NonceData = sig.runtime.nonce.Data;
const NonceState = sig.runtime.nonce.State;
const NonceVersions = sig.runtime.nonce.Versions;
const RuntimeTransaction = sig.runtime.transaction_execution.RuntimeTransaction;
const TransactionResult = sig.runtime.transaction_execution.TransactionResult;

pub const CheckResult = ?error{ AlreadyProcessed, BlockhashNotFound };

const NONCED_TX_MARKER_IX_INDEX = 0;

/// [agave] https://github.com/firedancer-io/agave/blob/403d23b809fc513e2c4b433125c127cf172281a2/runtime/src/bank/check_transactions.rs#L186
pub fn checkStatusCache(
    msg_hash: *const Hash,
    recent_blockhash: *const Hash,
    ancestors: *const Ancestors,
    status_cache: *const sig.core.StatusCache,
) ?TransactionError {
    if (status_cache.getStatus(&msg_hash.data, recent_blockhash, ancestors) != null)
        return .AlreadyProcessed;
    return null;
}

/// Requires full transaction to find nonce account in the event that the transactions recent blockhash
/// is not in the blockhash queue within the max age. Also worth noting that Agave returns a CheckTransactionDetails
/// struct which contains a lamports_per_signature field which is unused, hence we return only the nonce account
/// if it exists.
/// [agave] https://github.com/firedancer-io/agave/blob/403d23b809fc513e2c4b433125c127cf172281a2/runtime/src/bank/check_transactions.rs#L105
pub fn checkAge(
    transaction: *const RuntimeTransaction,
    batch_account_cache: *const BatchAccountCache,
    blockhash_queue: *const BlockhashQueue,
    max_age: u64,
    next_durable_nonce: *const Hash,
    next_lamports_per_signature: u64,
) TransactionResult(?CachedAccount) {
    if (blockhash_queue.getHashInfoIfValid(&transaction.recent_blockhash, max_age) != null) {
        return .{ .ok = null };
    }

    if (checkLoadAndAdvanceMessageNonceAccount(
        transaction,
        next_durable_nonce,
        next_lamports_per_signature,
        batch_account_cache,
    )) |nonce| {
        const nonce_account = nonce.@"0";
        return .{ .ok = nonce_account };
    }

    return .{ .err = .BlockhashNotFound };
}

fn checkLoadAndAdvanceMessageNonceAccount(
    transaction: *const RuntimeTransaction,
    next_durable_nonce: *const Hash,
    next_lamports_per_signature: u64,
    batch_account_cache: *const BatchAccountCache,
) ?struct { CachedAccount, u64 } {
    if (transaction.recent_blockhash.eql(next_durable_nonce.*)) return null;

    const cached_account, const nonce_data = loadMessageNonceAccount(
        transaction,
        batch_account_cache,
    ) orelse return null;

    const previous_lamports_per_signature = nonce_data.fee_calculator.lamports_per_signature;
    const next_nonce_state = NonceVersions{
        .current = NonceState{
            .initialized = .{
                .authority = nonce_data.authority,
                .durable_nonce = next_durable_nonce.*,
                .fee_calculator = .{
                    .lamports_per_signature = next_lamports_per_signature,
                },
            },
        },
    };

    var serialize_buf: [NonceVersions.SERIALIZED_SIZE]u8 = undefined;
    const new_data = sig.bincode.writeToSlice(&serialize_buf, next_nonce_state, .{}) catch
        return null;

    @memcpy(cached_account.account.data, new_data);

    return .{ cached_account, previous_lamports_per_signature };
}

fn loadMessageNonceAccount(
    transaction: *const RuntimeTransaction,
    batch_account_cache: *const BatchAccountCache,
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

fn verifyNonceAccount(account: AccountSharedData, recent_blockhash: *const Hash) ?NonceData {
    if (!account.owner.equals(&sig.runtime.program.system.ID)) return null;

    // could probably be smaller
    var deserialize_buf: [@sizeOf(NonceData) * 2]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&deserialize_buf);

    const nonce = sig.bincode.readFromSlice(fba.allocator(), NonceVersions, account.data, .{}) catch
        return null;

    const nonce_data = nonce.verify(recent_blockhash.*) orelse
        return null;

    return nonce_data;
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

    if (!program_key.equals(&sig.runtime.program.system.ID)) return null;

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

test checkStatusCache {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(0);

    var ancestors = Ancestors{};
    defer ancestors.deinit(allocator);

    var status_cache = sig.core.StatusCache.default();
    defer status_cache.deinit(allocator);

    const msg_hash = Hash.generateSha256("msg hash");
    const recent_blockhash = Hash.generateSha256("recent blockhash");

    try std.testing.expectEqual(
        null,
        checkStatusCache(
            &msg_hash,
            &recent_blockhash,
            &ancestors,
            &status_cache,
        ),
    );

    try ancestors.ancestors.put(allocator, 0, {});
    try status_cache.insert(allocator, prng.random(), &recent_blockhash, &msg_hash.data, 0);

    try std.testing.expectEqual(
        .AlreadyProcessed,
        checkStatusCache(
            &msg_hash,
            &recent_blockhash,
            &ancestors,
            &status_cache,
        ),
    );
}

test checkAge {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(0);

    { // Check that a transaction with a valid recent blockhash is okay
        const max_age = 5;
        const recent_blockhash = Hash.initRandom(prng.random());

        const transaction = RuntimeTransaction{
            .signature_count = 0,
            .fee_payer = Pubkey.ZEROES,
            .msg_hash = Hash.ZEROES,
            .recent_blockhash = recent_blockhash,
            .instruction_infos = &.{},
        };

        const blockhash_queue = BlockhashQueue{
            .last_hash = null,
            .max_age = max_age,
            .ages = try .init(
                allocator,
                &.{recent_blockhash},
                &.{.{
                    .fee_calculator = .{ .lamports_per_signature = 5000 },
                    .hash_index = 31,
                    .timestamp = 0,
                }},
            ),
            .last_hash_index = 35,
        };
        defer blockhash_queue.deinit(allocator);

        const result = checkAge(
            &transaction,
            &BatchAccountCache{},
            &blockhash_queue,
            max_age,
            &Hash.ZEROES,
            0,
        );

        try std.testing.expectEqual(result.ok, null);
    }
}
