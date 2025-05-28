const std = @import("std");
const sig = @import("../sig.zig");

const Hash = sig.core.Hash;
const Ancestors = sig.core.status_cache.Ancestors;
const BlockhashQueue = sig.core.bank.BlockhashQueue;
const Pubkey = sig.core.Pubkey;
const RentCollector = sig.core.rent_collector.RentCollector;

const account_loader = sig.runtime.account_loader;
const AccountSharedData = sig.runtime.AccountSharedData;
const BatchAccountCache = sig.runtime.account_loader.BatchAccountCache;
const CachedAccount = sig.runtime.account_loader.CachedAccount;
const ComputeBudgetLimits = sig.runtime.program.compute_budget.ComputeBudgetLimits;
const CopiedAccount = sig.runtime.transaction_execution.CopiedAccount;
const FeatureSet = sig.runtime.FeatureSet;
const LoadedTransactionAccount = BatchAccountCache.LoadedTransactionAccount;
const NonceData = sig.runtime.nonce.Data;
const NonceState = sig.runtime.nonce.State;
const NonceVersions = sig.runtime.nonce.Versions;
const RuntimeTransaction = sig.runtime.transaction_execution.RuntimeTransaction;
const TransactionResult = sig.runtime.transaction_execution.TransactionResult;
const TransactionRollbacks = sig.runtime.transaction_execution.TransactionRollbacks;

const TransactionError = sig.ledger.transaction_status.TransactionError;

pub const CheckResult = ?error{ AlreadyProcessed, BlockhashNotFound };

const NONCED_TX_MARKER_IX_INDEX = 0;

/// [agave] https://github.com/firedancer-io/agave/blob/403d23b809fc513e2c4b433125c127cf172281a2/runtime/src/bank/check_transactions.rs#L186
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

/// Requires full transaction to find nonce account in the event that the transactions recent blockhash
/// is not in the blockhash queue within the max age. Also worth noting that Agave returns a CheckTransactionDetails
/// struct which contains a lamports_per_signature field which is unused, hence we return only the nonce account
/// if it exists.
/// [agave] https://github.com/firedancer-io/agave/blob/403d23b809fc513e2c4b433125c127cf172281a2/runtime/src/bank/check_transactions.rs#L105
pub fn checkAge(
    transaction: *const RuntimeTransaction,
    batch_account_cache: *BatchAccountCache,
    blockhash_queue: *const BlockhashQueue,
    max_age: u64,
    last_blockhash: *const Hash,
    next_durable_nonce: *const Hash,
    next_lamports_per_signature: u64,
) TransactionResult(?CachedAccount) {
    if (blockhash_queue.getHashInfoIfValid(last_blockhash, max_age) != null) {
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

/// [agave] https://github.com/anza-xyz/agave/blob/d70b1714b1153674c16e2b15b68790d274dfe953/svm/src/transaction_processor.rs#L557
pub fn checkFeePayer(
    /// same allocator as batch account cache
    allocator: std.mem.Allocator,
    transaction: *const RuntimeTransaction,
    batch_account_cache: *BatchAccountCache,
    compute_budget_limits: *const ComputeBudgetLimits,
    nonce_account: ?CachedAccount,
    rent_collector: *const RentCollector,
    feature_set: *const FeatureSet,
    lamports_per_signature: u64,
) error{OutOfMemory}!TransactionResult(struct {
    FeeDetails,
    TransactionRollbacks,
    LoadedTransactionAccount,
}) {
    const enable_secp256r1 = feature_set.active.contains(
        sig.runtime.features.ENABLE_SECP256R1_PRECOMPILE,
    );

    const fee_payer_key = transaction.accounts.items(.pubkey)[0];

    var loaded_fee_payer = try batch_account_cache.loadAccount(
        allocator,
        transaction,
        &fee_payer_key,
        true,
    ) orelse return .{ .err = .AccountNotFound };

    const fee_payer_loaded_rent_epoch = loaded_fee_payer.account.rent_epoch;

    loaded_fee_payer.rent_collected = account_loader.collectRentFromAccount(
        loaded_fee_payer.account,
        &fee_payer_key,
        feature_set,
        rent_collector,
    ).rent_amount;

    const fee_budget_limits = FeeBudgetLimits.fromComputeBudgetLimits(compute_budget_limits.*);
    const fee_details = if (lamports_per_signature == 0) FeeDetails.DEFAULT else fee: {
        const signature_counts = SignatureCounts.fromTransaction(transaction);
        break :fee FeeDetails.init(
            signature_counts,
            lamports_per_signature,
            enable_secp256r1,
            fee_budget_limits.prioritization_fee,
        );
    };

    const cached_fee_payer_account: CachedAccount = .{
        .pubkey = fee_payer_key,
        .account = loaded_fee_payer.account,
    };

    if (validateFeePayer(
        cached_fee_payer_account,
        rent_collector,
        fee_details.total(),
    )) |validation_error| return .{ .err = validation_error };

    const rollback_accounts = try TransactionRollbacks.new(
        allocator,
        nonce_account,
        cached_fee_payer_account,
        loaded_fee_payer.rent_collected,
        fee_payer_loaded_rent_epoch,
    );

    return .{
        .ok = .{ fee_details, rollback_accounts, loaded_fee_payer },
    };
}

/// [agave] https://github.com/anza-xyz/agave/blob/dad81b9b2ecf81ceb518dd9f7cc91e83ba33bda8/fee/src/lib.rs#L85
const SignatureCounts = struct {
    num_transaction_signatures: u64,
    num_ed25519_signatures: u64,
    num_secp256k1_signatures: u64,
    num_secp256r1_signatures: u64,

    // [agave] https://github.com/anza-xyz/agave/blob/eb416825349ca376fa13249a0267cf7b35701938/svm-transaction/src/svm_message.rs#L139
    fn sumPrecompileSigs(
        transaction: *const RuntimeTransaction,
        precompile: *const Pubkey,
    ) u64 {
        var n_signatures: u64 = 0;
        for (transaction.instruction_infos) |instr_info| {
            if (instr_info.program_meta.pubkey.equals(precompile)) continue;
            if (instr_info.instruction_data.len == 0) continue;
            n_signatures += instr_info.instruction_data[0];
        }
        return n_signatures;
    }

    // [agave] https://github.com/anza-xyz/agave/blob/eb416825349ca376fa13249a0267cf7b35701938/svm-transaction/src/svm_message.rs#L139
    fn fromTransaction(transaction: *const RuntimeTransaction) SignatureCounts {
        const precompiles = sig.runtime.program.precompiles;

        return .{
            .num_ed25519_signatures = sumPrecompileSigs(transaction, &precompiles.ed25519.ID),
            .num_secp256k1_signatures = sumPrecompileSigs(transaction, &precompiles.secp256k1.ID),
            .num_secp256r1_signatures = sumPrecompileSigs(transaction, &precompiles.secp256r1.ID),
            .num_transaction_signatures = transaction.signature_count,
        };
    }
};

pub const FeeDetails = struct {
    transaction_fee: u64,
    prioritization_fee: u64,

    const DEFAULT: FeeDetails = .{ .transaction_fee = 0, .prioritization_fee = 0 };

    fn init(
        sig_counts: SignatureCounts,
        lamports_per_signature: u64,
        enable_secp256r1: bool,
        prioritization_fee: u64,
    ) FeeDetails {
        return .{
            .transaction_fee = calculateSignatureFee(
                sig_counts,
                lamports_per_signature,
                enable_secp256r1,
            ),
            .prioritization_fee = prioritization_fee,
        };
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/dad81b9b2ecf81ceb518dd9f7cc91e83ba33bda8/fee/src/lib.rs#L66
    fn calculateSignatureFee(
        sig_counts: SignatureCounts,
        lamports_per_signature: u64,
        enable_secp256r1: bool,
    ) u64 {
        const sig_count = sig_counts.num_transaction_signatures +|
            sig_counts.num_ed25519_signatures +|
            sig_counts.num_secp256k1_signatures +|
            if (enable_secp256r1) sig_counts.num_secp256r1_signatures else 0;

        return sig_count *| lamports_per_signature;
    }

    fn total(self: FeeDetails) u64 {
        return self.prioritization_fee +| self.transaction_fee;
    }
};

const FeeBudgetLimits = struct {
    /// non-zero
    loaded_accounts_data_size_limit: u32,
    heap_cost: u64,
    compute_unit_limit: u64,
    prioritization_fee: u64,

    // [agave] https://github.com/anza-xyz/agave/blob/3e9af14f3a145070773c719ad104b6a02aefd718/compute-budget/src/compute_budget_limits.rs#L20
    const MICRO_LAMPORTS_PER_LAMPORT = 1_000_000;
    const DEFAULT_HEAP_COST = 8;

    fn getPrioritizationFee(compute_unit_price: u64, compute_unit_limit: u64) u64 {
        const micro_lamport_fee = @as(u128, compute_unit_price) *| @as(u128, compute_unit_limit);

        return std.math.cast(
            u64,
            (micro_lamport_fee +| (MICRO_LAMPORTS_PER_LAMPORT -| 1)) / MICRO_LAMPORTS_PER_LAMPORT,
        ) orelse std.math.maxInt(u64);
    }

    fn fromComputeBudgetLimits(val: ComputeBudgetLimits) FeeBudgetLimits {
        const prioritization_fee = getPrioritizationFee(
            val.compute_unit_price,
            val.compute_unit_limit,
        );

        return .{
            .loaded_accounts_data_size_limit = val.loaded_accounts_bytes,
            .heap_cost = DEFAULT_HEAP_COST,
            .compute_unit_limit = val.compute_unit_limit,
            .prioritization_fee = prioritization_fee,
        };
    }
};

// [agave] https://github.com/anza-xyz/agave/blob/64b616042450fa6553427471f70895f1dfe0cd86/svm/src/account_loader.rs#L293
fn validateFeePayer(
    payer: CachedAccount,
    rent_collector: *const RentCollector,
    fee: u64,
) ?TransactionError {
    if (payer.account.lamports == 0) return .AccountNotFound;

    const system_account_kind = getSystemAccountKind(payer.account) orelse
        return .InvalidAccountForFee;

    const min_balance = switch (system_account_kind) {
        .System => 0,
        .Nonce => rent_collector.rent.minimumBalance(NonceState.SIZE),
    };

    if (payer.account.lamports < min_balance) return .InsufficientFundsForFee;

    const pre_rent_state = rent_collector.getAccountRentState(
        payer.account.lamports,
        payer.account.data.len,
    );

    payer.account.lamports = std.math.sub(u64, payer.account.lamports, fee) catch
        return .InsufficientFundsForFee;

    const post_rent_state = rent_collector.getAccountRentState(
        payer.account.lamports,
        payer.account.data.len,
    );

    sig.core.rent_collector.RentCollector.checkRentStateWithAccount(
        pre_rent_state,
        post_rent_state,
        &payer.pubkey,
    ) catch
        return .{ .InsufficientFundsForRent = .{ .account_index = 0 } };

    return null;
}

const SystemAccountKind = enum { System, Nonce };

// [agave] https://github.com/anza-xyz/agave/blob/64b616042450fa6553427471f70895f1dfe0cd86/svm/src/account_loader.rs#L293
fn getSystemAccountKind(account: *const AccountSharedData) ?SystemAccountKind {
    return switch (account.data.len) {
        else => null,
        0 => .System,
        NonceState.SIZE => {
            const versions = NonceVersions.deserialize(account.data) orelse
                return null;

            const state = versions.state();
            return switch (state) {
                .Uninitialized => null,
                .Initialized => .Nonce,
            };
        },
    };
}

fn checkLoadAndAdvanceMessageNonceAccount(
    transaction: *const RuntimeTransaction,
    next_durable_nonce: *const Hash,
    next_lamports_per_signature: u64,
    batch_account_cache: *BatchAccountCache,
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

    var serialize_buf: [NonceState.SERIALIZED_SIZE]u8 = undefined;
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

fn isTransactionAlreadyProcessed(
    msg_hash: *const Hash,
    recent_blockhash: *const Hash,
    ancestors: *const sig.core.status_cache.Ancestors,
    status_cache: *const sig.core.StatusCache,
) bool {
    return status_cache.getStatus(&msg_hash.data, recent_blockhash, ancestors) != null;
}
