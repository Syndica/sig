const std = @import("std");
const sig = @import("../sig.zig");
const tracy = @import("tracy");

const Allocator = std.mem.Allocator;

const Hash = sig.core.Hash;
const Ancestors = sig.core.Ancestors;
const BlockhashQueue = sig.core.BlockhashQueue;
const Pubkey = sig.core.Pubkey;
const RentCollector = sig.core.rent_collector.RentCollector;
const AccountMeta = sig.core.instruction.InstructionAccount;

const account_loader = sig.runtime.account_loader;
const AccountSharedData = sig.runtime.AccountSharedData;
const BatchAccountCache = sig.runtime.account_loader.BatchAccountCache;
const CachedAccount = sig.runtime.account_loader.CachedAccount;
const CopiedAccount = sig.runtime.transaction_execution.CopiedAccount;
const ComputeBudgetLimits = sig.runtime.program.compute_budget.ComputeBudgetLimits;
const FeatureSet = sig.core.FeatureSet;
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
    status_cache: *sig.core.StatusCache,
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
    allocator: Allocator,
    transaction: *const RuntimeTransaction,
    batch_account_cache: *const BatchAccountCache,
    blockhash_queue: *const BlockhashQueue,
    max_age: u64,
    next_durable_nonce: *const Hash,
    next_lamports_per_signature: u64,
) error{OutOfMemory}!TransactionResult(?CopiedAccount) {
    if (blockhash_queue.getHashInfoIfValid(transaction.recent_blockhash, max_age) != null) {
        return .{ .ok = null };
    }

    if (try checkLoadAndAdvanceMessageNonceAccount(
        allocator,
        transaction,
        next_durable_nonce,
        next_lamports_per_signature,
        batch_account_cache,
    )) |nonce| {
        const nonce_account = nonce[0];
        return .{ .ok = nonce_account };
    }

    return .{ .err = .BlockhashNotFound };
}

/// Checks that the payer can pay the fee and rent, AND mutates the underlying
/// account in the cache to collect both.
///
/// Returns the rollback accounts for the transaction, which includes a snapshot
/// of the fee payer after collecting fees (but not rent) and the copied nonce
/// account with its nonce already advanced.
///
/// Analogous to [validate_transaction_fee_payer](https://github.com/anza-xyz/agave/blob/d70b1714b1153674c16e2b15b68790d274dfe953/svm/src/transaction_processor.rs#L557)
pub fn checkFeePayer(
    /// same allocator as batch account cache
    allocator: Allocator,
    transaction: *const RuntimeTransaction,
    batch_account_cache: *BatchAccountCache,
    compute_budget_limits: *const ComputeBudgetLimits,
    /// Takes ownership of this
    nonce_account: ?CopiedAccount,
    rent_collector: *const RentCollector,
    feature_set: *const FeatureSet,
    slot: sig.core.Slot,
    lamports_per_signature: u64,
) error{OutOfMemory}!TransactionResult(struct {
    FeeDetails,
    TransactionRollbacks,
}) {
    var zone = tracy.Zone.init(@src(), .{ .name = "checkFeePayer" });
    defer zone.deinit();

    var nonce_account_is_owned = true;
    defer if (nonce_account_is_owned) if (nonce_account) |na| allocator.free(na.account.data);

    const enable_secp256r1 = feature_set.active(.enable_secp256r1_precompile, slot);
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
        slot,
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

    nonce_account_is_owned = false;
    const rollback_accounts = try TransactionRollbacks.init(
        allocator,
        nonce_account,
        cached_fee_payer_account,
        loaded_fee_payer.rent_collected,
        fee_payer_loaded_rent_epoch,
    );

    return .{ .ok = .{ fee_details, rollback_accounts } };
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
        for (transaction.instructions) |instr_info| {
            if (!instr_info.program_meta.pubkey.equals(precompile)) continue;
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
        .Nonce => rent_collector.rent.minimumBalance(NonceVersions.SERIALIZED_SIZE),
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

    if (RentCollector.checkRentStateWithAccount(
        pre_rent_state,
        post_rent_state,
        &payer.pubkey,
        0, // Fee payer is always at index 0
    )) |err| return err;

    return null;
}

const SystemAccountKind = enum { System, Nonce };

// [agave] https://github.com/anza-xyz/agave/blob/64b616042450fa6553427471f70895f1dfe0cd86/svm/src/account_loader.rs#L293
fn getSystemAccountKind(account: *const AccountSharedData) ?SystemAccountKind {
    if (!account.owner.equals(&sig.runtime.program.system.ID)) return null;
    if (account.data.len == 0) return .System;
    if (account.data.len == NonceVersions.SERIALIZED_SIZE) {
        const versions = NonceVersions.fromAccountData(account.data) orelse
            return null;

        const state = versions.getState();
        return switch (state) {
            .uninitialized => null,
            .initialized => .Nonce,
        };
    }
    return null;
}

fn checkLoadAndAdvanceMessageNonceAccount(
    allocator: Allocator,
    transaction: *const RuntimeTransaction,
    next_durable_nonce: *const Hash,
    next_lamports_per_signature: u64,
    batch_account_cache: *const BatchAccountCache,
) error{OutOfMemory}!?struct { CopiedAccount, u64 } {
    if (transaction.recent_blockhash.eql(next_durable_nonce.*)) return null;

    const cached_account, const nonce_data = loadMessageNonceAccount(
        transaction,
        batch_account_cache,
    ) orelse return null;

    const previous_lamports_per_signature = nonce_data.lamports_per_signature;
    const next_nonce_state = NonceVersions{
        .current = NonceState{
            .initialized = .{
                .authority = nonce_data.authority,
                .durable_nonce = next_durable_nonce.*,
                .lamports_per_signature = next_lamports_per_signature,
            },
        },
    };

    const new_data = sig.bincode.writeAlloc(allocator, next_nonce_state, .{}) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    };

    return .{
        CopiedAccount.init(cached_account, new_data, cached_account.account.lamports),
        previous_lamports_per_signature,
    };
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

    const signers = transaction.instructions[
        NONCED_TX_MARKER_IX_INDEX
    ].getSigners();

    // check nonce is authorised
    for (signers.constSlice()) |signer| {
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

    const nonce_data = nonce.verify(recent_blockhash.*) orelse return null;

    return nonce_data;
}

// [agave] https://github.com/anza-xyz/agave/blob/eb416825349ca376fa13249a0267cf7b35701938/svm-transaction/src/svm_message.rs#L84
/// If the message uses a durable nonce, return the pubkey of the nonce account
fn getDurableNonce(transaction: *const RuntimeTransaction) ?Pubkey {
    if (transaction.instructions.len <= 0) return null;
    const instruction = transaction.instructions[NONCED_TX_MARKER_IX_INDEX];

    if (instruction.account_metas.len == 0) return null;

    const serialized_size = 4;
    if (instruction.instruction_data.len < serialized_size) return null;

    const account_keys = transaction.accounts.items(.pubkey);
    if (account_keys.len == 0) return null;

    const program_account_idx = instruction.program_meta.index_in_transaction;
    if (program_account_idx >= account_keys.len) return null;
    const program_key = account_keys[program_account_idx];

    if (!program_key.equals(&sig.runtime.program.system.ID)) return null;

    if (!std.mem.eql(
        u8,
        instruction.instruction_data[0..4],
        &.{ 4, 0, 0, 0 }, // SystemInstruction::AdvanceNonceAccount
    )) return null;

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

    var status_cache: sig.core.StatusCache = .DEFAULT;
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

test "checkAge: recent blockhash" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(0);

    const max_age = 5;
    const recent_blockhash = Hash.initRandom(prng.random());

    const transaction = RuntimeTransaction{
        .signature_count = 0,
        .fee_payer = Pubkey.ZEROES,
        .msg_hash = Hash.ZEROES,
        .recent_blockhash = recent_blockhash,
        .instructions = &.{},
    };

    var blockhash_queue = try BlockhashQueue.initWithSingleEntry(
        allocator,
        recent_blockhash,
        5000,
    );
    defer blockhash_queue.deinit(allocator);

    { // Check valid recent blockhash ok
        for (0..max_age) |_| {
            blockhash_queue.last_hash_index += 1;

            const result = try checkAge(
                allocator,
                &transaction,
                &BatchAccountCache{},
                &blockhash_queue,
                max_age,
                &Hash.ZEROES,
                0,
            );

            try std.testing.expectEqual(null, result.ok);
        }
    }

    { // Check invalid recent blockhash err
        blockhash_queue.last_hash_index += 1;

        const result = try checkAge(
            allocator,
            &transaction,
            &BatchAccountCache{},
            &blockhash_queue,
            max_age,
            &Hash.ZEROES,
            0,
        );

        try std.testing.expectEqual(TransactionError.BlockhashNotFound, result.err);
    }
}

test "checkAge: nonce account" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(0);

    const nonce_key = Pubkey.initRandom(prng.random());
    const nonce_authority_key = Pubkey.initRandom(prng.random());
    const recent_blockhash = Hash.initRandom(prng.random());
    const next_durable_nonce = Hash.initRandom(prng.random());

    const nonce_account = AccountSharedData{
        .lamports = 0,
        .owner = sig.runtime.program.system.ID,
        .data = try sig.bincode.writeAlloc(
            allocator,
            sig.runtime.nonce.Versions{ .current = .{
                .initialized = .{
                    .authority = nonce_authority_key,
                    .durable_nonce = recent_blockhash,
                    .lamports_per_signature = 5000,
                },
            } },
            .{},
        ),
        .executable = false,
        .rent_epoch = 0,
    };

    var account_cache = BatchAccountCache{};
    defer account_cache.deinit(allocator);
    try account_cache.account_cache.put(allocator, nonce_key, nonce_account);

    const instruction_data = try sig.bincode.writeAlloc(
        allocator,
        sig.runtime.program.system.Instruction.advance_nonce_account,
        .{},
    );
    defer allocator.free(instruction_data);

    var accounts = std.MultiArrayList(AccountMeta){};
    defer accounts.deinit(allocator);
    try accounts.append(
        allocator,
        .{ .pubkey = sig.runtime.program.system.ID, .is_signer = false, .is_writable = false },
    );
    try accounts.append(
        allocator,
        .{ .pubkey = nonce_key, .is_signer = false, .is_writable = true },
    );
    try accounts.append(
        allocator,
        .{ .pubkey = nonce_authority_key, .is_signer = true, .is_writable = false },
    );

    const transaction = RuntimeTransaction{
        .signature_count = 0,
        .fee_payer = Pubkey.ZEROES,
        .msg_hash = Hash.ZEROES,
        .recent_blockhash = recent_blockhash,
        .instructions = &.{.{
            .program_meta = .{ .pubkey = sig.runtime.program.system.ID, .index_in_transaction = 0 },
            .account_metas = try sig.runtime.InstructionInfo.AccountMetas.fromSlice(&.{
                .{
                    .pubkey = nonce_key,
                    .index_in_transaction = 1,
                    .index_in_caller = 1,
                    .index_in_callee = 1,
                    .is_signer = false,
                    .is_writable = true,
                },
                .{
                    .pubkey = nonce_authority_key,
                    .index_in_transaction = 2,
                    .index_in_caller = 2,
                    .index_in_callee = 2,
                    .is_signer = true,
                    .is_writable = false,
                },
            }),
            .instruction_data = instruction_data,
            .initial_account_lamports = 0,
        }},
        .accounts = accounts,
    };

    var blockhash_queue = BlockhashQueue{
        .last_hash = null,
        .max_age = 0,
        .hash_infos = .{},
        .last_hash_index = 0,
    };

    const result = try checkAge(
        allocator,
        &transaction,
        &account_cache,
        &blockhash_queue,
        0,
        &next_durable_nonce,
        5001,
    );
    defer if (result.ok) |account| allocator.free(account.account.data);

    switch (result) {
        .ok => |ca| {
            try std.testing.expectEqualSlices(
                u8,
                &nonce_key.data,
                &ca.?.pubkey.data,
            );
            const nv = try sig.bincode.readFromSlice(
                allocator,
                sig.runtime.nonce.Versions,
                ca.?.account.data,
                .{},
            );
            try std.testing.expectEqualSlices(
                u8,
                &nv.getState().initialized.authority.data,
                &nonce_authority_key.data,
            );
            try std.testing.expectEqualSlices(
                u8,
                &nv.getState().initialized.durable_nonce.data,
                &next_durable_nonce.data,
            );
            try std.testing.expectEqual(
                5001,
                nv.getState().initialized.lamports_per_signature,
            );
        },
        .err => return error.ExpectedOk,
    }
}

test "checkFeePayer: happy path fee payer only" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(0);

    const recent_blockhash = Hash.initRandom(prng.random());

    var transaction = RuntimeTransaction{
        .signature_count = 1,
        .fee_payer = Pubkey.initRandom(prng.random()),
        .msg_hash = Hash.ZEROES,
        .recent_blockhash = recent_blockhash,
        .instructions = &.{},
    };
    defer transaction.accounts.deinit(allocator);

    try transaction.accounts.append(
        allocator,
        .{ .pubkey = transaction.fee_payer, .is_signer = true, .is_writable = true },
    );

    var account_cache = BatchAccountCache{};
    defer account_cache.deinit(allocator);

    try account_cache.account_cache.put(allocator, transaction.fee_payer, .{
        .lamports = 1_000_000,
        .owner = sig.runtime.program.system.ID,
        .data = &.{},
        .executable = false,
        .rent_epoch = 0,
    });

    const result = try checkFeePayer(
        allocator,
        &transaction,
        &account_cache,
        &ComputeBudgetLimits.DEFAULT,
        null,
        &sig.core.rent_collector.defaultCollector(10),
        &sig.core.FeatureSet.ALL_DISABLED,
        0,
        5000,
    );

    const fee_details, const rollbacks = result.ok;

    try std.testing.expectEqual(5000, fee_details.transaction_fee);
    try std.testing.expectEqual(0, fee_details.prioritization_fee);

    try std.testing.expectEqual(995_000, rollbacks.fee_payer_only.account.lamports);
    try std.testing.expectEqual(0, rollbacks.fee_payer_only.account.rent_epoch);
}

test "checkFeePayer: happy path with same nonce and fee payer" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(0);

    const recent_blockhash = Hash.initRandom(prng.random());

    var transaction = RuntimeTransaction{
        .signature_count = 1,
        .fee_payer = Pubkey.initRandom(prng.random()),
        .msg_hash = Hash.ZEROES,
        .recent_blockhash = recent_blockhash,
        .instructions = &.{},
    };
    defer transaction.accounts.deinit(allocator);

    try transaction.accounts.append(
        allocator,
        .{ .pubkey = transaction.fee_payer, .is_signer = true, .is_writable = true },
    );

    var account_cache = BatchAccountCache{};
    defer account_cache.deinit(allocator);

    try account_cache.account_cache.put(allocator, transaction.fee_payer, .{
        .lamports = 1_000_000,
        .owner = sig.runtime.program.system.ID,
        .data = &.{},
        .executable = false,
        .rent_epoch = 0,
    });

    const nonce_account = AccountSharedData{
        .lamports = 1_000,
        .owner = sig.runtime.program.system.ID,
        .data = try allocator.dupe(u8, &.{ 0, 0, 0, 0 }),
        .executable = false,
        .rent_epoch = 0,
    };

    const result = try checkFeePayer(
        allocator,
        &transaction,
        &account_cache,
        &ComputeBudgetLimits.DEFAULT,
        .{ .pubkey = transaction.fee_payer, .account = nonce_account },
        &sig.core.rent_collector.defaultCollector(10),
        &sig.core.FeatureSet.ALL_DISABLED,
        0,
        5000,
    );

    const fee_details, const rollbacks = result.ok;
    defer rollbacks.deinit(allocator);

    const rollback_account = rollbacks.same_nonce_and_fee_payer.account;

    try std.testing.expectEqual(5000, fee_details.transaction_fee);
    try std.testing.expectEqual(0, fee_details.prioritization_fee);
    try std.testing.expectEqual(995_000, rollback_account.lamports);
    try std.testing.expectEqual(std.math.maxInt(u64), rollback_account.rent_epoch);
}

test "checkFeePayer: happy path with separate nonce and fee payer" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(0);

    const recent_blockhash = Hash.initRandom(prng.random());

    var transaction = RuntimeTransaction{
        .signature_count = 1,
        .fee_payer = Pubkey.initRandom(prng.random()),
        .msg_hash = Hash.ZEROES,
        .recent_blockhash = recent_blockhash,
        .instructions = &.{},
    };
    defer transaction.accounts.deinit(allocator);

    try transaction.accounts.append(
        allocator,
        .{ .pubkey = transaction.fee_payer, .is_signer = true, .is_writable = true },
    );

    var account_cache = BatchAccountCache{};
    defer account_cache.deinit(allocator);

    try account_cache.account_cache.put(allocator, transaction.fee_payer, .{
        .lamports = 1_000_000,
        .owner = sig.runtime.program.system.ID,
        .data = &.{},
        .executable = false,
        .rent_epoch = 0,
    });

    const nonce_account = AccountSharedData{
        .lamports = 1_000,
        .owner = sig.runtime.program.system.ID,
        .data = try allocator.dupe(u8, &.{ 0, 0, 0, 0 }),
        .executable = false,
        .rent_epoch = 0,
    };

    const result = try checkFeePayer(
        allocator,
        &transaction,
        &account_cache,
        &ComputeBudgetLimits.DEFAULT,
        .{ .pubkey = Pubkey.initRandom(prng.random()), .account = nonce_account },
        &sig.core.rent_collector.defaultCollector(10),
        &sig.core.FeatureSet.ALL_DISABLED,
        0,
        5000,
    );

    const fee_details, const rollbacks = result.ok;
    defer rollbacks.deinit(allocator);

    const rollback_nonce_account = rollbacks.separate_nonce_and_fee_payer[0].account;
    const rollback_fee_payer_account = rollbacks.separate_nonce_and_fee_payer[1].account;

    try std.testing.expectEqual(5000, fee_details.transaction_fee);
    try std.testing.expectEqual(0, fee_details.prioritization_fee);
    try std.testing.expectEqual(1_000, rollback_nonce_account.lamports);
    try std.testing.expectEqual(0, rollback_nonce_account.rent_epoch);
    try std.testing.expectEqual(995_000, rollback_fee_payer_account.lamports);
    try std.testing.expectEqual(std.math.maxInt(u64), rollback_fee_payer_account.rent_epoch);
}
