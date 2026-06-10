const std = @import("std");
const std14 = @import("std14");
const sig = @import("../lib.zig");
const tracy = @import("tracy");

const Allocator = std.mem.Allocator;

const AccountReader = sig.runtime.execution_interfaces.AccountReader;

const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const RentCollector = sig.core.rent_collector.RentCollector;
const AccountMeta = sig.core.instruction.InstructionAccount;

const account_loader = sig.runtime.account_loader;
const AccountSharedData = sig.runtime.AccountSharedData;
const LoadedAccount = sig.runtime.account_loader.LoadedAccount;
const PreparedAccount = sig.runtime.account_loader.PreparedAccount;
const ComputeBudgetLimits = sig.runtime.program.compute_budget.ComputeBudgetLimits;
const NonceData = sig.runtime.nonce.Data;
const NonceState = sig.runtime.nonce.State;
const NonceVersions = sig.runtime.nonce.Versions;
const RuntimeTransaction = sig.runtime.transaction_execution.RuntimeTransaction;
const TransactionResult = sig.runtime.transaction_execution.TransactionResult;

const TransactionError = sig.core.transaction_error.TransactionError;

const deinitAccountMap = sig.runtime.testing.deinitAccountMap;

const AccountLoadError = sig.runtime.execution_interfaces.AccountLoadError;

const NONCED_TX_MARKER_IX_INDEX = 0;

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
    accounts: AccountReader,
    compute_budget_limits: *const ComputeBudgetLimits,
    /// Takes ownership of this
    maybe_nonce: ?LoadedAccount,
    rent_collector: *const RentCollector,
    lamports_per_signature: u64,
) AccountLoadError!TransactionResult(struct {
    FeeDetails,
    std14.BoundedArray(LoadedAccount, 2),
    PreparedAccount,
}) {
    var zone = tracy.Zone.init(@src(), .{ .name = "checkFeePayer" });
    defer zone.deinit();

    var maybe_nonce_to_free = maybe_nonce;
    defer if (maybe_nonce_to_free) |na| na.deinit(allocator);

    const fee_payer_key = transaction.accounts.items(.pubkey)[0];
    var payer_account = try accounts.get(allocator, fee_payer_key) orelse
        return .{ .err = .AccountNotFound };
    // [agave] https://github.com/anza-xyz/agave/commit/d5757e29aa - formalize_loaded_transaction_data_size hardcoded
    const payer_loaded_size = account_loader.TRANSACTION_ACCOUNT_BASE_SIZE +| payer_account.data.len;
    errdefer payer_account.deinit(allocator);

    const fee_payer_loaded_rent_epoch = payer_account.rent_epoch;

    const rent_collected = account_loader.collectRentFromAccount(
        &payer_account,
        rent_collector,
    ).rent_amount;

    // NOTE: FeeDetails (transaction fee, prioritization fee) in Agave is set
    // at the same time that compute budget limits are calculated. This value
    // does not actually come from the fee rate governor, but rather a field
    // in the bank (fee_structure.lamports_per_signature).
    // The bank initialises this field using impl default for FeeStructure,
    // and never actually mutates it, meaning it remains the default value.
    // This means that lamports_per_signature is in effect *always* 5000, even
    // when the fee rate governor disagrees.
    //
    // [agave] https://github.com/anza-xyz/agave/blob/b6c96e84b10396b92912d4574dae7d03f606da26/runtime/src/bank/check_transactions.rs#L106-L112

    const fee_budget_limits = FeeBudgetLimits.fromComputeBudgetLimits(compute_budget_limits.*);
    const fee_details = FeeDetails.init(
        SignatureCounts.fromTransaction(transaction),
        lamports_per_signature,
        fee_budget_limits.prioritization_fee,
        compute_budget_limits.compute_unit_price,
    );

    if (validateFeePayer(
        fee_payer_key,
        &payer_account,
        rent_collector,
        fee_details.total(),
    )) |validation_error| {
        payer_account.deinit(allocator);
        return .{ .err = validation_error };
    }

    var rollbacks = std14.BoundedArray(LoadedAccount, 2){};
    errdefer for (rollbacks.slice()) |rollback| rollback.deinit(allocator);

    maybe_nonce_to_free = null;
    if (maybe_nonce != null and fee_payer_key.equals(&maybe_nonce.?.pubkey)) {
        rollbacks.append(.{
            .pubkey = maybe_nonce.?.pubkey,
            .account = .{
                .lamports = payer_account.lamports +| rent_collected,
                .data = maybe_nonce.?.account.data,
                .owner = maybe_nonce.?.account.owner,
                .executable = maybe_nonce.?.account.executable,
                .rent_epoch = payer_account.rent_epoch,
            },
        }) catch unreachable;
    } else {
        var rollback_payer = try payer_account.clone(allocator);
        if (maybe_nonce) |nonce|
            rollbacks.append(nonce) catch unreachable
        else
            rollback_payer.rent_epoch = fee_payer_loaded_rent_epoch;
        rollback_payer.lamports +|= rent_collected;
        rollbacks.append(.{
            .pubkey = fee_payer_key,
            .account = rollback_payer,
        }) catch unreachable;
    }

    return .{ .ok = .{ fee_details, rollbacks, .{
        .account = payer_account,
        .loaded_size = payer_loaded_size,
        .rent_collected = rent_collected,
    } } };
}

/// [agave] https://github.com/anza-xyz/agave/blob/dad81b9b2ecf81ceb518dd9f7cc91e83ba33bda8/fee/src/lib.rs#L85
pub const SignatureCounts = struct {
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
    pub fn fromTransaction(transaction: *const RuntimeTransaction) SignatureCounts {
        const precompiles = sig.runtime.program.precompiles;

        return .{
            .num_ed25519_signatures = sumPrecompileSigs(transaction, &precompiles.ed25519.ID),
            .num_secp256k1_signatures = sumPrecompileSigs(transaction, &precompiles.secp256k1.ID),
            .num_secp256r1_signatures = sumPrecompileSigs(transaction, &precompiles.secp256r1.ID),
            .num_transaction_signatures = transaction.signature_count,
        };
    }
};

pub const LAMPORTS_PER_SIGNATURE: u64 = 5_000;

pub const FeeDetails = struct {
    transaction_fee: u64,
    prioritization_fee: u64,
    /// The compute unit price in micro-lamports per compute unit.
    /// Used by PrioritizationFeeCache to track per-slot minimum fees for RPC queries.
    compute_unit_price: u64,

    pub const DEFAULT: FeeDetails = .{
        .transaction_fee = 0,
        .prioritization_fee = 0,
        .compute_unit_price = 0,
    };

    pub fn init(
        sig_counts: SignatureCounts,
        lamports_per_signature: u64,
        prioritization_fee: u64,
        compute_unit_price: u64,
    ) FeeDetails {
        return .{
            .transaction_fee = calculateSignatureFee(
                sig_counts,
                lamports_per_signature,
            ),
            .prioritization_fee = prioritization_fee,
            .compute_unit_price = compute_unit_price,
        };
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/dad81b9b2ecf81ceb518dd9f7cc91e83ba33bda8/fee/src/lib.rs#L66
    fn calculateSignatureFee(
        sig_counts: SignatureCounts,
        lamports_per_signature: u64,
    ) u64 {
        const sig_count = sig_counts.num_transaction_signatures +|
            sig_counts.num_ed25519_signatures +|
            sig_counts.num_secp256k1_signatures +|
            sig_counts.num_secp256r1_signatures;

        return sig_count *| lamports_per_signature;
    }

    pub fn total(self: FeeDetails) u64 {
        return self.prioritization_fee +| self.transaction_fee;
    }
};

pub const FeeBudgetLimits = struct {
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

    pub fn fromComputeBudgetLimits(val: ComputeBudgetLimits) FeeBudgetLimits {
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
    pubkey: Pubkey,
    payer: *AccountSharedData,
    rent_collector: *const RentCollector,
    fee: u64,
) ?TransactionError {
    if (payer.lamports == 0) return .AccountNotFound;

    const system_account_kind = getSystemAccountKind(payer) orelse
        return .InvalidAccountForFee;

    const min_balance = switch (system_account_kind) {
        .System => 0,
        .Nonce => rent_collector.rent.minimumBalance(NonceVersions.SERIALIZED_SIZE),
    };

    // Matches agave's `lamports.checked_sub(min_balance).and_then(|v| v.checked_sub(fee))`
    // guard: a payer that cannot cover BOTH the system-account minimum balance
    // AND the fee must fail here as InsufficientFundsForFee, before the rent-state
    // transition below has a chance to surface a misleading InsufficientFundsForRent.
    // [agave] https://github.com/anza-xyz/agave/blob/64b616042450fa6553427471f70895f1dfe0cd86/svm/src/account_loader.rs#L320-L327
    {
        const lamports_min_balance_diff = std.math.sub(u64, payer.lamports, min_balance) catch
            return .InsufficientFundsForFee;
        _ = std.math.sub(u64, lamports_min_balance_diff, fee) catch
            return .InsufficientFundsForFee;
    }

    const pre_rent_state = rent_collector.getAccountRentState(
        payer.lamports,
        payer.data.len,
    );

    payer.lamports = std.math.sub(u64, payer.lamports, fee) catch
        return .InsufficientFundsForFee;

    const post_rent_state = rent_collector.getAccountRentState(
        payer.lamports,
        payer.data.len,
    );

    if (RentCollector.checkRentStateWithAccount(
        pre_rent_state,
        post_rent_state,
        &pubkey,
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

pub fn checkLoadAndAdvanceMessageNonceAccount(
    allocator: Allocator,
    transaction: *const RuntimeTransaction,
    next_durable_nonce: *const Hash,
    next_lamports_per_signature: u64,
    account_reader: AccountReader,
) AccountLoadError!?struct { LoadedAccount, u64 } {
    if (transaction.recent_blockhash.eql(next_durable_nonce.*)) return null;

    const address, var nonce_account, const nonce_data =
        try loadMessageNonceAccount(
            allocator,
            transaction,
            account_reader,
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

    // Mirror agave's `AccountSharedData::set_state`: `bincode::serialize_into`
    // the new state over the existing buffer in place. Length and any trailing
    // bytes past the serialized region are preserved, and both flow into the
    // rollback account's data and `loaded_accounts_data_size`. Ownership of
    // `nonce_account.data` transfers into the returned `LoadedAccount`.
    _ = sig.bincode.writeToSlice(nonce_account.data, next_nonce_state, .{}) catch {
        nonce_account.deinit(allocator);
        return null;
    };

    return .{
        .{
            .pubkey = address,
            .account = .{
                .lamports = nonce_account.lamports,
                .data = nonce_account.data,
                .owner = nonce_account.owner,
                .executable = nonce_account.executable,
                .rent_epoch = nonce_account.rent_epoch,
            },
        },
        previous_lamports_per_signature,
    };
}

pub fn loadMessageNonceAccount(
    allocator: Allocator,
    transaction: *const RuntimeTransaction,
    account_reader: AccountReader,
) AccountLoadError!?struct { Pubkey, AccountSharedData, NonceData } {
    const nonce_address = getDurableNonce(transaction) orelse
        return null;
    // TODO(accounts_interface): we don't need an owned account data here
    const nonce_account = try account_reader.get(allocator, nonce_address) orelse
        return null;
    var nonce_account_consumed = false;
    defer if (!nonce_account_consumed) nonce_account.deinit(allocator);

    var nonce_account_data = std.io.fixedBufferStream(nonce_account.data);
    const nonce_data = verifyNonceAccount(
        &nonce_account.owner,
        nonce_account_data.reader(),
        &transaction.recent_blockhash,
    ) orelse return null;

    const signers = try transaction.instructions[
        NONCED_TX_MARKER_IX_INDEX
    ].getSigners(allocator);
    defer allocator.free(signers);

    // check nonce is authorised
    for (signers) |signer| {
        if (signer.equals(&nonce_data.authority)) break;
    } else return null;

    nonce_account_consumed = true;
    return .{ nonce_address, nonce_account, nonce_data };
}

pub fn verifyNonceAccount(
    owner: *const Pubkey,
    account_data_reader: anytype,
    recent_blockhash: *const Hash,
) ?NonceData {
    if (!owner.equals(&sig.runtime.program.system.ID)) return null;

    // could probably be smaller
    var deserialize_buf: [@sizeOf(NonceData) * 2]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&deserialize_buf);

    const nonce = sig.bincode.read(
        fba.allocator(),
        NonceVersions,
        account_data_reader,
        .{},
    ) catch return null;

    const nonce_data = nonce.verify(recent_blockhash.*) orelse return null;

    return nonce_data;
}

// [agave] https://github.com/anza-xyz/agave/blob/v4.0.0-rc.0/svm-transaction/src/svm_message.rs#L99-L131
/// If the message uses a durable nonce, return the pubkey of the nonce account.
///
/// SIMD-0242: the nonce account index must reference a statically-included key
/// (i.e. be below `transaction.num_static_account_keys`); otherwise we treat
/// the message as not having a durable nonce, mirroring Agave's `get_durable_nonce`.
pub fn getDurableNonce(
    transaction: *const RuntimeTransaction,
) ?Pubkey {
    if (transaction.instructions.len <= 0) return null;
    const instruction = transaction.instructions[NONCED_TX_MARKER_IX_INDEX];

    if (instruction.account_metas.items.len == 0) return null;

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

    const nonce_meta = instruction.account_metas.items[0];
    if (!nonce_meta.is_writable) return null;
    if (nonce_meta.index_in_transaction >= account_keys.len) return null;
    if (nonce_meta.index_in_transaction >= transaction.num_static_account_keys)
        return null;
    return account_keys[nonce_meta.index_in_transaction];
}

test "checkLoadAndAdvanceMessageNonceAccount: advances valid nonce" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const nonce_key = Pubkey.initRandom(prng.random());
    const nonce_authority_key = Pubkey.initRandom(prng.random());
    const recent_blockhash = Hash.initRandom(prng.random());
    const next_durable_nonce = Hash.initRandom(prng.random());

    const nonce_account = AccountSharedData{
        .lamports = 1,
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

    var account_map = sig.utils.collections.PubkeyMap(AccountSharedData){};
    defer deinitAccountMap(account_map, allocator);
    try account_map.put(allocator, nonce_key, nonce_account);

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

    var metas: sig.runtime.InstructionInfo.AccountMetas = .empty;
    defer metas.deinit(allocator);

    try metas.appendSlice(allocator, &.{
        .{
            .pubkey = nonce_key,
            .index_in_transaction = 1,
            .is_signer = false,
            .is_writable = true,
        },
        .{
            .pubkey = nonce_authority_key,
            .index_in_transaction = 2,
            .is_signer = true,
            .is_writable = false,
        },
    });

    const transaction = RuntimeTransaction{
        .signature_count = 0,
        .fee_payer = Pubkey.ZEROES,
        .msg_hash = Hash.ZEROES,
        .recent_blockhash = recent_blockhash,
        .instructions = &.{.{
            .program_meta = .{ .pubkey = sig.runtime.program.system.ID, .index_in_transaction = 0 },
            .account_metas = metas,
            .dedupe_map = blk: {
                var dedupe_map: [sig.runtime.InstructionInfo.MAX_ACCOUNT_METAS]u16 = @splat(0xffff);
                dedupe_map[1] = 1;
                dedupe_map[2] = 2;
                break :blk dedupe_map;
            },
            .instruction_data = instruction_data,
            .owned_instruction_data = false,
            .initial_account_lamports = 0,
        }},
        .accounts = accounts,
        .num_lookup_tables = 0,
        .num_static_account_keys = @intCast(accounts.len),
        .is_simple_vote_transaction = false,
    };

    const maybe_result = try checkLoadAndAdvanceMessageNonceAccount(
        allocator,
        &transaction,
        &next_durable_nonce,
        5001,
        AccountReader.fromMap(&account_map),
    );

    const loaded_nonce, const previous_lamports_per_signature =
        maybe_result orelse return error.ExpectedNonceLoaded;
    defer loaded_nonce.deinit(allocator);

    try std.testing.expectEqual(5000, previous_lamports_per_signature);
    try std.testing.expectEqualSlices(u8, &nonce_key.data, &loaded_nonce.pubkey.data);

    const nv = try sig.bincode.readFromSlice(
        allocator,
        sig.runtime.nonce.Versions,
        loaded_nonce.account.data,
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
}

// SIMD-0242: when the nonce account is not in the static account keys,
// getDurableNonce must return null so the message-nonce resolution falls
// through and the caller surfaces BlockhashNotFound, matching Agave's
// get_durable_nonce behavior.
test "checkLoadAndAdvanceMessageNonceAccount: SIMD-0242 ALT-resolved nonce" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const nonce_key = Pubkey.initRandom(prng.random());
    const nonce_authority_key = Pubkey.initRandom(prng.random());
    const recent_blockhash = Hash.initRandom(prng.random());
    const next_durable_nonce = Hash.initRandom(prng.random());

    const nonce_account_data = AccountSharedData{
        .lamports = 1,
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

    var account_map = sig.utils.collections.PubkeyMap(AccountSharedData){};
    defer deinitAccountMap(account_map, allocator);
    try account_map.put(allocator, nonce_key, nonce_account_data);

    const instruction_data = try sig.bincode.writeAlloc(
        allocator,
        sig.runtime.program.system.Instruction.advance_nonce_account,
        .{},
    );
    defer allocator.free(instruction_data);

    // Resolved account list: [system_program (static), authority (static),
    // nonce (ALT-resolved)]. num_static_account_keys = 2, so the nonce at
    // index 2 is NOT statically included.
    var accounts = std.MultiArrayList(AccountMeta){};
    defer accounts.deinit(allocator);
    try accounts.append(
        allocator,
        .{ .pubkey = sig.runtime.program.system.ID, .is_signer = false, .is_writable = false },
    );
    try accounts.append(
        allocator,
        .{ .pubkey = nonce_authority_key, .is_signer = true, .is_writable = false },
    );
    try accounts.append(
        allocator,
        .{ .pubkey = nonce_key, .is_signer = false, .is_writable = true },
    );

    var metas: sig.runtime.InstructionInfo.AccountMetas = .empty;
    defer metas.deinit(allocator);

    try metas.appendSlice(allocator, &.{
        .{
            .pubkey = nonce_key,
            .index_in_transaction = 2,
            .is_signer = false,
            .is_writable = true,
        },
        .{
            .pubkey = nonce_authority_key,
            .index_in_transaction = 1,
            .is_signer = true,
            .is_writable = false,
        },
    });

    const transaction = RuntimeTransaction{
        .signature_count = 0,
        .fee_payer = Pubkey.ZEROES,
        .msg_hash = Hash.ZEROES,
        .recent_blockhash = recent_blockhash,
        .instructions = &.{.{
            .program_meta = .{ .pubkey = sig.runtime.program.system.ID, .index_in_transaction = 0 },
            .account_metas = metas,
            .dedupe_map = blk: {
                var dedupe_map: [sig.runtime.InstructionInfo.MAX_ACCOUNT_METAS]u16 = @splat(0xffff);
                dedupe_map[2] = 0;
                dedupe_map[1] = 1;
                break :blk dedupe_map;
            },
            .instruction_data = instruction_data,
            .owned_instruction_data = false,
            .initial_account_lamports = 0,
        }},
        .accounts = accounts,
        .num_lookup_tables = 1,
        .num_static_account_keys = 2,
        .is_simple_vote_transaction = false,
    };

    // ALT-resolved nonce is not recognized, so nonce loading returns
    // null. (The transaction_execution caller then surfaces BlockhashNotFound.)
    const result = try checkLoadAndAdvanceMessageNonceAccount(
        allocator,
        &transaction,
        &next_durable_nonce,
        5001,
        AccountReader.fromMap(&account_map),
    );
    try std.testing.expectEqual(null, result);
}

test "checkFeePayer: happy path fee payer only" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const recent_blockhash = Hash.initRandom(prng.random());

    var transaction = RuntimeTransaction{
        .signature_count = 1,
        .fee_payer = Pubkey.initRandom(prng.random()),
        .msg_hash = Hash.ZEROES,
        .recent_blockhash = recent_blockhash,
        .instructions = &.{},
        .num_lookup_tables = 0,
        .num_static_account_keys = 1,
        .is_simple_vote_transaction = false,
    };
    defer transaction.accounts.deinit(allocator);

    try transaction.accounts.append(
        allocator,
        .{ .pubkey = transaction.fee_payer, .is_signer = true, .is_writable = true },
    );

    var account_map = sig.utils.collections.PubkeyMap(AccountSharedData){};
    defer deinitAccountMap(account_map, allocator);

    try account_map.put(allocator, transaction.fee_payer, .{
        .lamports = 1_000_000,
        .owner = sig.runtime.program.system.ID,
        .data = &.{},
        .executable = false,
        .rent_epoch = 0,
    });

    const result = try checkFeePayer(
        allocator,
        &transaction,
        AccountReader.fromMap(&account_map),
        &ComputeBudgetLimits.DEFAULT,
        null,
        &sig.core.rent_collector.defaultCollector(10),
        LAMPORTS_PER_SIGNATURE,
    );

    const fee_details, const rollbacks, const prepared_fee_payer = result.ok;
    defer prepared_fee_payer.account.deinit(allocator);

    try std.testing.expectEqual(LAMPORTS_PER_SIGNATURE, fee_details.transaction_fee);
    try std.testing.expectEqual(0, fee_details.prioritization_fee);

    try std.testing.expectEqual(1, rollbacks.slice().len);
    const payer = rollbacks.slice()[0];
    try std.testing.expectEqual(1_000_000 - LAMPORTS_PER_SIGNATURE, payer.account.lamports);
    try std.testing.expectEqual(0, payer.account.rent_epoch);
}

test "checkFeePayer: happy path with same nonce and fee payer" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const recent_blockhash = Hash.initRandom(prng.random());

    var transaction = RuntimeTransaction{
        .signature_count = 1,
        .fee_payer = Pubkey.initRandom(prng.random()),
        .msg_hash = Hash.ZEROES,
        .recent_blockhash = recent_blockhash,
        .instructions = &.{},
        .num_lookup_tables = 0,
        .num_static_account_keys = 1,
        .is_simple_vote_transaction = false,
    };
    defer transaction.accounts.deinit(allocator);

    try transaction.accounts.append(
        allocator,
        .{ .pubkey = transaction.fee_payer, .is_signer = true, .is_writable = true },
    );

    var account_map = sig.utils.collections.PubkeyMap(AccountSharedData){};
    defer deinitAccountMap(account_map, allocator);

    try account_map.put(allocator, transaction.fee_payer, .{
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
        AccountReader.fromMap(&account_map),
        &ComputeBudgetLimits.DEFAULT,
        .{
            .pubkey = transaction.fee_payer,
            .account = nonce_account,
        },
        &sig.core.rent_collector.defaultCollector(10),
        LAMPORTS_PER_SIGNATURE,
    );

    const fee_details, const rollbacks, const prepared_fee_payer = result.ok;
    defer prepared_fee_payer.account.deinit(allocator);
    defer for (rollbacks.slice()) |r| r.deinit(allocator);

    try std.testing.expectEqual(1, rollbacks.len);
    const rollback_account = rollbacks.get(0).account;

    try std.testing.expectEqual(LAMPORTS_PER_SIGNATURE, fee_details.transaction_fee);
    try std.testing.expectEqual(0, fee_details.prioritization_fee);
    try std.testing.expectEqual(1_000_000 - LAMPORTS_PER_SIGNATURE, rollback_account.lamports);
    try std.testing.expectEqual(std.math.maxInt(u64), rollback_account.rent_epoch);
}

test "checkFeePayer: happy path with separate nonce and fee payer" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const recent_blockhash = Hash.initRandom(prng.random());

    var transaction = RuntimeTransaction{
        .signature_count = 1,
        .fee_payer = Pubkey.initRandom(prng.random()),
        .msg_hash = Hash.ZEROES,
        .recent_blockhash = recent_blockhash,
        .instructions = &.{},
        .num_lookup_tables = 0,
        .num_static_account_keys = 1,
        .is_simple_vote_transaction = false,
    };
    defer transaction.accounts.deinit(allocator);

    try transaction.accounts.append(
        allocator,
        .{ .pubkey = transaction.fee_payer, .is_signer = true, .is_writable = true },
    );

    var account_map = sig.utils.collections.PubkeyMap(AccountSharedData){};
    defer deinitAccountMap(account_map, allocator);

    try account_map.put(allocator, transaction.fee_payer, .{
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
        AccountReader.fromMap(&account_map),
        &ComputeBudgetLimits.DEFAULT,
        .{
            .pubkey = Pubkey.initRandom(prng.random()),
            .account = nonce_account,
        },
        &sig.core.rent_collector.defaultCollector(10),
        LAMPORTS_PER_SIGNATURE,
    );

    const fee_details, const rollbacks, const prepared_fee_payer = result.ok;
    defer prepared_fee_payer.account.deinit(allocator);
    defer for (rollbacks.slice()) |r| r.deinit(allocator);

    const rollback_nonce_account = rollbacks.get(0).account;
    const rollback_fee_payer_account = rollbacks.get(1).account;

    try std.testing.expectEqual(LAMPORTS_PER_SIGNATURE, fee_details.transaction_fee);
    try std.testing.expectEqual(0, fee_details.prioritization_fee);
    try std.testing.expectEqual(1_000, rollback_nonce_account.lamports);
    try std.testing.expectEqual(0, rollback_nonce_account.rent_epoch);
    try std.testing.expectEqual(1_000_000 - LAMPORTS_PER_SIGNATURE, rollback_fee_payer_account.lamports);
    try std.testing.expectEqual(std.math.maxInt(u64), rollback_fee_payer_account.rent_epoch);
}
