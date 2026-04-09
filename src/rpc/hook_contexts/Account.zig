//! The Account RPC hook context. Contains references to the necessary state in the validator required for reading out account data and for serving RPC.

const std = @import("std");
const tracy = @import("tracy");

const sig = @import("../../sig.zig");

const account_codec = sig.rpc.account_codec;
const parse_stake = account_codec.parse_stake;
const parse_token = account_codec.parse_token;

const check_transactions = sig.runtime.check_transactions;
const compute_budget = sig.runtime.program.compute_budget;

const Base64Decoder = std.base64.standard.Decoder;
const FeeBudgetLimits = check_transactions.FeeBudgetLimits;
const ComputeBudgetLimits = compute_budget.ComputeBudgetLimits;
const FeeDetails = check_transactions.FeeDetails;
const SignatureCounts = check_transactions.SignatureCounts;
const Message = sig.core.transaction.Message;
const Version = sig.core.transaction.Version;
const RuntimeTransaction = sig.runtime.transaction_execution.RuntimeTransaction;
const Signature = sig.core.Signature;
const Slot = sig.core.Slot;

const GetAccountInfo = sig.rpc.methods.GetAccountInfo;
const GetBalance = sig.rpc.methods.GetBalance;
const GetFeeForMessage = sig.rpc.methods.GetFeeForMessage;
const GetLargestAccounts = sig.rpc.methods.GetLargestAccounts;
const GetSupply = sig.rpc.methods.GetSupply;
const GetTokenAccountBalance = sig.rpc.methods.GetTokenAccountBalance;
const GetTokenLargestAccounts = sig.rpc.methods.GetTokenLargestAccounts;
const GetTokenSupply = sig.rpc.methods.GetTokenSupply;
const GetMultipleAccounts = sig.rpc.methods.GetMultipleAccounts;
const GetProgramAccounts = sig.rpc.methods.GetProgramAccounts;
const GetTokenAccountsByOwner = sig.rpc.methods.GetTokenAccountsByOwner;
const GetTokenAccountsByDelegate = sig.rpc.methods.GetTokenAccountsByDelegate;

const AccountEncoding = account_codec.AccountEncoding;
const CommitmentSlotConfig = sig.rpc.methods.common.CommitmentSlotConfig;
const RpcFilterType = sig.rpc.filters.RpcFilterType;
const slot_resolution = @import("./slot_resolution.zig");
const non_circulating_supply = @import("non-circulating-supply");

/// Compile-time perfect hash set for O(1) membership checks against the static
/// non-circulating accounts list. Built from the build-time-decoded pubkey arrays.
const NonCirculatingSet = blk: {
    var entries: []const struct { sig.core.Pubkey, void } = &.{};
    for (&non_circulating_supply.non_circulating_accounts) |*raw| {
        entries = entries ++ &[_]struct { sig.core.Pubkey, void }{
            .{ .{ .data = raw.* }, {} },
        };
    }
    break :blk sig.utils.pht(void, entries);
};

const AccountHookContext = @This();

slot_tracker: *sig.replay.trackers.SlotTracker,
commitments: *sig.replay.trackers.CommitmentTracker,
account_reader: sig.accounts_db.AccountReader,

pub fn getAccountInfo(
    self: AccountHookContext,
    arena: std.mem.Allocator,
    params: GetAccountInfo,
) !GetAccountInfo.Response {
    const config = params.config orelse GetAccountInfo.Config{};
    // [agave] Default commitment is finalized:
    // https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L348
    const commitment = config.commitment orelse .finalized;
    // [agave] Default is legacy `Binary` for `getAccountInfo`.
    // https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L545
    const encoding = config.encoding orelse AccountEncoding.binary;

    const slot = try slot_resolution.resolveReadableCommitmentSlot(
        self.slot_tracker,
        self.commitments,
        commitment,
        config.minContextSlot,
    );

    const ref = self.slot_tracker.get(slot) orelse return error.SlotNotAvailable;
    defer ref.release();
    const slot_reader = self.account_reader.forSlot(&ref.constants().ancestors).toOwnedReader();
    const account = try slot_reader.get(arena, params.pubkey) orelse return .{
        .context = .{ .slot = slot },
        .value = null,
    };

    // TODO: [agave conformance] When base58 encoding is requested and account data exceeds
    // 128 bytes, Agave returns JSON-RPC error code -32600 (InvalidRequest) with the message:
    // "Encoded binary (base 58) data should be less than 128 bytes, please use Base64 encoding."
    // Currently, `error.Base58DataTooLarge` propagates to hooks.zig's generic error mapper,
    // which produces a non-deterministic positive error code via `@intFromError` and the raw
    // error name as the message.
    const data = try account_codec.encodeAccount(
        arena,
        params.pubkey,
        account,
        encoding,
        slot_reader,
        config.dataSlice,
    );

    return .{
        .context = .{ .slot = slot },
        .value = .from(account, data),
    };
}

pub fn getBalance(
    self: AccountHookContext,
    arena: std.mem.Allocator,
    params: GetBalance,
) !GetBalance.Response {
    const config = params.config orelse CommitmentSlotConfig{};
    // [agave] Default commitment is finalized:
    // https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L348
    const commitment = config.commitment orelse .finalized;

    const slot = try slot_resolution.resolveReadableCommitmentSlot(
        self.slot_tracker,
        self.commitments,
        commitment,
        config.minContextSlot,
    );

    // Get slot reference to access ancestors
    const ref = self.slot_tracker.get(slot) orelse return error.SlotNotAvailable;
    defer ref.release();
    const slot_reader = self.account_reader.forSlot(&ref.constants().ancestors).toOwnedReader();

    // Look up account
    const maybe_account = try slot_reader.get(arena, params.pubkey);

    const lamports: u64 = if (maybe_account) |account| blk: {
        break :blk account.lamports;
    } else 0;

    return .{
        .context = .{
            .slot = slot,
        },
        .value = lamports,
    };
}

pub fn getTokenAccountBalance(
    self: AccountHookContext,
    arena: std.mem.Allocator,
    params: GetTokenAccountBalance,
) !GetTokenAccountBalance.Response {
    const config: GetTokenAccountBalance.Config = params.config orelse .{};
    const commitment = config.commitment orelse .finalized;

    const slot = try slot_resolution.resolveReadableCommitmentSlot(
        self.slot_tracker,
        self.commitments,
        commitment,
        null,
    );

    const ref = self.slot_tracker.get(slot) orelse return error.SlotNotAvailable;
    defer ref.release();
    const slot_reader = self.account_reader.forSlot(&ref.constants().ancestors).toOwnedReader();
    const maybe_account = try slot_reader.get(arena, params.pubkey);

    const account = maybe_account orelse return error.RpcAccountNotFound;

    // Validate that this is a token account (owned by SPL Token or Token-2022)
    const is_token_program = account.owner.equals(&sig.runtime.ids.TOKEN_PROGRAM_ID) or
        account.owner.equals(&sig.runtime.ids.TOKEN_2022_PROGRAM_ID);
    if (!is_token_program) return error.RpcNotATokenAccount;

    // Read account data and unpack the token account
    var data_buf: [account_codec.parse_token.TokenAccount.LEN]u8 = undefined;
    var data_iter = account.data.iterator();
    const bytes_read = data_iter.readBytes(&data_buf) catch return error.RpcNotATokenAccount;
    if (bytes_read < account_codec.parse_token.TokenAccount.LEN)
        return error.RpcNotATokenAccount;

    const token_account = account_codec.parse_token.TokenAccount.unpack(&data_buf) catch
        return error.RpcNotATokenAccount;
    if (token_account.state == .uninitialized) return error.RpcNotATokenAccount;

    // Build SplTokenAdditionalData for mint decimals and extension configs
    const is_native_mint = token_account.mint.equals(&sig.runtime.ids.NATIVE_MINT_ID);
    const spl_token_data: account_codec.parse_token.SplTokenAdditionalData = if (is_native_mint)
        // Native mint (wrapped SOL): decimals=9, no extensions
        // TODO: document agave conformance.
        .{ .decimals = 9 }
    else
        // Look up the mint account for decimals and extension configs
        account_codec.getMintAdditionalData(
            arena,
            token_account.mint,
            slot_reader,
        ) orelse return error.RpcMintNotFound;

    const ui_token_amount = account_codec.parse_token.UiTokenAmount.init(
        token_account.amount,
        spl_token_data,
    );

    return .{
        .context = .{ .slot = slot },
        .value = ui_token_amount,
    };
}

pub fn getTokenSupply(
    self: AccountHookContext,
    arena: std.mem.Allocator,
    params: GetTokenSupply,
) !GetTokenSupply.Response {
    const config: GetTokenSupply.Config = params.config orelse .{};
    const commitment = config.commitment orelse .finalized;

    const slot = try slot_resolution.resolveReadableCommitmentSlot(
        self.slot_tracker,
        self.commitments,
        commitment,
        null,
    );

    const ref = self.slot_tracker.get(slot) orelse return error.SlotNotAvailable;
    defer ref.release();
    const slot_reader = self.account_reader.forSlot(&ref.constants().ancestors).toOwnedReader();

    // Fetch mint account
    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L1989-L1991
    const maybe_account = try slot_reader.get(arena, params.mint);
    const account = maybe_account orelse return error.RpcAccountNotFound;

    // Validate that this is owned by a token program
    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L1992-L1996
    const is_token_program = account.owner.equals(&sig.runtime.ids.TOKEN_PROGRAM_ID) or
        account.owner.equals(&sig.runtime.ids.TOKEN_2022_PROGRAM_ID);
    if (!is_token_program) return error.RpcNotATokenAccount;

    // Read account data into contiguous buffer for mint parsing and extension extraction
    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L1997-L2009
    const data_len = account.data.len();
    const mint_data = try arena.alloc(u8, data_len);
    var data_iter = account.data.iterator();
    _ = data_iter.readBytes(mint_data) catch return error.RpcMintUnpackFailed;

    // Validate this is actually a mint account, not a token account or multisig.
    // Without this, a token account's garbage bytes at the decimals offset can cause
    // a panic in formatTokenAmount. Agave performs similar validation.
    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L1997
    const detected = parse_token.DetectedType.parse(mint_data) orelse
        return error.RpcMintUnpackFailed;
    if (detected != .mint) return error.RpcMintUnpackFailed;

    // Parse mint to get supply
    const mint = parse_token.Mint.unpack(mint_data) catch return error.RpcMintUnpackFailed;
    if (!mint.is_initialized) return error.RpcMintUnpackFailed;

    // Extract decimals, extension configs, and clock timestamp from the raw mint data
    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L2011-L2019
    const spl_token_data = account_codec.parseMintAdditionalData(
        arena,
        mint_data,
        slot_reader,
    ) orelse return error.RpcMintUnpackFailed;

    const ui_token_amount = parse_token.UiTokenAmount.init(
        mint.supply,
        spl_token_data,
    );

    return .{
        .context = .{ .slot = slot },
        .value = ui_token_amount,
    };
}

pub fn getMultipleAccounts(
    self: AccountHookContext,
    arena: std.mem.Allocator,
    params: GetMultipleAccounts,
) !GetMultipleAccounts.Response {
    if (params.pubkeys.len > GetMultipleAccounts.MAX_PUBKEYS) {
        return error.TooManyInputs;
    }
    const config = params.config orelse GetAccountInfo.Config{};
    const commitment = config.commitment orelse .finalized;
    const encoding = config.encoding orelse AccountEncoding.base64;
    const slot = try slot_resolution.resolveReadableCommitmentSlot(
        self.slot_tracker,
        self.commitments,
        commitment,
        config.minContextSlot,
    );
    const ref = self.slot_tracker.get(slot) orelse return error.SlotNotAvailable;
    defer ref.release();
    const slot_reader = self.account_reader.forSlot(&ref.constants().ancestors).toOwnedReader();
    const values = try arena.alloc(?GetAccountInfo.Response.Value, params.pubkeys.len);

    for (params.pubkeys, values) |pubkey, *value| {
        const account = try slot_reader.get(arena, pubkey) orelse {
            value.* = null;
            continue;
        };
        const data: account_codec.AccountData = if (encoding == .jsonParsed)
            try account_codec.encodeJsonParsed(
                arena,
                pubkey,
                account,
                slot_reader,
                config.dataSlice,
            )
        else
            try account_codec.encodeStandard(
                arena,
                account,
                encoding,
                config.dataSlice,
            );
        value.* = .{
            .data = data,
            .executable = account.executable,
            .lamports = account.lamports,
            .owner = account.owner,
            .rentEpoch = account.rent_epoch,
            .space = account.data.len(),
        };
    }

    return .{
        .context = .{
            .slot = slot,
        },
        .value = values,
    };
}

/// Get the fee the network will charge for a particular Message.
/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L4254-L4278
pub fn getFeeForMessage(
    self: AccountHookContext,
    arena: std.mem.Allocator,
    params: GetFeeForMessage,
) !GetFeeForMessage.Response {
    const config: GetFeeForMessage.Config = params.config orelse .{};
    const commitment = config.commitment orelse .finalized;

    const slot = try slot_resolution.resolveReadableCommitmentSlot(
        self.slot_tracker,
        self.commitments,
        commitment,
        config.minContextSlot,
    );

    // [agave] get_bank_with_config() validates min context after bank fallback.
    // https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L270-L285
    const slot_ref = self.slot_tracker.get(slot) orelse return error.SlotNotAvailable;
    defer slot_ref.release();

    // Decode base64-encoded message.
    const decoded_len = Base64Decoder.calcSizeForSlice(params.message) catch
        return error.InvalidBase64Encoding;
    const decoded_bytes = try arena.alloc(u8, decoded_len);
    Base64Decoder.decode(decoded_bytes, params.message) catch return error.InvalidBase64Encoding;

    // Deserialize into a VersionedMessage.
    var fbs = std.io.fixedBufferStream(decoded_bytes);
    var peekable = sig.utils.io.peekableReader(fbs.reader());
    const version = Version.deserialize(&peekable) catch return error.InvalidMessageFormat;
    var limit_allocator = sig.bincode.LimitAllocator.init(
        arena,
        sig.core.Transaction.MAX_BYTES,
    );
    const message = Message.deserialize(&limit_allocator, peekable.reader(), version) catch
        return error.InvalidMessageFormat;

    const slot_reader = self.account_reader.forSlot(&slot_ref.constants().ancestors).toOwnedReader();

    const empty_result: GetFeeForMessage.Response = .{
        .context = .{ .slot = slot },
        .value = null,
    };

    const runtime_txn = (messageToRuntimeTransaction(
        arena,
        message,
        version,
        slot_reader,
        &slot_ref.constants().reserved_accounts,
        slot,
    ) catch return empty_result) orelse return empty_result;

    // Look up lamports_per_signature from the blockhash queue, or from nonce account if durable nonce.
    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/bank.rs#L2732-L2741
    const maybe_bq_lps: ?u64 = blk: {
        const bq, var bq_guard = slot_ref.state().blockhash_queue.readWithLock();
        defer bq_guard.unlock();
        break :blk bq.getLamportsPerSignature(message.recent_blockhash);
    };

    const bq_lps = maybe_bq_lps orelse {
        const nonce_result = check_transactions.loadMessageNonceAccount(
            arena,
            &runtime_txn,
            slot_reader,
        ) catch return empty_result;
        if (nonce_result) |r| return .{
            .context = .{ .slot = slot },
            .value = r[2].lamports_per_signature,
        };
        return empty_result;
    };

    var fee_details: FeeDetails = FeeDetails.DEFAULT;
    if (bq_lps != 0) {
        const feature_set = &slot_ref.constants().feature_set;
        const enable_secp256r1 = feature_set.active(.enable_secp256r1_precompile, slot);

        // [agave] process_compute_budget_instructions(message.program_instructions_iter(), &self.feature_set).unwrap_or_default()
        // In Agave, execute+sanitize is a single call; on ANY error, ComputeBudgetLimits::default() is used.
        var budget_limits = ComputeBudgetLimits.DEFAULT;
        const details = compute_budget.execute(&message);
        if (details == .ok) {
            const sanitized = compute_budget.sanitize(details.ok, feature_set, slot);
            if (sanitized == .ok) budget_limits = sanitized.ok;
        }
        const fee_budget_limits = FeeBudgetLimits.fromComputeBudgetLimits(budget_limits);
        fee_details = FeeDetails.init(
            SignatureCounts.fromTransaction(&runtime_txn),
            5_000,
            enable_secp256r1,
            fee_budget_limits.prioritization_fee,
            budget_limits.compute_unit_price,
        );
    }

    return .{
        .context = .{ .slot = slot },
        .value = fee_details.total(),
    };
}

/// Build a minimal Transaction from a Message for resolution (e.g. nonce lookup).
/// Caller owns the returned transaction and must call deinit.
///
/// IMPORTANT: Signatures are zeroed because it's used only in getFeeForMessage
/// and there only receives the message (unsigned transaction body)—
/// the client asks for the fee before signing, so no real signatures
/// exist. This has no downside: resolveTransaction and loadMessageNonceAccount only use
/// the message structure (instructions, accounts, blockhash); they never verify or use
/// the signature bytes. Signer checks use account metas (is_signer flags), not signature
/// data.
fn messageToRuntimeTransaction(
    arena: std.mem.Allocator,
    message: sig.core.transaction.Message,
    version: sig.core.transaction.Version,
    slot_account_reader: sig.accounts_db.SlotAccountReader,
    reserved_accounts: *const sig.core.ReservedAccounts,
    slot: Slot,
) std.mem.Allocator.Error!?RuntimeTransaction {
    const signatures = try arena.alloc(Signature, message.signature_count);
    @memset(signatures, Signature.ZEROES);
    const transaction: sig.core.Transaction = .{
        .signatures = signatures,
        .version = version,
        .msg = message,
    };

    const slot_hashes = sig.replay.update_sysvar.getSysvarFromAccount(
        sig.runtime.sysvar.SlotHashes,
        arena,
        slot_account_reader,
    ) catch null orelse sig.runtime.sysvar.SlotHashes.INIT;

    const resolved = sig.replay.resolve_lookup.resolveTransaction(arena, transaction, .{
        .slot = slot,
        .account_reader = slot_account_reader,
        .reserved_accounts = reserved_accounts,
        .slot_hashes = slot_hashes,
    }) catch return null;

    const msg_hash = Message.hash(
        (message.serializeBounded(version) catch return null).constSlice(),
    );
    const runtime_txn = resolved.toRuntimeTransaction(
        msg_hash,
        .{},
    );

    return runtime_txn;
}

pub fn getProgramAccounts(
    self: AccountHookContext,
    arena: std.mem.Allocator,
    params: GetProgramAccounts,
) !GetProgramAccounts.Response {
    const zone = tracy.Zone.init(@src(), .{ .name = "rpc.getProgramAccounts" });
    defer zone.deinit();

    const config = params.config orelse GetProgramAccounts.Config{};
    const commitment = config.commitment orelse .finalized;
    const encoding = config.encoding orelse .base64;
    const f = config.filters orelse &.{};
    try sig.rpc.filters.verifyFilters(f);

    const slot = try slot_resolution.resolveReadableCommitmentSlot(
        self.slot_tracker,
        self.commitments,
        commitment,
        config.minContextSlot,
    );

    const ref = self.slot_tracker.get(slot) orelse return error.SlotNotAvailable;
    defer ref.release();
    const ancestors = &ref.constants().ancestors;
    const slot_reader = self.account_reader.forSlot(ancestors).toOwnedReader();

    var iter = blk: {
        const z = tracy.Zone.init(@src(), .{ .name = "rpc.getProgramAccounts.ownerQuery" });
        defer z.deinit();
        break :blk try slot_reader.getByOwner(arena, &params.program_id);
    };
    defer iter.deinit();

    var results = std.ArrayListUnmanaged(GetProgramAccounts.Value){};

    while (try iter.next()) |entry| {
        const pubkey, const account = entry;
        if (!sig.rpc.filters.filtersAllow(f, &account.data)) continue;

        const data = try account_codec.encodeAccount(
            arena,
            pubkey,
            account,
            encoding,
            slot_reader,
            config.dataSlice,
        );
        try results.append(arena, .{
            .pubkey = pubkey,
            .account = .from(account, data),
        });
    }

    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L3361
    if (config.sortResults orelse true) {
        const z = tracy.Zone.init(@src(), .{ .name = "rpc.getProgramAccounts.sort" });
        defer z.deinit();
        std.mem.sortUnstable(GetProgramAccounts.Value, results.items, {}, struct {
            fn lessThan(_: void, a: GetProgramAccounts.Value, b: GetProgramAccounts.Value) bool {
                return std.mem.order(u8, &a.pubkey.data, &b.pubkey.data) == .lt;
            }
        }.lessThan);
    }
    const values = try results.toOwnedSlice(arena);
    if (config.withContext orelse false) {
        return .{ .context = .{ .context = .{ .slot = slot }, .value = values } };
    }
    return .{ .list = values };
}

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L2132
pub fn getTokenAccountsByDelegate(
    self: AccountHookContext,
    arena: std.mem.Allocator,
    params: GetTokenAccountsByDelegate,
) !GetTokenAccountsByDelegate.Response {
    const zone = tracy.Zone.init(@src(), .{ .name = "rpc.gTABD" });
    defer zone.deinit();

    const config = params.config orelse GetTokenAccountsByOwner.Config{};
    const commitment = config.commitment orelse .finalized;
    // [agave] Default encoding for gTABD is `Binary` (legacy base58), not base64.
    // https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L2149
    const encoding = config.encoding orelse AccountEncoding.binary;

    const slot = self.commitments.get(commitment);
    if (config.minContextSlot) |min_slot| {
        if (slot < min_slot) return error.RpcMinContextSlotNotMet;
    }

    const ref = self.slot_tracker.get(slot) orelse return error.SlotNotAvailable;
    defer ref.release();
    const ancestors = &ref.constants().ancestors;
    const slot_reader = self.account_reader.forSlot(ancestors).toOwnedReader();

    // Resolve filter -> token program ID + optional mint.
    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L2150
    const resolved = try params.filter.resolve(arena, slot_reader);

    // Build auto-filters: delegate option tag + delegate address + tokenAccountState + optional mint.
    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L2152
    const delegate_option_tag = [4]u8{ 0x01, 0x00, 0x00, 0x00 }; // COption<Pubkey>::Some, little-endian u32
    var filters: [4]RpcFilterType = undefined;
    var filter_count: usize = 0;
    // Filter on Delegate is_some() — COption tag at offset 72 == 1.
    filters[filter_count] = .{ .memcmp = .{ .offset = 72, .bytes = &delegate_option_tag } };
    filter_count += 1;
    // Filter on Delegate address at offset 76.
    filters[filter_count] = .{ .memcmp = .{ .offset = 76, .bytes = &params.delegate.data } };
    filter_count += 1;
    // Token account state: data.len == 165 && data[108] != 0.
    filters[filter_count] = .tokenAccountState;
    filter_count += 1;
    if (resolved.mint) |mint| {
        filters[filter_count] = .{ .memcmp = .{ .offset = 0, .bytes = &mint.data } };
        filter_count += 1;
    }
    const f = filters[0..filter_count];

    // [agave] No dedicated delegate index exists — scan all accounts of the token program.
    // https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L2174-L2180
    var iter = blk: {
        const z = tracy.Zone.init(@src(), .{ .name = "rpc.gTABD.ownerQuery" });
        defer z.deinit();
        break :blk try slot_reader.getByOwner(arena, &resolved.token_program_id);
    };
    defer iter.deinit();

    var results = std.ArrayListUnmanaged(GetTokenAccountsByDelegate.Value){};

    while (try iter.next()) |entry| {
        const pubkey, const account = entry;

        if (!sig.rpc.filters.filtersAllow(f, &account.data)) continue;

        const data = try account_codec.encodeAccount(
            arena,
            pubkey,
            account,
            encoding,
            slot_reader,
            config.dataSlice,
        );
        try results.append(arena, .{
            .pubkey = pubkey,
            .account = .from(account, data),
        });
    }

    // [agave] gTABD always sorts results by pubkey.
    // https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L2182
    {
        const z = tracy.Zone.init(@src(), .{ .name = "rpc.gTABD.sort" });
        defer z.deinit();
        std.mem.sortUnstable(GetTokenAccountsByDelegate.Value, results.items, {}, struct {
            fn lessThan(
                _: void,
                a: GetTokenAccountsByDelegate.Value,
                b: GetTokenAccountsByDelegate.Value,
            ) bool {
                return std.mem.order(u8, &a.pubkey.data, &b.pubkey.data) == .lt;
            }
        }.lessThan);
    }

    return .{
        .context = .{ .slot = slot },
        .value = try results.toOwnedSlice(arena),
    };
}

pub fn getTokenAccountsByOwner(
    self: AccountHookContext,
    arena: std.mem.Allocator,
    params: GetTokenAccountsByOwner,
) !GetTokenAccountsByOwner.Response {
    const zone = tracy.Zone.init(@src(), .{ .name = "rpc.getTokenAccountsByOwner" });
    defer zone.deinit();

    const config = params.config orelse GetTokenAccountsByOwner.Config{};
    const commitment = config.commitment orelse .finalized;
    // [agave] Default encoding for gTABO is `Binary` (legacy base58), not base64.
    // https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L2098
    const encoding = config.encoding orelse AccountEncoding.binary;

    const slot = try slot_resolution.resolveReadableCommitmentSlot(
        self.slot_tracker,
        self.commitments,
        commitment,
        config.minContextSlot,
    );

    const ref = self.slot_tracker.get(slot) orelse return error.SlotNotAvailable;
    defer ref.release();
    const ancestors = &ref.constants().ancestors;
    const slot_reader = self.account_reader.forSlot(ancestors).toOwnedReader();

    // Resolve filter -> token program ID + optional mint.
    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L2649-L2673
    const resolved = try params.filter.resolve(arena, slot_reader);

    // Build auto-filters: tokenAccountState + optional memcmp@0(mint).
    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L2627-L2648
    var filters: [2]RpcFilterType = undefined;
    var filter_count: usize = 0;
    filters[filter_count] = .tokenAccountState;
    filter_count += 1;
    if (resolved.mint != null) {
        filters[filter_count] = .{ .memcmp = .{ .offset = 0, .bytes = &resolved.mint.?.data } };
        filter_count += 1;
    }
    const f = filters[0..filter_count];

    var iter = blk: {
        const z = tracy.Zone.init(@src(), .{ .name = "rpc.gTABO.splTokenOwnerQuery" });
        defer z.deinit();
        break :blk try slot_reader.getBySplTokenOwner(&params.owner);
    };
    defer iter.deinit();

    var results = std.ArrayListUnmanaged(GetTokenAccountsByOwner.Value){};

    while (try iter.next()) |entry| {
        const pubkey, const account = entry;

        // Only include accounts owned by the resolved token program.
        // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L2115
        if (!account.owner.equals(&resolved.token_program_id)) continue;

        if (!sig.rpc.filters.filtersAllow(f, &account.data)) continue;

        const data = try account_codec.encodeAccount(
            arena,
            pubkey,
            account,
            encoding,
            slot_reader,
            config.dataSlice,
        );
        try results.append(arena, .{
            .pubkey = pubkey,
            .account = .from(account, data),
        });
    }

    // [agave] gTABO always sorts results by pubkey.
    // https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L2127
    {
        const z = tracy.Zone.init(@src(), .{ .name = "rpc.gTABO.sort" });
        defer z.deinit();
        std.mem.sortUnstable(GetTokenAccountsByOwner.Value, results.items, {}, struct {
            fn lessThan(
                _: void,
                a: GetTokenAccountsByOwner.Value,
                b: GetTokenAccountsByOwner.Value,
            ) bool {
                return a.pubkey.order(b.pubkey) == .lt;
            }
        }.lessThan);
    }

    return .{
        .context = .{ .slot = slot },
        .value = try results.toOwnedSlice(arena),
    };
}

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L1105-L1137
pub fn getSupply(
    self: AccountHookContext,
    arena: std.mem.Allocator,
    params: GetSupply,
) !GetSupply.Response {
    const config = params.config orelse GetSupply.Config{};
    const commitment = config.commitment orelse .finalized;
    const exclude_accounts = config.excludeNonCirculatingAccountsList;

    const slot = self.commitments.get(commitment);
    const ref = self.slot_tracker.get(slot) orelse return error.SlotNotAvailable;
    defer ref.release();
    const ancestors = &ref.constants().ancestors;
    const slot_reader = self.account_reader.forSlot(ancestors).toOwnedReader();

    // Read the Clock sysvar to check lockup conditions.
    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/non_circulating_supply.rs#L18-L22
    const clock = try account_codec.getSysvar(sig.runtime.sysvar.Clock, arena, slot_reader) orelse
        return error.SlotNotAvailable;

    var non_circulating_lamports: u64 = 0;
    var non_circulating_accounts = std.ArrayListUnmanaged(sig.core.Pubkey){};
    if (!exclude_accounts) try non_circulating_accounts
        .ensureUnusedCapacity(arena, non_circulating_supply.non_circulating_accounts.len);

    // Sum lamports for the static non-circulating accounts.
    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/non_circulating_supply.rs#L24-L29
    for (&non_circulating_supply.non_circulating_accounts) |*raw| {
        if (slot_reader.get(arena, .{ .data = raw.* }) catch null) |account| {
            non_circulating_lamports += account.lamports;
        }
        if (!exclude_accounts) non_circulating_accounts.appendAssumeCapacity(.{ .data = raw.* });
    }

    // Iterate all stake accounts and collect non-circulating ones not already in the static set.
    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/non_circulating_supply.rs#L30-L46
    var owner_iter = try slot_reader.getByOwner(arena, &sig.runtime.program.stake.ID);
    defer owner_iter.deinit();

    while (try owner_iter.next()) |entry| {
        const pubkey, const account = entry;

        if (parse_stake.isNonCirculatingStake(arena, &account.data, &clock)) {
            // Dedup against the static set via perfect hash lookup.
            if (NonCirculatingSet.get(&pubkey) == null) {
                non_circulating_lamports += account.lamports;
                if (!exclude_accounts) try non_circulating_accounts.append(arena, pubkey);
            }
        }
    }

    // [agave] Total supply is the capitalization at this slot.
    // https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L1121
    const total = ref.state().capitalization.load(.monotonic);

    return .{
        .context = .{ .slot = slot },
        .value = .{
            .total = total,
            .circulating = total -| non_circulating_lamports,
            .nonCirculating = non_circulating_lamports,
            .nonCirculatingAccounts = try non_circulating_accounts.toOwnedSlice(arena),
        },
    };
}

/// Returns the 20 largest accounts of a particular SPL Token mint.
/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L2021-L2069
pub fn getTokenLargestAccounts(
    self: AccountHookContext,
    arena: std.mem.Allocator,
    params: GetTokenLargestAccounts,
) !GetTokenLargestAccounts.Response {
    const config: GetTokenLargestAccounts.Config = params.config orelse .{};
    const commitment = config.commitment orelse .finalized;

    const slot = self.commitments.get(commitment);

    const ref = self.slot_tracker.get(slot) orelse return error.SlotNotAvailable;
    defer ref.release();
    const slot_reader = self.account_reader.forSlot(&ref.constants().ancestors).toOwnedReader();

    // Validate that the mint exists and is owned by a token program.
    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L2030-L2039
    const maybe_mint_account = try slot_reader.get(arena, params.mint);
    const mint_account = maybe_mint_account orelse return error.RpcAccountNotFound;

    const mint_owner = mint_account.owner;
    const is_token_program = mint_owner.equals(&sig.runtime.ids.TOKEN_PROGRAM_ID) or
        mint_owner.equals(&sig.runtime.ids.TOKEN_2022_PROGRAM_ID);
    if (!is_token_program) return error.RpcNotATokenAccount;

    // Read mint data into contiguous buffer for parsing and extension extraction.
    const mint_data_len = mint_account.data.len();
    const mint_data = try arena.alloc(u8, mint_data_len);
    var mint_data_iter = mint_account.data.iterator();
    _ = mint_data_iter.readBytes(mint_data) catch return error.RpcMintUnpackFailed;

    // Validate this is actually a mint account, not a token account or multisig.
    const detected = parse_token.DetectedType.parse(mint_data) orelse
        return error.RpcMintUnpackFailed;
    if (detected != .mint) return error.RpcMintUnpackFailed;

    // Parse mint to validate it's initialized (matching getTokenSupply).
    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L2028
    const mint = parse_token.Mint.unpack(mint_data) catch return error.RpcMintUnpackFailed;
    if (!mint.is_initialized) return error.RpcMintUnpackFailed;

    // Extract decimals, extension configs for UiTokenAmount conversion.
    const spl_token_data = account_codec.parseMintAdditionalData(
        arena,
        mint_data,
        slot_reader,
    ) orelse return error.RpcMintUnpackFailed;

    // Scan all token accounts owned by the mint's token program, filtered to this mint.
    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L2035-L2062
    const N = GetTokenLargestAccounts.NUM_LARGEST_ACCOUNTS;
    const Entry = struct { address: sig.core.Pubkey, amount: u64 };

    // Min-heap: smallest amount at top for efficient eviction of the smallest entry.
    // Tiebreak by pubkey for determinism, matching Agave's (u64, Pubkey) tuple ordering.
    const MinHeap = std.PriorityQueue(Entry, void, struct {
        fn order(_: void, a: Entry, b: Entry) std.math.Order {
            const amt_order = std.math.order(a.amount, b.amount);
            if (amt_order != .eq) return amt_order;
            return std.mem.order(u8, &a.address.data, &b.address.data);
        }
    }.order);

    var heap = MinHeap.init(arena, {});
    try heap.ensureTotalCapacity(N + 1);

    // Only scan the token program that owns this mint — a mint's token accounts
    // are always under the same program as the mint itself.
    var iter = try slot_reader.getByOwner(arena, &mint_owner);
    defer iter.deinit();

    while (try iter.next()) |entry| {
        const pubkey, const account = entry;

        // Parse token account data to get mint and amount.
        var data_buf: [parse_token.TokenAccount.LEN]u8 = undefined;
        var data_iter = account.data.iterator();
        const bytes_read = data_iter.readBytes(&data_buf) catch continue;
        if (bytes_read < parse_token.TokenAccount.LEN) continue;

        const token_account = parse_token.TokenAccount.unpack(&data_buf) catch continue;
        if (token_account.state == .uninitialized) continue;

        // Filter by the requested mint.
        if (!token_account.mint.equals(&params.mint)) continue;

        // Insert into min-heap, evict smallest if over capacity.
        heap.add(.{ .address = pubkey, .amount = token_account.amount }) catch unreachable;
        if (heap.count() > N) {
            _ = heap.remove();
        }
    }

    // Extract results from heap and sort by amount descending.
    const results = try arena.alloc(
        GetTokenLargestAccounts.TokenAccountBalancePair,
        heap.count(),
    );
    // Min-heap extraction yields ascending order; fill backwards for
    // descending (largest first) to match Agave behavior.
    var i: usize = results.len;
    while (i > 0) {
        i -= 1;
        const entry = heap.remove();
        results[i] = .{
            .address = entry.address,
            .ui_token_amount = .init(entry.amount, spl_token_data),
        };
    }

    return .{
        .context = .{ .slot = slot },
        .value = results,
    };
}

/// [agave] Agave's cache is keyed only by filter (None/Circulating/NonCirculating),
/// not by commitment level. The cache is checked before bank selection, so a
/// cached processed-era result is served to finalized callers and vice versa.
/// TTL is 2 hours with no explicit invalidation. (rpc.rs:1053-1058, rpc_cache.rs:1-77)
pub fn getLargestAccounts(
    self: AccountHookContext,
    arena: std.mem.Allocator,
    params: GetLargestAccounts,
) !GetLargestAccounts.Response {
    const config = params.config orelse GetLargestAccounts.Config{};
    const commitment = config.commitment orelse .finalized;
    const sort_results = config.sortResults orelse true;

    const slot = self.commitments.get(commitment);
    const ref = self.slot_tracker.get(slot) orelse return error.SlotNotAvailable;
    defer ref.release();
    const ancestors = &ref.constants().ancestors;
    const slot_reader = self.account_reader.forSlot(ancestors).toOwnedReader();

    const results = try slot_reader.getLargest(arena, GetLargestAccounts.MAX_LARGEST_ACCOUNTS);

    // Apply circulating/nonCirculating filter if requested.
    const values = if (config.filter) |filter| blk: {
        // Build the non-circulating account set (same logic as getSupply).
        const clock = try account_codec.getSysvar(
            sig.runtime.sysvar.Clock,
            arena,
            slot_reader,
        ) orelse
            return error.SlotNotAvailable;

        var nc_set = std.AutoArrayHashMap(sig.core.Pubkey, void).init(arena);

        for (&non_circulating_supply.non_circulating_accounts) |*raw| {
            try nc_set.put(.{ .data = raw.* }, {});
        }

        var owner_iter = try slot_reader.getByOwner(arena, &sig.runtime.program.stake.ID);
        defer owner_iter.deinit();

        while (try owner_iter.next()) |entry| {
            const pubkey, const account = entry;
            if (parse_stake.isNonCirculatingStake(arena, &account.data, &clock)) {
                try nc_set.put(pubkey, {});
            }
        }

        // Filter results based on whether they are in the non-circulating set.
        var filtered = std.ArrayListUnmanaged(GetLargestAccounts.AccountBalance){};
        for (results) |entry| {
            const pubkey, const lamports = entry;
            const is_non_circulating = nc_set.contains(pubkey);
            const include = switch (filter) {
                .circulating => !is_non_circulating,
                .nonCirculating => is_non_circulating,
            };
            if (include) {
                try filtered.append(arena, .{ .address = pubkey, .lamports = lamports });
            }
        }
        break :blk try filtered.toOwnedSlice(arena);
    } else blk: {
        const vals = try arena.alloc(GetLargestAccounts.AccountBalance, results.len);
        for (vals, results) |*val, entry| {
            const pubkey, const lamports = entry;
            val.* = .{ .address = pubkey, .lamports = lamports };
        }
        break :blk vals;
    };

    if (sort_results) {
        std.mem.sortUnstable(GetLargestAccounts.AccountBalance, values, {}, struct {
            pub fn lessThan(
                _: void,
                a: GetLargestAccounts.AccountBalance,
                b: GetLargestAccounts.AccountBalance,
            ) bool {
                if (a.lamports != b.lamports) return a.lamports > b.lamports;
                return b.address.order(a.address) == .lt;
            }
        }.lessThan);
    }

    return .{
        .context = .{ .slot = slot },
        .value = values,
    };
}

const testing = std.testing;

fn testSlotConstants(slot: Slot, ancestors: sig.core.Ancestors) sig.core.SlotConstants {
    return .{
        .parent_slot = slot -| 1,
        .parent_hash = .ZEROES,
        .parent_lt_hash = .IDENTITY,
        .block_height = slot,
        .collector_id = .ZEROES,
        .max_tick_height = 0,
        .fee_rate_governor = .DEFAULT,
        .ancestors = ancestors,
        .feature_set = .ALL_DISABLED,
        .reserved_accounts = .empty,
        .inflation = .DEFAULT,
        .rent_collector = .DEFAULT,
    };
}

fn testSlotState() sig.core.SlotState {
    return .GENESIS;
}

fn testSetupContext(
    db: *sig.accounts_db.Db,
    slot_tracker: *sig.replay.trackers.SlotTracker,
    commitments: *sig.replay.trackers.CommitmentTracker,
) AccountHookContext {
    return .{
        .slot_tracker = slot_tracker,
        .commitments = commitments,
        .account_reader = .{ .accounts_db = db },
    };
}

/// Helper to create a SlotTracker with ancestors for tests.
/// The returned slot_tracker owns the ancestors; caller must only deinit slot_tracker.
fn testInitSlotTracker(
    slot: Slot,
    ancestors_slots: []const Slot,
) !sig.replay.trackers.SlotTracker {
    const ancestors: sig.core.Ancestors = try .initWithSlots(testing.allocator, ancestors_slots);
    // SlotTracker.init takes ownership of ancestors via SlotConstants.
    // Only slot_tracker.deinit should be called (not ancestors.deinit).
    const slot_tracker: sig.replay.trackers.SlotTracker = try .init(testing.allocator, slot, .{
        .constants = testSlotConstants(slot, ancestors),
        .state = testSlotState(),
        .allocator = testing.allocator,
    });

    return slot_tracker;
}

test "getBalance - returns balance for existing account" {
    var test_state = try sig.accounts_db.Db.initTest(testing.allocator);
    defer test_state.deinit();
    const db = &test_state.db;

    const test_slot: Slot = 42;
    const test_pubkey = sig.core.Pubkey.ZEROES;
    const test_lamports: u64 = 1_000_000;

    try db.put(test_slot, test_pubkey, .{
        .lamports = test_lamports,
        .data = &.{},
        .owner = sig.core.Pubkey.ZEROES,
        .executable = false,
        .rent_epoch = 0,
    });

    var slot_tracker = try testInitSlotTracker(test_slot, &.{test_slot});
    defer slot_tracker.deinit(testing.allocator);

    var commitments: sig.replay.trackers.CommitmentTracker = .init(testing.allocator, test_slot);
    defer commitments.deinit(testing.allocator);

    const ctx = testSetupContext(db, &slot_tracker, &commitments);
    const result = try ctx.getBalance(testing.allocator, .{ .pubkey = test_pubkey });
    try testing.expectEqual(test_lamports, result.value);
    try testing.expectEqual(test_slot, result.context.slot);
}

test "getBalance - returns zero for non-existent account" {
    var test_state = try sig.accounts_db.Db.initTest(testing.allocator);
    defer test_state.deinit();
    const db = &test_state.db;

    const test_slot: Slot = 42;
    var slot_tracker = try testInitSlotTracker(test_slot, &.{test_slot});
    defer slot_tracker.deinit(testing.allocator);

    var commitments: sig.replay.trackers.CommitmentTracker = .init(testing.allocator, test_slot);
    defer commitments.deinit(testing.allocator);

    const ctx = testSetupContext(db, &slot_tracker, &commitments);
    const result = try ctx.getBalance(testing.allocator, .{ .pubkey = sig.core.Pubkey.ZEROES });
    try testing.expectEqual(@as(u64, 0), result.value);
}

test "getBalance - minContextSlot enforcement" {
    var test_state = try sig.accounts_db.Db.initTest(testing.allocator);
    defer test_state.deinit();
    const db = &test_state.db;

    const test_slot: Slot = 10;
    var slot_tracker = try testInitSlotTracker(test_slot, &.{test_slot});
    defer slot_tracker.deinit(testing.allocator);

    var commitments: sig.replay.trackers.CommitmentTracker = .init(testing.allocator, test_slot);
    defer commitments.deinit(testing.allocator);

    const ctx = testSetupContext(db, &slot_tracker, &commitments);
    const err = ctx.getBalance(testing.allocator, .{
        .pubkey = sig.core.Pubkey.ZEROES,
        .config = .{ .minContextSlot = 100 },
    });
    try testing.expectError(error.RpcMinContextSlotNotMet, err);
}

test "getAccountInfo - returns account data" {
    var test_state = try sig.accounts_db.Db.initTest(testing.allocator);
    defer test_state.deinit();
    const db = &test_state.db;

    const test_slot: Slot = 42;
    const test_pubkey = sig.core.Pubkey.ZEROES;
    const test_lamports: u64 = 500_000;

    try db.put(test_slot, test_pubkey, .{
        .lamports = test_lamports,
        .data = &.{},
        .owner = sig.core.Pubkey.ZEROES,
        .executable = false,
        .rent_epoch = 0,
    });

    var slot_tracker = try testInitSlotTracker(test_slot, &.{test_slot});
    defer slot_tracker.deinit(testing.allocator);

    var commitments: sig.replay.trackers.CommitmentTracker = .init(testing.allocator, test_slot);
    defer commitments.deinit(testing.allocator);

    const ctx = testSetupContext(db, &slot_tracker, &commitments);
    const result = try ctx.getAccountInfo(testing.allocator, .{
        .pubkey = test_pubkey,
        .config = .{ .encoding = .base64 },
    });
    try testing.expectEqual(test_slot, result.context.slot);
    try testing.expect(result.value != null);
    try testing.expectEqual(test_lamports, result.value.?.lamports);
}

test "getAccountInfo - returns null for non-existent account" {
    var test_state = try sig.accounts_db.Db.initTest(testing.allocator);
    defer test_state.deinit();
    const db = &test_state.db;

    const test_slot: Slot = 42;
    var slot_tracker = try testInitSlotTracker(test_slot, &.{test_slot});
    defer slot_tracker.deinit(testing.allocator);

    var commitments: sig.replay.trackers.CommitmentTracker = .init(testing.allocator, test_slot);
    defer commitments.deinit(testing.allocator);

    const ctx = testSetupContext(db, &slot_tracker, &commitments);
    const result = try ctx.getAccountInfo(testing.allocator, .{
        .pubkey = sig.core.Pubkey.ZEROES,
        .config = .{ .encoding = .base64 },
    });
    try testing.expectEqual(test_slot, result.context.slot);
    try testing.expect(result.value == null);
}

test "getAccountInfo - minContextSlot enforcement" {
    var test_state = try sig.accounts_db.Db.initTest(testing.allocator);
    defer test_state.deinit();
    const db = &test_state.db;

    const test_slot: Slot = 10;
    var slot_tracker = try testInitSlotTracker(test_slot, &.{test_slot});
    defer slot_tracker.deinit(testing.allocator);

    var commitments: sig.replay.trackers.CommitmentTracker = .init(testing.allocator, test_slot);
    defer commitments.deinit(testing.allocator);

    const ctx = testSetupContext(db, &slot_tracker, &commitments);
    const err = ctx.getAccountInfo(testing.allocator, .{
        .pubkey = sig.core.Pubkey.ZEROES,
        .config = .{ .minContextSlot = 100 },
    });
    try testing.expectError(error.RpcMinContextSlotNotMet, err);
}

test "getMultipleAccounts - returns accounts" {
    var test_state = try sig.accounts_db.Db.initTest(testing.allocator);
    defer test_state.deinit();
    const db = &test_state.db;

    const test_slot: Slot = 42;
    var pubkey1: sig.core.Pubkey = .ZEROES;
    pubkey1.data[0] = 1;
    var pubkey2: sig.core.Pubkey = .ZEROES;
    pubkey2.data[0] = 2;

    try db.put(test_slot, pubkey1, .{
        .lamports = 100,
        .data = &.{},
        .owner = sig.core.Pubkey.ZEROES,
        .executable = false,
        .rent_epoch = 0,
    });

    var slot_tracker = try testInitSlotTracker(test_slot, &.{test_slot});
    defer slot_tracker.deinit(testing.allocator);

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var commitments: sig.replay.trackers.CommitmentTracker = .init(testing.allocator, test_slot);
    defer commitments.deinit(testing.allocator);

    const ctx = testSetupContext(db, &slot_tracker, &commitments);
    const result = try ctx.getMultipleAccounts(arena, .{
        .pubkeys = &.{ pubkey1, pubkey2 },
    });
    try testing.expectEqual(test_slot, result.context.slot);
    try testing.expectEqual(@as(usize, 2), result.value.len);
    try testing.expect(result.value[0] != null); // pubkey1 exists
    try testing.expect(result.value[1] == null); // pubkey2 doesn't exist
    try testing.expectEqual(@as(u64, 100), result.value[0].?.lamports);
}

test "getMultipleAccounts - minContextSlot enforcement" {
    var test_state = try sig.accounts_db.Db.initTest(testing.allocator);
    defer test_state.deinit();
    const db = &test_state.db;

    const test_slot: Slot = 10;
    var slot_tracker = try testInitSlotTracker(test_slot, &.{test_slot});
    defer slot_tracker.deinit(testing.allocator);

    var commitments: sig.replay.trackers.CommitmentTracker = .init(testing.allocator, test_slot);
    defer commitments.deinit(testing.allocator);

    const ctx = testSetupContext(db, &slot_tracker, &commitments);
    const err = ctx.getMultipleAccounts(testing.allocator, .{
        .pubkeys = &.{sig.core.Pubkey.ZEROES},
        .config = .{ .minContextSlot = 100 },
    });
    try testing.expectError(error.RpcMinContextSlotNotMet, err);
}

test "getFeeForMessage - minContextSlot enforcement" {
    var test_state = try sig.accounts_db.Db.initTest(testing.allocator);
    defer test_state.deinit();
    const db = &test_state.db;

    const test_slot: Slot = 10;
    var slot_tracker = try testInitSlotTracker(test_slot, &.{test_slot});
    defer slot_tracker.deinit(testing.allocator);

    var commitments: sig.replay.trackers.CommitmentTracker = .init(testing.allocator, test_slot);
    defer commitments.deinit(testing.allocator);

    const ctx = testSetupContext(db, &slot_tracker, &commitments);
    const err = ctx.getFeeForMessage(testing.allocator, .{
        .message = "AQABA",
        .config = .{ .minContextSlot = 100 },
    });
    try testing.expectError(error.RpcMinContextSlotNotMet, err);
}

test "getProgramAccounts - minContextSlot enforcement" {
    var test_state = try sig.accounts_db.Db.initTest(testing.allocator);
    defer test_state.deinit();
    const db = &test_state.db;

    const test_slot: Slot = 10;
    var slot_tracker = try testInitSlotTracker(test_slot, &.{test_slot});
    defer slot_tracker.deinit(testing.allocator);

    var commitments: sig.replay.trackers.CommitmentTracker = .init(testing.allocator, test_slot);
    defer commitments.deinit(testing.allocator);

    const ctx = testSetupContext(db, &slot_tracker, &commitments);
    const err = ctx.getProgramAccounts(testing.allocator, .{
        .program_id = sig.core.Pubkey.ZEROES,
        .config = .{ .minContextSlot = 100 },
    });
    try testing.expectError(error.RpcMinContextSlotNotMet, err);
}

test "getTokenAccountsByOwner - minContextSlot enforcement" {
    var test_state = try sig.accounts_db.Db.initTest(testing.allocator);
    defer test_state.deinit();
    const db = &test_state.db;

    const test_slot: Slot = 10;
    var slot_tracker = try testInitSlotTracker(test_slot, &.{test_slot});
    defer slot_tracker.deinit(testing.allocator);

    var commitments: sig.replay.trackers.CommitmentTracker = .init(testing.allocator, test_slot);
    defer commitments.deinit(testing.allocator);

    const ctx = testSetupContext(db, &slot_tracker, &commitments);
    const err = ctx.getTokenAccountsByOwner(testing.allocator, .{
        .owner = sig.core.Pubkey.ZEROES,
        .filter = .{ .programId = sig.runtime.ids.TOKEN_PROGRAM_ID },
        .config = .{ .minContextSlot = 100 },
    });
    try testing.expectError(error.RpcMinContextSlotNotMet, err);
}

test "getTokenAccountBalance - resolves commitment slot" {
    var test_state = try sig.accounts_db.Db.initTest(testing.allocator);
    defer test_state.deinit();
    const db = &test_state.db;

    const test_slot: Slot = 42;
    var slot_tracker = try testInitSlotTracker(test_slot, &.{test_slot});
    defer slot_tracker.deinit(testing.allocator);

    var commitments: sig.replay.trackers.CommitmentTracker = .init(testing.allocator, test_slot);
    defer commitments.deinit(testing.allocator);

    const ctx = testSetupContext(db, &slot_tracker, &commitments);
    // Non-existent account should return RpcAccountNotFound
    const err = ctx.getTokenAccountBalance(testing.allocator, .{
        .pubkey = sig.core.Pubkey.ZEROES,
    });
    try testing.expectError(error.RpcAccountNotFound, err);
}

test "getTokenSupply - resolves commitment slot" {
    var test_state = try sig.accounts_db.Db.initTest(testing.allocator);
    defer test_state.deinit();
    const db = &test_state.db;

    const test_slot: Slot = 42;
    var slot_tracker = try testInitSlotTracker(test_slot, &.{test_slot});
    defer slot_tracker.deinit(testing.allocator);

    var commitments: sig.replay.trackers.CommitmentTracker = .init(testing.allocator, test_slot);
    defer commitments.deinit(testing.allocator);

    const ctx = testSetupContext(db, &slot_tracker, &commitments);
    // Non-existent mint should return RpcAccountNotFound
    const err = ctx.getTokenSupply(testing.allocator, .{
        .mint = sig.core.Pubkey.ZEROES,
    });
    try testing.expectError(error.RpcAccountNotFound, err);
}
