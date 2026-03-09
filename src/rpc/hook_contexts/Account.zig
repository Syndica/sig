//! The Account RPC hook context. Contains references to the necessary state in the validator required for reading out account data and for serving RPC.

const std = @import("std");
const tracy = @import("tracy");

const sig = @import("../../sig.zig");

const account_codec = sig.rpc.account_codec;
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
const GetTokenAccountBalance = sig.rpc.methods.GetTokenAccountBalance;
const GetTokenSupply = sig.rpc.methods.GetTokenSupply;
const GetMultipleAccounts = sig.rpc.methods.GetMultipleAccounts;
const GetProgramAccounts = sig.rpc.methods.GetProgramAccounts;

const AccountEncoding = account_codec.AccountEncoding;
const CommitmentSlotConfig = sig.rpc.methods.common.CommitmentSlotConfig;

const AccountHookContext = @This();

slot_tracker: *sig.replay.trackers.SlotTracker,
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
    // [agave] Default encoding in agave is `Binary` (legacy base58):
    // https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L545
    // However, `Binary` is deprecated and `Base64` is preferred for performance.
    // We default to base64 as it's more efficient and the recommended encoding.
    const encoding = config.encoding orelse AccountEncoding.binary;

    const slot = self.slot_tracker.commitments.get(commitment);
    if (config.minContextSlot) |min_slot| {
        if (slot < min_slot) return error.RpcMinContextSlotNotMet;
    }

    const ref = self.slot_tracker.get(slot) orelse return error.SlotNotAvailable;
    defer ref.release();
    const slot_reader = self.account_reader.forSlot(&ref.constants().ancestors);
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

    const slot = self.slot_tracker.commitments.get(commitment);
    if (config.minContextSlot) |min_slot| {
        if (slot < min_slot) return error.RpcMinContextSlotNotMet;
    }

    // Get slot reference to access ancestors
    const ref = self.slot_tracker.get(slot) orelse return error.SlotNotAvailable;
    defer ref.release();
    const slot_reader = self.account_reader.forSlot(&ref.constants().ancestors);

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

    const slot = self.slot_tracker.commitments.get(commitment);

    const ref = self.slot_tracker.get(slot) orelse return error.SlotNotAvailable;
    defer ref.release();
    const slot_reader = self.account_reader.forSlot(&ref.constants().ancestors);
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

    const slot = self.slot_tracker.commitments.get(commitment);

    const ref = self.slot_tracker.get(slot) orelse return error.SlotNotAvailable;
    defer ref.release();
    const slot_reader = self.account_reader.forSlot(&ref.constants().ancestors);

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

    const slot = self.slot_tracker.getSlotForCommitment(commitment);
    if (config.minContextSlot) |min_slot| {
        if (slot < min_slot) return error.RpcMinContextSlotNotMet;
    }

    const ref = self.slot_tracker.get(slot) orelse return error.SlotNotAvailable;
    defer ref.release();
    const slot_reader = self.account_reader.forSlot(&ref.constants().ancestors);
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

    const slot = self.slot_tracker.commitments.get(commitment);

    if (config.minContextSlot) |min_slot| {
        if (slot < min_slot) return error.RpcMinContextSlotNotMet;
    }

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

    const slot_account_reader = self.account_reader.forSlot(&slot_ref.constants().ancestors);

    const empty_result: GetFeeForMessage.Response = .{
        .context = .{ .slot = slot },
        .value = null,
    };

    const runtime_txn = (messageToRuntimeTransaction(
        arena,
        message,
        version,
        slot_account_reader,
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
            slot_account_reader,
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
    const zone = tracy.Zone.init(@src(), .{ .name = "rpc.gPA" });
    defer zone.deinit();

    const config = params.config orelse GetProgramAccounts.Config{};
    const commitment = config.commitment orelse .finalized;
    const encoding = config.encoding orelse .base64;
    const f = config.filters orelse &.{};
    try sig.rpc.filters.verifyFilters(f);

    const slot = self.slot_tracker.getSlotForCommitment(commitment);
    const ref = self.slot_tracker.get(slot) orelse return error.SlotNotAvailable;
    defer ref.release();
    const ancestors = &ref.constants().ancestors;
    const slot_reader = self.account_reader.forSlot(ancestors);

    var iter = blk: {
        const z = tracy.Zone.init(@src(), .{ .name = "rpc.gPA.ownerQuery" });
        defer z.deinit();
        break :blk try slot_reader.getByOwner(arena, &params.program_id);
    };

    var results = std.ArrayListUnmanaged(GetProgramAccounts.Value){};

    while (try iter.next()) |entry| {
        const pubkey, const account = entry;
        if (account.lamports == 0) continue;
        const data_slice: []const u8 = switch (account.data) {
            .unowned_allocation => |d| d,
            .owned_allocation => |d| d,
            else => @panic("gPA: unexpected AccountDataHandle variant"),
        };
        if (!sig.rpc.filters.filtersAllow(f, data_slice)) continue;

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

    if (config.sortResults orelse false) {
        const z = tracy.Zone.init(@src(), .{ .name = "rpc.gPA.sort" });
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
