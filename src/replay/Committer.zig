const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");
const tracy = @import("tracy");

const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const Channel = sig.sync.Channel;
const Logger = sig.trace.Logger("replay.committer");

const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const Transaction = sig.core.Transaction;

const ResolvedTransaction = replay.resolve_lookup.ResolvedTransaction;

const Account = sig.core.Account;
const LoadedAccount = sig.runtime.account_loader.LoadedAccount;
const ProcessedTransaction = sig.runtime.transaction_execution.ProcessedTransaction;
const TransactionStatusMeta = sig.ledger.transaction_status.TransactionStatusMeta;
const TransactionStatusMetaBuilder = sig.ledger.transaction_status.TransactionStatusMetaBuilder;
const LoadedAddresses = sig.ledger.transaction_status.LoadedAddresses;
const Ledger = sig.ledger.Ledger;
const SlotAccountStore = sig.accounts_db.SlotAccountStore;
const spl_token = sig.runtime.spl_token;

const ParsedVote = sig.consensus.vote_listener.vote_parser.ParsedVote;
const parseSanitizedVoteTransaction =
    sig.consensus.vote_listener.vote_parser.parseSanitizedVoteTransaction;

const Committer = @This();

logger: Logger,
slot_state: *sig.core.SlotState,
status_cache: *sig.core.StatusCache,
stakes_cache: *sig.core.StakesCache,
new_rate_activation_epoch: ?sig.core.Epoch,
replay_votes_sender: ?*Channel(ParsedVote),
/// Ledger for persisting transaction status metadata (optional for backwards compatibility)
ledger: ?*Ledger,
/// Account store for looking up accounts (e.g. mint accounts for token balance resolution)
account_store: ?SlotAccountStore,

pub fn commitTransactions(
    self: Committer,
    persistent_allocator: Allocator,
    temp_allocator: Allocator,
    slot: Slot,
    transactions: []const ResolvedTransaction,
    tx_results: []const struct { Hash, ProcessedTransaction },
) !void {
    var zone = tracy.Zone.init(@src(), .{ .name = "commitTransactions" });
    zone.value(transactions.len);
    defer zone.deinit();
    errdefer zone.color(0xFF0000);

    var rng = std.Random.DefaultPrng.init(slot + transactions.len);

    var accounts_to_store = sig.utils.collections.PubkeyMap(LoadedAccount).empty;
    defer accounts_to_store.deinit(temp_allocator);

    var signature_count: usize = 0;
    var rent_collected: u64 = 0;

    var transaction_fees: u64 = 0;
    var priority_fees: u64 = 0;

    for (transactions, tx_results, 0..) |transaction, *result, transaction_index| {
        const message_hash = &result.@"0";
        const tx_result = &result.@"1";

        signature_count += transaction.transaction.signatures.len;

        for (tx_result.writes.constSlice()) |*account| {
            try accounts_to_store.put(temp_allocator, account.pubkey, account.*);
        }
        transaction_fees += tx_result.fees.transaction_fee;
        priority_fees += tx_result.fees.prioritization_fee;

        // TODO: fix nesting, this sucks

        if (tx_result.outputs != null) {
            rent_collected += tx_result.rent;

            // Skip non successful or non vote transactions.
            // Only send votes if consensus is enabled (sender exists)
            if (self.replay_votes_sender) |sender| {
                if (tx_result.err == null and isSimpleVoteTransaction(transaction.transaction)) {
                    if (try parseSanitizedVoteTransaction(
                        persistent_allocator,
                        transaction,
                    )) |parsed| {
                        if (parsed.vote.lastVotedSlot() != null) {
                            sender.send(parsed) catch parsed.deinit(persistent_allocator);
                        } else {
                            parsed.deinit(persistent_allocator);
                        }
                    }
                }
            }
        }

        const recent_blockhash = &transaction.transaction.msg.recent_blockhash;
        const signature = transaction.transaction.signatures[0];
        {
            const status_cache_zone = tracy.Zone.init(
                @src(),
                .{ .name = "status_cache.insert: message_hash.data" },
            );
            defer status_cache_zone.deinit();

            try self.status_cache.insert(
                persistent_allocator,
                rng.random(),
                recent_blockhash,
                &message_hash.data,
                slot,
            );
        }
        {
            const status_cache_zone = tracy.Zone.init(
                @src(),
                .{ .name = "status_cache.insert: signature.toBytes()" },
            );
            defer status_cache_zone.deinit();

            try self.status_cache.insert(
                persistent_allocator,
                rng.random(),
                recent_blockhash,
                &signature.toBytes(),
                slot,
            );
        }

        // Write transaction status to ledger for RPC (getBlock, getTransaction)
        if (self.ledger) |ledger| {
            try writeTransactionStatus(
                temp_allocator,
                ledger,
                slot,
                transaction,
                tx_result.*,
                transaction_index,
                self.account_store,
            );
        }
    }

    _ = self.slot_state.collected_transaction_fees.fetchAdd(transaction_fees, .monotonic);
    _ = self.slot_state.collected_priority_fees.fetchAdd(priority_fees, .monotonic);
    _ = self.slot_state.transaction_count.fetchAdd(tx_results.len, .monotonic);
    _ = self.slot_state.signature_count.fetchAdd(signature_count, .monotonic);
    _ = self.slot_state.collected_rent.fetchAdd(rent_collected, .monotonic);

    for (accounts_to_store.values()) |account| {
        try self.stakes_cache.checkAndStore(
            persistent_allocator,
            account.pubkey,
            account.account,
            self.new_rate_activation_epoch,
        );
    }
}

/// Build and write TransactionStatusMeta to the ledger for a single transaction.
fn writeTransactionStatus(
    allocator: Allocator,
    ledger: *Ledger,
    slot: Slot,
    transaction: ResolvedTransaction,
    tx_result: ProcessedTransaction,
    transaction_index: usize,
    account_store: ?SlotAccountStore,
) !void {
    const status_write_zone = tracy.Zone.init(@src(), .{ .name = "writeTransactionStatus" });
    defer status_write_zone.deinit();

    const signature = transaction.transaction.signatures[0];
    const num_accounts = transaction.accounts.len;

    // Use pre-balances captured during execution
    // If pre_balances is empty (account loading failed), use zeros
    const pre_balances = try allocator.alloc(u64, num_accounts);
    defer allocator.free(pre_balances);
    if (tx_result.pre_balances.len == num_accounts) {
        @memcpy(pre_balances, tx_result.pre_balances.constSlice());
    } else {
        // Account loading failed - pre-balances not available
        @memset(pre_balances, 0);
    }

    // Compute post-balances: start with pre-balances, then update from writes
    var post_balances = try allocator.alloc(u64, num_accounts);
    defer allocator.free(post_balances);
    @memcpy(post_balances, pre_balances);

    // Update post-balances with values from written accounts
    for (tx_result.writes.constSlice()) |*written_account| {
        // Find the index of this account in the transaction
        for (transaction.accounts.items(.pubkey), 0..) |pubkey, idx| {
            if (pubkey.equals(&written_account.pubkey)) {
                post_balances[idx] = written_account.account.lamports;
                break;
            }
        }
    }

    // Extract loaded addresses from address lookup tables if present
    // For now, we use empty loaded addresses since the transaction resolution
    // already expanded the lookup table addresses into the accounts list
    const loaded_addresses = LoadedAddresses{
        .writable = &.{},
        .readonly = &.{},
    };

    // Collect token balances
    // Build a mint decimals cache from writes (for mints modified in this tx)
    var mint_cache = spl_token.MintDecimalsCache.init(allocator);
    defer mint_cache.deinit();

    // Populate cache with any mints found in the transaction writes
    for (tx_result.writes.constSlice()) |*written_account| {
        const acc = written_account.account;
        const pubkey = written_account.pubkey;
        if (acc.data.len >= spl_token.MINT_ACCOUNT_SIZE) {
            if (spl_token.ParsedMint.parse(acc.data[0..spl_token.MINT_ACCOUNT_SIZE])) |mint| {
                mint_cache.put(pubkey, mint.decimals) catch {};
            }
        }
    }

    // Resolve pre-token balances using FallbackAccountReader (writes first, then account store)
    const mint_reader = FallbackAccountReader{
        .writes = tx_result.writes.constSlice(),
        .account_store_reader = if (account_store) |store| store.reader() else null,
    };
    const pre_token_balances = spl_token.resolveTokenBalances(
        allocator,
        tx_result.pre_token_balances,
        &mint_cache,
        FallbackAccountReader,
        mint_reader,
    );
    defer if (pre_token_balances) |balances| {
        for (balances) |b| b.deinit(allocator);
        allocator.free(balances);
    };

    // Compute post-token balances from writes
    const post_raw_token_balances = collectPostTokenBalances(transaction, tx_result);
    const post_token_balances = spl_token.resolveTokenBalances(
        allocator,
        post_raw_token_balances,
        &mint_cache,
        FallbackAccountReader,
        mint_reader,
    );
    defer if (post_token_balances) |balances| {
        for (balances) |b| b.deinit(allocator);
        allocator.free(balances);
    };

    // Build TransactionStatusMeta
    const status = try TransactionStatusMetaBuilder.build(
        allocator,
        tx_result,
        pre_balances,
        post_balances,
        loaded_addresses,
        pre_token_balances,
        post_token_balances,
    );
    errdefer status.deinit(allocator);

    // Extract writable and readonly keys for address_signatures index
    var writable_keys = ArrayList(Pubkey).init(allocator);
    defer writable_keys.deinit();
    var readonly_keys = ArrayList(Pubkey).init(allocator);
    defer readonly_keys.deinit();

    for (
        transaction.accounts.items(.pubkey),
        transaction.accounts.items(.is_writable),
    ) |pubkey, is_writable| {
        if (is_writable) {
            try writable_keys.append(pubkey);
        } else {
            try readonly_keys.append(pubkey);
        }
    }

    // Write to ledger
    const result_writer = ledger.resultWriter();
    try result_writer.writeTransactionStatus(
        slot,
        signature,
        writable_keys.items,
        readonly_keys.items,
        status,
        transaction_index,
    );
}

/// Collect post-execution token balances from transaction writes.
fn collectPostTokenBalances(
    transaction: ResolvedTransaction,
    tx_result: ProcessedTransaction,
) spl_token.RawTokenBalances {
    var result = spl_token.RawTokenBalances{};

    for (tx_result.writes.constSlice()) |*written_account| {
        // Skip non-token accounts
        if (!spl_token.isTokenProgram(written_account.account.owner)) continue;

        // Skip if data is too short for a token account
        if (written_account.account.data.len < spl_token.TOKEN_ACCOUNT_SIZE) continue;

        // Try to parse as token account
        const parsed = spl_token.ParsedTokenAccount.parse(
            written_account.account.data[0..spl_token.TOKEN_ACCOUNT_SIZE],
        ) orelse continue;

        // Find the account index in the transaction
        var account_index: ?u8 = null;
        for (transaction.accounts.items(.pubkey), 0..) |pubkey, idx| {
            if (pubkey.equals(&written_account.pubkey)) {
                account_index = @intCast(idx);
                break;
            }
        }

        if (account_index) |idx| {
            result.append(.{
                .account_index = idx,
                .mint = parsed.mint,
                .owner = parsed.owner,
                .amount = parsed.amount,
                .program_id = written_account.account.owner,
            }) catch {};
        }
    }

    return result;
}

/// Account reader that checks transaction writes first, then falls back to the
/// account store. This ensures mint accounts can be found even when they weren't
/// modified by the transaction (the common case for token transfers).
/// [agave] Agave uses account_loader.load_account() which has full store access.
const FallbackAccountReader = struct {
    writes: []const LoadedAccount,
    account_store_reader: ?sig.accounts_db.SlotAccountReader,

    /// Stub account type returned by this reader.
    /// Allocates and owns the data buffer.
    const StubAccount = struct {
        data: DataHandle,
        allocator: Allocator,

        const DataHandle = struct {
            slice: []const u8,
            pub fn constSlice(self: DataHandle) []const u8 {
                return self.slice;
            }
        };

        pub fn deinit(self: StubAccount, _: Allocator) void {
            self.allocator.free(self.data.slice);
        }
    };

    pub fn get(self: FallbackAccountReader, pubkey: Pubkey, alloc: Allocator) !?StubAccount {
        // Check transaction writes first
        for (self.writes) |*account| {
            if (account.pubkey.equals(&pubkey)) {
                const data_copy = try alloc.dupe(u8, account.account.data);
                return StubAccount{
                    .data = .{ .slice = data_copy },
                    .allocator = alloc,
                };
            }
        }

        // Fall back to account store (e.g. for mint accounts not modified in this tx)
        if (self.account_store_reader) |reader| {
            const account = try reader.get(alloc, pubkey) orelse return null;
            defer account.deinit(alloc);
            const data_copy = try account.data.readAllAllocate(alloc);
            return StubAccount{
                .data = .{ .slice = data_copy },
                .allocator = alloc,
            };
        }

        return null;
    }
};

fn isSimpleVoteTransaction(tx: Transaction) bool {
    const msg = tx.msg;
    if (msg.instructions.len == 0) return false;
    const ix = msg.instructions[0];
    if (ix.program_index >= msg.account_keys.len) return false;
    return sig.runtime.program.vote.ID.equals(&msg.account_keys[ix.program_index]);
}
