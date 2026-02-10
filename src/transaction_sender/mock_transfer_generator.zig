const std = @import("std");
const sig = @import("../sig.zig");

const AtomicBool = std.atomic.Value(bool);
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const Channel = sig.sync.Channel;

const Signature = sig.core.Signature;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const RpcClient = sig.rpc.Client;
const TransactionInfo = sig.transaction_sender.TransactionInfo;
const Duration = sig.time.Duration;

const GetLatestBlockhash = sig.rpc.methods.GetLatestBlockhash;

const TRANSFER_FEE_LAMPORTS: u64 = 5000;
const MAX_AIRDROP_LAMPORTS: u64 = 5e9;
const MIN_LAMPORTS_FOR_RENT: u64 = 1e6; // This is a nonsense number but works

const MAX_RPC_RETRIES: u64 = 5;
const MAX_RPC_WAIT_FOR_SIGNATURE_CONFIRMATION: Duration = Duration.fromSecs(30);

const MAX_SIG_RETRIES: u64 = 5;
const MAX_SIG_WAIT_FOR_SIGNATURE_CONFIRMATION: Duration = Duration.fromSecs(300);

pub const KeypairAndPubkey = struct {
    keypair: KeyPair,
    pubkey: Pubkey,

    pub fn init(keypair: KeyPair) KeypairAndPubkey {
        return .{
            .keypair = keypair,
            .pubkey = Pubkey.fromPublicKey(&keypair.public_key),
        };
    }
};

pub const MockAccounts = struct {
    bank: KeypairAndPubkey,
    alice: KeypairAndPubkey,

    pub const DEFAULT: MockAccounts = .{
        .bank = KeypairAndPubkey.init(.{
            .public_key = .{ .bytes = .{ 239, 10, 4, 236, 219, 237, 69, 197, 199, 60, 117, 184, 223, 215, 132, 73, 93, 248, 200, 254, 212, 239, 251, 120, 223, 25, 201, 196, 20, 58, 163, 62 } },
            .secret_key = .{ .bytes = .{ 208, 26, 255, 64, 164, 52, 99, 120, 92, 227, 25, 240, 222, 245, 70, 77, 171, 89, 129, 64, 110, 73, 159, 230, 38, 212, 150, 202, 57, 157, 151, 175, 239, 10, 4, 236, 219, 237, 69, 197, 199, 60, 117, 184, 223, 215, 132, 73, 93, 248, 200, 254, 212, 239, 251, 120, 223, 25, 201, 196, 20, 58, 163, 62 } },
        }),
        .alice = KeypairAndPubkey.init(.{
            .public_key = .{ .bytes = .{ 3, 140, 214, 34, 176, 145, 149, 13, 169, 145, 117, 3, 98, 140, 206, 183, 20, 52, 35, 97, 89, 82, 55, 162, 13, 26, 172, 9, 77, 242, 217, 211 } },
            .secret_key = .{ .bytes = .{ 28, 57, 92, 177, 192, 198, 0, 137, 66, 122, 128, 0, 112, 193, 184, 209, 72, 187, 109, 65, 115, 173, 181, 139, 194, 185, 253, 182, 173, 110, 184, 124, 3, 140, 214, 34, 176, 145, 149, 13, 169, 145, 117, 3, 98, 140, 206, 183, 20, 52, 35, 97, 89, 82, 55, 162, 13, 26, 172, 9, 77, 242, 217, 211 } },
        }),
    };
};

pub const MockTransferService = struct {
    allocator: std.mem.Allocator,
    sender: *Channel(TransactionInfo),
    rpc_client: RpcClient,
    exit: *AtomicBool,
    logger: Logger,
    accounts: MockAccounts = MockAccounts.DEFAULT,

    const Logger = sig.trace.Logger(@typeName(Self));

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        sender: *Channel(TransactionInfo),
        rpc_client: RpcClient,
        exit: *AtomicBool,
        logger: Logger,
    ) !MockTransferService {
        return .{
            .allocator = allocator,
            .sender = sender,
            .rpc_client = rpc_client,
            .exit = exit,
            .logger = logger.withScope(@typeName(Self)),
        };
    }

    /// Run the mock transfer service
    pub fn run(self: *MockTransferService, n_transactions: u64, n_lamports_per_tx: u64) !void {
        errdefer self.exit.store(true, .monotonic);

        var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
        const random = prng.random();

        if (n_lamports_per_tx < MIN_LAMPORTS_FOR_RENT) {
            @panic("transaction amount is less than MIN_LAMPORTS_FOR_RENT");
        }

        self.logger.info().logf("accounts: bank={f}, alice={f}", .{
            self.accounts.bank.pubkey,
            self.accounts.alice.pubkey,
        });

        const required_bank_balance = n_transactions * (n_lamports_per_tx + TRANSFER_FEE_LAMPORTS);

        if (required_bank_balance > MAX_AIRDROP_LAMPORTS) {
            @panic("requested transfer amount exceeds MAX_AIRDROP_LAMPORTS");
        }

        const balances = try self.getBalances(null);
        if (balances.bank < required_bank_balance) {
            self.logger.debug().log("airdropping to bank");
            try self.airdrop(self.accounts.bank.pubkey, MAX_AIRDROP_LAMPORTS);
        }

        if (balances.alice > 0) {
            self.logger.debug().log("closing alice's account");
            try self.closeAccount(random, self.accounts.alice.keypair);
        }

        _ = try self.getBalances("initial balances");

        for (0..n_transactions) |tx_i| {
            self.logger.info().logf("transfering {} lamports from bank to alice ({}/{})", .{ n_lamports_per_tx, tx_i + 1, n_transactions });
            try self.sigTransferAndWait(
                random,
                self.accounts.bank.keypair,
                self.accounts.alice.pubkey,
                n_lamports_per_tx,
            );
            self.logger.info().logf("SUCCESS - transferred {} lamports from bank to alice ({}/{})", .{ n_lamports_per_tx, tx_i + 1, n_transactions });
        }

        _ = try self.getBalances("final balances");

        try self.closeAccount(random, self.accounts.alice.keypair);

        self.exit.store(false, .monotonic);
    }

    /// Wait for a signature to be confirmed, return true if confirmed, false if failed
    pub fn waitForSignatureConfirmation(self: *MockTransferService, signature: Signature, max_wait: Duration, log: bool) !bool {
        const start = sig.time.Instant.now();
        var log_timer = sig.time.Timer.start();
        while (start.elapsed().asNanos() < max_wait.asNanos()) {
            if (log_timer.read().asSecs() > 10) {
                const time_remaining = max_wait.asSecs() - start.elapsed().asSecs();
                if (log) {
                    self.logger.info().logf("waiting for signature confirmation ({}s remaining): {f}", .{
                        time_remaining,
                        signature,
                    });
                }
                log_timer.reset();
            }
            const signature_statuses_response = try self.rpc_client.getSignatureStatuses(
                .{ .signatures = &[_]Signature{signature} },
            );
            defer signature_statuses_response.deinit();
            const signature_statuses = try signature_statuses_response.result();
            if (signature_statuses.value[0]) |signature_status| {
                if (signature_status.confirmations == null) return true;
                if (signature_status.err) |_| return false;
            }
            std.Thread.sleep(sig.time.Duration.fromSecs(1).asNanos());
        }
        return false;
    }

    /// Transfer lamports via rpc from one account to another, retries transaction 5 times
    pub fn rpcTransferAndWait(self: *MockTransferService, random: std.Random, from_keypair: KeyPair, to_pubkey: Pubkey, lamports: u64) !void {
        const from_pubkey = Pubkey.fromPublicKey(&from_keypair.public_key);
        for (0..MAX_RPC_RETRIES) |_| {
            self.logger.debug().logf(
                "rpc transfer: amount={} from_pubkey={f} to_pubkey={f}",
                .{ lamports, from_pubkey, to_pubkey },
            );

            const latest_blockhash, _ = blk: {
                const blockhash_response = try self.rpc_client.getLatestBlockhash(.{});
                defer blockhash_response.deinit();
                const blockhash = try blockhash_response.result();
                break :blk .{
                    try Hash.parseRuntime(blockhash.value.blockhash),
                    blockhash.value.lastValidBlockHeight,
                };
            };

            const transaction = try buildTransferTansaction(
                self.allocator,
                random,
                from_keypair,
                to_pubkey,
                lamports,
                latest_blockhash,
            );
            defer transaction.deinit(self.allocator);

            const signature = blk: {
                const response = try self.rpc_client.sendTransaction(.{ .transaction = transaction });
                defer response.deinit();
                break :blk response.result() catch |err| {
                    self.logger.debug().logf("rpc transfer failed with: {}", .{err});
                    return error.RpcTransferFailed;
                };
            };

            const signature_confirmed = try self.waitForSignatureConfirmation(
                signature,
                MAX_RPC_WAIT_FOR_SIGNATURE_CONFIRMATION,
                false,
            );
            if (signature_confirmed) return;
        }
        return error.RpcTransferFailedMaxRetries;
    }

    /// Transfer lamports via sig from one account to another, retries transaction max
    pub fn sigTransferAndWait(
        self: *MockTransferService,
        random: std.Random,
        from_keypair: KeyPair,
        to_pubkey: Pubkey,
        lamports: u64,
    ) !void {
        for (0..MAX_SIG_RETRIES) |_| {
            const block_height = blk: {
                const block_height_response = try self.rpc_client.getBlockHeight(.{});
                defer block_height_response.deinit();
                const block_height = try block_height_response.result();
                break :blk block_height;
            };

            const latest_blockhash, const last_valid_block_height = blk: {
                const blockhash_response = try self.rpc_client.getLatestBlockhash(.{});
                defer blockhash_response.deinit();
                const blockhash = try blockhash_response.result();
                break :blk .{
                    try Hash.parseRuntime(blockhash.value.blockhash),
                    blockhash.value.lastValidBlockHeight,
                };
            };

            const transaction = try buildTransferTansaction(
                self.allocator,
                random,
                from_keypair,
                to_pubkey,
                lamports,
                latest_blockhash,
            );
            defer transaction.deinit(self.allocator);

            const transaction_info = try TransactionInfo.init(
                transaction,
                last_valid_block_height,
                null,
                null,
            );
            try self.sender.send(transaction_info);
            self.logger.info().logf("sent transaction: {f}", .{transaction_info.signature});

            const signature_confirmed = try self.waitForSignatureConfirmation(
                transaction_info.signature,
                Duration.fromMillis(@min(
                    MAX_SIG_WAIT_FOR_SIGNATURE_CONFIRMATION.asMillis(),
                    (last_valid_block_height - block_height) * 400,
                )),
                false,
            );

            if (signature_confirmed) return;
        }
        return error.SigTransferFailedMaxRetries;
    }

    /// Transfer lamports via sig from one account to another, retries transaction max
    pub fn sigTransfer(self: *MockTransferService, random: std.Random, from_keypair: KeyPair, to_pubkey: Pubkey, lamports: u64) !void {
        const latest_blockhash, const last_valid_block_height = blk: {
            const blockhash_response = try self.rpc_client.fetch(GetLatestBlockhash{});
            defer blockhash_response.deinit();
            const blockhash = try blockhash_response.result();
            break :blk .{
                try Hash.parseRuntime(blockhash.value.blockhash),
                blockhash.value.lastValidBlockHeight,
            };
        };

        const transaction = try buildTransferTansaction(
            self.allocator,
            random,
            from_keypair,
            to_pubkey,
            lamports,
            latest_blockhash,
        );
        defer transaction.deinit(self.allocator);

        const transaction_info = try TransactionInfo.init(
            transaction,
            last_valid_block_height,
            null,
            null,
        );

        try self.sender.send(transaction_info);
    }

    /// Closes an account by transferring all SOL to the bank (using rpc methods)
    pub fn closeAccount(self: *MockTransferService, random: std.Random, keypair: KeyPair) !void {
        const pubkey = Pubkey.fromPublicKey(&keypair.public_key);
        const balance = try self.getBalance(pubkey);
        if (balance == 0) return;

        self.logger.debug().logf(
            "closing account: transfering {} from {f} to {f}",
            .{ balance - TRANSFER_FEE_LAMPORTS, pubkey, self.accounts.bank.pubkey },
        );
        try self.rpcTransferAndWait(
            random,
            keypair,
            self.accounts.bank.pubkey,
            balance - TRANSFER_FEE_LAMPORTS,
        );

        const new_balance = try self.getBalance(pubkey);
        if (new_balance != 0) {
            self.logger.warn().logf("close account failed: account still has {d} lamports", .{new_balance});
            return error.CloseAccountFailed;
        }
    }

    /// Get the balance of a pubkey
    pub fn getBalance(self: *MockTransferService, pubkey: Pubkey) !u64 {
        const balance_response = try self.rpc_client.getBalance(.{ .pubkey = pubkey });
        defer balance_response.deinit();
        const balance = try balance_response.result();
        return balance.value;
    }

    /// Log account balances with a message
    ///
    /// When `maybe_log_prefix` is null, no log is emitted.
    pub fn getBalances(self: *MockTransferService, maybe_log_prefix: ?[]const u8) !struct {
        bank: u64,
        alice: u64,
    } {
        const bank_balance = try self.getBalance(self.accounts.bank.pubkey);
        const alice_balance = try self.getBalance(self.accounts.alice.pubkey);
        if (maybe_log_prefix) |message_prefix| {
            self.logger.info().logf("{s}: bank={}, alice={}", .{ message_prefix, bank_balance, alice_balance });
        }
        return .{ .bank = bank_balance, .alice = alice_balance };
    }

    /// airdrops SOL to the given pubkey (using rpc methods)
    pub fn airdrop(
        self: *MockTransferService,
        pubkey: Pubkey,
        lamports: u64,
    ) !void {
        for (0..MAX_RPC_RETRIES) |_| {
            const signature = blk: {
                const response = try self.rpc_client.requestAirdrop(
                    .{ .pubkey = pubkey, .lamports = lamports },
                );
                defer response.deinit();
                break :blk try response.result();
            };
            const signature_confirmed = try self.waitForSignatureConfirmation(
                signature,
                MAX_RPC_WAIT_FOR_SIGNATURE_CONFIRMATION,
                false,
            );
            if (signature_confirmed) {
                return;
            }
        }
        return error.AirdropFailed;
    }

    pub fn buildTransferTansaction(
        allocator: std.mem.Allocator,
        random: std.Random,
        from_keypair: KeyPair,
        to_pubkey: Pubkey,
        lamports: u64,
        recent_blockhash: Hash,
    ) !sig.core.Transaction {
        const from_pubkey = Pubkey.fromPublicKey(&from_keypair.public_key);

        const addresses = try allocator.dupe(Pubkey, &.{
            from_pubkey,
            to_pubkey,
            sig.runtime.program.system.ID,
        });
        errdefer allocator.free(addresses);

        const account_indexes = try allocator.dupe(u8, &.{ 0, 1 });
        errdefer allocator.free(account_indexes);

        var data = [_]u8{0} ** 12;
        var fbs = std.io.fixedBufferStream(&data);
        const writer = fbs.writer();
        try writer.writeInt(u32, 2, .little);
        try writer.writeInt(u64, lamports, .little);

        const instructions = try allocator.alloc(sig.core.transaction.Instruction, 1);
        errdefer allocator.free(instructions);
        instructions[0] = .{
            .program_index = 2,
            .account_indexes = account_indexes,
            .data = try allocator.dupe(u8, &data),
        };

        const signature: Signature = blk: {
            const buffer = [_]u8{0} ** sig.core.Transaction.MAX_BYTES;
            const signable = &buffer; //try transaction.msgwriteSignableToSlice(&buffer);

            var noise: [KeyPair.seed_length]u8 = undefined;
            random.bytes(&noise);

            const signature = try from_keypair.sign(signable, noise);
            break :blk .fromSignature(signature);
        };

        const signatures = try allocator.dupe(Signature, &.{signature});
        errdefer allocator.free(signatures);

        return .{
            .signatures = signatures,
            .version = .legacy,
            .msg = .{
                .signature_count = @intCast(signatures.len),
                .readonly_signed_count = 0,
                .readonly_unsigned_count = 1,
                .account_keys = addresses,
                .recent_blockhash = recent_blockhash,
                .instructions = instructions,
            },
        };
    }
};
