const std = @import("std");
const sig = @import("../sig.zig");
const types = @import("../rpc/types.zig");

const Logger = sig.trace.Logger;
const AtomicBool = std.atomic.Value(bool);
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const Channel = sig.sync.Channel;

const ClusterType = sig.accounts_db.ClusterType;
const Signature = sig.core.Signature;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const RpcClient = sig.rpc.Client;
const TransactionInfo = sig.transaction_sender.TransactionInfo;
const Duration = sig.time.Duration;

const TRANSFER_FEE: u64 = 5000;
const TOTAL_TRANSFER_AMOUNT: u64 = 5e8;
const NUMBER_OF_TRANSACTIONS: u64 = 200;

const MAX_RPC_RETRIES: u64 = 5;
const MAX_RPC_WAIT_FOR_SIGNATURE_CONFIRMATION: Duration = Duration.fromSecs(30);

const MAX_SIG_RETRIES: u64 = 5;
const MAX_SIG_WAIT_FOR_SIGNATURE_CONFIRMATION: Duration = Duration.fromSecs(300);

pub const MockTransferService = struct {
    allocator: std.mem.Allocator,
    network: ClusterType,
    sender: *Channel(TransactionInfo),
    exit: *AtomicBool,
    logger: Logger,

    pub fn init(
        allocator: std.mem.Allocator,
        network: ClusterType,
        sender: *Channel(TransactionInfo),
        exit: *AtomicBool,
        logger: Logger,
    ) !MockTransferService {
        return .{
            .allocator = allocator,
            .network = network,
            .sender = sender,
            .exit = exit,
            .logger = logger,
        };
    }

    /// https://explorer.solana.com/address/H67JSziFxAZR1KSQshWfa8Rdpr7LSv1VkT2cFQHL79rd?cluster=testnet
    const bank_keypair: KeyPair = .{
        .public_key = .{ .bytes = .{
            239, 10,  4,   236, 219, 237, 69,  197, 199, 60,  117, 184,
            223, 215, 132, 73,  93,  248, 200, 254, 212, 239, 251, 120,
            223, 25,  201, 196, 20,  58,  163, 62,
        } },
        .secret_key = .{ .bytes = .{
            208, 26,  255, 64,  164, 52,  99,  120, 92,  227, 25,  240,
            222, 245, 70,  77,  171, 89,  129, 64,  110, 73,  159, 230,
            38,  212, 150, 202, 57,  157, 151, 175, 239, 10,  4,   236,
            219, 237, 69,  197, 199, 60,  117, 184, 223, 215, 132, 73,
            93,  248, 200, 254, 212, 239, 251, 120, 223, 25,  201, 196,
            20,  58,  163, 62,
        } },
    };
    const bank_pubkey: Pubkey = .{
        .data = .{
            239, 10,  4,   236, 219, 237, 69,  197, 199, 60,  117, 184,
            223, 215, 132, 73,  93,  248, 200, 254, 212, 239, 251, 120,
            223, 25,  201, 196, 20,  58,  163, 62,
        },
    };

    const account_a_keypair: KeyPair = .{
        .public_key = .{ .bytes = .{
            3,  140, 214, 34,  176, 145, 149, 13,  169, 145, 117, 3,
            98, 140, 206, 183, 20,  52,  35,  97,  89,  82,  55,  162,
            13, 26,  172, 9,   77,  242, 217, 211,
        } },
        .secret_key = .{ .bytes = .{
            28,  57,  92,  177, 192, 198, 0,   137, 66,  122, 128, 0,
            112, 193, 184, 209, 72,  187, 109, 65,  115, 173, 181, 139,
            194, 185, 253, 182, 173, 110, 184, 124, 3,   140, 214, 34,
            176, 145, 149, 13,  169, 145, 117, 3,   98,  140, 206, 183,
            20,  52,  35,  97,  89,  82,  55,  162, 13,  26,  172, 9,
            77,  242, 217, 211,
        } },
    };
    const account_a_pubkey: Pubkey = .{
        .data = .{
            3,  140, 214, 34,  176, 145, 149, 13,  169, 145, 117, 3,
            98, 140, 206, 183, 20,  52,  35,  97,  89,  82,  55,  162,
            13, 26,  172, 9,   77,  242, 217, 211,
        },
    };

    const account_b_keypair: KeyPair = .{
        .public_key = .{ .bytes = .{
            214, 249, 254, 104, 120, 241, 160, 197, 198, 112, 216, 225,
            214, 43,  186, 232, 237, 73,  88,  96,  113, 228, 175, 163,
            237, 251, 236, 117, 20,  45,  61,  167,
        } },
        .secret_key = .{ .bytes = .{
            130, 75,  103, 204, 182, 105, 141, 67,  102, 204, 102, 107,
            63,  0,   54,  80,  84,  101, 103, 222, 176, 198, 47,  111,
            94,  197, 121, 43,  226, 185, 95,  236, 214, 249, 254, 104,
            120, 241, 160, 197, 198, 112, 216, 225, 214, 43,  186, 232,
            237, 73,  88,  96,  113, 228, 175, 163, 237, 251, 236, 117,
            20,  45,  61,  167,
        } },
    };
    const account_b_pubkey: Pubkey = .{
        .data = .{
            214, 249, 254, 104, 120, 241, 160, 197, 198, 112, 216, 225,
            214, 43,  186, 232, 237, 73,  88,  96,  113, 228, 175, 163,
            237, 251, 236, 117, 20,  45,  61,  167,
        },
    };

    /// Wait for a signature to be confirmed, return true if confirmed, false if failed
    pub fn waitForSignatureConfirmation(self: *MockTransferService, rpc_client: *RpcClient, signature: Signature, max_wait: Duration) !bool {
        const start = sig.time.Instant.now();
        while (start.elapsed().asNanos() < max_wait.asNanos()) {
            self.logger.info().logf("(transaction_sender.MockTransferService) waiting for signature confirmation ({}s remaining): {s}", .{
                max_wait.asSecs() - start.elapsed().asSecs(),
                signature.base58String().slice(),
            });
            const signature_statuses_response = try rpc_client.getSignatureStatuses(
                self.allocator,
                &[_]Signature{signature},
                .{},
            );
            defer signature_statuses_response.deinit();
            const signature_statuses = try signature_statuses_response.result();
            if (signature_statuses.value[0]) |signature_status| {
                if (signature_status.confirmations == null) return true;
                if (signature_status.err) |_| return false;
            }
            std.time.sleep(sig.time.Duration.fromSecs(1).asNanos());
        }
        return false;
    }

    /// Get the balance of a pubkey
    pub fn getBalance(self: *MockTransferService, rpc_client: *RpcClient, pubkey: Pubkey) !u64 {
        const balance_response = try rpc_client.getBalance(self.allocator, pubkey, .{});
        defer balance_response.deinit();
        const balance = try balance_response.result();
        return balance.value;
    }

    /// Open bank and ensure that it has at least 1 SOL
    pub fn openBank(self: *MockTransferService, rpc_client: *RpcClient) !void {
        const balance = try self.getBalance(
            rpc_client,
            bank_pubkey,
        );

        if (balance < 1e9) {
            for (0..5) |_| {
                const signature = blk: {
                    const response = try rpc_client.requestAirDrop(self.allocator, bank_pubkey, 5e9, .{});
                    defer response.deinit();
                    const signature_string = try response.result();
                    break :blk try Signature.fromString(signature_string);
                };
                if (try self.waitForSignatureConfirmation(rpc_client, signature, MAX_RPC_WAIT_FOR_SIGNATURE_CONFIRMATION)) return;
            }
            return error.OpenBankFailed;
        }

        const new_balance = try self.getBalance(
            rpc_client,
            bank_pubkey,
        );

        if (new_balance < 1e9) return error.OpenBankFailed;
    }

    /// Closes an account by transferring all SOL to the bank
    pub fn closeAccount(self: *MockTransferService, random: std.Random, rpc_client: *RpcClient, keypair: KeyPair) !void {
        const pubkey = try Pubkey.fromPublicKey(&keypair.public_key);
        const balance = try self.getBalance(rpc_client, pubkey);
        if (balance == 0) return;

        self.logger.info().logf("(transaction_sender.MockTransferService) closing account: transfering {} from {s} to {s}", .{ balance - TRANSFER_FEE, pubkey.string().slice(), bank_pubkey.string().slice() });
        try self.rpcTransferAndWait(
            random,
            rpc_client,
            keypair,
            bank_pubkey,
            balance - TRANSFER_FEE,
        );

        const new_balance = try self.getBalance(
            rpc_client,
            try Pubkey.fromPublicKey(&keypair.public_key),
        );

        if (new_balance != 0) return error.CloseAccountFailed;
    }

    /// Log account balances with a message
    pub fn logBalances(self: *MockTransferService, rpc_client: *RpcClient, message: []const u8) !void {
        self.logger.info().logf(
            "{s}: bank={}, account_a={}, account_b={}",
            .{
                message,
                try self.getBalance(rpc_client, bank_pubkey),
                try self.getBalance(rpc_client, account_a_pubkey),
                try self.getBalance(rpc_client, account_b_pubkey),
            },
        );
    }

    /// Transfer lamports via rpc from one account to another, retries transaction 5 times
    pub fn rpcTransferAndWait(self: *MockTransferService, random: std.Random, rpc_client: *RpcClient, from_keypair: KeyPair, to_pubkey: Pubkey, lamports: u64) !void {
        const from_pubkey = try Pubkey.fromPublicKey(&from_keypair.public_key);
        for (0..MAX_RPC_RETRIES) |_| {
            self.logger.info().logf("(transaction_sender.MockTransferService) attempting transfer: from_pubkey={s} to_pubkey={s} amount={}", .{
                from_pubkey.string().slice(),
                to_pubkey.string().slice(),
                lamports,
            });

            const latest_blockhash, _ = blk: {
                const blockhash_response = try rpc_client.getLatestBlockhash(self.allocator, .{});
                defer blockhash_response.deinit();
                const blockhash = try blockhash_response.result();
                break :blk .{
                    try Hash.parseBase58String(blockhash.value.blockhash),
                    blockhash.value.lastValidBlockHeight,
                };
            };

            const transaction = try sig.core.transaction.buildTransferTansaction(
                self.allocator,
                random,
                from_keypair,
                to_pubkey,
                lamports,
                latest_blockhash,
            );
            defer transaction.deinit(self.allocator);

            const signature = blk: {
                const response = try rpc_client.sendTransaction(self.allocator, transaction, .{});
                defer response.deinit();
                const signature_string = response.result() catch |err| {
                    const data_str = try response.parsed.@"error".?.dataAsString(self.allocator);
                    defer self.allocator.free(data_str);
                    self.logger.info().logf("(transaction_sender.MockTransferService) {}: amount={} message={s} data={s}", .{ err, lamports, response.parsed.@"error".?.message, data_str });
                    return error.RpcTransferFailed;
                };
                break :blk try Signature.fromString(signature_string);
            };

            const signature_confirmed = try self.waitForSignatureConfirmation(
                rpc_client,
                signature,
                MAX_RPC_WAIT_FOR_SIGNATURE_CONFIRMATION,
            );

            if (signature_confirmed) return;
        }
        return error.RpcTransferFailedMaxRetries;
    }

    /// Transfer lamports via sig from one account to another, retries transaction max
    pub fn sigTransferAndWait(self: *MockTransferService, random: std.Random, rpc_client: *RpcClient, from_keypair: KeyPair, to_pubkey: Pubkey, lamports: u64) !void {
        for (0..MAX_SIG_RETRIES) |_| {
            const block_height = blk: {
                const block_height_response = try rpc_client.getBlockHeight(self.allocator, .{});
                defer block_height_response.deinit();
                const block_height = try block_height_response.result();
                break :blk block_height;
            };

            const latest_blockhash, const last_valid_block_height = blk: {
                const blockhash_response = try rpc_client.getLatestBlockhash(self.allocator, .{});
                defer blockhash_response.deinit();
                const blockhash = try blockhash_response.result();
                break :blk .{
                    try Hash.parseBase58String(blockhash.value.blockhash),
                    blockhash.value.lastValidBlockHeight,
                };
            };

            const transaction = try sig.core.transaction.buildTransferTansaction(
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

            const signature_confirmed = try self.waitForSignatureConfirmation(
                rpc_client,
                transaction_info.signature,
                Duration.fromMillis(@min(
                    MAX_SIG_WAIT_FOR_SIGNATURE_CONFIRMATION.asMillis(),
                    (last_valid_block_height - block_height) * 400,
                )),
            );

            if (signature_confirmed) return;
        }
        return error.SigTransferFailedMaxRetries;
    }

    /// Transfer lamports via sig from one account to another, retries transaction max
    pub fn sigTransfer(self: *MockTransferService, random: std.Random, rpc_client: *RpcClient, from_keypair: KeyPair, to_pubkey: Pubkey, lamports: u64) !void {
        const latest_blockhash, const last_valid_block_height = blk: {
            const blockhash_response = try rpc_client.getLatestBlockhash(self.allocator, .{});
            defer blockhash_response.deinit();
            const blockhash = try blockhash_response.result();
            break :blk .{
                try Hash.parseBase58String(blockhash.value.blockhash),
                blockhash.value.lastValidBlockHeight,
            };
        };

        const transaction = try sig.core.transaction.buildTransferTansaction(
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

    /// Run the mock transfer service
    pub fn run(self: *MockTransferService) !void {
        errdefer self.exit.store(true, .monotonic);

        var prng = std.Random.DefaultPrng.init(10);
        const random = prng.random();

        var rpc_client = RpcClient.init(self.allocator, self.network, .{});
        defer rpc_client.deinit();

        try self.logBalances(&rpc_client, "(transaction_sender.MockTransferService) resetting mock transfer accounts");
        try self.openBank(&rpc_client);
        try self.closeAccount(random, &rpc_client, account_a_keypair);
        try self.closeAccount(random, &rpc_client, account_b_keypair);

        try self.logBalances(&rpc_client, "(transaction_sender.MockTransferService) initialising mock transfer accounts");
        try self.rpcTransferAndWait(random, &rpc_client, bank_keypair, account_a_pubkey, TOTAL_TRANSFER_AMOUNT + TRANSFER_FEE * NUMBER_OF_TRANSACTIONS);

        { // CORE TRANSFER LOGIC
            for (0..NUMBER_OF_TRANSACTIONS) |i| {
                self.logger.info().logf("(transaction_sender.MockTransferService) executing mock transfer {} of {}", .{ i, NUMBER_OF_TRANSACTIONS });
                try self.logBalances(&rpc_client, "(transaction_sender.MockTransferService) executing mock transfer from A to B");
                // try self.rpcTransferAndWait(random, &rpc_client, account_a_keypair, account_b_pubkey, @divExact(TOTAL_TRANSFER_AMOUNT, NUMBER_OF_TRANSACTIONS));
                try self.sigTransfer(random, &rpc_client, account_a_keypair, account_b_pubkey, @divExact(TOTAL_TRANSFER_AMOUNT, NUMBER_OF_TRANSACTIONS));
                // try self.sigTransferAndWait(random, &rpc_client, account_a_keypair, account_b_pubkey, @divExact(TOTAL_TRANSFER_AMOUNT, NUMBER_OF_TRANSACTIONS));
                std.time.sleep(Duration.fromSecs(10).asNanos());
            }
        }

        try self.logBalances(&rpc_client, "(transaction_sender.MockTransferService) resetting mock transfer accounts");
        try self.closeAccount(random, &rpc_client, account_a_keypair);
        try self.closeAccount(random, &rpc_client, account_b_keypair);

        try self.logBalances(&rpc_client, "(transaction_sender.MockTransferService) exiting mock transfer service");
        self.exit.store(false, .monotonic);
    }
};
