const std = @import("std");
const sig = @import("../sig.zig");
const types = @import("../rpc/types.zig");

const Logger = sig.trace.Logger;
const AtomicBool = std.atomic.Value(bool);
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const Channel = sig.sync.Channel;

const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const RpcClient = sig.rpc.Client;
const TransactionInfo = sig.transaction_sender.TransactionInfo;
const Duration = sig.time.Duration;

pub const MockTransferService = struct {
    allocator: std.mem.Allocator,
    logger: Logger,
    sender: *Channel(TransactionInfo),
    exit: *AtomicBool,

    pub fn init(
        allocator: std.mem.Allocator,
        sender: *Channel(TransactionInfo),
        exit: *AtomicBool,
        logger: Logger,
    ) !MockTransferService {
        return .{
            .allocator = allocator,
            .sender = sender,
            .exit = exit,
            .logger = logger,
        };
    }

    /// https://explorer.solana.com/address/H67JSziFxAZR1KSQshWfa8Rdpr7LSv1VkT2cFQHL79rd?cluster=testnet
    const bank_kp: KeyPair = .{
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

    /// Mock transaction generator that sends a transaction every 10 seconds
    /// Used to test the transaction sender
    /// TODO:
    /// - Pass sender keypair and receiver pubkey
    pub fn run(self: *MockTransferService, network: types.ClusterType) !void {
        errdefer self.exit.store(true, .monotonic);
        var rpc_client = RpcClient.init(self.allocator, network, .{});
        defer rpc_client.deinit();

        const bank_pubkey = try Pubkey.fromPublicKey(&bank_kp.public_key);

        self.logger.debug().logf("bank key: {}", .{bank_pubkey});
        {
            const bank_balance_response = try rpc_client.getBalance(
                self.allocator,
                bank_pubkey,
                .{},
            );
            defer bank_balance_response.deinit();
            const bank_balance = try bank_balance_response.result();

            self.logger.debug().logf(
                "bank balance: {} lamports, or about {d:.4} SOL",
                .{ bank_balance.value, @as(f32, @floatFromInt(bank_balance.value)) / 1e9 },
            );

            std.time.sleep(1 * std.time.ns_per_s);

            // if we have less than 1 SOL, airdrop some more
            if (bank_balance.value < 1e9) {}
        }

        // create test accounts
        // it's important the test code doesn't have the secret key of the accounts,
        // to better mimick real-world.

        const account_a_pubkey = blk: {
            const new_kp = try KeyPair.create(null);
            break :blk try Pubkey.fromPublicKey(&new_kp.public_key);
        };

        const account_b_pubkey = blk: {
            const new_kp = try KeyPair.create(null);
            break :blk try Pubkey.fromPublicKey(&new_kp.public_key);
        };

        var prng = std.Random.DefaultPrng.init(10);
        const random = prng.random();

        self.logger.debug().logf("account a: {}", .{account_a_pubkey});
        self.logger.debug().logf("account b: {}", .{account_b_pubkey});

        // move 0.5 SOL to account A
        while (true) {
            const latest_blockhash, const last_valid_blockheight = blk: {
                const blockhash_response = try rpc_client.getLatestBlockhash(self.allocator, .{});
                defer blockhash_response.deinit();
                const blockhash = try blockhash_response.result();
                break :blk .{
                    try Hash.parseBase58String(blockhash.value.blockhash),
                    blockhash.value.lastValidBlockHeight,
                };
            };

            std.debug.print("block height: {}\n", .{last_valid_blockheight});

            const transaction = try sig.core.transaction.buildTransferTansaction(
                self.allocator,
                bank_kp,
                account_a_pubkey,
                5e8, // 0.5 SOL
                latest_blockhash,
                random,
            );

            std.debug.print("sig: {}\n", .{transaction.signatures[0]});

            defer transaction.deinit(self.allocator);
            const transaction_info = try TransactionInfo.new(
                transaction,
                last_valid_blockheight,
                null,
                null,
            );

            try self.sender.send(transaction_info);

            // sleep as to not overload the http server
            std.time.sleep(10 * std.time.ns_per_s);

            // check if the SOL is in the account
            const bank_balance_response = try rpc_client.getBalance(
                self.allocator,
                account_a_pubkey,
                .{},
            );
            defer bank_balance_response.deinit();
            const bank_balance = try bank_balance_response.result();
            if (bank_balance.value == 5e8) break;
        }

        // const from_pubkey = try Pubkey.fromString("Bkd9xbHF7JgwXmEib6uU3y582WaPWWiasPxzMesiBwWm");
        // const from_keypair = KeyPair{
        //     .public_key = .{ .bytes = from_pubkey.data },
        //     .secret_key = .{ .bytes = [_]u8{ 76, 196, 192, 17, 40, 245, 120, 49, 64, 133, 213, 227, 12, 42, 183, 70, 235, 64, 235, 96, 246, 205, 78, 13, 173, 111, 254, 96, 210, 208, 121, 240, 159, 193, 185, 89, 227, 77, 234, 91, 232, 234, 253, 119, 162, 105, 200, 227, 123, 90, 111, 105, 72, 53, 60, 147, 76, 154, 44, 72, 29, 165, 2, 246 } },
        // };
        // const to_pubkey = try Pubkey.fromString("GDFVa3uYXDcNhcNk8A4v28VeF4wcMn8mauZNwVWbpcN");
        // const lamports: u64 = 1000;

        // var rpc_client = RpcClient.init(self.allocator, .Testnet, .{});
        // defer rpc_client.deinit();

        // while (!self.exit.load(.monotonic)) {
        //     std.time.sleep(Duration.fromSecs(10).asNanos());

        //     self.logger.debugf(
        //         "latest blockhash: {}, last valid blockheight: {}",
        //         .{ latest_blockhash, last_valid_blockheight },
        //     );

        // }
    }
};
