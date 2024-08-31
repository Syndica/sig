const std = @import("std");
const sig = @import("../sig.zig");

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
    sender: *Channel(TransactionInfo),
    exit: *AtomicBool,

    pub fn init(allocator: std.mem.Allocator, sender: *Channel(TransactionInfo), exit: *AtomicBool) !MockTransferService {
        return .{
            .allocator = allocator,
            .sender = sender,
            .exit = exit,
        };
    }

    /// Mock transaction generator that sends a transaction every 10 seconds
    /// Used to test the transaction sender
    /// TODO:
    /// - Pass sender keypair and receiver pubkey
    pub fn run(self: *MockTransferService) !void {
        errdefer self.exit.store(true, .unordered);

        const from_pubkey = try Pubkey.fromString("Bkd9xbHF7JgwXmEib6uU3y582WaPWWiasPxzMesiBwWm");
        const from_keypair = KeyPair{
            .public_key = .{ .bytes = from_pubkey.data },
            .secret_key = .{ .bytes = [_]u8{ 76, 196, 192, 17, 40, 245, 120, 49, 64, 133, 213, 227, 12, 42, 183, 70, 235, 64, 235, 96, 246, 205, 78, 13, 173, 111, 254, 96, 210, 208, 121, 240, 159, 193, 185, 89, 227, 77, 234, 91, 232, 234, 253, 119, 162, 105, 200, 227, 123, 90, 111, 105, 72, 53, 60, 147, 76, 154, 44, 72, 29, 165, 2, 246 } },
        };
        const to_pubkey = try Pubkey.fromString("GDFVa3uYXDcNhcNk8A4v28VeF4wcMn8mauZNwVWbpcN");
        const lamports: u64 = 100;

        var rpc_client = RpcClient.init(self.allocator, .Testnet, .{});
        defer rpc_client.deinit();

        while (!self.exit.load(.unordered)) {
            std.time.sleep(Duration.fromSecs(10).asNanos());

            const latest_blockhash, const last_valid_blockheight = blk: {
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
                from_keypair,
                from_pubkey,
                to_pubkey,
                lamports,
                latest_blockhash,
            );

            const transaction_info = try TransactionInfo.new(
                transaction,
                last_valid_blockheight,
                null,
                null,
            );

            try self.sender.send(transaction_info);
        }
    }
};
