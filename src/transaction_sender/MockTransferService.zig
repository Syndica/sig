const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;

const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;
const Status = sig.core.status_cache.Status;

const RpcClient = sig.rpc.Client;

const Channel = sig.sync.Channel;
const ExitCondition = sig.sync.ExitCondition;

const Instant = sig.time.Instant;
const Duration = sig.time.Duration;

const TransactionInfo = sig.TransactionSenderService.TransactionInfo;

const Commitment = sig.rpc.methods.common.Commitment;

const Logger = sig.trace.Logger("MockTransferService");

pub const Service = @This();

logger: Logger,
exit: ExitCondition,

client: RpcClient,
submit: SubmitMode,
skip_preflight: bool = false,

account_0: Account = ACCOUNT_0,
account_1: Account = ACCOUNT_1,

transfers: u64 = TRANSFERS,
successful: u64 = 0,

const TRANSFERS: u64 = 10;
const TRANSFER_AMOUNT: u64 = 1e6;
const TRANSFER_FEE: u64 = 5000;
const TRANSFER_COST: u64 = TRANSFER_AMOUNT + TRANSFER_FEE;

pub const ACCOUNT_0: Account = .init("account_0", .{ // Pubkey: H67JSziFxAZR1KSQshWfa8Rdpr7LSv1VkT2cFQHL79rd
    .public_key = .{ .bytes = .{
        3,   140, 214, 34, 176, 145, 149, 13,
        169, 145, 117, 3,  98,  140, 206, 183,
        20,  52,  35,  97, 89,  82,  55,  162,
        13,  26,  172, 9,  77,  242, 217, 211,
    } },
    .secret_key = .{ .bytes = .{
        28,  57,  92,  177, 192, 198, 0,   137,
        66,  122, 128, 0,   112, 193, 184, 209,
        72,  187, 109, 65,  115, 173, 181, 139,
        194, 185, 253, 182, 173, 110, 184, 124,
        3,   140, 214, 34,  176, 145, 149, 13,
        169, 145, 117, 3,   98,  140, 206, 183,
        20,  52,  35,  97,  89,  82,  55,  162,
        13,  26,  172, 9,   77,  242, 217, 211,
    } },
});
pub const ACCOUNT_1: Account = .init("account_1", .{ // Pubkey: ErnDW7vq2XmzstretUJ7NhT95PV6zeXeyXwLssowF6i
    .public_key = .{ .bytes = .{
        239, 10,  4,   236, 219, 237, 69,  197,
        199, 60,  117, 184, 223, 215, 132, 73,
        93,  248, 200, 254, 212, 239, 251, 120,
        223, 25,  201, 196, 20,  58,  163, 62,
    } },
    .secret_key = .{ .bytes = .{
        208, 26,  255, 64,  164, 52,  99,  120,
        92,  227, 25,  240, 222, 245, 70,  77,
        171, 89,  129, 64,  110, 73,  159, 230,
        38,  212, 150, 202, 57,  157, 151, 175,
        239, 10,  4,   236, 219, 237, 69,  197,
        199, 60,  117, 184, 223, 215, 132, 73,
        93,  248, 200, 254, 212, 239, 251, 120,
        223, 25,  201, 196, 20,  58,  163, 62,
    } },
});

pub fn deinit(self: *Service) void {
    self.client.deinit();
    switch (self.submit) {
        .rpc => self.submit.rpc.deinit(),
        .direct => {},
    }
}

pub const SubmitMode = union(enum) {
    /// Submit transactions directly to the TransactionSenderService channel,
    /// bypassing the RPC layer.
    direct: *Channel(TransactionInfo),
    /// Submit transactions via sendTransaction RPC requests to the validator.
    /// Uses a separate client since the target validator may differ from the
    /// client used for state queries.
    rpc: RpcClient,
};

pub const Account = struct {
    name: []const u8,
    keypair: KeyPair,
    pubkey: Pubkey,
    lamports: u64,

    fn init(name: []const u8, keypair: KeyPair) Account {
        return .{
            .name = name,
            .keypair = keypair,
            .pubkey = Pubkey.fromPublicKey(&keypair.public_key),
            .lamports = 0,
        };
    }

    pub fn format(self: Account, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("(name={s}, lamports={d}, pubkey={f})", .{
            self.name,
            self.lamports,
            self.pubkey,
        });
    }
};

pub fn run(self: *Service, allocator: Allocator) !void {
    errdefer |err| {
        self.logger.err().logf("MockTransferService Error: {s}", .{@errorName(err)});
        if (@errorReturnTrace()) |tr| std.debug.dumpStackTrace(tr.*);
        self.exit.setExit();
    }

    self.logger.info().log("Initializing accounts for mock transfer");
    var from_account, var to_account = try self.initAccounts(allocator);

    self.logger.info().logf("Starting mock transfers: {f} -> {f}", .{ from_account, to_account });
    while (!self.exit.shouldExit() and self.successful < self.transfers) {
        if (from_account.lamports < TRANSFER_COST and to_account.lamports < TRANSFER_COST) {
            self.logger.info().logf("Insufficient lamports: {f} -> {f}", .{
                from_account,
                to_account,
            });
            return error.InsufficientBalance;
        } else if (from_account.lamports < TRANSFER_COST) {
            self.logger.info().logf("Switching mock transfers: {f} -> {f}", .{
                from_account,
                to_account,
            });
            const tmp = from_account;
            from_account = to_account;
            to_account = tmp;
        }

        self.logger.info().logf("Attempting transfer {}/{}", .{
            self.successful + 1,
            self.transfers,
        });
        const txn_info = try self.buildTransfer(allocator, from_account, to_account);

        self.logger.info().logf("Sending transfer {}/{}: signature={f}", .{
            self.successful + 1,
            self.transfers,
            txn_info.signature,
        });
        try self.submitTransaction(txn_info);

        switch (self.waitForTransfer(&txn_info, .fromSecs(60))) {
            .succeeded => {
                try self.resetAccountBalances(allocator, .confirmed);
                self.logger.info().logf("Transfer success {}/{}: signature={f}", .{
                    self.successful + 1,
                    self.transfers,
                    txn_info.signature,
                });
                self.successful += 1;
                continue;
            },
            .failed => {
                self.logger.info().logf("Transfer failure {}/{}: signature={f}", .{
                    self.successful + 1,
                    self.transfers,
                    txn_info.signature,
                });
                return error.TransferFailed;
            },
            .pending => {
                self.logger.info().logf("Transfer timeout {}/{}: signature={f}", .{
                    self.successful + 1,
                    self.transfers,
                    txn_info.signature,
                });
                continue;
            },
        }
    }
}

fn submitTransaction(self: *Service, txn_info: TransactionInfo) !void {
    switch (self.submit) {
        .direct => |channel| try channel.send(txn_info),
        .rpc => |*rpc_client| {
            const Encoder = std.base64.standard.Encoder;
            const wire_bytes = txn_info.wire_transaction[0..txn_info.wire_transaction_size];
            var encode_buf: [Encoder.calcSize(sig.net.Packet.DATA_SIZE)]u8 = undefined;
            const encoded = Encoder.encode(&encode_buf, wire_bytes);

            var response = try rpc_client.sendTransaction(.{
                .transaction = encoded,
                .config = .{
                    .encoding = .base64,
                    .skipPreflight = self.skip_preflight,
                    // Match the commitment used to fetch the blockhash.
                    .preflightCommitment = .confirmed,
                },
            });
            defer response.deinit();

            switch (response.payload) {
                .result => |result| switch (result) {
                    .signature => {},
                    .preflight_failure => |failure| {
                        self.logger.err().logf("Preflight failure: {any}", .{failure.err});
                        return error.PreflightFailure;
                    },
                },
                .err => |rpc_err| {
                    self.logger.err().logf("RPC error: code={any} message={s}", .{
                        rpc_err.code,
                        rpc_err.message,
                    });
                    if (rpc_err.data) |data| {
                        self.logger.err().logf("RPC error data: {any}", .{data});
                    }
                    return error.RpcRequestFailed;
                },
            }
        },
    }
}

fn initAccounts(self: *Service, allocator: Allocator) !struct { *Account, *Account } {
    while (self.exit.shouldRun()) {
        self.resetAccountBalances(allocator, .finalized) catch |err| {
            self.logger.info().logf("Failed to get account balances: {any}", .{err});
            std.Thread.sleep(10 * std.time.ns_per_s);
            continue;
        };
        break;
    }
    return if (self.account_0.lamports > self.account_1.lamports)
        .{ &self.account_0, &self.account_1 }
    else
        .{ &self.account_1, &self.account_0 };
}

fn resetAccountBalances(self: *Service, allocator: Allocator, commitment: Commitment) !void {
    self.account_0.lamports = try self.getAccountBalance(
        allocator,
        self.account_0.pubkey,
        commitment,
    );
    self.account_1.lamports = try self.getAccountBalance(
        allocator,
        self.account_1.pubkey,
        commitment,
    );
}

fn getAccountBalance(self: *Service, _: Allocator, pubkey: Pubkey, commitment: Commitment) !u64 {
    var response = try self.client.getBalance(
        .{ .pubkey = pubkey, .config = .{ .commitment = commitment } },
    );
    defer response.deinit();
    const result = try response.result();
    return result.value;
}

fn getLatestBlockhash(self: *Service, commitment: Commitment) !Hash {
    var response = try self.client.getLatestBlockhash(
        .{ .config = .{ .commitment = commitment } },
    );
    defer response.deinit();
    const result = try response.result();
    return result.value.blockhash;
}

fn getSignatureStatus(self: *Service, signature: Signature) !Status {
    var response = try self.client.getSignatureStatuses(.{
        .signatures = &.{signature},
        .config = .{ .searchTransactionHistory = true },
    });
    defer response.deinit();
    const result = try response.result();
    if (result.value.len == 0) return .pending;

    const maybe_status = result.value[0] orelse return .pending;
    if (maybe_status.err != null) return .failed;
    return .succeeded;
}

fn buildTransfer(
    self: *Service,
    allocator: Allocator,
    from_account: *Account,
    to_account: *Account,
) !TransactionInfo {
    const blockhash = try self.getLatestBlockhash(.finalized);

    const transaction = try buildTransferTransaction(
        allocator,
        from_account.keypair,
        to_account.pubkey,
        TRANSFER_AMOUNT,
        blockhash,
    );
    defer transaction.deinit(allocator);

    const msg_bytes = try transaction.msg.serializeBounded(transaction.version);
    const message_hash = sig.core.transaction.Message.hash(msg_bytes.constSlice());

    return try TransactionInfo.init(
        transaction,
        message_hash,
        // No block height eviction for mock transactions.
        // Eviction will be based on the send service max retries.
        std.math.maxInt(u64),
        null,
        null,
    );
}

fn waitForTransfer(
    self: *Service,
    transfer: *const TransactionInfo,
    timeout: Duration,
) Status {
    const start_time = Instant.now();

    while (self.exit.shouldRun() and start_time.elapsed().lt(timeout)) {
        const status = self.getSignatureStatus(transfer.signature) catch |err| {
            self.logger.info().logf("Failed to get transaction status: {any}", .{err});
            std.Thread.sleep(1 * std.time.ns_per_s);
            continue;
        };

        switch (status) {
            .failed, .succeeded => return status,
            .pending => std.Thread.sleep(1 * std.time.ns_per_s),
        }
    }

    return .pending;
}

fn buildTransferTransaction(
    allocator: Allocator,
    from_keypair: KeyPair,
    to_pubkey: Pubkey,
    lamports: u64,
    recent_blockhash: Hash,
) !sig.core.Transaction {
    const from_pubkey = Pubkey.fromPublicKey(&from_keypair.public_key);

    const account_keys = try allocator.dupe(Pubkey, &.{
        from_pubkey,
        to_pubkey,
        sig.runtime.program.system.ID,
    });
    errdefer allocator.free(account_keys);

    const account_indexes = try allocator.dupe(u8, &.{ 0, 1 });
    errdefer allocator.free(account_indexes);

    var transfer_data = [_]u8{0} ** 12;
    var fbs = std.io.fixedBufferStream(&transfer_data);
    const writer = fbs.writer();
    try writer.writeInt(u32, 2, .little);
    try writer.writeInt(u64, lamports, .little);

    const instruction_data = try allocator.dupe(u8, &transfer_data);
    errdefer allocator.free(instruction_data);

    const instructions = try allocator.alloc(sig.core.transaction.Instruction, 1);
    errdefer allocator.free(instructions);
    instructions[0] = .{
        .program_index = 2,
        .account_indexes = account_indexes,
        .data = instruction_data,
    };

    const msg: sig.core.transaction.Message = .{
        .signature_count = 1,
        .readonly_signed_count = 0,
        .readonly_unsigned_count = 1,
        .account_keys = account_keys,
        .recent_blockhash = recent_blockhash,
        .instructions = instructions,
    };

    return try sig.core.Transaction.initOwnedMessageWithSigningKeypairs(
        allocator,
        .legacy,
        msg,
        &.{from_keypair},
    );
}
