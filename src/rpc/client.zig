const std = @import("std");
const sig = @import("../sig.zig");

const types = sig.rpc.types;

const Epoch = sig.core.Epoch;
const Slot = sig.core.Slot;
const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;
const ClusterType = sig.accounts_db.genesis_config.ClusterType;
const Request = sig.rpc.Request;
const Response = sig.rpc.Response;
const Logger = sig.trace.log.Logger;

pub const Client = struct {
    endpoint: []const u8,
    client: std.http.Client,
    retries: usize,
    logger: Logger,

    pub const Options = struct {
        retries: usize = 0,
        logger: Logger = .noop,
    };

    pub fn init(allocator: std.mem.Allocator, cluster_type: ClusterType, options: Options) Client {
        const endpoint = switch (cluster_type) {
            .MainnetBeta => "https://api.mainnet-beta.solana.com",
            .Testnet => "https://api.testnet.solana.com",
            .Devnet => "https://api.devnet.solana.com",
            .Development => @panic("Unsupported cluster type 'Development'"),
        };
        return .{
            .endpoint = endpoint,
            .client = std.http.Client{ .allocator = allocator },
            .retries = options.retries,
            .logger = options.logger,
        };
    }

    pub fn deinit(self: *Client) void {
        self.client.deinit();
    }

    /// Wraps a parsed response from the RPC server with an arena
    /// used for request, response, and json parsing allocations
    pub fn Result(comptime T: type) type {
        return struct {
            arena: std.heap.ArenaAllocator,
            value: T,

            pub fn deinit(self: *const Result(T)) void {
                self.arena.deinit();
            }
        };
    }

    pub const GetAccountInfoConfig = struct {
        commitment: ?types.Commitment = null,
        encoding: ?[]const u8 = null,
        dataSlice: ?DataSlice = null,
        minContextSlot: ?u64 = null,

        const DataSlice = struct {
            offset: usize,
            length: usize,
        };
    };

    pub fn getAccountInfo(self: *Client, allocator: std.mem.Allocator, pubkey: Pubkey, config: GetAccountInfoConfig) !Result(types.AccountInfo) {
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();

        var params_builder = Request.ParamsBuilder.init(arena.allocator());
        try params_builder.addArgument("\"{s}\"", pubkey);
        try params_builder.addConfig(config);

        const value = try self.sendFetchRequest(arena.allocator(), types.AccountInfo, .{
            .method = "getAccountInfo",
            .params = try params_builder.build(),
        });

        return .{ .arena = arena, .value = value };
    }

    pub const GetBalanceConfig = struct {
        commitment: ?types.Commitment = null,
        minContextSlot: ?u64 = null,
    };

    pub fn getBalance(self: *Client, allocator: std.mem.Allocator, pubkey: Pubkey, config: GetBalanceConfig) !Result(types.Balance) {
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();

        var params_builder = Request.ParamsBuilder.init(arena.allocator());
        try params_builder.addArgument("\"{s}\"", pubkey);
        try params_builder.addConfig(config);

        const value = try self.sendFetchRequest(arena.allocator(), types.Balance, .{
            .method = "getBalance",
            .params = try params_builder.build(),
        });

        return .{ .arena = arena, .value = value };
    }

    pub const GetBlockConfig = struct {
        commitment: ?types.Commitment = null,
        encoding: ?[]const u8 = null,
        transactionDetails: ?[]const u8 = null,
        maxSupportedTransactionVersion: ?u64 = null,
        rewards: ?bool = null,
    };

    pub fn getBlock(self: *Client, allocator: std.mem.Allocator, slot: Slot, config: GetBlockConfig) !Result(?types.Block) {
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();

        var params_builder = Request.ParamsBuilder.init(arena.allocator());
        try params_builder.addArgument("{d}", slot);
        try params_builder.addConfig(config);

        const value = try self.sendFetchRequest(arena.allocator(), ?types.Block, .{
            .method = "getBlock",
            .params = try params_builder.build(),
        });

        return .{ .arena = arena, .value = value };
    }

    pub fn getBlockCommitment(self: *Client, allocator: std.mem.Allocator, block: u64) !Result(types.BlockCommitment) {
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();

        var params_builder = Request.ParamsBuilder.init(arena.allocator());
        try params_builder.addArgument("{d}", block);
        const value = try self.sendFetchRequest(arena.allocator(), types.BlockCommitment, .{
            .method = "getBlockCommitment",
            .params = try params_builder.build(),
        });

        return .{ .arena = arena, .value = value };
    }

    pub const GetBlockHeightConfig = struct {
        commitment: ?types.Commitment = null,
        minContextSlot: ?u64 = null,
    };

    pub fn getBlockHeight(self: *Client, allocator: std.mem.Allocator, config: GetBlockHeightConfig) !Result(u64) {
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();

        var params_builder = Request.ParamsBuilder.init(arena.allocator());
        try params_builder.addConfig(config);

        const value = try self.sendFetchRequest(arena.allocator(), u64, .{
            .method = "getBlockHeight",
            .params = try params_builder.build(),
        });

        return .{ .arena = arena, .value = value };
    }

    // TODO: getBlockProduction()
    // TODO: getBlockTime()
    // TODO: getBlocks()
    // TODO: getBlocksWithLimit()
    // TODO: getClusterNodes()

    pub const GetEpochInfoConfig = struct {
        commitment: ?types.Commitment = null,
        minContextSlot: ?u64 = null,
    };

    pub fn getEpochInfo(self: *Client, allocator: std.mem.Allocator, maybe_epoch: ?Epoch, config: GetEpochInfoConfig) !Result(types.EpochInfo) {
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();

        var params_builder = Request.ParamsBuilder.init(arena.allocator());
        try params_builder.addOptionalArgument("{d}", maybe_epoch);
        try params_builder.addConfig(config);
        const value = try self.sendFetchRequest(arena.allocator(), types.EpochInfo, .{
            .method = "getEpochInfo",
            .params = try params_builder.build(),
        });

        return .{ .arena = arena, .value = value };
    }
    // TODO: getEpochSchedule()
    // TODO: getFeeForMessage()
    // TODO: getFirstAvailableBlock()
    // TODO: getGenesisHash()
    // TODO: getHealth()
    // TODO: getHighestSnapshotSlot()
    // TODO: getIdentity()
    // TODO: getInflationGovernor()
    // TODO: getInflationRate()
    // TODO: getInflationReward()
    // TODO: getLargeAccounts()

    pub const GetLatestBlockhashConfig = struct {
        commitment: ?types.Commitment = null,
        minContextSlot: ?Slot = null,
    };

    pub fn getLatestBlockhash(self: *Client, allocator: std.mem.Allocator, config: GetLatestBlockhashConfig) !Result(types.LatestBlockhash) {
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();

        var params_builder = Request.ParamsBuilder.init(arena.allocator());
        try params_builder.addConfig(config);

        const value = try self.sendFetchRequest(arena.allocator(), types.LatestBlockhash, .{
            .method = "getLatestBlockhash",
            .params = try params_builder.build(),
        });

        return .{ .arena = arena, .value = value };
    }

    pub const GetLeaderScheduleConfig = struct {
        identity: ?[]const u8 = null,
        commitment: ?types.Commitment = null,
    };

    pub fn getLeaderSchedule(self: *Client, allocator: std.mem.Allocator, maybe_epoch: ?Epoch, config: GetLeaderScheduleConfig) !Result(types.LeaderSchedule) {
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();

        var params_builder = Request.ParamsBuilder.init(arena.allocator());
        try params_builder.addOptionalArgument("{d}", maybe_epoch);
        try params_builder.addConfig(config);

        const leader_schedule_json = try self.sendFetchRequest(arena.allocator(), std.json.Value, .{
            .method = "getLeaderSchedule",
            .params = try params_builder.build(),
        });

        var leader_schedule = types.LeaderSchedule.init(arena.allocator());
        var json_iter = leader_schedule_json.object.iterator();
        while (json_iter.next()) |entry| {
            var slots = try arena.allocator().alloc(u64, entry.value_ptr.*.array.items.len);
            for (entry.value_ptr.*.array.items, 0..) |slot, i| {
                slots[i] = @intCast(slot.integer);
            }
            try leader_schedule.put(entry.key_ptr.*, slots);
        }

        return .{ .arena = arena, .value = leader_schedule };
    }

    // TODO: getMaxRetransmitSlot()
    // TODO: getMaxShredInsertSlot()
    // TODO: getMinimumBalanceForRentExemption()
    // TODO: getMultipleAccounts()
    // TODO: getProgramAccounts()
    // TODO: getRecentPerformanceSamples()
    // TODO: getRecentPrioritizationFees()

    pub const GetSignatureStatusesConfig = struct {
        searchTransactionHistory: ?bool = null,
    };

    pub fn getSignatureStatuses(self: *Client, allocator: std.mem.Allocator, signatures: []const Signature, config: GetSignatureStatusesConfig) !Result(types.SignatureStatuses) {
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();

        var signatures_base58 = try arena.allocator().alloc([]const u8, signatures.len);
        for (signatures, 0..) |signature, i| {
            signatures_base58[i] = try signature.base58StringAlloc(arena.allocator());
        }
        const signatures_json = try std.json.stringifyAlloc(arena.allocator(), signatures_base58, .{});

        var params_builder = Request.ParamsBuilder.init(arena.allocator());
        try params_builder.addArgument("{s}", signatures_json);
        try params_builder.addConfig(config);

        const value = try self.sendFetchRequest(arena.allocator(), types.SignatureStatuses, .{
            .method = "getSignatureStatuses",
            .params = try params_builder.build(),
            .parse_options = .{ .ignore_unknown_fields = true },
        });

        return .{ .arena = arena, .value = value };
    }

    // TODO: getSignaturesForAddress()

    pub const GetSlotConfig = struct {
        commitment: ?types.Commitment = null,
        minContextSlot: ?Slot = null,
    };

    pub fn getSlot(self: *Client, allocator: std.mem.Allocator, config: GetSlotConfig) !Result(Slot) {
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();

        var params_builder = Request.ParamsBuilder.init(arena.allocator());
        try params_builder.addConfig(config);

        const value = try self.sendFetchRequest(arena.allocator(), Slot, .{
            .method = "getSlot",
            .params = try params_builder.build(),
        });

        return .{ .arena = arena, .value = value };
    }

    // TODO: getSlotLeader()
    // TODO: getSlotLeaders()
    // TODO: getStakeActivation()
    // TODO: getStakeMinimumDelegation()
    // TODO: getSupply()
    // TODO: getTokenAccountBalance()
    // TODO: getTokenAccountsByDelegate()
    // TODO: getTockenAccountsByOwner()
    // TODO: getTokenLargestAccounts()
    // TODO: getTokenSupply()
    // TODO: getTransaction()
    // TODO: getTransactionCount()
    // TODO: getVersion()
    // TODO: getVoteAccounts()
    // TODO: isBlockhashValid()
    // TODO: minimumLedgerSlot()
    // TODO: requestAirdrop()
    // TODO: sendTransaction()
    // TODO: simulateTransaction()

    /// Sends a oneshot HTTP request to the RPC server
    /// and parses the response into a JSON object of type T
    /// or returns an error if the request fails or the response
    /// cannot be parsed. Retries the request up to self.retries times.
    /// Allocates are not tracked, so the caller must use an arena allocator.
    fn sendFetchRequest(self: *Client, allocator: std.mem.Allocator, comptime T: type, request: Request) !T {
        var response_payload = try std.ArrayList(u8).initCapacity(allocator, 100 * 1024 * 1024);
        const request_payload = try request.toJsonString(allocator);

        var retries: usize = 0;
        while (true) {
            const result = try self.client.fetch(.{
                .location = .{
                    .url = self.endpoint,
                },
                .method = .POST,
                .headers = .{
                    .content_type = .{
                        .override = "application/json",
                    },
                    .user_agent = .{
                        .override = "sig/0.1",
                    },
                },
                .payload = request_payload,
                .response_storage = .{ .dynamic = &response_payload },
                .max_append_size = 100 * 1024 * 1024,
            });

            if (result.status != std.http.Status.ok) {
                if (retries == self.retries) return error.HttpRequestFailed;
                self.logger.warnf("HTTP request failed ({d}/{d}): {}\n", .{ retries, self.retries, result.status });
                retries += 1;
                continue;
            }

            break;
        }

        const response = std.json.parseFromSliceLeaky(
            Response(T),
            allocator,
            response_payload.items,
            request.parse_options,
        ) catch |err| {
            self.logger.errf("Failed to parse JSON response: error={} response={s}\n", .{ err, response_payload.items });
            return err;
        };

        if (response.@"error") |err| {
            self.logger.errf("Rpc request failed: request={s} error={s}\n", .{ request_payload, try err.toJsonString(allocator) });
            return error.RpcRequestFailed;
        }

        if (response.result) |res| {
            return res;
        }

        self.logger.err("Rpc response has null error and result\n");
        return error.UnknownRpcError;
    }
};

test "getAccountInfo" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    const pubkey = try Pubkey.fromString("Bkd9xbHF7JgwXmEib6uU3y582WaPWWiasPxzMesiBwWm");
    const result = try client.getAccountInfo(allocator, pubkey, .{});
    defer result.deinit();
}

test "getBalance" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    const pubkey = try Pubkey.fromString("Bkd9xbHF7JgwXmEib6uU3y582WaPWWiasPxzMesiBwWm");
    const result = try client.getBalance(allocator, pubkey, .{});
    defer result.deinit();
}

test "getBlock" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    const block_result = try client.getSlot(allocator, .{ .commitment = .finalized });
    defer block_result.deinit();
    const result = try client.getBlock(allocator, block_result.value, .{
        .transactionDetails = "none",
        .rewards = false,
    });
    defer result.deinit();
}

test "getBlockHeight" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    const result = try client.getBlockHeight(allocator, .{});
    defer result.deinit();
}

test "getBlockCommitment" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    const slot_result = try client.getSlot(allocator, .{ .commitment = .finalized });
    defer slot_result.deinit();
    const result = try client.getBlockCommitment(allocator, slot_result.value);
    defer result.deinit();
}

test "getEpochInfo" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    const result = try client.getEpochInfo(allocator, null, .{});
    defer result.deinit();
}

// TODO: test getEpochSchedule()
// TODO: test getFeeForMessage()
// TODO: test getFirstAvailableBlock()
// TODO: test getGenesisHash()
// TODO: test getHealth()
// TODO: test getHighestSnapshotSlot()
// TODO: test getIdentity()
// TODO: test getInflationGovernor()
// TODO: test getInflationRate()
// TODO: test getInflationReward()
// TODO: test getLargeAccounts()

test "getLatestBlockhash" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    const result = try client.getLatestBlockhash(allocator, .{});
    defer result.deinit();
}

test "getLeaderSchedule" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    const result = try client.getLeaderSchedule(allocator, null, .{});
    defer result.deinit();
}

// TODO: test getMaxRetransmitSlot()
// TODO: test getMaxShredInsertSlot()
// TODO: test getMinimumBalanceForRentExemption()
// TODO: test getMultipleAccounts()
// TODO: test getProgramAccounts()
// TODO: test getRecentPerformanceSamples()
// TODO: test getRecentPrioritizationFees()

test "getSignatureStatuses" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    var signatures = try allocator.alloc(Signature, 2);
    defer allocator.free(signatures);
    signatures[0] = try Signature.fromString(
        "56H13bd79hzZa67gMACJYsKxb5MdfqHhe3ceEKHuBEa7hgjMgAA4Daivx68gBFUa92pxMnhCunngcP3dpVnvczGp",
    );
    signatures[1] = try Signature.fromString(
        "4K6Gjut37p3ajRtsN2s6q1Miywit8VyP7bAYLfVSkripdNJkF3bL6BWG7dauzZGMr3jfsuFaPR91k2NuuCc7EqAz",
    );
    const result = try client.getSignatureStatuses(allocator, signatures, .{});
    defer result.deinit();
}

// TODO: test getSignaturesForAddress()

test "getSlot" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    const result = try client.getSlot(allocator, .{});
    defer result.deinit();
}

// TODO: test getSlotLeader()
// TODO: test getSlotLeaders()
// TODO: test getStakeActivation()
// TODO: test getStakeMinimumDelegation()
// TODO: test getSupply()
// TODO: test getTokenAccountBalance()
// TODO: test getTokenAccountsByDelegate()
// TODO: test getTockenAccountsByOwner()
// TODO: test getTokenLargestAccounts()
// TODO: test getTokenSupply()
// TODO: test getTransaction()
// TODO: test getTransactionCount()
// TODO: test getVersion()
// TODO: test getVoteAccounts()
// TODO: test isBlockhashValid()
// TODO: test minimumLedgerSlot()
// TODO: test requestAirdrop()
// TODO: test sendTransaction()
// TODO: test simulateTransaction()
