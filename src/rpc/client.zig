const std = @import("std");
const sig = @import("../sig.zig");

const Hash = sig.core.Hash;
const Epoch = sig.core.Epoch;
const Slot = sig.core.Slot;
const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;
const ClusterType = sig.accounts_db.genesis_config.ClusterType;

/// Rpc Client
/// TODO:
/// - change get methods to take std.mem.Allocator and return type T wrapped with arena
/// - implement remaining methods
pub const Client = struct {
    cluster: ClusterType,
    client: std.http.Client,

    pub fn init(allocator: std.mem.Allocator, cluster: ClusterType) Client {
        return .{
            .cluster = cluster,
            .client = std.http.Client{ .allocator = allocator },
        };
    }

    pub fn deinit(self: *Client) void {
        self.client.deinit();
    }

    pub const AccountInfo = struct {
        context: Context,
        value: Value,

        const Context = struct {
            slot: u64,
            apiVersion: []const u8,
        };

        const Value = struct {
            data: []const u8,
            executable: bool,
            lamports: u64,
            owner: []const u8,
            rentEpoch: u64,
            space: u64,
        };
    };

    pub const GetAccountInfoConfig = struct {
        commitment: ?Commitment = null,
        encoding: ?[]const u8 = null,
        dataSlice: ?DataSlice = null,
        minContextSlot: ?u64 = null,

        const DataSlice = struct {
            offset: usize,
            length: usize,
        };
    };

    pub fn getAccountInfo(self: *Client, arena: *std.heap.ArenaAllocator, pubkey: Pubkey, config: GetAccountInfoConfig) !AccountInfo {
        var params_builder = ParamsBuilder.init(arena.allocator());
        try params_builder.addArgument("\"{s}\"", pubkey.toBase58String().slice());
        try params_builder.addConfig(config);
        return try self.sendFetchRequest(arena.allocator(), AccountInfo, .{
            .method = "getAccountInfo",
            .params = try params_builder.build(),
        });
    }

    pub const Balance = struct {
        context: Context,
        value: u64,

        const Context = struct {
            slot: u64,
            apiVersion: []const u8,
        };

        pub fn deinit(self: *const Balance, allocator: std.mem.Allocator) void {
            allocator.free(self.context.apiVersion);
        }
    };

    pub const GetBalanceConfig = struct {
        commitment: ?Commitment = null,
        minContextSlot: ?u64 = null,
    };

    pub fn getBalance(self: *Client, arena: *std.heap.ArenaAllocator, pubkey: Pubkey, config: GetBalanceConfig) !Balance {
        var params_builder = ParamsBuilder.init(arena.allocator());
        try params_builder.addArgument("\"{s}\"", pubkey.toBase58String().slice());
        try params_builder.addConfig(config);
        return try self.sendFetchRequest(arena.allocator(), Balance, .{
            .method = "getBalance",
            .params = try params_builder.build(),
        });
    }

    pub const Block = struct {
        blockhash: []const u8,
        previousBlockhash: []const u8,
        parentSlot: u64,
        blockTime: ?u64 = null,
        blockHeight: ?u64 = null,
        transactions: ?[]const _Transaction = null,
        signatures: ?[]const _Signature = null,
        rewards: ?[]const _Rewards = null,

        const _Transaction = struct {
            // TODO: Implement
        };

        const _Signature = struct {
            // TODO: Implement
        };

        const _Rewards = struct {
            pubkey: []const u8,
            lamports: u64,
            postBalance: u64,
            rewardType: ?[]const u8,
            commission: ?u8,
        };
    };

    pub const GetBlockConfig = struct {
        commitment: ?Commitment = null,
        encoding: ?[]const u8 = null,
        transactionDetails: ?[]const u8 = null,
        maxSupportedTransactionVersion: ?u64 = null,
        rewards: ?bool = null,
    };

    pub fn getBlock(self: *Client, arena: *std.heap.ArenaAllocator, slot: Slot, config: GetBlockConfig) !?Block {
        var params_builder = ParamsBuilder.init(arena.allocator());
        try params_builder.addArgument("{d}", slot);
        try params_builder.addConfig(config);
        return try self.sendFetchRequest(arena.allocator(), ?Block, .{
            .method = "getBlock",
            .params = try params_builder.build(),
        });
    }

    pub const BlockCommitment = struct {
        commitment: ?[]const u64,
        totalStake: u64,
    };

    pub fn getBlockCommitment(self: *Client, arena: *std.heap.ArenaAllocator, block: u64) !BlockCommitment {
        const allocator = arena.allocator();
        var params_builder = ParamsBuilder.init(allocator);
        try params_builder.addArgument("{d}", block);
        return try self.sendFetchRequest(arena.allocator(), BlockCommitment, .{
            .method = "getBlockCommitment",
            .params = try params_builder.build(),
        });
    }

    pub const GetBlockHeightConfig = struct {
        commitment: ?Commitment = null,
        minContextSlot: ?u64 = null,
    };

    pub fn getBlockHeight(self: *Client, arena: *std.heap.ArenaAllocator, config: GetBlockHeightConfig) !u64 {
        var params_builder = ParamsBuilder.init(arena.allocator());
        try params_builder.addConfig(config);
        return try self.sendFetchRequest(arena.allocator(), u64, .{
            .method = "getBlockHeight",
            .params = try params_builder.build(),
        });
    }

    // TODO: getBlockProduction()
    // TODO: getBlockTime()
    // TODO: getBlocks()
    // TODO: getBlocksWithLimit()
    // TODO: getClusterNodes()

    pub const EpochInfo = struct {
        absoluteSlot: u64,
        blockHeight: u64,
        epoch: u64,
        slotIndex: u64,
        slotsInEpoch: u64,
        transactionCount: u64,
    };

    pub const GetEpochInfoConfig = struct {
        commitment: ?Commitment = null,
        minContextSlot: ?u64 = null,
    };

    pub fn getEpochInfo(self: *Client, arena: *std.heap.ArenaAllocator, maybe_epoch: ?Epoch, config: GetEpochInfoConfig) !EpochInfo {
        var params_builder = ParamsBuilder.init(arena.allocator());
        try params_builder.addOptionalArgument("{d}", maybe_epoch);
        try params_builder.addConfig(config);
        return try self.sendFetchRequest(arena.allocator(), EpochInfo, .{
            .method = "getEpochInfo",
            .params = try params_builder.build(),
        });
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

    pub const LatestBlockhash = struct {
        context: Context,
        value: Value,

        const Context = struct {
            slot: u64,
            apiVersion: []const u8,
        };

        const Value = struct {
            blockhash: []const u8,
            lastValidBlockHeight: u64,
        };
    };

    pub const GetLatestBlockhashConfig = struct {
        commitment: ?Commitment = null,
        minContextSlot: ?Slot = null,
    };

    pub fn getLatestBlockhash(self: *Client, arena: *std.heap.ArenaAllocator, config: GetLatestBlockhashConfig) !LatestBlockhash {
        var params_builder = ParamsBuilder.init(arena.allocator());
        try params_builder.addConfig(config);
        return try self.sendFetchRequest(arena.allocator(), LatestBlockhash, .{
            .method = "getLatestBlockhash",
            .params = try params_builder.build(),
        });
    }

    pub const LeaderSchedule = std.StringArrayHashMap([]const u64);

    pub const GetLeaderScheduleConfig = struct {
        identity: ?[]const u8 = null,
        commitment: ?Commitment = null,
    };

    pub fn getLeaderSchedule(self: *Client, arena: *std.heap.ArenaAllocator, maybe_epoch: ?Epoch, config: GetLeaderScheduleConfig) !LeaderSchedule {
        const allocator = arena.allocator();
        var params_builder = ParamsBuilder.init(allocator);
        try params_builder.addOptionalArgument("{d}", maybe_epoch);
        try params_builder.addConfig(config);
        const leader_schedule_json = try self.sendFetchRequest(allocator, std.json.Value, .{
            .method = "getLeaderSchedule",
            .params = try params_builder.build(),
        });

        var leader_schedule = LeaderSchedule.init(allocator);
        var json_iter = leader_schedule_json.object.iterator();
        while (json_iter.next()) |entry| {
            var slots = try allocator.alloc(u64, entry.value_ptr.*.array.items.len);
            for (entry.value_ptr.*.array.items, 0..) |slot, i| {
                slots[i] = @intCast(slot.integer);
            }
            try leader_schedule.put(entry.key_ptr.*, slots);
        }

        return leader_schedule; // TODO: handle error
    }

    // TODO: getMaxRetransmitSlot()
    // TODO: getMaxShredInsertSlot()
    // TODO: getMinimumBalanceForRentExemption()
    // TODO: getMultipleAccounts()
    // TODO: getProgramAccounts()
    // TODO: getRecentPerformanceSamples()
    // TODO: getRecentPrioritizationFees()

    pub const SignatureStatuses = struct {
        context: Context,
        value: []const ?Status,

        pub const Context = struct {
            apiVersion: []const u8,
            slot: u64,
        };

        pub const Status = struct {
            slot: u64,
            confirmations: ?usize,
            err: ?[]const u8,
            confirmationStatus: ?[]const u8,
        };
    };

    pub const GetSignatureStatusesConfig = struct {
        searchTransactionHistory: ?bool = null,
    };

    pub fn getSignatureStatuses(
        self: *Client,
        arena: *std.heap.ArenaAllocator,
        signatures: []const Signature,
        config: GetSignatureStatusesConfig,
    ) !SignatureStatuses {
        const allocator = arena.allocator();

        var signatures_base58 = try allocator.alloc([]const u8, signatures.len);
        for (signatures, 0..) |signature, i| {
            signatures_base58[i] = try allocator.dupe(u8, signature.toBase58String().slice());
        }
        const signatures_json = try std.json.stringifyAlloc(allocator, signatures_base58, .{});

        var params_builder = ParamsBuilder.init(arena.allocator());
        try params_builder.addArgument("{s}", signatures_json);
        try params_builder.addConfig(config);
        return try self.sendFetchRequest(arena.allocator(), SignatureStatuses, .{
            .method = "getSignatureStatuses",
            .params = try params_builder.build(),
            .parse_options = .{ .ignore_unknown_fields = true },
        });
    }

    // TODO: getSignaturesForAddress()

    pub const GetSlotConfig = struct {
        commitment: ?Commitment = null,
        minContextSlot: ?Slot = null,
    };

    pub fn getSlot(
        self: *Client,
        arena: *std.heap.ArenaAllocator,
        config: GetSlotConfig,
    ) !Slot {
        var params_builder = ParamsBuilder.init(arena.allocator());
        try params_builder.addConfig(config);
        return try self.sendFetchRequest(arena.allocator(), Slot, .{
            .method = "getSlot",
            .params = try params_builder.build(),
        });
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

    fn sendFetchRequest(self: *Client, allocator: std.mem.Allocator, comptime T: type, request: Request) !T {
        var response_payload = std.ArrayList(u8).init(allocator);
        const request_payload = try request.toJsonString(allocator);

        const result = try self.client.fetch(.{
            .location = .{
                .url = clusterHttpEndpoint(self.cluster),
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
            std.debug.print("HTTP request failed: {}\n", .{result.status});
            return error.HttpRequestFailed;
        }

        const response = std.json.parseFromSliceLeaky(
            Response(T),
            allocator,
            response_payload.items,
            request.parse_options,
        ) catch |err| {
            std.debug.print("Failed to parse JSON response: error={} response={s}\n", .{ err, response_payload.items });
            return err;
        };

        if (response.@"error") |err| {
            const err_string = try std.json.stringifyAlloc(allocator, err, .{});
            std.debug.print("Rpc request failed: request={s} error={s}\n", .{ request_payload, err_string });
            return error.RpcRequestFailed;
        }

        if (response.result) |res| {
            return res;
        }

        std.debug.panic("Both error and result are null\n", .{});

        return error.RpcRequestFailed;
    }

    pub fn clusterHttpEndpoint(cluster_type: ClusterType) []const u8 {
        return switch (cluster_type) {
            .MainnetBeta => "https://api.mainnet-beta.solana.com",
            .Testnet => "https://api.testnet.solana.com",
            .Devnet => "https://api.devnet.solana.com",
            .Development => @panic("Unsupported cluster type 'Development'"),
        };
    }

    const Commitment = enum {
        finalized,
        confirmed,
        processed,
    };

    const Request = struct {
        id: u64 = 1,
        jsonrpc: []const u8 = "2.0",
        method: []const u8,
        params: ?[]const u8 = null,
        parse_options: std.json.ParseOptions = .{},

        pub fn toJsonString(self: Request, allocator: std.mem.Allocator) ![]const u8 {
            if (self.params) |params|
                return try std.fmt.allocPrint(
                    allocator,
                    "{{\"id\":{},\"jsonrpc\":\"{s}\",\"method\":\"{s}\",\"params\":{s}}}",
                    .{
                        self.id,
                        self.jsonrpc,
                        self.method,
                        params,
                    },
                );
            return try std.fmt.allocPrint(
                allocator,
                "{{\"id\":{d},\"jsonrpc\":\"{s}\",\"method\":\"{s}\"}}",
                .{
                    self.id,
                    self.jsonrpc,
                    self.method,
                },
            );
        }
    };

    const ParamsBuilder = struct {
        allocator: std.mem.Allocator,
        array: std.ArrayList([]const u8),

        pub fn init(allocator: std.mem.Allocator) ParamsBuilder {
            return .{
                .allocator = allocator,
                .array = std.ArrayList([]const u8).init(allocator),
            };
        }

        pub fn addArgument(self: *ParamsBuilder, comptime fmt: []const u8, arg: anytype) !void {
            try self.array.append(try std.fmt.allocPrint(self.allocator, fmt, .{arg}));
        }

        pub fn addOptionalArgument(self: *ParamsBuilder, comptime fmt: []const u8, maybe_arg: anytype) !void {
            if (maybe_arg) |arg| {
                try self.array.append(try std.fmt.allocPrint(self.allocator, fmt, .{arg}));
            }
        }

        pub fn addConfig(self: *ParamsBuilder, config: anytype) !void {
            const config_string = try std.json.stringifyAlloc(
                self.allocator,
                config,
                .{ .emit_null_optional_fields = false },
            );
            if (!std.mem.eql(u8, config_string, "{}")) {
                try self.array.append(try std.fmt.allocPrint(self.allocator, "{s}", .{config_string}));
            }
        }

        pub fn build(self: *ParamsBuilder) !?[]const u8 {
            if (self.array.items.len == 0) return null;
            // TODO: Replace hacky solution with proper json serialization
            var params = try std.fmt.allocPrint(self.allocator, "{s}", .{self.array.items});
            params[0] = '[';
            params[params.len - 1] = ']';
            return params;
        }
    };

    fn Response(comptime T: type) type {
        return struct {
            id: ?u64,
            jsonrpc: []const u8,
            result: ?T = null,
            @"error": ?Error = null,

            const Error = struct {
                code: i64,
                message: []const u8,
            };
        };
    }
};

test "getAccountInfo" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet);
    defer client.deinit();
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const pubkey = try Pubkey.fromBase58String("Bkd9xbHF7JgwXmEib6uU3y582WaPWWiasPxzMesiBwWm");
    _ = try client.getAccountInfo(&arena, pubkey, .{});
}

test "getBalance" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet);
    defer client.deinit();
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const pubkey = try Pubkey.fromBase58String("Bkd9xbHF7JgwXmEib6uU3y582WaPWWiasPxzMesiBwWm");
    _ = try client.getBalance(&arena, pubkey, .{});
}

test "getBlock" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet);
    defer client.deinit();
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const block = try client.getSlot(&arena, .{ .commitment = .finalized });
    _ = try client.getBlock(&arena, block, .{
        .transactionDetails = "none",
        .rewards = false,
    });
}

test "getBlockHeight" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet);
    defer client.deinit();
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    _ = try client.getBlockHeight(&arena, .{});
}

test "getBlockCommitment" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet);
    defer client.deinit();
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const slot = try client.getSlot(&arena, .{ .commitment = .finalized });
    _ = try client.getBlockCommitment(&arena, slot);
}

test "getEpochInfo" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet);
    defer client.deinit();
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    _ = try client.getEpochInfo(&arena, null, .{});
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
    var client = Client.init(allocator, .Testnet);
    defer client.deinit();
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    _ = try client.getLatestBlockhash(&arena, .{});
}

test "getLeaderSchedule" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet);
    defer client.deinit();
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    _ = try client.getLeaderSchedule(&arena, null, .{});
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
    var client = Client.init(allocator, .Testnet);
    defer client.deinit();
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var signatures = try allocator.alloc(Signature, 2);
    defer allocator.free(signatures);
    signatures[0] = try Signature.fromBase58String(
        "56H13bd79hzZa67gMACJYsKxb5MdfqHhe3ceEKHuBEa7hgjMgAA4Daivx68gBFUa92pxMnhCunngcP3dpVnvczGp",
    );
    signatures[1] = try Signature.fromBase58String(
        "4K6Gjut37p3ajRtsN2s6q1Miywit8VyP7bAYLfVSkripdNJkF3bL6BWG7dauzZGMr3jfsuFaPR91k2NuuCc7EqAz",
    );
    _ = try client.getSignatureStatuses(&arena, signatures, .{});
}

// TODO: test getSignaturesForAddress()

test "getSlot" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet);
    defer client.deinit();
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    _ = try client.getSlot(&arena, .{});
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
