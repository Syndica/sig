const std = @import("std");
const sig = @import("../sig.zig");

const Hash = sig.core.Hash;
const Epoch = sig.core.Epoch;
const Slot = sig.core.Slot;
const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;

pub const Client = struct {
    cluster: Cluster,
    client: std.http.Client,

    pub fn init(allocator: std.mem.Allocator, cluster: Cluster) Client {
        return .{
            .cluster = cluster,
            .client = std.http.Client{ .allocator = allocator },
        };
    }

    pub fn deinit(self: *Client) void {
        self.client.deinit();
    }

    const AccountInfo = struct {
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

    const GetAccountInfoConfig = struct {
        commitment: ?[]const u8 = null,
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

    const Balance = struct {
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

    const GetBalanceConfig = struct {
        commitment: ?[]const u8 = null,
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

    const Block = struct {
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

    const GetBlockConfig = struct {
        commitment: ?[]const u8 = null,
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

    const BlockCommitment = struct {
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

    const GetBlockHeightConfig = struct {
        commitment: ?[]const u8 = null,
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

    const GetEpochInfoConfig = struct {
        commitment: ?[]const u8 = null,
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

    const GetLatestBlockhashConfig = struct {
        commitment: ?[]const u8 = null,
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

    // pub const LeaderSchedule = std.StringArrayHashMap([]const u64);
    pub const LeaderSchedule = std.StringArrayHashMap([]const u64);

    pub const GetLeaderScheduleConfig = struct {
        identity: ?[]const u8 = null,
        commitment: ?[]const u8 = null,
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
    // TODO: getSignatureStatuses()
    // TODO: getSignaturesForAddress()

    pub fn getSlot(self: *Client, arena: *std.heap.ArenaAllocator) !Slot {
        return try self.sendFetchRequest(arena.allocator(), Slot, .{
            .method = "getSlot",
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
                .url = self.cluster.httpEndpoint(),
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

        const response = std.json.parseFromSliceLeaky(Response(T), allocator, response_payload.items, .{}) catch |err| {
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

    const Cluster = enum {
        Mainnet,
        Testnet,
        Devnet,

        pub fn httpEndpoint(self: Cluster) []const u8 {
            return switch (self) {
                .Mainnet => "https://api.mainnet.solana.com",
                .Testnet => "https://api.testnet.solana.com",
                .Devnet => "https://api.devnet.solana.com",
            };
        }
    };

    const Request = struct {
        id: u64 = 1,
        jsonrpc: []const u8 = "2.0",
        method: []const u8,
        params: ?[]const u8 = null,

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

test "rpc.Client.getAccountInfo: returns account info" {
    {
        const allocator = std.testing.allocator;
        var client = Client.init(allocator, .Testnet);
        defer client.deinit();
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const pubkey = try Pubkey.fromBase58String("Bkd9xbHF7JgwXmEib6uU3y582WaPWWiasPxzMesiBwWm");
        _ = try client.getAccountInfo(&arena, pubkey, .{});
    }
}

test "rpc.Client.getBalance: returns balance" {
    {
        const allocator = std.testing.allocator;
        var client = Client.init(allocator, .Testnet);
        defer client.deinit();
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const pubkey = try Pubkey.fromBase58String("Bkd9xbHF7JgwXmEib6uU3y582WaPWWiasPxzMesiBwWm");
        _ = try client.getBalance(&arena, pubkey, .{});
    }
}

test "rpc.Client.getBlock: returns block" {
    {
        const allocator = std.testing.allocator;
        var client = Client.init(allocator, .Testnet);
        defer client.deinit();
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        _ = try client.getBlock(&arena, try client.getSlot(&arena) - 10, .{
            .transactionDetails = "none",
            .rewards = false,
        });
    }
}

test "rpc.Client.getBlockHeight: returns block height" {
    {
        const allocator = std.testing.allocator;
        var client = Client.init(allocator, .Testnet);
        defer client.deinit();
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        _ = try client.getBlockHeight(&arena, .{});
    }
}

test "rpc.Client.getBlockCommitment: returns block commitment" {
    {
        const allocator = std.testing.allocator;
        var client = Client.init(allocator, .Testnet);
        defer client.deinit();
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        _ = try client.getBlockCommitment(&arena, try client.getSlot(&arena));
    }
}

test "rpc.Client.getEpochInfo: returns epoch info" {
    {
        const allocator = std.testing.allocator;
        var client = Client.init(allocator, .Testnet);
        defer client.deinit();
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        _ = try client.getEpochInfo(&arena, null, .{});
    }
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

test "rpc.Client.getLatestBlockhash: returns latest blockhash" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet);
    defer client.deinit();
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    _ = try client.getLatestBlockhash(&arena, .{});
}

test "rpc.Client.getLeaderSchedule: returns leader schedule" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet);
    defer client.deinit();
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    _ = try client.getLeaderSchedule(&arena, null, .{});
}

// TODO: getMaxRetransmitSlot()
// TODO: getMaxShredInsertSlot()
// TODO: getMinimumBalanceForRentExemption()
// TODO: getMultipleAccounts()
// TODO: getProgramAccounts()
// TODO: getRecentPerformanceSamples()
// TODO: getRecentPrioritizationFees()
// TODO: getSignatureStatuses()
// TODO: getSignaturesForAddress()

test "rpc.Client.getSlot: returns slot" {
    {
        const allocator = std.testing.allocator;
        var client = Client.init(allocator, .Testnet);
        defer client.deinit();
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        _ = try client.getSlot(&arena);
    }
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
