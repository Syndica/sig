const std = @import("std");
const testing = std.testing;
const RpcClient = @import("./rpc/client.zig").Client;
const Filter = RpcClient.Filter;
const types = @import("./rpc/types.zig");
const jsonrpc = @import("./rpc/jsonrpc.zig");
const Error = RpcClient.Error;
const Pubkey = @import("./core/pubkey.zig").Pubkey;
const json = std.json;

const HTTP_ENDPOINT = "https://api.mainnet-beta.solana.com";
const SKIP_RPC_CALLS_TESTING = true; // temp due to std.http.Client leaking

test {
    testing.log_level = std.log.Level.debug;
}

const TestError = error{
    SkipZigTest,
};

test "client should create successfully" {
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();
}

test "client should accept custom headers" {
    var customHeaders = [_][2][]const u8{.{ "Cache-Control", "no-cache" }};
    var client = try RpcClient.init(testing.allocator, .{
        .http_endpoint = HTTP_ENDPOINT,
        .http_headers = &customHeaders,
    });
    defer client.deinit();
}

test "client should not accept bad headers" {
    var customHeaders = [_][2][]const u8{.{ "Cache-Control", "" }};
    try testing.expectError(Error.InvalidHttpHeaders, RpcClient.init(testing.allocator, .{
        .http_endpoint = HTTP_ENDPOINT,
        .http_headers = &customHeaders,
    }));
}

test "pubkey equality works" {
    var pubkey1 = try Pubkey.fromString("4rL4RCWHz3iNCdCaveD8KcHfV9YWGsqSHFPo7X2zBNwa");
    var pubkey1Again = try Pubkey.fromString("4rL4RCWHz3iNCdCaveD8KcHfV9YWGsqSHFPo7X2zBNwa");
    var pubkeyOther = try Pubkey.fromString("Bvg7GuhqwNmV2JVyeZjhAcTPFqPktfmq25VBaZipozda");

    try testing.expect(pubkey1.equals(&pubkey1Again));
    try testing.expect(!pubkey1.equals(&pubkeyOther));
}

test "make 'getAccountInfo' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    const pubkey = try Pubkey.fromString("4rL4RCWHz3iNCdCaveD8KcHfV9YWGsqSHFPo7X2zBNwa");

    var resp = try client.getAccountInfo(pubkey, .{ .encoding = .Base64 });
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("Account info: {any}", .{resp.result().value.data});
}

test "make 'getBalance' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    const pubkey = try Pubkey.fromString("4rL4RCWHz3iNCdCaveD8KcHfV9YWGsqSHFPo7X2zBNwa");

    var resp = try client.getBalance(pubkey);
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("balance info: {any}", .{resp.result().value});
}

test "make 'getBlockHeight' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getBlockHeight();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("block height: {any}", .{resp.result()});
}

test "make 'getBlock' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getBlock(500, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("block info: {any}", .{resp.result()});
}

test "make 'getBlockProduction' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    testing.log_level = std.log.Level.debug;
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getBlockProduction(.{ .identity = "1EWZm7aZYxfZHbyiELXtTgN1yT2vU1HF9d8DWswX2Tp" });
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("block production info: {any}", .{resp.result()});
}

test "make 'getBlockCommitment' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getBlockCommitment(400);
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("block commitment info: {any}", .{resp.result()});
}

test "make 'getBlocks' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getBlocks(400, 500, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("blocks: {any}", .{resp.result()});
}

test "make 'getBlocksWithLimit' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getBlocksWithLimit(400, 25, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("blocks: {any}", .{resp.result()});
}

test "make 'getBlockTime' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getBlockTime(163954396);
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("block time: {any}", .{resp.result()});
}

test "make 'getClusterNodes' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getClusterNodes();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("cluster nodes: {any}", .{resp.result()});
}

test "make 'getEpochInfo' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getEpochInfo(.{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("epoch info: {any}", .{resp.result()});
}

test "make 'getEpochSchedule' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getEpochSchedule();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("epoch schedule: {any}", .{resp.result()});
}

test "make 'getFeeForMessage' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getFeeForMessage("AQABAgIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEBAQAA", .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("message fee info: {any}", .{resp.result()});
}

test "make 'getFirstAvailableBlock' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getFirstAvailableBlock();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("first available block: {any}", .{resp.result()});
}

test "make 'getGenesisHash' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getGenesisHash();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("genesis hash: {any}", .{resp.result()});
}

test "make 'getHealth' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getHealth();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("health: {any}", .{resp.result()});
}

test "make 'getHighestSnapshotSlot' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getHighestSnapshotSlot();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("snapshot info: {any}", .{resp.result()});
}

test "make 'getIdentity' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getIdentity();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("indentity info: {any}", .{resp.result()});
}

test "make 'getInflationGovernor' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getInflationGovernor(.{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("inflation info: {any}", .{resp.result()});
}

test "make 'getInflationRate' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getInflationRate();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("inflation rate: {any}", .{resp.result()});
}

test "make 'getInflationReward' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var accounts = [2]Pubkey{
        Pubkey.fromString(
            "6dmNQ5jwLeLk5REvio1JcMshcbvkYMwy26sJ8pbkvStu",
        ) catch unreachable,
        Pubkey.fromString(
            "BGsqMegLpV6n6Ve146sSX2dTjUMj3M92HnU8BbNRMhF2",
        ) catch unreachable,
    };
    var resp = try client.getInflationReward(&accounts, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("inflation reward info: {any}", .{resp.result()});
}

test "make 'getLargestAccounts' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getLargestAccounts(.{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("largest accounts: {any}", .{resp.result()});
}

test "make 'getLatestBlockhash' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getLatestBlockhash(.{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("latest blockhash: {any}", .{resp.result()});
}

test "make 'getLeaderSchedule' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getLeaderSchedule(null, .{ .identity = "GRmtMtAeSL8HgX1p815ATQjaYU4Sk7XCP21i4yoFd3KS" });
    // defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("leader schedule: {any}", .{resp.result()});
}

test "make 'getMaxRetransmitSlot' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getMaxRetransmitSlot();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("max retransmit slot: {any}", .{resp.result()});
}

test "make 'getMaxShredInsertSlot' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getMaxShredInsertSlot();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("max shred insert slot: {any}", .{resp.result()});
}

test "make 'getMinimumBalanceForRentExemption' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getMinimumBalanceForRentExemption(1000);
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("minimum balance: {any}", .{resp.result()});
}

test "make 'getMultipleAccounts' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var accounts2 = [2]Pubkey{
        try Pubkey.fromString(
            "4rL4RCWHz3iNCdCaveD8KcHfV9YWGsqSHFPo7X2zBNwa",
        ),
        try Pubkey.fromString(
            "BGsqMegLpV6n6Ve146sSX2dTjUMj3M92HnU8BbNRMhF2",
        ),
    };
    var resp = try client.getMultipleAccounts(&accounts2, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("multiple accounts: {any}", .{resp.result()});
}

test "make 'getProgramAccounts' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var filters = [1]Filter{.{ .memcmp = .{ .offset = 0, .bytes = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v" } }};
    var resp = try client.getProgramAccounts(
        try Pubkey.fromString("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
        .{ .filters = &filters },
    );
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("program accounts: {any}", .{resp.result()});
}

test "make 'getRecentPerformanceSamples' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getRecentPerformanceSamples(null);
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("recent performance samples: {any}", .{resp.result()});
}

test "make 'getRecentPrioritizationFees' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getRecentPrioritizationFees(null);
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("recent prioritization fees: {any}", .{resp.result()});
}

test "make 'getSignaturesForAddress' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getSignaturesForAddress(try Pubkey.fromString("4rL4RCWHz3iNCdCaveD8KcHfV9YWGsqSHFPo7X2zBNwa"), .{ .limit = 10 });
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("signatures: {any}", .{resp.result()});
}

test "make 'getSignatureStatuses' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var signatures = [2][]const u8{
        "3oK4vMqnRbLhdNVq9Cb81JwHim4QaxvgcNEyA4jTySFFtFtBhJgmLwT3rMFAGakKHE9iMiymVNZsTbnrzNjuxXJc",
        "5fqHdfeY1GbshDFzTdybqDbR3mwj5tkgHEP28dFWFZDcvQkkJUynVWrsfMYip8SsfAaFYTFmRdeC3K1CQRC7Ukkb",
    };
    var resp = try client.getSignatureStatuses(&signatures, .{ .searchTransactionHistory = true });
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("signature statuses: {any}", .{resp.result()});
}

test "make 'getSlotLeader' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getSlotLeader(.{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("slot leader: {any}", .{resp.result()});
}

test "make 'getSlotLeaders' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getSlotLeaders(193536000, 10);
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("slot leaders: {any}", .{resp.result()});
}

test "make 'getStakeActivation' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getStakeActivation(try Pubkey.fromString(
        "CWrKSEDYhj6VHGocZowq2BUncKESqD7rdLTSrsoasTjU",
    ), .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("stake activation: {any}", .{resp.result()});
}

test "make 'getStakeMinimumDelegation' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getStakeMinimumDelegation(.{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("min stake delegation: {any}", .{resp.result()});
}

test "make 'getSupply' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getSupply(.{ .excludeNonCirculatingAccountsList = false });
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("get supply: {any}", .{resp.result()});
}

test "make 'getTokenAccountBalance' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var pubkey = try Pubkey.fromString(
        "6A5NHCj1yF6urc9wZNe6Bcjj4LVszQNj5DwAWG97yzMu",
    );
    var resp = try client.getTokenAccountBalance(pubkey, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("token account balance: {any}", .{resp.result()});
}

test "make 'getTokenAccountsByDelegate' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var programPubkey = try Pubkey.fromString(
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
    );
    var pubkey = try Pubkey.fromString(
        "CTz5UMLQm2SRWHzQnU62Pi4yJqbNGjgRBHqqp6oDHfF7",
    );
    var resp = try client.getTokenAccountsByDelegate(pubkey, .{ .programId = programPubkey }, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("token accounts: {any}", .{resp.result()});
}

test "make 'getTokenAccountsByOwner' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var mintPubkey = try Pubkey.fromString(
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    );
    var pubkey = try Pubkey.fromString(
        "CTz5UMLQm2SRWHzQnU62Pi4yJqbNGjgRBHqqp6oDHfF7",
    );
    var resp = try client.getTokenAccountsByOwner(pubkey, .{ .mint = mintPubkey }, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("token accounts: {any}", .{resp.result()});
}

test "make 'getTokenLargestAccounts' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var mintPubkey = try Pubkey.fromString(
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    );
    var resp = try client.getTokenLargestAccounts(mintPubkey, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("token largest accounts: {any}", .{resp.result()});
}

test "make 'getTokenSupply' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var mintPubkey = try Pubkey.fromString(
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    );
    var resp = try client.getTokenSupply(mintPubkey, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("token supply: {any}", .{resp.result()});
}

test "make 'getTransaction' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var txSig = "5UfDuX7WXY18keiz9mZ6zKkY8JyNuLDFz2QycQcr7skRkgVaNmo6tgFbsePRrX5C6crvycJ2A3txSdGgjPHvPbTZ";
    var resp = try client.getTransaction(txSig, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("transaction: {any}", .{resp.result()});
}

test "make 'getTransactionCount' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getTransactionCount(.{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("transaction count: {any}", .{resp.result()});
}

test "make 'getVersion' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.getVersion();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("version: {any}", .{resp.result()});
}

test "make 'getVoteAccounts' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var votePubkey = try Pubkey.fromString(
        "CertusDeBmqN8ZawdkxK5kFGMwBXdudvWHYwtNgNhvLu",
    );
    var resp = try client.getVoteAccounts(.{ .votePubkey = votePubkey });
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("vote accounts: {any}", .{resp.result()});
}

test "make 'isBlockhashValid' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.isBlockhashValid("AaPs8sYJjnDLMMAADYj2fPyDyNzp9to9v4J6c5gevxpX", .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("blockhash valid: {any}", .{resp.result()});
}

test "make 'minimumLedgerSlot' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.minimumLedgerSlot();
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("minimum ledger slot: {any}", .{resp.result()});
}

test "make 'requestAirdrop' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var pubkey = try Pubkey.fromString(
        "Bvg7GuhqwNmV2JVyeZjhAcTPFqPktfmq25VBaZipozda",
    );
    var resp = try client.requestAirdrop(pubkey, 10000, .{});
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("airdrop result: {any}", .{resp.result()});
}

test "make 'sendTransaction' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.sendTransaction(
        "4hXTCkRzt9WyecNzV1XPgCDfGAZzQKNxLXgynz5QDuWWPSAZBZSHptvWRL3BjCvzUXRdKvHL2b7yGrRQcWyaqsaBCncVG7BFggS8w9snUts67BSh3EqKpXLUm5UMHfD7ZBe9GhARjbNQMLJ1QD3Spr6oMTBU6EhdB4RD8CP2xUxr2u3d6fos36PD98XS6oX8TQjLpsMwncs5DAMiD4nNnR8NBfyghGCWvCVifVwvA8B8TJxE1aiyiv2L429BCWfyzAme5sZW8rDb14NeCQHhZbtNqfXhcp2tAnaAT",
        .{},
    );
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("tx signature: {any}", .{resp.result()});
}

test "make 'simulateTransaction' rpc call successfully" {
    if (SKIP_RPC_CALLS_TESTING) {
        return TestError.SkipZigTest;
    }
    var client = try RpcClient.init(testing.allocator, .{ .http_endpoint = HTTP_ENDPOINT });
    defer client.deinit();

    var resp = try client.simulateTransaction(
        "AdYOLBh+RlElmqIY08YZ4OvkWzmGz5ccQLKOENWccchuSluWO7ZTy6B4x/A/WJAFvSFfUhXEcG/PZajL5EmZBQMBAAEDb3Q4CUF/hTg/MgAsYv45KRoWu+9GafjMndSktv5KzQ3fydC+bF4RL7cMFn8iCnd9sKVJp3K3PwOxVZ3agBBUWAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAjkczsB8wv5yFAgAKUdvb4irHybi2IEEHJcAJrfdhMfgBAgIAAQwCAAAAgJaYAAAAAAA=",
        .{},
    );
    defer resp.deinit();

    if (resp.err()) |err| {
        std.log.err("error response: {any}", .{err});
        return;
    }

    std.log.debug("simulate tx info: {any}", .{resp.result()});
}
