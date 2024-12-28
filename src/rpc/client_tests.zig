const std = @import("std");
const base58 = @import("base58-zig");
const sig = @import("../sig.zig");
const rpc = @import("lib.zig");

const types = rpc.types;
const methods = rpc.methods;

const Allocator = std.mem.Allocator;

const ClusterType = sig.accounts_db.genesis_config.ClusterType;
const Logger = sig.trace.log.Logger;
const ScopedLogger = sig.trace.log.ScopedLogger;

const Slot = sig.core.Slot;
const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;
const Transaction = sig.core.transaction.Transaction;

const GetAccountInfo = methods.GetAccountInfo;
const GetBalance = methods.GetBalance;
const GetBlockCommitment = methods.GetBlockCommitment;
const GetBlockHeight = methods.GetBlockHeight;
const GetClusterNodes = methods.GetClusterNodes;
const GetEpochInfo = methods.GetEpochInfo;
const GetEpochSchedule = methods.GetEpochSchedule;
const GetLatestBlockhash = methods.GetLatestBlockhash;
const GetLeaderSchedule = methods.GetLeaderSchedule;
const GetSignatureStatuses = methods.GetSignatureStatuses;
const GetSlot = methods.GetSlot;
const GetVersion = methods.GetVersion;

const Response = rpc.response.Response;

fn testRequest(
    /// passed into the client
    request: anytype,
    /// test will assert the request serializes to this json
    expected_request_json: []const u8,
) !void {
    const actual_request_json = try rpc.request.serialize(std.testing.allocator, request);
    defer std.testing.allocator.free(actual_request_json);
    try std.testing.expectEqualSlices(u8, expected_request_json, actual_request_json);
}

fn testResponse(
    Method: type,
    /// test will assert the response deserializes to this struct
    expected_response: Response(Method).Payload,
    /// will be provided to the client as a response
    response_json: []const u8,
) !void {
    const actual_response = try Response(Method).fromJson(std.testing.allocator, response_json);
    defer actual_response.deinit();
    try std.testing.expect(sig.utils.types.eql(expected_response, actual_response.payload));
}

test GetAccountInfo {
    const pubkey = try Pubkey.fromString("Bkd9xbHF7JgwXmEib6uU3y582WaPWWiasPxzMesiBwWm");
    try testRequest(
        GetAccountInfo{ .pubkey = pubkey },
        \\{"id":1,"jsonrpc":"2.0","method":"getAccountInfo","params":["Bkd9xbHF7JgwXmEib6uU3y582WaPWWiasPxzMesiBwWm"]}
        ,
    );
    try testResponse(
        GetAccountInfo,
        .{ .result = .{
            .context = .{ .apiVersion = "2.1.6", .slot = 309275280 },
            .value = .{
                .data = "",
                .executable = false,
                .lamports = 963849100,
                .owner = try Pubkey.fromString("11111111111111111111111111111111"),
                .rentEpoch = 18446744073709551615,
                .space = 0,
            },
        } },
        \\{"jsonrpc":"2.0","result":{"context":{"apiVersion":"2.1.6","slot":309275280},"value":{"data":"","executable":false,"lamports":963849100,"owner":"11111111111111111111111111111111","rentEpoch":18446744073709551615,"space":0}},"id":1}
        ,
    );
    try testResponse(
        GetAccountInfo,
        .{ .result = .{
            .context = .{ .apiVersion = "2.1.6", .slot = 309275280 },
            .value = null,
        } },
        \\{"jsonrpc":"2.0","result":{"context":{"apiVersion":"2.1.6","slot":309275280},"value":null},"id":1}
        ,
    );
}

test GetBalance {
    try testRequest(
        GetBalance{ .pubkey = try Pubkey.fromString("Bkd9xbHF7JgwXmEib6uU3y582WaPWWiasPxzMesiBwWm") },
        \\{"id":1,"jsonrpc":"2.0","method":"getBalance","params":["Bkd9xbHF7JgwXmEib6uU3y582WaPWWiasPxzMesiBwWm"]}
        ,
    );
    try testResponse(GetBalance, .{ .result = .{
        .context = .{ .slot = 309275283, .apiVersion = "2.1.6" },
        .value = 963849100,
    } },
        \\{"jsonrpc":"2.0","result":{"context":{"apiVersion":"2.1.6","slot":309275283},"value":963849100},"id":1}
    );
}

test GetBlockHeight {
    try testRequest(GetBlockHeight{},
        \\{"id":1,"jsonrpc":"2.0","method":"getBlockHeight","params":[]}
    );
    try testResponse(GetBlockHeight, .{ .result = 268651537 },
        \\{"jsonrpc":"2.0","result":268651537,"id":1}
    );
}

test GetBlockCommitment {
    try testRequest(GetBlockCommitment{ .slot = 309275321 },
        \\{"id":1,"jsonrpc":"2.0","method":"getBlockCommitment","params":[309275321]}
    );
    try testResponse(
        GetBlockCommitment,
        .{
            .result = .{
                .commitment = &.{ 56410821025255, 33711292695244, 27701727782831, 55401460131423, 72618639807497, 0, 27796008663080, 0, 28095671118333, 0, 0, 55401620019031, 0, 0, 27705104515750, 55503391231079, 55401283113964, 38837474545660, 38948031805667, 59470578427800, 0, 0, 11133899193586, 0, 11133899193587, 27704990400041, 66439189441453, 0, 2085408698601000, 2095104661986814, 4274561647461058, 282363342888089693 },
                .totalStake = 302884919142324276,
            },
        },
        \\{"jsonrpc":"2.0","result":{"commitment":[56410821025255,33711292695244,27701727782831,55401460131423,72618639807497,0,27796008663080,0,28095671118333,0,0,55401620019031,0,0,27705104515750,55503391231079,55401283113964,38837474545660,38948031805667,59470578427800,0,0,11133899193586,0,11133899193587,27704990400041,66439189441453,0,2085408698601000,2095104661986814,4274561647461058,282363342888089693],"totalStake":302884919142324276},"id":1}
        ,
    );
}

test GetEpochInfo {
    try testRequest(GetEpochInfo{},
        \\{"id":1,"jsonrpc":"2.0","method":"getEpochInfo","params":[]}
    );
    try testResponse(GetEpochInfo, .{ .result = rpc.types.EpochInfo{
        .absoluteSlot = 309275328,
        .blockHeight = 268651552,
        .epoch = 728,
        .slotIndex = 303072,
        .slotsInEpoch = 432000,
        .transactionCount = 511581946977,
    } },
        \\{"jsonrpc":"2.0","result":{"absoluteSlot":309275328,"blockHeight":268651552,"epoch":728,"slotIndex":303072,"slotsInEpoch":432000,"transactionCount":511581946977},"id":1}
    );
}

test GetEpochSchedule {
    try testRequest(GetEpochSchedule{},
        \\{"id":1,"jsonrpc":"2.0","method":"getEpochSchedule","params":[]}
    );
    try testResponse(GetEpochSchedule, .{ .result = .{
        .slotsPerEpoch = 432000,
        .leaderScheduleSlotOffset = 432000,
        .warmup = true,
        .firstNormalEpoch = 14,
        .firstNormalSlot = 524256,
    } },
        \\{"jsonrpc":"2.0","result":{"firstNormalEpoch":14,"firstNormalSlot":524256,"leaderScheduleSlotOffset":432000,"slotsPerEpoch":432000,"warmup":true},"id":1}
    );
}

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

test GetLatestBlockhash {
    try testRequest(GetLatestBlockhash{},
        \\{"id":1,"jsonrpc":"2.0","method":"getLatestBlockhash","params":[]}
    );
    try testResponse(GetLatestBlockhash, .{ .result = .{
        .context = .{ .slot = 309275334, .apiVersion = "2.1.6" },
        .value = .{
            .blockhash = "9hH9qYcmBSZqHa4MyCxEz7P3wPuoo1mDAqrmgmnYF2hZ",
            .lastValidBlockHeight = 268651708,
        },
    } },
        \\{"jsonrpc":"2.0","result":{"context":{"apiVersion":"2.1.6","slot":309275334},"value":{"blockhash":"9hH9qYcmBSZqHa4MyCxEz7P3wPuoo1mDAqrmgmnYF2hZ","lastValidBlockHeight":268651708}},"id":1}
    );
}

test GetLeaderSchedule {
    try testRequest(GetLeaderSchedule{},
        \\{"id":1,"jsonrpc":"2.0","method":"getLeaderSchedule","params":[]}
    );
    const response = try Response(GetLeaderSchedule).fromJson(std.testing.allocator,
        \\{"jsonrpc":"2.0","result":{"111uPd5xQyRHSmPzFJuHNUiuHbF55QXsuEbmqxE4ro":[1,3],"123vij84ecQEKUvQ7gYMKxKwKF6PbYSzCzzURYA4xULY":[2,4]},"id":1}
    );
    defer response.deinit();
    const result: GetLeaderSchedule.Response = try response.result();
    try std.testing.expectEqual(2, result.value.count());
    try std.testing.expectEqualSlices(
        u64,
        &.{ 1, 3 },
        result.value.get(try Pubkey.fromString("111uPd5xQyRHSmPzFJuHNUiuHbF55QXsuEbmqxE4ro")).?,
    );
    try std.testing.expectEqualSlices(
        u64,
        &.{ 2, 4 },
        result.value.get(try Pubkey.fromString("123vij84ecQEKUvQ7gYMKxKwKF6PbYSzCzzURYA4xULY")).?,
    );
}

// TODO: test getMaxRetransmitSlot()
// TODO: test getMaxShredInsertSlot()
// TODO: test getMinimumBalanceForRentExemption()
// TODO: test getMultipleAccounts()
// TODO: test getProgramAccounts()
// TODO: test getRecentPerformanceSamples()
// TODO: test getRecentPrioritizationFees()

test GetSignatureStatuses {
    var signatures = try std.testing.allocator.alloc(Signature, 2);
    defer std.testing.allocator.free(signatures);
    signatures[0] = try Signature.fromString(
        "56H13bd79hzZa67gMACJYsKxb5MdfqHhe3ceEKHuBEa7hgjMgAA4Daivx68gBFUa92pxMnhCunngcP3dpVnvczGp",
    );
    signatures[1] = try Signature.fromString(
        "4K6Gjut37p3ajRtsN2s6q1Miywit8VyP7bAYLfVSkripdNJkF3bL6BWG7dauzZGMr3jfsuFaPR91k2NuuCc7EqAz",
    );
    try testRequest(GetSignatureStatuses{ .signatures = signatures },
        \\{"id":1,"jsonrpc":"2.0","method":"getSignatureStatuses","params":[["56H13bd79hzZa67gMACJYsKxb5MdfqHhe3ceEKHuBEa7hgjMgAA4Daivx68gBFUa92pxMnhCunngcP3dpVnvczGp","4K6Gjut37p3ajRtsN2s6q1Miywit8VyP7bAYLfVSkripdNJkF3bL6BWG7dauzZGMr3jfsuFaPR91k2NuuCc7EqAz"]]}
    );
    try testResponse(GetSignatureStatuses, .{ .result = .{
        .context = .{ .slot = 309275388, .apiVersion = "2.1.6" },
        .value = &.{ null, null },
    } },
        \\{"jsonrpc":"2.0","result":{"context":{"apiVersion":"2.1.6","slot":309275388},"value":[null,null]},"id":1}
    );
}

// TODO: test getSignaturesForAddress()

test GetSlot {
    try testRequest(GetSlot{},
        \\{"id":1,"jsonrpc":"2.0","method":"getSlot","params":[]}
    );
    try testResponse(GetSlot, .{ .result = 309275353 },
        \\{"jsonrpc":"2.0","result":309275353,"id":1}
    );
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
// TODO: test getVoteAccounts()
// TODO: test isBlockhashValid()
// TODO: test minimumLedgerSlot()
// TODO: test requestAirdrop()
// TODO: test sendTransaction()
// TODO: test simulateTransaction()

test GetVersion {
    try testRequest(GetVersion{},
        \\{"id":1,"jsonrpc":"2.0","method":"getVersion","params":[]}
    );
    try testResponse(
        GetVersion,
        .{ .result = .{ .solana_core = &.{ 50, 46, 49, 46, 54 }, .feature_set = 1793238286 } },
        \\{"jsonrpc":"2.0","result":{"feature-set":1793238286,"solana-core":"2.1.6"},"id":1}
        ,
    );
}
