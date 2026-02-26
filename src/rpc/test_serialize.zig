const std = @import("std");
const sig = @import("../sig.zig");
const rpc = @import("lib.zig");

const methods = rpc.methods;

const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;

const GetAccountInfo = methods.GetAccountInfo;
const GetBalance = methods.GetBalance;
const GetBlockCommitment = methods.GetBlockCommitment;
const GetBlockHeight = methods.GetBlockHeight;
const GetEpochInfo = methods.GetEpochInfo;
const GetEpochSchedule = methods.GetEpochSchedule;
const GetGenesisHash = methods.GetGenesisHash;
const GetHighestSnapshotSlot = methods.GetHighestSnapshotSlot;
const GetLatestBlockhash = methods.GetLatestBlockhash;
const GetLeaderSchedule = methods.GetLeaderSchedule;
const GetSignatureStatuses = methods.GetSignatureStatuses;
const GetSlot = methods.GetSlot;
const GetTransactionCount = methods.GetTransactionCount;
const GetVersion = methods.GetVersion;
const GetVoteAccounts = methods.GetVoteAccounts;

const Response = rpc.response.Response;

fn testRequest(
    comptime method: methods.MethodAndParams.Tag,
    /// passed into the client
    params: @FieldType(methods.MethodAndParams, @tagName(method)),
    /// test will assert the request serializes to this json
    expected_request_json: []const u8,
) !void {
    const request: rpc.request.Request = .{
        .id = .{ .int = 1 },
        .method = @unionInit(
            methods.MethodAndParams,
            @tagName(method),
            params,
        ),
    };

    var w = std.io.Writer.Allocating.init(std.testing.allocator);
    defer w.deinit();
    try std.json.fmt(request, .{}).format(&w.writer);
    const actual_request_json = w.written();

    try std.testing.expectEqualSlices(u8, expected_request_json, actual_request_json);
}

fn testResponse(
    Method: type,
    /// test will assert the response deserializes to this struct
    expected_response: Response(Method.Response).Payload,
    /// will be provided to the client as a response
    response_json: []const u8,
) !void {
    const actual_response = try Response(Method.Response).fromJson(std.testing.allocator, response_json);
    defer actual_response.deinit();
    try std.testing.expect(sig.utils.types.eql(expected_response, actual_response.payload));
}

test GetAccountInfo {
    const pubkey: Pubkey = .parse("Bkd9xbHF7JgwXmEib6uU3y582WaPWWiasPxzMesiBwWm");
    try testRequest(
        .getAccountInfo,
        .{ .pubkey = pubkey },
        \\{"jsonrpc":"2.0","id":1,"method":"getAccountInfo","params":["Bkd9xbHF7JgwXmEib6uU3y582WaPWWiasPxzMesiBwWm"]}
        ,
    );
    try testResponse(
        GetAccountInfo,
        .{ .result = .{
            .context = .{ .apiVersion = "2.1.6", .slot = 309275280 },
            .value = .{
                .data = .{ .json_parsed_base64_fallback = "" },
                .executable = false,
                .lamports = 963849100,
                .owner = .parse("11111111111111111111111111111111"),
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
        .getBalance,
        .{ .pubkey = .parse("Bkd9xbHF7JgwXmEib6uU3y582WaPWWiasPxzMesiBwWm") },
        \\{"jsonrpc":"2.0","id":1,"method":"getBalance","params":["Bkd9xbHF7JgwXmEib6uU3y582WaPWWiasPxzMesiBwWm"]}
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
    try testRequest(.getBlockHeight, .{},
        \\{"jsonrpc":"2.0","id":1,"method":"getBlockHeight","params":[]}
    );
    try testResponse(GetBlockHeight, .{ .result = 268651537 },
        \\{"jsonrpc":"2.0","result":268651537,"id":1}
    );
}

test GetBlockCommitment {
    try testRequest(.getBlockCommitment, .{ .slot = 309275321 },
        \\{"jsonrpc":"2.0","id":1,"method":"getBlockCommitment","params":[309275321]}
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
    try testRequest(.getEpochInfo, .{},
        \\{"jsonrpc":"2.0","id":1,"method":"getEpochInfo","params":[]}
    );
    try testResponse(GetEpochInfo, .{ .result = GetEpochInfo.Response{
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
    try testRequest(.getEpochSchedule, .{},
        \\{"jsonrpc":"2.0","id":1,"method":"getEpochSchedule","params":[]}
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

test GetGenesisHash {
    try testRequest(.getGenesisHash, .{},
        \\{"jsonrpc":"2.0","id":1,"method":"getGenesisHash","params":[]}
    );
    try testResponse(GetGenesisHash, .{ .result = .{ .hash = sig.core.Hash.parse("4sGjMW1sUnHzSxGspuhpqLDx6wiyjNtZAMdL4VZHirAn") } },
        \\{"jsonrpc":"2.0","result":"4sGjMW1sUnHzSxGspuhpqLDx6wiyjNtZAMdL4VZHirAn","id":1}
    );
}

// TODO: test getHealth()
test GetHighestSnapshotSlot {
    try testRequest(.getHighestSnapshotSlot, .{},
        \\{"jsonrpc":"2.0","id":1,"method":"getHighestSnapshotSlot","params":[]}
    );
    try testResponse(GetHighestSnapshotSlot, .{ .result = .{
        .full = 100,
        .incremental = 110,
    } },
        \\{"jsonrpc":"2.0","result":{"full":100,"incremental":110},"id":1}
    );
    try testResponse(GetHighestSnapshotSlot, .{ .result = .{
        .full = 100,
        .incremental = null,
    } },
        \\{"jsonrpc":"2.0","result":{"full":100},"id":1}
    );
}
// TODO: test getIdentity()
// TODO: test getInflationGovernor()
// TODO: test getInflationRate()
// TODO: test getInflationReward()
// TODO: test getLargeAccounts()

test GetLatestBlockhash {
    try testRequest(.getLatestBlockhash, .{},
        \\{"jsonrpc":"2.0","id":1,"method":"getLatestBlockhash","params":[]}
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
    try testRequest(.getLeaderSchedule, .{},
        \\{"jsonrpc":"2.0","id":1,"method":"getLeaderSchedule","params":[]}
    );
    const response = try Response(GetLeaderSchedule.Response).fromJson(std.testing.allocator,
        \\{"jsonrpc":"2.0","result":{"111uPd5xQyRHSmPzFJuHNUiuHbF55QXsuEbmqxE4ro":[1,3],"123vij84ecQEKUvQ7gYMKxKwKF6PbYSzCzzURYA4xULY":[2,4]},"id":1}
    );
    defer response.deinit();
    const result: GetLeaderSchedule.Response = try response.result();
    try std.testing.expectEqual(2, result.value.count());
    try std.testing.expectEqualSlices(
        u64,
        &.{ 1, 3 },
        result.value.get(.parse("111uPd5xQyRHSmPzFJuHNUiuHbF55QXsuEbmqxE4ro")).?,
    );
    try std.testing.expectEqualSlices(
        u64,
        &.{ 2, 4 },
        result.value.get(.parse("123vij84ecQEKUvQ7gYMKxKwKF6PbYSzCzzURYA4xULY")).?,
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
    signatures[0] = .parse(
        "56H13bd79hzZa67gMACJYsKxb5MdfqHhe3ceEKHuBEa7hgjMgAA4Daivx68gBFUa92pxMnhCunngcP3dpVnvczGp",
    );
    signatures[1] = .parse(
        "4K6Gjut37p3ajRtsN2s6q1Miywit8VyP7bAYLfVSkripdNJkF3bL6BWG7dauzZGMr3jfsuFaPR91k2NuuCc7EqAz",
    );
    try testRequest(.getSignatureStatuses, .{ .signatures = signatures },
        \\{"jsonrpc":"2.0","id":1,"method":"getSignatureStatuses","params":[["56H13bd79hzZa67gMACJYsKxb5MdfqHhe3ceEKHuBEa7hgjMgAA4Daivx68gBFUa92pxMnhCunngcP3dpVnvczGp","4K6Gjut37p3ajRtsN2s6q1Miywit8VyP7bAYLfVSkripdNJkF3bL6BWG7dauzZGMr3jfsuFaPR91k2NuuCc7EqAz"]]}
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
    try testRequest(.getSlot, .{},
        \\{"jsonrpc":"2.0","id":1,"method":"getSlot","params":[]}
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
test GetTransactionCount {
    try testRequest(.getTransactionCount, .{},
        \\{"jsonrpc":"2.0","id":1,"method":"getTransactionCount","params":[]}
    );
    try testResponse(GetTransactionCount, .{ .result = 268651537 },
        \\{"jsonrpc":"2.0","result":268651537,"id":1}
    );
}
// TODO: test getVoteAccounts()
// TODO: test isBlockhashValid()
// TODO: test minimumLedgerSlot()
// TODO: test requestAirdrop()
// TODO: test sendTransaction()
// TODO: test simulateTransaction()

test GetVersion {
    try testRequest(.getVersion, .{},
        \\{"jsonrpc":"2.0","id":1,"method":"getVersion","params":[]}
    );
    try testResponse(
        GetVersion,
        .{ .result = .{ .solana_core = &.{ 50, 46, 49, 46, 54 }, .feature_set = 1793238286 } },
        \\{"jsonrpc":"2.0","result":{"feature-set":1793238286,"solana-core":"2.1.6"},"id":1}
        ,
    );
}

test GetVoteAccounts {
    try testResponse(
        GetVoteAccounts,
        .{ .result = .{
            .current = &.{.{
                .commission = 0,
                .epochVoteAccount = true,
                .epochCredits = &.{ .{ 1, 64, 0 }, .{ 2, 192, 64 } },
                .nodePubkey = .parse("B97CCUW3AEZFGy6uUg6zUdnNYvnVq5VG8PUtb2HayTDD"),
                .lastVote = 147,
                .activatedStake = 42,
                .votePubkey = .parse("3ZT31jkAGhUaw8jsy4bTknwBMP8i4Eueh52By4zXcsVw"),
                .rootSlot = 100,
            }},
            .delinquent = &.{},
        } },
        \\{
        \\  "jsonrpc": "2.0",
        \\  "result": {
        \\    "current": [
        \\      {
        \\        "commission": 0,
        \\        "epochVoteAccount": true,
        \\        "epochCredits": [
        \\          [1, 64, 0],
        \\          [2, 192, 64]
        \\        ],
        \\        "nodePubkey": "B97CCUW3AEZFGy6uUg6zUdnNYvnVq5VG8PUtb2HayTDD",
        \\        "lastVote": 147,
        \\        "activatedStake": 42,
        \\        "votePubkey": "3ZT31jkAGhUaw8jsy4bTknwBMP8i4Eueh52By4zXcsVw",
        \\        "rootSlot": 100
        \\      }
        \\    ],
        \\    "delinquent": []
        \\  },
        \\  "id": 1
        \\}
        ,
    );
}
