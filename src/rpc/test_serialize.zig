const std = @import("std");
const sig = @import("../sig.zig");
const rpc = @import("lib.zig");
const parse_instruction = @import("parse_instruction/lib.zig");

const methods = rpc.methods;

const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;

const GetAccountInfo = methods.GetAccountInfo;
const GetBalance = methods.GetBalance;
const GetBlock = methods.GetBlock;
const GetBlockCommitment = methods.GetBlockCommitment;
const GetBlockHeight = methods.GetBlockHeight;
const GetClusterNodes = methods.GetClusterNodes;
const GetBlocks = methods.GetBlocks;
const GetBlocksWithLimit = methods.GetBlocksWithLimit;
const GetEpochInfo = methods.GetEpochInfo;
const GetEpochSchedule = methods.GetEpochSchedule;
const GetGenesisHash = methods.GetGenesisHash;
const GetInflationGovernor = methods.GetInflationGovernor;
const GetInflationRate = methods.GetInflationRate;
const GetHighestSnapshotSlot = methods.GetHighestSnapshotSlot;
const GetLatestBlockhash = methods.GetLatestBlockhash;
const GetLeaderSchedule = methods.GetLeaderSchedule;
const GetSignatureStatuses = methods.GetSignatureStatuses;
const GetSlot = methods.GetSlot;
const GetTransaction = methods.GetTransaction;
const GetTransactionCount = methods.GetTransactionCount;
const GetTokenAccountBalance = methods.GetTokenAccountBalance;
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

    // Test jsonParsed response deserialization (object_begin branch).
    // Uses std.json.Value as generic representation on the client side.
    {
        const response_json =
            \\{"jsonrpc":"2.0","result":{"context":{"apiVersion":"2.1.6","slot":309275280},"value":{"data":{"program":"nonce","parsed":{"type":"initialized","info":{"authority":"5CZKcm98vSbMwBPRBMF6VkaFtyZfCsjLBbGygQiGGqmJ","blockhash":"4N7Mz3MHMTFgrF2FawpFE42PerjEfyPnsmPSWRxoCon3","feeCalculator":{"lamportsPerSignature":"5000"}}},"space":80},"executable":false,"lamports":1169280,"owner":"11111111111111111111111111111111","rentEpoch":18446744073709551615,"space":80}},"id":1}
        ;
        const response = try Response(GetAccountInfo.Response).fromJson(std.testing.allocator, response_json);
        defer response.deinit();
        const res: GetAccountInfo.Response = try response.result();
        try std.testing.expectEqual(@as(u64, 309275280), res.context.slot);
        try std.testing.expectEqualStrings("2.1.6", res.context.apiVersion);

        const value = res.value.?;
        try std.testing.expectEqual(false, value.executable);
        try std.testing.expectEqual(@as(u64, 1169280), value.lamports);
        try std.testing.expectEqual(@as(u64, 80), value.space);

        // Verify the data is a jsonParsed pre-serialized JSON string
        const json_str = value.data.jsonParsed;
        const parsed_json = try std.json.parseFromSlice(
            std.json.Value,
            std.testing.allocator,
            json_str,
            .{},
        );
        defer parsed_json.deinit();
        const json_val = parsed_json.value;
        try std.testing.expect(json_val == .object);
        const obj = json_val.object;
        try std.testing.expectEqualStrings("nonce", obj.get("program").?.string);
        try std.testing.expectEqual(@as(i64, 80), obj.get("space").?.integer);

        // Verify nested parsed content
        const parsed = obj.get("parsed").?.object;
        try std.testing.expectEqualStrings("initialized", parsed.get("type").?.string);
        const info = parsed.get("info").?.object;
        try std.testing.expectEqualStrings(
            "5CZKcm98vSbMwBPRBMF6VkaFtyZfCsjLBbGygQiGGqmJ",
            info.get("authority").?.string,
        );
    }
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

test GetClusterNodes {
    // getClusterNodes takes no parameters
    try testRequest(.getClusterNodes, .{},
        \\{"jsonrpc":"2.0","id":1,"method":"getClusterNodes","params":[]}
    );
    // Test response with full node info
    try testResponse(GetClusterNodes, .{ .result = &.{.{
        .pubkey = "9QzsJf7LPLj8GkXbYT3LFDKqsj2hHG7TA3xinJHu8epQ",
        .gossip = "10.239.6.48:8001",
        .tvu = "10.239.6.48:8000",
        .tpu = "10.239.6.48:8003",
        .tpuQuic = "10.239.6.48:8009",
        .tpuForwards = "10.239.6.48:8004",
        .tpuForwardsQuic = "10.239.6.48:8010",
        .tpuVote = "10.239.6.48:8005",
        .serveRepair = "10.239.6.48:8008",
        .rpc = "10.239.6.48:8899",
        .pubsub = "10.239.6.48:8900",
        .version = "1.18.15",
        .featureSet = 3241752014,
        .shredVersion = 50093,
    }} },
        \\{"jsonrpc":"2.0","result":[{"featureSet":3241752014,"gossip":"10.239.6.48:8001","pubkey":"9QzsJf7LPLj8GkXbYT3LFDKqsj2hHG7TA3xinJHu8epQ","pubsub":"10.239.6.48:8900","rpc":"10.239.6.48:8899","serveRepair":"10.239.6.48:8008","shredVersion":50093,"tpu":"10.239.6.48:8003","tpuForwards":"10.239.6.48:8004","tpuForwardsQuic":"10.239.6.48:8010","tpuQuic":"10.239.6.48:8009","tpuVote":"10.239.6.48:8005","tvu":"10.239.6.48:8000","version":"1.18.15"}],"id":1}
    );
    // Test response with minimal node info (some fields null)
    try testResponse(GetClusterNodes, .{ .result = &.{.{
        .pubkey = "9QzsJf7LPLj8GkXbYT3LFDKqsj2hHG7TA3xinJHu8epQ",
        .gossip = "10.239.6.48:8001",
        .tvu = null,
        .tpu = null,
        .tpuQuic = null,
        .tpuForwards = null,
        .tpuForwardsQuic = null,
        .tpuVote = null,
        .serveRepair = null,
        .rpc = null,
        .pubsub = null,
        .version = null,
        .featureSet = null,
        .shredVersion = 50093,
    }} },
        \\{"jsonrpc":"2.0","result":[{"featureSet":null,"gossip":"10.239.6.48:8001","pubkey":"9QzsJf7LPLj8GkXbYT3LFDKqsj2hHG7TA3xinJHu8epQ","pubsub":null,"rpc":null,"serveRepair":null,"shredVersion":50093,"tpu":null,"tpuForwards":null,"tpuForwardsQuic":null,"tpuQuic":null,"tpuVote":null,"tvu":null,"version":null}],"id":1}
    );
}

test GetBlocks {
    try testRequest(.getBlocks, .{ .start_slot = 5 },
        \\{"jsonrpc":"2.0","id":1,"method":"getBlocks","params":[5]}
    );
    try testRequest(.getBlocks, .{
        .start_slot = 5,
        .end_slot_or_config = .{ .end_slot = 10 },
    },
        \\{"jsonrpc":"2.0","id":1,"method":"getBlocks","params":[5,10]}
    );
    try testRequest(.getBlocks, .{
        .start_slot = 5,
        .end_slot_or_config = .{ .config = .{ .commitment = .finalized } },
    },
        \\{"jsonrpc":"2.0","id":1,"method":"getBlocks","params":[5,{"commitment":"finalized"}]}
    );
    try testResponse(GetBlocks, .{ .result = &.{ 5, 6, 7, 8, 9, 10 } },
        \\{"jsonrpc":"2.0","result":[5,6,7,8,9,10],"id":1}
    );
    try testResponse(GetBlocks, .{ .result = &.{} },
        \\{"jsonrpc":"2.0","result":[],"id":1}
    );

    // EndSlotOrConfig
    {
        const result = try GetBlocks.EndSlotOrConfig.jsonParseFromValue(
            std.testing.allocator,
            .{ .integer = 42 },
            .{},
        );
        try std.testing.expectEqual(GetBlocks.EndSlotOrConfig{ .end_slot = 42 }, result);
    }
    {
        var obj = std.json.ObjectMap.init(std.testing.allocator);
        defer obj.deinit();
        try obj.put("commitment", .{ .string = "confirmed" });
        const result = try GetBlocks.EndSlotOrConfig.jsonParseFromValue(
            std.testing.allocator,
            .{ .object = obj },
            .{},
        );
        try std.testing.expectEqual(.confirmed, result.config.commitment.?);
    }
    {
        const result = GetBlocks.EndSlotOrConfig.jsonParseFromValue(
            std.testing.allocator,
            .{ .bool = true },
            .{},
        );
        try std.testing.expectError(error.UnexpectedToken, result);
    }
}

test GetBlocksWithLimit {
    try testRequest(.getBlocksWithLimit, .{ .start_slot = 5, .limit = 3 },
        \\{"jsonrpc":"2.0","id":1,"method":"getBlocksWithLimit","params":[5,3]}
    );
    try testRequest(.getBlocksWithLimit, .{
        .start_slot = 5,
        .limit = 3,
        .config = .{ .commitment = .confirmed },
    },
        \\{"jsonrpc":"2.0","id":1,"method":"getBlocksWithLimit","params":[5,3,{"commitment":"confirmed"}]}
    );
    try testResponse(GetBlocksWithLimit, .{ .result = &.{ 5, 6, 7 } },
        \\{"jsonrpc":"2.0","result":[5,6,7],"id":1}
    );
    try testResponse(GetBlocksWithLimit, .{ .result = &.{} },
        \\{"jsonrpc":"2.0","result":[],"id":1}
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
    try testResponse(GetHighestSnapshotSlot, .{ .result = null },
        \\{"jsonrpc":"2.0","result":null,"id":1}
    );
}
// TODO: test getIdentity()

test GetInflationGovernor {
    try testRequest(.getInflationGovernor, .{},
        \\{"jsonrpc":"2.0","id":1,"method":"getInflationGovernor","params":[]}
    );
    try testRequest(.getInflationGovernor, .{ .config = .{ .commitment = .confirmed } },
        \\{"jsonrpc":"2.0","id":1,"method":"getInflationGovernor","params":[{"commitment":"confirmed"}]}
    );
    try testResponse(GetInflationGovernor, .{ .result = .{
        .initial = 0.08,
        .terminal = 0.015,
        .taper = 0.15,
        .foundation = 0.05,
        .foundationTerm = 7.0,
    } },
        \\{"jsonrpc":"2.0","result":{"foundation":0.05,"foundationTerm":7.0,"initial":0.08,"taper":0.15,"terminal":0.015},"id":1}
    );
}

test GetInflationRate {
    // getInflationRate takes no parameters
    try testRequest(.getInflationRate, .{},
        \\{"jsonrpc":"2.0","id":1,"method":"getInflationRate","params":[]}
    );
    try testResponse(GetInflationRate, .{ .result = .{
        .total = 0.08,
        .validator = 0.076,
        .foundation = 0.004,
        .epoch = 728,
    } },
        \\{"jsonrpc":"2.0","result":{"epoch":728,"foundation":0.004,"total":0.08,"validator":0.076},"id":1}
    );
}

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

test GetTokenAccountBalance {
    const pubkey: Pubkey = .parse("7fUAJdStEuGbc3sM84cKRL6yYaaSstyLSU4ve5oovLS7");

    // Request without config
    try testRequest(
        .getTokenAccountBalance,
        .{ .pubkey = pubkey },
        \\{"jsonrpc":"2.0","id":1,"method":"getTokenAccountBalance","params":["7fUAJdStEuGbc3sM84cKRL6yYaaSstyLSU4ve5oovLS7"]}
        ,
    );

    // Request with commitment config
    try testRequest(
        .getTokenAccountBalance,
        .{ .pubkey = pubkey, .config = .{ .commitment = .finalized } },
        \\{"jsonrpc":"2.0","id":1,"method":"getTokenAccountBalance","params":["7fUAJdStEuGbc3sM84cKRL6yYaaSstyLSU4ve5oovLS7",{"commitment":"finalized"}]}
        ,
    );

    // Response deserialization
    try testResponse(GetTokenAccountBalance, .{ .result = .{
        .context = .{ .slot = 1114, .apiVersion = "2.1.6" },
        .value = .init(
            9864,
            .{ .decimals = 2 },
        ),
    } },
        \\{"jsonrpc":"2.0","result":{"context":{"slot":1114,"apiVersion":"2.1.6"},"value":{"uiAmount":98.64,"decimals":2,"amount":"9864","uiAmountString":"98.64"}},"id":1}
    );
}

// TODO: test getTokenAccountsByDelegate()
// TODO: test getTockenAccountsByOwner()
// TODO: test getTokenLargestAccounts()
// TODO: test getTokenSupply()
test GetTransaction {
    const tx_sig: Signature = .parse(
        "56H13bd79hzZa67gMACJYsKxb5MdfqHhe3ceEKHuBEa7hgjMgAA4Daivx68gBFUa92pxMnhCunngcP3dpVnvczGp",
    );

    // Request serialization - signature only
    try testRequest(
        .getTransaction,
        .{ .signature = tx_sig },
        \\{"jsonrpc":"2.0","id":1,"method":"getTransaction","params":["56H13bd79hzZa67gMACJYsKxb5MdfqHhe3ceEKHuBEa7hgjMgAA4Daivx68gBFUa92pxMnhCunngcP3dpVnvczGp"]}
        ,
    );

    // Request serialization - with config
    try testRequest(
        .getTransaction,
        .{
            .signature = tx_sig,
            .config = .{
                .maxSupportedTransactionVersion = 0,
                .encoding = .base64,
            },
        },
        \\{"jsonrpc":"2.0","id":1,"method":"getTransaction","params":["56H13bd79hzZa67gMACJYsKxb5MdfqHhe3ceEKHuBEa7hgjMgAA4Daivx68gBFUa92pxMnhCunngcP3dpVnvczGp",{"commitment":null,"maxSupportedTransactionVersion":0,"encoding":"base64"}]}
        ,
    );

    // Response serialization - transaction not found (none)
    try expectJsonStringify("null", @as(GetTransaction.Response, .none));

    // Response serialization - minimal (no meta, no version, no blockTime)
    try expectJsonStringify(
        \\{"slot":430,"transaction":["AQID","base64"]}
    , @as(GetTransaction.Response, .{ .value = .{
        .slot = 430,
        .transaction = .{
            .transaction = .{ .binary = .{ "AQID", .base64 } },
        },
        .block_time = null,
    } }));

    // Response serialization - full (with meta, version, and blockTime)
    const pre_balances = [_]u64{ 1_000_000_000, 500_000_000 };
    const post_balances = [_]u64{ 999_995_000, 500_005_000 };
    try expectJsonStringify(
        \\{"slot":430,"meta":{"err":null,"fee":5000,"innerInstructions":[],"logMessages":[],"postBalances":[999995000,500005000],"postTokenBalances":[],"preBalances":[1000000000,500000000],"preTokenBalances":[],"rewards":[],"status":{"Ok":null}},"transaction":["AQID","base64"],"version":0,"blockTime":1700000000}
    , @as(GetTransaction.Response, .{ .value = .{
        .slot = 430,
        .transaction = .{
            .transaction = .{ .binary = .{ "AQID", .base64 } },
            .meta = .{
                .err = null,
                .status = .{ .Ok = .{}, .Err = null },
                .fee = 5000,
                .preBalances = &pre_balances,
                .postBalances = &post_balances,
            },
            .version = .{ .number = 0 },
        },
        .block_time = 1_700_000_000,
    } }));
}

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

/// Helper to stringify a value and compare against expected JSON.
fn expectJsonStringify(expected: []const u8, value: anytype) !void {
    const actual = try std.json.Stringify.valueAlloc(std.testing.allocator, value, .{});
    defer std.testing.allocator.free(actual);
    try std.testing.expectEqualStrings(expected, actual);
}

test "GetBlock" {
    // Request serialization
    try testRequest(.getBlock, .{ .slot = 430 },
        \\{"jsonrpc":"2.0","id":1,"method":"getBlock","params":[430]}
    );
    try testRequest(.getBlock, .{
        .slot = 430,
        .encoding_or_config = .{ .encoding = .base64 },
    },
        \\{"jsonrpc":"2.0","id":1,"method":"getBlock","params":[430,"base64"]}
    );
    try testRequest(.getBlock, .{
        .slot = 430,
        .encoding_or_config = .{ .config = .{
            .encoding = .json,
            .transactionDetails = .full,
            .rewards = false,
        } },
    },
        \\{"jsonrpc":"2.0","id":1,"method":"getBlock","params":[430,{"commitment":null,"encoding":"json","transactionDetails":"full","maxSupportedTransactionVersion":null,"rewards":false}]}
    );

    // Response serialization - minimal block
    {
        const response = GetBlock.Response{
            .previousBlockhash = Hash.ZEROES,
            .blockhash = Hash.ZEROES,
            .parentSlot = 99,
        };
        try expectJsonStringify(
            \\{"blockhash":"11111111111111111111111111111111","parentSlot":99,"previousBlockhash":"11111111111111111111111111111111"}
        , response);
    }

    // Response serialization - with blockTime and blockHeight
    {
        const response = GetBlock.Response{
            .previousBlockhash = Hash.ZEROES,
            .blockhash = Hash.ZEROES,
            .parentSlot = 99,
            .blockTime = 1_700_000_000,
            .blockHeight = 42,
        };
        try expectJsonStringify(
            \\{"blockHeight":42,"blockTime":1700000000,"blockhash":"11111111111111111111111111111111","parentSlot":99,"previousBlockhash":"11111111111111111111111111111111"}
        , response);
    }

    // Response serialization - with rewards
    {
        const rewards = [_]GetBlock.Response.UiReward{.{
            .pubkey = Pubkey.ZEROES,
            .lamports = 5000,
            .postBalance = 1_000_000_000,
            .rewardType = .Fee,
            .commission = null,
        }};
        const response = GetBlock.Response{
            .previousBlockhash = Hash.ZEROES,
            .blockhash = Hash.ZEROES,
            .parentSlot = 99,
            .rewards = &rewards,
        };
        try expectJsonStringify(
            \\{"blockhash":"11111111111111111111111111111111","parentSlot":99,"previousBlockhash":"11111111111111111111111111111111","rewards":[{"pubkey":"11111111111111111111111111111111","lamports":5000,"postBalance":1000000000,"rewardType":"Fee","commission":null}]}
        , response);
    }

    // Response serialization - with signatures
    {
        const sigs = [_]Signature{Signature.ZEROES};
        const response = GetBlock.Response{
            .previousBlockhash = Hash.ZEROES,
            .blockhash = Hash.ZEROES,
            .parentSlot = 99,
            .signatures = &sigs,
        };
        try expectJsonStringify(
            \\{"blockhash":"11111111111111111111111111111111","parentSlot":99,"previousBlockhash":"11111111111111111111111111111111","signatures":["1111111111111111111111111111111111111111111111111111111111111111"]}
        , response);
    }

    // UiReward serialization - Fee
    try expectJsonStringify(
        \\{"pubkey":"11111111111111111111111111111111","lamports":5000,"postBalance":1000000000,"rewardType":"Fee","commission":null}
    , GetBlock.Response.UiReward{
        .pubkey = Pubkey.ZEROES,
        .lamports = 5000,
        .postBalance = 1_000_000_000,
        .rewardType = .Fee,
        .commission = null,
    });

    // UiReward serialization - Staking with commission
    try expectJsonStringify(
        \\{"pubkey":"11111111111111111111111111111111","lamports":100000,"postBalance":5000000000,"rewardType":"Staking","commission":10}
    , GetBlock.Response.UiReward{
        .pubkey = Pubkey.ZEROES,
        .lamports = 100_000,
        .postBalance = 5_000_000_000,
        .rewardType = .Staking,
        .commission = 10,
    });

    // UiReward serialization - all reward types
    inline for (.{
        .{ GetBlock.Response.UiReward.RewardType.Fee, "Fee" },
        .{ GetBlock.Response.UiReward.RewardType.Rent, "Rent" },
        .{ GetBlock.Response.UiReward.RewardType.Staking, "Staking" },
        .{ GetBlock.Response.UiReward.RewardType.Voting, "Voting" },
    }) |pair| {
        const actual = try std.json.Stringify.valueAlloc(std.testing.allocator, pair[0], .{});
        defer std.testing.allocator.free(actual);
        const expected = "\"" ++ pair[1] ++ "\"";
        try std.testing.expectEqualStrings(expected, actual);
    }

    // UiReward.fromLedgerReward
    {
        const ledger_reward = sig.ledger.transaction_status.Reward{
            .pubkey = Pubkey.ZEROES,
            .lamports = 5000,
            .post_balance = 1_000_000_000,
            .reward_type = .fee,
            .commission = null,
        };
        const ui_reward = GetBlock.Response.UiReward.fromLedgerReward(ledger_reward);
        try std.testing.expectEqual(Pubkey.ZEROES, ui_reward.pubkey);
        try std.testing.expectEqual(@as(i64, 5000), ui_reward.lamports);
        try std.testing.expectEqual(@as(u64, 1_000_000_000), ui_reward.postBalance);
        try std.testing.expectEqual(GetBlock.Response.UiReward.RewardType.Fee, ui_reward.rewardType.?);
        try std.testing.expectEqual(@as(?u8, null), ui_reward.commission);
    }

    // UiReward.fromLedgerReward - all reward type mappings
    {
        const mappings = .{
            .{ @as(?sig.replay.rewards.RewardType, .fee), GetBlock.Response.UiReward.RewardType.Fee },
            .{ @as(?sig.replay.rewards.RewardType, .rent), GetBlock.Response.UiReward.RewardType.Rent },
            .{ @as(?sig.replay.rewards.RewardType, .staking), GetBlock.Response.UiReward.RewardType.Staking },
            .{ @as(?sig.replay.rewards.RewardType, .voting), GetBlock.Response.UiReward.RewardType.Voting },
        };
        inline for (mappings) |pair| {
            const ledger_reward = sig.ledger.transaction_status.Reward{
                .pubkey = Pubkey.ZEROES,
                .lamports = 0,
                .post_balance = 0,
                .reward_type = pair[0],
                .commission = null,
            };
            const ui_reward = GetBlock.Response.UiReward.fromLedgerReward(ledger_reward);
            try std.testing.expectEqual(pair[1], ui_reward.rewardType.?);
        }
    }

    // UiReward.fromLedgerReward - null reward type
    {
        const ledger_reward = sig.ledger.transaction_status.Reward{
            .pubkey = Pubkey.ZEROES,
            .lamports = 0,
            .post_balance = 0,
            .reward_type = null,
            .commission = null,
        };
        const ui_reward = GetBlock.Response.UiReward.fromLedgerReward(ledger_reward);
        try std.testing.expectEqual(@as(?GetBlock.Response.UiReward.RewardType, null), ui_reward.rewardType);
    }

    // UiTransactionResultStatus serialization
    try expectJsonStringify(
        \\{"Ok":null}
    , GetBlock.Response.UiTransactionResultStatus{ .Ok = .{}, .Err = null });
    try expectJsonStringify(
        \\{"Err":"InsufficientFundsForFee"}
    , GetBlock.Response.UiTransactionResultStatus{ .Ok = null, .Err = .InsufficientFundsForFee });

    // TransactionVersion serialization
    try expectJsonStringify(
        \\"legacy"
    , GetBlock.Response.EncodedTransactionWithStatusMeta.TransactionVersion{ .legacy = {} });
    try expectJsonStringify("0", GetBlock.Response.EncodedTransactionWithStatusMeta.TransactionVersion{ .number = 0 });

    // EncodedTransaction serialization
    try expectJsonStringify(
        \\["AQID","base64"]
    , GetBlock.Response.EncodedTransaction{ .binary = .{ "AQID", .base64 } });
    try expectJsonStringify(
        \\["2j","base58"]
    , GetBlock.Response.EncodedTransaction{ .binary = .{ "2j", .base58 } });
    try expectJsonStringify(
        \\"some_base58_data"
    , GetBlock.Response.EncodedTransaction{ .legacy_binary = "some_base58_data" });

    // EncodedTransactionWithStatusMeta serialization
    try expectJsonStringify(
        \\{"transaction":["AQID","base64"]}
    , GetBlock.Response.EncodedTransactionWithStatusMeta{
        .transaction = .{ .binary = .{ "AQID", .base64 } },
        .meta = null,
        .version = null,
    });
    try expectJsonStringify(
        \\{"transaction":["AQID","base64"],"version":"legacy"}
    , GetBlock.Response.EncodedTransactionWithStatusMeta{
        .transaction = .{ .binary = .{ "AQID", .base64 } },
        .meta = null,
        .version = .legacy,
    });

    // UiTransactionStatusMeta serialization - success with balances
    {
        const pre_balances = [_]u64{ 1_000_000_000, 500_000_000 };
        const post_balances = [_]u64{ 999_995_000, 500_005_000 };
        try expectJsonStringify(
            \\{"err":null,"fee":5000,"innerInstructions":[],"logMessages":[],"postBalances":[999995000,500005000],"postTokenBalances":[],"preBalances":[1000000000,500000000],"preTokenBalances":[],"rewards":[],"status":{"Ok":null}}
        , GetBlock.Response.UiTransactionStatusMeta{
            .err = null,
            .status = .{ .Ok = .{}, .Err = null },
            .fee = 5000,
            .preBalances = &pre_balances,
            .postBalances = &post_balances,
        });
    }

    // UiTransactionStatusMeta serialization - with computeUnitsConsumed
    try expectJsonStringify(
        \\{"computeUnitsConsumed":150000,"err":null,"fee":5000,"innerInstructions":[],"logMessages":[],"postBalances":[],"postTokenBalances":[],"preBalances":[],"preTokenBalances":[],"rewards":[],"status":{"Ok":null}}
    , GetBlock.Response.UiTransactionStatusMeta{
        .err = null,
        .status = .{ .Ok = .{}, .Err = null },
        .fee = 5000,
        .preBalances = &.{},
        .postBalances = &.{},
        .computeUnitsConsumed = .{ .value = 150_000 },
    });

    // UiTransactionStatusMeta serialization - with loadedAddresses
    try expectJsonStringify(
        \\{"err":null,"fee":5000,"innerInstructions":[],"loadedAddresses":{"readonly":["11111111111111111111111111111111"],"writable":[]},"logMessages":[],"postBalances":[],"postTokenBalances":[],"preBalances":[],"preTokenBalances":[],"rewards":[],"status":{"Ok":null}}
    , GetBlock.Response.UiTransactionStatusMeta{
        .err = null,
        .status = .{ .Ok = .{}, .Err = null },
        .fee = 5000,
        .preBalances = &.{},
        .postBalances = &.{},
        .loadedAddresses = .{ .value = .{
            .readonly = &.{Pubkey.ZEROES},
            .writable = &.{},
        } },
    });

    // UiTransactionStatusMeta serialization - innerInstructions and logMessages skipped
    {
        const meta = GetBlock.Response.UiTransactionStatusMeta{
            .err = null,
            .status = .{ .Ok = .{}, .Err = null },
            .fee = 0,
            .preBalances = &.{},
            .postBalances = &.{},
            .innerInstructions = .skip,
            .logMessages = .skip,
            .rewards = .skip,
        };
        const json = try std.json.Stringify.valueAlloc(std.testing.allocator, meta, .{});
        defer std.testing.allocator.free(json);
        try std.testing.expect(std.mem.indexOf(u8, json, "innerInstructions") == null);
        try std.testing.expect(std.mem.indexOf(u8, json, "logMessages") == null);
        try std.testing.expect(std.mem.indexOf(u8, json, "rewards") == null);
        try std.testing.expect(std.mem.indexOf(u8, json, "\"err\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, json, "\"fee\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, json, "\"status\"") != null);
    }

    // UiTransactionStatusMeta serialization - costUnits present
    {
        const json = try std.json.Stringify.valueAlloc(std.testing.allocator, GetBlock.Response.UiTransactionStatusMeta{
            .err = null,
            .status = .{ .Ok = .{}, .Err = null },
            .fee = 0,
            .preBalances = &.{},
            .postBalances = &.{},
            .costUnits = .{ .value = 3428 },
        }, .{});
        defer std.testing.allocator.free(json);
        try std.testing.expect(std.mem.indexOf(u8, json, "\"costUnits\":3428") != null);
    }

    // UiTransactionStatusMeta serialization - returnData present
    {
        const json = try std.json.Stringify.valueAlloc(std.testing.allocator, GetBlock.Response.UiTransactionStatusMeta{
            .err = null,
            .status = .{ .Ok = .{}, .Err = null },
            .fee = 0,
            .preBalances = &.{},
            .postBalances = &.{},
            .returnData = .{ .value = .{
                .programId = Pubkey.ZEROES,
                .data = .{ "AQID", .base64 },
            } },
        }, .{});
        defer std.testing.allocator.free(json);
        try std.testing.expect(std.mem.indexOf(u8, json, "\"returnData\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, json, "\"programId\"") != null);
    }

    // JsonSkippable - value state
    {
        const json = try std.json.Stringify.valueAlloc(std.testing.allocator, GetBlock.Response.UiTransactionStatusMeta{
            .err = null,
            .status = .{ .Ok = .{}, .Err = null },
            .fee = 0,
            .preBalances = &.{},
            .postBalances = &.{},
            .computeUnitsConsumed = .{ .value = 42 },
        }, .{});
        defer std.testing.allocator.free(json);
        try std.testing.expect(std.mem.indexOf(u8, json, "\"computeUnitsConsumed\":42") != null);
    }

    // JsonSkippable - skip state
    {
        const json = try std.json.Stringify.valueAlloc(std.testing.allocator, GetBlock.Response.UiTransactionStatusMeta{
            .err = null,
            .status = .{ .Ok = .{}, .Err = null },
            .fee = 0,
            .preBalances = &.{},
            .postBalances = &.{},
            .computeUnitsConsumed = .skip,
            .loadedAddresses = .skip,
            .returnData = .skip,
        }, .{});
        defer std.testing.allocator.free(json);
        try std.testing.expect(std.mem.indexOf(u8, json, "computeUnitsConsumed") == null);
        try std.testing.expect(std.mem.indexOf(u8, json, "loadedAddresses") == null);
        try std.testing.expect(std.mem.indexOf(u8, json, "returnData") == null);
    }

    // JsonSkippable - none state serializes as null
    {
        const json = try std.json.Stringify.valueAlloc(std.testing.allocator, GetBlock.Response.UiTransactionStatusMeta{
            .err = null,
            .status = .{ .Ok = .{}, .Err = null },
            .fee = 0,
            .preBalances = &.{},
            .postBalances = &.{},
            .rewards = .none,
        }, .{});
        defer std.testing.allocator.free(json);
        try std.testing.expect(std.mem.indexOf(u8, json, "\"rewards\":null") != null);
    }

    // UiTransactionReturnData serialization
    try expectJsonStringify(
        \\{"programId":"11111111111111111111111111111111","data":["AQID","base64"]}
    , GetBlock.Response.UiTransactionReturnData{
        .programId = Pubkey.ZEROES,
        .data = .{ "AQID", .base64 },
    });

    // UiTransactionTokenBalance serialization
    try expectJsonStringify(
        \\{"accountIndex":2,"mint":"11111111111111111111111111111111","owner":"11111111111111111111111111111111","programId":"11111111111111111111111111111111","uiTokenAmount":{"amount":"1000000","decimals":6,"uiAmount":1.0,"uiAmountString":"1"}}
    , GetBlock.Response.UiTransactionTokenBalance{
        .accountIndex = 2,
        .mint = Pubkey.ZEROES,
        .owner = Pubkey.ZEROES,
        .programId = Pubkey.ZEROES,
        .uiTokenAmount = .{
            .amount = "1000000",
            .decimals = 6,
            .uiAmount = 1.0,
            .uiAmountString = "1",
        },
    });

    // UiTokenAmount serialization - without uiAmount
    try expectJsonStringify(
        \\{"amount":"42","decimals":0,"uiAmountString":"42"}
    , GetBlock.Response.UiTokenAmount{
        .amount = "42",
        .decimals = 0,
        .uiAmount = null,
        .uiAmountString = "42",
    });

    // EncodedInstruction serialization
    {
        const accounts = [_]u8{ 0, 1 };
        try expectJsonStringify(
            \\{"programIdIndex":2,"accounts":[0,1],"data":"3Bxs3zzLZLuLQEYX"}
        , GetBlock.Response.EncodedInstruction{
            .programIdIndex = 2,
            .accounts = &accounts,
            .data = "3Bxs3zzLZLuLQEYX",
        });
    }
    try expectJsonStringify(
        \\{"programIdIndex":2,"accounts":[],"data":"3Bxs3zzLZLuLQEYX","stackHeight":1}
    , GetBlock.Response.EncodedInstruction{
        .programIdIndex = 2,
        .accounts = &.{},
        .data = "3Bxs3zzLZLuLQEYX",
        .stackHeight = 1,
    });
    try expectJsonStringify(
        \\{"programIdIndex":3,"accounts":[0,1,2],"data":"base58data"}
    , GetBlock.Response.EncodedInstruction{
        .programIdIndex = 3,
        .accounts = &[_]u8{ 0, 1, 2 },
        .data = "base58data",
    });

    // EncodedMessage serialization
    try expectJsonStringify(
        \\{"accountKeys":["11111111111111111111111111111111"],"header":{"numRequiredSignatures":1,"numReadonlySignedAccounts":0,"numReadonlyUnsignedAccounts":1},"recentBlockhash":"11111111111111111111111111111111","instructions":[]}
    , GetBlock.Response.EncodedMessage{
        .accountKeys = &.{Pubkey.ZEROES},
        .header = .{
            .numRequiredSignatures = 1,
            .numReadonlySignedAccounts = 0,
            .numReadonlyUnsignedAccounts = 1,
        },
        .recentBlockhash = Hash.ZEROES,
        .instructions = &.{},
    });
    try expectJsonStringify(
        \\{"accountKeys":[],"header":{"numRequiredSignatures":1,"numReadonlySignedAccounts":0,"numReadonlyUnsignedAccounts":0},"recentBlockhash":"11111111111111111111111111111111","instructions":[],"addressTableLookups":[{"accountKey":"11111111111111111111111111111111","readonlyIndexes":[1],"writableIndexes":[0]}]}
    , GetBlock.Response.EncodedMessage{
        .accountKeys = &.{},
        .header = .{
            .numRequiredSignatures = 1,
            .numReadonlySignedAccounts = 0,
            .numReadonlyUnsignedAccounts = 0,
        },
        .recentBlockhash = Hash.ZEROES,
        .instructions = &.{},
        .addressTableLookups = &.{.{
            .accountKey = Pubkey.ZEROES,
            .writableIndexes = &.{0},
            .readonlyIndexes = &.{1},
        }},
    });

    // ParsedAccount serialization
    try expectJsonStringify(
        \\{"pubkey":"11111111111111111111111111111111","signer":true,"source":"transaction","writable":true}
    , GetBlock.Response.ParsedAccount{
        .pubkey = Pubkey.ZEROES,
        .writable = true,
        .signer = true,
        .source = .transaction,
    });
    try expectJsonStringify(
        \\{"pubkey":"11111111111111111111111111111111","signer":false,"source":"lookupTable","writable":false}
    , GetBlock.Response.ParsedAccount{
        .pubkey = Pubkey.ZEROES,
        .writable = false,
        .signer = false,
        .source = .lookupTable,
    });

    // AddressTableLookup serialization
    try expectJsonStringify(
        \\{"accountKey":"11111111111111111111111111111111","readonlyIndexes":[2,3],"writableIndexes":[0,1,4]}
    , GetBlock.Response.AddressTableLookup{
        .accountKey = Pubkey.ZEROES,
        .writableIndexes = &[_]u8{ 0, 1, 4 },
        .readonlyIndexes = &[_]u8{ 2, 3 },
    });
    try expectJsonStringify(
        \\{"accountKey":"11111111111111111111111111111111","readonlyIndexes":[],"writableIndexes":[]}
    , GetBlock.Response.AddressTableLookup{
        .accountKey = Pubkey.ZEROES,
        .writableIndexes = &.{},
        .readonlyIndexes = &.{},
    });

    // UiRawMessage serialization - without address table lookups
    {
        const json = try std.json.Stringify.valueAlloc(std.testing.allocator, GetBlock.Response.UiRawMessage{
            .header = .{
                .numRequiredSignatures = 1,
                .numReadonlySignedAccounts = 0,
                .numReadonlyUnsignedAccounts = 1,
            },
            .account_keys = &.{Pubkey.ZEROES},
            .recent_blockhash = Hash.ZEROES,
            .instructions = &.{},
        }, .{});
        defer std.testing.allocator.free(json);
        try std.testing.expect(std.mem.indexOf(u8, json, "\"accountKeys\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, json, "\"header\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, json, "\"numRequiredSignatures\":1") != null);
        try std.testing.expect(std.mem.indexOf(u8, json, "addressTableLookups") == null);
    }

    // UiRawMessage serialization - with address table lookups
    {
        const atl = GetBlock.Response.AddressTableLookup{
            .accountKey = Pubkey.ZEROES,
            .writableIndexes = &[_]u8{0},
            .readonlyIndexes = &.{},
        };
        const json = try std.json.Stringify.valueAlloc(std.testing.allocator, GetBlock.Response.UiRawMessage{
            .header = .{
                .numRequiredSignatures = 1,
                .numReadonlySignedAccounts = 0,
                .numReadonlyUnsignedAccounts = 0,
            },
            .account_keys = &.{},
            .recent_blockhash = Hash.ZEROES,
            .instructions = &.{},
            .address_table_lookups = &.{atl},
        }, .{});
        defer std.testing.allocator.free(json);
        try std.testing.expect(std.mem.indexOf(u8, json, "\"addressTableLookups\"") != null);
    }

    // UiParsedMessage serialization - without address table lookups
    {
        const json = try std.json.Stringify.valueAlloc(std.testing.allocator, GetBlock.Response.UiParsedMessage{
            .account_keys = &.{},
            .recent_blockhash = Hash.ZEROES,
            .instructions = &.{},
        }, .{});
        defer std.testing.allocator.free(json);
        try std.testing.expect(std.mem.indexOf(u8, json, "\"accountKeys\":[]") != null);
        try std.testing.expect(std.mem.indexOf(u8, json, "\"recentBlockhash\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, json, "addressTableLookups") == null);
    }

    // UiMessage serialization - raw variant
    {
        const json = try std.json.Stringify.valueAlloc(std.testing.allocator, GetBlock.Response.UiMessage{ .raw = .{
            .header = .{
                .numRequiredSignatures = 2,
                .numReadonlySignedAccounts = 0,
                .numReadonlyUnsignedAccounts = 1,
            },
            .account_keys = &.{},
            .recent_blockhash = Hash.ZEROES,
            .instructions = &.{},
        } }, .{});
        defer std.testing.allocator.free(json);
        try std.testing.expect(std.mem.indexOf(u8, json, "\"numRequiredSignatures\":2") != null);
    }

    // EncodedTransaction serialization - accounts variant
    {
        const account = GetBlock.Response.ParsedAccount{
            .pubkey = Pubkey.ZEROES,
            .writable = true,
            .signer = true,
            .source = .transaction,
        };
        const json = try std.json.Stringify.valueAlloc(std.testing.allocator, GetBlock.Response.EncodedTransaction{ .accounts = .{
            .signatures = &.{},
            .accountKeys = &.{account},
        } }, .{});
        defer std.testing.allocator.free(json);
        try std.testing.expect(std.mem.indexOf(u8, json, "\"accountKeys\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, json, "\"source\":\"transaction\"") != null);
    }

    // UiCompiledInstruction serialization
    try expectJsonStringify(
        \\{"accounts":[0,1,2],"data":"3Bxs3zzLZLuLQEYX","programIdIndex":3,"stackHeight":2}
    , parse_instruction.UiCompiledInstruction{
        .programIdIndex = 3,
        .accounts = &.{ 0, 1, 2 },
        .data = "3Bxs3zzLZLuLQEYX",
        .stackHeight = 2,
    });
    try expectJsonStringify(
        \\{"accounts":[],"data":"3Bxs3zzLZLuLQEYX","programIdIndex":3}
    , parse_instruction.UiCompiledInstruction{
        .programIdIndex = 3,
        .accounts = &.{},
        .data = "3Bxs3zzLZLuLQEYX",
    });

    // UiPartiallyDecodedInstruction serialization
    try expectJsonStringify(
        \\{"accounts":["Vote111111111111111111111111111111111111111"],"data":"3Bxs3zzLZLuLQEYX","programId":"11111111111111111111111111111111"}
    , parse_instruction.UiPartiallyDecodedInstruction{
        .programId = "11111111111111111111111111111111",
        .accounts = &.{"Vote111111111111111111111111111111111111111"},
        .data = "3Bxs3zzLZLuLQEYX",
    });

    // ParsedInstruction serialization
    {
        var info = std.json.ObjectMap.init(std.testing.allocator);
        defer info.deinit();
        try info.put("lamports", .{ .integer = 5000 });
        try info.put("source", .{ .string = "11111111111111111111111111111111" });

        var parsed = std.json.ObjectMap.init(std.testing.allocator);
        defer parsed.deinit();
        try parsed.put("type", .{ .string = "transfer" });
        try parsed.put("info", .{ .object = info });

        const pi = parse_instruction.ParsedInstruction{
            .program = "system",
            .program_id = "11111111111111111111111111111111",
            .parsed = .{ .object = parsed },
            .stack_height = null,
        };

        const output = try std.json.Stringify.valueAlloc(std.testing.allocator, pi, .{});
        defer std.testing.allocator.free(output);
        try std.testing.expect(std.mem.indexOf(u8, output, "\"parsed\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, output, "\"program\":\"system\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, output, "\"programId\":\"11111111111111111111111111111111\"") != null);
    }

    // UiInnerInstructions serialization
    try expectJsonStringify(
        \\{"index":0,"instructions":[{"accounts":[0],"data":"3Bxs3zzLZLuLQEYX","programIdIndex":2,"stackHeight":2}]}
    , parse_instruction.UiInnerInstructions{
        .index = 0,
        .instructions = &.{.{ .compiled = .{
            .programIdIndex = 2,
            .accounts = &.{0},
            .data = "3Bxs3zzLZLuLQEYX",
            .stackHeight = 2,
        } }},
    });

    // UiInstruction serialization - compiled variant
    try expectJsonStringify(
        \\{"accounts":[0,2],"data":"abcd","programIdIndex":1}
    , parse_instruction.UiInstruction{
        .compiled = .{
            .programIdIndex = 1,
            .accounts = &.{ 0, 2 },
            .data = "abcd",
        },
    });
}
