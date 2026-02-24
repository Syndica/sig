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
const GetEpochInfo = methods.GetEpochInfo;
const GetEpochSchedule = methods.GetEpochSchedule;
const GetGenesisHash = methods.GetGenesisHash;
const GetLatestBlockhash = methods.GetLatestBlockhash;
const GetLeaderSchedule = methods.GetLeaderSchedule;
const GetSignatureStatuses = methods.GetSignatureStatuses;
const GetSlot = methods.GetSlot;
const GetTransaction = methods.GetTransaction;
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

    const actual_request_json = try std.json.stringifyAlloc(std.testing.allocator, request, .{});
    defer std.testing.allocator.free(actual_request_json);

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
// TODO: test getHighestSnapshotSlot()
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
            .transaction = .{ .binary = .{ .data = "AQID", .encoding = .base64 } },
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
            .transaction = .{ .binary = .{ .data = "AQID", .encoding = .base64 } },
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

// TODO: test getTransactionCount()
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

// ============================================================================
// GetBlock serialization tests
// ============================================================================

/// Helper to stringify a value and compare against expected JSON.
fn expectJsonStringify(expected: []const u8, value: anytype) !void {
    const actual = try std.json.stringifyAlloc(std.testing.allocator, value, .{});
    defer std.testing.allocator.free(actual);
    try std.testing.expectEqualStrings(expected, actual);
}

test "GetBlock.Response serialization - minimal block (no transactions, no rewards)" {
    const response = GetBlock.Response{
        .previousBlockhash = Hash.ZEROES,
        .blockhash = Hash.ZEROES,
        .parentSlot = 99,
    };
    try expectJsonStringify(
        \\{"blockhash":"11111111111111111111111111111111","parentSlot":99,"previousBlockhash":"11111111111111111111111111111111"}
    , response);
}

test "GetBlock.Response serialization - full block with blockTime and blockHeight" {
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

test "GetBlock.Response serialization - block with rewards" {
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

test "GetBlock.Response serialization - block with signatures" {
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

test "UiReward serialization - Fee reward type" {
    const reward = GetBlock.Response.UiReward{
        .pubkey = Pubkey.ZEROES,
        .lamports = 5000,
        .postBalance = 1_000_000_000,
        .rewardType = .Fee,
        .commission = null,
    };
    try expectJsonStringify(
        \\{"pubkey":"11111111111111111111111111111111","lamports":5000,"postBalance":1000000000,"rewardType":"Fee","commission":null}
    , reward);
}

test "UiReward serialization - Staking reward with commission" {
    const reward = GetBlock.Response.UiReward{
        .pubkey = Pubkey.ZEROES,
        .lamports = 100_000,
        .postBalance = 5_000_000_000,
        .rewardType = .Staking,
        .commission = 10,
    };
    try expectJsonStringify(
        \\{"pubkey":"11111111111111111111111111111111","lamports":100000,"postBalance":5000000000,"rewardType":"Staking","commission":10}
    , reward);
}

test "UiReward serialization - all reward types" {
    // Test all four reward types serialize with correct capitalization
    inline for (.{
        .{ GetBlock.Response.UiReward.RewardType.Fee, "Fee" },
        .{ GetBlock.Response.UiReward.RewardType.Rent, "Rent" },
        .{ GetBlock.Response.UiReward.RewardType.Staking, "Staking" },
        .{ GetBlock.Response.UiReward.RewardType.Voting, "Voting" },
    }) |pair| {
        const actual = try std.json.stringifyAlloc(std.testing.allocator, pair[0], .{});
        defer std.testing.allocator.free(actual);
        const expected = "\"" ++ pair[1] ++ "\"";
        try std.testing.expectEqualStrings(expected, actual);
    }
}

test "UiReward.fromLedgerReward" {
    const ledger_reward = sig.ledger.transaction_status.Reward{
        .pubkey = Pubkey.ZEROES,
        .lamports = 5000,
        .post_balance = 1_000_000_000,
        .reward_type = .fee,
        .commission = null,
    };
    const ui_reward = try GetBlock.Response.UiReward.fromLedgerReward(ledger_reward);
    try std.testing.expectEqual(Pubkey.ZEROES, ui_reward.pubkey);
    try std.testing.expectEqual(@as(i64, 5000), ui_reward.lamports);
    try std.testing.expectEqual(@as(u64, 1_000_000_000), ui_reward.postBalance);
    try std.testing.expectEqual(GetBlock.Response.UiReward.RewardType.Fee, ui_reward.rewardType.?);
    try std.testing.expectEqual(@as(?u8, null), ui_reward.commission);
}

test "UiReward.fromLedgerReward - all reward type mappings" {
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
        const ui_reward = try GetBlock.Response.UiReward.fromLedgerReward(ledger_reward);
        try std.testing.expectEqual(pair[1], ui_reward.rewardType.?);
    }
}

test "UiReward.fromLedgerReward - null reward type" {
    const ledger_reward = sig.ledger.transaction_status.Reward{
        .pubkey = Pubkey.ZEROES,
        .lamports = 0,
        .post_balance = 0,
        .reward_type = null,
        .commission = null,
    };
    const ui_reward = try GetBlock.Response.UiReward.fromLedgerReward(ledger_reward);
    try std.testing.expectEqual(@as(?GetBlock.Response.UiReward.RewardType, null), ui_reward.rewardType);
}

test "UiTransactionResultStatus serialization - success" {
    const status = GetBlock.Response.UiTransactionResultStatus{
        .Ok = .{},
        .Err = null,
    };
    try expectJsonStringify(
        \\{"Ok":null}
    , status);
}

test "UiTransactionResultStatus serialization - error" {
    const status = GetBlock.Response.UiTransactionResultStatus{
        .Ok = null,
        .Err = .InsufficientFundsForFee,
    };
    try expectJsonStringify(
        \\{"Err":"InsufficientFundsForFee"}
    , status);
}

test "TransactionVersion serialization - legacy" {
    const version = GetBlock.Response.EncodedTransactionWithStatusMeta.TransactionVersion{ .legacy = {} };
    try expectJsonStringify(
        \\"legacy"
    , version);
}

test "TransactionVersion serialization - number" {
    const version = GetBlock.Response.EncodedTransactionWithStatusMeta.TransactionVersion{ .number = 0 };
    try expectJsonStringify("0", version);
}

test "EncodedTransaction serialization - binary base64" {
    const tx = GetBlock.Response.EncodedTransaction{
        .binary = .{ .data = "AQID", .encoding = .base64 },
    };
    try expectJsonStringify(
        \\["AQID","base64"]
    , tx);
}

test "EncodedTransaction serialization - binary base58" {
    const tx = GetBlock.Response.EncodedTransaction{
        .binary = .{ .data = "2j", .encoding = .base58 },
    };
    try expectJsonStringify(
        \\["2j","base58"]
    , tx);
}

test "EncodedTransaction serialization - legacy binary" {
    const tx = GetBlock.Response.EncodedTransaction{
        .legacy_binary = "some_base58_data",
    };
    try expectJsonStringify(
        \\"some_base58_data"
    , tx);
}

test "EncodedTransactionWithStatusMeta serialization - minimal" {
    const tx_with_meta = GetBlock.Response.EncodedTransactionWithStatusMeta{
        .transaction = .{ .binary = .{ .data = "AQID", .encoding = .base64 } },
        .meta = null,
        .version = null,
    };
    try expectJsonStringify(
        \\{"transaction":["AQID","base64"]}
    , tx_with_meta);
}

test "EncodedTransactionWithStatusMeta serialization - with version" {
    const tx_with_meta = GetBlock.Response.EncodedTransactionWithStatusMeta{
        .transaction = .{ .binary = .{ .data = "AQID", .encoding = .base64 } },
        .meta = null,
        .version = .legacy,
    };
    try expectJsonStringify(
        \\{"transaction":["AQID","base64"],"version":"legacy"}
    , tx_with_meta);
}

test "UiTransactionStatusMeta serialization - success with balances" {
    const pre_balances = [_]u64{ 1_000_000_000, 500_000_000 };
    const post_balances = [_]u64{ 999_995_000, 500_005_000 };
    const meta = GetBlock.Response.UiTransactionStatusMeta{
        .err = null,
        .status = .{ .Ok = .{}, .Err = null },
        .fee = 5000,
        .preBalances = &pre_balances,
        .postBalances = &post_balances,
    };
    try expectJsonStringify(
        \\{"err":null,"fee":5000,"innerInstructions":[],"logMessages":[],"postBalances":[999995000,500005000],"postTokenBalances":[],"preBalances":[1000000000,500000000],"preTokenBalances":[],"rewards":[],"status":{"Ok":null}}
    , meta);
}

test "UiTransactionStatusMeta serialization - with computeUnitsConsumed" {
    const meta = GetBlock.Response.UiTransactionStatusMeta{
        .err = null,
        .status = .{ .Ok = .{}, .Err = null },
        .fee = 5000,
        .preBalances = &.{},
        .postBalances = &.{},
        .computeUnitsConsumed = .{ .value = 150_000 },
    };
    try expectJsonStringify(
        \\{"computeUnitsConsumed":150000,"err":null,"fee":5000,"innerInstructions":[],"logMessages":[],"postBalances":[],"postTokenBalances":[],"preBalances":[],"preTokenBalances":[],"rewards":[],"status":{"Ok":null}}
    , meta);
}

test "UiTransactionStatusMeta serialization - with loadedAddresses" {
    const meta = GetBlock.Response.UiTransactionStatusMeta{
        .err = null,
        .status = .{ .Ok = .{}, .Err = null },
        .fee = 5000,
        .preBalances = &.{},
        .postBalances = &.{},
        .loadedAddresses = .{ .value = .{
            .readonly = &.{Pubkey.ZEROES},
            .writable = &.{},
        } },
    };
    try expectJsonStringify(
        \\{"err":null,"fee":5000,"innerInstructions":[],"loadedAddresses":{"readonly":["11111111111111111111111111111111"],"writable":[]},"logMessages":[],"postBalances":[],"postTokenBalances":[],"preBalances":[],"preTokenBalances":[],"rewards":[],"status":{"Ok":null}}
    , meta);
}

test "UiTransactionReturnData serialization" {
    const return_data = GetBlock.Response.UiTransactionReturnData{
        .programId = Pubkey.ZEROES,
        .data = .{ "AQID", .base64 },
    };
    try expectJsonStringify(
        \\{"programId":"11111111111111111111111111111111","data":["AQID","base64"]}
    , return_data);
}

test "UiTransactionTokenBalance serialization" {
    const token_balance = GetBlock.Response.UiTransactionTokenBalance{
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
    };
    try expectJsonStringify(
        \\{"accountIndex":2,"mint":"11111111111111111111111111111111","owner":"11111111111111111111111111111111","programId":"11111111111111111111111111111111","uiTokenAmount":{"amount":"1000000","decimals":6,"uiAmount":1e0,"uiAmountString":"1"}}
    , token_balance);
}

test "UiTokenAmount serialization - without uiAmount" {
    const token_amount = GetBlock.Response.UiTokenAmount{
        .amount = "42",
        .decimals = 0,
        .uiAmount = null,
        .uiAmountString = "42",
    };
    try expectJsonStringify(
        \\{"amount":"42","decimals":0,"uiAmountString":"42"}
    , token_amount);
}

test "EncodedInstruction serialization" {
    const accounts = [_]u8{ 0, 1 };
    const ix = GetBlock.Response.EncodedInstruction{
        .programIdIndex = 2,
        .accounts = &accounts,
        .data = "3Bxs3zzLZLuLQEYX",
    };
    // Note: []const u8 serializes as a string via std.json, not as an integer array.
    // The accounts field contains raw byte values, serialized as escaped characters.
    try expectJsonStringify(
        \\{"programIdIndex":2,"accounts":[0,1],"data":"3Bxs3zzLZLuLQEYX"}
    , ix);
}

test "EncodedInstruction serialization - with stackHeight" {
    const ix = GetBlock.Response.EncodedInstruction{
        .programIdIndex = 2,
        .accounts = &.{},
        .data = "3Bxs3zzLZLuLQEYX",
        .stackHeight = 1,
    };
    try expectJsonStringify(
        \\{"programIdIndex":2,"accounts":[],"data":"3Bxs3zzLZLuLQEYX","stackHeight":1}
    , ix);
}

test "EncodedMessage serialization" {
    const msg = GetBlock.Response.EncodedMessage{
        .accountKeys = &.{Pubkey.ZEROES},
        .header = .{
            .numRequiredSignatures = 1,
            .numReadonlySignedAccounts = 0,
            .numReadonlyUnsignedAccounts = 1,
        },
        .recentBlockhash = Hash.ZEROES,
        .instructions = &.{},
    };
    try expectJsonStringify(
        \\{"accountKeys":["11111111111111111111111111111111"],"header":{"numRequiredSignatures":1,"numReadonlySignedAccounts":0,"numReadonlyUnsignedAccounts":1},"recentBlockhash":"11111111111111111111111111111111","instructions":[]}
    , msg);
}

test "EncodedMessage serialization - with addressTableLookups" {
    const msg = GetBlock.Response.EncodedMessage{
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
    };
    // Note: writableIndexes/readonlyIndexes are []const u8, serialized as strings
    try expectJsonStringify(
        \\{"accountKeys":[],"header":{"numRequiredSignatures":1,"numReadonlySignedAccounts":0,"numReadonlyUnsignedAccounts":0},"recentBlockhash":"11111111111111111111111111111111","instructions":[],"addressTableLookups":[{"accountKey":"11111111111111111111111111111111","readonlyIndexes":[1],"writableIndexes":[0]}]}
    , msg);
}

// ============================================================================
// parse_instruction serialization tests
// ============================================================================

test "UiCompiledInstruction serialization" {
    const ix = parse_instruction.UiCompiledInstruction{
        .programIdIndex = 3,
        .accounts = &.{ 0, 1, 2 },
        .data = "3Bxs3zzLZLuLQEYX",
        .stackHeight = 2,
    };
    // UiCompiledInstruction serializes accounts as array of integers
    try expectJsonStringify(
        \\{"accounts":[0,1,2],"data":"3Bxs3zzLZLuLQEYX","programIdIndex":3,"stackHeight":2}
    , ix);
}

test "UiCompiledInstruction serialization - no stackHeight" {
    const ix = parse_instruction.UiCompiledInstruction{
        .programIdIndex = 3,
        .accounts = &.{},
        .data = "3Bxs3zzLZLuLQEYX",
    };
    try expectJsonStringify(
        \\{"accounts":[],"data":"3Bxs3zzLZLuLQEYX","programIdIndex":3}
    , ix);
}

test "UiPartiallyDecodedInstruction serialization" {
    const ix = parse_instruction.UiPartiallyDecodedInstruction{
        .programId = "11111111111111111111111111111111",
        .accounts = &.{"Vote111111111111111111111111111111111111111"},
        .data = "3Bxs3zzLZLuLQEYX",
    };
    try expectJsonStringify(
        \\{"accounts":["Vote111111111111111111111111111111111111111"],"data":"3Bxs3zzLZLuLQEYX","programId":"11111111111111111111111111111111"}
    , ix);
}

test "ParsedInstruction serialization" {
    var info = std.json.ObjectMap.init(std.testing.allocator);
    defer info.deinit();
    try info.put("lamports", .{ .integer = 5000 });
    try info.put("source", .{ .string = "11111111111111111111111111111111" });

    var parsed = std.json.ObjectMap.init(std.testing.allocator);
    defer parsed.deinit();
    try parsed.put("type", .{ .string = "transfer" });
    try parsed.put("info", .{ .object = info });

    // We need to test serialization through jsonStringify, not the struct directly,
    // since ObjectMap doesn't have standard serialization.
    // Instead, test that a fully constructed ParsedInstruction serializes correctly.
    const pi = parse_instruction.ParsedInstruction{
        .program = "system",
        .program_id = "11111111111111111111111111111111",
        .parsed = .{ .object = parsed },
        .stack_height = null,
    };

    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    var jw = std.json.writeStream(buf.writer(), .{});
    try pi.jsonStringify(&jw);
    // try jw.endDocument();

    // Verify it contains the expected fields
    const output = buf.items;
    try std.testing.expect(std.mem.indexOf(u8, output, "\"parsed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"program\":\"system\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"programId\":\"11111111111111111111111111111111\"") != null);
}

test "UiInnerInstructions serialization" {
    const inner = parse_instruction.UiInnerInstructions{
        .index = 0,
        .instructions = &.{.{ .compiled = .{
            .programIdIndex = 2,
            .accounts = &.{0},
            .data = "3Bxs3zzLZLuLQEYX",
            .stackHeight = 2,
        } }},
    };
    try expectJsonStringify(
        \\{"index":0,"instructions":[{"accounts":[0],"data":"3Bxs3zzLZLuLQEYX","programIdIndex":2,"stackHeight":2}]}
    , inner);
}

test "UiInstruction serialization - compiled variant" {
    const ix = parse_instruction.UiInstruction{
        .compiled = .{
            .programIdIndex = 1,
            .accounts = &.{ 0, 2 },
            .data = "abcd",
        },
    };
    try expectJsonStringify(
        \\{"accounts":[0,2],"data":"abcd","programIdIndex":1}
    , ix);
}

// ============================================================================
// GetBlock request serialization test
// ============================================================================

test "GetBlock request serialization" {
    try testRequest(.getBlock, .{ .slot = 430 },
        \\{"jsonrpc":"2.0","id":1,"method":"getBlock","params":[430]}
    );
}

test "GetBlock request serialization - with config" {
    try testRequest(.getBlock, .{
        .slot = 430,
        .config = .{
            .encoding = .json,
            .transactionDetails = .full,
            .rewards = false,
        },
    },
        \\{"jsonrpc":"2.0","id":1,"method":"getBlock","params":[430,{"commitment":null,"encoding":"json","transactionDetails":"full","maxSupportedTransactionVersion":null,"rewards":false}]}
    );
}

// ============================================================================
// JsonSkippable serialization tests
// ============================================================================

test "JsonSkippable - value state serializes the inner value" {
    const meta = GetBlock.Response.UiTransactionStatusMeta{
        .err = null,
        .status = .{ .Ok = .{}, .Err = null },
        .fee = 0,
        .preBalances = &.{},
        .postBalances = &.{},
        .computeUnitsConsumed = .{ .value = 42 },
    };
    const json = try std.json.stringifyAlloc(std.testing.allocator, meta, .{});
    defer std.testing.allocator.free(json);
    // computeUnitsConsumed should appear with value 42
    try std.testing.expect(std.mem.indexOf(u8, json, "\"computeUnitsConsumed\":42") != null);
}

test "JsonSkippable - skip state omits the field entirely" {
    const meta = GetBlock.Response.UiTransactionStatusMeta{
        .err = null,
        .status = .{ .Ok = .{}, .Err = null },
        .fee = 0,
        .preBalances = &.{},
        .postBalances = &.{},
        .computeUnitsConsumed = .skip,
        .loadedAddresses = .skip,
        .returnData = .skip,
    };
    const json = try std.json.stringifyAlloc(std.testing.allocator, meta, .{});
    defer std.testing.allocator.free(json);
    // These fields should NOT appear in the output
    try std.testing.expect(std.mem.indexOf(u8, json, "computeUnitsConsumed") == null);
    try std.testing.expect(std.mem.indexOf(u8, json, "loadedAddresses") == null);
    try std.testing.expect(std.mem.indexOf(u8, json, "returnData") == null);
}

test "JsonSkippable - none state serializes as null" {
    const meta = GetBlock.Response.UiTransactionStatusMeta{
        .err = null,
        .status = .{ .Ok = .{}, .Err = null },
        .fee = 0,
        .preBalances = &.{},
        .postBalances = &.{},
        .rewards = .none,
    };
    const json = try std.json.stringifyAlloc(std.testing.allocator, meta, .{});
    defer std.testing.allocator.free(json);
    // rewards should appear as null
    try std.testing.expect(std.mem.indexOf(u8, json, "\"rewards\":null") != null);
}

// ============================================================================
// ParsedAccount serialization tests
// ============================================================================

test "ParsedAccount serialization - transaction source" {
    const account = GetBlock.Response.ParsedAccount{
        .pubkey = Pubkey.ZEROES,
        .writable = true,
        .signer = true,
        .source = .transaction,
    };
    try expectJsonStringify(
        \\{"pubkey":"11111111111111111111111111111111","signer":true,"source":"transaction","writable":true}
    , account);
}

test "ParsedAccount serialization - lookupTable source" {
    const account = GetBlock.Response.ParsedAccount{
        .pubkey = Pubkey.ZEROES,
        .writable = false,
        .signer = false,
        .source = .lookupTable,
    };
    try expectJsonStringify(
        \\{"pubkey":"11111111111111111111111111111111","signer":false,"source":"lookupTable","writable":false}
    , account);
}

// ============================================================================
// AddressTableLookup serialization tests (uses writeU8SliceAsIntArray)
// ============================================================================

test "AddressTableLookup serialization - indexes as integer arrays" {
    const atl = GetBlock.Response.AddressTableLookup{
        .accountKey = Pubkey.ZEROES,
        .writableIndexes = &[_]u8{ 0, 1, 4 },
        .readonlyIndexes = &[_]u8{ 2, 3 },
    };
    try expectJsonStringify(
        \\{"accountKey":"11111111111111111111111111111111","readonlyIndexes":[2,3],"writableIndexes":[0,1,4]}
    , atl);
}

test "AddressTableLookup serialization - empty indexes" {
    const atl = GetBlock.Response.AddressTableLookup{
        .accountKey = Pubkey.ZEROES,
        .writableIndexes = &.{},
        .readonlyIndexes = &.{},
    };
    try expectJsonStringify(
        \\{"accountKey":"11111111111111111111111111111111","readonlyIndexes":[],"writableIndexes":[]}
    , atl);
}

// ============================================================================
// EncodedInstruction serialization (accounts as integer array)
// ============================================================================

test "EncodedInstruction serialization - accounts as integer array" {
    // Verifies that accounts field is serialized as [0,1,2] not as a string
    const ix = GetBlock.Response.EncodedInstruction{
        .programIdIndex = 3,
        .accounts = &[_]u8{ 0, 1, 2 },
        .data = "base58data",
    };
    try expectJsonStringify(
        \\{"programIdIndex":3,"accounts":[0,1,2],"data":"base58data"}
    , ix);
}

// ============================================================================
// UiRawMessage serialization tests
// ============================================================================

test "UiRawMessage serialization - without address table lookups" {
    const msg = GetBlock.Response.UiRawMessage{
        .header = .{
            .numRequiredSignatures = 1,
            .numReadonlySignedAccounts = 0,
            .numReadonlyUnsignedAccounts = 1,
        },
        .account_keys = &.{Pubkey.ZEROES},
        .recent_blockhash = Hash.ZEROES,
        .instructions = &.{},
    };
    const json = try std.json.stringifyAlloc(std.testing.allocator, msg, .{});
    defer std.testing.allocator.free(json);
    // Should have accountKeys, header, recentBlockhash, instructions but NOT addressTableLookups
    try std.testing.expect(std.mem.indexOf(u8, json, "\"accountKeys\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"header\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"numRequiredSignatures\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "addressTableLookups") == null);
}

test "UiRawMessage serialization - with address table lookups" {
    const atl = GetBlock.Response.AddressTableLookup{
        .accountKey = Pubkey.ZEROES,
        .writableIndexes = &[_]u8{0},
        .readonlyIndexes = &.{},
    };
    const msg = GetBlock.Response.UiRawMessage{
        .header = .{
            .numRequiredSignatures = 1,
            .numReadonlySignedAccounts = 0,
            .numReadonlyUnsignedAccounts = 0,
        },
        .account_keys = &.{},
        .recent_blockhash = Hash.ZEROES,
        .instructions = &.{},
        .address_table_lookups = &.{atl},
    };
    const json = try std.json.stringifyAlloc(std.testing.allocator, msg, .{});
    defer std.testing.allocator.free(json);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"addressTableLookups\"") != null);
}

// ============================================================================
// UiParsedMessage serialization tests
// ============================================================================

test "UiParsedMessage serialization - without address table lookups" {
    const msg = GetBlock.Response.UiParsedMessage{
        .account_keys = &.{},
        .recent_blockhash = Hash.ZEROES,
        .instructions = &.{},
    };
    const json = try std.json.stringifyAlloc(std.testing.allocator, msg, .{});
    defer std.testing.allocator.free(json);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"accountKeys\":[]") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"recentBlockhash\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "addressTableLookups") == null);
}

// ============================================================================
// UiMessage serialization tests
// ============================================================================

test "UiMessage serialization - raw variant" {
    const msg = GetBlock.Response.UiMessage{ .raw = .{
        .header = .{
            .numRequiredSignatures = 2,
            .numReadonlySignedAccounts = 0,
            .numReadonlyUnsignedAccounts = 1,
        },
        .account_keys = &.{},
        .recent_blockhash = Hash.ZEROES,
        .instructions = &.{},
    } };
    const json = try std.json.stringifyAlloc(std.testing.allocator, msg, .{});
    defer std.testing.allocator.free(json);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"numRequiredSignatures\":2") != null);
}

// ============================================================================
// EncodedTransaction.accounts serialization test
// ============================================================================

test "EncodedTransaction serialization - accounts variant" {
    const account = GetBlock.Response.ParsedAccount{
        .pubkey = Pubkey.ZEROES,
        .writable = true,
        .signer = true,
        .source = .transaction,
    };
    const tx = GetBlock.Response.EncodedTransaction{ .accounts = .{
        .signatures = &.{},
        .accountKeys = &.{account},
    } };
    const json = try std.json.stringifyAlloc(std.testing.allocator, tx, .{});
    defer std.testing.allocator.free(json);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"accountKeys\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"source\":\"transaction\"") != null);
}

// ============================================================================
// UiTransactionStatusMeta serialization - skipped fields
// ============================================================================

test "UiTransactionStatusMeta serialization - innerInstructions and logMessages skipped" {
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
    const json = try std.json.stringifyAlloc(std.testing.allocator, meta, .{});
    defer std.testing.allocator.free(json);
    // innerInstructions, logMessages, and rewards should all be omitted
    try std.testing.expect(std.mem.indexOf(u8, json, "innerInstructions") == null);
    try std.testing.expect(std.mem.indexOf(u8, json, "logMessages") == null);
    try std.testing.expect(std.mem.indexOf(u8, json, "rewards") == null);
    // But err, fee, balances, status should still be present
    try std.testing.expect(std.mem.indexOf(u8, json, "\"err\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"fee\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"status\"") != null);
}

test "UiTransactionStatusMeta serialization - costUnits present" {
    const meta = GetBlock.Response.UiTransactionStatusMeta{
        .err = null,
        .status = .{ .Ok = .{}, .Err = null },
        .fee = 0,
        .preBalances = &.{},
        .postBalances = &.{},
        .costUnits = .{ .value = 3428 },
    };
    const json = try std.json.stringifyAlloc(std.testing.allocator, meta, .{});
    defer std.testing.allocator.free(json);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"costUnits\":3428") != null);
}

test "UiTransactionStatusMeta serialization - returnData present" {
    const meta = GetBlock.Response.UiTransactionStatusMeta{
        .err = null,
        .status = .{ .Ok = .{}, .Err = null },
        .fee = 0,
        .preBalances = &.{},
        .postBalances = &.{},
        .returnData = .{ .value = .{
            .programId = Pubkey.ZEROES,
            .data = .{ "AQID", .base64 },
        } },
    };
    const json = try std.json.stringifyAlloc(std.testing.allocator, meta, .{});
    defer std.testing.allocator.free(json);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"returnData\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"programId\"") != null);
}

// ============================================================================
// UiTransactionStatusMeta.from() tests
// ============================================================================

test "UiTransactionStatusMeta.from - always includes loadedAddresses" {
    const allocator = std.testing.allocator;
    const meta = sig.ledger.transaction_status.TransactionStatusMeta.EMPTY_FOR_TEST;
    const result = try GetBlock.Response.UiTransactionStatusMeta.from(
        allocator,
        meta,
        true,
    );
    defer {
        allocator.free(result.preBalances);
        allocator.free(result.postBalances);
        if (result.loadedAddresses == .value) {
            allocator.free(result.loadedAddresses.value.writable);
            allocator.free(result.loadedAddresses.value.readonly);
        }
    }
    // loadedAddresses should always have a value
    try std.testing.expect(result.loadedAddresses == .value);
}

test "UiTransactionStatusMeta.from - show_rewards false skips rewards" {
    const allocator = std.testing.allocator;
    const meta = sig.ledger.transaction_status.TransactionStatusMeta.EMPTY_FOR_TEST;
    const result = try GetBlock.Response.UiTransactionStatusMeta.from(
        allocator,
        meta,
        false,
    );
    defer {
        allocator.free(result.preBalances);
        allocator.free(result.postBalances);
    }
    // Rewards should be .none (serialized as null) when show_rewards is false
    try std.testing.expect(result.rewards == .none);
}

test "UiTransactionStatusMeta.from - show_rewards true includes rewards" {
    const allocator = std.testing.allocator;
    const meta = sig.ledger.transaction_status.TransactionStatusMeta.EMPTY_FOR_TEST;
    const result = try GetBlock.Response.UiTransactionStatusMeta.from(
        allocator,
        meta,
        true,
    );
    defer {
        allocator.free(result.preBalances);
        allocator.free(result.postBalances);
    }
    // Rewards should be present (as value) when show_rewards is true
    try std.testing.expect(result.rewards != .skip);
}

test "UiTransactionStatusMeta.from - compute_units_consumed present" {
    const allocator = std.testing.allocator;
    var meta = sig.ledger.transaction_status.TransactionStatusMeta.EMPTY_FOR_TEST;
    meta.compute_units_consumed = 42_000;
    const result = try GetBlock.Response.UiTransactionStatusMeta.from(
        allocator,
        meta,
        false,
    );
    defer {
        allocator.free(result.preBalances);
        allocator.free(result.postBalances);
    }
    try std.testing.expect(result.computeUnitsConsumed == .value);
    try std.testing.expectEqual(@as(u64, 42_000), result.computeUnitsConsumed.value);
}

test "UiTransactionStatusMeta.from - compute_units_consumed absent" {
    const allocator = std.testing.allocator;
    const meta = sig.ledger.transaction_status.TransactionStatusMeta.EMPTY_FOR_TEST;
    const result = try GetBlock.Response.UiTransactionStatusMeta.from(
        allocator,
        meta,
        false,
    );
    defer {
        allocator.free(result.preBalances);
        allocator.free(result.postBalances);
    }
    try std.testing.expect(result.computeUnitsConsumed == .skip);
}
