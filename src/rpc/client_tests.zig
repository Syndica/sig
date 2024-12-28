const std = @import("std");
const base58 = @import("base58-zig");
const sig = @import("../sig.zig");
const rpc = @import("lib.zig");

const types = rpc.types;
const methods = rpc.methods;

const Allocator = std.mem.Allocator;

const ClusterType = sig.accounts_db.genesis_config.ClusterType;
const Response = rpc.response.Response;
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

const Client = rpc.Client;

test "getAccountInfo: null value" {
    // if (true) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var client = try Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    // random pubkey that should not exist
    const pubkey = try Pubkey.fromString("Bkd9xbHF7JgwXmEib6uU3y582WaPWWiasPxzMesiBwWn");
    const response = try client.fetch(GetAccountInfo{ .pubkey = pubkey });
    defer response.deinit();
    const x = try response.result();

    try std.testing.expectEqual(null, x.value);
}

test "getAccountInfo" {
    // if (true) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var client = try Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    const pubkey = try Pubkey.fromString("Bkd9xbHF7JgwXmEib6uU3y582WaPWWiasPxzMesiBwWm");
    const response = try client.fetch(GetAccountInfo{ .pubkey = pubkey });
    defer response.deinit();
    _ = try response.result();
}

test "getBalance" {
    // if (true) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var client = try Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    const pubkey = try Pubkey.fromString("Bkd9xbHF7JgwXmEib6uU3y582WaPWWiasPxzMesiBwWm");
    const response = try client.fetch(GetBalance{ .pubkey = pubkey });
    defer response.deinit();
    _ = try response.result();
}

test "getBlockHeight" {
    // if (true) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var client = try Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    const response = try client.fetch(GetBlockHeight{});
    defer response.deinit();
    _ = try response.result();
}

test "getBlockCommitment" {
    // if (true) return error.SkipZigTest;
    var gpa = std.heap.GeneralPurposeAllocator(.{ .stack_trace_frames = 100 }){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var client = try Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    const slot_response = try client.fetch(GetSlot{});
    defer slot_response.deinit();
    const response = try client.fetch(GetBlockCommitment{ .slot = try slot_response.result() });
    defer response.deinit();
    _ = try response.result();
}

test "getEpochInfo" {
    // if (true) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var client = try Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    const response = try client.fetch(GetEpochInfo{});
    defer response.deinit();
    _ = try response.result();
}

test "getEpochSchedule" {
    // if (true) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var client = try Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    const response = try client.fetch(GetEpochSchedule{});
    defer response.deinit();
    _ = try response.result();
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

test "getLatestBlockhash" {
    // if (true) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var client = try Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    const response = try client.fetch(GetLatestBlockhash{});
    defer response.deinit();
    _ = try response.result();
}

test "getLeaderSchedule" {
    // if (true) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var client = try Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    const response = try client.fetch(GetLeaderSchedule{});
    defer response.deinit();
    _ = try response.result();
}

// TODO: test getMaxRetransmitSlot()
// TODO: test getMaxShredInsertSlot()
// TODO: test getMinimumBalanceForRentExemption()
// TODO: test getMultipleAccounts()
// TODO: test getProgramAccounts()
// TODO: test getRecentPerformanceSamples()
// TODO: test getRecentPrioritizationFees()

test "getSignatureStatuses" {
    // if (true) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var client = try Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    var signatures = try allocator.alloc(Signature, 2);
    defer allocator.free(signatures);
    signatures[0] = try Signature.fromString(
        "56H13bd79hzZa67gMACJYsKxb5MdfqHhe3ceEKHuBEa7hgjMgAA4Daivx68gBFUa92pxMnhCunngcP3dpVnvczGp",
    );
    signatures[1] = try Signature.fromString(
        "4K6Gjut37p3ajRtsN2s6q1Miywit8VyP7bAYLfVSkripdNJkF3bL6BWG7dauzZGMr3jfsuFaPR91k2NuuCc7EqAz",
    );
    const response = try client.fetch(GetSignatureStatuses{ .signatures = signatures });
    defer response.deinit();
    _ = try response.result();
}

// TODO: test getSignaturesForAddress()

test "getSlot" {
    // if (true) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var client = try Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    const response = try client.fetch(GetSlot{});
    defer response.deinit();
    _ = try response.result();
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

test "getVersion" {
    // if (true) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var client = try Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    const response = try client.fetch(GetVersion{});
    defer response.deinit();
    _ = try response.result();
}
