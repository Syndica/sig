const std = @import("std");
const sig = @import("../sig.zig");

const Client = sig.rpc.Client;
const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;

test "getAccountInfo: null value" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    // random pubkey that should not exist
    const pubkey = try Pubkey.fromString("Bkd9xbHF7JgwXmEib6uU3y582WaPWWiasPxzMesiBwWn");
    const response = try client.getAccountInfo(allocator, pubkey, .{});
    defer response.deinit();
    const x = try response.result();

    try std.testing.expectEqual(null, x.value);
}

test "getAccountInfo" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    const pubkey = try Pubkey.fromString("Bkd9xbHF7JgwXmEib6uU3y582WaPWWiasPxzMesiBwWm");
    const response = try client.getAccountInfo(allocator, pubkey, .{});
    defer response.deinit();
    _ = try response.result();
}

test "getBalance" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    const pubkey = try Pubkey.fromString("Bkd9xbHF7JgwXmEib6uU3y582WaPWWiasPxzMesiBwWm");
    const response = try client.getBalance(allocator, pubkey, .{});
    defer response.deinit();
    _ = try response.result();
}

test "getBlockHeight" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    const response = try client.getBlockHeight(allocator, .{});
    defer response.deinit();
    _ = try response.result();
}

test "getBlockCommitment" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    const slot_response = try client.getSlot(allocator, .{ .commitment = .finalized });
    defer slot_response.deinit();
    const response = try client.getBlockCommitment(allocator, slot_response.parsed.result.?);
    defer response.deinit();
    _ = try response.result();
}

test "getEpochInfo" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    const response = try client.getEpochInfo(allocator, .{});
    defer response.deinit();
    _ = try response.result();
}

test "getEpochSchedule" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    const response = try client.getEpochSchedule(allocator);
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
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    const response = try client.getLatestBlockhash(allocator, .{});
    defer response.deinit();
    _ = try response.result();
}

test "getLeaderSchedule" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    const response = try client.getLeaderSchedule(allocator, null, .{});
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
    const response = try client.getSignatureStatuses(allocator, signatures, .{});
    defer response.deinit();
    _ = try response.result();
}

// TODO: test getSignaturesForAddress()

test "getSlot" {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    const response = try client.getSlot(allocator, .{});
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
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .Testnet, .{});
    defer client.deinit();
    const response = try client.getVersion(allocator);
    defer response.deinit();
    _ = try response.result();
}
