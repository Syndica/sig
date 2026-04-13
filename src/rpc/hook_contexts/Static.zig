//! The Static RPC hook context. These methods serve fixed values that are determined at startup and remain constant (e.g. genesis hash).

const std = @import("std");
const sig = @import("../../sig.zig");

const GetGenesisHash = sig.rpc.methods.GetGenesisHash;

const StaticHookContext = @This();

genesis_hash: sig.core.Hash,
identity: sig.core.Pubkey,

pub fn getGenesisHash(
    self: StaticHookContext,
    _: std.mem.Allocator,
    _: GetGenesisHash,
) !GetGenesisHash.Response {
    return .{ .hash = self.genesis_hash };
}

pub fn getIdentity(
    self: StaticHookContext,
    _: std.mem.Allocator,
    _: sig.rpc.methods.GetIdentity,
) !sig.rpc.methods.GetIdentity.Response {
    return .{ .identity = self.identity };
}

pub fn getVersion(
    _: StaticHookContext,
    _: std.mem.Allocator,
    _: sig.rpc.methods.GetVersion,
) !sig.rpc.methods.GetVersion.Response {
    return .{
        .solana_core = sig.version.ClientVersion.API_VERSION,
        .feature_set = sig.version.ClientVersion.CURRENT.feature_set,
    };
}
