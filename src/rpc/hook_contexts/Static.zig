//! The Static RPC hook context. These methods serve fixed values that are determined at startup and remain constant (e.g. genesis hash).

const std = @import("std");
const sig = @import("../../sig.zig");

const GetGenesisHash = sig.rpc.methods.GetGenesisHash;

const StaticHookContext = @This();

genesis_hash: sig.core.Hash,

pub fn getGenesisHash(
    self: *const StaticHookContext,
    _: std.mem.Allocator,
    _: GetGenesisHash,
) !GetGenesisHash.Response {
    return .{ .hash = self.genesis_hash };
}
