const std = @import("std");
const lib = @import("../lib.zig");
const testing = std.testing;

const Slot = lib.solana.Slot;

const BlockPool = lib.replay.BlockPool;
const BlockRef = lib.replay.BlockRef;

const finalization_depth: Slot = 32;

pub fn consensus_tests(SimpleConsensus: type) type {
    _ = SimpleConsensus; // autofix
    return struct {};
}
