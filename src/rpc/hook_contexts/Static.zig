//! The Static RPC hook context. These methods serve fixed values that are determined at startup and remain constant (e.g. genesis hash).

const std = @import("std");
const sig = @import("../../sig.zig");

const EpochSchedule = sig.core.EpochSchedule;
const GetEpochSchedule = sig.rpc.methods.GetEpochSchedule;
const GetGenesisHash = sig.rpc.methods.GetGenesisHash;

const StaticHookContext = @This();

genesis_hash: sig.core.Hash,
identity: sig.core.Pubkey,
epoch_schedule: *const EpochSchedule,

/// Returns the epoch schedule information from this cluster's genesis config.
/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L911-L916
/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L3023-L3026
pub fn getEpochSchedule(
    self: StaticHookContext,
    _: std.mem.Allocator,
    _: GetEpochSchedule,
) !GetEpochSchedule.Response {
    return .{
        .slotsPerEpoch = self.epoch_schedule.slots_per_epoch,
        .leaderScheduleSlotOffset = self.epoch_schedule.leader_schedule_slot_offset,
        .warmup = self.epoch_schedule.warmup,
        .firstNormalEpoch = self.epoch_schedule.first_normal_epoch,
        .firstNormalSlot = self.epoch_schedule.first_normal_slot,
    };
}

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
