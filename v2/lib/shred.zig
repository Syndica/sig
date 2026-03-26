const std = @import("std");
const solana = @import("solana.zig");
const ipc = @import("ipc.zig");

pub const reed_solomon_table = @import("shred/reed_solomon_table.zig");

const Hash = solana.Hash;
const Slot = solana.Slot;
const LeaderSchedule = solana.LeaderSchedule;

pub const RecvConfig = extern struct {
    leader_schedule: LeaderSchedule,
    shred_version: u16,
};

pub const DeshredRing = ipc.Ring(256, DeshreddedFecSet);

pub const FecSetId = extern struct {
    slot: Slot,
    fec_set_idx: u32,

    pub fn eql(a: *const FecSetId, b: *const FecSetId) bool {
        return (a.slot == b.slot and a.fec_set_idx == b.fec_set_idx);
    }

    pub fn compare(a: *const FecSetId, b: *const FecSetId) std.math.Order {
        if (a.slot > b.slot) return .gt;
        if (a.slot < b.slot) return .lt;
        if (a.fec_set_idx > b.fec_set_idx) return .gt;
        if (a.fec_set_idx < b.fec_set_idx) return .lt;
        std.debug.assert(a.slot == b.slot);
        std.debug.assert(a.fec_set_idx == b.fec_set_idx);
        return .eq;
    }
};

// TODO: this should be sent as a notification/header, with the payload sent separately.
// Currently this copies a lot.
pub const DeshreddedFecSet = extern struct {
    merkle_root: Hash,
    chained_merkle_root: Hash,
    id: FecSetId,
    data_complete: bool,
    slot_complete: bool,
    payload_len: u16,

    // TODO: this should be sent separately, ideally in a mem pool.
    payload_buf: [32 * Shred.data_payload_max]u8,

    fn payload(self: *const DeshreddedFecSet) []const u8 {
        return self.payload_buf[0..self.payload_len];
    }
};

pub const Shred = struct {
    const data_payload_max = 11918;
};
