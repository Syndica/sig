//! Must be replaced - cannot handle epoch transitions at all

const common = @import("../../common.zig");

const std = @import("std");

const Slot = common.solana.Slot;
const Pubkey = common.solana.Pubkey;

const slots_per_epoch = 432000;

pub const LeaderSchedule = extern struct {
    base_slot: Slot,
    leaders: [slots_per_epoch]Pubkey,

    pub fn get(self: *const LeaderSchedule, slot: Slot) ?*const Pubkey {
        if (slot < self.base_slot) return null;

        const idx = slot - self.base_slot;
        if (idx >= slots_per_epoch) return null;

        return &self.leaders[idx];
    }

    /// Reads the leader schedule as formatted by the `solana leader-schedule` and
    /// `sig leader-schedule` commands. Return the start slot and the leader schedule.
    pub fn fromCommand(schedule: *LeaderSchedule, reader: *std.Io.Reader) !void {
        const slot_max_len = comptime std.fmt.count("{d}", .{std.math.maxInt(Slot)});
        const hash_max_len = 44;
        std.debug.assert(reader.buffer.len >= @max(slot_max_len, hash_max_len));

        var start_slot: ?Slot = null;
        var i: u32 = 0;

        while (true) : (i += 1) {
            try skipSpaces(reader);

            const slot_str = reader.takeDelimiterExclusive(' ') catch |err| switch (err) {
                error.ReadFailed => |e| return e,
                error.EndOfStream => break,
                error.StreamTooLong => return error.InvalidSlot,
            };
            if (std.mem.indexOfScalar(u8, slot_str, '\n') != null) break;

            const slot = std.fmt.parseInt(Slot, slot_str, 10) catch return error.InvalidSlot;

            if (start_slot) |start| {
                if (slot != start + i) return error.Discontinuity;
            } else {
                start_slot = slot;
            }

            try skipSpaces(reader);

            const node_str = reader.takeDelimiterExclusive('\n') catch |err| switch (err) {
                error.ReadFailed => |e| return e,
                error.EndOfStream => break,
                error.StreamTooLong => return error.InvalidPubkey,
            };
            const node_pk = Pubkey.parseRuntime(std.mem.trim(u8, node_str, " ")) catch
                return error.InvalidPubkey;

            schedule.leaders[i] = node_pk;

            if (reader.buffer.len == 0) break; // no '\n' delimiter means end of stream.
            reader.toss(1);
        }

        if (i != slots_per_epoch) return error.IncorrectNumberOfSlots;
        schedule.base_slot = start_slot.?;
    }

    fn skipSpaces(r: *std.Io.Reader) error{ReadFailed}!void {
        while (true) {
            const byte = r.peekByte() catch |err| switch (err) {
                error.EndOfStream => return,
                error.ReadFailed => |e| return e,
            };

            if (byte != ' ') break;
            r.seek += 1;
        }
    }
};
