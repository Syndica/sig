//! Must be replaced - cannot handle epoch transitions at all

const common = @import("../../common.zig");

const std = @import("std");

const Slot = common.solana.Slot;
const Pubkey = common.solana.Pubkey;

const slots_per_epoch = 432000;

pub const LeaderSchedule = extern struct {
    base_slot: Slot,
    leaders: [slots_per_epoch]Pubkey,

    pub fn get(self: *const LeaderSchedule, slot: Slot) ?Pubkey {
        if (slot < self.base_slot) return null;

        const idx = slot - self.base_slot;
        if (idx >= slots_per_epoch) return null;

        return self.leaders[idx];
    }

    /// Reads the leader schedule as formatted by the `solana leader-schedule` and
    /// `sig leader-schedule` commands. Return the start slot and the leader schedule.
    pub fn fromCommand(schedule: *LeaderSchedule, reader: *std.io.Reader) !void {
        const nextNonEmpty = struct {
            pub fn nextNonEmpty(word_iter: anytype) ?[]const u8 {
                while (word_iter.next()) |word| if (word.len > 0) return word;
                return null;
            }
        }.nextNonEmpty;

        var start_slot: Slot = 0;
        var expect: ?Slot = null;

        var i: usize = 0;
        while (true) {
            const line = l: {
                const line = reader.takeDelimiterInclusive('\n') catch |e| switch (e) {
                    error.EndOfStream => break,
                    else => return e,
                };
                break :l std.mem.trim(u8, line, "\n");
            };

            var word_iter = std.mem.splitScalar(u8, line, ' ');
            const slot = try std.fmt.parseInt(Slot, nextNonEmpty(&word_iter) orelse continue, 10);

            if (expect) |*exp_slot| {
                if (slot != exp_slot.*) {
                    return error.Discontinuity;
                }
                exp_slot.* += 1;
            } else {
                expect = slot + 1;
                start_slot = slot;
            }
            const node_str = nextNonEmpty(&word_iter) orelse return error.MissingPubkey;
            const node_pk = try Pubkey.parseRuntime(node_str);
            schedule.leaders[i] = node_pk;
            i += 1;
        }

        schedule.base_slot = start_slot;
    }
};
