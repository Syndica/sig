const std = @import("std");
const sig = @import("../../sig.zig");

const ArrayMap = std.AutoArrayHashMapUnmanaged;

const Epoch = sig.core.Epoch;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;

const RwMux = sig.sync.RwMux;

pub const AccountsDB = struct {};

const UnrootedDB = struct {
    /// tells you which slot to look for an account
    index: ArrayMap(Pubkey, RwMux(RingBitSet)),
    accounts: ArrayMap(Slot, ArrayMap(Pubkey, Account)),
};

const RootedDB = struct {};

pub const Account = struct {};

const AccountMetadata = struct {
    lamports: u64,
    owner: Pubkey,
    executable: bool,
    rent_epoch: Epoch,
};

/// A bit set that is allowed to progress forwards by setting bits out of bounds
/// and deleting old values, but not allowed to regress backwards.
pub const RingBitSet = struct {
    /// underlying bitset
    slots: std.bit_set.StaticBitSet(len),
    /// The lowest value represented
    bottom: usize,
    /// The highest value that has been set
    last_set: usize,

    const len = 128;

    pub fn mark(self: *RingBitSet, index: usize) error{Underflow}!void {
        if (index < self.bottom) return error.Underflow;
        if (index - self.bottom > len) {
            // update the start slot
            self.start_slot = index - len + self.bottom;
            // delete stale values (set all to false)
            const wipe_start = self.bottom;
            const wipe_end = self.start_slot;
            if (wipe_start % len > wipe_end % len) {
                self.setRangeValue(.{ .start = wipe_start % len, .end = len }, false);
                self.setRangeValue(.{ .start = 0, .end = wipe_end % len }, false);
            } else {
                self.setRangeValue(.{ .start = wipe_start % len, .end = wipe_end % len }, false);
            }
        }
        self.last_set = index;
        self.slots.set(index % len);
    }

    pub fn reverseIterator(self: *const RingBitSet) void {
        return .{
            .marker = self,
            .start = self.last_set,
            .cursor = self.bottom,
        };
    }

    pub const ReverseIterator = struct {
        marker: *const RingBitSet,
        cursor: usize,

        pub fn next(self: *ReverseIterator) ?usize {
            while (self.cursor >= self.marker.bottom) {
                defer self.cursor -= 1;
                if (self.marker.slots.isSet(self.cursor % len)) {
                    return self.cursor;
                }
            }
            return null;
        }
    };
};
