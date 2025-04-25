//! Dependencies of replay that, in agave, would be defined as part of a
//! different component, but in sig, they were not yet implemented. So they were
//! added here with the minimal amount of necessary functionality to support
//! replay.

const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;

const Hash = sig.core.Hash;
const Slot = sig.core.Slot;

pub const tower_storage = struct {
    pub fn load() !?Tower {
        return Tower.init();
    }
};

pub const Tower = struct {
    pub fn init() Tower {
        return .{};
    }
};

pub const BankForks = struct {
    banks: std.AutoHashMapUnmanaged(Slot, Bank) = .{},

    pub fn activeBankSlots(
        self: *const BankForks,
        allocator: Allocator,
    ) Allocator.Error![]const Slot {
        var list = std.ArrayListUnmanaged(Slot){};
        var iter = self.banks.iterator();
        while (iter.next()) |entry| {
            if (!entry.value_ptr.isFrozen()) {
                try list.append(allocator, entry.key_ptr.*);
            }
        }
        return try list.toOwnedSlice(allocator);
    }
};

pub const Bank = struct {
    hash: Hash,
    slot: Slot,
    parent_slot: Slot,
    tick_height: std.atomic.Value(u64),
    max_tick_height: u64,
    hashes_per_tick: ?u64,

    pub fn isFrozen(self: *const Bank) bool {
        return !self.hash.eql(Hash.ZEROES);
    }

    pub fn tickHeight(self: *const Bank) u64 {
        return self.tick_height.load(.monotonic);
    }
};

pub const ProgressMap = struct {
    map: std.AutoHashMapUnmanaged(Slot, ForkProgress),
};

pub const ForkProgress = struct {
    is_dead: bool,
};
