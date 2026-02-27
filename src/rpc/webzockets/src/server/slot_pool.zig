const std = @import("std");

/// Wrapper around MemoryPool that ensures reset() is called before returning to pool.
/// Optionally enforces a maximum number of active slots (independent of preheat count).
pub fn SlotPool(comptime Slot: type) type {
    return struct {
        inner: std.heap.MemoryPool(Slot),
        /// Number of slots currently checked out (not in pool).
        active_count: usize,
        /// Upper bound on active_count; null means unlimited.
        max_size: ?usize,

        const SlotPoolSelf = @This();

        pub fn init(allocator: std.mem.Allocator, max_size: ?usize) SlotPoolSelf {
            return .{
                .inner = std.heap.MemoryPool(Slot).init(allocator),
                .active_count = 0,
                .max_size = max_size,
            };
        }

        pub fn deinit(self: *SlotPoolSelf) void {
            self.inner.deinit();
        }

        pub fn preheat(self: *SlotPoolSelf, count: usize) !void {
            try self.inner.preheat(count);
        }

        pub fn create(self: *SlotPoolSelf) !*Slot {
            if (self.max_size) |max| {
                if (self.active_count >= max) {
                    return error.PoolExhausted;
                }
            }
            const slot = try self.inner.create();
            self.active_count += 1;
            return slot;
        }

        /// Release a slot back to the pool, calling reset() first to clean up state.
        pub fn release(self: *SlotPoolSelf, slot: *Slot) void {
            slot.reset();
            self.inner.destroy(slot);
            self.active_count -= 1;
        }
    };
}
