pub const std = @import("std");
pub const sig = @import("../sig.zig");

pub const Entry = sig.core.entry.Entry;
pub const test_entry = sig.core.entry.test_entry;

pub const BenchmarkEntry = struct {
    pub const min_iterations = 200_000;
    pub const max_iterations = 200_000;

    pub fn serializeEntry() !sig.time.Duration {
        const allocator = std.heap.c_allocator;

        var timer = try sig.time.Timer.start();
        const actual_bytes = try sig.bincode.writeAlloc(allocator, test_entry.as_struct, .{});
        defer allocator.free(actual_bytes);
        return timer.read();
    }

    pub fn deserializeEntry() !sig.time.Duration {
        const allocator = std.heap.c_allocator;

        var timer = try sig.time.Timer.start();
        const actual_struct = try sig.bincode.readFromSlice(
            allocator,
            Entry,
            &test_entry.bincode_serialized_bytes,
            .{},
        );
        defer actual_struct.deinit(allocator);
        return timer.read();
    }
};
