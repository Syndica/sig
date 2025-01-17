pub const std = @import("std");
pub const sig = @import("../sig.zig");

const CheckedReader = sig.utils.io.CheckedReader;
const Entry = sig.core.entry.Entry;
const test_entry = sig.core.entry.test_entry;

pub const BenchmarkEntry = struct {
    pub const min_iterations = 200_000;
    pub const max_iterations = 200_000;

    pub fn serializeEntry() !sig.time.Duration {
        const allocator = std.heap.c_allocator;
        var timer = try sig.time.Timer.start();
        const actual_buffer = try allocator.alloc(u8, test_entry.as_bytes.len);
        defer allocator.free(actual_buffer);
        var actual_fbs = std.io.fixedBufferStream(actual_buffer);
        try test_entry.as_struct.serialize(actual_fbs.writer());
        return timer.read();
    }

    pub fn deserializeEntry() !sig.time.Duration {
        const allocator = std.heap.c_allocator;
        var timer = try sig.time.Timer.start();
        var actual_reader = CheckedReader.init(&test_entry.as_bytes);
        const actual_struct = try Entry.deserialize(allocator, &actual_reader);
        defer actual_struct.deinit(allocator);
        return timer.read();
    }
};
