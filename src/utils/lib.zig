pub const ahash = @import("ahash.zig");
pub const allocators = @import("allocators.zig");
pub const base64 = @import("base64.zig");
pub const bitflags = @import("bitflags.zig");
pub const bounded_array = @import("bounded_array.zig");
pub const BoundedArray = bounded_array.BoundedArray;
pub const collections = @import("collections.zig");
pub const deduper = @import("deduper.zig");
// TODO: 0.16, remove this in favour of the copy in stdlib
pub const Deque = @import("deque.zig").Deque;
pub const interface = @import("interface.zig");
pub const io = @import("io.zig");
pub const lru = @import("lru.zig");
pub const merkle_tree = @import("merkle_tree.zig");
pub const service_manager = @import("service.zig");
pub const tar = @import("tar.zig");
pub const thread = @import("thread.zig");
pub const types = @import("types.zig");

const std = @import("std");

/// A smaller help function for writing longer single-line format messages.
///
/// Converts all new-lines found in the string to spaces.
pub inline fn newLinesToSpaces(comptime input: []const u8) []const u8 {
    comptime {
        var array = input[0..input.len].*;
        std.mem.replaceScalar(u8, &array, '\n', ' ');
        const copy = array;
        return &copy;
    }
}
