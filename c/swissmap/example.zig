const std = @import("std");
const Atomic = std.atomic.Atomic;
const json = std.json;
var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const gpa_allocator = gpa.allocator();
const c = @cImport({
    @cInclude("hashmap.h");
});

pub fn main() !void {
    var map = c.hm_new_managed(2);

    // we allocate with std.c.malloc allocator as hm_map_t uses free on values
    var key = @as([*]u8, @ptrCast(std.c.malloc(6) orelse unreachable));
    defer std.c.free(key);
    @memcpy(key, "hello");

    var value = @as([*]u8, @ptrCast(std.c.malloc(6) orelse unreachable));
    defer std.c.free(value);
    @memcpy(value, "there");

    var null_str = [_]u8{ 'n', 'u', 'l', 'l', 0 };
    var null_str_c: [*]u8 = &null_str;

    // insert values
    c.hm_insert(&map, key, value);
    std.debug.print("inserted key = {s} \n", .{key[0..6]});

    // find values, cast into specific type if needed
    var matched_idx: usize = 0;
    var val = c.hm_find(map, key, &matched_idx);
    std.debug.print("found key at index = {any}, val = {s}\n", .{ matched_idx, if (val) |v| v else null_str_c });

    var buff = [_]u8{0} ** 24;
    var matched_key: [*c]u8 = @as([*c]u8, buff[0..]);

    // remove values
    var val_removed = c.hm_remove(map, key, &matched_key);
    std.debug.print("removed key with value = {s} \n", .{@as([*:0]u8, val_removed)});
}
