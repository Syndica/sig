const std = @import("std");
const Hash = @import("../core/hash.zig").Hash;
const Sha256 = std.crypto.hash.sha2.Sha256;
const ArrayList = std.ArrayList;
const bs58 = @import("base58-zig");
pub const LEAF_PREFIX: []const u8 = &.{0};

pub const INTERMEDIATE_PREFIX: []const u8 = &.{1};

pub fn hash_leaf(digest: []const u8) Hash {
    const data = [_][]const u8{ LEAF_PREFIX, digest };

    return hashv(&data);
}

pub fn hash_intermediate(left: []const u8, right: []const u8) Hash {
    return hashv(&.{ INTERMEDIATE_PREFIX, left, right });
}

pub fn hashv(vals: []const []const u8) Hash {
    var h = Sha256.init(.{});
    for (vals) |val| h.update(val);
    var hash: [32]u8 = undefined;
    h.final(&hash);
    return Hash{ .data = hash };
}

pub const MerkleTree = struct {
    leaf_count: usize,
    nodes: ArrayList(Hash),

    const Self = @This();

    pub fn new(alloc: std.mem.Allocator, items: []const []const u8) !Self {
        const capacity = Self.calculate_list_capacity(items.len);
        var mt = Self{ .leaf_count = items.len, .nodes = try ArrayList(Hash).initCapacity(alloc, capacity) };
        for (items) |item| {
            const hash = hash_leaf(item);
            mt.nodes.appendAssumeCapacity(hash);
        }
        var level_len = Self.next_level_len(items.len);
        var level_start = items.len;
        var prev_level_len = items.len;
        var prev_level_start: usize = 0;
        while (level_len > 0) {
            for (0..level_len) |index| {
                const prev_level_idx = 2 * index;
                const lsib = mt.nodes.items[prev_level_start + prev_level_idx];
                var rsib: Hash = undefined;
                if (prev_level_idx + 1 < prev_level_len) {
                    rsib = mt.nodes.items[prev_level_start + prev_level_idx + 1];
                } else {
                    rsib = mt.nodes.items[prev_level_start + prev_level_idx];
                }

                const hash = hash_intermediate(&lsib.data, &rsib.data);
                mt.nodes.appendAssumeCapacity(hash);
            }

            prev_level_start = level_start;
            prev_level_len = level_len;
            level_start += level_len;
            level_len = Self.next_level_len(level_len);
        }
        return mt;
    }

    pub fn get_root(self: *Self) ?Hash {
        return self.nodes.getLastOrNull();
    }

    pub fn calculate_list_capacity(leaf_count: usize) usize {
        @setFloatMode(.Optimized);
        if (leaf_count > 0) {
            const float_lc: f64 = @floatFromInt(leaf_count);
            const log_lc: usize = @intFromFloat(@log2(float_lc));
            return log_lc + 2 * leaf_count + 1;
        } else {
            return 0;
        }
    }

    pub fn next_level_len(level_len: usize) usize {
        if (level_len == 1) {
            return 0;
        } else {
            return (level_len + 1) / 2;
        }
    }
    pub fn deinit(self: *const Self) void {
        self.nodes.deinit();
    }
};

test "merkle-tree.hash_leaf: Hash a valid leaf" {
    const leaf = "Lorem Ipsum Dolor";
    var hashed_leaf = hash_leaf(leaf);
    std.debug.print("hashed_leaf: {}\n", .{hashed_leaf});
}

test "merkle-tree.hash_intermediate: Hash a valid intermediate node" {
    const l1 = "This is the first leaf.";
    const l2 = "This is the second leaf.";
    var hl1 = hash_leaf(l1);
    var hl2 = hash_leaf(l2);
    var inter_node = hash_intermediate(&hl1.data, &hl2.data);
    std.debug.print("intermediate_hashed_node: {}\n", .{inter_node});
}
test "merkle-tree.calculate_list_capacity: Create a merkle tree with capacity" {
    const testing_allocator = std.testing.allocator;

    var test_items = try ArrayList([]const u8).initCapacity(testing_allocator, 10);
    for (0..test_items.capacity) |_| {
        const leaf = "Lorem Ipsum Dolor";
        const hashed_leaf = hash_leaf(leaf);
        test_items.appendAssumeCapacity(&hashed_leaf.data);
    }
    var mt = try MerkleTree.new(testing_allocator, test_items.items);
    defer mt.deinit();
    //defer testing_allocator.free(test_items);
    defer test_items.deinit();
    var enc = bs58.Encoder.init(.{});
    var dest: [45]u8 = undefined;
    @memset(&dest, 0);
    var res = try enc.encode(&mt.get_root().?.data, &dest);
    _ = res;
    std.debug.print("root: {?s}\n", .{dest});
}
