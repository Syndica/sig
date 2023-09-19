const std = @import("std");
const Hash = @import("../core/hash.zig").Hash;
const Sha256 = std.crypto.hash.sha2.Sha256;
const ArrayList = std.ArrayList;
const bs58 = @import("base58-zig");
const Allocator = std.mem.Allocator;
const expect = std.testing.expect;
const print = std.debug.print;
pub const MerkleTreeError = error{InvalidProofEntry};
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

pub const ProofEntry = struct {
    target: Hash,
    lsib: ?Hash,
    rsib: ?Hash,
    const Self = @This();
    pub fn new(target: Hash, lsib: ?Hash, rsib: ?Hash) !Self {
        if ((@intFromBool(lsib == null) ^ @intFromBool(rsib == null)) == 0) {
            //print("lsib: {?} \nrsib: {?}", .{ lsib, rsib });
            return MerkleTreeError.InvalidProofEntry;
        }

        return .{ .target = target, .lsib = lsib, .rsib = rsib };
    }
};

pub const Proof = struct {
    entries: ArrayList(ProofEntry),

    const Self = @This();

    pub fn init(alloc: Allocator) Self {
        return .{ .entries = ArrayList(ProofEntry).init(alloc) };
    }

    pub fn push(self: *Self, entry: ProofEntry) Allocator.Error!void {
        try self.entries.append(entry);
    }

    pub fn verify(self: *const Self, candidate: Hash) bool {
        var result: ?Hash = undefined;
        var accumulator: Hash = candidate;
        for (self.entries.items) |entry| {
            var lsib: Hash = undefined;
            var rsib: Hash = undefined;
            if (entry.lsib != null) {
                lsib = entry.lsib.?;
            } else {
                lsib = accumulator;
            }
            if (entry.rsib != null) {
                rsib = entry.rsib.?;
            } else {
                rsib = accumulator;
            }
            const hash = hash_intermediate(&lsib.data, &rsib.data);
            result = accumulator;
            if (std.mem.eql(u8, &hash.data, &entry.target.data)) {
                accumulator = hash;
            } else {
                result = null;
                break;
            }
        }
        if (result != null) {
            return true;
        } else {
            return false;
        }
    }

    pub fn deinit(self: *const Self) void {
        self.entries.deinit();
    }
};

pub const MerkleTree = struct {
    leaf_count: usize,
    nodes: ArrayList(Hash),

    const Self = @This();

    pub fn new(alloc: Allocator, items: []const []const u8) !Self {
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

    pub fn find_path(self: *const Self, alloc: Allocator, index: usize) !?Proof {
        if (index >= self.leaf_count) {
            return null;
        }

        var level_len = self.leaf_count;
        var level_start: usize = 0;
        var path = Proof.init(alloc);
        var node_index = index;
        var lsib: ?Hash = null;
        var rsib: ?Hash = null;

        while (level_len > 0) {
            const level = self.nodes.items[level_start..(level_start + level_len)];
            const target = level[node_index];

            if (lsib != null or rsib != null) {
                var pe = try ProofEntry.new(target, lsib, rsib);
                try path.push(pe);
            }

            if (node_index % 2 == 0) {
                lsib = null;
                if (node_index + 1 < level.len) {
                    rsib = level[node_index + 1];
                } else {
                    rsib = level[node_index];
                }
            } else {
                lsib = level[node_index - 1];
                rsib = null;
            }

            node_index /= 2;

            level_start += level_len;
            level_len = Self.next_level_len(level_len);
        }

        return path;
    }
    pub fn deinit(self: *const Self) void {
        self.nodes.deinit();
    }
};

const TEST: []const []const u8 = &[_][]const u8{ "my", "very", "eager", "mother", "just", "served", "us", "nine", "pizzas", "make", "prime" };

const BAD: []const []const u8 = &[_][]const u8{ "bad", "missing", "false" };

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
    defer test_items.deinit();
    var dest: [256]u8 = undefined;
    const root = &mt.get_root().?;
    try root.encode_bs58(&dest);
    std.debug.print("root: {?s}\n", .{dest});
}
test "merkle-tree.path_verify: good path" {
    const testing_allocator = std.testing.allocator;
    var mt = try MerkleTree.new(testing_allocator, TEST);
    defer mt.deinit();
    for (TEST[0..], 0..) |s, index| {
        const hash = hash_leaf(s);
        const path = try mt.find_path(testing_allocator, index);
        defer path.?.deinit();
        try expect(path.?.verify(hash));
    }
}

test "merkle-tree.path_verify: bad path" {
    const testing_allocator = std.testing.allocator;
    var mt = try MerkleTree.new(testing_allocator, TEST);
    defer mt.deinit();
    for (BAD[0..], 0..) |s, index| {
        const hash = hash_leaf(s);
        const path = try mt.find_path(testing_allocator, index);
        defer path.?.deinit();
        const result = path.?.verify(hash);
        try expect(!result);
    }
}
test "merkle-tree.test_from_many" {
    var dest: [32]u8 = undefined;
    @memset(&dest, 0);
    _ = try std.fmt.hexToBytes(&dest, "b40c847546fdceea166f927fc46c5ca33c3638236a36275c1346d3dffb84e1bc");

    const testing_allocator = std.testing.allocator;
    var mt = try MerkleTree.new(testing_allocator, TEST);
    defer mt.deinit();
    print("decoded {any}\nroot: {any}", .{ dest, mt.get_root().?.data });
    try expect(std.mem.eql(u8, &mt.get_root().?.data, &dest));
}
