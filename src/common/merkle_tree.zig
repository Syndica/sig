const std = @import("std");
const Hash = @import("../core/hash.zig").Hash;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub fn merkleTreeHash(hashes: []Hash, fanout: usize) !*Hash {
    var length = hashes.len;
    if (length == 0) return error.EmptyHashList;

    while (true) {
        const chunks = try std.math.divCeil(usize, length, fanout);
        var index: usize = 0;
        for (0..chunks) |i| {
            const start = i * fanout;
            const end = @min(start + fanout, length);

            var hasher = Sha256.init(.{});
            for (start..end) |j| {
                hasher.update(&hashes[j].data);
            }
            const hash = hasher.finalResult();
            hashes[index] = Hash{ .data = hash };
            index += 1;
        }
        length = index;
        if (length == 1) {
            return &hashes[0];
        }
    }
}

pub const NestedHashTree = struct {
    hashes: []std.ArrayListUnmanaged(Hash),

    pub fn getValue(self: *NestedHashTree, index: usize) !*Hash {
        var search_index: usize = 0;
        var i: usize = 0;
        while (i < self.hashes.len) {
            const nested_len = self.hashes[i].items.len;
            if (search_index + nested_len > index) {
                const index_in_nested = index - search_index;
                return &self.hashes[i].items[index_in_nested];
            } else {
                search_index += nested_len;
                i += 1;
            }
        }

        return error.InvalidIndex;
    }

    pub fn len(self: *NestedHashTree) usize {
        var length: usize = 0;
        for (self.hashes) |*hashes| {
            length += hashes.items.len;
        }
        return length;
    }

    pub fn computeMerkleRoot(self: *NestedHashTree, fanout: usize) !*Hash {
        var length = self.len();
        if (length == 0) return error.EmptyHashList;

        while (true) {
            const chunks = try std.math.divCeil(usize, length, fanout);

            var index: usize = 0;
            for (0..chunks) |i| {
                const start = i * fanout;
                const end = @min(start + fanout, length);

                var hasher = Sha256.init(.{});
                for (start..end) |j| {
                    const h = self.getValue(j) catch unreachable;
                    hasher.update(&h.data);
                }
                const hash = hasher.finalResult();
                (self.getValue(index) catch unreachable).data = hash;
                index += 1;
            }
            length = index;
            if (length == 1) {
                return self.getValue(0) catch unreachable;
            }
        }
    }
};

test "common.merkle_tree: test nested impl" {
    const init_length: usize = 10;
    var hashes: [init_length]Hash = undefined;
    for (&hashes, 0..) |*hash, i| {
        hash.* = Hash{ .data = [_]u8{@intCast(i)} ** 32 };
    }
    const hashes_list = std.ArrayListUnmanaged(Hash).fromOwnedSlice(&hashes);

    var hashes_full = [_]std.ArrayListUnmanaged(Hash){hashes_list};
    var nested_hashes = NestedHashTree{
        .hashes = &hashes_full,
    };

    const root = try nested_hashes.computeMerkleRoot(3);
    const expected_root: [32]u8 = .{ 56, 239, 163, 39, 169, 252, 144, 195, 85, 228, 99, 82, 225, 185, 237, 141, 186, 90, 36, 220, 86, 140, 59, 47, 18, 172, 250, 231, 79, 178, 51, 100 };
    try std.testing.expect(std.mem.eql(u8, &expected_root, &root.data));
}

test "common.merkle_tree: test nested impl deeper" {
    var hashes: [4]Hash = undefined;
    for (&hashes, 0..) |*hash, i| {
        hash.* = Hash{ .data = [_]u8{@intCast(i)} ** 32 };
    }
    const hashes_list = std.ArrayListUnmanaged(Hash).fromOwnedSlice(&hashes);

    var hashes2: [4]Hash = undefined;
    for (&hashes2, 4..) |*hash, i| {
        hash.* = Hash{ .data = [_]u8{@intCast(i)} ** 32 };
    }
    const hashes2_list = std.ArrayListUnmanaged(Hash).fromOwnedSlice(&hashes2);

    var hashes3: [2]Hash = undefined;
    for (&hashes3, 8..) |*hash, i| {
        hash.* = Hash{ .data = [_]u8{@intCast(i)} ** 32 };
    }
    const hashes3_list = std.ArrayListUnmanaged(Hash).fromOwnedSlice(&hashes3);

    var hashes_full = [_]std.ArrayListUnmanaged(Hash){ hashes_list, hashes2_list, hashes3_list };
    var nested_hashes = NestedHashTree{
        .hashes = &hashes_full,
    };

    const root = try nested_hashes.computeMerkleRoot(3);
    const expected_root: [32]u8 = .{ 56, 239, 163, 39, 169, 252, 144, 195, 85, 228, 99, 82, 225, 185, 237, 141, 186, 90, 36, 220, 86, 140, 59, 47, 18, 172, 250, 231, 79, 178, 51, 100 };
    try std.testing.expect(std.mem.eql(u8, &expected_root, &root.data));
}

test "common.merkle_tree: test tree impl" {
    const init_length: usize = 10;
    var hashes: [init_length]Hash = undefined;
    for (&hashes, 0..) |*hash, i| {
        hash.* = Hash{ .data = [_]u8{@intCast(i)} ** 32 };
    }

    const root = try merkleTreeHash(&hashes, 3);
    const expected_root: [32]u8 = .{ 56, 239, 163, 39, 169, 252, 144, 195, 85, 228, 99, 82, 225, 185, 237, 141, 186, 90, 36, 220, 86, 140, 59, 47, 18, 172, 250, 231, 79, 178, 51, 100 };
    try std.testing.expect(std.mem.eql(u8, &expected_root, &root.data));
}
