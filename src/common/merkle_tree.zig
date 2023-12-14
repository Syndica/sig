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
            var hash = hasher.finalResult();
            hashes[index] = Hash{ .data = hash };
            index += 1;
        }
        length = index;
        if (length == 1) {
            return &hashes[0];
        }
    }
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
