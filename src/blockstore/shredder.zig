const std = @import("std");
const sig = @import("../lib.zig");

const Allocator = std.mem.Allocator;

const CodingShred = sig.shred_collector.shred.CodingShred;
const CodingShredHeader = sig.shred_collector.shred.CodingShredHeader;
const CommonHeader = sig.shred_collector.shred.CommonHeader;
const DataShred = sig.shred_collector.shred.DataShred;
const Hash = sig.core.Hash;
const Lru = sig.common.lru.LruCacheCustom;
const MerkleProofEntryList = sig.shred_collector.shred.MerkleProofEntryList;
const ReedSolomon = sig.blockstore.reed_solomon.ReedSolomon;
const Shred = sig.shred_collector.shred.Shred;
const Signature = sig.core.Signature;

const checkedSub = sig.utils.math.checkedSub;
const makeMerkleTree = sig.shred_collector.shred.makeMerkleTree;
const makeMerkleProof = sig.shred_collector.shred.makeMerkleProof;

const DATA_SHREDS_PER_FEC_BLOCK = sig.shred_collector.shred.DATA_SHREDS_PER_FEC_BLOCK;

pub const ReedSolomonCache = struct {
    cache: Cache,
    const Cache = Lru(
        .locking,
        struct { data: usize, parity: usize },
        ReedSolomon,
        void,
        ReedSolomon.deinit,
    );

    const Self = @This();

    pub fn init(allocator: Allocator) Allocator.Error!Self {
        return .{ .cache = try Cache.init(allocator, 4 * DATA_SHREDS_PER_FEC_BLOCK) };
    }

    pub fn deinit(self: *Self) void {
        self.cache.deinit();
    }

    /// Caller owns the ReedSolomon. Call `ReedSolomon.deinit` when done.
    pub fn get(self: *Self, data_shards: usize, parity_shards: usize) !ReedSolomon {
        if (self.cache.get(.{ .data = data_shards, .parity = parity_shards })) |rs| {
            var reed_solomon = rs;
            if (reed_solomon.acquire()) {
                return reed_solomon;
            }
        }
        var rs = try ReedSolomon.init(self.cache.allocator, data_shards, parity_shards);
        const acquired = rs.acquire();
        std.debug.assert(acquired);
        const old = self.cache.put(.{ .data = data_shards, .parity = parity_shards }, rs);
        std.debug.assert(old == null);
        return rs;
    }
};

/// agave: merkle::recover
pub fn recover(
    allocator: Allocator,
    shreds: []const Shred,
    reed_solomon_cache: *ReedSolomonCache,
) !std.ArrayList(Shred) {
    // Grab {common, coding} headers from first coding shred.
    // Incoming shreds are resigned immediately after signature verification,
    // so we can just grab the retransmitter signature from one of the
    // available shreds and attach it to the recovered shreds.
    const common_header: CommonHeader, //
    const coding_header: CodingShredHeader, //
    const chained_merkle_root: ?Hash, //
    const retransmitter_signature: ?Signature =
        for (shreds) |shred|
    {
        if (shred == .code) {
            const code_shred = shred.code;
            const chained_merkle_root = code_shred.fields.chainedMerkleRoot() catch null;
            const retransmitter_signature = code_shred.fields.retransmitterSignature() catch null;
            const position = code_shred.fields.custom.position;
            var common_header = code_shred.fields.common;
            var coding_header = code_shred.fields.custom;
            common_header.index = try checkedSub(common_header.index, position);
            coding_header.position = 0;
            break .{ common_header, coding_header, chained_merkle_root, retransmitter_signature };
        }
    } else return error.TooFewParityShards;
    const proof_size = common_header.shred_variant.proof_size;
    const chained = common_header.shred_variant.chained;
    const resigned = common_header.shred_variant.resigned;
    std.debug.assert(!resigned or retransmitter_signature != null);
    std.debug.assert(verifyErasureBatch(common_header, coding_header, shreds));
    const num_data_shreds: usize = @intCast(coding_header.num_data_shreds);
    const num_coding_shreds: usize = @intCast(coding_header.num_coding_shreds);
    const num_shards = num_data_shreds + num_coding_shreds;

    // Obtain erasure encoded shards from shreds.
    const all_shreds = try allocator.alloc(?Shred, num_shards);
    defer allocator.free(all_shreds);
    const shards = try allocator.alloc(?[]const u8, num_shards);
    defer allocator.free(shards);

    for (all_shreds) |*s| s.* = null;
    for (shards) |*s| s.* = null;
    for (shreds) |shred| {
        const index = shred.erasureShardIndex() catch {
            return error.InvalidIndex;
        };
        if (index >= shards.len) return error.InvalidIndex;
        all_shreds[index] = shred;
        shards[index] = try shred.erasureShardAsSlice();
    }

    // identify which shreds were already present and which need to be recovered
    var num_to_recover: usize = 1;
    const mask = try allocator.alloc(bool, all_shreds.len);
    defer allocator.free(mask);
    for (all_shreds, 0..) |s, i| {
        mask[i] = s != null;
        if (s == null) {
            num_to_recover += 1;
        }
    }
    defer {
        // The shards that are created during reconstruct need to be freed.
        // Existing shards do not need to be freed because they were already owned by calling scope.
        for (shards, mask) |shard, was_present| {
            if (shard) |s| {
                if (!was_present) allocator.free(s);
            }
        }
    }

    // Reconstruct the shard bytes using reed solomon
    var rs = try reed_solomon_cache.get(num_data_shreds, num_coding_shreds);
    defer rs.deinit();
    try rs.reconstruct(allocator, shards, false);

    // Reconstruct code and data shreds from erasure encoded shards.
    const all_including_recovered = try allocator.alloc(Shred, all_shreds.len);
    defer allocator.free(all_including_recovered);
    var num_recovered_so_far: usize = 0;
    errdefer {
        // The shreds that are created below need to be freed if there is an error.
        // If no error, ownership is transfered to calling scope.
        // Existing shreds do not need to be freed because they were already owned by calling scope.
        for (all_including_recovered, mask, 0..num_recovered_so_far) |shred, was_present, _| {
            if (!was_present) shred.deinit();
        }
    }
    std.debug.assert(all_shreds.len == shards.len);
    for (all_shreds, shards, 0..) |maybe_shred, maybe_shard, index| {
        if (maybe_shred) |shred| {
            all_including_recovered[index] = shred;
        } else {
            const shard = maybe_shard orelse return error.TooFewShards;
            if (index < num_data_shreds) {
                const data_shred = try DataShred.fromRecoveredShard(
                    allocator,
                    common_header.signature,
                    chained_merkle_root,
                    retransmitter_signature,
                    shard,
                );
                const c = data_shred.fields.common;
                if (c.shred_variant.proof_size != proof_size or
                    c.shred_variant.chained != chained or
                    c.shred_variant.resigned != resigned or
                    c.slot != common_header.slot or
                    c.version != common_header.version or
                    c.fec_set_index != common_header.fec_set_index)
                {
                    return error.InvalidRecoveredShred;
                }
                all_including_recovered[index] = .{ .data = data_shred };
            } else {
                const offset = index - num_data_shreds;
                var this_common_header = common_header;
                var this_coding_header = coding_header;
                this_common_header.index += @intCast(offset);
                this_coding_header.position = @intCast(offset);
                const coding_shred = try CodingShred.fromRecoveredShard(
                    allocator,
                    common_header,
                    coding_header,
                    chained_merkle_root,
                    retransmitter_signature,
                    shard,
                );
                all_including_recovered[index] = .{ .code = coding_shred };
            }
        }
        num_recovered_so_far += 1;
        // TODO perf: should this only run in debug mode?
        try all_including_recovered[index].sanitize();
    }

    // Compute merkle tree
    var tree = try std.ArrayList(Hash).initCapacity(allocator, all_including_recovered.len);
    defer tree.deinit();
    for (all_including_recovered) |shred| {
        tree.appendAssumeCapacity(try shred.merkleNode());
    }
    try makeMerkleTree(&tree);

    // set the merkle proof on the recovered shreds.
    for (all_including_recovered, mask, 0..) |*shred, was_present, index| {
        const proof: MerkleProofEntryList = try makeMerkleProof(
            allocator,
            index,
            num_shards,
            tree.items,
        ) orelse return error.InvalidMerkleProof;
        defer proof.deinit(allocator);
        if (proof.len != @as(usize, @intCast(proof_size))) {
            return error.InvalidMerkleProof;
        }
        if (was_present) {
            const expected_proof = try shred.merkleProof();
            var expected_proof_iterator = expected_proof.iterator();
            var i: usize = 0;
            while (expected_proof_iterator.next()) |expected_entry| : (i += 1) {
                const actual_entry = proof.get(i) orelse return error.InvalidMerkleProof;
                if (!std.mem.eql(u8, expected_entry, &actual_entry)) {
                    return error.InvalidMerkleProof;
                }
            }
        } else {
            try shred.setMerkleProof(proof);
            std.debug.assert(if (shred.sanitize()) |_| true else |_| false);
            // TODO: Assert that shred payload is fully populated.
        }
    }

    // Assemble list that excludes the shreds we already had
    var ret = try std.ArrayList(Shred).initCapacity(allocator, num_to_recover);
    for (all_including_recovered, mask) |shred, was_present| {
        if (!was_present) {
            try shred.sanitize();
            ret.appendAssumeCapacity(shred);
        }
    }
    return ret;
}

/// Verify that shreds belong to the same erasure batch
/// and have consistent headers.
fn verifyErasureBatch(
    expect: CommonHeader,
    code: CodingShredHeader,
    shreds: []const Shred,
) bool {
    for (shreds) |shred| {
        const actual = shred.commonHeader();
        if (!(expect.signature.eql(&actual.signature) and
            expect.slot == actual.slot and
            expect.version == actual.version and
            expect.fec_set_index == actual.fec_set_index and
            expect.shred_variant.proof_size == actual.shred_variant.proof_size and
            expect.shred_variant.chained == actual.shred_variant.chained and
            expect.shred_variant.resigned == actual.shred_variant.resigned and
            (shred == .data or
            code.num_data_shreds == shred.code.fields.custom.num_data_shreds and
            code.num_coding_shreds == shred.code.fields.custom.num_coding_shreds)))
        {
            return false;
        }
    }
    return true;
}
