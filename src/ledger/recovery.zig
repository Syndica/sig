const std = @import("std");
const sig = @import("../lib.zig");
const ledger = @import("lib.zig");

const Allocator = std.mem.Allocator;

const Hash = sig.core.Hash;
const Lru = sig.common.lru.LruCacheCustom;

const CodeShred = ledger.shred.CodeShred;
const CodeShredHeader = ledger.shred.CodeHeader;
const CommonHeader = ledger.shred.CommonHeader;
const DataShred = ledger.shred.DataShred;
const MerkleProofEntryList = ledger.shred.MerkleProofEntryList;
const ReedSolomon = ledger.reed_solomon.ReedSolomon;
const Shred = ledger.shred.Shred;
const Signature = sig.core.Signature;

const checkedSub = sig.utils.math.checkedSub;
const makeMerkleTree = ledger.shred.makeMerkleTree;
const makeMerkleProof = ledger.shred.makeMerkleProof;

const DATA_SHREDS_PER_FEC_BLOCK = ledger.shred.DATA_SHREDS_PER_FEC_BLOCK;

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

const RecoveryMetadata = struct {
    common_header: CommonHeader,
    code_header: CodeShredHeader,
    chained_merkle_root: ?Hash,
    retransmitter_signature: ?Signature,
};

const RecoveryShreds = struct {
    allocator: Allocator,
    input_shreds: []?Shred,
    shards: []?[]const u8,
    mask: []const bool,
    num_to_recover: usize,

    /// The shards that are created during reconstruct need to be freed.
    /// Existing shards are assumed to be owned by another scope.
    ///
    /// No shreds are freed, as they are assumed to be owned by another scope.
    pub fn deinit(self: @This()) void {
        for (self.mask, self.shards) |was_present, shard| {
            if (!was_present) {
                if (shard) |s| self.allocator.free(s);
            }
        }
        self.allocator.free(self.input_shreds);
        self.allocator.free(self.shards);
        self.allocator.free(self.mask);
    }

    // Any shreds that were created during reconstruct are freed.
    // Existing shards are assumed to be owned by another scope.
    pub fn deinitShreds(self: @This()) void {
        for (self.mask, self.input_shreds) |was_present, shred| {
            if (!was_present) {
                if (shred) |s| s.deinit();
            }
        }
    }
};

/// agave: merkle::recover
pub fn recover(
    allocator: Allocator,
    shreds: []const Shred,
    reed_solomon_cache: *ReedSolomonCache,
) !std.ArrayList(Shred) {
    const meta = try getRecoveryMetadata(shreds);
    const organized = try organizeShredsForRecovery(allocator, shreds, meta);
    defer organized.deinit();
    errdefer organized.deinitShreds();

    // Reconstruct the shard bytes using reed solomon
    var reed_solomon = try reed_solomon_cache.get(
        @intCast(meta.code_header.num_data_shreds),
        @intCast(meta.code_header.num_code_shreds),
    );
    defer reed_solomon.deinit();
    try reed_solomon.reconstruct(allocator, organized.shards, false);

    // Reconstruct code and data shreds from erasure encoded shards.
    const all_shreds = try reconstructShreds(allocator, meta, organized);
    defer allocator.free(all_shreds);

    // Assemble list that excludes the shreds we already had
    var ret = try std.ArrayList(Shred).initCapacity(allocator, organized.num_to_recover);
    for (all_shreds, organized.mask) |shred, was_present| {
        if (!was_present) {
            try shred.sanitize();
            ret.appendAssumeCapacity(shred);
        }
    }
    return ret;
}

/// Collect metadata from the shreds about their erasure set,
/// to be used during shred recovery.
///
/// Input shreds are expected to all be from the same erasure set,
/// and there should be at least one coding shred.
///
/// Grab {common, code} headers from first code shred.
/// Incoming shreds are resigned immediately after signature verification,
/// so we can just grab the retransmitter signature from one of the
/// available shreds and attach it to the recovered shreds.
fn getRecoveryMetadata(shreds: []const Shred) !RecoveryMetadata {
    const meta: RecoveryMetadata = for (shreds) |shred| {
        if (shred == .code) {
            const code_shred = shred.code;
            const chained_merkle_root = code_shred.fields.chainedMerkleRoot() catch null;
            const retransmitter_signature = code_shred.fields.retransmitterSignature() catch null;
            const position = code_shred.fields.custom.position;
            var common_header = code_shred.fields.common;
            var code_header = code_shred.fields.custom;
            common_header.index = try checkedSub(common_header.index, position);
            code_header.position = 0;
            break .{
                .common_header = common_header,
                .code_header = code_header,
                .chained_merkle_root = chained_merkle_root,
                .retransmitter_signature = retransmitter_signature,
            };
        }
    } else return error.TooFewParityShards;
    std.debug.assert(verifyErasureBatch(meta.common_header, meta.code_header, shreds));
    std.debug.assert(!meta.common_header.variant.resigned or
        meta.retransmitter_signature != null);
    return meta;
}

fn organizeShredsForRecovery(
    allocator: Allocator,
    shreds: []const Shred,
    meta: RecoveryMetadata,
) !RecoveryShreds {
    const num_shards: usize =
        @intCast(meta.code_header.num_data_shreds + meta.code_header.num_code_shreds);

    // Obtain erasure encoded shards from shreds.
    const input_shreds = try allocator.alloc(?Shred, num_shards);
    errdefer allocator.free(input_shreds);
    const shards = try allocator.alloc(?[]const u8, num_shards);
    errdefer {
        for (shards) |shard| if (shard) |s| allocator.free(s);
        allocator.free(shards);
    }

    for (input_shreds) |*s| s.* = null;
    for (shards) |*s| s.* = null;
    for (shreds) |shred| {
        const index = shred.erasureShardIndex() catch {
            return error.InvalidIndex;
        };
        if (index >= shards.len) return error.InvalidIndex;
        input_shreds[index] = shred;
        shards[index] = try shred.erasureShardAsSlice();
    }

    // identify which shreds were already present and which need to be recovered
    var num_to_recover: usize = 1;
    const mask = try allocator.alloc(bool, input_shreds.len);
    errdefer allocator.free(mask);
    for (input_shreds, 0..) |s, i| {
        mask[i] = s != null;
        if (s == null) {
            num_to_recover += 1;
        }
    }

    return .{
        .allocator = allocator,
        .input_shreds = input_shreds,
        .shards = shards,
        .mask = mask,
        .num_to_recover = num_to_recover,
    };
}

/// Reconstruct code and data shreds from erasure encoded shards.
fn reconstructShreds(
    allocator: Allocator,
    meta: RecoveryMetadata,
    shreds: RecoveryShreds,
) ![]const Shred {
    // Reconstruct code and data shreds from erasure encoded shards.
    const all_shreds = try allocator.alloc(Shred, shreds.input_shreds.len);
    var num_recovered_so_far: usize = 0;
    errdefer {
        // The shreds that are created below need to be freed if there is an error.
        // If no error, ownership is transfered to calling scope.
        // Existing shreds do not need to be freed because they were already owned by calling scope.
        for (all_shreds, shreds.mask, 0..num_recovered_so_far) |shred, was_present, _| {
            if (!was_present) shred.deinit();
        }
    }
    std.debug.assert(shreds.input_shreds.len == shreds.shards.len);
    for (shreds.input_shreds, shreds.shards, 0..) |maybe_shred, maybe_shard, index| {
        if (maybe_shred) |shred| {
            all_shreds[index] = shred;
        } else {
            const shard = maybe_shard orelse return error.TooFewShards;
            all_shreds[index] = try reconstructShred(allocator, meta, shard, index);
        }
        num_recovered_so_far += 1;
    }

    try setMerkleProofs(allocator, meta, shreds, all_shreds);

    return all_shreds;
}

fn reconstructShred(
    allocator: Allocator,
    meta: RecoveryMetadata,
    shard: []const u8,
    index: usize,
) !Shred {
    if (index < meta.code_header.num_data_shreds) {
        const data_shred = try DataShred.fromRecoveredShard(
            allocator,
            meta.common_header.signature,
            meta.chained_merkle_root,
            meta.retransmitter_signature,
            shard,
        );
        const this = data_shred.fields.common;
        const set = meta.common_header;
        if (this.variant.proof_size != set.variant.proof_size or
            this.variant.chained != set.variant.chained or
            this.variant.resigned != set.variant.resigned or
            this.slot != set.slot or
            this.version != set.version or
            this.fec_set_index != set.fec_set_index)
        {
            return error.InvalidRecoveredShred;
        }
        return .{ .data = data_shred };
    } else {
        const offset = index - meta.code_header.num_data_shreds;
        var this_common_header = meta.common_header;
        var this_code_header = meta.code_header;
        this_common_header.index += @intCast(offset);
        this_code_header.position = @intCast(offset);
        const code_shred = try CodeShred.fromRecoveredShard(
            allocator,
            meta.common_header,
            meta.code_header,
            meta.chained_merkle_root,
            meta.retransmitter_signature,
            shard,
        );
        return .{ .code = code_shred };
    }
}

fn setMerkleProofs(
    allocator: Allocator,
    meta: RecoveryMetadata,
    shreds: RecoveryShreds,
    all_shreds: []Shred,
) !void {
    // Compute merkle tree
    var tree = try std.ArrayList(Hash).initCapacity(allocator, all_shreds.len);
    defer tree.deinit();
    for (all_shreds) |shred| {
        tree.appendAssumeCapacity(try shred.merkleNode());
    }
    try makeMerkleTree(&tree);

    // set the merkle proof on the recovered shreds.
    const num_shards: usize =
        @intCast(meta.code_header.num_data_shreds + meta.code_header.num_code_shreds);
    for (all_shreds, shreds.mask, 0..) |*shred, was_present, index| {
        const proof: MerkleProofEntryList = try makeMerkleProof(
            allocator,
            index,
            num_shards,
            tree.items,
        ) orelse return error.InvalidMerkleProof;
        defer proof.deinit(allocator);
        if (proof.len != @as(usize, @intCast(meta.common_header.variant.proof_size))) {
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
}

/// Verify that shreds belong to the same erasure batch
/// and have consistent headers.
fn verifyErasureBatch(
    expect: CommonHeader,
    code: CodeShredHeader,
    shreds: []const Shred,
) bool {
    for (shreds) |shred| {
        const actual = shred.commonHeader();
        if (!(expect.signature.eql(&actual.signature) and
            expect.slot == actual.slot and
            expect.version == actual.version and
            expect.fec_set_index == actual.fec_set_index and
            expect.variant.proof_size == actual.variant.proof_size and
            expect.variant.chained == actual.variant.chained and
            expect.variant.resigned == actual.variant.resigned and
            (shred == .data or
            code.num_data_shreds == shred.code.fields.custom.num_data_shreds and
            code.num_code_shreds == shred.code.fields.custom.num_code_shreds)))
        {
            return false;
        }
    }
    return true;
}

///////////
// Tests

const mainnet_shreds = @import("test_shreds.zig").mainnet_recovery_shreds;
const CodeHeader = ledger.shred.CodeHeader;

// test "recover mainnet shreds - end to end" {
//     const allocator = std.testing.allocator;
//     const shred_bytes = @import("test_shreds.zig").mainnet_recovery_shreds;
//     var shreds = std.ArrayList(Shred).init(allocator);
//     defer shreds.deinit();
//     defer for (shreds.items) |s| s.deinit();
//     for (shred_bytes) |sb| {
//         try shreds.append(try Shred.fromPayload(allocator, sb));
//     }
//     var cache = try ReedSolomonCache.init(allocator);
//     defer cache.deinit();
//     _ = try recover(allocator, shreds.items, &cache);
// }

test "recover mainnet shreds - metadata is correct" {
    const shreds = try toShreds(std.testing.allocator, &mainnet_shreds);
    defer {
        for (shreds) |shred| shred.deinit();
        std.testing.allocator.free(shreds);
    }
    const actual = try getRecoveryMetadata(shreds);
    const expected = RecoveryMetadata{
        .common_header = CommonHeader{
            .signature = try Signature.fromString(
                "ksnjzXzraR5hWthnKAWVgJkDBUoRX8CHpLttYs2sAmhPFvh6Ga6HMTLMKRi45p1PfLevfm272ANmwTBEvGwW19m",
            ),
            .variant = .{
                .shred_type = .code,
                .proof_size = 5,
                .chained = false,
                .resigned = false,
            },
            .slot = 284737905,
            .index = 483,
            .version = 50093,
            .fec_set_index = 483,
        },
        .code_header = CodeHeader{
            .num_data_shreds = 7,
            .num_code_shreds = 21,
            .position = 0,
        },
        .retransmitter_signature = null,
        .chained_merkle_root = null,
    };
    try std.testing.expectEqual(expected, actual);
}

fn toShreds(allocator: Allocator, payloads: []const []const u8) ![]const Shred {
    var shreds = try std.ArrayList(Shred).initCapacity(allocator, payloads.len);
    for (payloads) |payload| {
        shreds.appendAssumeCapacity(try Shred.fromPayload(allocator, payload));
    }
    return shreds.items;
}
