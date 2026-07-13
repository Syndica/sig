const std = @import("std");
const sig = @import("../../sig.zig");
const ledger = @import("../lib.zig");

const Allocator = std.mem.Allocator;

const Hash = sig.core.Hash;
const Lru = sig.utils.lru.LruCacheCustom;

const CodeShred = ledger.shred.CodeShred;
const CodeShredHeader = ledger.shred.CodeHeader;
const CommonHeader = ledger.shred.CommonHeader;
const DataShred = ledger.shred.DataShred;
const MerkleProofEntryList = ledger.shred.MerkleProofEntryList;
const ReedSolomon = ledger.reed_solomon.ReedSolomon;
const Shred = ledger.shred.Shred;
const Signature = sig.core.Signature;

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

/// Analogous to [merkle::recover](https://github.com/anza-xyz/agave/blob/42e72bf1b31f5335d3f7ee56ce1f607ceb899c3f/ledger/src/shred/merkle.rs#L778)
pub fn recover(
    allocator: Allocator,
    shreds: []const Shred,
    reed_solomon_cache: *ReedSolomonCache,
) !std.array_list.Managed(Shred) {
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
    var ret = try std.array_list.Managed(Shred).initCapacity(allocator, organized.num_to_recover);
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
            const chained_merkle_root = code_shred.chainedMerkleRoot() catch null;
            const retransmitter_signature = code_shred.retransmitterSignature() catch null;
            const position = code_shred.custom.erasure_code_index;
            var common_header = code_shred.common;
            var code_header = code_shred.custom;
            common_header.index = try std.math.sub(u32, common_header.index, position);
            code_header.erasure_code_index = 0;
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
    const num_shards: usize = meta.code_header.num_data_shreds + meta.code_header.num_code_shreds;

    // Obtain erasure encoded shards from shreds.
    const input_shreds = try allocator.alloc(?Shred, num_shards);
    errdefer allocator.free(input_shreds);
    const shards = try allocator.alloc(?[]const u8, num_shards);
    errdefer {
        for (shards) |shard| if (shard) |s| allocator.free(s);
        allocator.free(shards);
    }

    @memset(input_shreds, null);
    @memset(shards, null);
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
    var all_shreds = try std.ArrayListUnmanaged(Shred)
        .initCapacity(allocator, shreds.input_shreds.len);
    errdefer {
        // The shreds that are created below need to be freed if there is an error.
        // If no error, ownership is transfered to calling scope.
        // Existing shreds do not need to be freed because they were already owned by calling scope.
        for (all_shreds.items, 0..) |shred, i| {
            if (!shreds.mask[i]) shred.deinit();
        }
    }
    std.debug.assert(shreds.input_shreds.len == shreds.shards.len);
    for (shreds.input_shreds, shreds.shards, 0..) |maybe_shred, maybe_shard, index| {
        if (maybe_shred) |shred| {
            all_shreds.appendAssumeCapacity(shred);
        } else {
            const shard = maybe_shard orelse return error.TooFewShards;
            all_shreds.appendAssumeCapacity(try reconstructShred(allocator, meta, shard, index));
        }
    }

    try setMerkleProofs(allocator, meta, shreds, all_shreds.items);

    return all_shreds.toOwnedSlice(allocator);
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
            meta.common_header.leader_signature,
            meta.chained_merkle_root,
            meta.retransmitter_signature,
            shard,
        );
        const this = data_shred.common;
        const set = meta.common_header;
        if (this.variant.proof_size != set.variant.proof_size or
            this.variant.chained != set.variant.chained or
            this.variant.resigned != set.variant.resigned or
            this.slot != set.slot or
            this.version != set.version or
            this.erasure_set_index != set.erasure_set_index)
        {
            return error.InvalidRecoveredShred;
        }
        return .{ .data = data_shred };
    } else {
        const offset = index - meta.code_header.num_data_shreds;
        var this_common_header = meta.common_header;
        var this_code_header = meta.code_header;
        this_common_header.index += @intCast(offset);
        this_code_header.erasure_code_index = @intCast(offset);
        const code_shred = try CodeShred.fromRecoveredShard(
            allocator,
            this_common_header,
            this_code_header,
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
    var tree = try std.array_list.Managed(Hash).initCapacity(allocator, all_shreds.len);
    defer tree.deinit();
    for (all_shreds) |shred| {
        const merkle_node = try sig.ledger.shred.getMerkleNode(shred.payload());
        tree.appendAssumeCapacity(merkle_node);
    }
    try makeMerkleTree(&tree);

    // set the merkle proof on the recovered shreds.
    const num_shards: usize = meta.code_header.num_data_shreds + meta.code_header.num_code_shreds;
    for (all_shreds, shreds.mask, 0..) |*shred, was_present, index| {
        const proof: MerkleProofEntryList = try makeMerkleProof(
            allocator,
            index,
            num_shards,
            tree.items,
        ) orelse return error.InvalidMerkleProof;
        defer proof.deinit(allocator);
        if (proof.len != meta.common_header.variant.proof_size) {
            return error.InvalidMerkleProof;
        }
        if (was_present) {
            const expected_proof = try sig.ledger.shred.getMerkleProof(shred.payload());
            var expected_proof_iterator = expected_proof.iterator();
            var i: usize = 0;
            while (expected_proof_iterator.next()) |expected_entry| : (i += 1) {
                const actual_entry = proof.get(i) orelse return error.InvalidMerkleProof;
                if (!std.mem.eql(u8, expected_entry, &actual_entry)) {
                    return error.InvalidMerkleProof;
                }
            }
        } else {
            try sig.ledger.shred.setMerkleProof(shred.mutablePayload(), proof);
            std.debug.assert(!std.meta.isError(shred.sanitize())); // TODO error somewhere else
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
        if (!(expect.leader_signature.eql(&actual.leader_signature) and
            expect.slot == actual.slot and
            expect.version == actual.version and
            expect.erasure_set_index == actual.erasure_set_index and
            expect.variant.proof_size == actual.variant.proof_size and
            expect.variant.chained == actual.variant.chained and
            expect.variant.resigned == actual.variant.resigned and
            (shred == .data or
                code.num_data_shreds == shred.code.custom.num_data_shreds and
                    code.num_code_shreds == shred.code.custom.num_code_shreds)))
        {
            return false;
        }
    }
    return true;
}

///////////
// Tests

const test_shreds = @import("../test_shreds.zig");

const deinitShreds = ledger.tests.deinitShreds;

const mainnet_shreds = test_shreds.mainnet_recovery_shreds;
const mainnet_shards = test_shreds.mainnet_recovery_shards;
const mainnet_recovered_shards = test_shreds.mainnet_expected_recovered_shards;
const mainnet_partially_recovered_shreds = test_shreds.mainnet_expected_partially_recovered_shreds;
const mainnet_expected_recovered_shreds = test_shreds.mainnet_expected_recovered_shreds;

test "recover mainnet shreds - end to end" {
    const allocator = std.testing.allocator;
    const shreds = try toShreds(&mainnet_shreds);
    defer deinitShreds(std.testing.allocator, shreds);
    var cache = try ReedSolomonCache.init(allocator);
    defer cache.deinit();

    const recovered_shreds = try recover(allocator, shreds, &cache);
    defer {
        for (recovered_shreds.items) |shred| shred.deinit();
        recovered_shreds.deinit();
    }

    try std.testing.expectEqual(mainnet_expected_recovered_shreds.len, recovered_shreds.items.len);
    for (mainnet_expected_recovered_shreds, recovered_shreds.items) |expected, actual| {
        try std.testing.expectEqualSlices(u8, expected, actual.payload());
        const expected_shred = try Shred.fromPayload(allocator, expected);
        defer expected_shred.deinit();
        try std.testing.expect(sig.utils.types.eql(expected_shred, actual));
    }
}

const expected_leader =
    "ksnjzXzraR5hWthnKAWVgJkDBUoRX8CHpLttYs2sAmhPFvh6Ga6HMTLMKRi45p1PfLevfm272ANmwTBEvGwW19m";
const expected_metadata: RecoveryMetadata = .{
    .common_header = .{
        .leader_signature = .parse(expected_leader),
        .variant = .{
            .shred_type = .code,
            .proof_size = 5,
            .chained = false,
            .resigned = false,
        },
        .slot = 284737905,
        .index = 483,
        .version = 50093,
        .erasure_set_index = 483,
    },
    .code_header = .{
        .num_data_shreds = 7,
        .num_code_shreds = 21,
        .erasure_code_index = 0,
    },
    .retransmitter_signature = null,
    .chained_merkle_root = null,
};

test "recover mainnet shreds - metadata is correct" {
    const shreds = try toShreds(&mainnet_shreds);
    defer deinitShreds(std.testing.allocator, shreds);
    const actual = try getRecoveryMetadata(shreds);
    try std.testing.expectEqual(expected_metadata, actual);
}

test "recover mainnet shreds - correct input shards" {
    const shreds = try toShreds(&mainnet_shreds);
    defer deinitShreds(std.testing.allocator, shreds);
    const organized =
        try organizeShredsForRecovery(std.testing.allocator, shreds, expected_metadata);
    defer organized.deinit();
    defer organized.deinitShreds();
    try std.testing.expectEqual(mainnet_shards.len, organized.shards.len);
    try std.testing.expect(sig.utils.types.eql(
        @as([]const ?[]const u8, &mainnet_shards),
        @as([]const ?[]const u8, organized.shards),
    ));
}

test "recover mainnet shreds - construct shreds from shards" {
    const allocator = std.testing.allocator;
    const shreds = try toShreds(&mainnet_shreds);
    defer allocator.free(shreds);
    const organized =
        try organizeShredsForRecovery(std.testing.allocator, shreds, expected_metadata);
    defer organized.deinit();
    const meta = try getRecoveryMetadata(shreds);

    const all_shreds = try allocator.alloc(Shred, mainnet_recovered_shards.len);
    defer deinitShreds(std.testing.allocator, all_shreds);
    for (organized.input_shreds, mainnet_recovered_shards, 0..) |maybe_shred, shard, index| {
        all_shreds[index] = if (maybe_shred) |shred|
            shred
        else
            try reconstructShred(allocator, meta, shard, index);
    }
    var i: usize = 0;
    for (all_shreds, mainnet_partially_recovered_shreds) |recovered_shred, shred_bytes| {
        try std.testing.expectEqualSlices(u8, shred_bytes, recovered_shred.payload());
        const expected_shred = try Shred.fromPayload(allocator, shred_bytes);
        defer expected_shred.deinit();
        switch (expected_shred) {
            inline .code => |c| {
                try std.testing.expectEqual(c.common, recovered_shred.code.common);
                try std.testing.expectEqual(c.custom, recovered_shred.code.custom);
            },
            inline .data => |c| {
                try std.testing.expectEqual(c.common, recovered_shred.data.common);
                try std.testing.expectEqual(c.custom, recovered_shred.data.custom);
            },
        }
        try std.testing.expect(sig.utils.types.eql(expected_shred, recovered_shred));
        i += 1;
    }
}

fn toShreds(payloads: []const []const u8) ![]const Shred {
    var shreds = try std.array_list.Managed(Shred).initCapacity(std.testing.allocator, payloads.len);
    for (payloads) |payload| {
        shreds.appendAssumeCapacity(try Shred.fromPayload(std.testing.allocator, payload));
    }
    return shreds.toOwnedSlice();
}
