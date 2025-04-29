pub const std = @import("std");
pub const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;
const Hash = sig.core.hash.Hash;
const Transaction = sig.core.transaction.Transaction;
const Signature = sig.core.Signature;

pub const Entry = struct {
    /// The number of hashes since the previous Entry ID.
    num_hashes: u64,

    /// The SHA-256 hash `num_hashes` after the previous Entry ID.
    hash: Hash,

    /// An unordered list of transactions that were observed before the Entry ID was
    /// generated. They may have been observed before a previous Entry ID but were
    /// pushed back into this list to ensure deterministic interpretation of the ledger.
    transactions: std.ArrayListUnmanaged(Transaction),

    pub const slice = entry_slice;

    pub fn isTick(self: Entry) bool {
        return self.transactions.items.len == 0;
    }

    pub fn deinit(self: Entry, allocator: std.mem.Allocator) void {
        for (self.transactions.items) |tx| tx.deinit(allocator);
        allocator.free(self.transactions.allocatedSlice());
    }
};

/// analogous to agave's [impl EntrySlice for [Entry]](https://github.com/anza-xyz/agave/blob/161fc1965bdb4190aa2d7e36c7c745b4661b10ed/entry/src/entry.rs#L632)
pub const entry_slice = struct {
    /// Count the number of ticks in all the entries
    pub fn tickCount(entries: []const Entry) u64 {
        var tick_count: u64 = 0;
        for (entries) |entry| {
            if (entry.isTick()) tick_count += 1;
        }
        return tick_count;
    }

    /// analogous to agave's [verify_tick_hash_count](https://github.com/anza-xyz/agave/blob/161fc1965bdb4190aa2d7e36c7c745b4661b10ed/entry/src/entry.rs#L880)
    pub fn verifyTickHashCount(
        logger: anytype,
        entries: []const Entry,
        tick_hash_count: *u64,
        hashes_per_tick: u64,
    ) bool {
        // When hashes_per_tick is 0, hashing is disabled.
        if (hashes_per_tick == 0) {
            return true;
        }

        for (entries) |entry| {
            tick_hash_count.* = tick_hash_count.* +| entry.num_hashes;
            if (entry.isTick()) {
                if (tick_hash_count.* != hashes_per_tick) {
                    logger.warn().logf(
                        "invalid tick hash count!: entry: {any}, " ++
                            "tick_hash_count: {}, hashes_per_tick: {}",
                        .{ entry, tick_hash_count, hashes_per_tick },
                    );
                    return false;
                }
                tick_hash_count.* = 0;
            }
        }

        return tick_hash_count.* < hashes_per_tick;
    }
};

/// Simple PoH validation that validates the hash of every entry in sequence.
pub fn verifyPoh(
    allocator: Allocator,
    preallocated_nodes: ?*std.ArrayListUnmanaged(Hash),
    initial_hash: Hash,
    entries: []const Entry,
) Allocator.Error!bool {
    var current_hash = initial_hash;

    for (entries) |entry| {
        if (entry.num_hashes == 0) continue;

        for (1..entry.num_hashes) |_| {
            current_hash = Hash.generateSha256Hash(&current_hash.data);
        }

        if (entry.transactions.items.len > 0) {
            const mixin = try hashTransactions(allocator, preallocated_nodes, entry.transactions.items);
            current_hash = current_hash.extendAndHash(&mixin.data);
        } else {
            current_hash = Hash.generateSha256Hash(&current_hash.data);
        }

        if (!current_hash.eql(entry.hash)) {
            return false;
        }
    }

    return true;
}

/// Hash a group of transactions as a merkle tree and return the root node.
///
/// This is typically used to get an Entry's hash for PoH.
///
/// Optionally accepts a pointer to a list of hashes for reuse across calls to
/// minimize the number of allocations when hashing large numbers of entries.
///
/// Based on these agave functions for conformance:
/// - [hash_transactions](https://github.com/anza-xyz/agave/blob/161fc1965bdb4190aa2d7e36c7c745b4661b10ed/entry/src/entry.rs#L215)
/// - [MerkleTree::new](https://github.com/anza-xyz/agave/blob/161fc1965bdb4190aa2d7e36c7c745b4661b10ed/merkle-tree/src/merkle_tree.rs#L98)
fn hashTransactions(
    allocator: std.mem.Allocator,
    preallocated_nodes: ?*std.ArrayListUnmanaged(Hash),
    transactions: []const Transaction,
) Allocator.Error!Hash {
    const LEAF_PREFIX: []const u8 = &.{0};
    const INTERMEDIATE_PREFIX: []const u8 = &.{1};

    var num_signatures: usize = 0;
    for (transactions) |tx| num_signatures += tx.signatures.len;
    if (num_signatures == 0) return Hash.ZEROES;

    var owned_nodes = std.ArrayListUnmanaged(Hash){};
    defer owned_nodes.deinit(allocator);
    const nodes = if (preallocated_nodes) |pn| pn else &owned_nodes;
    const capacity = std.math.log2(num_signatures) + 2 * num_signatures + 1;
    nodes.clearRetainingCapacity();
    try nodes.ensureTotalCapacity(allocator, capacity);

    for (transactions) |tx| for (tx.signatures) |signature| {
        const hash = Hash.hashv(&.{ LEAF_PREFIX, &signature.data });
        nodes.appendAssumeCapacity(hash);
    };

    var level_len = nextLevelLen(num_signatures);
    var level_start = num_signatures;
    var prev_level_len = num_signatures;
    var prev_level_start: usize = 0;
    while (level_len > 0) {
        for (0..level_len) |i| {
            const prev_level_idx = 2 * i;
            const lsib = &nodes.items[prev_level_start + prev_level_idx];
            const rsib = if (prev_level_idx + 1 < prev_level_len)
                &nodes.items[prev_level_start + prev_level_idx + 1]
            else
                // Duplicate last entry if the level length is odd
                &nodes.items[prev_level_start + prev_level_idx];

            const hash = Hash.hashv(&.{ INTERMEDIATE_PREFIX, &lsib.data, &rsib.data });
            nodes.appendAssumeCapacity(hash);
        }
        prev_level_start = level_start;
        prev_level_len = level_len;
        level_start += level_len;
        level_len = nextLevelLen(level_len);
    }

    return nodes.getLast();
}

fn nextLevelLen(level_len: usize) usize {
    return if (level_len == 1) 0 else (level_len + 1) / 2;
}

test "Entry serialization and deserialization" {
    const entry = test_entry.as_struct;
    try sig.bincode.testRoundTrip(entry, &test_entry.as_bytes);
}

pub const test_entry = struct {
    var txns = [_]Transaction{
        sig.core.transaction.transaction_v0_example.as_struct,
        sig.core.transaction.transaction_v0_example.as_struct,
    };

    pub const as_struct = Entry{
        .num_hashes = 149218308,
        .hash = sig.core.Hash
            .parseBase58String("G8T3smgLc4XavAtxScD3u4FTAqPtwbFCEJKwJbfoECcd") catch unreachable,
        .transactions = .{
            .items = txns[0..2],
            .capacity = 2,
        },
    };

    pub const as_bytes = [_]u8{
        4,   228, 228, 8,   0,   0,   0,   0,   224, 199, 210, 235, 148, 143, 98,  241, 248, 45,
        140, 115, 214, 164, 132, 17,  95,  89,  221, 166, 5,   158, 5,   121, 181, 80,  48,  103,
        173, 21,  40,  70,  2,   0,   0,   0,   0,   0,   0,   0,   2,   81,  7,   106, 50,  99,
        54,  99,  92,  187, 47,  10,  170, 102, 132, 42,  25,  4,   26,  67,  106, 76,  132, 119,
        57,  38,  159, 7,   243, 132, 127, 236, 31,  83,  124, 56,  140, 54,  239, 100, 65,  111,
        8,   246, 103, 155, 246, 108, 196, 95,  231, 253, 121, 109, 53,  222, 96,  249, 211, 168,
        197, 148, 38,  209, 4,   184, 105, 238, 157, 236, 93,  219, 197, 154, 48,  106, 71,  230,
        220, 228, 253, 4,   34,  174, 202, 164, 57,  144, 240, 13,  183, 169, 164, 90,  77,  21,
        133, 150, 138, 9,   130, 196, 7,   48,  65,  73,  204, 64,  157, 104, 93,  54,  46,  185,
        1,   192, 88,  55,  179, 181, 207, 170, 11,  183, 143, 104, 116, 71,  4,   128, 39,  12,
        102, 2,   236, 88,  117, 221, 34,  125, 55,  183, 193, 174, 21,  99,  70,  167, 52,  227,
        254, 241, 14,  239, 13,  172, 158, 81,  254, 134, 30,  78,  35,  15,  168, 79,  73,  211,
        242, 100, 122, 21,  163, 216, 62,  58,  230, 205, 163, 112, 95,  100, 134, 113, 98,  129,
        164, 240, 184, 157, 4,   34,  55,  72,  89,  113, 179, 97,  58,  235, 71,  20,  83,  42,
        196, 46,  189, 136, 194, 90,  249, 14,  154, 144, 141, 234, 253, 148, 146, 168, 110, 10,
        237, 82,  157, 190, 248, 20,  215, 105, 1,   100, 2,   1,   3,   32,  104, 232, 42,  254,
        46,  48,  104, 89,  101, 211, 253, 161, 65,  155, 204, 89,  126, 187, 180, 191, 60,  59,
        88,  119, 106, 20,  194, 80,  11,  200, 76,  0,   1,   8,   65,  203, 149, 184, 2,   85,
        213, 101, 44,  13,  181, 13,  65,  128, 17,  94,  229, 31,  215, 47,  49,  72,  57,  158,
        144, 193, 224, 205, 241, 120, 78,  5,   1,   3,   5,   7,   90,  0,   2,   81,  7,   106,
        50,  99,  54,  99,  92,  187, 47,  10,  170, 102, 132, 42,  25,  4,   26,  67,  106, 76,
        132, 119, 57,  38,  159, 7,   243, 132, 127, 236, 31,  83,  124, 56,  140, 54,  239, 100,
        65,  111, 8,   246, 103, 155, 246, 108, 196, 95,  231, 253, 121, 109, 53,  222, 96,  249,
        211, 168, 197, 148, 38,  209, 4,   184, 105, 238, 157, 236, 93,  219, 197, 154, 48,  106,
        71,  230, 220, 228, 253, 4,   34,  174, 202, 164, 57,  144, 240, 13,  183, 169, 164, 90,
        77,  21,  133, 150, 138, 9,   130, 196, 7,   48,  65,  73,  204, 64,  157, 104, 93,  54,
        46,  185, 1,   192, 88,  55,  179, 181, 207, 170, 11,  183, 143, 104, 116, 71,  4,   128,
        39,  12,  102, 2,   236, 88,  117, 221, 34,  125, 55,  183, 193, 174, 21,  99,  70,  167,
        52,  227, 254, 241, 14,  239, 13,  172, 158, 81,  254, 134, 30,  78,  35,  15,  168, 79,
        73,  211, 242, 100, 122, 21,  163, 216, 62,  58,  230, 205, 163, 112, 95,  100, 134, 113,
        98,  129, 164, 240, 184, 157, 4,   34,  55,  72,  89,  113, 179, 97,  58,  235, 71,  20,
        83,  42,  196, 46,  189, 136, 194, 90,  249, 14,  154, 144, 141, 234, 253, 148, 146, 168,
        110, 10,  237, 82,  157, 190, 248, 20,  215, 105, 1,   100, 2,   1,   3,   32,  104, 232,
        42,  254, 46,  48,  104, 89,  101, 211, 253, 161, 65,  155, 204, 89,  126, 187, 180, 191,
        60,  59,  88,  119, 106, 20,  194, 80,  11,  200, 76,  0,   1,   8,   65,  203, 149, 184,
        2,   85,  213, 101, 44,  13,  181, 13,  65,  128, 17,  94,  229, 31,  215, 47,  49,  72,
        57,  158, 144, 193, 224, 205, 241, 120, 78,  5,   1,   3,   5,   7,   90,  0,
    };
};
