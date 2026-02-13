const std = @import("std");
const std14 = @import("std14");
const sig = @import("../sig.zig");

const Hash = sig.core.Hash;
const verifyPoh = sig.core.entry.verifyPoh;
const assert = std.debug.assert;

/// Tracks the latest hash value and tick counts, and updates it with new hashes
pub const Poh = struct {
    /// Latest hash value
    latest_hash: Hash,
    /// Number of hashes since the last entry
    num_hashes: u64,
    /// Static number of hashes expected between tick entries
    hashes_per_tick: u64,
    /// Current remaining number of hashes until the next tick
    remaining_hashes: u64,
    /// Counter for the number of ticks that happened so far
    tick_count: u64,

    pub fn init(start_hash: Hash, hashes_per_tick: u64, starting_tick_count: u64) Poh {
        return .{
            .latest_hash = start_hash,
            .num_hashes = 0,
            .hashes_per_tick = hashes_per_tick,
            .remaining_hashes = hashes_per_tick,
            .tick_count = starting_tick_count,
        };
    }

    /// re-hash the existing hash repeatedly without any mixin hashes.
    ///
    /// stops hashing when it hashes up to as many times as either:
    /// - state `self.remaining_hashes - 1`
    /// - parameter `max_num_hashes`
    pub fn hash(self: *Poh, max_num_hashes: u64) bool {
        const num_hashes = @min(self.remaining_hashes -| 1, max_num_hashes);
        Hash.hashRepeated(&self.latest_hash, &self.latest_hash, num_hashes);
        self.num_hashes += num_hashes;
        self.remaining_hashes -= num_hashes;

        assert(self.remaining_hashes != 0);
        return self.remaining_hashes == 1;
    }

    /// Definitively records the mixin. If a tick is needed, ticks first before
    /// recording the mixin.
    ///
    /// Calling this function when hashes_per_tick < 2 has undefined behavior.
    pub fn recordAndMaybeTick(self: *Poh, mixin: Hash) struct {
        maybe_tick: ?PohEntry,
        record: PohEntry,
    } {
        assert(self.hashes_per_tick > 1);
        var maybe_tick: ?PohEntry = null;
        if (self.remaining_hashes == 1) maybe_tick = self.tick().?;
        const record = self.tryRecord(mixin).?;
        return .{ .maybe_tick = maybe_tick, .record = record };
    }

    /// Calculate the hash for an entry containing a mixin hash, such as a
    /// transaction record
    ///
    /// If this returns null, that means you need to tick first and then try
    /// processing this record again.
    pub fn tryRecord(self: *Poh, mixin: Hash) ?PohEntry {
        if (self.remaining_hashes == 1) {
            return null; // needs a tick first
        }

        self.latest_hash = self.latest_hash.extend(&mixin.data);
        const num_hashes = self.num_hashes + 1;
        self.num_hashes = 0;
        self.remaining_hashes -= 1;

        return .{
            .num_hashes = num_hashes,
            .hash = self.latest_hash,
        };
    }

    /// Calculate the hash for a tick entry, without a mixin hash, and increment
    /// the tick counter
    pub fn tick(self: *Poh) ?PohEntry {
        self.latest_hash = .init(&self.latest_hash.data);
        self.num_hashes += 1;
        self.remaining_hashes -= 1;

        // TODO: low power mode
        if (self.remaining_hashes != 0) {
            return null;
        }

        const num_hashes = self.num_hashes;
        self.remaining_hashes = self.hashes_per_tick;
        self.num_hashes = 0;
        self.tick_count += 1;

        return .{
            .num_hashes = num_hashes,
            .hash = self.latest_hash,
        };
    }
};

/// The output from a sequence of hashes
pub const PohEntry = struct {
    /// Number of hashes since the previous entry this is derived from.
    num_hashes: u64,
    /// The final resulting hash from this sequence.
    hash: Hash,
};

/// returns a valid PoH chain of entries with transactions that have valid signatures.
pub fn testPoh(
    valid_signatures: bool,
    include_account_conflict: bool,
) !struct { Poh, std14.BoundedArray(sig.core.Entry, 7) } {
    const allocator = std.testing.allocator;
    const expect = std.testing.expect;
    const expectEqual = std.testing.expectEqual;
    const Transaction = sig.core.Transaction;
    const hashTransactions = sig.core.entry.hashTransactions;

    var rng = std.Random.DefaultPrng.init(std.testing.random_seed);

    var seed: [32]u8 = undefined;
    rng.random().bytes(&seed);
    const shared_payer: ?std.crypto.sign.Ed25519.KeyPair = if (include_account_conflict)
        try .generateDeterministic(seed)
    else
        null;

    var a_transaction = try Transaction.initRandom(allocator, rng.random(), shared_payer);
    if (!valid_signatures) {
        const sigs = try allocator.dupe(sig.core.Signature, a_transaction.signatures);
        allocator.free(a_transaction.signatures);
        a_transaction.signatures = sigs;
        sigs[0].r[0] +%= 1;
    }

    var transactions = [_]Transaction{
        a_transaction,
        try Transaction.initRandom(allocator, rng.random(), shared_payer),
        try Transaction.initRandom(allocator, rng.random(), null),
        try Transaction.initRandom(allocator, rng.random(), null),
        try Transaction.initRandom(allocator, rng.random(), null),
        try Transaction.initRandom(allocator, rng.random(), null),
    };

    const batch1 = try allocator.dupe(Transaction, transactions[0..2]);
    const batch2 = try allocator.dupe(Transaction, transactions[2..3]);
    const batch3 = try allocator.dupe(Transaction, transactions[3..6]);

    const mixin1 = hashTransactions(batch1);
    const mixin2 = hashTransactions(batch2);
    const mixin3 = hashTransactions(batch3);

    var poh = Poh.init(.ZEROES, 20, 0);

    var entries = try std14.BoundedArray(sig.core.Entry, 7).init(0);

    try expect(!poh.hash(18));
    try expect(poh.hash(100));
    try expectEqual(null, poh.tryRecord(mixin1));

    const entry = struct {
        pub fn init(poh_entry: PohEntry, txs: []const Transaction) sig.core.Entry {
            return .{
                .num_hashes = poh_entry.num_hashes,
                .hash = poh_entry.hash,
                .transactions = txs,
            };
        }
    };

    // record/tick negotiation
    const result1 = poh.recordAndMaybeTick(mixin1);
    try entries.append(entry.init(result1.maybe_tick.?, &.{}));
    try entries.append(entry.init(result1.record, batch1));

    try expect(!poh.hash(10));

    // just record
    const result2 = poh.recordAndMaybeTick(mixin2);
    try expectEqual(null, result2.maybe_tick);
    try entries.append(entry.init(result2.record, batch2));

    // tick/hash negotiation
    try expectEqual(null, poh.tick());
    try expect(poh.hash(20));
    try entries.append(entry.init(poh.tick().?, &.{}));
    try expect(!poh.hash(18));
    try expectEqual(null, poh.tick());
    try entries.append(entry.init(poh.tick().?, &.{}));

    // just record
    const result3 = poh.tryRecord(mixin3).?;
    try entries.append(entry.init(result3, batch3));

    // end with a tick
    try expect(poh.hash(20));
    try entries.append(entry.init(poh.tick().?, &.{}));

    return .{ poh, entries };
}

test Poh {
    const allocator = std.testing.allocator;

    _, var entry_array = try testPoh(true, false);
    const entries: []sig.core.Entry = entry_array.slice();
    defer for (entries) |entry| entry.deinit(allocator);

    try std.testing.expectEqual(7, entries.len);
    try std.testing.expect(verifyPoh(entries, .ZEROES));

    entries[1].hash = .ZEROES;
    try std.testing.expect(!verifyPoh(entries, .ZEROES));
}
