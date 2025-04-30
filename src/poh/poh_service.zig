const std = @import("std");
const sig = @import("../sig.zig");
const poh = @import("lib.zig");

const Atomic = std.atomic.Value;

const Channel = sig.sync.Channel;
const Hash = sig.core.Hash;

const Poh = poh.poh.Poh;
const PohRecorder = poh.poh_recorder.PohRecorder;
const PohRecorderError = poh.poh_recorder.PohRecorderError;
const Bank = poh.poh_recorder.Bank;
const WorkingBankEntry = poh.poh_recorder.WorkingBankEntry;

const hash = std.crypto.hash.sha2.Sha256.hash;

const default_hashes_per_tick = 2_000_000 / 160;

/// High level PoH orchestrator that ticks, hashes, and mixes in entries.
/// Delegates to Poh and PohRecorder to run hashes and publish entries.
pub const PohService = struct {
    recorder: PohRecorder,
    next_record: ?Record = null,
    record_receiver: *Channel(Record),
    hashes_per_batch: u64,

    pub fn deinit(self: PohService) void {
        self.recorder.deinit();
    }

    /// Run the next PoH step, which could be to tick, hash, or record an entry.
    pub fn next(self: *PohService) !void {
        if (self.next_record) |record| {
            _ = try self.recorder.record(record.slot, record.mixin, record.transactions);
            // TODO: send
        } else {
            const should_tick = self.recorder.poh.runHash(self.hashes_per_batch);
            if (should_tick) try self.recorder.tick();
        }
        self.next_record = self.record_receiver.tryReceive();
    }
};

pub const PohConfig = struct {
    hashes_per_tick: u64 = default_hashes_per_tick,
    hashes_per_batch: u64 = 64,
    // ticks_per_slot: u64, // used for timing
    // target_ns_per_tick: u64, // used for timing
};

/// Create PohRecorder and run PohService in a loop until poh_exit is set or an
/// unhandled error occurs.
pub fn tickProducer(
    allocator: std.mem.Allocator,
    entries: *Channel(WorkingBankEntry),
    bank: *Bank,
    poh_exit: *Atomic(bool),
    record_receiver: *Channel(Record),
    config: PohConfig,
    start_hash: Hash,
) !void {
    var service = PohService{
        .poh_recorder = PohRecorder.init(allocator, start_hash, config.hashes_per_tick, bank, entries),
        .record_receiver = record_receiver,
        .hashes_per_batch = config.hashes_per_batch,
    };
    while (!poh_exit.load(.monotonic)) {
        try service.next();
    }
}

/// Sent into the PoH service to mix in transaction data and publish an entry for those transactions
pub const Record = struct {
    /// The data to mix in with the final hash of the entry
    mixin: Hash,
    transactions: []const Transaction,
    slot: u64,
    /// Where to send info about the record when it is processed
    sender: PohRecorderError!?usize, // TODO
};

/// Artifact produced by PoH representing the sequence of hashes and
/// transactions leading to a single tick or transaction record.
pub const Entry = struct {
    /// The number of hashes since the previous entry
    num_hashes: u64,
    /// The final hash in the sequence
    hash: Hash,
    /// Any potential transactions, which would have been mixed into the final hash.
    transactions: ?[]const Transaction,
};

/// Represents a Solana transaction but transaction data is not needed in this
/// proof of concept. Just some data to use for the hash.
pub const Transaction = u8;

/// Hack to create a deterministic "hash" value for a group of transactions.
pub fn hashTransactions(tx: []const Transaction) Hash {
    if (tx.len < 32) {
        var hsh: Hash = .{ .data = .{0} ** 32 };
        @memcpy(hsh.data[0..tx.len], tx);
        return hsh;
    }
    return .{ .data = tx[0..32].* };
}
