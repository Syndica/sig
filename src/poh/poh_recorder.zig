const std = @import("std");
const sig = @import("../sig.zig");

const ArrayList = std.ArrayList;
const Instant = std.time.Instant;

const Channel = sig.sync.Channel;
const Hash = sig.core.Hash;

const poh_service = @import("poh_service.zig");
const Poh = @import("poh.zig").Poh;
const PohEntry = @import("poh.zig").PohEntry;
const Entry = poh_service.Entry;
const Transaction = poh_service.Transaction;

const Slot = u64;

pub const PohRecorderError = SendError || error{
    NoTransactionsProvided,
    MaxHeightReached,
    MinHeightNotReached,
};

const SendError = sig.utils.types.ErrorReturn(Channel(WorkingBankEntry).send);

/// Full message that is sent out from PohRecorder when a tick entry is
/// published including the Bank that it was published with.
pub const WorkingBankEntry = struct {
    working_bank: *Bank,
    tick_entry: TickEntry,
};
pub const TickEntry = struct { entry: Entry, tick_height: u64 };

/// Manages the Poh state and sends out tick and transaction record entry
/// messages out as needed.
///
/// This struct and all of its contained data (except sender) is intended to be
/// used in a single thread and would need additional synchronization mechanisms
/// to make it safe to mutate across multiple threads.
pub const PohRecorder = struct {
    /// The current hash state and logic to continue hashing
    poh: Poh,
    /// Count of the number of ticks so far
    tick_height: u64,
    start_bank: *Bank,
    start_tick_height: u64,
    working_bank: ?WorkingBank,
    /// Tick and transaction record entries are sent here to be consumed elsewhere.
    sender: *Channel(WorkingBankEntry),
    leader_first_tick_height_including_grace_ticks: ?u64,
    /// Tick messages that will be sent when the bank is ready
    tick_cache: ArrayList(TickEntry),
    ticks_from_record: u64,
    ticks_per_slot: u64,

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        start_hash: Hash,
        hashes_per_tick: u64,
        bank: *Bank,
        sender: *Channel(WorkingBankEntry),
    ) PohRecorder {
        return PohRecorder{
            .poh = Poh.init(start_hash, hashes_per_tick),
            .tick_height = 0,
            .start_tick_height = 1,
            .start_bank = bank,
            .working_bank = WorkingBank{
                .bank = bank,
                .start = Instant.now() catch @panic("no time"),
            },
            .sender = sender,
            .tick_cache = ArrayList(TickEntry).init(allocator),
            .ticks_from_record = 0, //TODO
            .ticks_per_slot = 0, //TODO
            .leader_first_tick_height_including_grace_ticks = 0, //TODO
        };
    }

    pub fn deinit(self: Self) void {
        self.tick_cache.deinit();
    }

    /// Process a transaction record by calling Poh::record with the mixin hash
    /// and publishing an entry including the transactions
    pub fn record(
        self: *Self,
        _: Slot,
        hash: Hash,
        transactions: []const Transaction,
    ) PohRecorderError!?usize {
        if (transactions.len == 0) {
            return PohRecorderError.NoTransactionsProvided;
        }
        while (true) {
            if (self.working_bank == null) {
                return PohRecorderError.MaxHeightReached;
            }
            var working_bank = &self.working_bank.?;
            try self.flushCache(false);
            if (self.poh.record(hash)) |poh_entry| {
                const entry = Entry{
                    .num_hashes = poh_entry.num_hashes,
                    .hash = poh_entry.hash,
                    .transactions = transactions,
                };
                const tick_entry = TickEntry{ .entry = entry, .tick_height = self.tick_height };
                try self.sender.send(.{ .working_bank = working_bank.bank, .tick_entry = tick_entry });
                const starting_transaction_index = working_bank.transaction_index;
                if (working_bank.transaction_index) |_| {
                    working_bank.transaction_index.? +|= transactions.len;
                }
                return starting_transaction_index;
            }
            self.ticks_from_record += 1;
            try self.tick();
        }
    }

    /// Record a tick using Poh::tick, increment the tick height, and publish an entry for the tick.
    pub fn tick(self: *Self) !void {
        if (self.poh.tick()) |poh_entry| {
            self.tick_height += 1;

            if (self.leader_first_tick_height_including_grace_ticks == null) {
                return;
            }

            try self.tick_cache.append(.{
                .entry = Entry{
                    .num_hashes = poh_entry.num_hashes,
                    .hash = poh_entry.hash,
                    .transactions = null,
                },
                .tick_height = self.tick_height,
            });

            try self.flushCache(true);
        }
    }

    /// Sends the ticks that were queued up by the tick method
    ///
    /// Delays sending ticks until there is a working bank available, then
    /// sends them in a batch up to the maximum tick height.
    pub fn flushCache(self: *Self, is_tick: bool) PohRecorderError!void {
        if (self.working_bank == null) {
            return PohRecorderError.MaxHeightReached;
        }
        var working_bank = &self.working_bank.?;
        if (self.tick_height < working_bank.min_tick_height or is_tick and self.tick_height == working_bank.min_tick_height) {
            return PohRecorderError.MinHeightNotReached;
        }

        const entry_count = for (self.tick_cache.items, 0..) |tick_item, i| {
            if (tick_item.tick_height > working_bank.max_tick_height) {
                break i;
            }
        } else self.tick_cache.items.len;
        var send_result: SendError!void = {};
        if (entry_count > 0) {
            for (self.tick_cache.items, 0..entry_count) |tick_item, _| {
                working_bank.bank.registerTick(&tick_item.entry.hash);
                // TODO: sending a naked pointer, this may become a problem
                send_result = self.sender.send(.{ .working_bank = working_bank.bank, .tick_entry = tick_item });
                send_result catch {
                    break;
                };
            }
        }
        if (self.tick_height >= working_bank.max_tick_height) {
            self.start_bank = working_bank.bank;
            const working_slot = self.start_bank.slot();
            self.start_tick_height = working_slot * self.ticks_per_slot + 1;
            self.clear_bank();
        }
        if (send_result) |_| {
            dropItems(TickEntry, &self.tick_cache, entry_count);
        } else |err| {
            std.debug.print("sender failed with error {}\n", .{err});
            self.clear_bank();
        }
    }

    pub fn clear_bank(self: *Self) void {
        if (self.working_bank) |working_bank| {
            std.debug.print("\ndone leading\n", .{});
            self.working_bank = null;
            _ = working_bank;
        }
        // TODO
    }
};

/// Manages the state of the bank being used by the PohRecorder
const WorkingBank = struct {
    bank: *Bank,
    start: Instant,
    min_tick_height: u64 = 0, // TODO
    max_tick_height: u64 = std.math.maxInt(u64), // TODO
    transaction_index: ?usize = null, // TODO
};

/// Stub to only represent direct interactions with PoH
pub const Bank = struct {
    fn registerTick(_: *@This(), _: *const Hash) void {}
    fn slot(_: *@This()) Slot {
        return 0;
    }
};

pub fn dropItems(comptime T: type, list: *std.ArrayList(T), n: usize) void {
    if (n == 0) {
        return;
    }
    if (n > list.items.len) {
        for (list.items[n .. list.items.len - 1], 0..) |*b, i| {
            b.* = list.items[i + 1];
        }
    }
    list.items.len = list.items.len - n;
}
