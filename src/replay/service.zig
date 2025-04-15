const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");

const deps = replay.deps;

const Allocator = std.mem.Allocator;

const AsyncEntryVerifier = sig.core.entry.AsyncEntryVerifier;
const BlockstoreReader = sig.ledger.BlockstoreReader;
const Entry = sig.core.Entry;
const Hash = sig.core.Hash;
const Slot = sig.core.Slot;

const BankForks = deps.BankForks;
const ProgressMap = deps.ProgressMap;
const Bank = deps.Bank;
const Tower = deps.Tower;
const tower_storage = deps.tower_storage;

const ScopedLogger = sig.trace.ScopedLogger("replay");

const ReplayState = struct {
    tower: Tower,
    bank_forks: BankForks,
    blockstore_reader: BlockstoreReader,

    fn init() ReplayState {
        const tower = try tower_storage.load() orelse Tower.init();
        return .{ .tower = tower };
    }
};

fn run(state: ReplayState) void {
    while (true) iterate(state);
}

fn iterate(state: ReplayState) void {
    // TODO: generate_new_bank_forks

    // TODO: replay_active_banks
    replayActiveBanks(&state.bank_forks);

    // TODO: process_ancestor_hashes_duplicate_slots

    // TODO: process_duplicate_confirmed_slots

    // TODO: process_gossip_verified_vote_hashes

    // TODO: process_popular_pruned_forks

    // TODO: process_duplicate_slots

    // TODO: for each slot:
    //           tower_duplicate_confirmed_forks
    //           mark_slots_duplicate_confirmed

    // TODO: select_forks

    // TODO: check_for_vote_only_mode

    // TODO: select_vote_and_reset_forks

    // TODO: if vote_bank.is_none: maybe_refresh_last_vote

    // TODO: handle_votable_bank

    // TODO: if reset_bank: Reset onto a fork

    // TODO: dump_then_repair_correct_slots

    // TODO: maybe_start_leader
}

// Analogous to [replay_active_banks](https://github.com/anza-xyz/agave/blob/3f68568060fd06f2d561ad79e8d8eb5c5136815a/core/src/replay_stage.rs#L3356)
fn replayActiveBanks(allocator: Allocator, bank_forks: *BankForks) bool {
    // TODO: parallel processing: https://github.com/anza-xyz/agave/blob/3f68568060fd06f2d561ad79e8d8eb5c5136815a/core/src/replay_stage.rs#L3401

    const active_bank_slots = try bank_forks.activeBankSlots(allocator);
    if (active_bank_slots.len == 0) {
        return false;
    }

    // TODO: process_replay_results: https://github.com/anza-xyz/agave/blob/3f68568060fd06f2d561ad79e8d8eb5c5136815a/core/src/replay_stage.rs#L3443
}

const ReplaySlotFromBlockstore = struct {
    is_slot_dead: bool,
    bank_slot: Slot,
    replay_result: ?BlockstoreProcessorError!usize,
};

const ReplayActiveBankError = Allocator.Error | error{BankNotFound};

fn replayActiveBank(
    allocator: Allocator,
    logger: ScopedLogger,
    blockstore_reader: *const BlockstoreReader,
    bank_forks: *BankForks,
    progress: *ProgressMap,
    bank_slot: Slot,
) ReplayActiveBankError!void {
    var replay_result = ReplaySlotFromBlockstore{
        .is_slot_dead = false,
        .bank_slot = bank_slot,
        .replay_result = null,
    };
    const fork_progress = try progress.map.getOrPut(allocator, bank_slot);
    if (fork_progress.found_existing and fork_progress.value_ptr.is_dead) {
        replay_result.is_slot_dead = true;
        return replay_result;
    }
    // TODO prepare Bank and ForkProgress
    const bank = bank_forks.banks.get(bank_slot) orelse return error.MissingBank;

    const slot = bank_slot;
    const start_shred = 0; // TODO: progress.num_shreds;
    // TODO: measure time
    const entries, const num_shreds, const slot_is_full =
        try blockstore_reader.getSlotEntriesWithShredInfo(bank_slot, start_shred, false);
    _ = num_shreds; // autofix

    try confirmSlotEntries(logger, bank, entries, slot, slot_is_full, false, false);
}

pub const ConfirmationProgress = struct {
    last_entry: Hash,
    tick_hash_count: u64,
    num_shreds: u64,
    num_entries: usize,
    num_txs: usize,
};

/// Placeholder to represent that we will need to introduce a synchronization
/// mechanism for the contained data eventually, but it's not needed currently
/// since it's not yet used in a multithreaded context.
pub fn PseudoMux(T: type) type {
    return struct { get: T };
}

/// agave: confirm_slot
fn confirmSlotEntries(
    entry_verifier: *AsyncEntryVerifier,
    progress: *ConfirmationProgress,
    logger: ScopedLogger,
    bank: *const Bank,
    entries: []const Entry,
    slot: Slot,
    slot_is_full: bool,
    allow_dead_slots: bool,
) BlockstoreProcessorError!void {
    _ = slot; // autofix
    _ = allow_dead_slots; // autofix
    // TODO: send each entry to entry notification sender
    try verifyTicks(logger, bank, entries, slot_is_full, progress.get.tick_hash_count);
    entry_verifier.start(progress.get.last_entry, entries);

    // TODO: verify transaction signatures:
    //     TODO: call entry::start_verify_transactions
    //     TODO: return error on failure
    // TODO: executes entry transactions and verify results
    //     TODO: call process_entries
    // TODO: entry::finish_verify
    entry_verifier.finish();
}

const BlockstoreProcessorError = BlockError;

/// Verify that a segment of entries has the correct number of ticks and hashes
/// analogous to [verify_ticks](https://github.com/anza-xyz/agave/blob/161fc1965bdb4190aa2d7e36c7c745b4661b10ed/ledger/src/blockstore_processor.rs#L1097)
fn verifyTicks(
    logger: ScopedLogger,
    bank: *const Bank,
    entries: []const Entry,
    slot_full: bool,
    tick_hash_count: *u64,
) BlockError!void {
    const next_bank_tick_height = bank.tickHeight() + Entry.slice.tickCount(entries);
    const max_bank_tick_height = bank.max_tick_height;

    if (next_bank_tick_height > max_bank_tick_height) {
        logger.warn().logf("Too many entry ticks found in slot: {}", .{bank.slot});
        return error.TooManyTicks;
    }

    if (next_bank_tick_height < max_bank_tick_height and slot_full) {
        logger.info().logf("Too few entry ticks found in slot: {}", .{bank.slot});
        return error.TooFewTicks;
    }

    if (next_bank_tick_height == max_bank_tick_height) {
        if (entries.len == 0 or !entries[entries.len - 1].isTick()) {
            logger.warn().logf("Slot: {} did not end with a tick entry", .{bank.slot});
            return error.TrailingEntry;
        }

        if (!slot_full) {
            logger.warn().logf("Slot: {} was not marked full", .{bank.slot});
            return error.InvalidLastTick;
        }
    }

    const hashes_per_tick = bank.hashes_per_tick orelse 0;
    if (!Entry.slice.verifyTickHashCount(tick_hash_count, hashes_per_tick)) {
        logger.warn().logf("Tick with invalid number of hashes found in slot: {}", bank.slot);
        return error.InvalidTickHashCount;
    }
}

pub const BlockError = error{
    /// Block did not have enough ticks was not marked full
    /// and no shred with is_last was seen.
    Incomplete,

    /// Block entries hashes must all be valid
    InvalidEntryHash,

    /// Blocks must end in a tick that has been marked as the last tick.
    InvalidLastTick,

    /// Blocks can not have missing ticks
    /// Usually indicates that the node was interrupted with a more valuable block during
    /// production and abandoned it for that more-favorable block. Leader sent data to indicate
    /// the end of the block.
    TooFewTicks,

    /// Blocks can not have extra ticks
    TooManyTicks,

    /// All ticks must contain the same number of hashes within a block
    InvalidTickHashCount,

    /// Blocks must end in a tick entry, trailing transaction entries are not allowed to guarantee
    /// that each block has the same number of hashes
    TrailingEntry,

    DuplicateBlock,
};

fn @"Reset onto a fork"() void {
    // if last reset is last blockhash, get active descendants and set them
    // else, do the rest...

    // load new tower if identity changed

    // reset_poh_recorder

    // update partition info
}

fn generate_new_bank_forks() void {}
