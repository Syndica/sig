const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");

const core = sig.core;

const Allocator = std.mem.Allocator;

const ThreadPool = sig.sync.ThreadPool;

const Slot = core.Slot;

const AccountsDB = sig.accounts_db.AccountsDB;
const BlockstoreReader = sig.ledger.BlockstoreReader;

const ProgressMap = sig.consensus.ProgressMap;

const ConfirmSlotError = replay.confirm_slot.ConfirmSlotError;
const ConfirmSlotFuture = replay.confirm_slot.ConfirmSlotFuture;
const EpochTracker = replay.trackers.EpochTracker;
const SlotTracker = replay.trackers.SlotTracker;
const VerifyTicksConfig = replay.confirm_slot.VerifyTicksParams;

const confirmSlot = replay.confirm_slot.confirmSlot;

const ScopedLogger = sig.trace.ScopedLogger("replay-execution");

/// State used for replaying and validating data from blockstore/accountsdb/svm
pub const ReplayExecutionState = struct {
    allocator: Allocator,
    logger: ScopedLogger,
    accounts_db: *AccountsDB,
    thread_pool: *ThreadPool,
    blockstore_reader: *BlockstoreReader,
    slot_tracker: SlotTracker,
    epochs: EpochTracker,
    progress_map: ProgressMap,

    pub fn init(
        allocator: Allocator,
        logger: sig.trace.Logger,
        thread_pool: *ThreadPool,
        epoch_schedule: core.EpochSchedule,
        accounts_db: *AccountsDB,
        blockstore_reader: *BlockstoreReader,
    ) Allocator.Error!ReplayExecutionState {
        _ = thread_pool; // autofix
        return .{
            .allocator = allocator,
            .logger = ScopedLogger.from(logger),
            .accounts_db = accounts_db,
            .blockstore_reader = blockstore_reader,
            .slot_tracker = .{},
            .epochs = .{ .schedule = epoch_schedule },
            .progress_map = ProgressMap.INIT,
        };
    }

    pub fn deinit(self: ReplayExecutionState) void {
        self.epochs.deinit(self.allocator);
    }
};

/// Analogous to [replay_active_banks](https://github.com/anza-xyz/agave/blob/3f68568060fd06f2d561ad79e8d8eb5c5136815a/core/src/replay_stage.rs#L3356)
pub fn replayActiveSlots(state: *ReplayExecutionState) !bool {
    // TODO: parallel processing: https://github.com/anza-xyz/agave/blob/3f68568060fd06f2d561ad79e8d8eb5c5136815a/core/src/replay_stage.rs#L3401

    const active_slots = try state.slot_tracker.activeSlots(state.allocator);
    if (active_slots.len == 0) {
        return false;
    }

    for (active_slots) |slot| {
        _ = try replaySlot(state, slot);
    }

    // TODO: process_replay_results: https://github.com/anza-xyz/agave/blob/3f68568060fd06f2d561ad79e8d8eb5c5136815a/core/src/replay_stage.rs#L3443

    return undefined;
}

/// Analogous to [ReplaySlotFromBlockstore](https://github.com/anza-xyz/agave/blob/161fc1965bdb4190aa2d7e36c7c745b4661b10ed/core/src/replay_stage.rs#L175)
const ReplayResult = union(enum) {
    /// Replay succeeded with this many transactions.
    success: struct { transaction_count: usize },
    /// The slot was previously marked as dead, so it was not replayed.
    dead,
    /// Replay failed due to this error.
    failure: ConfirmSlotError,
};

/// replay_active_bank
fn replaySlot(state: *ReplayExecutionState, bank_slot: Slot) !ConfirmSlotFuture {
    const fork_progress = try state.progress_map.map.getOrPut(state.allocator, bank_slot);
    if (fork_progress.found_existing and fork_progress.value_ptr.is_dead) {
        return .dead;
    }

    const slot_info = state.slot_tracker.slots.get(bank_slot) orelse return error.MissingSlot;
    const epoch_info = state.epochs.getForSlot(bank_slot) orelse return error.MissingEpoch;

    const slot = bank_slot;
    const start_shred = 0; // TODO: progress.num_shreds;
    // TODO: measure time
    const entries, const num_shreds, const slot_is_full =
        try state.blockstore_reader.getSlotEntriesWithShredInfo(bank_slot, start_shred, false);
    _ = num_shreds; // autofix

    const verify_ticks_config = VerifyTicksConfig{
        .tick_height = slot_info.state.tickHeight(),
        .max_tick_height = slot_info.constants.max_tick_height,
        .hashes_per_tick = epoch_info.hashes_per_tick,
        .slot = slot,
        .slot_is_full = slot_is_full,
    };
    _ = verify_ticks_config; // autofix

    const replay_progress = &fork_progress.value_ptr.replay_progress.arc_ed.rwlock_ed;

    return try confirmSlot(
        state.allocator,
        state.logger,
        entries.items,
        replay_progress.last_entry,
        .{
            .tick_height = slot_info.state.tickHeight(),
            .max_tick_height = slot_info.constants.max_tick_height,
            .hashes_per_tick = epoch_info.hashes_per_tick,
            .slot = slot,
            .slot_is_full = slot_is_full,
        },
    );
}
