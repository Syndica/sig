//! A continuously running service that flushes, cleans, shrinks, and purges
//! accounts from accountsdb.

const std = @import("std");
const sig = @import("../sig.zig");
const builtin = @import("builtin");
const zstd = @import("zstd");
const tracy = @import("tracy");

const Allocator = std.mem.Allocator;
const ArrayList = std.array_list.Managed;

const Account = sig.core.Account;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const BankFields = sig.core.BankFields;

const AccountsDB = sig.accounts_db.db.AccountsDB;
const AccountFile = sig.accounts_db.accounts_file.AccountFile;
const FileId = sig.accounts_db.accounts_file.FileId;
const AccountRef = sig.accounts_db.index.AccountRef;
const BufferPool = sig.accounts_db.buffer_pool.BufferPool;
const SnapshotGenerationInfo = AccountsDB.SnapshotGenerationInfo;

const Logger = sig.trace.log.Logger("accounts_db.manager");

const DB_MANAGER_LOOP_MIN = sig.time.Duration.fromSecs(5);
const ACCOUNT_FILE_SHRINK_THRESHOLD = 70; // shrink account files with more than X% dead bytes

pub const Config = struct {
    /// default copied from Agave
    slots_per_full_snapshot: u64 = 100_000,
    /// default copied from Agave
    slots_per_incremental_snapshot: u64 = 100,
    /// 0 => no thread spawning
    zstd_nb_workers: u31 = 0,
    /// Enable/disable the clean (+ shrink & purge) cycle. Keep this disabled if you don't want to
    /// overwrite previous slots.
    /// Currently, we don't want to mutate the account files of older slots, as this
    /// would invalidate the index made from the snapshot.
    do_cleaning: bool = false,
};

/// Flushes a rooted slot to accountsdb, creating a new AccountFile, and doing some cleanup of old
/// AccountFiles.
pub fn onSlotRooted(
    allocator: std.mem.Allocator,
    db: *AccountsDB,
    newly_rooted_slot: Slot,
    lamports_per_signature: u64,
) !void {
    const zone = tracy.Zone.init(@src(), .{ .name = "onSlotRooted" });
    defer zone.deinit();
    errdefer zone.color(0xFF0000);

    const config = db.on_root_config;

    {
        var max_slots, var max_slots_lg = db.max_slots.writeWithLock();
        defer max_slots_lg.unlock();
        if (max_slots.rooted) |previously_rooted| {
            if (newly_rooted_slot < previously_rooted) {
                db.logger.err().logf(
                    "onSlotRooted called on previously rooted slot ({} < {})",
                    .{ newly_rooted_slot, previously_rooted },
                );
                return error.SlotNotFound;
            }
        }
        max_slots.rooted = newly_rooted_slot;

        if (max_slots.flushed) |previously_flushed| {
            if (newly_rooted_slot < previously_flushed) {
                db.logger.err().logf(
                    "onSlotRooted called on previously flushed slot ({} < {})",
                    .{ newly_rooted_slot, previously_flushed },
                );
            }
        }
    }

    db.logger.info().logf("flushing slot {} to disk", .{newly_rooted_slot});

    var failed: bool = false;
    defer if (!failed) {
        db.logger.info().logf("successfully flushed slot {} to disk", .{newly_rooted_slot});
        tracy.frameMarkNamed("rooted slots flushed");
    };
    errdefer |err| {
        db.logger.err().logf(
            "failed to flushed slot {} to disk, err: {}",
            .{ newly_rooted_slot, err },
        );
        failed = true;
    }

    // make a new AccountFile for our newly rooted slot, and "flush" the data to it
    const file_id = try flushSlot(db, newly_rooted_slot);

    {
        var max_slots, var max_slots_lg = db.max_slots.writeWithLock();
        defer max_slots_lg.unlock();
        max_slots.flushed = newly_rooted_slot;
    }

    // when we last made a full snapshot, and when we last made an incremental snapshot (relative to
    // the last full snapshot).
    const latest_full_snapshot_slot, const latest_inc_snapshot = blk: {
        const snapshot_gen_info = db.latest_snapshot_gen_info.readCopy() orelse
            break :blk .{ 0, 0 };
        const incremental_info = snapshot_gen_info.inc orelse
            break :blk .{ snapshot_gen_info.full.slot, 0 };
        break :blk .{ snapshot_gen_info.full.slot, incremental_info.slot };
    };

    // TODO: this should be configurable - leaving disabled until snapshot generation is fixed
    const snapshot_generation_enabled = builtin.is_test;

    const make_full_snapshot = snapshot_generation_enabled and newly_rooted_slot >=
        latest_full_snapshot_slot + config.slots_per_full_snapshot;
    const make_inc_snapshot = snapshot_generation_enabled and !make_full_snapshot and
        newly_rooted_slot >=
            latest_inc_snapshot + latest_full_snapshot_slot + config.slots_per_incremental_snapshot;

    // TODO: might be a good idea to move snapshot creation to another thread
    if (make_full_snapshot or make_inc_snapshot) {
        // set up ztd compression for snapshot generation
        const zstd_buffer = try allocator.alloc(u8, zstd.Compressor.recommOutSize());
        defer allocator.free(zstd_buffer);
        const zstd_compressor = try zstd.Compressor.init(.{ .nb_workers = config.zstd_nb_workers });
        defer zstd_compressor.deinit();

        // TODO: get rid of this once `generateFullSnapshot` can actually
        // derive this data correctly by itdb.
        var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
        var tmp_bank_fields = try BankFields.initRandom(allocator, prng.random(), 128);
        defer tmp_bank_fields.deinit(allocator);

        _ = lamports_per_signature;

        // if (make_full_snapshot) {
        //     db.logger.info().logf(
        //         "accountsdb[manager]: generating full snapshot at slot {d}",
        //         .{newly_rooted_slot},
        //     );

        //     const result = try db.generateFullSnapshotWithCompressor(
        //         zstd_compressor,
        //         zstd_buffer,
        //         .{
        //             .target_slot = newly_rooted_slot,
        //             .bank_fields = &tmp_bank_fields,
        //             .lamports_per_signature = lamports_per_signature,
        //             .old_snapshot_action = .delete_old,
        //         },
        //     );

        //     const gen_info: *?SnapshotGenerationInfo, var gen_info_lg =
        //         db.latest_snapshot_gen_info.writeWithLock();
        //     defer gen_info_lg.unlock();

        //     const prev = gen_info.*.?; // value set in generateFullSnapshotWithCompressor
        //     std.debug.assert(newly_rooted_slot == prev.full.slot);

        //     gen_info.* = .{
        //         .full = .{
        //             .capitalization = result.capitalization,
        //             .hash = result.hash,
        //             .slot = newly_rooted_slot,
        //         },
        //         .inc = null,
        //     };
        // }

        // const has_made_full_snapshot = blk: {
        //     const maybe_gen_info, var gen_info_lg = db.latest_snapshot_gen_info.readWithLock();
        //     defer gen_info_lg.unlock();
        //     break :blk maybe_gen_info.* != null;
        // };

        // if (make_inc_snapshot and has_made_full_snapshot) {
        //     std.debug.assert(!make_full_snapshot);

        //     db.logger.info().logf(
        //         "accountsdb[manager]: generating incremental snapshot from {d} to {d}",
        //         .{ latest_full_snapshot_slot, newly_rooted_slot },
        //     );
        //     const result = try db.generateIncrementalSnapshotWithCompressor(
        //         zstd_compressor,
        //         zstd_buffer,
        //         .{
        //             .target_slot = newly_rooted_slot,
        //             .bank_fields = &tmp_bank_fields,
        //             .lamports_per_signature = lamports_per_signature,
        //             .old_snapshot_action = .delete_old,
        //         },
        //     );

        //     const maybe_gen_info: *?SnapshotGenerationInfo, var gen_info_lg =
        //         db.latest_snapshot_gen_info.writeWithLock();
        //     defer gen_info_lg.unlock();

        //     const gen_info = &((maybe_gen_info.*) orelse
        //         @panic("illegal state - snapshot_gen_info (previously non-null) is now null"));

        // gen_info.inc = .{
        //     .hash = result.incremental_hash,
        //     .slot = newly_rooted_slot,
        // };
        // }
    }

    if (config.do_cleaning) {
        // TODO: change APIs of {clean, shrink, delete}AccountFiles to take single accounts, and stop
        // doing this.
        // TODO: could use an arena allocator for this whole function
        var to_shrink: std.AutoArrayHashMapUnmanaged(FileId, void) = .empty;
        defer to_shrink.deinit(allocator);
        var to_delete: std.AutoArrayHashMapUnmanaged(FileId, void) = .empty;
        defer to_delete.deinit(allocator);

        const clean_result = try cleanAccountFiles(
            allocator,
            db,
            newly_rooted_slot,
            &.{file_id},
            &to_shrink,
            &to_delete,
        );
        _ = clean_result;

        // shrink any account files which have been cleaned
        const shrink_result = try shrinkAccountFiles(
            allocator,
            db,
            to_shrink.keys(),
            &to_delete,
        );
        _ = shrink_result;

        // delete any empty account files
        try deleteAccountFiles(db, to_delete.keys());
    }
}

/// flushes a slot account data from the cache onto disk, and updates the index
/// note: this deallocates the []account and []pubkey data from the cache, as well
/// as the data field ([]u8) for each account.
/// Returns the unclean file id.
fn flushSlot(db: *AccountsDB, slot: Slot) !FileId {
    const zone = tracy.Zone.init(@src(), .{ .name = "accountsdb flushSlot" });
    defer zone.deinit();
    errdefer zone.color(0xFF0000);

    var timer = sig.time.Timer.start();

    defer db.metrics.number_files_flushed.inc();

    var pubkeys_and_accounts = blk: {
        // NOTE: flush should be the only function to delete/free cache slices of a flushed slot
        // -- purgeSlot removes slices but we should never purge rooted slots
        const unrooted_accounts, var unrooted_accounts_lg = db.unrooted_accounts.readWithLock();
        defer unrooted_accounts_lg.unlock();

        const pubkeys_and_accounts = unrooted_accounts.get(slot) orelse return error.SlotNotFound;
        break :blk pubkeys_and_accounts;
    };

    // create account file which is big enough
    var size: usize = 0;
    for (pubkeys_and_accounts.items(.account)) |*account| {
        const account_size_in_file = account.getSizeInFile();
        size += account_size_in_file;
        db.metrics.flush_account_file_size.observe(account_size_in_file);
    }

    const file, const file_id = try db.createAccountFile(size, slot);
    errdefer file.close();

    const offsets = try db.allocator.alloc(u64, pubkeys_and_accounts.len);
    defer db.allocator.free(offsets);

    var file_size: usize = 0;
    for (pubkeys_and_accounts.items(.account)) |account| file_size += account.getSizeInFile();

    var account_file_buf = std.array_list.Managed(u8).init(db.allocator);
    defer account_file_buf.deinit();

    var current_offset: u64 = 0;
    for (
        offsets,
        pubkeys_and_accounts.items(.account),
        pubkeys_and_accounts.items(.pubkey),
    ) |*offset, account, pubkey| {
        try account_file_buf.resize(account.getSizeInFile());

        offset.* = current_offset;
        // write the account to the file
        const bytes_written = account.serialize(&pubkey, account_file_buf.items);
        current_offset += bytes_written;

        if (bytes_written != account.getSizeInFile()) unreachable;
        try file.writeAll(account_file_buf.items);
    }

    var account_file = try AccountFile.init(file, .{
        .id = file_id,
        .length = current_offset,
    }, slot);
    account_file.number_of_accounts = pubkeys_and_accounts.len;

    // update the file map
    {
        const file_map, var file_map_lg = db.file_map.writeWithLock();
        defer file_map_lg.unlock();
        try file_map.putNoClobber(db.allocator, file_id, account_file);
    }

    db.metrics.flush_accounts_written.add(account_file.number_of_accounts);

    // update the reference AFTER the data exists
    for (pubkeys_and_accounts.items(.pubkey), offsets) |pubkey, offset| {
        const head_ref, var head_reference_lg =
            db.account_index.pubkey_ref_map.getWrite(&pubkey) orelse return error.PubkeyNotFound;
        defer head_reference_lg.unlock();

        // find the slot in the reference list
        var curr_ref: ?*AccountRef = head_ref.ref_ptr;
        const did_update = while (curr_ref) |ref| : (curr_ref = ref.next_ptr) {
            if (ref.slot == slot) {
                ref.location = .{ .file = .{ .file_id = file_id, .offset = offset } };
                // NOTE: we break here because we dont allow multiple account states per slot
                // NOTE: if there are multiple states, then it will likely break during clean
                // trying to access a .file location which is actually still .unrooted_map (bc it
                // was never updated)
                break true;
            }
        } else false;
        std.debug.assert(did_update);
    }

    // TODO: prom metrics
    // db.logger.debug().logf("flushed {} accounts, totalling size {}",
    // .{ account_file.number_of_accounts, size });

    // remove old references
    {
        const unrooted_accounts, var unrooted_accounts_lg = db.unrooted_accounts.writeWithLock();
        defer unrooted_accounts_lg.unlock();

        // remove from cache map
        const did_remove = unrooted_accounts.remove(slot);
        std.debug.assert(did_remove);

        // free slices
        for (pubkeys_and_accounts.items(.account)) |account| account.data.deinit(db.allocator);
        pubkeys_and_accounts.deinit(db.allocator);
    }

    db.metrics.time_flush.observe(timer.read().asNanos());

    // return to queue for cleaning
    return file_id;
}

/// removes stale accounts and zero-lamport accounts from disk
/// including removing the account from the index and updating the account files
/// dead bytes. this also queues accounts for shrink or deletion if they contain
/// a small number of 'alive' accounts.
///
/// note: this method should not be called in parallel to shrink or delete.
fn cleanAccountFiles(
    allocator: Allocator,
    db: *AccountsDB,
    rooted_slot_max: Slot,
    unclean_account_files: []const FileId,
    shrink_account_files: *std.AutoArrayHashMapUnmanaged(FileId, void),
    delete_account_files: *std.AutoArrayHashMapUnmanaged(FileId, void),
) !struct {
    num_zero_lamports: usize,
    num_old_states: usize,
} {
    const zone = tracy.Zone.init(@src(), .{ .name = "accountsdb cleanAccountFiles" });
    defer zone.deinit();

    var timer = sig.time.Timer.start();

    const number_of_files = unclean_account_files.len;
    defer db.metrics.number_files_cleaned.add(number_of_files);

    var num_zero_lamports: usize = 0;
    var num_old_states: usize = 0;

    // TODO: move this out into a CleanState struct to reduce allocations
    // track then delete all to avoid deleting while iterating
    var references_to_delete = std.array_list.Managed(struct { pubkey: Pubkey, slot: Slot })
        .init(db.allocator);
    defer references_to_delete.deinit();

    // track so we dont double delete
    var cleaned_pubkeys = sig.utils.collections.PubkeyMapManaged(void).init(db.allocator);
    defer cleaned_pubkeys.deinit();

    for (unclean_account_files) |file_id| {
        // NOTE: this read-lock is held for a while but
        // is not expensive since writes only happen
        // during delete, which doesn't happen in parallel
        // to this function.
        db.file_map_fd_rw.lockShared();
        defer db.file_map_fd_rw.unlockShared();

        const account_file = blk: {
            const file_map, var file_map_lg = db.file_map.readWithLock();
            defer file_map_lg.unlock();
            break :blk file_map.get(file_id).?;
        };

        var account_iter = account_file.iterator(&db.buffer_pool);
        while (try account_iter.nextNoData()) |account| {
            defer account.deinit(db.allocator);
            const pubkey = account.store_info.pubkey;

            // check if already cleaned
            if (try cleaned_pubkeys.fetchPut(pubkey, {}) != null) continue;

            // SAFE: this should always succeed or something is wrong
            const head_ref, var head_ref_lg = db.account_index.pubkey_ref_map.getRead(&pubkey).?;
            defer head_ref_lg.unlock();

            // get the highest slot <= highest_rooted_slot
            const rooted_ref_count, const ref_slot_max =
                head_ref.highestRootedSlot(rooted_slot_max);

            // short exit because nothing else to do
            if (rooted_ref_count == 0) continue;
            // if there are extra references, remove them

            var curr: ?*AccountRef = head_ref.ref_ptr;
            while (curr) |ref| : (curr = ref.next_ptr) {
                const is_not_rooted = ref.slot > rooted_slot_max;
                if (is_not_rooted) continue;

                const is_old_state = ref.slot < ref_slot_max;

                // the only reason to delete the highest ref is if it is zero-lamports
                var is_largest_root_zero_lamports = false;
                if (ref.slot == ref_slot_max) {
                    // check if account is zero-lamports
                    _, const lamports = try db.getAccountHashAndLamportsFromRef(ref.location);
                    is_largest_root_zero_lamports = lamports == 0;
                }

                if (is_old_state) num_old_states += 1;
                if (is_largest_root_zero_lamports) num_zero_lamports += 1;

                const should_delete_ref = is_largest_root_zero_lamports or is_old_state;
                if (should_delete_ref) {
                    // queue for deletion
                    try references_to_delete.append(.{
                        .pubkey = ref.pubkey,
                        .slot = ref.slot,
                    });

                    // NOTE: we should never clean non-rooted references
                    // (ie, should always be in a file)
                    const ref_file_id = ref.location.file.file_id;
                    const ref_slot = ref.slot;

                    const accounts_total_count, const accounts_dead_count = blk: {
                        const dead_accounts_counter, var dead_accounts_counter_lg =
                            db.dead_accounts_counter.writeWithLock();
                        defer dead_accounts_counter_lg.unlock();

                        // NOTE: if there is no counter for this slot, it may
                        // have been removed after reaching 0 dead accounts
                        // previously. it is added back as needed.
                        const number_dead_accounts_ptr =
                            (try dead_accounts_counter.getOrPutValue(ref_slot, 0)).value_ptr;
                        number_dead_accounts_ptr.* += 1;
                        const accounts_dead_count = number_dead_accounts_ptr.*;

                        if (ref_file_id == file_id) {
                            // read from the currently locked file
                            break :blk .{ account_file.number_of_accounts, accounts_dead_count };
                        } else {
                            // read number of accounts from another file
                            const ref_account_file = ref_blk: {
                                const file_map, var file_map_lg = db.file_map.readWithLock();
                                defer file_map_lg.unlock();
                                // we are holding a lock on `file_map_fd_rw`.
                                break :ref_blk file_map.get(ref_file_id).?;
                            };
                            break :blk .{
                                ref_account_file.number_of_accounts,
                                accounts_dead_count,
                            };
                        }
                    };
                    std.debug.assert(accounts_dead_count <= accounts_total_count);

                    const dead_percentage = 100 * accounts_dead_count / accounts_total_count;
                    if (dead_percentage == 100) {
                        // if its queued for shrink, remove it and queue it for deletion
                        _ = shrink_account_files.swapRemove(ref_file_id);
                        try delete_account_files.put(allocator, ref_file_id, {});
                    } else if (dead_percentage >= ACCOUNT_FILE_SHRINK_THRESHOLD) {
                        // queue for shrink
                        try shrink_account_files.put(allocator, ref_file_id, {});
                    }
                }
            }
        }

        // remove from index
        for (references_to_delete.items) |ref| {
            try db.account_index.removeReference(&ref.pubkey, ref.slot);
            // sanity check
            if (builtin.mode == .Debug) {
                std.debug.assert(!db.account_index.exists(&ref.pubkey, ref.slot));
            }
        }
        references_to_delete.clearRetainingCapacity();
        db.metrics.clean_references_deleted.set(references_to_delete.items.len);
    }

    if (number_of_files > 0) {
        db.logger.debug().logf(
            "cleaned {} slots - old_state: {}, zero_lamports: {}",
            .{ number_of_files, num_old_states, num_zero_lamports },
        );
    }

    db.metrics.clean_files_queued_deletion.set(delete_account_files.count());
    db.metrics.clean_files_queued_shrink.set(delete_account_files.count());
    db.metrics.clean_slot_old_state.set(num_old_states);
    db.metrics.clean_slot_zero_lamports.set(num_zero_lamports);

    db.metrics.time_clean.observe(timer.read().asNanos());
    return .{
        .num_zero_lamports = num_zero_lamports,
        .num_old_states = num_old_states,
    };
}

/// should only be called when all the accounts are dead (ie, no longer
/// exist in the index).
fn deleteAccountFiles(
    db: *AccountsDB,
    delete_account_files: []const FileId,
) !void {
    const zone = tracy.Zone.init(@src(), .{ .name = "accountsdb deleteAccountFiles" });
    defer zone.deinit();

    const number_of_files = delete_account_files.len;
    defer {
        db.metrics.number_files_deleted.add(number_of_files);
    }

    var delete_queue = try std.array_list.Managed(AccountFile).initCapacity(
        db.allocator,
        number_of_files,
    );
    defer delete_queue.deinit();

    {
        // we acquire this lock to ensure no account files are being accessed
        db.file_map_fd_rw.lock();
        defer db.file_map_fd_rw.unlock();

        // we acquire this lock to saftely remove file_id's from the file_map
        const file_map, var file_map_lg = db.file_map.writeWithLock();
        defer file_map_lg.unlock();

        for (delete_account_files) |file_id| {
            const account_file = file_map.get(file_id).?;

            // remove from file map
            const did_remove = file_map.swapRemove(file_id);
            std.debug.assert(did_remove);

            // NOTE: we can queue the actual removal of the account file without the lock because
            // because we know 1) no account files are being accessed and 2) no files are reading
            // from the file_map, so its no possible to access the file after this block returns.
            delete_queue.appendAssumeCapacity(account_file);
        }
    }

    db.logger.info().logf("deleting {} slots ...", .{delete_queue.items.len});
    for (delete_queue.items) |account_file| {
        const slot = account_file.slot;
        account_file.deinit();

        // delete file from disk
        deleteAccountFile(db, slot, account_file.id) catch |err| {
            // NOTE: this should always succeed or something is wrong
            db.logger.err().logf(
                "failed to delete account file slot.file_id: {d}.{d}: {s}",
                .{ slot, account_file.id, @errorName(err) },
            );
        };
    }

    {
        const dead_accounts_counter, var dead_accounts_counter_lg =
            db.dead_accounts_counter.writeWithLock();
        defer dead_accounts_counter_lg.unlock();

        for (delete_queue.items) |account_file| {
            const slot = account_file.slot;
            // there are two cases for an account file being queued for deletion
            // from cleaning:
            // 1) it was queued for shrink, and this is the *old* accountFile:
            //    dead_count == 0 and the slot DNE in the map (shrink removed it)
            // 2) it contains 100% dead accounts (in which dead_count > 0 and we
            //    can remove it from the map)
            _ = dead_accounts_counter.swapRemove(slot);
        }
    }
}

fn deleteAccountFile(
    db: *const AccountsDB,
    slot: Slot,
    file_id: FileId,
) !void {
    const file_path_bounded =
        sig.utils.fmt.boundedFmt("accounts/{d}.{d}", .{ slot, file_id.toInt() });
    db.snapshot_dir.deleteFile(file_path_bounded.constSlice()) catch |err| switch (err) {
        error.FileNotFound => {
            db.logger.warn().logf(
                "trying to delete accounts file which does not exist: {s}",
                .{sig.utils.fmt.tryRealPath(db.snapshot_dir, file_path_bounded.constSlice())},
            );
            return error.InvalidAccountFile;
        },
        else => |e| return e,
    };
}

/// resizes account files to reduce disk usage and remove dead accounts.
fn shrinkAccountFiles(
    allocator: Allocator,
    db: *AccountsDB,
    shrink_account_files: []const FileId,
    delete_account_files: *std.AutoArrayHashMapUnmanaged(FileId, void),
) !struct { num_accounts_deleted: usize } {
    const zone = tracy.Zone.init(@src(), .{ .name = "accountsdb shrinkAccountFiles" });
    defer zone.deinit();

    var timer = sig.time.Timer.start();

    const number_of_files = shrink_account_files.len;
    defer db.metrics.number_files_shrunk.add(number_of_files);

    var alive_pubkeys = sig.utils.collections.PubkeyMapManaged(void).init(db.allocator);
    defer alive_pubkeys.deinit();

    try delete_account_files.ensureUnusedCapacity(allocator, shrink_account_files.len);

    var total_accounts_deleted_size: u64 = 0;
    var total_accounts_deleted: u64 = 0;
    for (shrink_account_files) |shrink_file_id| {
        db.file_map_fd_rw.lockShared();
        defer db.file_map_fd_rw.unlockShared();

        const shrink_account_file = blk: {
            const file_map, var file_map_lg = db.file_map.readWithLock();
            defer file_map_lg.unlock();
            break :blk file_map.get(shrink_file_id).?;
        };

        const slot = shrink_account_file.slot;

        // compute size of alive accounts (read)
        var is_alive_flags = try std.array_list.Managed(bool).initCapacity(
            db.allocator,
            shrink_account_file.number_of_accounts,
        );
        defer is_alive_flags.deinit();

        var accounts_dead_count: u64 = 0;
        var accounts_alive_count: u64 = 0;

        alive_pubkeys.clearRetainingCapacity();
        try alive_pubkeys.ensureTotalCapacity(shrink_account_file.number_of_accounts);

        var accounts_alive_size: u64 = 0;
        var accounts_dead_size: u64 = 0;
        var account_iter = shrink_account_file.iterator(&db.buffer_pool);
        while (try account_iter.nextNoData()) |*account_in_file| {
            defer account_in_file.deinit(db.allocator);

            const pubkey = account_in_file.store_info.pubkey;
            // account is dead if it is not in the index; dead accounts
            // are removed from the index during cleaning
            const is_alive = db.account_index.exists(&pubkey, shrink_account_file.slot);
            // NOTE: there may be duplicate state in account files which we must account for
            const is_not_duplicate = !alive_pubkeys.contains(pubkey);
            if (is_alive and is_not_duplicate) {
                accounts_alive_size += account_in_file.getSizeInFile();
                accounts_alive_count += 1;
                is_alive_flags.appendAssumeCapacity(true);
                alive_pubkeys.putAssumeCapacity(pubkey, {});
            } else {
                accounts_dead_size += account_in_file.getSizeInFile();
                accounts_dead_count += 1;
                is_alive_flags.appendAssumeCapacity(false);
            }
        }
        // if there are no alive accounts, it should have been queued for deletion
        std.debug.assert(accounts_alive_count > 0);
        // if there are no dead accounts, it should have not been queued for shrink
        std.debug.assert(accounts_dead_count > 0);
        total_accounts_deleted += accounts_dead_count;
        total_accounts_deleted_size += accounts_dead_size;

        db.metrics.shrink_alive_accounts.observe(accounts_alive_count);
        db.metrics.shrink_dead_accounts.observe(accounts_dead_count);
        db.metrics.shrink_file_shrunk_by.observe(accounts_dead_size);

        // alloc account file for accounts
        const new_file, const new_file_id = try db.createAccountFile(
            accounts_alive_size,
            slot,
        );
        // don't close file if it ends up in file_map
        var new_file_in_map = false;
        defer if (!new_file_in_map) new_file.close();

        var file_size: usize = 0;
        account_iter.reset();
        for (is_alive_flags.items) |is_alive| {
            // SAFE: we know is_alive_flags is the same length as the account_iter
            const account = (try account_iter.nextNoData()).?;
            defer account.deinit(db.allocator);
            if (is_alive) file_size += account.getSizeInFile();
        }

        var account_file_buf = std.array_list.Managed(u8).init(db.allocator);
        defer account_file_buf.deinit();

        // write the alive accounts
        var offsets = try std.array_list.Managed(u64).initCapacity(db.allocator, accounts_alive_count);
        defer offsets.deinit();

        account_iter.reset();
        var offset: usize = 0;
        for (is_alive_flags.items) |is_alive| {
            // SAFE: we know is_alive_flags is the same length as the account_iter
            const account = (try account_iter.next(db.allocator)).?;
            defer account.deinit(db.allocator);
            if (is_alive) {
                try account_file_buf.resize(account.getSizeInFile());
                offsets.appendAssumeCapacity(offset);
                offset += account.serialize(account_file_buf.items);
                try new_file.writeAll(account_file_buf.items);
            }
        }

        {
            // add file to map
            const file_map, var file_map_lg = db.file_map.writeWithLock();
            defer file_map_lg.unlock();
            try file_map.ensureUnusedCapacity(db.allocator, 1);

            var new_account_file = try AccountFile.init(
                new_file,
                .{ .id = new_file_id, .length = offset },
                slot,
            );
            new_account_file.number_of_accounts = accounts_alive_count;

            file_map.putAssumeCapacityNoClobber(new_file_id, new_account_file);
            new_file_in_map = true;
        }

        // update the references
        const new_reference_block =
            try db.account_index.reference_manager.allocOrExpand(accounts_alive_count);
        account_iter.reset();
        var offset_index: u64 = 0;
        for (is_alive_flags.items) |is_alive| {
            // SAFE: we know is_alive_flags is the same length as the account_iter
            const account = (try account_iter.nextNoData()).?;
            defer account.deinit(db.allocator);
            if (is_alive) {
                // find the slot in the reference list
                const pubkey = &account.store_info.pubkey;

                const ref_parent, var ref_lg = db.account_index.getReferenceParent(
                    pubkey,
                    slot,
                ) catch |err| switch (err) {
                    // SAFE: we know the pubkey exists in the index because its alive
                    error.SlotNotFound, error.PubkeyNotFound => unreachable,
                };
                defer ref_lg.unlock();
                const ptr_to_ref_field = switch (ref_parent) {
                    .head => |head| &head.ref_ptr,
                    .parent => |parent| &parent.next_ptr.?,
                };

                // copy + update the values
                const new_ref_ptr = &new_reference_block[offset_index];
                new_ref_ptr.* = ptr_to_ref_field.*.*;
                new_ref_ptr.location.file = .{
                    .offset = offsets.items[offset_index],
                    .file_id = new_file_id,
                };
                ptr_to_ref_field.* = new_ref_ptr;

                offset_index += 1;
            }
        }

        // update slot's reference memory
        {
            const slot_reference_map, var slot_reference_map_lg =
                db.account_index.slot_reference_map.writeWithLock();
            defer slot_reference_map_lg.unlock();

            const slot_reference_map_entry = slot_reference_map.getEntry(slot) orelse {
                std.debug.panic("missing corresponding reference memory for slot {d}\n", .{slot});
            };
            // NOTE: this is ok because nothing points to this old reference memory
            // deinit old block of reference memory
            db.account_index.reference_manager.free(
                slot_reference_map_entry.value_ptr.refs.items.ptr,
            );

            // point to new block
            slot_reference_map_entry.value_ptr.* = .{
                .refs = .{
                    .items = new_reference_block,
                    .capacity = new_reference_block.len,
                },
            };
        }

        // queue the old account_file for deletion
        delete_account_files.putAssumeCapacityNoClobber(shrink_file_id, {});

        {
            // remove the dead accounts counter entry, since there
            // are no longer any dead accounts at this slot for now.
            // there has to be a counter for it at this point, since
            // cleanAccounts would only have added this file_id to
            // the queue if it deleted any accounts refs.
            const dead_accounts_counter, var dead_accounts_counter_lg =
                db.dead_accounts_counter.writeWithLock();
            defer dead_accounts_counter_lg.unlock();
            const removed = dead_accounts_counter.fetchSwapRemove(slot).?;
            std.debug.assert(removed.value == accounts_dead_count);
        }
    }

    if (number_of_files > 0) {
        db.logger.info().logf(
            "shrinked {} account files, total accounts deleted: {} ({} bytes)",
            .{ number_of_files, total_accounts_deleted, total_accounts_deleted_size },
        );
    }
    db.metrics.time_shrink.observe(timer.read().asNanos());

    return .{
        .num_accounts_deleted = total_accounts_deleted,
    };
}

/// remove all accounts and associated reference memory.
/// note: should only be called on non-rooted slots (ie, slots which
/// only exist in the cache, and not on disk). this is mainly used for dropping
/// forks.
fn purgeSlot(db: *AccountsDB, slot: Slot) void {
    var timer = sig.time.Timer.start();

    var pubkeys_and_accounts = blk: {
        const unrooted_accounts, var unrooted_accounts_lg = db.unrooted_accounts.writeWithLock();
        defer unrooted_accounts_lg.unlock();

        const removed_entry = unrooted_accounts.fetchRemove(slot) orelse {
            // the way it works right now, account files only exist for rooted slots
            // rooted slots should never need to be purged so we should never get here
            @panic("purging an account file not supported");
        };

        break :blk removed_entry.value;
    };

    // remove the references
    for (pubkeys_and_accounts.items(.pubkey)) |*pubkey| {
        db.account_index.removeReference(pubkey, slot) catch |err| switch (err) {
            error.PubkeyNotFound => std.debug.panic(
                "pubkey not found in index while purging: {any}",
                .{pubkey},
            ),
            error.SlotNotFound => std.debug.panic(
                "pubkey @ slot not found in index while purging: {any} @ {d}",
                .{ pubkey, slot },
            ),
        };
    }

    // free the reference memory
    {
        var slot_ref_map, var lock = db.account_index.slot_reference_map.writeWithLock();
        defer lock.unlock();
        const r = slot_ref_map.fetchRemove(slot) orelse std.debug.panic(
            "slot reference map not found for slot: {d}",
            .{slot},
        );
        db.account_index.reference_manager.free(r.value.refs.items.ptr);
    }

    // free the account memory
    for (pubkeys_and_accounts.items(.account)) |account| account.deinit(db.allocator);

    pubkeys_and_accounts.deinit(db.allocator);

    db.metrics.time_purge.observe(timer.read().asNanos());
}

test "flushing slots works" {
    const allocator = std.testing.allocator;
    const logger: Logger = .noop;

    var bp = try BufferPool.init(allocator, 100);
    defer bp.deinit(allocator);

    var tmp_dir_root = std.testing.tmpDir(.{});
    defer tmp_dir_root.cleanup();
    const snapshot_dir = tmp_dir_root.dir;

    var accounts_db = try AccountsDB.init(.{
        .allocator = allocator,
        .logger = .from(logger),
        .snapshot_dir = snapshot_dir,
        .geyser_writer = null,
        .gossip_view = null,
        .index_allocation = .ram,
        .number_of_index_shards = 4,
    });
    defer accounts_db.deinit();

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    const n_accounts = 3;

    try accounts_db.account_index.expandRefCapacity(n_accounts * 2);

    // we dont defer deinit to make sure that they are cleared on purge
    var pubkeys: [n_accounts]Pubkey = undefined;
    var accounts: [n_accounts]Account = undefined;
    for (&pubkeys, &accounts, 0..) |*pubkey, *account, i| {
        errdefer for (accounts[0..i]) |prev_account| prev_account.deinit(allocator);
        pubkey.* = Pubkey.initRandom(random);
        account.* = try Account.initRandom(allocator, random, i % 1_000);
    }
    defer for (accounts) |account| account.deinit(allocator);

    // this gets written to cache
    const slot: u64 = 200;
    try accounts_db.putAccountSlice(&accounts, &pubkeys, slot);

    // this writes to disk
    var unclean_account_files = ArrayList(FileId).init(allocator);
    defer unclean_account_files.deinit();
    try unclean_account_files.append(try flushSlot(&accounts_db, slot));

    accounts_db.file_map_fd_rw.lock();
    defer accounts_db.file_map_fd_rw.unlock();

    // try the validation
    const file_map, var file_map_lg = accounts_db.file_map.readWithLock();
    defer file_map_lg.unlock();

    const file_id = file_map.keys()[0];

    const account_file = file_map.getPtr(file_id).?;
    account_file.number_of_accounts = try account_file.validate(&bp);

    try std.testing.expect(account_file.number_of_accounts == n_accounts);
    try std.testing.expect(unclean_account_files.items.len == 1);
    try std.testing.expect(unclean_account_files.items[0] == file_id);
}

test "purge accounts in cache works" {
    const allocator = std.testing.allocator;
    const logger: Logger = .noop;

    var tmp_dir_root = std.testing.tmpDir(.{});
    defer tmp_dir_root.cleanup();
    const snapshot_dir = tmp_dir_root.dir;

    var accounts_db = try AccountsDB.init(.{
        .allocator = allocator,
        .logger = .from(logger),
        .snapshot_dir = snapshot_dir,
        .geyser_writer = null,
        .gossip_view = null,
        .index_allocation = .ram,
        .number_of_index_shards = 4,
    });
    defer accounts_db.deinit();

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    const n_accounts = 3;

    try accounts_db.account_index.expandRefCapacity(n_accounts * 2);

    var pubkeys: [n_accounts]Pubkey = undefined;
    var accounts: [n_accounts]Account = undefined;

    for (&pubkeys, &accounts, 0..) |*pubkey, *account, i| {
        errdefer for (accounts[0..i]) |prev_account| prev_account.deinit(allocator);
        pubkey.* = Pubkey.initRandom(random);
        account.* = try Account.initRandom(allocator, random, i % 1_000);
    }
    defer for (accounts) |account| account.deinit(allocator);

    const pubkey_copy: [n_accounts]Pubkey = pubkeys;

    const slot: u64 = 200;
    try accounts_db.putAccountSlice(&accounts, &pubkeys, slot);

    for (0..n_accounts) |i| {
        _, var lg = accounts_db.account_index.pubkey_ref_map.getRead(&pubkeys[i]) orelse
            return error.TestUnexpectedNull;
        lg.unlock();
    }

    purgeSlot(&accounts_db, slot);

    // ref backing memory is cleared
    {
        const slot_reference_map, var slot_reference_map_lg =
            accounts_db.account_index.slot_reference_map.readWithLock();
        defer slot_reference_map_lg.unlock();

        try std.testing.expect(slot_reference_map.count() == 0);
    }
    // account cache is cleared
    {
        var lg = accounts_db.unrooted_accounts.read();
        defer lg.unlock();
        try std.testing.expect(lg.get().count() == 0);
    }

    // ref hashmap is cleared
    for (0..n_accounts) |i| {
        try std.testing
            .expect(accounts_db.account_index.pubkey_ref_map.getRead(&pubkey_copy[i]) == null);
    }
}

test "clean to shrink account file works with zero-lamports" {
    const allocator = std.testing.allocator;

    var accounts_db, var dir = try AccountsDB.initForTest(allocator);
    defer accounts_db.deinit();
    defer dir.cleanup();

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    const n_accounts = 10;

    try accounts_db.account_index.expandRefCapacity(200);

    // generate the account file for slot 0
    var pubkeys: [n_accounts]Pubkey = undefined;
    var accounts: [n_accounts]Account = undefined;
    for (&pubkeys, &accounts, 0..) |*pubkey, *account, i| {
        errdefer for (accounts[0..i]) |prev_account| prev_account.deinit(allocator);
        pubkey.* = Pubkey.initRandom(random);
        account.* = try Account.initRandom(allocator, random, 100);
    }
    defer for (accounts) |account| account.deinit(allocator);

    const slot: u64 = 200;
    try accounts_db.putAccountSlice(&accounts, &pubkeys, slot);

    // test to make sure we can still read it
    const pubkey_remain = pubkeys[pubkeys.len - 1];

    // duplicate some before the flush/deinit
    const new_len = n_accounts - 1; // one new root with zero lamports
    var pubkeys2: [new_len]Pubkey = undefined;
    var accounts2: [new_len]Account = undefined;
    @memcpy(&pubkeys2, pubkeys[0..new_len]);
    for (&accounts2, 0..) |*account, i| {
        errdefer for (accounts2[0..i]) |prev_account| prev_account.deinit(allocator);
        account.* = try Account.initRandom(allocator, random, i % 1_000);
        account.lamports = 0; // !
    }
    defer for (accounts2) |account| account.deinit(allocator);

    var unclean_account_files = ArrayList(FileId).init(allocator);
    defer unclean_account_files.deinit();

    try unclean_account_files.append(try flushSlot(&accounts_db, slot));

    // write new state
    const new_slot: u64 = 500;
    try accounts_db.putAccountSlice(&accounts2, &pubkeys2, new_slot);
    try unclean_account_files.append(try flushSlot(&accounts_db, new_slot));

    var shrink_account_files = std.AutoArrayHashMapUnmanaged(FileId, void).empty;
    defer shrink_account_files.deinit(allocator);

    var delete_account_files = std.AutoArrayHashMapUnmanaged(FileId, void).empty;
    defer delete_account_files.deinit(allocator);

    const r = try cleanAccountFiles(
        allocator,
        &accounts_db,
        new_slot + 100,
        unclean_account_files.items,
        &shrink_account_files,
        &delete_account_files,
    );
    try std.testing.expect(r.num_old_states == new_len);
    try std.testing.expect(r.num_zero_lamports == new_len);
    // shrink
    try std.testing.expectEqual(1, shrink_account_files.count());
    // slot 500 will be fully dead because its all zero lamports
    try std.testing.expectEqual(1, delete_account_files.count());

    var account = try accounts_db.getAccountLatest(allocator, &pubkey_remain) orelse unreachable;
    defer account.deinit(allocator);
}

test "clean to shrink account file works - basic" {
    const allocator = std.testing.allocator;

    var accounts_db, var dir = try AccountsDB.initForTest(allocator);
    defer accounts_db.deinit();
    defer dir.cleanup();

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    const n_accounts = 10;

    try accounts_db.account_index.expandRefCapacity(200);

    // generate the account file for slot 0
    var pubkeys: [n_accounts]Pubkey = undefined;
    var accounts: [n_accounts]Account = undefined;
    for (&pubkeys, &accounts, 0..) |*pubkey, *account, i| {
        errdefer for (accounts[0..i]) |prev_account| prev_account.deinit(allocator);
        pubkey.* = Pubkey.initRandom(random);
        account.* = try Account.initRandom(allocator, random, 100);
    }
    defer for (accounts) |account| account.deinit(allocator);

    const slot: u64 = 200;
    try accounts_db.putAccountSlice(&accounts, &pubkeys, slot);

    // duplicate HALF before the flush/deinit
    const new_len = n_accounts - 1; // 90% delete = shrink
    var pubkeys2: [new_len]Pubkey = undefined;
    var accounts2: [new_len]Account = undefined;
    @memcpy(&pubkeys2, pubkeys[0..new_len]);
    for (&accounts2, 0..) |*account, i| {
        errdefer for (accounts2[0..i]) |prev_account| prev_account.deinit(allocator);
        account.* = try Account.initRandom(allocator, random, i % 1_000);
    }
    defer for (accounts2) |account| account.deinit(allocator);

    var unclean_account_files = ArrayList(FileId).init(allocator);
    defer unclean_account_files.deinit();

    var shrink_account_files = std.AutoArrayHashMapUnmanaged(FileId, void).empty;
    defer shrink_account_files.deinit(allocator);

    var delete_account_files = std.AutoArrayHashMapUnmanaged(FileId, void).empty;
    defer delete_account_files.deinit(allocator);

    try unclean_account_files.append(try flushSlot(&accounts_db, slot));

    // write new state
    const new_slot: u64 = 500;
    try accounts_db.putAccountSlice(&accounts2, &pubkeys2, new_slot);
    try unclean_account_files.append(try flushSlot(&accounts_db, new_slot));

    const r = try cleanAccountFiles(
        allocator,
        &accounts_db,
        new_slot + 100,
        unclean_account_files.items,
        &shrink_account_files,
        &delete_account_files,
    );
    try std.testing.expect(r.num_old_states == new_len);
    try std.testing.expect(r.num_zero_lamports == 0);
    // shrink
    try std.testing.expect(shrink_account_files.count() == 1);
    try std.testing.expect(delete_account_files.count() == 0);
}

test "full clean account file works" {
    const allocator = std.testing.allocator;
    const logger: Logger = .noop;

    var tmp_dir_root = std.testing.tmpDir(.{});
    defer tmp_dir_root.cleanup();
    const snapshot_dir = tmp_dir_root.dir;

    var accounts_db = try AccountsDB.init(.{
        .allocator = allocator,
        .logger = .from(logger),
        .snapshot_dir = snapshot_dir,
        .geyser_writer = null,
        .gossip_view = null,
        .index_allocation = .ram,
        .number_of_index_shards = 4,
    });
    defer accounts_db.deinit();

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    const n_accounts = 3;

    try accounts_db.account_index.expandRefCapacity(200);

    // generate the account file for slot 0
    var pubkeys: [n_accounts]Pubkey = undefined;
    var accounts: [n_accounts]Account = undefined;
    for (&pubkeys, &accounts, 0..) |*pubkey, *account, i| {
        errdefer for (accounts[0..i]) |prev_account| prev_account.deinit(allocator);
        pubkey.* = Pubkey.initRandom(random);
        account.* = try Account.initRandom(allocator, random, i % 1_000);
    }
    defer for (accounts) |account| account.deinit(allocator);

    const slot: u64 = 200;
    try accounts_db.putAccountSlice(&accounts, &pubkeys, slot);

    // duplicate before the flush/deinit
    var pubkeys2: [n_accounts]Pubkey = undefined;
    var accounts2: [n_accounts]Account = undefined;
    @memcpy(&pubkeys2, &pubkeys);
    for (&accounts2, 0..) |*account, i| {
        errdefer for (accounts2[0..i]) |prev_account| prev_account.deinit(allocator);
        account.* = try Account.initRandom(allocator, random, i % 1_000);
    }
    defer for (&accounts2) |account| account.deinit(allocator);

    var unclean_account_files = ArrayList(FileId).init(allocator);
    defer unclean_account_files.deinit();

    var shrink_account_files = std.AutoArrayHashMapUnmanaged(FileId, void).empty;
    defer shrink_account_files.deinit(allocator);

    var delete_account_files = std.AutoArrayHashMapUnmanaged(FileId, void).empty;
    defer delete_account_files.deinit(allocator);

    try unclean_account_files.append(try flushSlot(&accounts_db, slot));

    // zero is rooted so no files should be cleaned
    var r = try cleanAccountFiles(
        allocator,
        &accounts_db,
        0,
        unclean_account_files.items,
        &shrink_account_files,
        &delete_account_files,
    );
    try std.testing.expect(r.num_old_states == 0);
    try std.testing.expect(r.num_zero_lamports == 0);

    // zero has no old state so no files should be cleaned
    r = try cleanAccountFiles(
        allocator,
        &accounts_db,
        1,
        unclean_account_files.items,
        &shrink_account_files,
        &delete_account_files,
    );
    try std.testing.expect(r.num_old_states == 0);
    try std.testing.expect(r.num_zero_lamports == 0);

    // write new state
    const new_slot: u64 = 500;
    try accounts_db.putAccountSlice(&accounts2, &pubkeys2, new_slot);
    try unclean_account_files.append(try flushSlot(&accounts_db, new_slot));

    r = try cleanAccountFiles(
        allocator,
        &accounts_db,
        new_slot + 100,
        unclean_account_files.items,
        &shrink_account_files,
        &delete_account_files,
    );
    try std.testing.expect(r.num_old_states == n_accounts);
    try std.testing.expect(r.num_zero_lamports == 0);
    // full delete
    try std.testing.expect(delete_account_files.count() == 1);
    const delete_file_id = delete_account_files.keys()[0];

    // test delete
    {
        const file_map, var file_map_lg = accounts_db.file_map.readWithLock();
        defer file_map_lg.unlock();
        try std.testing.expect(file_map.get(delete_file_id) != null);
    }

    try deleteAccountFiles(&accounts_db, delete_account_files.keys());

    {
        const file_map, var file_map_lg = accounts_db.file_map.readWithLock();
        defer file_map_lg.unlock();
        try std.testing.expectEqual(null, file_map.get(delete_file_id));
    }
}

test "shrink account file works" {
    const allocator = std.testing.allocator;
    const logger: Logger = .noop;

    var tmp_dir_root = std.testing.tmpDir(.{});
    defer tmp_dir_root.cleanup();
    const snapshot_dir = tmp_dir_root.dir;

    var accounts_db = try AccountsDB.init(.{
        .allocator = allocator,
        .logger = .from(logger),
        .snapshot_dir = snapshot_dir,
        .geyser_writer = null,
        .gossip_view = null,
        .index_allocation = .ram,
        .number_of_index_shards = 4,
    });
    defer accounts_db.deinit();

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const n_accounts = 10;

    try accounts_db.account_index.expandRefCapacity(200);

    // generate the account file for slot 0
    var pubkeys: [n_accounts]Pubkey = undefined;
    var accounts: [n_accounts]Account = undefined;

    for (&pubkeys, &accounts, 0..) |*pubkey, *account, i| {
        errdefer for (accounts[0..i]) |prev_account| prev_account.deinit(allocator);
        pubkey.* = Pubkey.initRandom(random);
        account.* = try Account.initRandom(allocator, random, 100);
    }
    defer for (accounts) |account| account.deinit(allocator);

    const slot: u64 = 200;
    try accounts_db.putAccountSlice(&accounts, &pubkeys, slot);

    // test to make sure we can still read it
    const pubkey_remain = pubkeys[pubkeys.len - 1];

    // duplicate some before the flush/deinit
    const new_len = n_accounts - 1; // 90% delete = shrink
    var pubkeys2: [new_len]Pubkey = undefined;
    var accounts2: [new_len]Account = undefined;
    @memcpy(&pubkeys2, pubkeys[0..new_len]);
    for (&accounts2, 0..new_len) |*account, i| {
        account.* = try Account.initRandom(allocator, random, i % 1_000);
    }
    defer for (accounts2) |account| account.deinit(allocator);

    var unclean_account_files = ArrayList(FileId).init(allocator);
    defer unclean_account_files.deinit();
    var shrink_account_files = std.AutoArrayHashMapUnmanaged(FileId, void).empty;
    defer shrink_account_files.deinit(allocator);
    var delete_account_files = std.AutoArrayHashMapUnmanaged(FileId, void).empty;
    defer delete_account_files.deinit(allocator);

    try unclean_account_files.append(try flushSlot(&accounts_db, slot));

    // write new state
    const new_slot = @as(u64, @intCast(500));
    try accounts_db.putAccountSlice(
        &accounts2,
        &pubkeys2,
        new_slot,
    );
    try unclean_account_files.append(try flushSlot(&accounts_db, new_slot));

    // clean the account files - slot is queued for shrink
    const clean_result = try cleanAccountFiles(
        allocator,
        &accounts_db,
        new_slot + 100,
        unclean_account_files.items,
        &shrink_account_files,
        &delete_account_files,
    );
    try std.testing.expect(shrink_account_files.count() == 1);
    try std.testing.expectEqual(9, clean_result.num_old_states);

    const pre_shrink_size = blk: {
        accounts_db.file_map_fd_rw.lockShared();
        defer accounts_db.file_map_fd_rw.unlockShared();

        const file_map, var file_map_lg = accounts_db.file_map.readWithLock();
        defer file_map_lg.unlock();

        const slot_file_id: FileId = for (file_map.keys()) |file_id| {
            const account_file = file_map.get(file_id).?;
            if (account_file.slot == slot) break file_id;
        } else return error.NoSlotFile;
        break :blk file_map.get(slot_file_id).?.length;
    };

    // full memory block
    {
        const slot_reference_map, var slot_reference_map_lg =
            accounts_db.account_index.slot_reference_map.readWithLock();
        defer slot_reference_map_lg.unlock();

        const slot_mem = slot_reference_map.get(new_slot).?;
        try std.testing.expect(slot_mem.refs.items.len == accounts2.len);
    }

    // test: files were shrunk
    const r = try shrinkAccountFiles(
        allocator,
        &accounts_db,
        shrink_account_files.keys(),
        &delete_account_files,
    );
    try std.testing.expectEqual(9, r.num_accounts_deleted);

    // test: new account file is shrunk
    {
        accounts_db.file_map_fd_rw.lockShared();
        defer accounts_db.file_map_fd_rw.unlockShared();

        const file_map2, var file_map_lg2 = accounts_db.file_map.readWithLock();
        defer file_map_lg2.unlock();

        const new_slot_file_id: FileId = blk: {
            var maybe_max_file_id: ?FileId = null;
            for (file_map2.keys(), file_map2.values()) |file_id, account_file| {
                const max_file_id = maybe_max_file_id orelse {
                    if (account_file.slot == slot) {
                        maybe_max_file_id = file_id;
                    }
                    continue;
                };
                if (max_file_id.toInt() > file_id.toInt()) continue;
                if (account_file.slot != slot) continue;
                maybe_max_file_id = file_id;
            }
            break :blk maybe_max_file_id orelse return error.NoSlotFile;
        };

        const new_account_file = file_map2.get(new_slot_file_id).?;
        const post_shrink_size = new_account_file.length;
        try std.testing.expect(post_shrink_size < pre_shrink_size);
    }

    // test: memory block is shrunk too
    {
        const slot_reference_map, var slot_reference_map_lg =
            accounts_db.account_index.slot_reference_map.readWithLock();
        defer slot_reference_map_lg.unlock();

        const slot_mem = slot_reference_map.get(slot).?;
        try std.testing.expectEqual(1, slot_mem.refs.items.len);
    }

    // last account ref should still be accessible
    const account = try accounts_db.getAccountLatest(allocator, &pubkey_remain) orelse unreachable;
    account.deinit(allocator);
}

test "onSlotRooted basic" {
    const allocator = std.testing.allocator;
    const logger: Logger = .noop;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    var tmp_dir_root = std.testing.tmpDir(.{});
    defer tmp_dir_root.cleanup();
    const snapshot_dir = tmp_dir_root.dir;

    var db = try AccountsDB.init(.{
        .allocator = allocator,
        .logger = .from(logger),
        .snapshot_dir = snapshot_dir,
        .geyser_writer = null,
        .gossip_view = null,
        .index_allocation = .ram,
        .number_of_index_shards = 4,
        .on_root_config = .{ .do_cleaning = true },
    });
    defer db.deinit();

    const pk = Pubkey.initRandom(random);

    var account: sig.runtime.AccountSharedData = .EMPTY;
    account.lamports = 1;

    // interleave put + root
    try db.putAccount(149, pk, account);
    try onSlotRooted(allocator, &db, 149, 5000);
    try db.putAccount(150, pk, account);
    try onSlotRooted(allocator, &db, 150, 5000);

    // put some + root some
    try db.putAccount(151, pk, account);
    try db.putAccount(152, pk, account);
    try db.putAccount(153, pk, account);
    try onSlotRooted(allocator, &db, 151, 5000);
    try onSlotRooted(allocator, &db, 152, 5000);
    try onSlotRooted(allocator, &db, 153, 5000);

    // check failure cases
    for (&[_]u64{
        154, // no accounts are in 154 yet
        153, 150, // we already flushed these!
        1, 0, // nope
    }) |slot| {
        try std.testing.expectError(
            error.SlotNotFound,
            onSlotRooted(allocator, &db, slot, 5000),
        );
    }

    var accounts_dir = try snapshot_dir.openDir("accounts", .{ .iterate = true });
    defer accounts_dir.close();

    // the last slot should be the only one that remains after onSlotRooted(last_slot)
    var iter = accounts_dir.iterate();
    try std.testing.expectEqualStrings("153.5", (try iter.next()).?.name);
    try std.testing.expectEqual(null, try iter.next());
}

test "onSlotRooted zero_lamports" {
    const allocator = std.testing.allocator;
    const logger: Logger = .noop;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    var tmp_dir_root = std.testing.tmpDir(.{});
    defer tmp_dir_root.cleanup();
    const snapshot_dir = tmp_dir_root.dir;

    var db = try AccountsDB.init(.{
        .allocator = allocator,
        .logger = .from(logger),
        .snapshot_dir = snapshot_dir,
        .geyser_writer = null,
        .gossip_view = null,
        .index_allocation = .ram,
        .number_of_index_shards = 4,
        .on_root_config = .{ .do_cleaning = true },
    });
    defer db.deinit();

    const pk = Pubkey.initRandom(random);
    const account: sig.runtime.AccountSharedData = .EMPTY;

    // interleave put + root
    try db.putAccount(149, pk, account);
    try onSlotRooted(allocator, &db, 149, 5000);

    var accounts_dir = try snapshot_dir.openDir("accounts", .{ .iterate = true });
    defer accounts_dir.close();

    var iter = accounts_dir.iterate();
    // all files containing just zero lamport accounts should be deleted
    try std.testing.expectEqual(null, try iter.next());
}

test "onSlotRooted shrink and delete" {
    const allocator = std.testing.allocator;
    const logger: Logger = .noop;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    var tmp_dir_root = std.testing.tmpDir(.{});
    defer tmp_dir_root.cleanup();
    const snapshot_dir = tmp_dir_root.dir;

    var db = try AccountsDB.init(.{
        .allocator = allocator,
        .logger = .from(logger),
        .snapshot_dir = snapshot_dir,
        .geyser_writer = null,
        .gossip_view = null,
        .index_allocation = .ram,
        .number_of_index_shards = 4,
        .on_root_config = .{ .do_cleaning = true },
    });
    defer db.deinit();

    const accounts = try allocator.alloc(sig.runtime.AccountSharedData, 10);
    defer allocator.free(accounts);
    for (accounts) |*account| {
        account.* = sig.runtime.AccountSharedData.EMPTY;
        account.lamports = 1;
    }
    const pubkeys = try allocator.alloc(Pubkey, 10);
    defer allocator.free(pubkeys);
    for (pubkeys) |*pubkey| pubkey.* = Pubkey.initRandom(random);

    // put all accounts
    {
        for (accounts, pubkeys) |account, pubkey| {
            try db.putAccount(149, pubkey, account);
        }
        try onSlotRooted(allocator, &db, 149, 5000);
    }

    const size_149_before = blk: {
        var accounts_dir = try snapshot_dir.openDir("accounts", .{ .iterate = true });
        defer accounts_dir.close();
        const stat = try accounts_dir.statFile("149.1");
        break :blk stat.size;
    };

    // overwrite 90% of accounts in next slot
    {
        for (accounts[0..9], pubkeys[0..9]) |account, pubkey| {
            try db.putAccount(150, pubkey, account);
        }
        try onSlotRooted(allocator, &db, 150, 5000);
    }

    const size_149_after = blk: {
        var accounts_dir = try snapshot_dir.openDir("accounts", .{ .iterate = true });
        defer accounts_dir.close();
        const stat = try accounts_dir.statFile("149.3"); // shrinking a file means a new file id
        break :blk stat.size;
    };

    // slot 149 has been shrunk!
    try std.testing.expect(size_149_after < size_149_before);

    // overwrite 100% of accounts in both previous slots
    {
        for (accounts, pubkeys) |account, pubkey| {
            try db.putAccount(151, pubkey, account);
        }
        try onSlotRooted(allocator, &db, 151, 5000);
    }

    // slot 150 and 149 are gone
    var accounts_dir = try snapshot_dir.openDir("accounts", .{ .iterate = true });
    defer accounts_dir.close();
    var iter = accounts_dir.iterate();
    try std.testing.expectEqualStrings("151.4", (try iter.next()).?.name);
    try std.testing.expectEqual(null, try iter.next());
}

// test "snapshot generation happens without error" {
//     const allocator = std.testing.allocator;
//     const logger: Logger = .noop;
//     var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
//     const random = prng.random();

//     var tmp_dir_root = std.testing.tmpDir(.{ .iterate = true });
//     defer tmp_dir_root.cleanup();
//     const snapshot_dir = tmp_dir_root.dir;

//     var db = try AccountsDB.init(.{
//         .allocator = allocator,
//         .logger = .from(logger),
//         .snapshot_dir = snapshot_dir,
//         .geyser_writer = null,
//         .gossip_view = null,
//         .index_allocation = .ram,
//         .number_of_index_shards = 4,
//         .on_root_config = .{ .do_cleaning = true, .slots_per_full_snapshot = 1 },
//     });
//     defer db.deinit();

//     const accounts = try allocator.alloc(sig.runtime.AccountSharedData, 10);
//     defer allocator.free(accounts);
//     for (accounts) |*account| {
//         account.* = sig.runtime.AccountSharedData.EMPTY;
//         account.lamports = 1;
//     }
//     const pubkeys = try allocator.alloc(Pubkey, 10);
//     defer allocator.free(pubkeys);
//     for (pubkeys) |*pubkey| pubkey.* = Pubkey.initRandom(random);

//     // put all accounts
//     for (accounts, pubkeys) |account, pubkey| {
//         try db.putAccount(149, pubkey, account);
//     }

//     // generate full snapshot
//     try onSlotRooted(
//         allocator,
//         &db,
//         149,
//         5000,
//     );

//     for (accounts, pubkeys) |account, pubkey| try db.putAccount(150, pubkey, account);
//     for (accounts, pubkeys) |account, pubkey| try db.putAccount(151, pubkey, account);
//     for (accounts, pubkeys) |account, pubkey| try db.putAccount(152, pubkey, account);
//     for (accounts, pubkeys) |account, pubkey| try db.putAccount(153, pubkey, account);
//     for (accounts, pubkeys) |account, pubkey| try db.putAccount(154, pubkey, account);

//     // generate incremental
//     db.on_root_config = .{
//         .do_cleaning = true,
//         .slots_per_full_snapshot = 100,
//         .slots_per_incremental_snapshot = 1,
//     };
//     try onSlotRooted(allocator, &db, 150, 5000);

//     var found_inc = false;
//     var found_full = false;

//     var iter = snapshot_dir.iterate();
//     while (try iter.next()) |obj| {
//         if (obj.kind != .file) continue;

//         if (std.mem.startsWith(u8, obj.name, "incremental-snapshot-")) {
//             found_inc = true;
//         } else if (std.mem.startsWith(u8, obj.name, "snapshot-")) {
//             found_full = true;
//         } else {
//             return error.UnexpectedFileFound;
//         }
//     }

//     try std.testing.expect(found_inc);
//     try std.testing.expect(found_full);
// }
