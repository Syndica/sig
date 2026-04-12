const std = @import("std");
const sig = @import("../../sig.zig");

const Allocator = std.mem.Allocator;
const Ancestors = sig.core.Ancestors;
const BankFields = sig.core.BankFields;
const BlockhashQueue = sig.core.BlockhashQueue;
const Epoch = sig.core.time.Epoch;
const EpochSchedule = sig.core.EpochSchedule;
const ExtraFields = @import("data.zig").ExtraFields;
const FeeRateGovernor = sig.core.FeeRateGovernor;
const GenesisConfig = sig.core.GenesisConfig;
const HardForks = sig.core.HardForks;
const Hash = sig.core.hash.Hash;
const Inflation = sig.core.Inflation;
const LoadedSnapshot = @import("load.zig").LoadedSnapshot;
const LtHash = sig.core.hash.LtHash;
const Manifest = @import("data.zig").Manifest;
const Pubkey = sig.core.Pubkey;
const RentCollector = sig.core.RentCollector;
const Stakes = sig.core.Stakes;
const UnixTimestamp = sig.core.UnixTimestamp;
const UnusedAccounts = sig.core.bank.UnusedAccounts;
const VersionedEpochStakes = sig.core.VersionedEpochStakes;
const bincode = sig.bincode;

const Logger = sig.trace.Logger("accountsdb.snapshot.reduced_checkpoint");

pub const ReducedBankFields = struct {
    blockhash_queue: BlockhashQueue,
    ancestors: Ancestors,
    hash: Hash,
    parent_hash: Hash,
    parent_slot: sig.core.Slot,
    hard_forks: HardForks,
    transaction_count: u64,
    tick_height: u64,
    signature_count: u64,
    capitalization: u64,
    max_tick_height: u64,
    hashes_per_tick: ?u64,
    ticks_per_slot: u64,
    ns_per_slot: u128,
    genesis_creation_time: UnixTimestamp,
    slots_per_year: f64,
    slot: sig.core.Slot,
    epoch: Epoch,
    block_height: u64,
    collector_id: Pubkey,
    fee_rate_governor: FeeRateGovernor,
    collected_rent: u64,
    rent_collector: RentCollector,
    epoch_schedule: EpochSchedule,
    inflation: Inflation,
    stakes: Stakes(.delegation),

    pub fn deinit(self: *const ReducedBankFields, allocator: Allocator) void {
        self.blockhash_queue.deinit(allocator);

        var ancestors = self.ancestors;
        ancestors.deinit(allocator);

        self.hard_forks.deinit(allocator);
        self.stakes.deinit(allocator);
    }

    pub fn clone(
        self: *const ReducedBankFields,
        allocator: Allocator,
    ) Allocator.Error!ReducedBankFields {
        return .{
            .blockhash_queue = try self.blockhash_queue.clone(allocator),
            .ancestors = try self.ancestors.clone(allocator),
            .hash = self.hash,
            .parent_hash = self.parent_hash,
            .parent_slot = self.parent_slot,
            .hard_forks = try self.hard_forks.clone(allocator),
            .transaction_count = self.transaction_count,
            .tick_height = self.tick_height,
            .signature_count = self.signature_count,
            .capitalization = self.capitalization,
            .max_tick_height = self.max_tick_height,
            .hashes_per_tick = self.hashes_per_tick,
            .ticks_per_slot = self.ticks_per_slot,
            .ns_per_slot = self.ns_per_slot,
            .genesis_creation_time = self.genesis_creation_time,
            .slots_per_year = self.slots_per_year,
            .slot = self.slot,
            .epoch = self.epoch,
            .block_height = self.block_height,
            .collector_id = self.collector_id,
            .fee_rate_governor = self.fee_rate_governor,
            .collected_rent = self.collected_rent,
            .rent_collector = self.rent_collector,
            .epoch_schedule = self.epoch_schedule,
            .inflation = self.inflation,
            .stakes = try self.stakes.clone(allocator),
        };
    }

    pub fn fromBankFields(
        allocator: Allocator,
        bank_fields: *const BankFields,
    ) Allocator.Error!ReducedBankFields {
        return .{
            .blockhash_queue = try bank_fields.blockhash_queue.clone(allocator),
            .ancestors = try bank_fields.ancestors.clone(allocator),
            .hash = bank_fields.hash,
            .parent_hash = bank_fields.parent_hash,
            .parent_slot = bank_fields.parent_slot,
            .hard_forks = try bank_fields.hard_forks.clone(allocator),
            .transaction_count = bank_fields.transaction_count,
            .tick_height = bank_fields.tick_height,
            .signature_count = bank_fields.signature_count,
            .capitalization = bank_fields.capitalization,
            .max_tick_height = bank_fields.max_tick_height,
            .hashes_per_tick = bank_fields.hashes_per_tick,
            .ticks_per_slot = bank_fields.ticks_per_slot,
            .ns_per_slot = bank_fields.ns_per_slot,
            .genesis_creation_time = bank_fields.genesis_creation_time,
            .slots_per_year = bank_fields.slots_per_year,
            .slot = bank_fields.slot,
            .epoch = bank_fields.epoch,
            .block_height = bank_fields.block_height,
            .collector_id = bank_fields.collector_id,
            .fee_rate_governor = bank_fields.fee_rate_governor,
            .collected_rent = bank_fields.collected_rent,
            .rent_collector = bank_fields.rent_collector,
            .epoch_schedule = bank_fields.epoch_schedule,
            .inflation = bank_fields.inflation,
            .stakes = try bank_fields.stakes.clone(allocator),
        };
    }

    pub fn toBankFields(
        self: *const ReducedBankFields,
        allocator: Allocator,
    ) Allocator.Error!BankFields {
        return .{
            .blockhash_queue = try self.blockhash_queue.clone(allocator),
            .ancestors = try self.ancestors.clone(allocator),
            .hash = self.hash,
            .parent_hash = self.parent_hash,
            .parent_slot = self.parent_slot,
            .hard_forks = try self.hard_forks.clone(allocator),
            .transaction_count = self.transaction_count,
            .tick_height = self.tick_height,
            .signature_count = self.signature_count,
            .capitalization = self.capitalization,
            .max_tick_height = self.max_tick_height,
            .hashes_per_tick = self.hashes_per_tick,
            .ticks_per_slot = self.ticks_per_slot,
            .ns_per_slot = self.ns_per_slot,
            .genesis_creation_time = self.genesis_creation_time,
            .slots_per_year = self.slots_per_year,
            .accounts_data_len = 0,
            .slot = self.slot,
            .epoch = self.epoch,
            .block_height = self.block_height,
            .collector_id = self.collector_id,
            .collector_fees = 0,
            .fee_calculator = 0,
            .fee_rate_governor = self.fee_rate_governor,
            .collected_rent = self.collected_rent,
            .rent_collector = self.rent_collector,
            .epoch_schedule = self.epoch_schedule,
            .inflation = self.inflation,
            .stakes = try self.stakes.clone(allocator),
            .unused_accounts = UnusedAccounts.EMPTY,
            .epoch_stakes = .{},
            .is_delta = false,
        };
    }
};

pub const ReducedExtraFields = struct {
    versioned_epoch_stakes: std.AutoArrayHashMapUnmanaged(Epoch, VersionedEpochStakes),
    accounts_lt_hash: LtHash,

    pub fn deinit(self: *const ReducedExtraFields, allocator: Allocator) void {
        var versioned_epoch_stakes = self.versioned_epoch_stakes;
        for (versioned_epoch_stakes.values()) |ves| ves.deinit(allocator);
        versioned_epoch_stakes.deinit(allocator);
    }

    pub fn clone(
        self: *const ReducedExtraFields,
        allocator: Allocator,
    ) Allocator.Error!ReducedExtraFields {
        return .{
            .versioned_epoch_stakes = try sig.utils.collections.cloneMapAndValues(
                allocator,
                self.versioned_epoch_stakes,
            ),
            .accounts_lt_hash = self.accounts_lt_hash,
        };
    }

    pub fn fromExtraFields(
        allocator: Allocator,
        extra: *const ExtraFields,
    ) Allocator.Error!ReducedExtraFields {
        return .{
            .versioned_epoch_stakes = try sig.utils.collections.cloneMapAndValues(
                allocator,
                extra.versioned_epoch_stakes,
            ),
            .accounts_lt_hash = extra.accounts_lt_hash,
        };
    }

    pub fn toExtraFields(
        self: *const ReducedExtraFields,
        allocator: Allocator,
    ) Allocator.Error!ExtraFields {
        return .{
            .lamports_per_signature = 0,
            .snapshot_persistence = null,
            .epoch_accounts_hash = null,
            .versioned_epoch_stakes = try sig.utils.collections.cloneMapAndValues(
                allocator,
                self.versioned_epoch_stakes,
            ),
            .accounts_lt_hash = self.accounts_lt_hash,
        };
    }
};

/// Reduced checkpoint metadata for the selective local-state oracle.
///
/// This intentionally excludes the heavyweight snapshot `accounts_db_fields`
/// and other manifest fields that the current oracle bootstrap does not need.
/// The associated rooted DB is expected to already exist locally.
pub const ReducedCheckpoint = struct {
    bank_fields: ReducedBankFields,
    bank_extra: ReducedExtraFields,

    pub fn deinit(self: *ReducedCheckpoint, allocator: Allocator) void {
        self.bank_fields.deinit(allocator);
        self.bank_extra.deinit(allocator);
    }

    pub fn fromManifest(
        allocator: Allocator,
        manifest: *const Manifest,
    ) Allocator.Error!ReducedCheckpoint {
        return .{
            .bank_fields = try .fromBankFields(allocator, &manifest.bank_fields),
            .bank_extra = try .fromExtraFields(allocator, &manifest.bank_extra),
        };
    }

    pub fn toManifest(
        self: *const ReducedCheckpoint,
        allocator: Allocator,
    ) Allocator.Error!Manifest {
        return .{
            .bank_fields = try self.bank_fields.toBankFields(allocator),
            .accounts_db_fields = .{
                .file_map = .{},
                .stored_meta_write_version = 0,
                .slot = self.bank_fields.slot,
                .bank_hash_info = .{ .stats = .zero_init },
                .rooted_slots = &.{},
                .rooted_slot_hashes = &.{},
            },
            .bank_extra = try self.bank_extra.toExtraFields(allocator),
        };
    }

    pub fn readFromFilePath(
        allocator: Allocator,
        path: []const u8,
    ) !ReducedCheckpoint {
        const file = std.fs.cwd().openFile(path, .{}) catch |err| switch (err) {
            error.FileNotFound => return error.SnapshotFieldsNotFound,
            else => return err,
        };
        defer file.close();

        const stat = try file.stat();
        const contents = try file.readToEndAllocOptions(allocator, stat.size, stat.size, .@"1", null);
        defer allocator.free(contents);

        var fbs = std.io.fixedBufferStream(contents);
        return try bincode.read(allocator, ReducedCheckpoint, fbs.reader(), .{
            .allocation_limit = 2 << 30,
        });
    }

    pub fn writeToFilePath(
        self: *const ReducedCheckpoint,
        path: []const u8,
    ) !void {
        const file = try std.fs.cwd().createFile(path, .{ .truncate = true });
        defer file.close();
        try bincode.write(file.writer(), self.*, .{});
    }
};

pub fn loadAsLoadedSnapshot(
    allocator: Allocator,
    logger: Logger,
    checkpoint_path: []const u8,
    genesis_file_path: []const u8,
) !LoadedSnapshot {
    logger.info().logf("loading reduced checkpoint from {s}", .{checkpoint_path});

    var checkpoint = try ReducedCheckpoint.readFromFilePath(allocator, checkpoint_path);
    errdefer checkpoint.deinit(allocator);

    const genesis_config = try GenesisConfig.init(allocator, genesis_file_path);
    errdefer genesis_config.deinit(allocator);

    const reduced_bank_fields = try checkpoint.bank_fields.clone(allocator);
    defer reduced_bank_fields.deinit(allocator);
    const full_for_validation = try reduced_bank_fields.toBankFields(allocator);
    defer full_for_validation.deinit(allocator);
    try full_for_validation.validate(&genesis_config);

    const collapsed_manifest = try checkpoint.toManifest(allocator);
    errdefer collapsed_manifest.deinit(allocator);

    const full_manifest = try collapsed_manifest.clone(allocator);
    errdefer full_manifest.deinit(allocator);

    return .{
        .allocator = allocator,
        .combined_manifest = .{
            .full = full_manifest,
            .incremental = null,
        },
        .collapsed_manifest = collapsed_manifest,
        .genesis_config = genesis_config,
    };
}

test "ReducedCheckpoint round-trips through reduced schema" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(42);
    const random = prng.random();

    var bank_fields = try BankFields.initRandom(allocator, random, 4);
    defer bank_fields.deinit(allocator);

    var lt_hash: LtHash = undefined;
    random.bytes(std.mem.asBytes(&lt_hash));
    const bank_extra: ExtraFields = .{
        .lamports_per_signature = 0,
        .snapshot_persistence = null,
        .epoch_accounts_hash = null,
        .versioned_epoch_stakes = .{},
        .accounts_lt_hash = lt_hash,
    };

    var manifest: Manifest = .{
        .bank_fields = bank_fields,
        .accounts_db_fields = .{
            .file_map = .{},
            .stored_meta_write_version = 0,
            .slot = bank_fields.slot,
            .bank_hash_info = .{ .stats = .zero_init },
            .rooted_slots = &.{},
            .rooted_slot_hashes = &.{},
        },
        .bank_extra = bank_extra,
    };

    var checkpoint = try ReducedCheckpoint.fromManifest(allocator, &manifest);
    defer checkpoint.deinit(allocator);

    var rebuilt = try checkpoint.toManifest(allocator);
    defer rebuilt.deinit(allocator);

    try std.testing.expectEqual(manifest.bank_fields.slot, rebuilt.bank_fields.slot);
    try std.testing.expectEqual(manifest.bank_fields.parent_slot, rebuilt.bank_fields.parent_slot);
    try std.testing.expectEqual(manifest.bank_fields.block_height, rebuilt.bank_fields.block_height);
    try std.testing.expectEqual(manifest.bank_fields.ticks_per_slot, rebuilt.bank_fields.ticks_per_slot);
    try std.testing.expectEqual(manifest.bank_fields.ns_per_slot, rebuilt.bank_fields.ns_per_slot);
    try std.testing.expectEqual(manifest.bank_fields.genesis_creation_time, rebuilt.bank_fields.genesis_creation_time);
    try std.testing.expectEqual(manifest.bank_fields.epoch, rebuilt.bank_fields.epoch);
    try std.testing.expect(manifest.bank_fields.collector_id.equals(&rebuilt.bank_fields.collector_id));
    try std.testing.expect(manifest.bank_extra.accounts_lt_hash.eql(rebuilt.bank_extra.accounts_lt_hash));
    try std.testing.expectEqual(
        manifest.bank_extra.versioned_epoch_stakes.count(),
        rebuilt.bank_extra.versioned_epoch_stakes.count(),
    );
}
