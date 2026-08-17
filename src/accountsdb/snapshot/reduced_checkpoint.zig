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
const SlotConstants = sig.core.SlotConstants;
const SlotState = sig.core.SlotState;
const StakeHistory = sig.runtime.sysvar.StakeHistory;
const Stakes = sig.core.Stakes;
const StakeStateV2 = sig.runtime.program.stake.state.StakeStateV2;
const VoteAccount = sig.core.stakes.VoteAccount;
const VoteAccounts = sig.core.stakes.VoteAccounts;
const VoteState = sig.runtime.program.vote.state.VoteState;
const NodeVoteAccounts = sig.core.epoch_stakes.NodeVoteAccounts;
const UnixTimestamp = sig.core.UnixTimestamp;
const UnusedAccounts = sig.core.bank.UnusedAccounts;
const VersionedEpochStakes = sig.core.VersionedEpochStakes;
const bincode = sig.bincode;

const Logger = sig.trace.Logger("accountsdb.snapshot.reduced_checkpoint");

const ReducedStakeAndVoteAccountsMap = sig.utils.collections.PubkeyMap(ReducedStakeAndVoteAccount);
const ReducedStakedNodesMap = sig.utils.collections.PubkeyMap(u64);
const ReducedVersionedEpochStakesMap = std.AutoArrayHashMapUnmanaged(Epoch, ReducedVersionedEpochStakes);

pub const ReducedVoteAccount = struct {
    account: VoteAccount.MinimalAccount,
    state: VoteState,

    pub fn deinit(self: *const ReducedVoteAccount, allocator: Allocator) void {
        self.state.deinit(allocator);
    }

    pub fn clone(
        self: *const ReducedVoteAccount,
        allocator: Allocator,
    ) Allocator.Error!ReducedVoteAccount {
        return .{
            .account = self.account,
            .state = try self.state.clone(allocator),
        };
    }

    pub fn fromVoteAccount(
        allocator: Allocator,
        account: *const VoteAccount,
    ) Allocator.Error!ReducedVoteAccount {
        return .{
            .account = account.account,
            .state = try account.state.clone(allocator),
        };
    }

    pub fn toVoteAccount(
        self: *const ReducedVoteAccount,
        allocator: Allocator,
    ) Allocator.Error!VoteAccount {
        return .init(
            allocator,
            self.account,
            try self.state.clone(allocator),
        );
    }
};

pub const ReducedStakeAndVoteAccount = struct {
    stake: u64,
    account: ReducedVoteAccount,

    pub fn deinit(self: *const ReducedStakeAndVoteAccount, allocator: Allocator) void {
        self.account.deinit(allocator);
    }

    pub fn clone(
        self: *const ReducedStakeAndVoteAccount,
        allocator: Allocator,
    ) Allocator.Error!ReducedStakeAndVoteAccount {
        return .{
            .stake = self.stake,
            .account = try self.account.clone(allocator),
        };
    }
};

pub const ReducedVoteAccounts = struct {
    vote_accounts: ReducedStakeAndVoteAccountsMap = .{},
    staked_nodes: ReducedStakedNodesMap = .{},

    pub fn deinit(self: *const ReducedVoteAccounts, allocator: Allocator) void {
        sig.utils.collections.deinitMapAndValues(allocator, self.vote_accounts);
        var staked_nodes = self.staked_nodes;
        staked_nodes.deinit(allocator);
    }

    pub fn clone(
        self: *const ReducedVoteAccounts,
        allocator: Allocator,
    ) Allocator.Error!ReducedVoteAccounts {
        return .{
            .vote_accounts = try sig.utils.collections.cloneMapAndValues(allocator, self.vote_accounts),
            .staked_nodes = try self.staked_nodes.clone(allocator),
        };
    }

    pub fn fromVoteAccounts(
        allocator: Allocator,
        vote_accounts: *const VoteAccounts,
    ) Allocator.Error!ReducedVoteAccounts {
        var reduced_vote_accounts: ReducedStakeAndVoteAccountsMap = .{};
        errdefer sig.utils.collections.deinitMapAndValues(allocator, reduced_vote_accounts);

        for (vote_accounts.vote_accounts.keys(), vote_accounts.vote_accounts.values()) |key, value| {
            try reduced_vote_accounts.put(
                allocator,
                key,
                .{
                    .stake = value.stake,
                    .account = try ReducedVoteAccount.fromVoteAccount(allocator, &value.account),
                },
            );
        }

        return .{
            .vote_accounts = reduced_vote_accounts,
            .staked_nodes = try vote_accounts.staked_nodes.clone(allocator),
        };
    }

    pub fn toVoteAccounts(
        self: *const ReducedVoteAccounts,
        allocator: Allocator,
    ) Allocator.Error!VoteAccounts {
        var vote_accounts: sig.core.stakes.StakeAndVoteAccountsMap = .{};
        errdefer sig.utils.collections.deinitMapAndValues(allocator, vote_accounts);

        for (self.vote_accounts.keys(), self.vote_accounts.values()) |key, value| {
            try vote_accounts.put(
                allocator,
                key,
                .{
                    .stake = value.stake,
                    .account = try value.account.toVoteAccount(allocator),
                },
            );
        }

        return .{
            .vote_accounts = vote_accounts,
            .staked_nodes = try self.staked_nodes.clone(allocator),
        };
    }
};

pub const ReducedStakes = struct {
    vote_accounts: ReducedVoteAccounts,
    stake_accounts: std.AutoArrayHashMapUnmanaged(Pubkey, StakeStateV2.Stake),
    unused: u64,
    epoch: Epoch,
    stake_history: StakeHistory,

    pub fn deinit(self: *const ReducedStakes, allocator: Allocator) void {
        self.vote_accounts.deinit(allocator);
        var stake_accounts = self.stake_accounts;
        stake_accounts.deinit(allocator);
    }

    pub fn clone(
        self: *const ReducedStakes,
        allocator: Allocator,
    ) Allocator.Error!ReducedStakes {
        return .{
            .vote_accounts = try self.vote_accounts.clone(allocator),
            .stake_accounts = try self.stake_accounts.clone(allocator),
            .unused = self.unused,
            .epoch = self.epoch,
            .stake_history = self.stake_history,
        };
    }

    pub fn fromStakes(
        allocator: Allocator,
        stakes: *const Stakes(.stake),
    ) Allocator.Error!ReducedStakes {
        return .{
            .vote_accounts = try ReducedVoteAccounts.fromVoteAccounts(allocator, &stakes.vote_accounts),
            .stake_accounts = try stakes.stake_accounts.clone(allocator),
            .unused = stakes.unused,
            .epoch = stakes.epoch,
            .stake_history = stakes.stake_history,
        };
    }

    pub fn toStakes(
        self: *const ReducedStakes,
        allocator: Allocator,
    ) Allocator.Error!Stakes(.stake) {
        return .{
            .vote_accounts = try self.vote_accounts.toVoteAccounts(allocator),
            .stake_accounts = try self.stake_accounts.clone(allocator),
            .unused = self.unused,
            .epoch = self.epoch,
            .stake_history = self.stake_history,
        };
    }
};

pub const ReducedEpochStakes = struct {
    stakes: ReducedStakes,
    total_stake: u64,
    node_id_to_vote_accounts: sig.utils.collections.PubkeyMap(NodeVoteAccounts),
    epoch_authorized_voters: sig.utils.collections.PubkeyMap(Pubkey),

    pub fn deinit(self: *const ReducedEpochStakes, allocator: Allocator) void {
        self.stakes.deinit(allocator);
        sig.utils.collections.deinitMapAndValues(allocator, self.node_id_to_vote_accounts);
        var epoch_authorized_voters = self.epoch_authorized_voters;
        epoch_authorized_voters.deinit(allocator);
    }

    pub fn clone(
        self: *const ReducedEpochStakes,
        allocator: Allocator,
    ) Allocator.Error!ReducedEpochStakes {
        return .{
            .stakes = try self.stakes.clone(allocator),
            .total_stake = self.total_stake,
            .node_id_to_vote_accounts = try sig.utils.collections.cloneMapAndValues(
                allocator,
                self.node_id_to_vote_accounts,
            ),
            .epoch_authorized_voters = try self.epoch_authorized_voters.clone(allocator),
        };
    }

    pub fn fromEpochStakes(
        allocator: Allocator,
        epoch_stakes: *const sig.core.epoch_stakes.EpochStakesGeneric(.stake),
    ) Allocator.Error!ReducedEpochStakes {
        return .{
            .stakes = try ReducedStakes.fromStakes(allocator, &epoch_stakes.stakes),
            .total_stake = epoch_stakes.total_stake,
            .node_id_to_vote_accounts = try sig.utils.collections.cloneMapAndValues(
                allocator,
                epoch_stakes.node_id_to_vote_accounts,
            ),
            .epoch_authorized_voters = try epoch_stakes.epoch_authorized_voters.clone(allocator),
        };
    }

    pub fn toEpochStakes(
        self: *const ReducedEpochStakes,
        allocator: Allocator,
    ) Allocator.Error!sig.core.epoch_stakes.EpochStakesGeneric(.stake) {
        return .{
            .stakes = try self.stakes.toStakes(allocator),
            .total_stake = self.total_stake,
            .node_id_to_vote_accounts = try sig.utils.collections.cloneMapAndValues(
                allocator,
                self.node_id_to_vote_accounts,
            ),
            .epoch_authorized_voters = try self.epoch_authorized_voters.clone(allocator),
        };
    }
};

pub const ReducedVersionedEpochStakes = union(enum(u32)) {
    current: ReducedEpochStakes,

    pub fn deinit(self: *const ReducedVersionedEpochStakes, allocator: Allocator) void {
        self.current.deinit(allocator);
    }

    pub fn clone(
        self: *const ReducedVersionedEpochStakes,
        allocator: Allocator,
    ) Allocator.Error!ReducedVersionedEpochStakes {
        return .{ .current = try self.current.clone(allocator) };
    }

    pub fn fromVersionedEpochStakes(
        allocator: Allocator,
        value: *const VersionedEpochStakes,
    ) Allocator.Error!ReducedVersionedEpochStakes {
        return .{ .current = try ReducedEpochStakes.fromEpochStakes(allocator, &value.current) };
    }

    pub fn toVersionedEpochStakes(
        self: *const ReducedVersionedEpochStakes,
        allocator: Allocator,
    ) Allocator.Error!VersionedEpochStakes {
        return .{ .current = try self.current.toEpochStakes(allocator) };
    }
};

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

    pub fn deinit(self: *const ReducedBankFields, allocator: Allocator) void {
        self.blockhash_queue.deinit(allocator);

        var ancestors = self.ancestors;
        ancestors.deinit(allocator);

        self.hard_forks.deinit(allocator);
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
            .epoch = bank_fields.epoch_schedule.getEpoch(bank_fields.slot),
            .block_height = bank_fields.block_height,
            .collector_id = bank_fields.collector_id,
            .fee_rate_governor = bank_fields.fee_rate_governor,
            .collected_rent = bank_fields.collected_rent,
            .rent_collector = bank_fields.rent_collector,
            .epoch_schedule = bank_fields.epoch_schedule,
            .inflation = bank_fields.inflation,
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
            .stakes = .EMPTY,
            .unused_accounts = UnusedAccounts.EMPTY,
            .epoch_stakes = .{},
            .is_delta = false,
        };
    }
};

pub const ReducedExtraFields = struct {
    versioned_epoch_stakes: ReducedVersionedEpochStakesMap,
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
        var versioned_epoch_stakes: ReducedVersionedEpochStakesMap = .{};
        errdefer sig.utils.collections.deinitMapAndValues(allocator, versioned_epoch_stakes);

        for (extra.versioned_epoch_stakes.keys(), extra.versioned_epoch_stakes.values()) |epoch, value| {
            try versioned_epoch_stakes.put(
                allocator,
                epoch,
                try ReducedVersionedEpochStakes.fromVersionedEpochStakes(allocator, &value),
            );
        }

        return .{
            .versioned_epoch_stakes = versioned_epoch_stakes,
            .accounts_lt_hash = extra.accounts_lt_hash,
        };
    }

    pub fn toExtraFields(
        self: *const ReducedExtraFields,
        allocator: Allocator,
    ) Allocator.Error!ExtraFields {
        var versioned_epoch_stakes: std.AutoArrayHashMapUnmanaged(Epoch, VersionedEpochStakes) = .{};
        errdefer sig.utils.collections.deinitMapAndValues(allocator, versioned_epoch_stakes);

        for (self.versioned_epoch_stakes.keys(), self.versioned_epoch_stakes.values()) |epoch, value| {
            try versioned_epoch_stakes.put(
                allocator,
                epoch,
                try value.toVersionedEpochStakes(allocator),
            );
        }

        return .{
            .lamports_per_signature = 0,
            .snapshot_persistence = null,
            .epoch_accounts_hash = null,
            .versioned_epoch_stakes = versioned_epoch_stakes,
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

    pub fn clone(
        self: *const ReducedCheckpoint,
        allocator: Allocator,
    ) Allocator.Error!ReducedCheckpoint {
        const bank_fields = try self.bank_fields.clone(allocator);
        errdefer bank_fields.deinit(allocator);
        return .{
            .bank_fields = bank_fields,
            .bank_extra = try self.bank_extra.clone(allocator),
        };
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

    /// Builds restart metadata from a frozen, rooted replay slot while retaining
    /// the snapshot-scoped constants and epoch-stakes payload from `template`.
    /// Epoch-boundary rollover is intentionally rejected until the live epoch
    /// tracker can be serialized into the reduced schema.
    pub fn fromFrozenReplaySlot(
        allocator: Allocator,
        template: *const ReducedCheckpoint,
        slot: sig.core.Slot,
        constants: *const SlotConstants,
        state: *SlotState,
        hard_forks: *const HardForks,
    ) !ReducedCheckpoint {
        if (!state.isFrozen()) return error.RollingCheckpointSlotNotFrozen;

        const epoch = template.bank_fields.epoch_schedule.getEpoch(slot);
        if (epoch != template.bank_fields.epoch) {
            return error.RollingCheckpointEpochBoundaryUnsupported;
        }

        const hash = state.hash.readCopy() orelse
            return error.RollingCheckpointSlotNotFrozen;
        const accounts_lt_hash = state.accounts_lt_hash.readCopy() orelse
            return error.RollingCheckpointMissingLtHash;

        const blockhash_queue = blk: {
            var guard = state.blockhash_queue.read();
            defer guard.unlock();
            break :blk try guard.get().clone(allocator);
        };
        errdefer blockhash_queue.deinit(allocator);

        const ancestors = try constants.ancestors.clone(allocator);
        errdefer ancestors.deinit(allocator);

        const cloned_hard_forks = try hard_forks.clone(allocator);
        errdefer cloned_hard_forks.deinit(allocator);

        var bank_extra = try template.bank_extra.clone(allocator);
        errdefer bank_extra.deinit(allocator);
        bank_extra.accounts_lt_hash = accounts_lt_hash;

        return .{
            .bank_fields = .{
                .blockhash_queue = blockhash_queue,
                .ancestors = ancestors,
                .hash = hash,
                .parent_hash = constants.parent_hash,
                .parent_slot = constants.parent_slot,
                .hard_forks = cloned_hard_forks,
                .transaction_count = state.transaction_count.load(.monotonic),
                .tick_height = state.tick_height.load(.monotonic),
                .signature_count = state.signature_count.load(.monotonic),
                .capitalization = state.capitalization.load(.monotonic),
                .max_tick_height = constants.max_tick_height,
                .hashes_per_tick = template.bank_fields.hashes_per_tick,
                .ticks_per_slot = template.bank_fields.ticks_per_slot,
                .ns_per_slot = template.bank_fields.ns_per_slot,
                .genesis_creation_time = template.bank_fields.genesis_creation_time,
                .slots_per_year = template.bank_fields.slots_per_year,
                .slot = slot,
                .epoch = epoch,
                .block_height = constants.block_height,
                .collector_id = constants.collector_id,
                .fee_rate_governor = constants.fee_rate_governor,
                .collected_rent = state.collected_rent.load(.monotonic),
                .rent_collector = constants.rent_collector,
                .epoch_schedule = template.bank_fields.epoch_schedule,
                .inflation = constants.inflation,
            },
            .bank_extra = bank_extra,
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

        var write_buf: [4096]u8 = undefined;
        var writer = file.writer(&write_buf);
        try bincode.write(&writer.interface, self.*, .{});
        try writer.end();
        try file.sync();
    }

    pub fn writeToFilePathAtomic(
        self: *const ReducedCheckpoint,
        allocator: Allocator,
        path: []const u8,
    ) !void {
        const next_path = try std.fmt.allocPrint(allocator, "{s}.next", .{path});
        defer allocator.free(next_path);
        errdefer std.fs.cwd().deleteFile(next_path) catch {};

        try self.writeToFilePath(next_path);
        try std.fs.cwd().rename(next_path, path);
    }
};

pub fn writeManifestToFilePath(
    allocator: Allocator,
    logger: Logger,
    manifest: *const Manifest,
    checkpoint_path: []const u8,
) !void {
    logger.info().logf("writing reduced checkpoint to {s}", .{checkpoint_path});

    var checkpoint = try ReducedCheckpoint.fromManifest(allocator, manifest);
    defer checkpoint.deinit(allocator);

    try checkpoint.writeToFilePath(checkpoint_path);
}

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
    try std.testing.expectEqual(
        manifest.bank_fields.epoch_schedule.getEpoch(manifest.bank_fields.slot),
        rebuilt.bank_fields.epoch,
    );
    try std.testing.expect(manifest.bank_fields.collector_id.equals(&rebuilt.bank_fields.collector_id));
    try std.testing.expect(manifest.bank_extra.accounts_lt_hash.eql(rebuilt.bank_extra.accounts_lt_hash));
    try std.testing.expectEqual(
        manifest.bank_extra.versioned_epoch_stakes.count(),
        rebuilt.bank_extra.versioned_epoch_stakes.count(),
    );
}

test "ReducedCheckpoint canonicalizes bank epoch from slot" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(123);
    const random = prng.random();

    var bank_fields = try BankFields.initRandom(allocator, random, 2);
    defer bank_fields.deinit(allocator);

    bank_fields.slot = 436_194_174;
    bank_fields.epoch_schedule = EpochSchedule.INIT;
    bank_fields.epoch = 0;

    const bank_extra: ExtraFields = .{
        .lamports_per_signature = 0,
        .snapshot_persistence = null,
        .epoch_accounts_hash = null,
        .versioned_epoch_stakes = .{},
        .accounts_lt_hash = .IDENTITY,
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

    const expected_epoch = bank_fields.epoch_schedule.getEpoch(bank_fields.slot);
    try std.testing.expectEqual(expected_epoch, checkpoint.bank_fields.epoch);

    var rebuilt = try checkpoint.toManifest(allocator);
    defer rebuilt.deinit(allocator);

    try std.testing.expectEqual(expected_epoch, rebuilt.bank_fields.epoch);
}

test "writeManifestToFilePath persists reduced checkpoint metadata" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(99);
    const random = prng.random();

    var bank_fields = try BankFields.initRandom(allocator, random, 3);
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

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const checkpoint_path = try tmp.dir.realpathAlloc(allocator, "oracle-reduced-checkpoint.bin");
    defer allocator.free(checkpoint_path);

    try writeManifestToFilePath(
        allocator,
        Logger.noop,
        &manifest,
        checkpoint_path,
    );

    var checkpoint = try ReducedCheckpoint.readFromFilePath(allocator, checkpoint_path);
    defer checkpoint.deinit(allocator);

    try std.testing.expectEqual(manifest.bank_fields.slot, checkpoint.bank_fields.slot);
    try std.testing.expectEqual(manifest.bank_fields.parent_slot, checkpoint.bank_fields.parent_slot);
    try std.testing.expect(manifest.bank_extra.accounts_lt_hash.eql(checkpoint.bank_extra.accounts_lt_hash));
}

test "ReducedCheckpoint rolls a frozen replay slot and replaces atomically" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(314_159);
    const random = prng.random();

    var bank_fields = try BankFields.initRandom(allocator, random, 3);
    defer bank_fields.deinit(allocator);

    var lt_hash: LtHash = undefined;
    random.bytes(std.mem.asBytes(&lt_hash));
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
        .bank_extra = .{
            .lamports_per_signature = 0,
            .snapshot_persistence = null,
            .epoch_accounts_hash = null,
            .versioned_epoch_stakes = .{},
            .accounts_lt_hash = lt_hash,
        },
    };

    var template = try ReducedCheckpoint.fromManifest(allocator, &manifest);
    defer template.deinit(allocator);
    var constants = try SlotConstants.fromBankFields(
        allocator,
        &bank_fields,
        .ALL_DISABLED,
    );
    defer constants.deinit(allocator);
    var state = try SlotState.fromBankFieldsForTest(allocator, &bank_fields, lt_hash);
    defer state.deinit(allocator);

    var rolled = try ReducedCheckpoint.fromFrozenReplaySlot(
        allocator,
        &template,
        bank_fields.slot,
        &constants,
        &state,
        &bank_fields.hard_forks,
    );
    defer rolled.deinit(allocator);

    try std.testing.expectEqual(bank_fields.slot, rolled.bank_fields.slot);
    try std.testing.expectEqual(bank_fields.parent_slot, rolled.bank_fields.parent_slot);
    try std.testing.expectEqual(bank_fields.block_height, rolled.bank_fields.block_height);
    try std.testing.expect(bank_fields.hash.eql(rolled.bank_fields.hash));
    try std.testing.expect(lt_hash.eql(rolled.bank_extra.accounts_lt_hash));

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_path);
    const checkpoint_path = try std.fs.path.join(
        allocator,
        &.{ tmp_path, "rolling-reduced-checkpoint.bin" },
    );
    defer allocator.free(checkpoint_path);

    try rolled.writeToFilePathAtomic(allocator, checkpoint_path);
    rolled.bank_fields.block_height +%= 1;
    try rolled.writeToFilePathAtomic(allocator, checkpoint_path);

    var loaded = try ReducedCheckpoint.readFromFilePath(allocator, checkpoint_path);
    defer loaded.deinit(allocator);
    try std.testing.expectEqual(rolled.bank_fields.block_height, loaded.bank_fields.block_height);

    const next_path = try std.fmt.allocPrint(allocator, "{s}.next", .{checkpoint_path});
    defer allocator.free(next_path);
    try std.testing.expectError(error.FileNotFound, std.fs.cwd().access(next_path, .{}));
}
