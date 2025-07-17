const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;

const Epoch = sig.core.Epoch;
const Pubkey = sig.core.Pubkey;
const Stakes = sig.core.Stakes;
const StakesType = sig.core.StakesType;
const StakeHistory = sig.runtime.sysvar.StakeHistory;

const deinitMapAndValues = sig.utils.collections.deinitMapAndValues;
const cloneMapAndValues = sig.utils.collections.cloneMapAndValues;

// Deserialisation of EpochStakesMap and StakesCache in Agave
//
// deserialize_bank_fields: https://github.com/firedancer-io/agave/blob/10fe1eb29aac9c236fd72d08ae60a3ef61ee8353/runtime/src/serde_snapshot.rs#L425
//     bank_fields = deserialise_bank_fields(...)
//     extra_fields = deserialise_extra_fields(...)
//     bank_fields.epoch_stakes.extend(extra_fields.versioned_epoch_stakes)
//
// fields_from_streams: https://github.com/firedancer-io/agave/blob/10fe1eb29aac9c236fd72d08ae60a3ef61ee8353/runtime/src/serde_snapshot.rs#L519
// bank_from_streams: https://github.com/firedancer-io/agave/blob/10fe1eb29aac9c236fd72d08ae60a3ef61ee8353/runtime/src/serde_snapshot.rs#L556
// reconstruct_bank_from_fields: https://github.com/firedancer-io/agave/blob/10fe1eb29aac9c236fd72d08ae60a3ef61ee8353/runtime/src/serde_snapshot.rs#L847
// new_from_fields: https://github.com/firedancer-io/agave/blob/10fe1eb29aac9c236fd72d08ae60a3ef61ee8353/runtime/src/bank.rs#L1700
//     bank.stakes_cache = StakesCache.init(create Stakes(.account) from bank_fields.stakes: Stakes(.delegation) with accountsdb)
//         - we could load the accounts here and create Stakes(.stake) from the accountsdb
//     bank.epoch_stakes = fields.epoch_stakes

pub const VersionedEpochStakes = union(enum(u32)) {
    current: EpochStakesGeneric(.stake),

    pub fn deinit(self: VersionedEpochStakes, allocator: Allocator) void {
        self.current.deinit(allocator);
    }

    pub fn clone(
        self: *const VersionedEpochStakes,
        allocator: Allocator,
    ) Allocator.Error!VersionedEpochStakes {
        return .{ .current = try self.current.clone(allocator) };
    }

    pub fn initRandom(
        allocator: Allocator,
        random: std.Random,
        max_list_entries: usize,
    ) Allocator.Error!VersionedEpochStakes {
        return .{ .current = try EpochStakesGeneric(.stake).initRandom(
            allocator,
            random,
            max_list_entries,
        ) };
    }
};

pub fn EpochStakesMapGeneric(comptime stakes_type: StakesType) type {
    std.debug.assert(stakes_type != .account);
    return std.AutoArrayHashMapUnmanaged(Epoch, EpochStakesGeneric(stakes_type));
}

pub fn epochStakeMapRandom(
    allocator: Allocator,
    random: std.Random,
    comptime stakes_type: StakesType,
    min_list_entries: usize,
    max_list_entries: usize,
) Allocator.Error!EpochStakesMapGeneric(stakes_type) {
    var map: EpochStakesMapGeneric(stakes_type) = .empty;
    errdefer deinitMapAndValues(allocator, map);

    const map_len = random.intRangeAtMost(usize, min_list_entries, max_list_entries);
    try map.ensureTotalCapacity(allocator, map_len);

    for (0..map_len) |_| {
        const value_ptr = while (true) {
            const gop = map.getOrPutAssumeCapacity(random.int(Epoch));
            if (gop.found_existing) continue;
            break gop.value_ptr;
        };
        value_ptr.* = try .initRandom(allocator, random, max_list_entries);
    }

    return map;
}

pub fn EpochStakesGeneric(comptime stakes_type: StakesType) type {
    std.debug.assert(stakes_type != .account);
    return struct {
        stakes: Stakes(stakes_type),
        total_stake: u64,
        node_id_to_vote_accounts: std.AutoArrayHashMapUnmanaged(Pubkey, NodeVoteAccounts),
        epoch_authorized_voters: std.AutoArrayHashMapUnmanaged(Pubkey, Pubkey),

        const Self = @This();

        pub fn deinit(self: Self, allocator: Allocator) void {
            self.stakes.deinit(allocator);
            deinitMapAndValues(allocator, self.node_id_to_vote_accounts);
            var epoch_authorized_voters = self.epoch_authorized_voters;
            epoch_authorized_voters.deinit(allocator);
        }

        pub fn clone(self: *const Self, allocator: Allocator) !Self {
            const stakes = try self.stakes.clone(allocator);
            errdefer stakes.deinit(allocator);

            const node_id_to_vote_accounts =
                try cloneMapAndValues(allocator, self.node_id_to_vote_accounts);
            errdefer deinitMapAndValues(allocator, node_id_to_vote_accounts);

            const epoch_authorized_voters = try self.epoch_authorized_voters.clone(allocator);
            errdefer epoch_authorized_voters.deinit(allocator);

            return .{
                .stakes = stakes,
                .total_stake = self.total_stake,
                .node_id_to_vote_accounts = node_id_to_vote_accounts,
                .epoch_authorized_voters = epoch_authorized_voters,
            };
        }

        pub fn initEmptyWithGenesisStakeHistoryEntry(
            allocator: std.mem.Allocator,
        ) !EpochStakesGeneric(stakes_type) {
            return .{
                .total_stake = 0,
                .stakes = .{
                    .vote_accounts = .{},
                    .stake_delegations = .empty,
                    .unused = 0,
                    .epoch = 0,
                    .stake_history = try StakeHistory.initWithEntries(allocator, &.{.{
                        .epoch = 0,
                        .stake = .{
                            .effective = 0,
                            .activating = 0,
                            .deactivating = 0,
                        },
                    }}),
                },
                .node_id_to_vote_accounts = .empty,
                .epoch_authorized_voters = .empty,
            };
        }

        pub fn initRandom(
            allocator: Allocator,
            random: std.Random,
            max_list_entries: usize,
        ) Allocator.Error!Self {
            const stakes =
                try Stakes(stakes_type).initRandom(allocator, random, max_list_entries);
            errdefer stakes.deinit(allocator);

            var node_id_to_vote_accounts =
                std.AutoArrayHashMapUnmanaged(Pubkey, NodeVoteAccounts){};
            errdefer deinitMapAndValues(allocator, node_id_to_vote_accounts);
            for (0..random.uintAtMost(usize, max_list_entries)) |_| {
                const value =
                    try NodeVoteAccounts.initRandom(random, allocator, max_list_entries);
                errdefer value.deinit(allocator);
                try node_id_to_vote_accounts.put(allocator, Pubkey.initRandom(random), value);
            }

            var epoch_authorized_voters = std.AutoArrayHashMapUnmanaged(Pubkey, Pubkey){};
            errdefer epoch_authorized_voters.deinit(allocator);
            for (0..random.uintAtMost(usize, max_list_entries)) |_| {
                try epoch_authorized_voters.put(
                    allocator,
                    Pubkey.initRandom(random),
                    Pubkey.initRandom(random),
                );
            }

            return .{
                .stakes = stakes,
                .total_stake = random.int(u64),
                .node_id_to_vote_accounts = node_id_to_vote_accounts,
                .epoch_authorized_voters = epoch_authorized_voters,
            };
        }
    };
}

/// Analogous to [NodeVoteAccounts](https://github.com/anza-xyz/agave/blob/8d1ef48c785a5d9ee5c0df71dc520ee1a49d8168/runtime/src/epoch_stakes.rs#L14)
pub const NodeVoteAccounts = struct {
    vote_accounts: []const Pubkey,
    total_stake: u64,

    pub fn deinit(self: NodeVoteAccounts, allocator: Allocator) void {
        allocator.free(self.vote_accounts);
    }

    pub fn clone(
        self: NodeVoteAccounts,
        allocator: Allocator,
    ) Allocator.Error!NodeVoteAccounts {
        return .{
            .vote_accounts = try allocator.dupe(Pubkey, self.vote_accounts),
            .total_stake = self.total_stake,
        };
    }

    pub fn initRandom(
        random: std.Random,
        allocator: Allocator,
        max_list_entries: usize,
    ) Allocator.Error!NodeVoteAccounts {
        const vote_accounts = try allocator.alloc(
            Pubkey,
            random.uintLessThan(usize, max_list_entries),
        );
        errdefer allocator.free(vote_accounts);
        for (vote_accounts) |*vote_account| vote_account.* = Pubkey.initRandom(random);
        return .{
            .vote_accounts = vote_accounts,
            .total_stake = random.int(u64),
        };
    }
};
