//! fields + data to deserialize snapshot metadata

const std = @import("std");
const zstd = @import("zstd");
const sig = @import("../sig.zig");

const bincode = sig.bincode;

const Account = sig.core.account.Account;
const Epoch = sig.core.time.Epoch;
const Hash = sig.core.hash.Hash;
const Pubkey = sig.core.pubkey.Pubkey;
const Slot = sig.core.time.Slot;

const FileId = sig.accounts_db.accounts_file.FileId;

const EpochSchedule = sig.core.EpochSchedule;
const FeeRateGovernor = sig.accounts_db.genesis_config.FeeRateGovernor;
const Inflation = sig.accounts_db.genesis_config.Inflation;
const Rent = sig.accounts_db.genesis_config.Rent;
const UnixTimestamp = sig.accounts_db.genesis_config.UnixTimestamp;
const SlotHistory = sig.accounts_db.sysvars.SlotHistory;

const Logger = sig.trace.Logger;

const defaultArrayListUnmanagedOnEOFConfig = bincode.arraylist.defaultArrayListUnmanagedOnEOFConfig;
const parallelUntarToFileSystem = sig.utils.tar.parallelUntarToFileSystem;
const readDirectory = sig.utils.directory.readDirectory;

pub const MAXIMUM_ACCOUNT_FILE_SIZE: u64 = 16 * 1024 * 1024 * 1024; // 16 GiB
pub const MAX_RECENT_BLOCKHASHES: usize = 300;
pub const MAX_CACHE_ENTRIES: usize = MAX_RECENT_BLOCKHASHES;
const CACHED_KEY_SIZE: usize = 20;

/// Analogous to [StakeHistoryEntry](https://github.com/anza-xyz/agave/blob/5a9906ebf4f24cd2a2b15aca638d609ceed87797/sdk/program/src/stake_history.rs#L17)
pub const StakeHistoryEntry = struct {
    /// effective stake at this epoch
    effective: u64,
    /// sum of portion of stakes not fully warmed up
    activating: u64,
    /// requested to be cooled down, not fully deactivated yet
    deactivating: u64,

    pub fn random(rand: std.Random) StakeHistoryEntry {
        return .{
            .effective = rand.int(u64),
            .activating = rand.int(u64),
            .deactivating = rand.int(u64),
        };
    }
};

pub const EpochAndStakeHistoryEntry = struct { Epoch, StakeHistoryEntry };

pub fn epochAndStakeHistoryEntryRandom(rand: std.Random) EpochAndStakeHistoryEntry {
    return .{ rand.int(Epoch), StakeHistoryEntry.random(rand) };
}

/// Analogous to [StakeHistory](https://github.com/anza-xyz/agave/blob/5a9906ebf4f24cd2a2b15aca638d609ceed87797/sdk/program/src/stake_history.rs#L62)
pub const StakeHistory = []const EpochAndStakeHistoryEntry;

pub fn stakeHistoryRandom(
    rand: std.Random,
    allocator: std.mem.Allocator,
    max_list_entries: usize,
) std.mem.Allocator.Error!StakeHistory {
    const StakeHistoryItem = struct { Epoch, StakeHistoryEntry };
    const stake_history_len = rand.uintAtMost(usize, max_list_entries);

    const stake_history = try allocator.alloc(StakeHistoryItem, stake_history_len);
    errdefer allocator.free(stake_history);

    for (stake_history) |*entry| entry.* = epochAndStakeHistoryEntryRandom(rand);
    return stake_history;
}

pub const StakeDelegations = std.AutoArrayHashMapUnmanaged(Pubkey, Delegation);

pub fn stakeDelegationsRandom(
    rand: std.Random,
    allocator: std.mem.Allocator,
    max_list_entries: usize,
) std.mem.Allocator.Error!StakeDelegations {
    var stake_delegations = std.AutoArrayHashMap(Pubkey, Delegation).init(allocator);
    errdefer stake_delegations.deinit();

    try sig.rand.fillHashmapWithRng(&stake_delegations, rand, rand.uintAtMost(usize, max_list_entries), struct {
        pub fn randomKey(_rand: std.Random) !Pubkey {
            return Pubkey.random(_rand);
        }
        pub fn randomValue(_rand: std.Random) !Delegation {
            return Delegation.random(_rand);
        }
    });

    return stake_delegations.unmanaged;
}

/// Analogous to [Stakes](https://github.com/anza-xyz/agave/blob/1f3ef3325fb0ce08333715aa9d92f831adc4c559/runtime/src/stakes.rs#L186)
pub const Stakes = struct {
    /// vote accounts
    vote_accounts: VoteAccounts,

    /// stake_delegations
    stake_delegations: StakeDelegations,

    /// unused
    unused: u64,

    /// current epoch, used to calculate current stake
    epoch: Epoch,

    /// history of staking levels
    stake_history: StakeHistory,

    pub fn deinit(stakes: Stakes, allocator: std.mem.Allocator) void {
        stakes.vote_accounts.deinit(allocator);

        var stake_delegations = stakes.stake_delegations;
        stake_delegations.deinit(allocator);

        allocator.free(stakes.stake_history);
    }

    pub fn random(
        allocator: std.mem.Allocator,
        /// Should be a PRNG, not a true RNG. See the documentation on `std.Random.uintLessThan`
        /// for commentary on the runtime of this function.
        rand: std.Random,
        max_list_entries: usize,
    ) std.mem.Allocator.Error!Stakes {
        const vote_accounts = try VoteAccounts.random(rand, allocator, max_list_entries);
        errdefer vote_accounts.deinit(allocator);

        var stake_delegations = try stakeDelegationsRandom(rand, allocator, max_list_entries);
        errdefer stake_delegations.deinit(allocator);

        var stake_history = try stakeHistoryRandom(rand, allocator, max_list_entries);
        errdefer stake_history.deinit(allocator);

        return .{
            .vote_accounts = vote_accounts,
            .stake_delegations = stake_delegations,
            .unused = rand.int(u64),
            .epoch = rand.int(Epoch),
            .stake_history = stake_history,
        };
    }
};

/// Analogous to [VoteAccounts](https://github.com/anza-xyz/agave/blob/cadba689cb44db93e9c625770cafd2fc0ae89e33/vote/src/vote_account.rs#L44)
pub const VoteAccounts = struct {
    vote_accounts: std.AutoArrayHashMapUnmanaged(Pubkey, StakeAndVoteAccount),
    staked_nodes: ?std.AutoArrayHashMapUnmanaged(
        Pubkey, // VoteAccount.vote_state.node_pubkey.
        u64, // Total stake across all vote-accounts.
    ) = null,

    pub const @"!bincode-config:staked_nodes" = bincode.FieldConfig(?std.AutoArrayHashMapUnmanaged(Pubkey, u64)){ .skip = true };

    const Self = @This();

    pub const StakeAndVoteAccount = struct { u64, VoteAccount };

    pub fn deinit(vote_accounts: VoteAccounts, allocator: std.mem.Allocator) void {
        var copy = vote_accounts;

        for (copy.vote_accounts.values()) |entry| {
            _, const vote_account = entry;
            vote_account.deinit(allocator);
        }
        copy.vote_accounts.deinit(allocator);

        if (copy.staked_nodes) |*staked_nodes| {
            staked_nodes.deinit(allocator);
        }
    }

    pub fn stakedNodes(self: *Self, allocator: std.mem.Allocator) !*const std.AutoArrayHashMapUnmanaged(Pubkey, u64) {
        if (self.staked_nodes) |*staked_nodes| {
            return staked_nodes;
        }
        const vote_accounts = self.vote_accounts;
        var staked_nodes = std.AutoArrayHashMap(Pubkey, u64).init(allocator);
        var iter = vote_accounts.iterator();
        while (iter.next()) |vote_entry| {
            if (vote_entry.value_ptr[0] == 0) continue;
            const vote_state = try vote_entry.value_ptr[1].voteState();
            const node_entry = try staked_nodes.getOrPut(vote_state.node_pubkey);
            if (!node_entry.found_existing) {
                node_entry.value_ptr.* = 0;
            }
            node_entry.value_ptr.* += vote_entry.value_ptr[0];
        }
        self.staked_nodes = staked_nodes.unmanaged;
        return &self.staked_nodes.?;
    }

    pub fn random(
        rand: std.Random,
        allocator: std.mem.Allocator,
        max_list_entries: usize,
    ) std.mem.Allocator.Error!VoteAccounts {
        var stakes_vote_accounts = std.AutoArrayHashMap(Pubkey, VoteAccounts.StakeAndVoteAccount).init(allocator);
        errdefer stakes_vote_accounts.deinit();

        errdefer for (stakes_vote_accounts.values()) |pair| {
            _, const vote_account = pair;
            vote_account.account.deinit(allocator);
        };

        try sig.rand.fillHashmapWithRng(&stakes_vote_accounts, rand, rand.uintAtMost(usize, max_list_entries), struct {
            allocator: std.mem.Allocator,
            max_list_entries: usize,

            pub fn randomKey(_: @This(), _rand: std.Random) !Pubkey {
                return Pubkey.random(_rand);
            }
            pub fn randomValue(ctx: @This(), _rand: std.Random) !StakeAndVoteAccount {
                const vote_account: VoteAccount = try VoteAccount.random(_rand, ctx.allocator, ctx.max_list_entries, error{ RandomError1, RandomError2, RandomError3 });
                errdefer vote_account.deinit(ctx.allocator);
                return .{ _rand.int(u64), vote_account };
            }
        }{
            .allocator = allocator,
            .max_list_entries = max_list_entries,
        });

        var stakes_maybe_staked_nodes = if (rand.boolean()) std.AutoArrayHashMap(Pubkey, u64).init(allocator) else null;
        errdefer if (stakes_maybe_staked_nodes) |*staked_nodes| staked_nodes.deinit();

        if (stakes_maybe_staked_nodes) |*staked_nodes| try sig.rand.fillHashmapWithRng(staked_nodes, rand, rand.uintAtMost(usize, max_list_entries), struct {
            pub fn randomKey(_rand: std.Random) !Pubkey {
                return Pubkey.random(_rand);
            }
            pub fn randomValue(_rand: std.Random) !u64 {
                return _rand.int(u64);
            }
        });

        return .{
            .vote_accounts = stakes_vote_accounts.unmanaged,
            .staked_nodes = if (stakes_maybe_staked_nodes) |staked_nodes| staked_nodes.unmanaged else null,
        };
    }
};

pub const VoteAccount = struct {
    account: Account,
    vote_state: ?anyerror!VoteState = null,

    pub const @"!bincode-config:vote_state" = bincode.FieldConfig(?anyerror!VoteState){ .skip = true };

    pub fn deinit(vote_account: VoteAccount, allocator: std.mem.Allocator) void {
        vote_account.account.deinit(allocator);
    }

    pub fn voteState(self: *@This()) !VoteState {
        if (self.vote_state) |vs| {
            return vs;
        }
        self.vote_state = bincode.readFromSlice(undefined, VoteState, self.account.data, .{});
        return self.vote_state.?;
    }

    pub fn random(
        rand: std.Random,
        allocator: std.mem.Allocator,
        max_list_entries: usize,
        comptime RandomErrorSet: type,
    ) std.mem.Allocator.Error!VoteAccount {
        const account = try Account.random(allocator, rand, rand.uintAtMost(usize, max_list_entries));
        errdefer account.deinit(allocator);

        const vote_state: ?anyerror!VoteState = switch (rand.enumValue(enum { null, err, value })) {
            .null => null,
            .err => @as(anyerror!VoteState, sig.rand.errorValue(rand, RandomErrorSet)),
            .value => VoteState.random(rand),
        };

        return .{
            .account = account,
            .vote_state = vote_state,
        };
    }
};

pub const VoteState = struct {
    /// The variant of the rust enum
    tag: u32, // TODO: consider varint bincode serialization (in rust this is enum)
    /// the node that votes in this account
    node_pubkey: Pubkey,

    pub fn random(rand: std.Random) VoteState {
        return .{
            .tag = 0, // must always be 0, since this is the enum tag
            .node_pubkey = Pubkey.random(rand),
        };
    }
};

test "deserialize VoteState.node_pubkey" {
    const bytes = .{
        2,  0,   0,   0, 60,  155, 13,  144, 187, 252, 153, 72,  190, 35,  87,  94,  7,  178,
        90, 174, 158, 6, 199, 179, 134, 194, 112, 248, 166, 232, 144, 253, 128, 249, 67, 118,
    } ++ .{0} ** 1586 ++ .{ 31, 0, 0, 0, 0, 0, 0, 0, 1 } ++ .{0} ** 24;
    const vote_state = try bincode.readFromSlice(undefined, VoteState, &bytes, .{});
    const expected_pubkey = try Pubkey.fromString("55abJrqFnjm7ZRB1noVdh7BzBe3bBSMFT3pt16mw6Vad");
    try std.testing.expect(expected_pubkey.equals(&vote_state.node_pubkey));
}

/// Analogous to [Delegation](https://github.com/anza-xyz/agave/blob/f807911531359e0ae4cfcaf371bd3843ec52f1c6/sdk/program/src/stake/state.rs#L587)
pub const Delegation = struct {
    /// to whom the stake is delegated
    voter_pubkey: Pubkey,
    /// activated stake amount, set at delegate() time
    stake: u64,
    /// epoch at which this stake was activated, std::Epoch::MAX if is a bootstrap stake
    activation_epoch: Epoch,
    /// epoch the stake was deactivated, std::Epoch::MAX if not deactivated
    deactivation_epoch: Epoch,
    /// how much stake we can activate per-epoch as a fraction of currently effective stake
    /// depreciated!
    warmup_cooldown_rate: f64,

    pub fn random(rand: std.Random) Delegation {
        return .{
            .voter_pubkey = Pubkey.random(rand),
            .stake = rand.int(u64),
            .activation_epoch = rand.int(Epoch),
            .deactivation_epoch = rand.int(Epoch),
            .warmup_cooldown_rate = @bitCast(rand.int(u64)),
        };
    }
};

/// Analogous to [RentCollector](https://github.com/anza-xyz/agave/blob/cadba689cb44db93e9c625770cafd2fc0ae89e33/sdk/src/rent_collector.rs#L16)
pub const RentCollector = struct {
    epoch: Epoch,
    epoch_schedule: EpochSchedule,
    slots_per_year: f64,
    rent: Rent,

    pub fn random(rand: std.Random) RentCollector {
        return .{
            .epoch = rand.int(Epoch),
            .epoch_schedule = EpochSchedule.random(rand),
            .slots_per_year = @bitCast(rand.int(u64)),
            .rent = Rent.random(rand),
        };
    }
};

/// Analogous to (FeeCalculator)[https://github.com/anza-xyz/agave/blob/ec9bd798492c3b15d62942f2d9b5923b99042350/sdk/program/src/fee_calculator.rs#L13]
pub const FeeCalculator = struct {
    /// The current cost of a signature.
    ///
    /// This amount may increase/decrease over time based on cluster processing
    /// load.
    lamports_per_signature: u64,

    pub fn random(rand: std.Random) FeeCalculator {
        return .{ .lamports_per_signature = rand.int(u64) };
    }
};

/// Analogous to [HashInfo](https://github.com/anza-xyz/agave/blob/a79ba51741864e94a066a8e27100dfef14df835f/accounts-db/src/blockhash_queue.rs#L13)
pub const HashAge = struct {
    fee_calculator: FeeCalculator,
    hash_index: u64,
    timestamp: u64,

    pub fn random(rand: std.Random) HashAge {
        return .{
            .fee_calculator = FeeCalculator.random(rand),
            .hash_index = rand.int(u64),
            .timestamp = rand.int(u64),
        };
    }
};

pub const BlockhashQueueAges = std.AutoArrayHashMapUnmanaged(Hash, HashAge);

pub fn blockhashQueueAgesRandom(
    rand: std.Random,
    allocator: std.mem.Allocator,
    max_list_entries: usize,
) std.mem.Allocator.Error!BlockhashQueueAges {
    var ages = BlockhashQueueAges.Managed.init(allocator);
    errdefer ages.deinit();

    try sig.rand.fillHashmapWithRng(&ages, rand, rand.uintAtMost(usize, max_list_entries), struct {
        pub fn randomKey(_rand: std.Random) !Hash {
            return Hash.random(_rand);
        }
        pub fn randomValue(_rand: std.Random) !HashAge {
            return HashAge.random(_rand);
        }
    });

    return ages.unmanaged;
}

/// Analogous to [BlockhashQueue](https://github.com/anza-xyz/agave/blob/a79ba51741864e94a066a8e27100dfef14df835f/accounts-db/src/blockhash_queue.rs#L32)
pub const BlockhashQueue = struct {
    last_hash_index: u64,

    /// last hash to be registered
    last_hash: ?Hash,
    ages: BlockhashQueueAges,

    /// hashes older than `max_age` will be dropped from the queue
    max_age: usize,

    pub fn deinit(bhq: BlockhashQueue, allocator: std.mem.Allocator) void {
        var ages = bhq.ages;
        ages.deinit(allocator);
    }

    pub fn random(
        rand: std.Random,
        allocator: std.mem.Allocator,
        max_list_entries: usize,
    ) std.mem.Allocator.Error!BlockhashQueue {
        var ages = try blockhashQueueAgesRandom(rand, allocator, max_list_entries);
        errdefer ages.deinit(allocator);

        return .{
            .last_hash_index = rand.int(u64),
            .last_hash = if (rand.boolean()) Hash.random(rand) else null,
            .ages = ages,
            .max_age = rand.int(usize),
        };
    }
};

/// Analogous to [UnusedAccounts](https://github.com/anza-xyz/agave/blob/2de7b565e8b1101824a5e3bac74f3a8cce88ea72/runtime/src/serde_snapshot.rs#L123)
pub const UnusedAccounts = struct {
    unused1: std.AutoArrayHashMapUnmanaged(Pubkey, void),
    unused2: std.AutoArrayHashMapUnmanaged(Pubkey, void),
    unused3: std.AutoArrayHashMapUnmanaged(Pubkey, u64),

    pub fn deinit(unused_accounts: UnusedAccounts, allocator: std.mem.Allocator) void {
        var copy = unused_accounts;
        copy.unused1.deinit(allocator);
        copy.unused2.deinit(allocator);
        copy.unused3.deinit(allocator);
    }

    pub fn random(
        rand: std.Random,
        allocator: std.mem.Allocator,
        max_list_entries: usize,
    ) std.mem.Allocator.Error!UnusedAccounts {
        var unused_accounts: UnusedAccounts = .{
            .unused1 = .{},
            .unused2 = .{},
            .unused3 = .{},
        };
        errdefer unused_accounts.deinit(allocator);

        inline for (@typeInfo(UnusedAccounts).Struct.fields) |field| {
            const hm_info = sig.utils.types.hashMapInfo(field.type).?;

            const ptr = &@field(unused_accounts, field.name);
            var managed = ptr.promote(allocator);
            defer ptr.* = managed.unmanaged;

            try sig.rand.fillHashmapWithRng(&managed, rand, rand.uintAtMost(usize, max_list_entries), struct {
                pub fn randomKey(_rand: std.Random) !Pubkey {
                    return Pubkey.random(_rand);
                }
                pub fn randomValue(_rand: std.Random) !hm_info.Value {
                    return switch (hm_info.Value) {
                        u64 => _rand.int(u64),
                        void => {},
                        else => @compileError("Unexpected value type: " ++ @typeName(hm_info.Value)),
                    };
                }
            });
        }

        return unused_accounts;
    }
};

/// Analogous to [AncestorsForSerialization](https://github.com/anza-xyz/agave/blob/cadba689cb44db93e9c625770cafd2fc0ae89e33/accounts-db/src/ancestors.rs#L8)
pub const Ancestors = std.AutoArrayHashMapUnmanaged(Slot, usize);

pub fn ancestorsRandom(
    rand: std.Random,
    allocator: std.mem.Allocator,
    max_list_entries: usize,
) std.mem.Allocator.Error!Ancestors {
    var ancestors = Ancestors.Managed.init(allocator);
    errdefer ancestors.deinit();

    try sig.rand.fillHashmapWithRng(&ancestors, rand, rand.uintAtMost(usize, max_list_entries), struct {
        pub fn randomKey(_rand: std.Random) !Slot {
            return _rand.int(Slot);
        }
        pub fn randomValue(_rand: std.Random) !usize {
            return _rand.int(usize);
        }
    });

    return ancestors.unmanaged;
}

pub const SlotAndCount = struct { Slot, usize };

/// Analogous to [HardForks](https://github.com/anza-xyz/agave/blob/cadba689cb44db93e9c625770cafd2fc0ae89e33/sdk/src/hard_forks.rs#L13)
pub const HardForks = struct {
    items: []const SlotAndCount,

    pub fn deinit(hard_forks: HardForks, allocator: std.mem.Allocator) void {
        allocator.free(hard_forks.items);
    }

    pub fn random(
        rand: std.Random,
        allocator: std.mem.Allocator,
        max_list_entries: usize,
    ) std.mem.Allocator.Error!HardForks {
        const hard_forks_len = rand.uintAtMost(usize, max_list_entries);

        const hard_forks = try allocator.alloc(SlotAndCount, hard_forks_len);
        errdefer allocator.free(hard_forks);

        for (hard_forks) |*hard_fork| hard_fork.* = .{
            rand.int(Slot),
            rand.int(usize),
        };

        return .{ .items = hard_forks };
    }
};

/// Analogous to [NodeVoteAccounts](https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/runtime/src/epoch_stakes.rs#L14)
pub const NodeVoteAccounts = struct {
    vote_accounts: []const Pubkey,
    total_stake: u64,

    pub fn deinit(node_vote_accounts: NodeVoteAccounts, allocator: std.mem.Allocator) void {
        allocator.free(node_vote_accounts.vote_accounts);
    }

    pub fn random(
        rand: std.Random,
        allocator: std.mem.Allocator,
        max_list_entries: usize,
    ) std.mem.Allocator.Error!NodeVoteAccounts {
        const vote_accounts = try allocator.alloc(Pubkey, rand.uintLessThan(usize, max_list_entries));
        errdefer allocator.free(vote_accounts);
        for (vote_accounts) |*vote_account| vote_account.* = Pubkey.random(rand);
        return .{
            .vote_accounts = vote_accounts,
            .total_stake = rand.int(u64),
        };
    }
};

pub const NodeIdToVoteAccountsMap = std.AutoArrayHashMapUnmanaged(Pubkey, NodeVoteAccounts);

pub fn nodeIdToVoteAccountsMapDeinit(map: NodeIdToVoteAccountsMap, allocator: std.mem.Allocator) void {
    for (map.values()) |*node_vote_accounts| {
        node_vote_accounts.deinit(allocator);
    }
    var copy = map;
    copy.deinit(allocator);
}

pub fn nodeIdToVoteAccountsMapRandom(
    rand: std.Random,
    allocator: std.mem.Allocator,
    max_list_entries: usize,
) std.mem.Allocator.Error!NodeIdToVoteAccountsMap {
    var node_id_to_vote_accounts = NodeIdToVoteAccountsMap.Managed.init(allocator);
    errdefer nodeIdToVoteAccountsMapDeinit(node_id_to_vote_accounts.unmanaged, allocator);

    try sig.rand.fillHashmapWithRng(&node_id_to_vote_accounts, rand, rand.uintAtMost(usize, max_list_entries), struct {
        allocator: std.mem.Allocator,
        max_list_entries: usize,

        pub fn randomKey(_: @This(), _rand: std.Random) !Pubkey {
            return Pubkey.random(_rand);
        }

        pub fn randomValue(ctx: @This(), _rand: std.Random) !NodeVoteAccounts {
            return try NodeVoteAccounts.random(_rand, ctx.allocator, ctx.max_list_entries);
        }
    }{
        .allocator = allocator,
        .max_list_entries = max_list_entries,
    });

    return node_id_to_vote_accounts.unmanaged;
}

pub const EpochAuthorizedVoters = std.AutoArrayHashMapUnmanaged(Pubkey, Pubkey);

pub fn epochAuthorizedVotersRandom(
    rand: std.Random,
    allocator: std.mem.Allocator,
    max_list_entries: usize,
) std.mem.Allocator.Error!EpochAuthorizedVoters {
    var epoch_authorized_voters = EpochAuthorizedVoters.Managed.init(allocator);
    errdefer epoch_authorized_voters.deinit();

    try sig.rand.fillHashmapWithRng(&epoch_authorized_voters, rand, rand.uintAtMost(usize, max_list_entries), struct {
        pub fn randomKey(_rand: std.Random) !Pubkey {
            return Pubkey.random(_rand);
        }
        pub fn randomValue(_rand: std.Random) !Pubkey {
            return Pubkey.random(_rand);
        }
    });

    return epoch_authorized_voters.unmanaged;
}

/// Analogous to [EpochStakes](https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/runtime/src/epoch_stakes.rs#L22)
pub const EpochStakes = struct {
    stakes: Stakes,
    total_stake: u64,
    node_id_to_vote_accounts: NodeIdToVoteAccountsMap,
    epoch_authorized_voters: EpochAuthorizedVoters,

    pub fn deinit(epoch_stakes: EpochStakes, allocator: std.mem.Allocator) void {
        epoch_stakes.stakes.deinit(allocator);
        nodeIdToVoteAccountsMapDeinit(epoch_stakes.node_id_to_vote_accounts, allocator);

        var epoch_authorized_voters = epoch_stakes.epoch_authorized_voters;
        epoch_authorized_voters.deinit(allocator);
    }

    pub fn random(
        allocator: std.mem.Allocator,
        /// Should be a PRNG, not a true RNG. See the documentation on `std.Random.uintLessThan`
        /// for commentary on the runtime of this function.
        rand: std.Random,
        max_list_entries: usize,
    ) std.mem.Allocator.Error!EpochStakes {
        var result_stakes = try Stakes.random(allocator, rand, max_list_entries);
        errdefer result_stakes.deinit(allocator);

        const node_id_to_vote_accounts = try nodeIdToVoteAccountsMapRandom(rand, allocator, max_list_entries);
        errdefer nodeIdToVoteAccountsMapDeinit(node_id_to_vote_accounts, allocator);

        var epoch_authorized_voters = try epochAuthorizedVotersRandom(rand, allocator, max_list_entries);
        errdefer epoch_authorized_voters.deinit(allocator);

        return .{
            .stakes = result_stakes,
            .total_stake = rand.int(u64),
            .node_id_to_vote_accounts = node_id_to_vote_accounts,
            .epoch_authorized_voters = epoch_authorized_voters,
        };
    }
};

/// Analogous to [BankIncrementalSnapshotPersistence](https://github.com/anza-xyz/agave/blob/2de7b565e8b1101824a5e3bac74f3a8cce88ea72/runtime/src/serde_snapshot.rs#L100)
pub const BankIncrementalSnapshotPersistence = struct {
    /// slot of full snapshot
    full_slot: Slot,
    /// accounts hash from the full snapshot
    full_hash: Hash,
    /// capitalization from the full snapshot
    full_capitalization: u64,
    /// hash of the accounts in the incremental snapshot slot range, including zero-lamport accounts
    incremental_hash: Hash,
    /// capitalization of the accounts in the incremental snapshot slot range
    incremental_capitalization: u64,

    pub fn default() @This() {
        return .{
            .full_slot = 0,
            .full_hash = Hash.default(),
            .full_capitalization = 0,
            .incremental_hash = Hash.default(),
            .incremental_capitalization = 0,
        };
    }
};

/// Analogous to [StakeReward](https://github.com/anza-xyz/agave/blob/cadba689cb44db93e9c625770cafd2fc0ae89e33/accounts-db/src/stake_rewards.rs#L12)
pub const StakeReward = struct {
    stake_pubkey: Pubkey,
    stake_reward_info: RewardInfo,
    stake_account: Account,
};

/// Analogous to [RewardInfo](https://github.com/anza-xyz/agave/blob/cadba689cb44db93e9c625770cafd2fc0ae89e33/sdk/src/reward_info.rs#L5)
pub const RewardInfo = struct {
    reward_type: RewardType,
    lamports: i64, // Reward amount
    post_balance: u64, // Account balance in lamports after `lamports` was applied
    commission: ?u8, // Vote account commission when the reward was credited, only present for voting and staking rewards
};

/// Analogous to [RewardType](https://github.com/anza-xyz/agave/blob/cadba689cb44db93e9c625770cafd2fc0ae89e33/sdk/src/reward_type.rs#L7)
pub const RewardType = enum {
    Fee,
    Rent,
    Staking,
    Voting,
};

/// Analogous to [StartBlockHeightAndRewards](https://github.com/anza-xyz/agave/blob/034cd7396a1db2db21a3305b259a17a5fdea312c/runtime/src/bank/partitioned_epoch_rewards/mod.rs#L60)
pub const StartBlockHeightAndRewards = struct {
    /// the block height of the parent of the slot at which rewards distribution began
    parent_start_block_height: u64,
    /// calculated epoch rewards pending distribution
    calculated_epoch_stake_rewards: std.ArrayList(StakeReward),
};

/// Analogous to [EpochRewardStatus](https://github.com/anza-xyz/agave/blob/034cd7396a1db2db21a3305b259a17a5fdea312c/runtime/src/bank/partitioned_epoch_rewards/mod.rs#L70)
pub const EpochRewardStatus = union(enum) {
    Active: StartBlockHeightAndRewards,
    Inactive: void,

    pub fn default() @This() {
        return @This().Inactive;
    }
};

pub const EpochStakeMap = std.AutoArrayHashMapUnmanaged(Epoch, EpochStakes);

pub fn epochStakeMapDeinit(
    epoch_stakes: EpochStakeMap,
    allocator: std.mem.Allocator,
) void {
    for (epoch_stakes.values()) |epoch_stake| {
        epoch_stake.deinit(allocator);
    }

    var copy = epoch_stakes;
    copy.deinit(allocator);
}

pub fn epochStakeMapRandom(
    rand: std.Random,
    allocator: std.mem.Allocator,
    max_list_entries: usize,
) std.mem.Allocator.Error!EpochStakeMap {
    var epoch_stakes = EpochStakeMap.Managed.init(allocator);
    errdefer epochStakeMapDeinit(epoch_stakes.unmanaged, allocator);

    try sig.rand.fillHashmapWithRng(&epoch_stakes, rand, rand.uintAtMost(usize, max_list_entries), struct {
        allocator: std.mem.Allocator,
        max_list_entries: usize,

        pub fn randomKey(_: @This(), _rand: std.Random) !Epoch {
            return _rand.int(Epoch);
        }

        pub fn randomValue(ctx: @This(), _rand: std.Random) !EpochStakes {
            return try EpochStakes.random(ctx.allocator, _rand, ctx.max_list_entries);
        }
    }{
        .allocator = allocator,
        .max_list_entries = max_list_entries,
    });

    return epoch_stakes.unmanaged;
}

/// Analogous to most of the fields of [Bank](https://github.com/anza-xyz/agave/blob/ad0a48c7311b08dbb6c81babaf66c136ac092e79/runtime/src/bank.rs#L718)
/// and [BankFieldsToDeserialize](https://github.com/anza-xyz/agave/blob/ad0a48c7311b08dbb6c81babaf66c136ac092e79/runtime/src/bank.rs#L459)
pub const BankFields = struct {
    blockhash_queue: BlockhashQueue,
    ancestors: Ancestors,
    hash: Hash,
    parent_hash: Hash,
    parent_slot: Slot,
    hard_forks: HardForks,
    transaction_count: u64,
    tick_height: u64,
    signature_count: u64,
    // ie, total lamports
    capitalization: u64,
    max_tick_height: u64,
    hashes_per_tick: ?u64,
    ticks_per_slot: u64,
    ns_per_slot: u128,
    genesis_creation_time: UnixTimestamp,
    slots_per_year: f64,
    accounts_data_len: u64,
    slot: Slot,
    epoch: Epoch,
    block_height: u64,
    collector_id: Pubkey,
    collector_fees: u64,
    fee_calculator: FeeCalculator,
    fee_rate_governor: FeeRateGovernor,
    collected_rent: u64,
    rent_collector: RentCollector,
    epoch_schedule: EpochSchedule,
    inflation: Inflation,
    stakes: Stakes,
    unused_accounts: UnusedAccounts, // required for deserialization
    epoch_stakes: EpochStakeMap,
    is_delta: bool,

    pub fn deinit(bank_fields: *const BankFields, allocator: std.mem.Allocator) void {
        bank_fields.blockhash_queue.deinit(allocator);

        var ancestors = bank_fields.ancestors;
        ancestors.deinit(allocator);

        bank_fields.hard_forks.deinit(allocator);

        bank_fields.stakes.deinit(allocator);

        bank_fields.unused_accounts.deinit(allocator);

        epochStakeMapDeinit(bank_fields.epoch_stakes, allocator);
    }

    pub const Incremental = struct {
        snapshot_persistence: ?BankIncrementalSnapshotPersistence = null,
        epoch_accounts_hash: ?Hash = null,
        epoch_reward_status: ?EpochRewardStatus = null,

        // TODO: do a thorough review on this, this seems to work by chance with the test data, but I don't trust it yet

        pub const @"!bincode-config:snapshot_persistence" = bincode.optional.defaultToNullOnEof(BankIncrementalSnapshotPersistence, .{ .encode_optional = true });
        pub const @"!bincode-config:epoch_accounts_hash" = bincode.optional.defaultToNullOnEof(Hash, .{ .encode_optional = true });
        pub const @"!bincode-config:epoch_reward_status" = bincode.optional.defaultToNullOnEof(EpochRewardStatus, .{ .encode_optional = false });
    };

    pub fn random(
        allocator: std.mem.Allocator,
        /// Should be a PRNG, not a true RNG. See the documentation on `std.Random.uintLessThan`
        /// for commentary on the runtime of this function.
        rand: std.Random,
        max_list_entries: usize,
    ) std.mem.Allocator.Error!BankFields {
        var blockhash_queue = try BlockhashQueue.random(rand, allocator, max_list_entries);
        errdefer blockhash_queue.deinit(allocator);

        var ancestors = try ancestorsRandom(rand, allocator, max_list_entries);
        errdefer ancestors.deinit(allocator);

        const hard_forks = try HardForks.random(rand, allocator, max_list_entries);
        errdefer hard_forks.deinit(allocator);

        const stakes = try Stakes.random(allocator, rand, max_list_entries);
        errdefer stakes.deinit(allocator);

        const unused_accounts = try UnusedAccounts.random(rand, allocator, max_list_entries);
        errdefer unused_accounts.deinit(allocator);

        const epoch_stakes = try epochStakeMapRandom(rand, allocator, max_list_entries);
        errdefer epochStakeMapDeinit(epoch_stakes, allocator);

        return .{
            .blockhash_queue = blockhash_queue,
            .ancestors = ancestors,
            .hash = Hash.random(rand),
            .parent_hash = Hash.random(rand),
            .parent_slot = rand.int(Slot),
            .hard_forks = hard_forks,
            .transaction_count = rand.int(u64),
            .tick_height = rand.int(u64),
            .signature_count = rand.int(u64),
            .capitalization = rand.int(u64),
            .max_tick_height = rand.int(u64),
            .hashes_per_tick = if (rand.boolean()) rand.int(u64) else null,
            .ticks_per_slot = rand.int(u64),
            .ns_per_slot = rand.int(u128),
            .genesis_creation_time = rand.int(sig.accounts_db.genesis_config.UnixTimestamp),
            .slots_per_year = @bitCast(rand.int(u64)),
            .accounts_data_len = rand.int(u64),
            .slot = rand.int(Slot),
            .epoch = rand.int(Epoch),
            .block_height = rand.int(u64),
            .collector_id = Pubkey.random(rand),
            .collector_fees = rand.int(u64),
            .fee_calculator = FeeCalculator.random(rand),
            .fee_rate_governor = FeeRateGovernor.random(rand),
            .collected_rent = rand.int(u64),
            .rent_collector = RentCollector.random(rand),
            .epoch_schedule = EpochSchedule.random(rand),
            .inflation = Inflation.random(rand),
            .stakes = stakes,
            .unused_accounts = unused_accounts,
            .epoch_stakes = epoch_stakes,
            .is_delta = rand.boolean(),
        };
    }

    pub fn getStakedNodes(self: *const BankFields, allocator: std.mem.Allocator, epoch: Epoch) !*const std.AutoArrayHashMapUnmanaged(Pubkey, u64) {
        const epoch_stakes = self.epoch_stakes.getPtr(epoch) orelse return error.NoEpochStakes;
        return epoch_stakes.stakes.vote_accounts.stakedNodes(allocator);
    }
};

/// Analogous to [SerializableAccountStorageEntry](https://github.com/anza-xyz/agave/blob/cadba689cb44db93e9c625770cafd2fc0ae89e33/runtime/src/serde_snapshot/storage.rs#L11)
pub const AccountFileInfo = struct {
    /// note: serialized id is a usize but in code it's FileId (u32)
    id: FileId,
    /// amount of bytes used
    length: usize,

    pub const @"!bincode-config:id": bincode.FieldConfig(FileId) = .{
        .serializer = idSerializer,
        .deserializer = idDeserializer,
    };

    fn idSerializer(writer: anytype, data: anytype, params: bincode.Params) anyerror!void {
        try bincode.write(writer, @as(usize, data.toInt()), params);
    }

    fn idDeserializer(_: std.mem.Allocator, reader: anytype, params: bincode.Params) anyerror!FileId {
        const int = try bincode.readInt(usize, reader, params);
        if (int > std.math.maxInt(FileId.Int)) return error.IdOverflow;
        return FileId.fromInt(@intCast(int));
    }

    /// Analogous to [AppendVecError](https://github.com/anza-xyz/agave/blob/91a4ecfff78423433cc0001362cea8fed860dcb9/accounts-db/src/append_vec.rs#L74)
    pub const ValidateError = error{
        FileSizeTooSmall,
        FileSizeTooLarge,
        OffsetOutOfBounds,
    };
    /// Analogous to [sanitize_len_and_size](https://github.com/anza-xyz/agave/blob/91a4ecfff78423433cc0001362cea8fed860dcb9/accounts-db/src/append_vec.rs#L376)
    pub fn validate(self: *const AccountFileInfo, file_size: usize) ValidateError!void {
        if (file_size == 0) {
            return error.FileSizeTooSmall;
        } else if (file_size > @as(usize, MAXIMUM_ACCOUNT_FILE_SIZE)) {
            return error.FileSizeTooLarge;
        } else if (self.length > file_size) {
            return error.OffsetOutOfBounds;
        }
    }

    pub fn format(
        account_file_info: AccountFileInfo,
        comptime fmt_str: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        _ = fmt_str;

        try writer.print(".{{ .id = {}, .length = {} }}", .{
            account_file_info.id.toInt(), account_file_info.length,
        });
    }
};

/// Analogous to [BankHashInfo](https://github.com/anza-xyz/agave/blob/2de7b565e8b1101824a5e3bac74f3a8cce88ea72/runtime/src/serde_snapshot.rs#L115)
pub const BankHashInfo = struct {
    accounts_delta_hash: Hash,
    accounts_hash: Hash,
    stats: BankHashStats,

    pub fn random(rand: std.Random) BankHashInfo {
        return .{
            .accounts_delta_hash = Hash.random(rand),
            .accounts_hash = Hash.random(rand),
            .stats = BankHashStats.random(rand),
        };
    }
};

/// Analogous to [BankHashStats](https://github.com/anza-xyz/agave/blob/4c921ca276bbd5997f809dec1dd3937fb06463cc/accounts-db/src/accounts_db.rs#L1299)
pub const BankHashStats = struct {
    num_updated_accounts: u64,
    num_removed_accounts: u64,
    num_lamports_stored: u64,
    total_data_len: u64,
    num_executable_accounts: u64,

    pub const zero_init: BankHashStats = .{
        .num_updated_accounts = 0,
        .num_removed_accounts = 0,
        .num_lamports_stored = 0,
        .total_data_len = 0,
        .num_executable_accounts = 0,
    };

    pub fn random(rand: std.Random) BankHashStats {
        return .{
            .num_updated_accounts = rand.int(u64),
            .num_removed_accounts = rand.int(u64),
            .num_lamports_stored = rand.int(u64),
            .total_data_len = rand.int(u64),
            .num_executable_accounts = rand.int(u64),
        };
    }

    pub const AccountData = struct {
        lamports: u64,
        data_len: u64,
        executable: bool,
    };
    pub fn update(stats: *BankHashStats, account: AccountData) void {
        if (account.lamports == 0) {
            stats.num_removed_accounts += 1;
        } else {
            stats.num_updated_accounts += 1;
        }
        stats.total_data_len +%= account.data_len;
        stats.num_executable_accounts += @intFromBool(account.executable);
        stats.num_lamports_stored +%= account.lamports;
    }

    pub fn accumulate(stats: *BankHashStats, other: BankHashStats) void {
        stats.num_updated_accounts += other.num_updated_accounts;
        stats.num_removed_accounts += other.num_removed_accounts;
        stats.total_data_len +%= other.total_data_len;
        stats.num_lamports_stored +%= other.num_lamports_stored;
        stats.num_executable_accounts += other.num_executable_accounts;
    }
};

pub const SlotAndHash = struct { slot: Slot, hash: Hash };

/// Analogous to [AccountsDbFields](https://github.com/anza-xyz/agave/blob/2de7b565e8b1101824a5e3bac74f3a8cce88ea72/runtime/src/serde_snapshot.rs#L77)
pub const AccountsDbFields = struct {
    file_map: FileMap,

    /// NOTE: this is not a meaningful field
    /// NOTE: at the time of writing, a test snapshots we use actually have this field set to 601 on disk,
    /// so be sure to keep that in mind while testing.
    stored_meta_write_version: u64,

    slot: Slot,
    bank_hash_info: BankHashInfo,

    // default on EOF
    /// NOTE: these are currently always empty?
    /// https://github.com/anza-xyz/agave/blob/b9eb4e2aa328abb9d3ee1d857d82ccd7a86f8c4d/runtime/src/serde_snapshot.rs#L769-L782
    rooted_slots: std.ArrayListUnmanaged(Slot),
    rooted_slot_hashes: std.ArrayListUnmanaged(SlotAndHash),

    pub const @"!bincode-config:file_map" = bincode.hashmap.hashMapFieldConfig(FileMap, .{
        .value = bincode.list.valueEncodedAsSlice(AccountFileInfo, .{}),
    });
    pub const @"!bincode-config:rooted_slots" = defaultArrayListUnmanagedOnEOFConfig(Slot);
    pub const @"!bincode-config:rooted_slot_hashes" = defaultArrayListUnmanagedOnEOFConfig(SlotAndHash);

    pub const FileMap = std.AutoArrayHashMap(Slot, AccountFileInfo);

    pub fn deinit(fields: AccountsDbFields, allocator: std.mem.Allocator) void {
        bincode.free(allocator, fields);
    }
};

/// contains all the metadata from a snapshot.
/// this includes fields for accounts-db and the bank of the snapshots slots.
/// this does not include account-specific data.
pub const SnapshotFields = struct {
    bank_fields: BankFields,
    accounts_db_fields: AccountsDbFields,
    lamports_per_signature: u64,
    /// incremental snapshot fields (to accompany added to bank_fields)
    bank_fields_inc: BankFields.Incremental = .{},

    pub const @"!bincode-config:lamports_per_signature" = bincode.int.defaultOnEof(u64, 0);

    pub fn readFromFilePath(
        allocator: std.mem.Allocator,
        path: []const u8,
    ) !SnapshotFields {
        const file = std.fs.cwd().openFile(path, .{}) catch |err| {
            switch (err) {
                error.FileNotFound => return error.SnapshotFieldsNotFound,
                else => return err,
            }
        };
        defer file.close();
        return readFromFile(allocator, file);
    }

    pub fn readFromFile(
        allocator: std.mem.Allocator,
        file: std.fs.File,
    ) !SnapshotFields {
        const size = (try file.stat()).size;
        const contents = try file.readToEndAllocOptions(allocator, size, size, @alignOf(u8), null);
        defer allocator.free(contents);

        var fbs = std.io.fixedBufferStream(contents);
        return try decodeFromBincode(allocator, fbs.reader());
    }

    pub fn decodeFromBincode(
        allocator: std.mem.Allocator,
        /// `std.io.GenericReader(...)` | `std.io.AnyReader`
        reader: anytype,
    ) !SnapshotFields {
        return try bincode.read(allocator, SnapshotFields, reader, .{});
    }

    pub fn deinit(self: SnapshotFields, allocator: std.mem.Allocator) void {
        bincode.free(allocator, self);
    }
};

/// Analogous to [InstructionError](https://github.com/anza-xyz/agave/blob/25ec30452c7d74e2aeb00f2fa35876de9ce718c6/sdk/program/src/instruction.rs#L36)
pub const InstructionError = union(enum) {
    /// Deprecated! Use CustomError instead!
    /// The program instruction returned an error
    GenericError,

    /// The arguments provided to a program were invalid
    InvalidArgument,

    /// An instruction's data contents were invalid
    InvalidInstructionData,

    /// An account's data contents was invalid
    InvalidAccountData,

    /// An account's data was too small
    AccountDataTooSmall,

    /// An account's balance was too small to complete the instruction
    InsufficientFunds,

    /// The account did not have the expected program id
    IncorrectProgramId,

    /// A signature was required but not found
    MissingRequiredSignature,

    /// An initialize instruction was sent to an account that has already been initialized.
    AccountAlreadyInitialized,

    /// An attempt to operate on an account that hasn't been initialized.
    UninitializedAccount,

    /// Program's instruction lamport balance does not equal the balance after the instruction
    UnbalancedInstruction,

    /// Program illegally modified an account's program id
    ModifiedProgramId,

    /// Program spent the lamports of an account that doesn't belong to it
    ExternalAccountLamportSpend,

    /// Program modified the data of an account that doesn't belong to it
    ExternalAccountDataModified,

    /// Read-only account's lamports modified
    ReadonlyLamportChange,

    /// Read-only account's data was modified
    ReadonlyDataModified,

    /// An account was referenced more than once in a single instruction
    // Deprecated, instructions can now contain duplicate accounts
    DuplicateAccountIndex,

    /// Executable bit on account changed, but shouldn't have
    ExecutableModified,

    /// Rent_epoch account changed, but shouldn't have
    RentEpochModified,

    /// The instruction expected additional account keys
    NotEnoughAccountKeys,

    /// Program other than the account's owner changed the size of the account data
    AccountDataSizeChanged,

    /// The instruction expected an executable account
    AccountNotExecutable,

    /// Failed to borrow a reference to account data, already borrowed
    AccountBorrowFailed,

    /// Account data has an outstanding reference after a program's execution
    AccountBorrowOutstanding,

    /// The same account was multiply passed to an on-chain program's entrypoint, but the program
    /// modified them differently.  A program can only modify one instance of the account because
    /// the runtime cannot determine which changes to pick or how to merge them if both are modified
    DuplicateAccountOutOfSync,

    /// Allows on-chain programs to implement program-specific error types and see them returned
    /// by the Solana runtime. A program-specific error may be any type that is represented as
    /// or serialized to a u32 integer.
    Custom: u32,

    /// The return value from the program was invalid.  Valid errors are either a defined builtin
    /// error value or a user-defined error in the lower 32 bits.
    InvalidError,

    /// Executable account's data was modified
    ExecutableDataModified,

    /// Executable account's lamports modified
    ExecutableLamportChange,

    /// Executable accounts must be rent exempt
    ExecutableAccountNotRentExempt,

    /// Unsupported program id
    UnsupportedProgramId,

    /// Cross-program invocation call depth too deep
    CallDepth,

    /// An account required by the instruction is missing
    MissingAccount,

    /// Cross-program invocation reentrancy not allowed for this instruction
    ReentrancyNotAllowed,

    /// Length of the seed is too long for address generation
    MaxSeedLengthExceeded,

    /// Provided seeds do not result in a valid address
    InvalidSeeds,

    /// Failed to reallocate account data of this length
    InvalidRealloc,

    /// Computational budget exceeded
    ComputationalBudgetExceeded,

    /// Cross-program invocation with unauthorized signer or writable account
    PrivilegeEscalation,

    /// Failed to create program execution environment
    ProgramEnvironmentSetupFailure,

    /// Program failed to complete
    ProgramFailedToComplete,

    /// Program failed to compile
    ProgramFailedToCompile,

    /// Account is immutable
    Immutable,

    /// Incorrect authority provided
    IncorrectAuthority,

    /// Failed to serialize or deserialize account data
    ///
    /// Warning: This error should never be emitted by the runtime.
    ///
    /// This error includes strings from the underlying 3rd party Borsh crate
    /// which can be dangerous because the error strings could change across
    /// Borsh versions. Only programs can use this error because they are
    /// consistent across Solana software versions.
    ///
    BorshIoError: []const u8,

    /// An account does not have enough lamports to be rent-exempt
    AccountNotRentExempt,

    /// Invalid account owner
    InvalidAccountOwner,

    /// Program arithmetic overflowed
    ArithmeticOverflow,

    /// Unsupported sysvar
    UnsupportedSysvar,

    /// Illegal account owner
    IllegalOwner,

    /// Accounts data allocations exceeded the maximum allowed per transaction
    MaxAccountsDataAllocationsExceeded,

    /// Max accounts exceeded
    MaxAccountsExceeded,

    /// Max instruction trace length exceeded
    MaxInstructionTraceLengthExceeded,

    /// Builtin programs must consume compute units
    BuiltinProgramsMustConsumeComputeUnits,
    // Note: For any new error added here an equivalent ProgramError and its
    // conversions must also be added
};

/// Analogous to [TransactionError](https://github.com/anza-xyz/agave/blob/cadba689cb44db93e9c625770cafd2fc0ae89e33/sdk/src/transaction/error.rs#L14)
const TransactionError = union(enum) {
    /// An account is already being processed in another transaction in a way
    /// that does not support parallelism
    AccountInUse,

    /// A `Pubkey` appears twice in the transaction's `account_keys`.  Instructions can reference
    /// `Pubkey`s more than once but the message must contain a list with no duplicate keys
    AccountLoadedTwice,

    /// Attempt to debit an account but found no record of a prior credit.
    AccountNotFound,

    /// Attempt to load a program that does not exist
    ProgramAccountNotFound,

    /// The from `Pubkey` does not have sufficient balance to pay the fee to schedule the transaction
    InsufficientFundsForFee,

    /// This account may not be used to pay transaction fees
    InvalidAccountForFee,

    /// The bank has seen this transaction before. This can occur under normal operation
    /// when a UDP packet is duplicated, as a user error from a client not updating
    /// its `recent_blockhash`, or as a double-spend attack.
    AlreadyProcessed,

    /// The bank has not seen the given `recent_blockhash` or the transaction is too old and
    /// the `recent_blockhash` has been discarded.
    BlockhashNotFound,

    /// An error occurred while processing an instruction. The first element of the tuple
    /// indicates the instruction index in which the error occurred.
    InstructionError: struct { instruction_index: u8, err: InstructionError },

    /// Loader call chain is too deep
    CallChainTooDeep,

    /// Transaction requires a fee but has no signature present
    MissingSignatureForFee,

    /// Transaction contains an invalid account reference
    InvalidAccountIndex,

    /// Transaction did not pass signature verification
    SignatureFailure,

    /// This program may not be used for executing instructions
    InvalidProgramForExecution,

    /// Transaction failed to sanitize accounts offsets correctly
    /// implies that account locks are not taken for this TX, and should
    /// not be unlocked.
    SanitizeFailure,

    ClusterMaintenance,

    /// Transaction processing left an account with an outstanding borrowed reference
    AccountBorrowOutstanding,

    /// Transaction would exceed max Block Cost Limit
    WouldExceedMaxBlockCostLimit,

    /// Transaction version is unsupported
    UnsupportedVersion,

    /// Transaction loads a writable account that cannot be written
    InvalidWritableAccount,

    /// Transaction would exceed max account limit within the block
    WouldExceedMaxAccountCostLimit,

    /// Transaction would exceed account data limit within the block
    WouldExceedAccountDataBlockLimit,

    /// Transaction locked too many accounts
    TooManyAccountLocks,

    /// Address lookup table not found
    AddressLookupTableNotFound,

    /// Attempted to lookup addresses from an account owned by the wrong program
    InvalidAddressLookupTableOwner,

    /// Attempted to lookup addresses from an invalid account
    InvalidAddressLookupTableData,

    /// Address table lookup uses an invalid index
    InvalidAddressLookupTableIndex,

    /// Transaction leaves an account with a lower balance than rent-exempt minimum
    InvalidRentPayingAccount,

    /// Transaction would exceed max Vote Cost Limit
    WouldExceedMaxVoteCostLimit,

    /// Transaction would exceed total account data limit
    WouldExceedAccountDataTotalLimit,

    /// Transaction contains a duplicate instruction that is not allowed
    DuplicateInstruction: u8,

    /// Transaction results in an account with insufficient funds for rent
    InsufficientFundsForRent: struct { account_index: u8 },

    /// Transaction exceeded max loaded accounts data size cap
    MaxLoadedAccountsDataSizeExceeded,

    /// LoadedAccountsDataSizeLimit set for transaction must be greater than 0.
    InvalidLoadedAccountsDataSizeLimit,

    /// Sanitized transaction differed before/after feature activiation. Needs to be resanitized.
    ResanitizationNeeded,

    /// Program execution is temporarily restricted on an account.
    ProgramExecutionTemporarilyRestricted: struct { account_index: u8 },
};

const Result = union(enum) {
    Ok,
    Error: TransactionError,
};

/// Analogous to [Status](https://github.com/anza-xyz/agave/blob/cadba689cb44db93e9c625770cafd2fc0ae89e33/runtime/src/status_cache.rs#L24)
pub const Status = struct {
    i: usize,
    j: []const KeySliceResult,

    pub const KeySliceResult = struct {
        key_slice: [CACHED_KEY_SIZE]u8,
        result: Result,
    };
};
pub const HashStatusMap = std.AutoArrayHashMapUnmanaged(Hash, Status);
/// Analogous to [SlotDelta](https://github.com/anza-xyz/agave/blob/cadba689cb44db93e9c625770cafd2fc0ae89e33/runtime/src/status_cache.rs#L35)
pub const BankSlotDelta = struct {
    slot: Slot,
    is_root: bool,
    status: HashStatusMap,
};

/// Analogous to [StatusCache](https://github.com/anza-xyz/agave/blob/cadba689cb44db93e9c625770cafd2fc0ae89e33/runtime/src/status_cache.rs#L39)
pub const StatusCache = struct {
    bank_slot_deltas: []const BankSlotDelta,

    pub fn default() @This() {
        return .{ .bank_slot_deltas = &.{} };
    }

    pub fn initFromPath(allocator: std.mem.Allocator, path: []const u8) !StatusCache {
        const status_cache_file = try std.fs.cwd().openFile(path, .{});
        defer status_cache_file.close();
        return readFromFile(allocator, status_cache_file);
    }

    pub fn readFromFile(allocator: std.mem.Allocator, file: std.fs.File) !StatusCache {
        return decodeFromBincode(allocator, file.reader());
    }

    pub fn decodeFromBincode(
        allocator: std.mem.Allocator,
        /// `std.io.GenericReader(...)` | `std.io.AnyReader`
        reader: anytype,
    ) !StatusCache {
        return try bincode.read(allocator, StatusCache, reader, .{});
    }

    pub fn deinit(self: StatusCache, allocator: std.mem.Allocator) void {
        bincode.free(allocator, self);
    }

    /// [verify_slot_deltas](https://github.com/anza-xyz/agave/blob/ed500b5afc77bc78d9890d96455ea7a7f28edbf9/runtime/src/snapshot_bank_utils.rs#L709)
    pub fn validate(
        self: *const StatusCache,
        allocator: std.mem.Allocator,
        bank_slot: Slot,
        slot_history: *const SlotHistory,
    ) !void {
        // status cache validation
        const len = self.bank_slot_deltas.len;
        if (len > MAX_CACHE_ENTRIES) {
            return error.TooManyCacheEntries;
        }

        var slots_seen = std.AutoArrayHashMap(Slot, void).init(allocator);
        defer slots_seen.deinit();

        for (self.bank_slot_deltas) |slot_delta| {
            if (!slot_delta.is_root) {
                return error.NonRootSlot;
            }
            const slot = slot_delta.slot;
            if (slot > bank_slot) {
                return error.SlotTooHigh;
            }
            const entry = try slots_seen.getOrPut(slot);
            if (entry.found_existing) {
                return error.MultipleSlotEntries;
            }
        }

        // validate bank's slot_history matches the status cache
        if (slot_history.newest() != bank_slot) {
            return error.SlotHistoryMismatch;
        }
        for (slots_seen.keys()) |slot| {
            if (slot_history.check(slot) != .Found) {
                return error.SlotNotFoundInHistory;
            }
        }

        var slots_checked: u32 = 0;
        var slot = slot_history.newest();
        while (slot >= slot_history.oldest() and slots_checked != MAX_CACHE_ENTRIES) {
            if (slot_history.check(slot) == .Found) {
                slots_checked += 1;
                if (!slots_seen.contains(slot)) {
                    return error.SlotNotFoundInStatusCache;
                }
            }
            if (slot == 0) break;
            slot -= 1;
        }
    }
};

pub const CompressionMethod = enum {
    zstd,

    pub inline fn extension(method: CompressionMethod) []const u8 {
        return switch (method) {
            .zstd => "zst",
        };
    }
};

/// information on a full snapshot including the filename, slot, and hash
///
/// Analogous to [SnapshotArchiveInfo](https://github.com/anza-xyz/agave/blob/59bf1809fe5115f0fad51e80cc0a19da1496e2e9/runtime/src/snapshot_archive_info.rs#L44)
pub const FullSnapshotFileInfo = struct {
    slot: Slot,
    hash: Hash,
    comptime compression: CompressionMethod = .zstd,

    const FULL_SNAPSHOT_NAME_FMT = "snapshot-{[slot]d}-{[hash]s}.tar.{[extension]s}";
    const FULL_SNAPSHOT_NAME_MAX_LEN = sig.utils.fmt.boundedLenValue(FULL_SNAPSHOT_NAME_FMT, .{
        .slot = std.math.maxInt(Slot),
        .hash = sig.utils.fmt.boundedString(&(Hash{ .data = .{255} ** 32 }).base58String()),
        .extension = CompressionMethod.extension(.zstd),
    });

    /// matches with the regex: r"^snapshot-(?P<slot>[[:digit:]]+)-(?P<hash>[[:alnum:]]+)\.(?P<ext>tar\.zst)$";
    pub fn fromString(filename: []const u8) !FullSnapshotFileInfo {
        var ext_parts = std.mem.splitSequence(u8, filename, ".");
        const stem = ext_parts.next() orelse return error.InvalidSnapshotPath;

        const extn = ext_parts.rest();
        // only support tar.zst
        if (!std.mem.eql(u8, extn, "tar.zst"))
            return error.InvalidSnapshotPath;

        var parts = std.mem.splitSequence(u8, stem, "-");
        const header = parts.next() orelse return error.InvalidSnapshotPath;
        if (!std.mem.eql(u8, header, "snapshot"))
            return error.InvalidSnapshotPath;

        const slot_str = parts.next() orelse return error.InvalidSnapshotPath;
        const slot = std.fmt.parseInt(Slot, slot_str, 10) catch return error.InvalidSnapshotPath;

        const hash_str = parts.next() orelse return error.InvalidSnapshotPath;
        const hash = Hash.parseBase58String(hash_str) catch return error.InvalidSnapshotPath;

        return .{
            .slot = slot,
            .hash = hash,
        };
    }

    pub fn snapshotNameStr(self: FullSnapshotFileInfo) std.BoundedArray(u8, FULL_SNAPSHOT_NAME_MAX_LEN) {
        const b58_str = self.hash.base58String();
        return sig.utils.fmt.boundedFmt(FULL_SNAPSHOT_NAME_FMT, .{
            .slot = self.slot,
            .hash = sig.utils.fmt.boundedString(&b58_str),
            .extension = self.compression.extension(),
        });
    }

    test snapshotNameStr {
        try std.testing.expectEqualStrings(
            "snapshot-10-11111111111111111111111111111111.tar.zst",
            snapshotNameStr(.{ .slot = 10, .hash = Hash.default() }).constSlice(),
        );
    }
};

/// information on an incremental snapshot including the filename, base slot (full snapshot), slot, and hash
///
/// Analogous to [IncrementalSnapshotArchiveInfo](https://github.com/anza-xyz/agave/blob/59bf1809fe5115f0fad51e80cc0a19da1496e2e9/runtime/src/snapshot_archive_info.rs#L103)
pub const IncrementalSnapshotFileInfo = struct {
    base_slot: Slot,
    slot: Slot,
    hash: Hash,
    comptime compression: CompressionMethod = .zstd,

    const INCREMENTAL_SNAPSHOT_NAME_FMT = "incremental-snapshot-{[base_slot]d}-{[slot]d}-{[hash]s}.tar.{[extension]s}";
    const INCREMENTAL_SNAPSHOT_NAME_MAX_LEN = sig.utils.fmt.boundedLenValue(INCREMENTAL_SNAPSHOT_NAME_FMT, .{
        .base_slot = std.math.maxInt(Slot),
        .slot = std.math.maxInt(Slot),
        .hash = sig.utils.fmt.boundedString(&(Hash{ .data = .{255} ** 32 }).base58String()),
        .extension = CompressionMethod.extension(.zstd),
    });

    /// matches against regex: r"^incremental-snapshot-(?P<base_slot>[[:digit:]]+)-(?P<slot>[[:digit:]]+)-(?P<hash>[[:alnum:]]+)\.(?P<ext>tar\.zst)$";
    pub fn fromString(filename: []const u8) !IncrementalSnapshotFileInfo {
        var ext_parts = std.mem.splitSequence(u8, filename, ".");
        const stem = ext_parts.next() orelse return error.InvalidSnapshotPath;

        const extn = ext_parts.rest();
        // only support tar.zst
        if (!std.mem.eql(u8, extn, "tar.zst"))
            return error.InvalidSnapshotPath;

        var parts = std.mem.splitSequence(u8, stem, "-");
        var header = parts.next() orelse return error.InvalidSnapshotPath;
        if (!std.mem.eql(u8, header, "incremental"))
            return error.InvalidSnapshotPath;

        header = parts.next() orelse return error.InvalidSnapshotPath;
        if (!std.mem.eql(u8, header, "snapshot"))
            return error.InvalidSnapshotPath;

        const base_slot_str = parts.next() orelse return error.InvalidSnapshotPath;
        const base_slot = std.fmt.parseInt(Slot, base_slot_str, 10) catch return error.InvalidSnapshotPath;

        const slot_str = parts.next() orelse return error.InvalidSnapshotPath;
        const slot = std.fmt.parseInt(Slot, slot_str, 10) catch return error.InvalidSnapshotPath;

        const hash_str = parts.next() orelse return error.InvalidSnapshotPath;
        const hash = Hash.parseBase58String(hash_str) catch return error.InvalidSnapshotPath;

        return .{
            .base_slot = base_slot,
            .slot = slot,
            .hash = hash,
        };
    }

    pub fn snapshotNameStr(self: IncrementalSnapshotFileInfo) std.BoundedArray(u8, INCREMENTAL_SNAPSHOT_NAME_MAX_LEN) {
        const b58_str = self.hash.base58String();
        return sig.utils.fmt.boundedFmt(INCREMENTAL_SNAPSHOT_NAME_FMT, .{
            .base_slot = self.base_slot,
            .slot = self.slot,
            .hash = sig.utils.fmt.boundedString(&b58_str),
            .extension = self.compression.extension(),
        });
    }

    test snapshotNameStr {
        try std.testing.expectEqualStrings(
            "incremental-snapshot-10-25-11111111111111111111111111111111.tar.zst",
            snapshotNameStr(.{ .base_slot = 10, .slot = 25, .hash = Hash.default() }).constSlice(),
        );
    }
};

pub const SnapshotFiles = struct {
    full_snapshot: FullSnapshotFileInfo,
    incremental_snapshot: ?IncrementalSnapshotFileInfo,

    const Self = @This();

    /// finds existing snapshots (full and matching incremental) by looking for .tar.zstd files
    pub fn find(allocator: std.mem.Allocator, snapshot_directory: std.fs.Dir) !Self {
        const snapshot_dir_iter = snapshot_directory.iterate();

        const files = try readDirectory(allocator, snapshot_dir_iter);
        var filenames = files.filenames;
        defer {
            filenames.deinit();
            allocator.free(files.filename_memory);
        }

        // find the snapshots
        var maybe_latest_full_snapshot: ?FullSnapshotFileInfo = null;
        var count: usize = 0;
        for (filenames.items) |filename| {
            const snapshot = FullSnapshotFileInfo.fromString(filename) catch continue;
            if (count == 0 or snapshot.slot > maybe_latest_full_snapshot.?.slot) {
                maybe_latest_full_snapshot = snapshot;
            }
            count += 1;
        }
        const latest_full_snapshot = maybe_latest_full_snapshot orelse return error.NoFullSnapshotFileInfoFound;

        count = 0;
        var maybe_latest_incremental_snapshot: ?IncrementalSnapshotFileInfo = null;
        for (filenames.items) |filename| {
            const snapshot = IncrementalSnapshotFileInfo.fromString(filename) catch continue;
            // need to match the base slot
            if (snapshot.base_slot == latest_full_snapshot.slot and (count == 0 or
                // this unwrap is safe because count > 0
                snapshot.slot > maybe_latest_incremental_snapshot.?.slot))
            {
                maybe_latest_incremental_snapshot = snapshot;
            }
            count += 1;
        }

        return .{
            .full_snapshot = latest_full_snapshot,
            .incremental_snapshot = maybe_latest_incremental_snapshot,
        };
    }
};

/// contains all fields from a snapshot (full and incremental)
///
/// Analogous to [SnapshotBankFields](https://github.com/anza-xyz/agave/blob/2de7b565e8b1101824a5e3bac74f3a8cce88ea72/runtime/src/serde_snapshot.rs#L299)
pub const AllSnapshotFields = struct {
    full: SnapshotFields,
    incremental: ?SnapshotFields,
    was_collapsed: bool = false, // used for deinit()

    const Self = @This();

    pub fn fromFiles(
        allocator: std.mem.Allocator,
        logger: Logger,
        snapshot_dir: std.fs.Dir,
        files: SnapshotFiles,
    ) !Self {
        // unpack
        const full_fields = blk: {
            const rel_path_bounded = sig.utils.fmt.boundedFmt("snapshots/{0}/{0}", .{files.full_snapshot.slot});
            const rel_path = rel_path_bounded.constSlice();

            logger.infof("reading snapshot fields from: {s}", .{sig.utils.fmt.tryRealPath(snapshot_dir, rel_path)});

            const full_file = try snapshot_dir.openFile(rel_path, .{});
            defer full_file.close();

            break :blk try SnapshotFields.readFromFile(allocator, full_file);
        };
        errdefer full_fields.deinit(allocator);

        const incremental_fields: ?SnapshotFields = blk: {
            if (files.incremental_snapshot) |incremental_snapshot_path| {
                const rel_path_bounded = sig.utils.fmt.boundedFmt("snapshots/{0}/{0}", .{incremental_snapshot_path.slot});
                const rel_path = rel_path_bounded.constSlice();

                logger.infof("reading inc snapshot fields from: {s}", .{sig.utils.fmt.tryRealPath(snapshot_dir, rel_path)});

                const incremental_file = try snapshot_dir.openFile(rel_path, .{});
                defer incremental_file.close();

                const incremental_fields = try SnapshotFields.readFromFile(allocator, incremental_file);
                errdefer incremental_fields.deinit(allocator);

                break :blk incremental_fields;
            } else {
                logger.info("no incremental snapshot fields found");
                break :blk null;
            }
        };
        errdefer if (incremental_fields) |fields| fields.deinit(allocator);

        return .{
            .full = full_fields,
            .incremental = incremental_fields,
        };
    }

    /// collapse all full and incremental snapshots into one.
    /// note: this works by stack copying the full snapshot and combining
    /// the accounts-db account file map.
    /// this will 1) modify the incremental snapshot account map
    /// and 2) the returned snapshot heap fields will still point to the incremental snapshot
    /// (so be sure not to deinit it while still using the returned snapshot)
    pub fn collapse(self: *Self) !SnapshotFields {
        // nothing to collapse
        if (self.incremental == null)
            return self.full;
        self.was_collapsed = true;

        // collapse bank fields into the
        // incremental =pushed into=> full
        var snapshot = self.incremental.?; // stack copy
        const full_slot = self.full.bank_fields.slot;

        // collapse accounts-db fields
        const storages_map = &self.incremental.?.accounts_db_fields.file_map;

        // TODO: use a better allocator
        const allocator = storages_map.allocator;
        var slots_to_remove = std.ArrayList(Slot).init(allocator);

        // make sure theres no overlap in slots between full and incremental and combine
        var storages_entry_iter = storages_map.iterator();
        while (storages_entry_iter.next()) |*incremental_entry| {
            const slot = incremental_entry.key_ptr.*;

            // only keep slots > full snapshot slot
            if (!(slot > full_slot)) {
                try slots_to_remove.append(slot);
                continue;
            }

            const slot_entry = try self.full.accounts_db_fields.file_map.getOrPut(slot);
            if (slot_entry.found_existing) {
                std.debug.panic("invalid incremental snapshot: slot {d} is in both full and incremental snapshots\n", .{slot});
            } else {
                slot_entry.value_ptr.* = incremental_entry.value_ptr.*;
            }
        }

        for (slots_to_remove.items) |slot| {
            _ = storages_map.swapRemove(slot);
        }

        snapshot.accounts_db_fields = self.full.accounts_db_fields;

        return snapshot;
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        if (!self.was_collapsed) {
            self.full.deinit(allocator);
            if (self.incremental) |inc| {
                inc.deinit(allocator);
            }
        } else {
            self.full.deinit(allocator);
            if (self.incremental) |*inc| {
                inc.accounts_db_fields.file_map.deinit();
                bincode.free(allocator, inc.bank_fields);
                bincode.free(allocator, inc.accounts_db_fields.rooted_slots);
                bincode.free(allocator, inc.accounts_db_fields.rooted_slot_hashes);
            }
        }
    }
};

/// unpacks a .tar.zstd file into the given directory
pub fn parallelUnpackZstdTarBall(
    allocator: std.mem.Allocator,
    logger: Logger,
    file: std.fs.File,
    output_dir: std.fs.Dir,
    n_threads: usize,
    /// only used for progress estimation
    full_snapshot: bool,
) !void {
    const file_stat = try file.stat();
    const file_size: u64 = @intCast(file_stat.size);
    const memory = try std.posix.mmap(
        null,
        file_size,
        std.posix.PROT.READ,
        std.posix.MAP{ .TYPE = .SHARED },
        file.handle,
        0,
    );
    var tar_stream = try zstd.Reader.init(memory);
    defer tar_stream.deinit();
    const n_files_estimate: usize = if (full_snapshot) 421_764 else 100_000; // estimate

    try parallelUntarToFileSystem(
        allocator,
        logger,
        output_dir,
        tar_stream.reader(),
        n_threads,
        n_files_estimate,
    );
}

test "full snapshot path parsing" {
    const full_snapshot_path = "snapshot-269-EAHHZCVccCdAoCXH8RWxvv9edcwjY2boqni9MJuh3TCn.tar.zst";
    const snapshot_info = try FullSnapshotFileInfo.fromString(full_snapshot_path);

    try std.testing.expectEqual(269, snapshot_info.slot);
    try std.testing.expectEqualStrings("EAHHZCVccCdAoCXH8RWxvv9edcwjY2boqni9MJuh3TCn", snapshot_info.hash.base58String().constSlice());
    try std.testing.expectEqual(.zstd, snapshot_info.compression);
}

test "incremental snapshot path parsing" {
    const path = "incremental-snapshot-269-307-4JLFzdaaqkSrmHs55bBDhZrQjHYZvqU1vCcQ5mP22pdB.tar.zst";
    const snapshot_info = try IncrementalSnapshotFileInfo.fromString(path);

    try std.testing.expectEqual(269, snapshot_info.base_slot);
    try std.testing.expectEqual(307, snapshot_info.slot);
    try std.testing.expectEqualStrings("4JLFzdaaqkSrmHs55bBDhZrQjHYZvqU1vCcQ5mP22pdB", snapshot_info.hash.base58String().constSlice());
    try std.testing.expectEqual(.zstd, snapshot_info.compression);
}

test "parse status cache" {
    const allocator = std.testing.allocator;

    const status_cache_path = sig.TEST_DATA_DIR ++ "status_cache";
    var status_cache = try StatusCache.initFromPath(allocator, status_cache_path);
    defer status_cache.deinit(allocator);

    try std.testing.expect(status_cache.bank_slot_deltas.len > 0);
}

test "parse snapshot fields" {
    const allocator = std.testing.allocator;
    const snapshot_path = sig.TEST_DATA_DIR ++ "10";

    var snapshot_fields = try SnapshotFields.readFromFilePath(allocator, snapshot_path);
    defer snapshot_fields.deinit(allocator);
}

test "parse incremental snapshot fields" {
    const allocator = std.testing.allocator;
    const snapshot_path = sig.TEST_DATA_DIR ++ "25";

    var snapshot_fields = try SnapshotFields.readFromFilePath(allocator, snapshot_path);
    defer snapshot_fields.deinit(allocator);

    try std.testing.expectEqual(snapshot_fields.lamports_per_signature, 5000);
    try std.testing.expectEqual(snapshot_fields.bank_fields_inc.snapshot_persistence.?.full_slot, 10);
}
