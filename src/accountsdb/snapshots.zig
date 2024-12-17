//! fields + data to deserialize snapshot metadata

const std = @import("std");
const zstd = @import("zstd");
const sig = @import("../sig.zig");
const base58 = @import("base58-zig");

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

    pub fn initRandom(random: std.Random) StakeHistoryEntry {
        return .{
            .effective = random.int(u64),
            .activating = random.int(u64),
            .deactivating = random.int(u64),
        };
    }
};

pub const EpochAndStakeHistoryEntry = struct { Epoch, StakeHistoryEntry };

pub fn epochAndStakeHistoryEntryRandom(random: std.Random) EpochAndStakeHistoryEntry {
    return .{ random.int(Epoch), StakeHistoryEntry.initRandom(random) };
}

/// Analogous to [StakeHistory](https://github.com/anza-xyz/agave/blob/5a9906ebf4f24cd2a2b15aca638d609ceed87797/sdk/program/src/stake_history.rs#L62)
pub const StakeHistory = []const EpochAndStakeHistoryEntry;

pub fn stakeHistoryRandom(
    random: std.Random,
    allocator: std.mem.Allocator,
    max_list_entries: usize,
) std.mem.Allocator.Error!StakeHistory {
    const StakeHistoryItem = struct { Epoch, StakeHistoryEntry };
    const stake_history_len = random.uintAtMost(usize, max_list_entries);

    const stake_history = try allocator.alloc(StakeHistoryItem, stake_history_len);
    errdefer allocator.free(stake_history);

    for (stake_history) |*entry| entry.* = epochAndStakeHistoryEntryRandom(random);
    return stake_history;
}

/// Analogous to [VoteAccounts](https://github.com/anza-xyz/agave/blob/cadba689cb44db93e9c625770cafd2fc0ae89e33/vote/src/vote_account.rs#L44)
pub const VoteAccounts = struct {
    accounts: StakeAndVoteAccountsMap,
    staked_nodes: ?StakedNodesMap,

    pub const @"!bincode-config:staked_nodes" = bincode.FieldConfig(?StakedNodesMap){
        .skip = true,
        .default_value = @as(?StakedNodesMap, null),
    };

    pub const StakeAndVoteAccount = struct { u64, VoteAccount };

    pub const StakeAndVoteAccountsMap = std.AutoArrayHashMapUnmanaged(
        Pubkey,
        StakeAndVoteAccount,
    );
    pub const StakedNodesMap = std.AutoArrayHashMapUnmanaged(
        Pubkey, // VoteAccount.vote_state.node_pubkey.
        u64, // Total stake across all vote-accounts.
    );

    pub fn deinit(
        vote_accounts: VoteAccounts,
        allocator: std.mem.Allocator,
    ) void {
        var copy = vote_accounts;

        for (copy.accounts.values()) |entry| {
            _, const vote_account = entry;
            vote_account.deinit(allocator);
        }
        copy.accounts.deinit(allocator);

        if (copy.staked_nodes) |*staked_nodes| {
            staked_nodes.deinit(allocator);
        }
    }

    pub fn stakedNodes(self: *VoteAccounts, allocator: std.mem.Allocator) !*const StakedNodesMap {
        if (self.staked_nodes) |*staked_nodes| {
            return staked_nodes;
        }
        const vote_accounts = self.accounts;
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

    pub fn initRandom(
        random: std.Random,
        allocator: std.mem.Allocator,
        max_list_entries: usize,
    ) std.mem.Allocator.Error!VoteAccounts {
        var stakes_vote_accounts = StakeAndVoteAccountsMap.Managed.init(allocator);
        errdefer stakes_vote_accounts.deinit();

        errdefer for (stakes_vote_accounts.values()) |pair| {
            _, const vote_account = pair;
            vote_account.account.deinit(allocator);
        };

        try sig.rand.fillHashmapWithRng(&stakes_vote_accounts, random, random.uintAtMost(usize, max_list_entries), struct {
            allocator: std.mem.Allocator,
            max_list_entries: usize,

            pub fn randomKey(_: @This(), rand: std.Random) !Pubkey {
                return Pubkey.initRandom(rand);
            }
            pub fn randomValue(ctx: @This(), rand: std.Random) !StakeAndVoteAccount {
                const vote_account: VoteAccount = try VoteAccount.initRandom(rand, ctx.allocator, ctx.max_list_entries, error{ RandomError1, RandomError2, RandomError3 });
                errdefer vote_account.deinit(ctx.allocator);
                return .{ rand.int(u64), vote_account };
            }
        }{
            .allocator = allocator,
            .max_list_entries = max_list_entries,
        });

        var stakes_maybe_staked_nodes = if (random.boolean()) std.AutoArrayHashMap(Pubkey, u64).init(allocator) else null;
        errdefer if (stakes_maybe_staked_nodes) |*staked_nodes| staked_nodes.deinit();

        if (stakes_maybe_staked_nodes) |*staked_nodes| {
            try sig.rand.fillHashmapWithRng(
                staked_nodes,
                random,
                random.uintAtMost(usize, max_list_entries),
                struct {
                    pub fn randomKey(rand: std.Random) !Pubkey {
                        return Pubkey.initRandom(rand);
                    }
                    pub fn randomValue(rand: std.Random) !u64 {
                        return rand.int(u64);
                    }
                },
            );
        }

        return .{
            .accounts = stakes_vote_accounts.unmanaged,
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
        const assert_alloc = sig.utils.allocators.failing.allocator(.{
            .alloc = .assert,
            .resize = .assert,
            .free = .assert,
        });
        const vote_state = bincode.readFromSlice(
            assert_alloc,
            VoteState,
            self.account.data,
            .{},
        );
        self.vote_state = vote_state;
        return vote_state;
    }

    pub fn initRandom(
        random: std.Random,
        allocator: std.mem.Allocator,
        max_list_entries: usize,
        comptime RandomErrorSet: type,
    ) std.mem.Allocator.Error!VoteAccount {
        const account = try Account.initRandom(allocator, random, random.uintAtMost(usize, max_list_entries));
        errdefer account.deinit(allocator);

        const vote_state: ?anyerror!VoteState = switch (random.enumValue(enum { null, err, value })) {
            .null => null,
            .err => @as(anyerror!VoteState, sig.rand.errorValue(random, RandomErrorSet)),
            .value => VoteState.initRandom(random),
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

    pub fn initRandom(random: std.Random) VoteState {
        return .{
            .tag = 0, // must always be 0, since this is the enum tag
            .node_pubkey = Pubkey.initRandom(random),
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

/// Analogous to [Delegation](https://github.com/anza-xyz/agave/blob/8d1ef48c785a5d9ee5c0df71dc520ee1a49d8168/sdk/program/src/stake/state.rs#L607)
pub const Delegation = struct {
    /// to whom the stake is delegated
    voter_pubkey: Pubkey,
    /// activated stake amount, set at delegate() time
    stake: u64,
    /// epoch at which this stake was activated, std::Epoch::MAX if is a bootstrap stake
    activation_epoch: Epoch,
    /// epoch the stake was deactivated, std::Epoch::MAX if not deactivated
    deactivation_epoch: Epoch,
    /// DEPRECATED: since 1.16.7
    deprecated_warmup_cooldown_rate: f64,

    pub fn initRandom(random: std.Random) Delegation {
        return .{
            .voter_pubkey = Pubkey.initRandom(random),
            .stake = random.int(u64),
            .activation_epoch = random.int(Epoch),
            .deactivation_epoch = random.int(Epoch),
            .deprecated_warmup_cooldown_rate = random.float(f64),
        };
    }
};

/// Analogous to [RentCollector](https://github.com/anza-xyz/agave/blob/cadba689cb44db93e9c625770cafd2fc0ae89e33/sdk/src/rent_collector.rs#L16)
pub const RentCollector = struct {
    epoch: Epoch,
    epoch_schedule: EpochSchedule,
    slots_per_year: f64,
    rent: Rent,

    pub fn initRandom(random: std.Random) RentCollector {
        return .{
            .epoch = random.int(Epoch),
            .epoch_schedule = EpochSchedule.initRandom(random),
            .slots_per_year = random.float(f64),
            .rent = Rent.initRandom(random),
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

    pub fn initRandom(random: std.Random) FeeCalculator {
        return .{ .lamports_per_signature = random.int(u64) };
    }
};

/// Analogous to [HashInfo](https://github.com/anza-xyz/agave/blob/a79ba51741864e94a066a8e27100dfef14df835f/accounts-db/src/blockhash_queue.rs#L13)
pub const HashAge = struct {
    fee_calculator: FeeCalculator,
    hash_index: u64,
    timestamp: u64,

    pub fn initRandom(random: std.Random) HashAge {
        return .{
            .fee_calculator = FeeCalculator.initRandom(random),
            .hash_index = random.int(u64),
            .timestamp = random.int(u64),
        };
    }
};

pub const BlockhashQueueAges = std.AutoArrayHashMapUnmanaged(Hash, HashAge);

pub fn blockhashQueueAgesRandom(
    random: std.Random,
    allocator: std.mem.Allocator,
    max_list_entries: usize,
) std.mem.Allocator.Error!BlockhashQueueAges {
    var ages = BlockhashQueueAges.Managed.init(allocator);
    errdefer ages.deinit();

    try sig.rand.fillHashmapWithRng(&ages, random, random.uintAtMost(usize, max_list_entries), struct {
        pub fn randomKey(rand: std.Random) !Hash {
            return Hash.initRandom(rand);
        }
        pub fn randomValue(rand: std.Random) !HashAge {
            return HashAge.initRandom(rand);
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

    pub fn initRandom(
        random: std.Random,
        allocator: std.mem.Allocator,
        max_list_entries: usize,
    ) std.mem.Allocator.Error!BlockhashQueue {
        var ages = try blockhashQueueAgesRandom(random, allocator, max_list_entries);
        errdefer ages.deinit(allocator);

        return .{
            .last_hash_index = random.int(u64),
            .last_hash = if (random.boolean()) Hash.initRandom(random) else null,
            .ages = ages,
            .max_age = random.int(usize),
        };
    }
};

/// Analogous to [UnusedAccounts](https://github.com/anza-xyz/agave/blob/2de7b565e8b1101824a5e3bac74f3a8cce88ea72/runtime/src/serde_snapshot.rs#L123)
pub const UnusedAccounts = struct {
    unused1: std.AutoArrayHashMapUnmanaged(Pubkey, void),
    unused2: std.AutoArrayHashMapUnmanaged(Pubkey, void),
    unused3: std.AutoArrayHashMapUnmanaged(Pubkey, u64),

    pub const EMPTY: UnusedAccounts = .{
        .unused1 = .{},
        .unused2 = .{},
        .unused3 = .{},
    };

    pub fn deinit(unused_accounts: UnusedAccounts, allocator: std.mem.Allocator) void {
        var copy = unused_accounts;
        copy.unused1.deinit(allocator);
        copy.unused2.deinit(allocator);
        copy.unused3.deinit(allocator);
    }

    pub fn initRandom(
        random: std.Random,
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

            try sig.rand.fillHashmapWithRng(&managed, random, random.uintAtMost(usize, max_list_entries), struct {
                pub fn randomKey(rand: std.Random) !Pubkey {
                    return Pubkey.initRandom(rand);
                }
                pub fn randomValue(rand: std.Random) !hm_info.Value {
                    return switch (hm_info.Value) {
                        u64 => rand.int(u64),
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
    random: std.Random,
    allocator: std.mem.Allocator,
    max_list_entries: usize,
) std.mem.Allocator.Error!Ancestors {
    var ancestors = Ancestors.Managed.init(allocator);
    errdefer ancestors.deinit();

    try sig.rand.fillHashmapWithRng(&ancestors, random, random.uintAtMost(usize, max_list_entries), struct {
        pub fn randomKey(rand: std.Random) !Slot {
            return rand.int(Slot);
        }
        pub fn randomValue(rand: std.Random) !usize {
            return rand.int(usize);
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

    pub fn initRandom(
        random: std.Random,
        allocator: std.mem.Allocator,
        max_list_entries: usize,
    ) std.mem.Allocator.Error!HardForks {
        const hard_forks_len = random.uintAtMost(usize, max_list_entries);

        const hard_forks = try allocator.alloc(SlotAndCount, hard_forks_len);
        errdefer allocator.free(hard_forks);

        for (hard_forks) |*hard_fork| hard_fork.* = .{
            random.int(Slot),
            random.int(usize),
        };

        return .{ .items = hard_forks };
    }
};

/// Analogous to [NodeVoteAccounts](https://github.com/anza-xyz/agave/blob/8d1ef48c785a5d9ee5c0df71dc520ee1a49d8168/runtime/src/epoch_stakes.rs#L14)
pub const NodeVoteAccounts = struct {
    vote_accounts: []const Pubkey,
    total_stake: u64,

    pub fn deinit(node_vote_accounts: NodeVoteAccounts, allocator: std.mem.Allocator) void {
        allocator.free(node_vote_accounts.vote_accounts);
    }

    pub fn initRandom(
        random: std.Random,
        allocator: std.mem.Allocator,
        max_list_entries: usize,
    ) std.mem.Allocator.Error!NodeVoteAccounts {
        const vote_accounts = try allocator.alloc(Pubkey, random.uintLessThan(usize, max_list_entries));
        errdefer allocator.free(vote_accounts);
        for (vote_accounts) |*vote_account| vote_account.* = Pubkey.initRandom(random);
        return .{
            .vote_accounts = vote_accounts,
            .total_stake = random.int(u64),
        };
    }
};

/// Analogous to [NodeIdToVoteAccounts](https://github.com/anza-xyz/agave/blob/8d1ef48c785a5d9ee5c0df71dc520ee1a49d8168/runtime/src/epoch_stakes.rs#L9)
pub const NodeIdToVoteAccountsMap = std.AutoArrayHashMapUnmanaged(Pubkey, NodeVoteAccounts);

pub fn nodeIdToVoteAccountsMapDeinit(
    map: NodeIdToVoteAccountsMap,
    allocator: std.mem.Allocator,
) void {
    for (map.values()) |*node_vote_accounts| {
        node_vote_accounts.deinit(allocator);
    }
    var copy = map;
    copy.deinit(allocator);
}

pub fn nodeIdToVoteAccountsMapRandom(
    allocator: std.mem.Allocator,
    random: std.Random,
    max_list_entries: usize,
) std.mem.Allocator.Error!NodeIdToVoteAccountsMap {
    var node_id_to_vote_accounts = NodeIdToVoteAccountsMap.Managed.init(allocator);
    errdefer nodeIdToVoteAccountsMapDeinit(node_id_to_vote_accounts.unmanaged, allocator);

    try sig.rand.fillHashmapWithRng(&node_id_to_vote_accounts, random, random.uintAtMost(usize, max_list_entries), struct {
        allocator: std.mem.Allocator,
        max_list_entries: usize,

        pub fn randomKey(_: @This(), rand: std.Random) !Pubkey {
            return Pubkey.initRandom(rand);
        }

        pub fn randomValue(ctx: @This(), rand: std.Random) !NodeVoteAccounts {
            return try NodeVoteAccounts.initRandom(rand, ctx.allocator, ctx.max_list_entries);
        }
    }{
        .allocator = allocator,
        .max_list_entries = max_list_entries,
    });

    return node_id_to_vote_accounts.unmanaged;
}

/// Analogous to [EpochAuthorizedVoters](https://github.com/anza-xyz/agave/blob/42df56cac041077e471655579d6189a389c53882/runtime/src/epoch_stakes.rs#L10)
pub const EpochAuthorizedVoters = std.AutoArrayHashMapUnmanaged(Pubkey, Pubkey);

pub fn epochAuthorizedVotersRandom(
    allocator: std.mem.Allocator,
    random: std.Random,
    max_list_entries: usize,
) std.mem.Allocator.Error!EpochAuthorizedVoters {
    var epoch_authorized_voters = EpochAuthorizedVoters.Managed.init(allocator);
    errdefer epoch_authorized_voters.deinit();

    try sig.rand.fillHashmapWithRng(&epoch_authorized_voters, random, random.uintAtMost(usize, max_list_entries), struct {
        pub fn randomKey(rand: std.Random) !Pubkey {
            return Pubkey.initRandom(rand);
        }
        pub fn randomValue(rand: std.Random) !Pubkey {
            return Pubkey.initRandom(rand);
        }
    });

    return epoch_authorized_voters.unmanaged;
}

/// Analogous to [EpochStakes](https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/runtime/src/epoch_stakes.rs#L22)
pub const EpochStakes = struct {
    stakes: Stakes(Delegation),
    total_stake: u64,
    node_id_to_vote_accounts: NodeIdToVoteAccountsMap,
    epoch_authorized_voters: EpochAuthorizedVoters,

    pub fn deinit(epoch_stakes: EpochStakes, allocator: std.mem.Allocator) void {
        epoch_stakes.stakes.deinit(allocator, {});
        nodeIdToVoteAccountsMapDeinit(epoch_stakes.node_id_to_vote_accounts, allocator);

        var epoch_authorized_voters = epoch_stakes.epoch_authorized_voters;
        epoch_authorized_voters.deinit(allocator);
    }

    pub fn initRandom(
        allocator: std.mem.Allocator,
        /// Should be a PRNG, not a true RNG. See the documentation on `std.Random.uintLessThan`
        /// for commentary on the runtime of this function.
        random: std.Random,
        max_list_entries: usize,
    ) std.mem.Allocator.Error!EpochStakes {
        var result_stakes = try Stakes(Delegation).initRandom(
            allocator,
            random,
            max_list_entries,
            struct {
                pub fn randomValue(rand: std.Random) !Delegation {
                    return Delegation.initRandom(rand);
                }
            },
        );
        errdefer result_stakes.deinit(allocator, {});

        const node_id_to_vote_accounts = try nodeIdToVoteAccountsMapRandom(allocator, random, max_list_entries);
        errdefer nodeIdToVoteAccountsMapDeinit(node_id_to_vote_accounts, allocator);

        var epoch_authorized_voters = try epochAuthorizedVotersRandom(allocator, random, max_list_entries);
        errdefer epoch_authorized_voters.deinit(allocator);

        return .{
            .stakes = result_stakes,
            .total_stake = random.int(u64),
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

    pub const ZEROES: BankIncrementalSnapshotPersistence = .{
        .full_slot = 0,
        .full_hash = Hash.ZEROES,
        .full_capitalization = 0,
        .incremental_hash = Hash.ZEROES,
        .incremental_capitalization = 0,
    };

    pub fn initRandom(random: std.Random) BankIncrementalSnapshotPersistence {
        const full_capitalization = random.int(u64);
        return .{
            .full_slot = random.int(Slot),
            .full_hash = Hash.initRandom(random),
            .full_capitalization = full_capitalization,
            .incremental_hash = Hash.initRandom(random),
            .incremental_capitalization = random.uintAtMost(u64, full_capitalization),
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

/// Analogous to [Authorized](https://github.com/anza-xyz/agave/blob/8d1ef48c785a5d9ee5c0df71dc520ee1a49d8168/sdk/program/src/stake/state.rs#L362)
pub const Authorized = struct {
    staker: Pubkey,
    withdrawer: Pubkey,

    pub fn initRandom(random: std.Random) Authorized {
        return .{
            .staker = Pubkey.initRandom(random),
            .withdrawer = Pubkey.initRandom(random),
        };
    }
};

/// Analogous to [Lockup](https://github.com/anza-xyz/agave/blob/8d1ef48c785a5d9ee5c0df71dc520ee1a49d8168/sdk/program/src/stake/state.rs#L273)
pub const Lockup = struct {
    /// UnixTimestamp at which this stake will allow withdrawal, unless the
    ///   transaction is signed by the custodian
    unix_timestamp: UnixTimestamp,
    /// epoch height at which this stake will allow withdrawal, unless the
    ///   transaction is signed by the custodian
    epoch: Epoch,
    /// custodian signature on a transaction exempts the operation from
    ///  lockup constraints
    custodian: Pubkey,

    pub fn initRandom(random: std.Random) Lockup {
        return .{
            .unix_timestamp = random.int(UnixTimestamp),
            .epoch = random.int(Epoch),
            .custodian = Pubkey.initRandom(random),
        };
    }
};

/// Analogous to [Stake](https://github.com/anza-xyz/agave/blob/8d1ef48c785a5d9ee5c0df71dc520ee1a49d8168/sdk/program/src/stake/state.rs#L918)
pub const Stake = struct {
    delegation: Delegation,
    /// Credits observed is credits from vote account state when delegated or redeemed.
    credits_observed: u64,

    pub fn initRandom(random: std.Random) Stake {
        return .{
            .delegation = Delegation.initRandom(random),
            .credits_observed = random.int(u64),
        };
    }
};

/// Analogous to [Stakes](https://github.com/anza-xyz/agave/blob/1f3ef3325fb0ce08333715aa9d92f831adc4c559/runtime/src/stakes.rs#L186)
pub fn Stakes(comptime StakeDelegationElem: type) type {
    return struct {
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
        const Self = @This();

        pub const StakeDelegations = std.AutoArrayHashMapUnmanaged(Pubkey, StakeDelegationElem);

        pub fn deinit(
            stakes: Self,
            allocator: std.mem.Allocator,
            /// Expected to be a `void` value, or a type/value providing methods/decls:
            /// * `fn clone(delegation_ctx, allocator: std.mem.Allocator, elem: StakeDelegationElem) std.mem.Allocator.Error!StakeDelegationElem`.
            /// * `fn free(delegation_ctx, allocator: std.mem.Allocator, elem: StakeDelegationElem) void`.
            ///
            /// If it is void, it will directly copy each element by value, and never deallocate them.
            void_or_delegation_ctx: anytype,
        ) void {
            stakes.vote_accounts.deinit(allocator);

            const delegation_ctx = switch (@TypeOf(void_or_delegation_ctx)) {
                void => struct {
                    inline fn free(_: std.mem.Allocator, _: StakeDelegationElem) void {}
                },
                else => void_or_delegation_ctx,
            };

            var stake_delegations = stakes.stake_delegations;
            for (stake_delegations.values()) |elem| {
                delegation_ctx.free(allocator, elem);
            }
            stake_delegations.deinit(allocator);

            allocator.free(stakes.stake_history);
        }

        pub fn initRandom(
            allocator: std.mem.Allocator,
            /// Should be a PRNG, not a true RNG. See the documentation on `std.Random.uintLessThan`
            /// for commentary on the runtime of this function.
            random: std.Random,
            max_list_entries: usize,
            /// Expected to provide methods/decls:
            /// * `fn randomValue(delegation_ctx, random: std.Random) StakeDelegationElem`.
            ///
            /// Also see `sig.rand.fillHashmapWithRng`.
            delegation_ctx: anytype,
        ) std.mem.Allocator.Error!Self {
            const vote_accounts = try VoteAccounts.initRandom(random, allocator, max_list_entries);
            errdefer vote_accounts.deinit(allocator);

            var stake_delegations = StakeDelegations.Managed.init(allocator);
            errdefer stake_delegations.deinit();

            try sig.rand.fillHashmapWithRng(
                &stake_delegations,
                random,
                random.uintAtMost(usize, max_list_entries),
                struct {
                    pub fn randomKey(_: @This(), rand: std.Random) !Pubkey {
                        return Pubkey.initRandom(rand);
                    }
                    pub fn randomValue(ctx: @This(), rand: std.Random) !StakeDelegationElem {
                        return ctx.delegation_ctx.randomValue(rand);
                    }

                    delegation_ctx: @TypeOf(delegation_ctx),
                }{ .delegation_ctx = delegation_ctx },
            );

            var stake_history = try stakeHistoryRandom(random, allocator, max_list_entries);
            errdefer stake_history.deinit(allocator);

            return .{
                .vote_accounts = vote_accounts,
                .stake_delegations = stake_delegations.unmanaged,
                .unused = random.int(u64),
                .epoch = random.int(Epoch),
                .stake_history = stake_history,
            };
        }
    };
}

/// Analogous to [VersionedEpochStake](https://github.com/anza-xyz/agave/blob/8d1ef48c785a5d9ee5c0df71dc520ee1a49d8168/runtime/src/epoch_stakes.rs#L137)
pub const VersionedEpochStake = union(enum(u32)) {
    current: Current,

    pub fn deinit(ves: VersionedEpochStake, allocator: std.mem.Allocator) void {
        switch (ves) {
            .current => |current| current.deinit(allocator),
        }
    }

    pub const Current = struct {
        stakes: Stakes(Stake),
        total_stake: u64,
        node_id_to_vote_accounts: NodeIdToVoteAccountsMap,
        epoch_authorized_voters: EpochAuthorizedVoters,

        pub fn deinit(current: Current, allocator: std.mem.Allocator) void {
            current.stakes.deinit(allocator, {});
            nodeIdToVoteAccountsMapDeinit(current.node_id_to_vote_accounts, allocator);
            var epoch_authorized_voters = current.epoch_authorized_voters;
            epoch_authorized_voters.deinit(allocator);
        }

        pub fn initRandom(
            allocator: std.mem.Allocator,
            random: std.Random,
            max_list_entries: usize,
        ) std.mem.Allocator.Error!Current {
            const stakes = try Stakes(Stake).initRandom(
                allocator,
                random,
                max_list_entries,
                struct {
                    pub fn randomValue(rand: std.Random) !Stake {
                        return Stake.initRandom(rand);
                    }
                },
            );
            errdefer stakes.deinit(allocator, {});

            const node_id_to_vote_accounts = try nodeIdToVoteAccountsMapRandom(
                allocator,
                random,
                max_list_entries,
            );
            errdefer nodeIdToVoteAccountsMapDeinit(node_id_to_vote_accounts, allocator);

            var epoch_authorized_voters = try epochAuthorizedVotersRandom(allocator, random, max_list_entries);
            errdefer epoch_authorized_voters.deinit(allocator);

            return .{
                .stakes = stakes,
                .total_stake = random.int(u64),
                .node_id_to_vote_accounts = node_id_to_vote_accounts,
                .epoch_authorized_voters = epoch_authorized_voters,
            };
        }
    };

    pub fn initRandom(
        allocator: std.mem.Allocator,
        random: std.Random,
        max_list_entries: usize,
    ) std.mem.Allocator.Error!VersionedEpochStake {
        comptime std.debug.assert(@typeInfo(VersionedEpochStake).Union.fields.len == 1); // randomly generate the tag otherwise
        return .{
            .current = try Current.initRandom(allocator, random, max_list_entries),
        };
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
    random: std.Random,
    allocator: std.mem.Allocator,
    max_list_entries: usize,
) std.mem.Allocator.Error!EpochStakeMap {
    var epoch_stakes = EpochStakeMap.Managed.init(allocator);
    errdefer epochStakeMapDeinit(epoch_stakes.unmanaged, allocator);

    try sig.rand.fillHashmapWithRng(&epoch_stakes, random, random.uintAtMost(usize, max_list_entries), struct {
        allocator: std.mem.Allocator,
        max_list_entries: usize,

        pub fn randomKey(_: @This(), rand: std.Random) !Epoch {
            return rand.int(Epoch);
        }

        pub fn randomValue(ctx: @This(), rand: std.Random) !EpochStakes {
            return try EpochStakes.initRandom(ctx.allocator, rand, ctx.max_list_entries);
        }
    }{
        .allocator = allocator,
        .max_list_entries = max_list_entries,
    });

    return epoch_stakes.unmanaged;
}

/// Analogous to [DeserializableVersionedBank](https://github.com/anza-xyz/agave/blob/9c899a72414993dc005f11afb5df10752b10810b/runtime/src/serde_snapshot.rs#L134).
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
    stakes: Stakes(Delegation),
    unused_accounts: UnusedAccounts,
    epoch_stakes: EpochStakeMap,
    is_delta: bool,

    pub fn deinit(
        bank_fields: *const BankFields,
        allocator: std.mem.Allocator,
    ) void {
        bank_fields.blockhash_queue.deinit(allocator);

        var ancestors = bank_fields.ancestors;
        ancestors.deinit(allocator);

        bank_fields.hard_forks.deinit(allocator);

        bank_fields.stakes.deinit(allocator, {});

        bank_fields.unused_accounts.deinit(allocator);

        epochStakeMapDeinit(bank_fields.epoch_stakes, allocator);
    }

    pub fn getStakedNodes(self: *const BankFields, allocator: std.mem.Allocator, epoch: Epoch) !*const std.AutoArrayHashMapUnmanaged(Pubkey, u64) {
        const epoch_stakes = self.epoch_stakes.getPtr(epoch) orelse return error.NoEpochStakes;
        return epoch_stakes.stakes.vote_accounts.stakedNodes(allocator);
    }

    /// Returns the leader schedule for this bank's epoch
    pub fn leaderSchedule(
        self: *const BankFields,
        allocator: std.mem.Allocator,
    ) !sig.core.leader_schedule.LeaderSchedule {
        return self.leaderScheduleForEpoch(allocator, self.epoch);
    }

    /// Returns the leader schedule for an arbitrary epoch.
    /// Only works if the bank is aware of the staked nodes for that epoch.
    pub fn leaderScheduleForEpoch(
        self: *const BankFields,
        allocator: std.mem.Allocator,
        epoch: Epoch,
    ) !sig.core.leader_schedule.LeaderSchedule {
        const slots_in_epoch = self.epoch_schedule.getSlotsInEpoch(self.epoch);
        const staked_nodes = try self.getStakedNodes(allocator, epoch);
        return .{
            .allocator = allocator,
            .slot_leaders = try sig.core.leader_schedule.LeaderSchedule.fromStakedNodes(
                allocator,
                epoch,
                slots_in_epoch,
                staked_nodes,
            ),
        };
    }

    pub fn initRandom(
        allocator: std.mem.Allocator,
        /// Should be a PRNG, not a true RNG. See the documentation on `std.Random.uintLessThan`
        /// for commentary on the runtime of this function.
        random: std.Random,
        max_list_entries: usize,
    ) std.mem.Allocator.Error!BankFields {
        var blockhash_queue = try BlockhashQueue.initRandom(random, allocator, max_list_entries);
        errdefer blockhash_queue.deinit(allocator);

        var ancestors = try ancestorsRandom(random, allocator, max_list_entries);
        errdefer ancestors.deinit(allocator);

        const hard_forks = try HardForks.initRandom(random, allocator, max_list_entries);
        errdefer hard_forks.deinit(allocator);

        const stakes = try Stakes(Delegation).initRandom(allocator, random, max_list_entries, struct {
            pub fn randomValue(rand: std.Random) !Delegation {
                return Delegation.initRandom(rand);
            }
        });
        errdefer stakes.deinit(allocator, {});

        const unused_accounts = try UnusedAccounts.initRandom(random, allocator, max_list_entries);
        errdefer unused_accounts.deinit(allocator);

        const epoch_stakes = try epochStakeMapRandom(random, allocator, max_list_entries);
        errdefer epochStakeMapDeinit(epoch_stakes, allocator);

        return .{
            .blockhash_queue = blockhash_queue,
            .ancestors = ancestors,
            .hash = Hash.initRandom(random),
            .parent_hash = Hash.initRandom(random),
            .parent_slot = random.int(Slot),
            .hard_forks = hard_forks,
            .transaction_count = random.int(u64),
            .tick_height = random.int(u64),
            .signature_count = random.int(u64),
            .capitalization = random.int(u64),
            .max_tick_height = random.int(u64),
            .hashes_per_tick = if (random.boolean()) random.int(u64) else null,
            .ticks_per_slot = random.int(u64),
            .ns_per_slot = random.int(u128),
            .genesis_creation_time = random.int(sig.accounts_db.genesis_config.UnixTimestamp),
            .slots_per_year = random.float(f64),
            .accounts_data_len = random.int(u64),
            .slot = random.int(Slot),
            .epoch = random.int(Epoch),
            .block_height = random.int(u64),
            .collector_id = Pubkey.initRandom(random),
            .collector_fees = random.int(u64),
            .fee_calculator = FeeCalculator.initRandom(random),
            .fee_rate_governor = FeeRateGovernor.initRandom(random),
            .collected_rent = random.int(u64),
            .rent_collector = RentCollector.initRandom(random),
            .epoch_schedule = EpochSchedule.initRandom(random),
            .inflation = Inflation.initRandom(random),
            .stakes = stakes,
            .unused_accounts = unused_accounts,
            .epoch_stakes = epoch_stakes,
            .is_delta = random.boolean(),
        };
    }
};

/// Analogous to [ExtraFieldsToDeserialize](https://github.com/anza-xyz/agave/blob/8d1ef48c785a5d9ee5c0df71dc520ee1a49d8168/runtime/src/serde_snapshot.rs#L396).
pub const ExtraFields = struct {
    lamports_per_signature: u64,
    snapshot_persistence: ?BankIncrementalSnapshotPersistence,
    epoch_accounts_hash: ?Hash,
    versioned_epoch_stakes: VersionedEpochStakesMap,
    accounts_lt_hash: ?AccountsLtHash,

    pub const @"!bincode-config": bincode.FieldConfig(ExtraFields) = .{
        .deserializer = bincodeRead,
        .serializer = null, // just use default serialization method
        .free = bincodeFree,
    };

    pub const VersionedEpochStakesMap = std.AutoArrayHashMapUnmanaged(u64, VersionedEpochStake);

    /// TODO: https://github.com/orgs/Syndica/projects/2/views/10?pane=issue&itemId=85238686
    pub const ACCOUNTS_LATTICE_HASH_LEN = 1024;
    pub const AccountsLtHash = [ACCOUNTS_LATTICE_HASH_LEN]u16;

    pub const INIT_EOF: ExtraFields = .{
        .lamports_per_signature = 0,
        .snapshot_persistence = null,
        .epoch_accounts_hash = null,
        .versioned_epoch_stakes = .{},
        .accounts_lt_hash = null,
    };

    pub fn deinit(extra: *const ExtraFields, allocator: std.mem.Allocator) void {
        var versioned_epoch_stakes = extra.versioned_epoch_stakes;
        for (versioned_epoch_stakes.values()) |ves| ves.deinit(allocator);
        versioned_epoch_stakes.deinit(allocator);
    }

    pub fn initRandom(
        allocator: std.mem.Allocator,
        random: std.Random,
        max_list_entries: usize,
    ) std.mem.Allocator.Error!ExtraFields {
        var extra_fields: ExtraFields = INIT_EOF;
        errdefer extra_fields.deinit(allocator);

        const FieldTag = std.meta.FieldEnum(ExtraFields);
        const field_infos = @typeInfo(ExtraFields).Struct.fields;

        const NonEofCount = std.math.IntFittingRange(0, field_infos.len);
        const non_eof_count = random.uintLessThan(NonEofCount, field_infos.len);

        inline for (field_infos, 0..) |field, i| runtime_continue: {
            if (i != non_eof_count) break :runtime_continue;
            const field_ptr = &@field(extra_fields, field.name);
            switch (@field(FieldTag, field.name)) {
                .lamports_per_signature,
                => field_ptr.* = random.int(u64),

                .snapshot_persistence,
                => field_ptr.* = BankIncrementalSnapshotPersistence.initRandom(random),

                .epoch_accounts_hash,
                => field_ptr.* = Hash.initRandom(random),

                .versioned_epoch_stakes,
                => {
                    const entry_count = random.uintAtMost(usize, max_list_entries);
                    try field_ptr.ensureTotalCapacity(allocator, entry_count);
                    for (0..entry_count) |_| {
                        const ves = try VersionedEpochStake.initRandom(
                            allocator,
                            random,
                            max_list_entries,
                        );
                        field_ptr.putAssumeCapacity(random.int(u64), ves);
                    }
                },

                .accounts_lt_hash,
                => field_ptr.* = hash: {
                    var hash: AccountsLtHash = undefined;
                    random.bytes(std.mem.asBytes(&hash));
                    break :hash hash;
                },
            }
        }

        return extra_fields;
    }

    fn bincodeRead(
        allocator: std.mem.Allocator,
        reader: anytype,
        params: bincode.Params,
    ) !ExtraFields {
        var extra_fields: ExtraFields = INIT_EOF;
        errdefer extra_fields.deinit(allocator);

        until_eof: {
            const FieldTag = std.meta.FieldEnum(ExtraFields);
            const assert_allocator = sig.utils.allocators.failing.allocator(.{
                .alloc = .assert,
                .resize = .assert,
                .free = .assert,
            });

            inline for (@typeInfo(ExtraFields).Struct.fields) |field| {
                const field_ptr = &@field(extra_fields, field.name);
                field_ptr.* = switch (@field(FieldTag, field.name)) {
                    .lamports_per_signature,
                    => bincode.readInt(u64, reader, params),

                    .snapshot_persistence,
                    .epoch_accounts_hash,
                    .accounts_lt_hash,
                    => bincode.read(assert_allocator, field.type, reader, params),

                    .versioned_epoch_stakes,
                    => bincode.read(allocator, field.type, reader, params),
                } catch |err| switch (err) {
                    error.EndOfStream => break :until_eof,
                    else => |e| return e,
                };
            }
        }

        return extra_fields;
    }

    fn bincodeFree(allocator: std.mem.Allocator, data: anytype) void {
        comptime if (@TypeOf(data) == ExtraFields) unreachable;
        data.deinit(allocator);
    }
};

/// Analogous to [SerializableAccountStorageEntry](https://github.com/anza-xyz/agave/blob/cadba689cb44db93e9c625770cafd2fc0ae89e33/runtime/src/serde_snapshot/storage.rs#L11)
pub const AccountFileInfo = struct {
    /// note: serialized id is a usize but in code it's FileId (u32)
    id: FileId,
    /// amount of bytes used
    length: usize,

    pub const @"!bincode-config:id" = FileId.BincodeConfig;

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

    pub fn initRandom(random: std.Random) BankHashInfo {
        return .{
            .accounts_delta_hash = Hash.initRandom(random),
            .accounts_hash = Hash.initRandom(random),
            .stats = BankHashStats.initRandom(random),
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

    pub fn initRandom(random: std.Random) BankHashStats {
        return .{
            .num_updated_accounts = random.int(u64),
            .num_removed_accounts = random.int(u64),
            .num_lamports_stored = random.int(u64),
            .total_data_len = random.int(u64),
            .num_executable_accounts = random.int(u64),
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

pub const SlotAndHash = struct {
    slot: Slot,
    hash: Hash,

    pub fn equals(a: *const SlotAndHash, b: *const SlotAndHash) bool {
        if (a.slot != b.slot) return false;
        if (!a.hash.eql(b.hash)) return false;
        return true;
    }
};

/// Analogous to [AccountsDbFields](https://github.com/anza-xyz/agave/blob/2de7b565e8b1101824a5e3bac74f3a8cce88ea72/runtime/src/serde_snapshot.rs#L77)
pub const AccountsDbFields = struct {
    file_map: FileMap,

    /// NOTE: this is not a meaningful field
    /// NOTE: at the time of writing, a test snapshots we use actually have this field set to 601 on disk,
    /// so be sure to keep that in mind while testing.
    stored_meta_write_version: u64,

    slot: Slot,
    bank_hash_info: BankHashInfo,

    /// NOTE: these are currently always empty?
    /// https://github.com/anza-xyz/agave/blob/9c899a72414993dc005f11afb5df10752b10810b/runtime/src/serde_snapshot.rs#L815-L825
    rooted_slots: []const Slot,
    rooted_slot_hashes: []const SlotAndHash,

    pub const @"!bincode-config": bincode.FieldConfig(AccountsDbFields) = .{
        .deserializer = bincodeRead,
        .serializer = bincodeWrite,
        .free = bincodeFree,
    };

    pub const FileMap = std.AutoArrayHashMapUnmanaged(Slot, AccountFileInfo);

    pub fn deinit(fields: AccountsDbFields, allocator: std.mem.Allocator) void {
        var file_map = fields.file_map;
        file_map.deinit(allocator);

        allocator.free(fields.rooted_slots);
        allocator.free(fields.rooted_slot_hashes);
    }

    fn bincodeRead(
        allocator: std.mem.Allocator,
        reader: anytype,
        params: bincode.Params,
    ) !AccountsDbFields {
        const assert_allocator = sig.utils.allocators.failing.allocator(.{
            .alloc = .assert,
            .resize = .assert,
            .free = .assert,
        });

        var file_map = try bincode.hashmap.readCtx(allocator, FileMap, reader, params, struct {
            pub const readKey = {};
            pub const freeKey = {};
            pub fn readValue(
                _: std.mem.Allocator,
                _reader: anytype,
                _params: bincode.Params,
            ) !AccountFileInfo {
                if (try bincode.readIntAsLength(usize, _reader, _params) != 1) {
                    return error.TooManyAccountFileInfos;
                }
                return bincode.read(assert_allocator, AccountFileInfo, _reader, _params);
            }
            pub const freeValue = {};
        });
        errdefer file_map.deinit(allocator);

        const stored_meta_write_version = try bincode.readInt(u64, reader, params);
        const slot = try bincode.readInt(Slot, reader, params);
        const bank_hash_info = try bincode.read(assert_allocator, BankHashInfo, reader, params);

        const rooted_slots: []const Slot =
            bincode.read(allocator, []const Slot, reader, params) catch |err| switch (err) {
            error.EndOfStream => &.{},
            else => |e| return e,
        };
        errdefer allocator.free(rooted_slots);

        const rooted_slot_hashes: []const SlotAndHash =
            bincode.read(allocator, []const SlotAndHash, reader, params) catch |err| switch (err) {
            error.EndOfStream => &.{},
            else => |e| return e,
        };
        errdefer allocator.free(rooted_slot_hashes);

        return .{
            .file_map = file_map,
            .stored_meta_write_version = stored_meta_write_version,
            .slot = slot,
            .bank_hash_info = bank_hash_info,

            .rooted_slots = rooted_slots,
            .rooted_slot_hashes = rooted_slot_hashes,
        };
    }

    fn bincodeWrite(writer: anytype, data: anytype, params: bincode.Params) !void {
        comptime if (@TypeOf(data) != AccountsDbFields) unreachable;

        {
            try bincode.write(writer, @as(usize, data.file_map.count()), params);
            var iter = data.file_map.iterator();
            while (iter.next()) |entry| {
                try bincode.write(writer, entry.key_ptr.*, params);

                const value_as_slice: []const AccountFileInfo = entry.value_ptr[0..1];
                try bincode.write(writer, value_as_slice, params);
            }
        }

        try bincode.write(writer, data.stored_meta_write_version, params);
        try bincode.write(writer, data.slot, params);
        try bincode.write(writer, data.bank_hash_info, params);

        if (data.rooted_slot_hashes.len != 0 or data.rooted_slots.len != 0) {
            try bincode.write(writer, data.rooted_slots, params);
        }

        if (data.rooted_slot_hashes.len != 0) {
            try bincode.write(writer, data.rooted_slot_hashes, params);
        }
    }

    fn bincodeFree(allocator: std.mem.Allocator, data: anytype) void {
        data.deinit(allocator);
    }
};

/// contains all the metadata from a snapshot.
/// this includes fields for accounts-db and the bank of the snapshots slots.
/// this does not include account-specific data.
pub const Manifest = struct {
    bank_fields: BankFields,
    accounts_db_fields: AccountsDbFields,
    /// incremental snapshot fields.
    bank_extra: ExtraFields,

    pub fn deinit(self: Manifest, allocator: std.mem.Allocator) void {
        self.bank_fields.deinit(allocator);
        self.accounts_db_fields.deinit(allocator);
        self.bank_extra.deinit(allocator);
    }

    pub fn readFromFilePath(
        allocator: std.mem.Allocator,
        path: []const u8,
    ) !Manifest {
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
    ) !Manifest {
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
    ) !Manifest {
        return try bincode.read(allocator, Manifest, reader, .{});
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

    pub const EMPTY: StatusCache = .{ .bank_slot_deltas = &.{} };

    pub fn initFromPath(allocator: std.mem.Allocator, path: []const u8) !StatusCache {
        const status_cache_file = try std.fs.cwd().openFile(path, .{});
        defer status_cache_file.close();
        return readFromFile(allocator, status_cache_file);
    }

    /// opens the status cache using path {dir}/snapshots/status_cache
    pub fn initFromDir(allocator: std.mem.Allocator, dir: std.fs.Dir) !StatusCache {
        const status_cache_file = try dir.openFile("snapshots/status_cache", .{});
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

/// information on a full snapshot including the filename, slot, and hash
///
/// Analogous to [SnapshotArchiveInfo](https://github.com/anza-xyz/agave/blob/59bf1809fe5115f0fad51e80cc0a19da1496e2e9/runtime/src/snapshot_archive_info.rs#L44)
pub const FullSnapshotFileInfo = struct {
    slot: Slot,
    hash: Hash,

    const SnapshotArchiveNameFmtSpec = sig.utils.fmt.BoundedSpec("snapshot-{[slot]d}-{[hash]s}.tar.zst");

    pub const SnapshotArchiveNameStr = SnapshotArchiveNameFmtSpec.BoundedArrayValue(.{
        .slot = std.math.maxInt(Slot),
        .hash = sig.utils.fmt.boundedString(&(Hash{ .data = .{255} ** 32 }).base58String()),
    });

    pub fn snapshotArchiveName(self: FullSnapshotFileInfo) SnapshotArchiveNameStr {
        const b58_str = self.hash.base58String();
        return SnapshotArchiveNameFmtSpec.fmt(.{
            .slot = self.slot,
            .hash = sig.utils.fmt.boundedString(&b58_str),
        });
    }

    pub const ParseFileNameTarZstError = ParseFileBaseNameError || error{
        MissingExtension,
        InvalidExtension,
    };

    /// Matches with the regex: `^snapshot-(?P<slot>[[:digit:]]+)-(?P<hash>[[:alnum:]]+)\.(?P<ext>tar\.zst)$`.
    pub fn parseFileNameTarZst(
        filename: []const u8,
    ) ParseFileNameTarZstError!FullSnapshotFileInfo {
        const snapshot_file_info, const extension_start = try parseFileBaseName(filename);
        if (extension_start == filename.len) return error.MissingExtension;
        if (!std.mem.eql(u8, filename[extension_start..], ".tar.zst")) return error.InvalidExtension;
        return snapshot_file_info;
    }

    pub const ParseFileBaseNameError = error{
        /// The file name did not start with 'snapshot-'.
        MissingPrefix,
        /// The prefix was not followed by a slot number.
        MissingSlot,
        /// The slot was not followed by a delimiter '-'.
        MissingSlotDelimiter,
        /// The slot number string either did not fit into
        /// a `Slot` integer, or contained invalid digits.
        InvalidSlot,
        /// The slot was not followed by a hash.
        MissingHash,
        /// The hash was invalid.
        InvalidHash,
    };

    /// Matches with the regex: `^snapshot-(?P<slot>[[:digit:]]+)-(?P<hash>[[:alnum:]]+)`.
    /// Returns the full snapshot info based on the parsed section, and the index to the
    /// remainder of the unparsed section of `filename`, which the caller can check for
    /// the expected extension.
    pub fn parseFileBaseName(
        filename: []const u8,
    ) ParseFileBaseNameError!struct { FullSnapshotFileInfo, usize } {
        const prefix = "snapshot-";
        if (!std.mem.startsWith(u8, filename, prefix)) {
            return error.MissingPrefix;
        }

        // parse slot until '-'
        const slot, const slot_end = slot: {
            const start = prefix.len;
            if (start == filename.len) {
                return error.MissingSlot;
            }

            const str_max_len = std.fmt.count("{d}", .{std.math.maxInt(Slot)});
            const end_max = @max(filename.len, start + str_max_len + 1);
            const filename_trunc = filename[0..end_max];
            const end = std.mem.indexOfScalarPos(u8, filename_trunc, start + 1, '-') orelse
                return error.MissingSlotDelimiter;

            const str = filename[start..end];
            const slot = std.fmt.parseInt(Slot, str, 10) catch |err| switch (err) {
                error.Overflow, error.InvalidCharacter => return error.InvalidSlot,
            };

            break :slot .{ slot, end };
        };

        // parse until there's no base58 characters left
        const hash, const hash_end = hash: {
            const start = slot_end + 1;
            if (start == filename.len) {
                return error.MissingHash;
            }

            const str_max_len = Hash.base58_max_encoded_size;
            const end_max = @max(filename.len, start + str_max_len + 1);
            const filename_truncated = filename[0..end_max];
            // TODO: accessing it this way is dirty, the base58 API should be improved
            const alphabet = &base58.Alphabet.DEFAULT.encode;
            const end = std.mem.indexOfNonePos(u8, filename_truncated, start + 1, alphabet) orelse
                filename_truncated.len;

            const str = filename[start..end];
            const hash = Hash.parseBase58String(str) catch |err| switch (err) {
                error.InvalidHash => return error.InvalidHash,
            };

            break :hash .{ hash, end };
        };

        const snapshot_file_info: FullSnapshotFileInfo = .{
            .slot = slot,
            .hash = hash,
        };

        return .{ snapshot_file_info, hash_end };
    }
};

/// information on an incremental snapshot including the filename, base slot (full snapshot), slot, and hash
///
/// Analogous to [IncrementalSnapshotArchiveInfo](https://github.com/anza-xyz/agave/blob/59bf1809fe5115f0fad51e80cc0a19da1496e2e9/runtime/src/snapshot_archive_info.rs#L103)
pub const IncrementalSnapshotFileInfo = struct {
    base_slot: Slot,
    slot: Slot,
    hash: Hash,

    /// Returns the incremental slot and hash.
    pub fn slotAndHash(self: IncrementalSnapshotFileInfo) SlotAndHash {
        return .{
            .slot = self.slot,
            .hash = self.hash,
        };
    }

    const SnapshotArchiveNameFmtSpec = sig.utils.fmt.BoundedSpec("incremental-snapshot-{[base_slot]d}-{[slot]d}-{[hash]s}.tar.zst");

    pub const SnapshotArchiveNameStr = SnapshotArchiveNameFmtSpec.BoundedArrayValue(.{
        .base_slot = std.math.maxInt(Slot),
        .slot = std.math.maxInt(Slot),
        .hash = sig.utils.fmt.boundedString(&(Hash{ .data = .{255} ** 32 }).base58String()),
    });

    pub fn snapshotArchiveName(self: IncrementalSnapshotFileInfo) SnapshotArchiveNameStr {
        const b58_str = self.hash.base58String();
        return SnapshotArchiveNameFmtSpec.fmt(.{
            .base_slot = self.base_slot,
            .slot = self.slot,
            .hash = sig.utils.fmt.boundedString(&b58_str),
        });
    }

    pub const ParseFileNameTarZstError = ParseFileBaseNameError || error{
        MissingExtension,
        InvalidExtension,
    };

    /// Matches against regex: `^incremental-snapshot-(?P<base_slot>[[:digit:]]+)-(?P<slot>[[:digit:]]+)-(?P<hash>[[:alnum:]]+)\.(?P<ext>tar\.zst)$`.
    pub fn parseFileNameTarZst(
        filename: []const u8,
    ) ParseFileNameTarZstError!IncrementalSnapshotFileInfo {
        const snapshot_file_info, const extension_start = try parseFileBaseName(filename);
        if (extension_start == filename.len) return error.MissingExtension;
        if (!std.mem.eql(u8, filename[extension_start..], ".tar.zst")) return error.InvalidExtension;
        return snapshot_file_info;
    }

    pub const ParseFileBaseNameError = error{
        /// The file name did not start with 'incremental-snapshot-'.
        MissingPrefix,
        /// The prefix was not followed by a base slot number.
        MissingBaseSlot,
        /// The base slot was not followed by a delimiter '-'.
        MissingBaseSlotDelimiter,
        /// The base slot number string either did not fit into
        /// a `Slot` integer, or contained invalid digits.
        InvalidBaseSlot,
        /// The base slot was not followed by a slot number.
        MissingSlot,
        /// The slot was not followed by a delimiter '-'.
        MissingSlotDelimiter,
        /// The slot number string either did not fit into
        /// a `Slot` integer, or contained invalid digits.
        InvalidSlot,
        /// The slot was not followed by a hash.
        MissingHash,
        /// The hash was invalid.
        InvalidHash,
    };

    /// Matches with the regex: `incremental-snapshot-(?P<base_slot>[[:digit:]]+)-(?P<slot>[[:digit:]]+)-(?P<hash>[[:alnum:]]+)`.
    /// Returns the full snapshot info based on the parsed section, and the index to the
    /// remainder of the unparsed section of `filename`, which the caller can check for
    /// the expected extension.
    pub fn parseFileBaseName(
        filename: []const u8,
    ) ParseFileBaseNameError!struct { IncrementalSnapshotFileInfo, usize } {
        const prefix = "incremental-snapshot-";
        if (!std.mem.startsWith(u8, filename, prefix)) {
            return error.MissingPrefix;
        }

        // parse base slot until '-'
        const base_slot, const base_slot_end = base_slot: {
            const start = prefix.len;
            if (start == filename.len) {
                return error.MissingBaseSlot;
            }

            const str_max_len = std.fmt.count("{d}", .{std.math.maxInt(Slot)});
            const end_max = @max(filename.len, start + str_max_len + 1);
            const filename_trunc = filename[0..end_max];
            const end = std.mem.indexOfScalarPos(u8, filename_trunc, start + 1, '-') orelse
                return error.MissingSlotDelimiter;

            const str = filename[start..end];
            const base_slot = std.fmt.parseInt(Slot, str, 10) catch |err| switch (err) {
                error.Overflow, error.InvalidCharacter => return error.InvalidBaseSlot,
            };

            break :base_slot .{ base_slot, end };
        };

        // parse slot until '-'
        const slot, const slot_end = slot: {
            const start = base_slot_end + 1;
            if (start == filename.len) {
                return error.MissingSlot;
            }

            const str_max_len = std.fmt.count("{d}", .{std.math.maxInt(Slot)});
            const end_max = @max(filename.len, start + str_max_len + 1);
            const filename_trunc = filename[0..end_max];
            const end = std.mem.indexOfScalarPos(u8, filename_trunc, start + 1, '-') orelse
                return error.MissingSlotDelimiter;

            const str = filename[start..end];
            const slot = std.fmt.parseInt(Slot, str, 10) catch |err| switch (err) {
                error.Overflow, error.InvalidCharacter => return error.InvalidSlot,
            };

            break :slot .{ slot, end };
        };

        // parse until there's no base58 characters left
        const hash, const hash_end = hash: {
            const start = slot_end + 1;
            if (start == filename.len) {
                return error.MissingHash;
            }

            const str_max_len = Hash.base58_max_encoded_size;
            const end_max = @max(filename.len, start + str_max_len + 1);
            const filename_truncated = filename[0..end_max];
            // TODO: accessing it this way is dirty, the base58 API should be improved
            const alphabet = &base58.Alphabet.DEFAULT.encode;
            const end = std.mem.indexOfNonePos(u8, filename_truncated, start + 1, alphabet) orelse
                filename_truncated.len;

            const str = filename[start..end];
            const hash = Hash.parseBase58String(str) catch |err| switch (err) {
                error.InvalidHash => return error.InvalidHash,
            };

            break :hash .{ hash, end };
        };

        const snapshot_file_info: IncrementalSnapshotFileInfo = .{
            .base_slot = base_slot,
            .slot = slot,
            .hash = hash,
        };

        return .{ snapshot_file_info, hash_end };
    }
};

pub const SnapshotFiles = struct {
    full: FullSnapshotFileInfo,
    incremental_info: ?SlotAndHash,

    pub fn incremental(snapshot_files: SnapshotFiles) ?IncrementalSnapshotFileInfo {
        const inc_info = snapshot_files.incremental_info orelse return null;
        return .{
            .base_slot = snapshot_files.full.slot,
            .slot = inc_info.slot,
            .hash = inc_info.hash,
        };
    }

    pub fn fromFileInfos(
        full_info: FullSnapshotFileInfo,
        maybe_incremental_info: ?IncrementalSnapshotFileInfo,
    ) SnapshotFiles {
        if (maybe_incremental_info) |inc| {
            std.debug.assert(inc.base_slot == full_info.slot);
        }
        return .{
            .full = full_info,
            .incremental_info = if (maybe_incremental_info) |inc| inc.slotAndHash() else null,
        };
    }

    pub const FindError = std.mem.Allocator.Error || std.fs.Dir.Iterator.Error || error{
        NoFullSnapshotFileInfoFound,
    };
    /// finds existing snapshots (full and matching incremental) by looking for .tar.zstd files
    pub fn find(allocator: std.mem.Allocator, search_dir: std.fs.Dir) FindError!SnapshotFiles {
        var incremental_snapshots: std.ArrayListUnmanaged(IncrementalSnapshotFileInfo) = .{};
        defer incremental_snapshots.deinit(allocator);

        var maybe_latest_full: ?FullSnapshotFileInfo = null;

        var dir_iter = search_dir.iterate();
        while (try dir_iter.next()) |dir_entry| {
            if (dir_entry.kind != .file) continue;
            const filename = dir_entry.name;

            if (IncrementalSnapshotFileInfo.parseFileNameTarZst(filename)) |_incremental| {
                if (maybe_latest_full) |latest_full| {
                    if (_incremental.slot < latest_full.slot) continue;
                    if (_incremental.base_slot < latest_full.slot) continue;
                }
                try incremental_snapshots.append(allocator, _incremental);
                continue;
            } else |_| {}

            const full = FullSnapshotFileInfo.parseFileNameTarZst(filename) catch continue;
            const latest_full = maybe_latest_full orelse {
                maybe_latest_full = full;
                continue;
            };
            if (latest_full.slot < full.slot) {
                maybe_latest_full = full;
                continue;
            }
            if (latest_full.slot == full.slot) {
                // TODO:
                std.debug.panic("TODO: report this error gracefully in some way ({s} vs {s})", .{
                    latest_full.snapshotArchiveName().constSlice(),
                    full.snapshotArchiveName().constSlice(),
                });
            }
        }
        const latest_full = maybe_latest_full orelse return error.NoFullSnapshotFileInfoFound;

        var maybe_latest_incremental: ?IncrementalSnapshotFileInfo = null;
        for (incremental_snapshots.items) |_incremental| {
            if (_incremental.base_slot != latest_full.slot) continue;
            const latest_incremental = maybe_latest_incremental orelse {
                maybe_latest_incremental = _incremental;
                continue;
            };
            if (latest_incremental.slot < _incremental.slot) {
                maybe_latest_incremental = _incremental;
                continue;
            }
            if (latest_incremental.slot == _incremental.slot) {
                // TODO: if they have the same slot, that means they have different hashes, despite it being
                // impossible for a given slot range to possess two different hashes; we have no way at this
                // stage to unambiguously decide which of the two snapshots we want to select, since either
                // could be valid. For now, we panic, but we should gracefully report this in some way.
                std.debug.panic("TODO: report this error gracefully in some way ({s} vs {s})", .{
                    latest_incremental.snapshotArchiveName().constSlice(),
                    _incremental.snapshotArchiveName().constSlice(),
                });
            }
        }

        return fromFileInfos(
            latest_full,
            maybe_latest_incremental,
        );
    }
};

/// Represents the full manifest optionally combined with an incremental manifest.
///
/// Analogous to [SnapshotBankFields](https://github.com/anza-xyz/agave/blob/2de7b565e8b1101824a5e3bac74f3a8cce88ea72/runtime/src/serde_snapshot.rs#L299)
pub const FullAndIncrementalManifest = struct {
    full: Manifest,
    incremental: ?Manifest,
    was_collapsed: bool = false, // used for deinit()

    pub fn fromFiles(
        allocator: std.mem.Allocator,
        unscoped_logger: Logger,
        snapshot_dir: std.fs.Dir,
        files: SnapshotFiles,
    ) !FullAndIncrementalManifest {
        const logger = unscoped_logger.withScope(@typeName(@This()));

        const full_fields = blk: {
            const rel_path_bounded = sig.utils.fmt.boundedFmt("snapshots/{0}/{0}", .{files.full.slot});
            const rel_path = rel_path_bounded.constSlice();

            logger.info().logf("reading snapshot fields from: {s}", .{sig.utils.fmt.tryRealPath(snapshot_dir, rel_path)});

            const full_file = try snapshot_dir.openFile(rel_path, .{});
            defer full_file.close();

            break :blk try Manifest.readFromFile(allocator, full_file);
        };
        errdefer full_fields.deinit(allocator);

        const incremental_fields = if (files.incremental_info) |inc_snap| blk: {
            const rel_path_bounded = sig.utils.fmt.boundedFmt("snapshots/{0}/{0}", .{inc_snap.slot});
            const rel_path = rel_path_bounded.constSlice();

            logger.info().logf("reading incremental snapshot manifest from: {s}", .{sig.utils.fmt.tryRealPath(snapshot_dir, rel_path)});

            const incremental_file = try snapshot_dir.openFile(rel_path, .{});
            defer incremental_file.close();

            break :blk try Manifest.readFromFile(allocator, incremental_file);
        } else blk: {
            logger.info().log("no incremental snapshot fields found");
            break :blk null;
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
    pub fn collapse(
        self: *FullAndIncrementalManifest,
        /// Should be the same allocator passed to `fromFiles`, or otherwise to allocate `Self`.
        allocator: std.mem.Allocator,
    ) !Manifest {
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
        var slots_to_remove = std.ArrayList(Slot).init(allocator);
        defer slots_to_remove.deinit();

        // make sure theres no overlap in slots between full and incremental and combine
        var storages_entry_iter = storages_map.iterator();
        while (storages_entry_iter.next()) |incremental_entry| {
            const slot = incremental_entry.key_ptr.*;

            // only keep slots > full snapshot slot
            if (!(slot > full_slot)) {
                try slots_to_remove.append(slot);
                continue;
            }

            const slot_entry = try self.full.accounts_db_fields.file_map.getOrPut(allocator, slot);
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

    pub fn deinit(self: *FullAndIncrementalManifest, allocator: std.mem.Allocator) void {
        self.full.deinit(allocator);
        if (self.incremental) |*inc| {
            if (!self.was_collapsed) {
                inc.deinit(allocator);
            } else {
                inc.accounts_db_fields.file_map.deinit(allocator);
                inc.bank_fields.deinit(allocator);
                allocator.free(inc.accounts_db_fields.rooted_slots);
                allocator.free(inc.accounts_db_fields.rooted_slot_hashes);
                inc.bank_extra.deinit(allocator);
            }
        }
    }
};

pub const generate = struct {
    /// Writes the version, status cache, and manifest files.
    /// Should call this first to begin generating the snapshot archive.
    pub fn writeMetadataFiles(
        archive_writer: anytype,
        version: sig.version.ClientVersion,
        status_cache: StatusCache,
        manifest: *const Manifest,
    ) !void {
        const slot: Slot = manifest.bank_fields.slot;

        var counting_writer_state = std.io.countingWriter(archive_writer);
        const writer = counting_writer_state.writer();

        // write the version file
        const version_str_bounded = sig.utils.fmt.boundedFmt("{d}.{d}.{d}", .{ version.major, version.minor, version.patch });
        const version_str = version_str_bounded.constSlice();
        try sig.utils.tar.writeTarHeader(writer, .regular, "version", version_str.len);
        try writer.writeAll(version_str);
        try writer.writeByteNTimes(0, sig.utils.tar.paddingBytes(counting_writer_state.bytes_written));

        // create the snapshots dir
        try sig.utils.tar.writeTarHeader(writer, .directory, "snapshots/", 0);

        // write the status cache
        try sig.utils.tar.writeTarHeader(writer, .regular, "snapshots/status_cache", bincode.sizeOf(status_cache, .{}));
        try bincode.write(writer, status_cache, .{});
        try writer.writeByteNTimes(0, sig.utils.tar.paddingBytes(counting_writer_state.bytes_written));

        // write the manifest
        const dir_name_bounded = sig.utils.fmt.boundedFmt("snapshots/{d}/", .{slot});
        try sig.utils.tar.writeTarHeader(writer, .directory, dir_name_bounded.constSlice(), 0);

        const file_name_bounded = sig.utils.fmt.boundedFmt("snapshots/{0d}/{0d}", .{slot});
        try sig.utils.tar.writeTarHeader(writer, .regular, file_name_bounded.constSlice(), bincode.sizeOf(manifest, .{}));
        try bincode.write(writer, manifest, .{});
        try writer.writeByteNTimes(0, sig.utils.tar.paddingBytes(counting_writer_state.bytes_written));

        std.debug.assert(counting_writer_state.bytes_written % 512 == 0);
    }

    /// Writes the accounts dir header. Do this after writing the metadata files.
    pub fn writeAccountsDirHeader(archive_writer: anytype) !void {
        try sig.utils.tar.writeTarHeader(archive_writer, .directory, "accounts/", 0);
    }

    /// Writes the account file header - follow this up by writing the file content to `archive_writer`,
    /// and then follow that up with `writeAccountFilePadding(archive_writer, file_info.length)`.
    /// Do this for each account file included in the snapshot.
    pub fn writeAccountFileHeader(archive_writer: anytype, file_slot: Slot, file_info: AccountFileInfo) !void {
        const name_bounded = sig.utils.fmt.boundedFmt("accounts/{d}.{d}", .{ file_slot, file_info.id.toInt() });
        try sig.utils.tar.writeTarHeader(archive_writer, .regular, name_bounded.constSlice(), file_info.length);
    }

    pub fn writeAccountFilePadding(archive_writer: anytype, file_length: usize) !void {
        try archive_writer.writeByteNTimes(0, sig.utils.tar.paddingBytes(file_length));
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
    const file_size = (try file.stat()).size;

    // TODO: improve `zstd.Reader` to be capable of sourcing a stream of bytes
    // rather than a fixed slice of bytes, so we don't have to load the entire
    // snapshot file into memory.
    const file_data = try allocator.alloc(u8, file_size);
    defer allocator.free(file_data);
    if (try file.readAll(file_data) != file_size) {
        return error.UnexpectedEOF; // has the file shrunk since we got its size?
    }
    var tar_stream = try zstd.Reader.init(file_data);
    defer tar_stream.deinit();
    const n_files_estimate: usize = if (full_snapshot) 421_764 else 100_000; // estimate

    try sig.utils.tar.parallelUntarToFileSystem(
        allocator,
        logger,
        output_dir,
        tar_stream.reader(),
        n_threads,
        n_files_estimate,
    );
}

test FullSnapshotFileInfo {
    try std.testing.expectEqualStrings(
        "snapshot-10-11111111111111111111111111111111.tar.zst",
        FullSnapshotFileInfo.snapshotArchiveName(.{ .slot = 10, .hash = Hash.ZEROES }).constSlice(),
    );

    const snapshot_name = "snapshot-269-EAHHZCVccCdAoCXH8RWxvv9edcwjY2boqni9MJuh3TCn.tar.zst";
    const snapshot_info = try FullSnapshotFileInfo.parseFileNameTarZst(snapshot_name);

    try std.testing.expectEqual(269, snapshot_info.slot);
    try std.testing.expectEqualStrings("EAHHZCVccCdAoCXH8RWxvv9edcwjY2boqni9MJuh3TCn", snapshot_info.hash.base58String().constSlice());

    try std.testing.expectEqualStrings(snapshot_name, snapshot_info.snapshotArchiveName().constSlice());
}

test IncrementalSnapshotFileInfo {
    try std.testing.expectEqualStrings(
        "incremental-snapshot-10-25-11111111111111111111111111111111.tar.zst",
        IncrementalSnapshotFileInfo.snapshotArchiveName(.{ .base_slot = 10, .slot = 25, .hash = Hash.ZEROES }).constSlice(),
    );

    const snapshot_name = "incremental-snapshot-269-307-4JLFzdaaqkSrmHs55bBDhZrQjHYZvqU1vCcQ5mP22pdB.tar.zst";
    const snapshot_info = try IncrementalSnapshotFileInfo.parseFileNameTarZst(snapshot_name);

    try std.testing.expectEqual(269, snapshot_info.base_slot);
    try std.testing.expectEqual(307, snapshot_info.slot);
    try std.testing.expectEqualStrings("4JLFzdaaqkSrmHs55bBDhZrQjHYZvqU1vCcQ5mP22pdB", snapshot_info.hash.base58String().constSlice());

    try std.testing.expectEqualStrings(snapshot_name, snapshot_info.snapshotArchiveName().constSlice());
}

test "parse status cache" {
    const allocator = std.testing.allocator;

    var tmp_dir_root = std.testing.tmpDir(.{});
    defer tmp_dir_root.cleanup();
    const snapdir = tmp_dir_root.dir;

    _ = try sig.accounts_db.db.findAndUnpackTestSnapshots(1, snapdir);

    const status_cache_file = try snapdir.openFile("snapshots/status_cache", .{});
    defer status_cache_file.close();

    const status_cache = try StatusCache.readFromFile(allocator, status_cache_file);
    defer status_cache.deinit(allocator);

    try std.testing.expect(status_cache.bank_slot_deltas.len > 0);
}

test "parse snapshot fields" {
    const allocator = std.testing.allocator;

    var tmp_dir_root = std.testing.tmpDir(.{});
    defer tmp_dir_root.cleanup();
    const snapdir = tmp_dir_root.dir;

    const snapshot_files = try sig.accounts_db.db.findAndUnpackTestSnapshots(1, snapdir);

    const full_slot = snapshot_files.full.slot;
    const full_manifest_path_bounded = sig.utils.fmt.boundedFmt("snapshots/{0}/{0}", .{full_slot});
    const full_manifest_path = full_manifest_path_bounded.constSlice();

    const full_manifest_file = try snapdir.openFile(full_manifest_path, .{});
    defer full_manifest_file.close();

    const snapshot_fields_full = try Manifest.readFromFile(allocator, full_manifest_file);
    defer snapshot_fields_full.deinit(allocator);

    if (snapshot_files.incremental_info) |inc| {
        const inc_slot = inc.slot;
        const inc_manifest_path_bounded = sig.utils.fmt.boundedFmt("snapshots/{0}/{0}", .{inc_slot});
        const inc_manifest_path = inc_manifest_path_bounded.constSlice();

        const inc_manifest_file = try snapdir.openFile(inc_manifest_path, .{});
        defer inc_manifest_file.close();

        const snapshot_fields_inc = try Manifest.readFromFile(allocator, inc_manifest_file);
        defer snapshot_fields_inc.deinit(allocator);
    }
}
