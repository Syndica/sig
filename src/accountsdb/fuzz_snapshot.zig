const std = @import("std");

const sig = @import("../lib.zig");

const bincode = sig.bincode;

const Slot = sig.core.Slot;
const Epoch = sig.core.Epoch;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Account = sig.core.Account;

const RwMux = sig.sync.RwMux;

const SnapshotFields = sig.accounts_db.SnapshotFields;

const EpochSchedule = sig.accounts_db.genesis_config.EpochSchedule;

const FileId = sig.accounts_db.accounts_file.FileId;
const AccountFile = sig.accounts_db.accounts_file.AccountFile;

const AccountsDbFields = sig.accounts_db.snapshots.AccountsDbFields;
const BankFields = sig.accounts_db.snapshots.BankFields;
const StatusCache = sig.accounts_db.snapshots.StatusCache;
const AccountFileInfo = sig.accounts_db.snapshots.AccountFileInfo;
const FileMap = sig.accounts_db.index;
const HashAge = sig.accounts_db.snapshots.HashAge;
const Ancestors = sig.accounts_db.snapshots.Ancestors;
const HardForks = sig.accounts_db.snapshots.HardForks;
const VoteAccounts = sig.accounts_db.snapshots.VoteAccounts;
const VoteAccount = sig.accounts_db.snapshots.VoteAccount;
const Delegation = sig.accounts_db.snapshots.Delegation;
const Stakes = sig.accounts_db.snapshots.Stakes;
const StakeHistory = sig.accounts_db.snapshots.StakeHistory;
const StakeHistoryEntry = sig.accounts_db.snapshots.StakeHistoryEntry;
const UnusedAccounts = sig.accounts_db.snapshots.UnusedAccounts;
const EpochStakes = sig.accounts_db.snapshots.EpochStakes;
const NodeVoteAccounts = sig.accounts_db.snapshots.NodeVoteAccounts;
const EpochRewardStatus = sig.accounts_db.snapshots.EpochRewardStatus;
const StakeReward = sig.accounts_db.snapshots.StakeReward;

const MAX_FUZZ_TIME_NS = std.time.ns_per_s * 100_000;

pub fn run(args: *std.process.ArgIterator) !void {
    _ = args;
    const seed = std.crypto.random.int(u64);

    var gpa_state: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    {
        // open and append seed
        const SEED_FILE_PATH = "test_data/fuzz_snapshot_seeds.txt";
        const seed_file = try std.fs.cwd().createFile(SEED_FILE_PATH, .{ .truncate = false });
        defer seed_file.close();
        // try seed_file.seekFromEnd(0);
        try seed_file.writer().print("{}\n", .{seed});
    }
    std.debug.print("seed: {}\n", .{seed});

    var prng = std.rand.DefaultPrng.init(seed);
    const rand = prng.random();

    var bytes_buffer = std.ArrayList(u8).init(gpa);
    defer bytes_buffer.deinit();

    var i: u64 = 0;

    var timer = try std.time.Timer.start();
    while (timer.read() < MAX_FUZZ_TIME_NS) : (i += 1) {
        bytes_buffer.clearRetainingCapacity();

        const snapshot_original: SnapshotFields = try randomSnapshotFields(gpa, rand);
        defer snapshot_original.deinit(gpa);

        try bytes_buffer.ensureUnusedCapacity(bincode.sizeOf(snapshot_original, .{}) * 2);

        const original_bytes_start = bytes_buffer.items.len;
        try bincode.write(bytes_buffer.writer(), snapshot_original, .{});
        const original_bytes_end = bytes_buffer.items.len;

        const snapshot_deserialized = try bincode.readFromSlice(gpa, SnapshotFields, bytes_buffer.items[original_bytes_start..original_bytes_end], .{});
        defer snapshot_deserialized.deinit(gpa);

        const serialized_bytes_start = bytes_buffer.items.len;
        try bincode.write(bytes_buffer.writer(), snapshot_deserialized, .{});
        const serialized_bytes_end = bytes_buffer.items.len;

        const original_bytes = bytes_buffer.items[original_bytes_start..original_bytes_end];
        const serialized_bytes = bytes_buffer.items[serialized_bytes_start..serialized_bytes_end];
        try std.testing.expectEqualSlices(u8, original_bytes, serialized_bytes);
        std.debug.print("Verified {d} snapshots\n", .{i});
    }
}

const max_list_entries = 1 << 8;

fn randomSnapshotFields(
    allocator: std.mem.Allocator,
    /// Should be a PRNG, not a true RNG. See the documentation on `std.Random.uintLessThan`
    /// for commentary on the runtime of this function.
    rand: std.Random,
) !SnapshotFields {
    const bank_fields = try randomBankFields(allocator, rand);
    errdefer bank_fields.deinit(allocator);

    const accounts_db_fields = try randomAccountsDbFields(allocator, rand, .{});
    errdefer accounts_db_fields.deinit(allocator);

    const epoch_reward_status: ?EpochRewardStatus = if (rand.boolean()) null else switch (rand.enumValue(@typeInfo(EpochRewardStatus).Union.tag_type.?)) {
        .Active => .{ .Active = .{
            .parent_start_block_height = rand.int(u64),
            .calculated_epoch_stake_rewards = blk: {
                const stake_rewards = try allocator.alloc(StakeReward, rand.uintLessThan(usize, max_list_entries));
                errdefer allocator.free(stake_rewards);
                errdefer for (stake_rewards) |*reward| {
                    reward.stake_account.deinit(allocator);
                };
                for (stake_rewards) |*rewards| {
                    rewards.* = .{
                        .stake_pubkey = Pubkey.random(rand),
                        .stake_reward_info = .{
                            .reward_type = rand.enumValue(sig.accounts_db.snapshots.RewardType),
                            .lamports = rand.int(i64),
                            .post_balance = rand.int(u64),
                            .commission = if (rand.boolean()) rand.int(u8) else null,
                        },
                        .stake_account = try randomAccount(allocator, rand),
                    };
                }
                break :blk std.ArrayList(StakeReward).fromOwnedSlice(allocator, stake_rewards);
            },
        } },
        .Inactive => .Inactive,
    };
    errdefer comptime unreachable;

    return .{
        .bank_fields = bank_fields,
        .accounts_db_fields = accounts_db_fields,
        .lamports_per_signature = rand.int(u64),
        .bank_fields_inc = .{
            .snapshot_persistence = if (rand.boolean()) null else .{
                .full_slot = rand.int(Slot),
                .full_hash = Hash.random(rand),
                .full_capitalization = rand.int(u64),
                .incremental_hash = Hash.random(rand),
                .incremental_capitalization = rand.int(u64),
            },
            .epoch_accounts_hash = if (rand.boolean()) null else Hash.random(rand),
            .epoch_reward_status = epoch_reward_status,
        },
    };
}

fn randomBankFields(
    allocator: std.mem.Allocator,
    /// Should be a PRNG, not a true RNG. See the documentation on `std.Random.uintLessThan`
    /// for commentary on the runtime of this function.
    rand: std.Random,
) std.mem.Allocator.Error!BankFields {
    var blockash_queue_ages = std.AutoArrayHashMap(Hash, HashAge).init(allocator);
    errdefer blockash_queue_ages.deinit();

    try fillHashmapWithRng(&blockash_queue_ages, rand, 0, max_list_entries, struct {
        pub fn randomKey(_rand: std.Random) Hash {
            return Hash.random(_rand);
        }
        pub fn randomValue(_rand: std.Random) !HashAge {
            return .{
                .fee_calculator = .{ .lamports_per_signature = _rand.int(u64) },
                .hash_index = _rand.int(u64),
                .timestamp = _rand.int(u64),
            };
        }
    });

    var ancestors = Ancestors.init(allocator);
    errdefer ancestors.deinit();

    try fillHashmapWithRng(&ancestors, rand, 0, max_list_entries, struct {
        pub fn randomKey(_rand: std.Random) Slot {
            return _rand.int(Slot);
        }
        pub fn randomValue(_rand: std.Random) !usize {
            return _rand.int(usize);
        }
    });

    const HardFork = HardForks.Entry;
    const hard_forks: []HardFork = blk: {
        const hard_forks_len = rand.uintAtMost(usize, max_list_entries);

        const hard_forks = try allocator.alloc(HardFork, hard_forks_len);
        errdefer allocator.free(hard_forks);

        for (hard_forks) |*hard_fork| hard_fork.* = .{
            rand.int(Slot),
            rand.int(usize),
        };

        break :blk hard_forks;
    };
    errdefer allocator.free(hard_forks);

    const slots_per_year: f64 = @floatFromInt(rand.int(u32));

    var stakes: Stakes = try randomStakes(allocator, rand);
    errdefer stakes.deinit(allocator);

    var unused_accounts: UnusedAccounts = .{
        .unused1 = std.AutoArrayHashMap(Pubkey, void).init(allocator),
        .unused2 = std.AutoArrayHashMap(Pubkey, void).init(allocator),
        .unused3 = std.AutoArrayHashMap(Pubkey, u64).init(allocator),
    };
    errdefer {
        unused_accounts.unused1.deinit();
        unused_accounts.unused2.deinit();
        unused_accounts.unused3.deinit();
    }

    inline for (@typeInfo(UnusedAccounts).Struct.fields) |field| {
        const ptr = &@field(unused_accounts, field.name);
        const hm_info = sig.utils.types.hashMapInfo(field.type).?;
        try fillHashmapWithRng(ptr, rand, 0, max_list_entries, struct {
            pub fn randomKey(_rand: std.Random) Pubkey {
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

    var epoch_stakes = std.AutoArrayHashMap(Epoch, EpochStakes).init(allocator);
    errdefer epoch_stakes.deinit();
    errdefer for (epoch_stakes.values()) |*epoch_stake| {
        epoch_stake.stakes.deinit(allocator);

        for (epoch_stake.node_id_to_vote_accounts.values()) |*node_vote_accounts| {
            node_vote_accounts.vote_accounts.deinit();
        }
        epoch_stake.node_id_to_vote_accounts.deinit();

        epoch_stake.epoch_authorized_voters.deinit();
    };

    try fillHashmapWithRng(&epoch_stakes, rand, 0, max_list_entries, struct {
        allocator: std.mem.Allocator,

        pub fn randomKey(_: @This(), _rand: std.Random) Epoch {
            return _rand.int(Epoch);
        }

        pub fn randomValue(ctx: @This(), _rand: std.Random) !EpochStakes {
            return try randomEpochStakes(ctx.allocator, _rand);
        }
    }{ .allocator = allocator });

    return .{
        .blockhash_queue = .{
            .last_hash_index = rand.int(u64),

            .last_hash = if (rand.boolean()) Hash.random(rand) else null,
            .ages = blockash_queue_ages,

            .max_age = rand.int(usize),
        },
        .ancestors = ancestors,
        .hash = Hash.random(rand),
        .parent_hash = Hash.random(rand),
        .parent_slot = rand.int(Slot),
        .hard_forks = .{ .hard_forks = std.ArrayList(HardFork).fromOwnedSlice(allocator, hard_forks) },
        .transaction_count = rand.int(u64),
        .tick_height = rand.int(u64),
        .signature_count = rand.int(u64),
        .capitalization = rand.int(u64),
        .max_tick_height = rand.int(u64),
        .hashes_per_tick = if (rand.boolean()) rand.int(u64) else null,
        .ticks_per_slot = rand.int(u64),
        .ns_per_slot = rand.int(u128),
        .genesis_creation_time = rand.int(sig.accounts_db.genesis_config.UnixTimestamp),
        .slots_per_year = slots_per_year,
        .accounts_data_len = rand.int(u64),
        .slot = rand.int(Slot),
        .epoch = rand.int(Epoch),
        .block_height = rand.int(u64),
        .collector_id = Pubkey.random(rand),
        .collector_fees = rand.int(u64),
        .fee_calculator = .{ .lamports_per_signature = rand.int(u64) },
        .fee_rate_governor = .{
            .lamports_per_signature = rand.int(u64),

            .target_lamports_per_signature = rand.int(u64),

            .target_signatures_per_slot = rand.int(u64),

            .min_lamports_per_signature = rand.int(u64),
            .max_lamports_per_signature = rand.int(u64),

            .burn_percent = rand.uintAtMost(u8, 100),
        },
        .collected_rent = rand.int(u64),
        .rent_collector = .{
            .epoch = rand.int(Epoch),
            .epoch_schedule = randomEpochSchedule(rand),
            .slots_per_year = slots_per_year,
            .rent = .{
                .lamports_per_byte_year = rand.int(u64),

                .exemption_threshold = @floatFromInt(rand.int(u32)),

                .burn_percent = rand.uintAtMost(u8, 100),
            },
        },
        .epoch_schedule = randomEpochSchedule(rand),
        .inflation = .{
            .initial = @floatFromInt(rand.int(u32)),

            .terminal = @floatFromInt(rand.int(u32)),

            .taper = @floatFromInt(rand.int(u32)),

            .foundation = @floatFromInt(rand.int(u32)),
            .foundation_term = @floatFromInt(rand.int(u32)),

            .__unused = @floatFromInt(rand.int(u32)),
        },
        .stakes = stakes,
        .unused_accounts = unused_accounts,
        .epoch_stakes = epoch_stakes,
        .is_delta = rand.boolean(),
    };
}

fn randomEpochSchedule(rand: std.Random) EpochSchedule {
    return .{
        .slots_per_epoch = rand.int(u64),
        .leader_schedule_slot_offset = rand.int(u64),
        .warmup = rand.boolean(),
        .first_normal_epoch = rand.int(Epoch),
        .first_normal_slot = rand.int(Slot),
    };
}

fn randomEpochStakes(allocator: std.mem.Allocator, rand: std.Random) !EpochStakes {
    var result_stakes = try randomStakes(allocator, rand);
    errdefer result_stakes.deinit(allocator);

    var node_id_to_vote_accounts = std.AutoArrayHashMap(Pubkey, NodeVoteAccounts).init(allocator);
    errdefer node_id_to_vote_accounts.deinit();
    errdefer for (node_id_to_vote_accounts.values()) |*node_vote_accounts| {
        node_vote_accounts.vote_accounts.deinit();
    };

    try fillHashmapWithRng(&node_id_to_vote_accounts, rand, 0, max_list_entries, struct {
        allocator: std.mem.Allocator,

        pub fn randomKey(_: @This(), _rand: std.Random) Pubkey {
            return Pubkey.random(_rand);
        }

        pub fn randomValue(ctx: @This(), _rand: std.Random) !NodeVoteAccounts {
            const vote_accounts = try ctx.allocator.alloc(Pubkey, _rand.uintLessThan(usize, max_list_entries));
            errdefer ctx.allocator.free(vote_accounts);
            for (vote_accounts) |*vote_account| vote_account.* = Pubkey.random(_rand);
            return .{
                .vote_accounts = std.ArrayList(Pubkey).fromOwnedSlice(ctx.allocator, vote_accounts),
                .total_stake = _rand.int(u64),
            };
        }
    }{ .allocator = allocator });

    var epoch_authorized_voters = std.AutoArrayHashMap(Pubkey, Pubkey).init(allocator);
    errdefer epoch_authorized_voters.deinit();

    return .{
        .stakes = result_stakes,
        .total_stake = rand.int(u64),
        .node_id_to_vote_accounts = node_id_to_vote_accounts,
        .epoch_authorized_voters = epoch_authorized_voters,
    };
}

fn randomAccount(
    allocator: std.mem.Allocator,
    rand: std.Random,
) !Account {
    const data = try allocator.alloc(u8, rand.uintAtMost(usize, max_list_entries));
    errdefer allocator.free(data);
    rand.bytes(data);
    return .{
        .lamports = rand.int(u64),
        .data = data,
        .owner = Pubkey.random(rand),
        .executable = rand.boolean(),
        .rent_epoch = rand.int(Epoch),
    };
}

fn randomStakes(
    allocator: std.mem.Allocator,
    rand: std.Random,
) !Stakes {
    var stakes_vote_accounts = std.AutoArrayHashMap(Pubkey, VoteAccounts.Entry).init(allocator);
    errdefer stakes_vote_accounts.deinit();

    errdefer for (stakes_vote_accounts.values()) |pair| {
        _, const vote_account = pair;
        allocator.free(vote_account.account.data);
    };

    try fillHashmapWithRng(&stakes_vote_accounts, rand, 0, max_list_entries, struct {
        allocator: std.mem.Allocator,

        pub fn randomKey(_: @This(), _rand: std.Random) Pubkey {
            return Pubkey.random(_rand);
        }
        pub fn randomValue(ctx: @This(), _rand: std.Random) !struct { u64, VoteAccount } {
            return .{
                _rand.int(u64),
                VoteAccount{
                    .account = try randomAccount(ctx.allocator, _rand),
                    .vote_state = switch (_rand.enumValue(enum { null, err, value })) {
                        .null => null,
                        .err => error.RandomError,
                        .value => .{
                            .tag = _rand.int(u32),
                            .node_pubkey = Pubkey.random(_rand),
                        },
                    },
                },
            };
        }
    }{ .allocator = allocator });

    var stakes_maybe_staked_nodes = if (rand.boolean()) std.AutoArrayHashMap(Pubkey, u64).init(allocator) else null;
    errdefer if (stakes_maybe_staked_nodes) |*staked_nodes| staked_nodes.deinit();

    if (stakes_maybe_staked_nodes) |*staked_nodes| try fillHashmapWithRng(staked_nodes, rand, 0, max_list_entries, struct {
        pub fn randomKey(_rand: std.Random) Pubkey {
            return Pubkey.random(_rand);
        }
        pub fn randomValue(_rand: std.Random) !u64 {
            return _rand.int(u64);
        }
    });

    var stake_delegations = std.AutoArrayHashMap(Pubkey, Delegation).init(allocator);
    errdefer stake_delegations.deinit();

    try fillHashmapWithRng(&stake_delegations, rand, 0, max_list_entries, struct {
        pub fn randomKey(_rand: std.Random) Pubkey {
            return Pubkey.random(_rand);
        }
        pub fn randomValue(_rand: std.Random) !Delegation {
            return .{
                .voter_pubkey = Pubkey.random(_rand),
                .stake = _rand.int(u64),
                .activation_epoch = _rand.int(Epoch),
                .deactivation_epoch = _rand.int(Epoch),
                .warmup_cooldown_rate = @floatFromInt(_rand.int(u32)),
            };
        }
    });

    const StakeHistoryItem = struct { Epoch, StakeHistoryEntry };
    const stake_history_len = rand.uintAtMost(usize, max_list_entries);

    const stake_history = try allocator.alloc(StakeHistoryItem, stake_history_len);
    errdefer allocator.free(stake_history);

    for (stake_history) |*entry| entry.* = .{
        rand.int(Epoch),
        .{
            .effective = rand.int(u64),
            .activating = rand.int(u64),
            .deactivating = rand.int(u64),
        },
    };

    return .{
        .vote_accounts = .{
            .vote_accounts = stakes_vote_accounts,
            .staked_nodes = stakes_maybe_staked_nodes,
        },

        .stake_delegations = stake_delegations,
        .unused = rand.int(u64),
        .epoch = rand.int(Epoch),
        .stake_history = StakeHistory.fromOwnedSlice(allocator, stake_history),
    };
}

const AccountsDbFieldsRandomConfig = struct {
    slot: struct { min: Slot, max: Slot } = .{
        .min = 0,
        .max = std.math.maxInt(Slot),
    },

    file_id: struct { min: FileId, max: FileId } = .{
        .min = FileId.fromInt(0),
        .max = FileId.fromInt(std.math.maxInt(FileId.Int)),
    },

    file_map_len: struct { min: usize, max: usize } = .{
        .min = 1,
        .max = 4096 * 8,
    },

    file_len: struct { min: usize, max: usize } = .{
        .min = 0,
        .max = 4096 * 4,
    },

    stored_meta_write_version_max: u64 = 0,
};

fn randomAccountsDbFields(
    allocator: std.mem.Allocator,
    /// Should be a PRNG, not a true RNG. See the documentation on `std.Random.uintLessThan`
    /// for commentary on the runtime of this function.
    rand: std.Random,
    params: AccountsDbFieldsRandomConfig,
) std.mem.Allocator.Error!AccountsDbFields {
    std.debug.assert(params.file_map_len.min >= 1);

    const FileIdAdapter = struct {
        file_map: *const AccountsDbFields.FileMap,

        pub fn hash(_: @This(), key: FileId) u32 {
            return key.toInt();
        }

        pub fn eql(ctx: @This(), a: FileId, _: void, b_index: usize) bool {
            const b = ctx.file_map.values()[b_index].id;
            return a == b;
        }
    };

    var total_data_len: u64 = 0;
    var max_slot: Slot = 0;

    const file_map_len = rand.intRangeAtMost(usize, params.file_map_len.min, params.file_map_len.max);

    var file_map = AccountsDbFields.FileMap.init(allocator);
    errdefer file_map.deinit();
    try file_map.ensureTotalCapacity(file_map_len);

    var file_id_set = std.AutoArrayHashMap(void, void).init(allocator);
    defer file_id_set.deinit();
    try file_id_set.ensureTotalCapacity(file_map_len);

    for (0..file_map_len) |_| while (true) {
        const new_slot = rand.intRangeAtMost(Slot, params.slot.min, params.slot.max);
        const slot_gop = file_map.getOrPutAssumeCapacity(new_slot);
        if (slot_gop.found_existing) continue;

        const new_id: FileId = while (true) {
            const new_id = FileId.fromInt(rand.intRangeAtMost(FileId.Int, params.file_id.min.toInt(), params.file_id.max.toInt()));
            const id_gop = file_id_set.getOrPutAssumeCapacityAdapted(new_id, FileIdAdapter{
                .file_map = &file_map,
            });
            if (id_gop.found_existing) continue;
            break new_id;
        };

        const account_file_info: AccountFileInfo = .{
            .id = new_id,
            .length = rand.intRangeAtMost(usize, params.file_len.min, @min(std.math.maxInt(u64) - total_data_len, params.file_len.max)),
        };
        slot_gop.value_ptr.* = account_file_info;
        max_slot = @max(max_slot, new_slot);
        total_data_len += account_file_info.length;
        break;
    };

    return .{
        .file_map = file_map,

        .stored_meta_write_version = rand.uintAtMost(u64, params.stored_meta_write_version_max),

        .slot = max_slot,

        .bank_hash_info = .{
            .accounts_delta_hash = Hash.random(rand),
            .accounts_hash = Hash.random(rand),
            .stats = .{
                .num_updated_accounts = rand.intRangeAtMost(u64, params.file_map_len.min, params.file_map_len.max),
                .num_removed_accounts = rand.intRangeAtMost(u64, params.file_map_len.min, params.file_map_len.max),
                .num_lamports_stored = rand.int(u64),
                .total_data_len = total_data_len,
                .num_executable_accounts = rand.intRangeAtMost(u64, params.file_map_len.min, params.file_map_len.max),
            },
        },

        // NOTE: see field comment about these always being empty
        .rooted_slots = .{},
        .rooted_slot_hashes = .{},
    };
}

fn fillHashmapWithRng(
    hashmap: anytype,
    rand: std.Random,
    min_len: usize,
    max_len: usize,
    context: anytype,
) !void {
    const Hm = @TypeOf(hashmap.*);
    const hm_info = sig.utils.types.hashMapInfo(Hm).?;
    const hm_len = rand.intRangeAtMost(if (hm_info.kind == .array) usize else Hm.Size, min_len, max_len);

    hashmap.clearRetainingCapacity();
    try hashmap.ensureTotalCapacity(hm_len);

    for (0..hm_len) |_| while (true) {
        const new_key: hm_info.Key = context.randomKey(rand);
        const gop = hashmap.getOrPutAssumeCapacity(new_key);
        if (gop.found_existing) continue;
        gop.value_ptr.* = try context.randomValue(rand);
        break;
    };
}
