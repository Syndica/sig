const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../sig.zig");

const bincode = sig.bincode;
const sysvar = sig.runtime.sysvar;

const Pubkey = sig.core.Pubkey;
const Hash = sig.core.Hash;
const Slot = sig.core.Slot;
const EpochStakes = sig.core.stake.EpochStakes;

const FeatureSet = sig.runtime.FeatureSet;
const InstructionInfo = sig.runtime.InstructionInfo;
const LogCollector = sig.runtime.LogCollector;
const SysvarCache = sig.runtime.SysvarCache;
const TransactionContext = sig.runtime.TransactionContext;
const TransactionContextAccount = sig.runtime.TransactionContextAccount;
const TransactionReturnData = sig.runtime.transaction_context.TransactionReturnData;
const Rent = sig.runtime.sysvar.Rent;
const ComputeBudget = sig.runtime.ComputeBudget;

pub const ExecuteContextsParams = struct {
    // If a user requires a mutable reference to the created feature set, they should
    // allocate it themselves and pass it in the params. Deinitialization is handled
    // by deinitTransactionContext.
    feature_set_ptr: ?*FeatureSet = null,
    feature_set: []const FeatureParams = &.{},
    epoch_stakes: []const EpochStakeParam = &.{},

    // Slot Context
    sysvar_cache: SysvarCacheParams = .{},

    // Transaction Context
    accounts: []const AccountParams = &.{},
    return_data: ReturnDataParams = .{},
    accounts_resize_delta: i64 = 0,
    compute_meter: u64 = 0,
    compute_budget: ComputeBudget = ComputeBudget.default(1_400_000),
    custom_error: ?u32 = null,
    log_collector: ?LogCollector = null,
    prev_blockhash: Hash = Hash.ZEROES,
    prev_lamports_per_signature: u64 = 0,

    pub const FeatureParams = struct {
        pubkey: Pubkey,
        slot: Slot = 0,
    };

    pub const EpochStakeParam = struct {
        pubkey: Pubkey,
        stake: u64,
    };

    pub const SysvarCacheParams = struct {
        clock: ?sysvar.Clock = null,
        epoch_schedule: ?sig.core.EpochSchedule = null,
        epoch_rewards: ?sysvar.EpochRewards = null,
        rent: ?sysvar.Rent = null,
        last_restart_slot: ?sysvar.LastRestartSlot = null,
        slot_hashes: ?sysvar.SlotHashes = null,
        stake_history: ?sysvar.StakeHistory = null,
        fees: ?sysvar.Fees = null,
        recent_blockhashes: ?sysvar.RecentBlockhashes = null,
    };

    pub const AccountParams = struct {
        pubkey: ?Pubkey = null,
        lamports: u64 = 0,
        data: []const u8 = &.{},
        owner: ?Pubkey = null,
        executable: bool = false,
        rent_epoch: u64 = 0,
    };

    pub const ReturnDataParams = struct {
        program_id: Pubkey = Pubkey.ZEROES,
        data: []const u8 = &.{},
    };
};

pub fn createTransactionContext(
    allocator: std.mem.Allocator,
    random: std.Random,
    params: ExecuteContextsParams,
) !TransactionContext {
    if (!builtin.is_test)
        @compileError("createTransactionContext should only be called in test mode");

    // Create FeatureSet
    const feature_set = if (params.feature_set_ptr) |ptr|
        ptr
    else
        try allocator.create(FeatureSet);
    feature_set.* = try createFeatureSet(allocator, params.feature_set);
    errdefer feature_set.deinit(allocator);

    // Create EpochStakes
    const epoch_stakes = try allocator.create(EpochStakes);
    epoch_stakes.* = try createEpochStakes(allocator, params.epoch_stakes);

    // Create SysvarCache
    const sysvar_cache = try allocator.create(SysvarCache);
    sysvar_cache.* = try createSysvarCache(allocator, params.sysvar_cache);
    errdefer sysvar_cache.deinit(allocator);

    // Create Accounts
    var accounts = std.ArrayList(TransactionContextAccount).init(allocator);
    errdefer accounts.deinit();

    for (params.accounts) |account_params| {
        try accounts.append(
            TransactionContextAccount.init(
                account_params.pubkey orelse Pubkey.initRandom(random),
                .{
                    .lamports = account_params.lamports,
                    .data = try allocator.dupe(u8, account_params.data),
                    .owner = account_params.owner orelse Pubkey.initRandom(random),
                    .executable = account_params.executable,
                    .rent_epoch = account_params.rent_epoch,
                },
            ),
        );
    }

    // Create Return Data
    var return_data = TransactionReturnData{};
    return_data.program_id = params.return_data.program_id;
    return_data.data.appendSliceAssumeCapacity(params.return_data.data);

    // Create Transaction Context
    const tc = TransactionContext{
        .allocator = allocator,
        .feature_set = feature_set,
        .sysvar_cache = sysvar_cache,
        .epoch_stakes = epoch_stakes,
        .accounts = try accounts.toOwnedSlice(),
        .serialized_accounts = .{},
        .instruction_stack = .{},
        .instruction_trace = .{},
        .return_data = return_data,
        .accounts_resize_delta = params.accounts_resize_delta,
        .compute_meter = params.compute_meter,
        .compute_budget = params.compute_budget,
        .custom_error = params.custom_error,
        .rent = Rent.DEFAULT,
        .log_collector = params.log_collector,
        .prev_blockhash = params.prev_blockhash,
        .prev_lamports_per_signature = params.prev_lamports_per_signature,
    };

    return tc;
}

pub fn deinitTransactionContext(
    allocator: std.mem.Allocator,
    tc: *TransactionContext,
) void {
    if (!builtin.is_test)
        @compileError("deinitTransactionContext should only be called in test mode");

    tc.feature_set.deinit(allocator);
    allocator.destroy(tc.feature_set);

    tc.sysvar_cache.deinit(allocator);
    allocator.destroy(tc.sysvar_cache);

    tc.epoch_stakes.deinit(allocator);
    allocator.destroy(tc.epoch_stakes);

    tc.deinit();
}

pub fn createEpochStakes(
    allocator: std.mem.Allocator,
    params: []const ExecuteContextsParams.EpochStakeParam,
) !EpochStakes {
    var self: EpochStakes = .{
        .stakes = .{
            .vote_accounts = .{
                .accounts = .{},
                .staked_nodes = null,
            },
            .delegations = .{},
            .unused = 0,
            .epoch = 0,
            .history = .{},
        },
        .total_stake = 0,
        .node_id_to_vote_accounts = .{},
        .epoch_authorized_voters = .{},
    };
    errdefer self.stakes.deinit(allocator);

    for (params) |param| {
        self.total_stake += param.stake;
        try self.stakes.delegations.put(allocator, param.pubkey, .{
            .voter_pubkey = param.pubkey,
            .stake = param.stake,
            .activation_epoch = 0,
            .deactivation_epoch = 0,
            .deprecated_warmup_cooldown_rate = 0.0,
        });
    }

    return self;
}

pub fn createFeatureSet(
    allocator: std.mem.Allocator,
    params: []const ExecuteContextsParams.FeatureParams,
) !FeatureSet {
    if (!builtin.is_test)
        @compileError("createFeatureSet should only be called in test mode");

    var feature_set = FeatureSet{ .active = .{} };
    errdefer feature_set.deinit(allocator);

    for (params) |args| {
        try feature_set.active.put(
            allocator,
            args.pubkey,
            args.slot,
        );
    }

    return feature_set;
}

pub fn createSysvarCache(
    allocator: std.mem.Allocator,
    params: ExecuteContextsParams.SysvarCacheParams,
) !SysvarCache {
    if (!builtin.is_test)
        @compileError("createSysvarCache should only be called in test mode");

    var sysvar_cache = SysvarCache{};
    errdefer sysvar_cache.deinit(allocator);

    if (params.clock) |clock| {
        sysvar_cache.clock = try sysvar.serialize(allocator, clock);
    }
    if (params.epoch_schedule) |epoch_schedule| {
        sysvar_cache.epoch_schedule = try sysvar.serialize(allocator, epoch_schedule);
    }
    if (params.epoch_rewards) |epoch_rewards| {
        sysvar_cache.epoch_rewards = try sysvar.serialize(allocator, epoch_rewards);
    }
    if (params.rent) |rent| {
        sysvar_cache.rent = try sysvar.serialize(allocator, rent);
    }
    if (params.last_restart_slot) |last_restart_slot| {
        sysvar_cache.last_restart_slot = try sysvar.serialize(allocator, last_restart_slot);
    }
    if (params.slot_hashes) |slot_hashes| {
        sysvar_cache.slot_hashes = try sysvar.serialize(allocator, slot_hashes);
        sysvar_cache.slot_hashes_obj = .{
            .entries = try allocator.dupe(
                sysvar.SlotHashes.Entry,
                slot_hashes.entries,
            ),
        };
    }
    if (params.stake_history) |stake_history| {
        sysvar_cache.stake_history = try sysvar.serialize(allocator, stake_history);
        sysvar_cache.stake_history_obj = .{
            .entries = try allocator.dupe(
                sysvar.StakeHistory.Entry,
                stake_history.entries,
            ),
        };
    }
    sysvar_cache.fees = params.fees;
    if (params.recent_blockhashes) |recent_blockhashes| {
        sysvar_cache.recent_blockhashes = .{
            .entries = try allocator.dupe(
                sysvar.RecentBlockhashes.Entry,
                recent_blockhashes.entries,
            ),
        };
    }

    return sysvar_cache;
}

pub fn createInstructionInfo(
    tc: *const TransactionContext,
    program_id: Pubkey,
    instruction: anytype,
    accounts_params: []const InstructionInfoAccountMetaParams,
) !InstructionInfo {
    if (!builtin.is_test)
        @compileError("createInstructionContext should only be called in test mode");

    const program_index_in_transaction = for (tc.accounts, 0..) |account, index| {
        if (account.pubkey.equals(&program_id)) break index;
    } else return error.CouldNotFindProgramAccount;

    const account_metas = try createInstructionInfoAccountMetas(tc, accounts_params);

    const instruction_data = if (@TypeOf(instruction) == []const u8)
        try tc.allocator.dupe(u8, instruction)
    else
        try bincode.writeAlloc(
            tc.allocator,
            instruction,
            .{},
        );

    return .{
        .program_meta = .{
            .pubkey = program_id,
            .index_in_transaction = @intCast(program_index_in_transaction),
        },
        .account_metas = account_metas,
        .instruction_data = instruction_data,
    };
}

pub const InstructionInfoAccountMetaParams = struct {
    index_in_transaction: u16 = 0,
    index_in_caller: ?u16 = null,
    index_in_callee: ?u16 = null,
    is_signer: bool = false,
    is_writable: bool = false,
};

pub fn createInstructionInfoAccountMetas(
    tc: *const TransactionContext,
    account_meta_params: []const InstructionInfoAccountMetaParams,
) !std.BoundedArray(
    InstructionInfo.AccountMeta,
    InstructionInfo.MAX_ACCOUNT_METAS,
) {
    if (!builtin.is_test)
        @compileError("createInstructionContextAccountMetas should only be called in test mode");

    var account_metas = std.BoundedArray(
        InstructionInfo.AccountMeta,
        InstructionInfo.MAX_ACCOUNT_METAS,
    ){};
    for (account_meta_params, 0..) |acc, idx| {
        if (acc.index_in_transaction >= tc.accounts.len)
            return error.AccountIndexOutOfBounds;

        const index_in_callee = blk: {
            for (0..idx) |i| {
                if (acc.index_in_transaction ==
                    account_meta_params[i].index_in_transaction)
                {
                    break :blk i;
                }
            }
            break :blk idx;
        };

        try account_metas.append(.{
            .pubkey = tc.accounts[acc.index_in_transaction].pubkey,
            .index_in_transaction = acc.index_in_transaction,
            .index_in_caller = acc.index_in_caller orelse acc.index_in_transaction,
            .index_in_callee = acc.index_in_callee orelse @intCast(index_in_callee),
            .is_signer = acc.is_signer,
            .is_writable = acc.is_writable,
        });
    }

    return account_metas;
}

pub fn expectTransactionContextEqual(
    expected: TransactionContext,
    actual: TransactionContext,
) !void {
    if (!builtin.is_test)
        @compileError("expectTransactionContextEqual should only be called in test mode");

    if (expected.accounts.len != actual.accounts.len)
        return error.AccountsLengthMismatch;

    for (expected.accounts, 0..) |expected_account, index|
        expectTransactionAccountEqual(
            expected_account,
            actual.accounts[index],
        ) catch |err| {
            std.debug.print(
                "TransactionContext accounts mismatch at index {}: {}\n",
                .{ index, err },
            );
            return err;
        };

    if (expected.accounts_resize_delta != actual.accounts_resize_delta)
        return error.AccountsResizeDeltaMismatch;

    if (expected.compute_meter != actual.compute_meter) {
        return error.ComputeMeterMismatch;
    }

    if (expected.custom_error != actual.custom_error)
        return error.CustomErrorMismatch;

    if (expected.log_collector) |elc| {
        if (actual.log_collector) |alc| {
            if (!elc.eql(alc)) return error.LogCollectorMismatch;
        } else {
            return error.LogCollectorMismatch;
        }
    } else {
        if (actual.log_collector) |_| return error.LogCollectorMismatch;
    }

    // TODO: implement eqls for SysvarCache
    // if (expected.sysvar_cache != actual.sysvar_cache)
    //     return error.SysvarCacheMismatch;

    if (expected.prev_lamports_per_signature != actual.prev_lamports_per_signature)
        return error.LamportsPerSignatureMismatch;

    if (!expected.prev_blockhash.eql(actual.prev_blockhash))
        return error.LastBlockhashMismatch;

    // TODO: implement eqls for FeatureSet
    // if (expected.feature_set != actual.feature_set)
    //     return error.FeatureSetMismatch;

    try expectTransactionReturnDataEqual(expected.return_data, actual.return_data);
}

pub fn expectTransactionReturnDataEqual(
    expected: TransactionReturnData,
    actual: TransactionReturnData,
) !void {
    if (!expected.program_id.equals(&actual.program_id))
        return error.ProgramIdMismatch;

    if (expected.data.len != actual.data.len)
        return error.DataLenMismatch;

    if (!std.mem.eql(u8, expected.data.constSlice(), actual.data.constSlice()))
        return error.DataMismatch;
}

pub fn expectTransactionAccountEqual(
    expected: TransactionContextAccount,
    actual: TransactionContextAccount,
) !void {
    if (!builtin.is_test)
        @compileError("expectTransactionAccountEqual should only be called in test mode");

    if (!expected.pubkey.equals(&actual.pubkey))
        return error.PubkeyMismatch;

    if (expected.account.lamports != actual.account.lamports)
        return error.LamportsMismatch;

    if (!std.mem.eql(u8, expected.account.data, actual.account.data)) {
        return if (expected.account.data.len != actual.account.data.len)
            error.DataLengthMismatch
        else
            return error.DataMismatch;
    }

    if (!expected.account.owner.equals(&actual.account.owner))
        return error.OwnerMismatch;

    if (expected.account.executable != actual.account.executable)
        return error.ExecutableMismatch;

    if (expected.account.rent_epoch != actual.account.rent_epoch)
        return error.RentEpochMismatch;

    if (expected.read_refs != actual.read_refs)
        return error.ReadRefsMismatch;

    if (expected.write_ref != actual.write_ref)
        return error.WriteRefMismatch;
}
