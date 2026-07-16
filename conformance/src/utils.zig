const std = @import("std");
const build_options = @import("build-options");
const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const sig = @import("sig");

const sysvar = sig.runtime.sysvar;
const memory = sig.vm.memory;

const TransactionError = sig.ledger.transaction_status.TransactionError;
const InstructionError = sig.core.instruction.InstructionError;
const InstructionInfo = sig.runtime.instruction_info.InstructionInfo;
const TransactionContext = sig.runtime.transaction_context.TransactionContext;
const TransactionContextAccount = sig.runtime.transaction_context.TransactionContextAccount;
const SysvarCache = sig.runtime.SysvarCache;
const EpochStakes = sig.core.EpochStakes;
const ProgramMap = sig.runtime.program_loader.ProgramMap;
const FeatureSet = sig.core.FeatureSet;

const intFromInstructionError = sig.core.instruction.intFromInstructionError;

const Pubkey = sig.core.Pubkey;

/// Mirrors Agave's `mock_compile_message` + `LegacyMessage::new`: the
/// transaction context is populated with **only** the accounts referenced by
/// the top-level instruction (its `AccountMeta`s plus the program). All other
/// fixture accounts are excluded from `tc.accounts`, so a CPI callee that names
/// an unreferenced pubkey correctly fails with `MissingAccount` (matching agave
/// and firedancer) rather than escalating perms against a stale meta.
///
/// Fixture indices in `InstrAcct.index` are relative to the input protobuf
/// `accounts` list, so callers must translate them to the compact
/// `tc.accounts` layout via `input_to_tx_idx` before handing them to the
/// runtime.
///
/// [agave] https://github.com/anza-xyz/agave/blob/master/program-runtime/src/invoke_context.rs — `mock_compile_message`
/// [firedancer] https://github.com/firedancer-io/firedancer/blob/main/src/flamenco/runtime/tests/fd_instr_harness.c — `account_in_message` / `input_txn_idx`
pub const CompiledMessage = struct {
    /// Fixture-index → `tc.accounts` index. `NOT_IN_MESSAGE` when the account
    /// is not part of the compiled message.
    input_to_tx_idx: []u16,
    /// Number of accounts in the compiled message (== `tc.accounts.len`).
    message_account_cnt: u16,
    /// Fixture index of the program account, or `null` when the program id is
    /// not present in the fixture's `accounts` list.
    program_input_idx: ?u16,

    pub const NOT_IN_MESSAGE: u16 = std.math.maxInt(u16);

    pub fn deinit(self: CompiledMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.input_to_tx_idx);
    }

    /// Translate a fixture-relative account index to a `tc.accounts` index,
    /// or `null` if the account is not in the compiled message.
    pub fn toTxIdx(self: CompiledMessage, input_idx: u32) ?u16 {
        if (input_idx >= self.input_to_tx_idx.len) return null;
        const tx_idx = self.input_to_tx_idx[input_idx];
        return if (tx_idx == NOT_IN_MESSAGE) null else tx_idx;
    }
};

/// Build a [`CompiledMessage`] for a top-level instruction. Marks the program
/// account and every account named by `instr_accounts` as in-message; assigns
/// them compact tc-indices in fixture order (matches firedancer's
/// `fd_instr_harness.c`, which uses fixture order and pushes unreferenced
/// accounts past `accounts.cnt`). All other fixture accounts are excluded.
pub fn compileMessage(
    allocator: std.mem.Allocator,
    pb_instr_ctx: pb.InstrContext,
) !CompiledMessage {
    if (pb_instr_ctx.program_id.len != Pubkey.SIZE) return error.OutOfBounds;

    const pb_accounts = pb_instr_ctx.accounts.items;
    var input_to_tx_idx = try allocator.alloc(u16, pb_accounts.len);
    errdefer allocator.free(input_to_tx_idx);
    @memset(input_to_tx_idx, CompiledMessage.NOT_IN_MESSAGE);

    // Mark accounts named by instr_accounts. Duplicate references collapse to
    // one tc slot in the second pass below.
    for (pb_instr_ctx.instr_accounts.items) |ia| {
        if (ia.index >= pb_accounts.len) return error.InstructionAccountIndexOutOfRange;
        input_to_tx_idx[ia.index] = 0; // sentinel meaning "in message"
    }

    // Mark the program account. `program_input_idx` is null when the fixture
    // omits the program from its account list; sig historically errors out in
    // `createInstructionInfo` in that case, which we preserve.
    var program_input_idx: ?u16 = null;
    for (pb_accounts, 0..) |a, i| {
        if (std.mem.eql(u8, a.address, pb_instr_ctx.program_id)) {
            program_input_idx = @intCast(i);
            input_to_tx_idx[i] = 0; // sentinel meaning "in message"
            break;
        }
    }

    // Second pass: assign compact tc-indices in fixture order.
    var cnt: u16 = 0;
    for (input_to_tx_idx) |*slot| {
        if (slot.* != CompiledMessage.NOT_IN_MESSAGE) {
            slot.* = cnt;
            cnt += 1;
        }
    }

    return .{
        .input_to_tx_idx = input_to_tx_idx,
        .message_account_cnt = cnt,
        .program_input_idx = program_input_idx,
    };
}

pub const ConvertedErrorCodes = struct {
    err: u32,
    instruction_error: u32,
    custom_error: u32,
    instruction_index: u32,

    pub const default: ConvertedErrorCodes = .{
        .err = 0,
        .instruction_error = 0,
        .custom_error = 0,
        .instruction_index = 0,
    };
};

pub fn convertTransactionError(maybe_err: ?TransactionError) ConvertedErrorCodes {
    return if (maybe_err) |err| switch (err) {
        .InstructionError => |p| {
            const index, const instruction_error = p;
            return .{
                .err = @intFromEnum(err) + 1,
                .instruction_error = @intFromEnum(instruction_error) + 1,
                .custom_error = switch (instruction_error) {
                    .Custom => |v| v,
                    else => 0,
                },
                .instruction_index = index,
            };
        },
        else => return .{
            .err = @intFromEnum(err) + 1,
            .instruction_error = 0,
            .custom_error = 0,
            .instruction_index = 0,
        },
    } else .default;
}

pub fn createTransactionContext(
    allocator: std.mem.Allocator,
    instr_ctx: pb.InstrContext,
    environment: struct {
        feature_set: ?*FeatureSet = null,
        epoch_stakes: ?*EpochStakes = null,
        sysvar_cache: ?*SysvarCache = null,
        vm_environment: ?*sig.vm.Environment = null,
        program_map: ?*ProgramMap = null,
    },
    tc: *TransactionContext,
) !CompiledMessage {
    const compiled_message = try compileMessage(allocator, instr_ctx);
    errdefer compiled_message.deinit(allocator);

    const feature_set = if (environment.feature_set) |ptr|
        ptr
    else
        try allocator.create(FeatureSet);
    feature_set.* = try loadFeatureSet(instr_ctx);

    const epoch_stakes = if (environment.epoch_stakes) |ptr|
        ptr
    else
        try allocator.create(EpochStakes);

    epoch_stakes.* = .EMPTY_WITH_GENESIS;

    const sysvar_cache = if (environment.sysvar_cache) |ptr|
        ptr
    else
        try allocator.create(SysvarCache);
    sysvar_cache.* = try createSysvarCache(allocator, instr_ctx);

    const vm_environment = if (environment.vm_environment) |ptr|
        ptr
    else
        try allocator.create(sig.vm.Environment);
    vm_environment.* = sig.vm.Environment{
        .config = .{},
        .loader = .ALL_DISABLED,
    };

    const program_map = if (environment.program_map) |ptr|
        ptr
    else
        try allocator.create(ProgramMap);
    errdefer if (environment.program_map == null) allocator.destroy(program_map);
    program_map.* = ProgramMap.empty;

    const log_collector = try sig.runtime.LogCollector.default(allocator);
    errdefer log_collector.deinit(allocator);

    const slot = 0;
    tc.* = TransactionContext{
        .allocator = allocator,
        .programs_allocator = allocator,
        .feature_set = feature_set,
        .epoch_stake_reader = (sig.runtime.EpochStakeReaderAdapter{
            .epoch_stakes = epoch_stakes,
        }).epochStakeReader(),
        .sysvar_cache = sysvar_cache,
        .vm_environment = vm_environment,
        .next_vm_environment = vm_environment,
        .program_map = program_map,
        .accounts = try createTransactionContextAccounts(
            allocator,
            instr_ctx.accounts.items,
            compiled_message,
        ),
        .serialized_accounts = .{},
        .instruction_stack = .{},
        .instruction_trace = .{},
        .return_data = .{},
        .accounts_resize_delta = 0,
        .compute_meter = instr_ctx.cu_avail,
        .compute_budget = .init(instr_ctx.cu_avail),
        .custom_error = null,
        .log_collector = log_collector,
        .rent = sysvar_cache.get(sysvar.Rent) catch sysvar.Rent.INIT,
        .prev_blockhash = sig.core.Hash.ZEROES,
        .prev_lamports_per_signature = 0,
        .slot = slot,
    };
    errdefer comptime unreachable;

    if (sysvar_cache.get(sysvar.RecentBlockhashes) catch null) |recent_blockhashes| {
        if (recent_blockhashes.entries.len > 0) {
            const prev_entry = recent_blockhashes.entries.get(recent_blockhashes.entries.len - 1);
            tc.prev_blockhash = prev_entry.blockhash;
            tc.prev_lamports_per_signature = prev_entry.lamports_per_signature;
        }
    }

    return compiled_message;
}

pub fn deinitTransactionContext(
    allocator: std.mem.Allocator,
    tc: TransactionContext,
) void {
    allocator.destroy(tc.feature_set);
    allocator.destroy(tc.vm_environment);

    const epoch_stakes: *const EpochStakes = @ptrCast(@alignCast(tc.epoch_stake_reader.ctx));
    epoch_stakes.deinit(allocator);
    allocator.destroy(epoch_stakes);

    tc.sysvar_cache.deinit(allocator);
    allocator.destroy(tc.sysvar_cache);

    tc.program_map.deinit(allocator);
    allocator.destroy(tc.program_map);

    for (tc.accounts) |account| {
        allocator.free(account.account.data);
        allocator.destroy(account.account);
    }

    tc.deinit();
}

/// Create a `FeatureSet` based on the feature IDs provided in the protobuf message.
///
/// Iterate over the feature IDs in the protobuf message and set the corresponding features in the `FeatureSet`.
/// Unknown, unsupported, or reverted debug logs indicate Sig is not compatible with the fixtures active features.
pub fn loadFeatureSet(ctx: anytype) !FeatureSet {
    const pb_features = switch (@TypeOf(ctx)) {
        *pb.TxnContext, *const pb.TxnContext => (ctx.bank orelse return .ALL_DISABLED).features,
        pb.InstrContext => ctx.features,
        pb.ELFLoaderCtx => ctx.features,
        else => comptime unreachable,
    } orelse return .ALL_DISABLED;

    var feature_set: FeatureSet = .ALL_DISABLED;
    for (pb_features.features.items) |id| {
        // Convert the feature ID from the protobuf message to the corresponding `Feature` enum value.
        // Log features which do not correspond to a `Feature` variant and are otherwise unknown (i.e. not present in `src/core/features.zon`).
        const feature = feature_set.getById(id) catch {
            if (build_options.log_feature_status and
                !sig.core.features.isKnownFeatureId(id)) std.debug.print(
                "feature 0x{x} is unknown\n",
                .{id},
            );
            continue;
        };

        // Log features which appear in a fixture but are marked as reverted or unsupported in Sig.
        if (build_options.log_feature_status) switch (sig.core.features.status_map.get(feature)) {
            .reverted => std.debug.print("feature {} (0x{x}) is reverted\n", .{ feature, id }),
            .unsupported => std.debug.print("feature {} (0x{x}) is unsupported\n", .{ feature, id }),
            .supported, .hardcoded_for_fuzzing, .hardcoded => {},
        };

        feature_set.setSlot(feature, 0);
    }
    return feature_set;
}

const AccountSharedData = sig.runtime.AccountSharedData;

pub fn createTransactionContextAccounts(
    allocator: std.mem.Allocator,
    pb_accounts: []const pb.AcctState,
    compiled_message: CompiledMessage,
) ![]TransactionContextAccount {
    errdefer |err| {
        std.debug.print("createTransactionContextAccounts: error={}\n", .{err});
    }

    var accounts: std.ArrayList(TransactionContextAccount) = .{};
    errdefer {
        for (accounts.items) |account| {
            allocator.free(account.account.data);
            allocator.destroy(account.account);
        }
        accounts.deinit(allocator);
    }

    try accounts.ensureTotalCapacityPrecise(allocator, compiled_message.message_account_cnt);

    for (pb_accounts, 0..) |pb_account, i| {
        // Skip accounts that aren't in the compiled message so the runtime
        // sees only what agave / firedancer see.
        if (compiled_message.input_to_tx_idx[i] == CompiledMessage.NOT_IN_MESSAGE) continue;

        const account_data = try allocator.dupe(u8, pb_account.data);
        errdefer allocator.free(account_data);

        if (pb_account.owner.len != Pubkey.SIZE) return error.OutOfBounds;
        if (pb_account.address.len != Pubkey.SIZE) return error.OutOfBounds;

        const account_ptr = try allocator.create(AccountSharedData);
        account_ptr.* = .{
            .lamports = pb_account.lamports,
            .data = account_data,
            .owner = .{ .data = pb_account.owner[0..Pubkey.SIZE].* },
            .executable = pb_account.executable,
            .rent_epoch = sig.core.rent_collector.RENT_EXEMPT_RENT_EPOCH,
        };

        accounts.appendAssumeCapacity(TransactionContextAccount.init(
            .{ .data = pb_account.address[0..Pubkey.SIZE].* },
            account_ptr,
        ));
    }

    std.debug.assert(accounts.items.len == compiled_message.message_account_cnt);
    return accounts.toOwnedSlice(allocator);
}

pub fn createInstructionInfo(
    allocator: std.mem.Allocator,
    tc: *const TransactionContext,
    program_id: Pubkey,
    instruction: []const u8,
    pb_instruction_accounts: []const pb.InstrAcct,
    compiled_message: CompiledMessage,
) !InstructionInfo {
    errdefer |err| {
        std.debug.print("createInstructionInfo: error={}\n", .{err});
    }

    const program_index_in_transaction =
        tc.getAccountIndex(program_id) orelse return error.CouldNotFindProgram;

    // Dedupe map is keyed by tc-index (the runtime's index_in_transaction),
    // not the fixture-relative index in `pb_instruction_accounts`.
    var dedupe_map: [InstructionInfo.MAX_ACCOUNT_METAS]u16 = @splat(0xffff);
    for (pb_instruction_accounts, 0..) |acc, idx| {
        const tx_idx = compiled_message.toTxIdx(acc.index) orelse
            return error.InstructionAccountIndexOutOfRange;
        if (dedupe_map[tx_idx] == 0xffff)
            dedupe_map[tx_idx] = @intCast(idx);
    }

    // An account called as a program is write-demoted to read-only during
    // message sanitization (unless an upgradeable loader is present). The
    // instruction harness bypasses message compilation, so replicate the
    // demotion here to match agave's `mock_compile_message` writability.
    // agave sanitizes with an empty reserved-accounts set, so only the
    // program-id demotion applies here (no sysvar/native-program demotion).
    // [agave] https://github.com/anza-xyz/agave/blob/6dcc39fcba90fbb5c924c71a1ef287c234f56c17/accounts-db/src/accounts.rs#L105
    const v3_id = sig.runtime.program.bpf_loader.v3.ID;
    const is_upgradeable_loader_present = blk: {
        if (program_id.equals(&v3_id)) break :blk true;
        for (pb_instruction_accounts) |acc| {
            const tx_idx = compiled_message.toTxIdx(acc.index) orelse continue;
            const tc_acc = tc.getAccountAtIndex(tx_idx) orelse continue;
            if (tc_acc.pubkey.equals(&v3_id)) break :blk true;
        }
        break :blk false;
    };

    var instruction_accounts = InstructionInfo.AccountMetas{};
    errdefer instruction_accounts.deinit(allocator);

    for (pb_instruction_accounts) |account| {
        const tx_idx = compiled_message.toTxIdx(account.index) orelse
            return error.InstructionAccountIndexOutOfRange;
        const tc_acc = tc.getAccountAtIndex(tx_idx) orelse
            return error.AccountNotInTransaction;
        const demote_program_id = tc_acc.pubkey.equals(&program_id) and
            !is_upgradeable_loader_present;
        try instruction_accounts.append(allocator, .{
            .pubkey = tc_acc.pubkey,
            .index_in_transaction = tx_idx,
            .is_signer = account.is_signer,
            .is_writable = account.is_writable and !demote_program_id,
        });
    }

    return .{
        .program_meta = .{
            .pubkey = program_id,
            .index_in_transaction = @intCast(program_index_in_transaction),
        },
        .account_metas = instruction_accounts,
        .dedupe_map = dedupe_map,
        .instruction_data = try allocator.dupe(u8, instruction),
        .owned_instruction_data = true,
        .initial_account_lamports = 0,
    };
}

/// Build a [`PubkeyMap`] of every fixture account for use by the program
/// loader. Programs and their programdata accounts are typically **not** in
/// the top-level instruction's compiled message (so they aren't in
/// `tc.accounts`), but the loader still needs to see them to build the
/// [`ProgramMap`]. Agave and firedancer both load executables from the raw
/// fixture accounts list independently of the compiled message; this helper
/// mirrors that.
///
/// The map borrows the pb-owned byte buffers via `@constCast` — the loader
/// only reads through the [`AccountReader`], so this is safe as long as the
/// pb `InstrContext` outlives the returned map (which the callers guarantee).
/// [agave] `fill_program_cache_from_accounts(&instr_context.accounts, ...)` in
/// `svm/src/conformance/syscall.rs`.
/// [firedancer] `fd_instr_harness.c` "Load in executable accounts" loop, which
/// iterates the raw `test_ctx->accounts` list.
pub fn createProgramCacheAccountsMap(
    allocator: std.mem.Allocator,
    pb_instr_ctx: pb.InstrContext,
) !sig.utils.collections.PubkeyMap(AccountSharedData) {
    var map: sig.utils.collections.PubkeyMap(AccountSharedData) = .{};
    errdefer map.deinit(allocator);

    for (pb_instr_ctx.accounts.items) |pb_account| {
        if (pb_account.address.len != Pubkey.SIZE) return error.OutOfBounds;
        if (pb_account.owner.len != Pubkey.SIZE) return error.OutOfBounds;

        try map.put(allocator, .{ .data = pb_account.address[0..Pubkey.SIZE].* }, .{
            .lamports = pb_account.lamports,
            .data = @constCast(pb_account.data),
            .owner = .{ .data = pb_account.owner[0..Pubkey.SIZE].* },
            .executable = pb_account.executable,
            .rent_epoch = sig.core.rent_collector.RENT_EXEMPT_RENT_EPOCH,
        });
    }

    return map;
}

pub fn createSysvarCache(
    allocator: std.mem.Allocator,
    ctx: pb.InstrContext,
) !sig.runtime.SysvarCache {
    errdefer |err| {
        std.debug.print("createSysvarCache: error={}\n", .{err});
    }

    var sysvar_cache: sig.runtime.SysvarCache = .{};
    sysvar_cache.clock = try cloneSysvarData(allocator, ctx, sysvar.Clock.ID);
    if (std.meta.isError(sysvar_cache.get(sysvar.Clock))) {
        var clock = sysvar.Clock.INIT;
        clock.slot = 10;
        sysvar_cache.clock = try sysvar.serialize(
            allocator,
            clock,
        );
    }

    sysvar_cache.epoch_schedule = try cloneSysvarData(allocator, ctx, sig.core.EpochSchedule.ID);
    if (std.meta.isError(sysvar_cache.get(sysvar.EpochSchedule))) {
        sysvar_cache.epoch_schedule = try sysvar.serialize(
            allocator,
            sig.core.EpochSchedule.INIT,
        );
    }

    sysvar_cache.epoch_rewards = try cloneSysvarData(allocator, ctx, sysvar.EpochRewards.ID);
    sysvar_cache.rent = try cloneSysvarData(allocator, ctx, sysvar.Rent.ID);
    if (std.meta.isError(sysvar_cache.get(sysvar.Rent))) {
        sysvar_cache.last_restart_slot = try sysvar.serialize(
            allocator,
            sysvar.LastRestartSlot{
                .last_restart_slot = 5000,
            },
        );
    }

    sysvar_cache.last_restart_slot = try cloneSysvarData(allocator, ctx, sysvar.LastRestartSlot.ID);
    if (std.meta.isError(sysvar_cache.get(sysvar.LastRestartSlot))) {
        if (sysvar_cache.last_restart_slot) |lrs| allocator.free(lrs);
        sysvar_cache.last_restart_slot = null;
    }

    if (sysvar_cache.slot_hashes == null) {
        if (try cloneSysvarData(allocator, ctx, sysvar.SlotHashes.ID)) |slot_hashes_data| {
            const len = sig.bincode.readFromSlice(allocator, u64, slot_hashes_data, .{}) catch 0;

            const maybe_entries = if (len < 1024 * 1024) sig.bincode.readFromSlice(
                allocator,
                []sysvar.SlotHashes.Entry,
                slot_hashes_data,
                .{},
            ) catch null else null;

            if (maybe_entries) |entries| {
                const start = entries.len -| sysvar.SlotHashes.MAX_ENTRIES;
                sysvar_cache.slot_hashes = slot_hashes_data;
                sysvar_cache.slot_hashes_obj = .INIT;
                sysvar_cache.slot_hashes_obj.?.entries.appendSliceAssumeCapacity(entries[start..]);
            }
        }
    }
    if (sysvar_cache.stake_history == null) {
        if (try cloneSysvarData(allocator, ctx, sysvar.StakeHistory.ID)) |stake_history_data| {
            const len = sig.bincode.readFromSlice(allocator, u64, stake_history_data, .{}) catch 0;

            const maybe_entries = if (len < 1024 * 1024) sig.bincode.readFromSlice(
                allocator,
                []sysvar.StakeHistory.Entry,
                stake_history_data,
                .{},
            ) catch null else null;

            if (maybe_entries) |entries| {
                const start = entries.len -| sysvar.StakeHistory.MAX_ENTRIES;
                sysvar_cache.stake_history = stake_history_data;
                sysvar_cache.stake_history_obj = .INIT;
                sysvar_cache.stake_history_obj.?.entries.appendSliceAssumeCapacity(entries[start..]);
            }
        }
    }
    if (sysvar_cache.fees_obj == null) {
        if (try cloneSysvarData(allocator, ctx, sysvar.Fees.ID)) |fees_data| {
            sysvar_cache.fees_obj = sig.bincode.readFromSlice(
                allocator,
                sysvar.Fees,
                fees_data,
                .{},
            ) catch null;
        }
    }
    if (sysvar_cache.recent_blockhashes_obj == null) {
        if (try cloneSysvarData(
            allocator,
            ctx,
            sysvar.RecentBlockhashes.ID,
        )) |recent_blockhashes_data| {
            const len = sig.bincode.readFromSlice(
                allocator,
                u64,
                recent_blockhashes_data,
                .{},
            ) catch 0;

            const maybe_entries = if (len < 1024 * 1024) sig.bincode.readFromSlice(
                allocator,
                []sysvar.RecentBlockhashes.Entry,
                recent_blockhashes_data,
                .{},
            ) catch null else null;

            if (maybe_entries) |entries| {
                const start = entries.len -| sysvar.RecentBlockhashes.MAX_ENTRIES;
                sysvar_cache.recent_blockhashes_obj = .INIT;
                sysvar_cache.recent_blockhashes_obj.?.entries.appendSliceAssumeCapacity(
                    entries[start..],
                );
            }
        }
    }
    return sysvar_cache;
}

fn cloneSysvarData(allocator: std.mem.Allocator, ctx: pb.InstrContext, pubkey: Pubkey) !?[]const u8 {
    for (ctx.accounts.items) |acc| {
        if (acc.lamports > 0 and std.mem.eql(u8, acc.address, &pubkey.data)) {
            return try allocator.dupe(u8, acc.data);
        }
    }
    return null;
}

pub fn createInstrEffects(
    allocator: std.mem.Allocator,
    tc: *const TransactionContext,
    result: ?InstructionError,
    pb_instr_ctx: pb.InstrContext,
    compiled_message: CompiledMessage,
) !pb.InstrEffects {
    const modified_accounts = try modifiedAccounts(allocator, tc, pb_instr_ctx, compiled_message);

    // Match Agave's direct_mapping_handle_cu_exhaustion behavior:
    // When virtual_address_space_adjustments is active and execution failed
    // with CU meter exhausted, account data regions cannot be reliably compared,
    // so clear them.
    // See: https://github.com/firedancer-io/solfuzz-agave/blob/agave-v4.0.0-beta.6/src/utils/mod.rs#L135-L146
    //      https://github.com/firedancer-io/solfuzz-agave/blob/agave-v4.0.0-beta.6/src/instr.rs#L763-L768
    const virtual_address_space_adjustments = tc.feature_set.active(
        .virtual_address_space_adjustments,
        tc.slot,
    );
    if (virtual_address_space_adjustments and tc.compute_meter == 0 and result != null) {
        for (modified_accounts.items) |*acc| {
            allocator.free(acc.data);
            acc.data = &.{};
        }
    }

    return pb.InstrEffects{
        .result = if (result) |err| intFromInstructionError(err) else 0,
        .custom_err = tc.custom_error orelse 0,
        .modified_accounts = modified_accounts,
        .cu_avail = tc.compute_meter,
        .return_data = try allocator.dupe(u8, tc.return_data.data.constSlice()),
    };
}

fn modifiedAccounts(
    allocator: std.mem.Allocator,
    tc: *const TransactionContext,
    pb_instr_ctx: pb.InstrContext,
    compiled_message: CompiledMessage,
) !std.ArrayList(pb.AcctState) {
    // Agave's InstrHarness only loads the "compiled message" accounts — the
    // program account plus the accounts referenced by `instr_accounts` — into
    // the transaction context, and its `resulting_accounts` overlay reports
    // any fixture account absent from the compiled message at its INPUT state
    // (unchanged), never a post-execution state. Sig's `tc.accounts` is
    // likewise compacted to just the compiled-message accounts, so for every
    // fixture account we either read the compact `tc` slot (in-message) or
    // echo the input (unreferenced).
    //
    // [agave] `resulting_accounts` overlay in the InstrHarness:
    // https://github.com/firedancer-io/agave/blob/agave-v4.2-90f63cbb-patches/svm/src/conformance/instr/harness.rs#L136-L146
    var accounts: std.ArrayList(pb.AcctState) = .{};
    errdefer accounts.deinit(allocator);

    try accounts.ensureTotalCapacityPrecise(allocator, pb_instr_ctx.accounts.items.len);

    for (pb_instr_ctx.accounts.items, 0..) |in, i| {
        if (compiled_message.input_to_tx_idx[i] != CompiledMessage.NOT_IN_MESSAGE) {
            const tx_idx = compiled_message.input_to_tx_idx[i];
            const acc = tc.accounts[tx_idx];
            accounts.appendAssumeCapacity(.{
                .address = try allocator.dupe(u8, &acc.pubkey.data),
                .lamports = acc.account.lamports,
                .data = try allocator.dupe(u8, acc.account.data),
                .executable = acc.account.executable,
                .owner = try allocator.dupe(u8, &acc.account.owner.data),
            });
        } else {
            // Not in the compiled message: report the input state, unchanged.
            accounts.appendAssumeCapacity(.{
                .address = try allocator.dupe(u8, in.address),
                .lamports = in.lamports,
                .data = try allocator.dupe(u8, in.data),
                .executable = in.executable,
                .owner = try allocator.dupe(u8, in.owner),
            });
        }
    }

    return accounts;
}

pub fn createSyscallEffect(allocator: std.mem.Allocator, params: struct {
    tc: *const TransactionContext,
    err: i64,
    err_kind: pb.ErrKind,
    heap: []const u8,
    stack: []const u8,
    rodata: []const u8,
    frame_count: u64,
    memory_map: sig.vm.memory.MemoryMap,
    registers: sig.vm.interpreter.RegisterMap = sig.vm.interpreter.RegisterMap.initFill(0),
    skip_input_data_regions: bool = false,
}) !pb.SyscallEffects {
    // Protosol marks SyscallEffects field 8 (`log`) as `reserved`, i.e.
    // conformance target no longer emits log output in the structured result
    // [protosol] https://github.com/firedancer-io/protosol/commit/040c98bd6468fd6dc94ab18639c9db190c8c692b
    // When virtual_address_space_adjustments is enabled, Agave's cpi_common()
    // calls update_caller_account_region only after process_instruction succeeds
    // (agave: program-runtime/src/cpi.rs). On failure the `?` propagates before
    // regions are updated, so they contain stale data. Return an empty list to
    // match that behaviour. See: https://github.com/firedancer-io/solfuzz-agave/pull/501
    const input_data_regions: std.ArrayList(pb.InputDataRegion) = if (params.skip_input_data_regions)
        .{}
    else
        try extractInputDataRegions(
            allocator,
            params.memory_map,
        );

    return .{
        .@"error" = params.err,
        .error_kind = params.err_kind,
        .cu_avail = params.tc.compute_meter,
        .heap = try allocator.dupe(u8, params.heap),
        .stack = try allocator.dupe(u8, params.stack),
        .input_data_regions = input_data_regions,
        .frame_count = params.frame_count,
        .rodata = try allocator.dupe(u8, params.rodata),
        .r0 = params.registers.get(.r0),
        .r1 = params.registers.get(.r1),
        .r2 = params.registers.get(.r2),
        .r3 = params.registers.get(.r3),
        .r4 = params.registers.get(.r4),
        .r5 = params.registers.get(.r5),
        .r6 = params.registers.get(.r6),
        .r7 = params.registers.get(.r7),
        .r8 = params.registers.get(.r8),
        .r9 = params.registers.get(.r9),
        .r10 = params.registers.get(.r10),
        .pc = params.registers.get(.pc),
    };
}

pub fn copyPrefix(dst: []u8, prefix: []const u8) void {
    const size = @min(dst.len, prefix.len);
    @memcpy(dst[0..size], prefix[0..size]);
}

pub fn extractInputDataRegions(
    allocator: std.mem.Allocator,
    memory_map: memory.MemoryMap,
) !std.ArrayList(pb.InputDataRegion) {
    var regions: std.ArrayList(pb.InputDataRegion) = .{};
    errdefer regions.deinit(allocator);

    const mm_regions: []const sig.vm.memory.Region = switch (memory_map) {
        .aligned => |amm| amm.regions,
        .unaligned => |umm| umm.regions,
    };

    for (mm_regions) |region| {
        if (region.vm_addr_start >= memory.INPUT_START) {
            try regions.append(allocator, .{
                .offset = region.vm_addr_start - memory.INPUT_START,
                .is_writable = switch (region.host_memory) {
                    .constant => false,
                    .mutable => true,
                },
                .content = try allocator.dupe(u8, region.constSlice()),
            });
        }
    }

    std.mem.sort(pb.InputDataRegion, regions.items, {}, struct {
        pub fn cmp(_: void, a: pb.InputDataRegion, b: pb.InputDataRegion) bool {
            return a.offset < b.offset;
        }
    }.cmp);

    return regions;
}

pub fn printPbInstrContext(ctx: pb.InstrContext) !void {
    var buffer = [_]u8{0} ** (1024 * 1024);
    var fbs = std.io.fixedBufferStream(&buffer);
    var writer = fbs.writer();
    try writer.writeAll("InstrContext {");
    try std.fmt.format(writer, "\n\tprogram_id: {any}", .{
        Pubkey{ .data = ctx.program_id[0..Pubkey.SIZE].* },
    });
    try writer.writeAll(",\n\taccounts: [");
    for (ctx.accounts.items) |acc| {
        try writer.writeAll("\n\t\tAcctState {");
        try std.fmt.format(writer, "\n\t\t\taddress: {any}", .{
            Pubkey{ .data = acc.address[0..Pubkey.SIZE].* },
        });
        try std.fmt.format(writer, ",\n\t\t\tlamports: {d}", .{acc.lamports});
        try std.fmt.format(writer, ",\n\t\t\tdata.len: {any}", .{acc.data.len});
        try std.fmt.format(writer, ",\n\t\t\texecutable: {}", .{acc.executable});
        try std.fmt.format(writer, ",\n\t\t\towner: {any}", .{
            Pubkey{ .data = acc.owner[0..Pubkey.SIZE].* },
        });
        try writer.writeAll("\n\t\t},\n");
    }
    try writer.writeAll("\t],\n\tinstr_accounts: [");
    for (ctx.instr_accounts.items) |acc| {
        try writer.writeAll("\n\t\tInstrAcct {");
        try std.fmt.format(writer, "\n\t\t\tindex: {}", .{acc.index});
        try std.fmt.format(writer, ",\n\t\t\tis_signer: {}", .{acc.is_signer});
        try std.fmt.format(writer, ",\n\t\t\tis_writable: {}", .{acc.is_writable});
        try writer.writeAll("\n\t\t},\n");
    }
    try std.fmt.format(writer, "\t],\n\tdata: {any}", .{ctx.data});
    try std.fmt.format(writer, ",\n\tcu_avail: {d}", .{ctx.cu_avail});
    try writer.writeAll(",\n}\n");
    std.debug.print("{s}", .{writer.context.getWritten()});
}

pub fn printPbInstrEffects(effects: pb.InstrEffects) !void {
    var buffer = [_]u8{0} ** (1024 * 1024);
    var fbs = std.io.fixedBufferStream(&buffer);
    var writer = fbs.writer();
    try writer.writeAll("InstrEffects {");
    try std.fmt.format(writer, "\n\tresult: {d}", .{effects.result});
    try std.fmt.format(writer, ",\n\tcustom_err: {d}", .{effects.custom_err});
    try writer.writeAll(",\n\tmodified_accounts: [");
    for (effects.modified_accounts.items) |acc| {
        try writer.writeAll("\n\t\tAcctState {");
        try std.fmt.format(writer, "\n\t\t\taddress: {}", .{
            Pubkey{ .data = acc.address[0..Pubkey.SIZE].* },
        });
        try std.fmt.format(writer, ",\n\t\t\tlamports: {d}", .{acc.lamports});
        try std.fmt.format(writer, ",\n\t\t\tdata: {any}", .{acc.data});
        try std.fmt.format(writer, ",\n\t\t\texecutable: {}", .{acc.executable});
        try std.fmt.format(writer, ",\n\t\t\towner: {}", .{
            Pubkey{ .data = acc.owner[0..Pubkey.SIZE].* },
        });
        try writer.writeAll("\n\t\t},\n");
    }
    try writer.writeAll("\t],");
    try std.fmt.format(writer, ",\n\tcu_avail: {d}", .{effects.cu_avail});
    try std.fmt.format(writer, ",\n\treturn_data: {any}", .{effects.return_data});
    try writer.writeAll("\n}\n");
    std.debug.print("{s}", .{writer.context.getWritten()});
}

pub fn printPbVmContext(ctx: pb.VmContext) !void {
    var buffer = [_]u8{0} ** (1024 * 1024);
    var fbs = std.io.fixedBufferStream(&buffer);
    var writer = fbs.writer();
    try writer.writeAll("VmContext {");
    try std.fmt.format(writer, "\n\theap_max: {}", .{ctx.heap_max});
    try std.fmt.format(writer, ",\n\trodata: {any}", .{ctx.rodata});
    try std.fmt.format(
        writer,
        ",\n\trodata_text_section_offset: {}",
        .{ctx.rodata_text_section_offset},
    );
    try std.fmt.format(
        writer,
        ",\n\trodata_text_section_length: {}",
        .{ctx.rodata_text_section_length},
    );
    try std.fmt.format(writer, "\n\tr0: {}", .{ctx.r0});
    try std.fmt.format(writer, ",\n\tr1: {}", .{ctx.r1});
    try std.fmt.format(writer, ",\n\tr2: {}", .{ctx.r2});
    try std.fmt.format(writer, ",\n\tr3: {}", .{ctx.r3});
    try std.fmt.format(writer, ",\n\tr4: {}", .{ctx.r4});
    try std.fmt.format(writer, ",\n\tr5: {}", .{ctx.r5});
    try std.fmt.format(writer, ",\n\tr6: {}", .{ctx.r6});
    try std.fmt.format(writer, ",\n\tr7: {}", .{ctx.r7});
    try std.fmt.format(writer, ",\n\tr8: {}", .{ctx.r8});
    try std.fmt.format(writer, ",\n\tr9: {}", .{ctx.r9});
    try std.fmt.format(writer, ",\n\tr10: {}", .{ctx.r10});
    try std.fmt.format(writer, ",\n\tr11: {}", .{ctx.r11});
    try std.fmt.format(writer, ",\n\tentry_pc: {}", .{ctx.entry_pc});
    try std.fmt.format(writer, ",\n\tcall_whitelist: {any}", .{ctx.call_whitelist});
    try std.fmt.format(writer, ",\n\ttracing_enabled: {}", .{ctx.tracing_enabled});
    try std.fmt.format(writer, ",\n\treturn_data: ", .{});
    if (ctx.return_data) |rd| {
        try std.fmt.format(writer, "{{\n\t\tprogram_id: {},\n\t\tdata: {any}\n\t}}", .{
            Pubkey{ .data = rd.program_id[0..Pubkey.SIZE].* },
            rd.data,
        });
    } else {
        try writer.writeAll("null");
    }
    try std.fmt.format(writer, ",\n\tsbpf_version: {}", .{ctx.sbpf_version});
    try writer.writeAll("\n}\n");
    std.debug.print("{s}", .{writer.context.getWritten()});
}

pub fn printPbSyscallInvocation(ctx: pb.SyscallInvocation) !void {
    var buffer = [_]u8{0} ** (1024 * 1024);
    var fbs = std.io.fixedBufferStream(&buffer);
    var writer = fbs.writer();
    try writer.writeAll("SyscallInvocation {");
    try std.fmt.format(writer, "\n\tfunction_name: {s}", .{ctx.function_name});
    try std.fmt.format(writer, ",\n\theap_prefix: {any}", .{ctx.heap_prefix});
    try std.fmt.format(writer, ",\n\tstack_prefix: {any}", .{ctx.stack_prefix});
    try writer.writeAll("\n}\n");
    std.debug.print("{s}", .{writer.context.getWritten()});
}

pub fn printPbSyscallContext(pb_syscall_ctx: pb.SyscallContext) !void {
    const pb_instr = pb_syscall_ctx.instr_ctx orelse
        return error.NoInstrCtx;
    const pb_vm = pb_syscall_ctx.vm_ctx orelse
        return error.NoVmCtx;
    const pb_syscall_invocation = pb_syscall_ctx.syscall_invocation orelse
        return error.NoSyscallInvocation;
    try printPbInstrContext(pb_instr);
    try printPbVmContext(pb_vm);
    try printPbSyscallInvocation(pb_syscall_invocation);
}

pub fn printPbSyscallEffects(ctx: pb.SyscallEffects) !void {
    var buffer = [_]u8{0} ** (1024 * 1024);
    var fbs = std.io.fixedBufferStream(&buffer);
    var writer = fbs.writer();
    try writer.writeAll("SyscallEffects {");
    try std.fmt.format(writer, "\n\terror: {}", .{ctx.@"error"});
    try std.fmt.format(writer, ",\n\terr_kind: {}", .{ctx.error_kind});
    try std.fmt.format(writer, ",\n\tr0: {}", .{ctx.r0});
    try std.fmt.format(writer, ",\n\tcu_avail: {}", .{ctx.cu_avail});
    try std.fmt.format(writer, ",\n\theap.len: {}", .{ctx.heap.len});
    try std.fmt.format(writer, ",\n\tstack.len: {}", .{ctx.stack.len});
    try std.fmt.format(writer, ",\n\tinput_data_regions: [", .{});
    for (ctx.input_data_regions.items) |region| {
        try writer.writeAll("\n\t\tInputDataRegion {");
        try std.fmt.format(writer, "\n\t\t\toffset: {}", .{region.offset});
        try std.fmt.format(writer, ",\n\t\t\tcontent.len: {}", .{region.content.len});
        try std.fmt.format(writer, ",\n\t\t\tis_writable: {}", .{region.is_writable});
        try writer.writeAll("\n\t\t},\n");
    }
    try writer.writeAll("\t],");
    try std.fmt.format(writer, "\n\tframe_count: {}", .{ctx.frame_count});
    try std.fmt.format(writer, ",\n\tlog: {s}", .{ctx.log});
    try std.fmt.format(writer, ",\n\trodata.len: {}", .{ctx.rodata.len});
    try std.fmt.format(writer, ",\n\tpc: {}", .{ctx.pc});
    try std.fmt.format(writer, ",\n\tr1: {}", .{ctx.r1});
    try std.fmt.format(writer, ",\n\tr2: {}", .{ctx.r2});
    try std.fmt.format(writer, ",\n\tr3: {}", .{ctx.r3});
    try std.fmt.format(writer, ",\n\tr4: {}", .{ctx.r4});
    try std.fmt.format(writer, ",\n\tr5: {}", .{ctx.r5});
    try std.fmt.format(writer, ",\n\tr6: {}", .{ctx.r6});
    try std.fmt.format(writer, ",\n\tr7: {}", .{ctx.r7});
    try std.fmt.format(writer, ",\n\tr8: {}", .{ctx.r8});
    try std.fmt.format(writer, ",\n\tr9: {}", .{ctx.r9});
    try std.fmt.format(writer, ",\n\tr10: {}", .{ctx.r10});
    try writer.writeAll("\n}\n");
    std.debug.print("{s}", .{writer.context.getWritten()});
}
