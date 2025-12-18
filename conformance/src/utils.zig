const std = @import("std");
const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const sig = @import("sig");

const ManagedString = @import("protobuf").ManagedString;

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
) !void {
    const feature_set = if (environment.feature_set) |ptr|
        ptr
    else
        try allocator.create(FeatureSet);
    feature_set.* = try createFeatureSet(instr_ctx);

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

    tc.* = TransactionContext{
        .allocator = allocator,
        .feature_set = feature_set,
        .epoch_stakes = epoch_stakes,
        .sysvar_cache = sysvar_cache,
        .vm_environment = vm_environment,
        .next_vm_environment = vm_environment,
        .program_map = program_map,
        .accounts = try createTransactionContextAccounts(
            allocator,
            instr_ctx.accounts.items,
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
        .slot = if (instr_ctx.slot_context) |slot_ctx| slot_ctx.slot else 0,
    };
    errdefer comptime unreachable;

    if (sysvar_cache.get(sysvar.RecentBlockhashes) catch null) |recent_blockhashes| {
        if (recent_blockhashes.entries.len > 0) {
            const prev_entry = recent_blockhashes.entries.get(recent_blockhashes.entries.len - 1);
            tc.prev_blockhash = prev_entry.blockhash;
            tc.prev_lamports_per_signature = prev_entry.lamports_per_signature;
        }
    }
}

pub fn deinitTransactionContext(
    allocator: std.mem.Allocator,
    tc: TransactionContext,
) void {
    allocator.destroy(tc.feature_set);
    allocator.destroy(tc.vm_environment);

    tc.epoch_stakes.deinit(allocator);
    allocator.destroy(tc.epoch_stakes);

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

pub fn createFeatureSet(pb_ctx: pb.InstrContext) !FeatureSet {
    errdefer |err| {
        std.debug.print("createFeatureSet: error={}\n", .{err});
    }

    const pb_epoch_context = pb_ctx.epoch_context orelse return FeatureSet.ALL_DISABLED;
    const pb_feature_set = pb_epoch_context.features orelse return FeatureSet.ALL_DISABLED;

    var feature_set: FeatureSet = .ALL_DISABLED;
    for (pb_feature_set.features.items) |id| {
        // only way for `setSlotId` to return an error is if the `id` didn't match.
        feature_set.setSlotId(id, 0) catch continue;
    }
    return feature_set;
}

const AccountSharedData = sig.runtime.AccountSharedData;

pub fn createTransactionContextAccounts(
    allocator: std.mem.Allocator,
    pb_accounts: []const pb.AcctState,
) ![]TransactionContextAccount {
    errdefer |err| {
        std.debug.print("createTransactionContextAccounts: error={}\n", .{err});
    }

    var accounts = std.ArrayList(TransactionContextAccount).init(allocator);
    errdefer {
        for (accounts.items) |account| {
            allocator.free(account.account.data);
            allocator.destroy(account.account);
        }
        accounts.deinit();
    }

    for (pb_accounts) |pb_account| {
        const account_data = try allocator.dupe(u8, pb_account.data.getSlice());
        errdefer allocator.free(account_data);

        if (pb_account.owner.getSlice().len != Pubkey.SIZE) return error.OutOfBounds;
        if (pb_account.address.getSlice().len != Pubkey.SIZE) return error.OutOfBounds;

        const account_ptr = try allocator.create(AccountSharedData);
        account_ptr.* = .{
            .lamports = pb_account.lamports,
            .data = account_data,
            .owner = .{ .data = pb_account.owner.getSlice()[0..Pubkey.SIZE].* },
            .executable = pb_account.executable,
            .rent_epoch = sig.core.rent_collector.RENT_EXEMPT_RENT_EPOCH,
        };

        try accounts.append(
            TransactionContextAccount.init(
                .{ .data = pb_account.address.getSlice()[0..Pubkey.SIZE].* },
                account_ptr,
            ),
        );
    }

    return accounts.toOwnedSlice();
}

pub fn createInstructionInfo(
    allocator: std.mem.Allocator,
    tc: *const TransactionContext,
    program_id: Pubkey,
    instruction: []const u8,
    pb_instruction_accounts: []const pb.InstrAcct,
) !InstructionInfo {
    errdefer |err| {
        std.debug.print("createInstructionInfo: error={}\n", .{err});
    }

    const program_index_in_transaction =
        tc.getAccountIndex(program_id) orelse return error.CouldNotFindProgram;

    var dedupe_map: [InstructionInfo.MAX_ACCOUNT_METAS]u8 = @splat(0xff);
    for (pb_instruction_accounts, 0..) |acc, idx| {
        if (dedupe_map[acc.index] == 0xff)
            dedupe_map[acc.index] = @intCast(idx);
    }

    var instruction_accounts = InstructionInfo.AccountMetas{};
    defer instruction_accounts.deinit(allocator);

    for (pb_instruction_accounts) |account| {
        const tc_acc = tc.getAccountAtIndex(@intCast(account.index)) orelse
            return error.AccountNotInTransaction;
        try instruction_accounts.append(allocator, .{
            .pubkey = tc_acc.pubkey,
            .index_in_transaction = @intCast(account.index),
            .is_signer = account.is_signer,
            .is_writable = account.is_writable,
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
        sysvar_cache.rent = try sysvar.serialize(
            allocator,
            sysvar.Rent.INIT,
        );
    }

    sysvar_cache.last_restart_slot = try cloneSysvarData(allocator, ctx, sysvar.LastRestartSlot.ID);
    if (std.meta.isError(sysvar_cache.get(sysvar.LastRestartSlot))) {
        sysvar_cache.last_restart_slot = try sysvar.serialize(
            allocator,
            sysvar.LastRestartSlot{
                .last_restart_slot = 5000,
            },
        );
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
        if (acc.lamports > 0 and std.mem.eql(u8, acc.address.getSlice(), &pubkey.data)) {
            return try allocator.dupe(u8, acc.data.getSlice());
        }
    }
    return null;
}

pub fn createInstrEffects(
    allocator: std.mem.Allocator,
    tc: *const TransactionContext,
    result: ?InstructionError,
) !pb.InstrEffects {
    return pb.InstrEffects{
        .result = if (result) |err| intFromInstructionError(err) else 0,
        .custom_err = tc.custom_error orelse 0,
        .modified_accounts = try modifiedAccounts(allocator, tc),
        .cu_avail = tc.compute_meter,
        .return_data = try ManagedString.copy(
            tc.return_data.data.constSlice(),
            allocator,
        ),
    };
}

fn modifiedAccounts(
    allocator: std.mem.Allocator,
    tc: *const TransactionContext,
) !std.ArrayList(pb.AcctState) {
    var accounts = std.ArrayList(pb.AcctState).init(allocator);
    errdefer accounts.deinit();

    for (tc.accounts) |acc| {
        try accounts.append(.{
            .address = try ManagedString.copy(
                &acc.pubkey.data,
                allocator,
            ),
            .lamports = acc.account.lamports,
            .data = try ManagedString.copy(
                acc.account.data,
                allocator,
            ),
            .executable = acc.account.executable,
            .owner = try ManagedString.copy(
                &acc.account.owner.data,
                allocator,
            ),
        });
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
}) !pb.SyscallEffects {
    var log = std.ArrayList(u8).init(allocator);
    defer log.deinit();
    if (params.tc.log_collector) |log_collector| {
        var iter = log_collector.iterator();
        while (iter.next()) |msg| {
            try log.appendSlice(msg);
            try log.append('\n');
        }
        if (log.items.len > 0) _ = log.pop();
    }

    const input_data_regions = try extractInputDataRegions(
        allocator,
        params.memory_map,
    );

    return .{
        .@"error" = params.err,
        .error_kind = params.err_kind,
        .cu_avail = params.tc.compute_meter,
        .heap = try ManagedString.copy(params.heap, allocator),
        .stack = try ManagedString.copy(params.stack, allocator),
        .inputdata = .Empty, // Deprecated
        .input_data_regions = input_data_regions,
        .frame_count = params.frame_count,
        .log = try ManagedString.copy(log.items, allocator),
        .rodata = try ManagedString.copy(params.rodata, allocator),
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
    var regions = std.ArrayList(pb.InputDataRegion).init(allocator);
    errdefer regions.deinit();

    const mm_regions: []const sig.vm.memory.Region = switch (memory_map) {
        .aligned => |amm| amm.regions,
        .unaligned => |umm| umm.regions,
    };

    for (mm_regions) |region| {
        if (region.vm_addr_start >= memory.INPUT_START) {
            try regions.append(.{
                .offset = region.vm_addr_start - memory.INPUT_START,
                .is_writable = switch (region.host_memory) {
                    .constant => false,
                    .mutable => true,
                },
                .content = try ManagedString.copy(region.constSlice(), allocator),
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
        Pubkey{ .data = ctx.program_id.getSlice()[0..Pubkey.SIZE].* },
    });
    try writer.writeAll(",\n\taccounts: [");
    for (ctx.accounts.items) |acc| {
        try writer.writeAll("\n\t\tAcctState {");
        try std.fmt.format(writer, "\n\t\t\taddress: {any}", .{
            Pubkey{ .data = acc.address.getSlice()[0..Pubkey.SIZE].* },
        });
        try std.fmt.format(writer, ",\n\t\t\tlamports: {d}", .{acc.lamports});
        try std.fmt.format(writer, ",\n\t\t\tdata.len: {any}", .{acc.data.getSlice().len});
        try std.fmt.format(writer, ",\n\t\t\texecutable: {}", .{acc.executable});
        try std.fmt.format(writer, ",\n\t\t\towner: {any}", .{
            Pubkey{ .data = acc.owner.getSlice()[0..Pubkey.SIZE].* },
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
    try std.fmt.format(writer, "\t],\n\tdata: {any}", .{ctx.data.getSlice()});
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
            Pubkey{ .data = acc.address.getSlice()[0..Pubkey.SIZE].* },
        });
        try std.fmt.format(writer, ",\n\t\t\tlamports: {d}", .{acc.lamports});
        try std.fmt.format(writer, ",\n\t\t\tdata: {any}", .{acc.data.getSlice()});
        try std.fmt.format(writer, ",\n\t\t\texecutable: {}", .{acc.executable});
        try std.fmt.format(writer, ",\n\t\t\towner: {}", .{
            Pubkey{ .data = acc.owner.getSlice()[0..Pubkey.SIZE].* },
        });
        try writer.writeAll("\n\t\t},\n");
    }
    try writer.writeAll("\t],");
    try std.fmt.format(writer, ",\n\tcu_avail: {d}", .{effects.cu_avail});
    try std.fmt.format(writer, ",\n\treturn_data: {any}", .{effects.return_data.getSlice()});
    try writer.writeAll("\n}\n");
    std.debug.print("{s}", .{writer.context.getWritten()});
}

pub fn printPbVmContext(ctx: pb.VmContext) !void {
    var buffer = [_]u8{0} ** (1024 * 1024);
    var fbs = std.io.fixedBufferStream(&buffer);
    var writer = fbs.writer();
    try writer.writeAll("VmContext {");
    try std.fmt.format(writer, "\n\theap_max: {}", .{ctx.heap_max});
    try std.fmt.format(writer, ",\n\trodata: {any}", .{ctx.rodata.getSlice()});
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
    try std.fmt.format(writer, ",\n\tcall_whitelist: {any}", .{ctx.call_whitelist.getSlice()});
    try std.fmt.format(writer, ",\n\ttracing_enabled: {}", .{ctx.tracing_enabled});
    try std.fmt.format(writer, ",\n\treturn_data: ", .{});
    if (ctx.return_data) |rd| {
        try std.fmt.format(writer, "{{\n\t\tprogram_id: {},\n\t\tdata: {any}\n\t}}", .{
            Pubkey{ .data = rd.program_id.getSlice()[0..Pubkey.SIZE].* },
            rd.data.getSlice(),
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
    try std.fmt.format(writer, "\n\tfunction_name: {s}", .{ctx.function_name.getSlice()});
    try std.fmt.format(writer, ",\n\theap_prefix: {any}", .{ctx.heap_prefix.getSlice()});
    try std.fmt.format(writer, ",\n\tstack_prefix: {any}", .{ctx.stack_prefix.getSlice()});
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
    try std.fmt.format(writer, ",\n\theap.len: {}", .{ctx.heap.getSlice().len});
    try std.fmt.format(writer, ",\n\tstack.len: {}", .{ctx.stack.getSlice().len});
    // try std.fmt.format(writer, ",\n\tinputdata: {any}", .{ctx.inputdata.getSlice()}); // Deprecated
    try std.fmt.format(writer, ",\n\tinput_data_regions: [", .{});
    for (ctx.input_data_regions.items) |region| {
        try writer.writeAll("\n\t\tInputDataRegion {");
        try std.fmt.format(writer, "\n\t\t\toffset: {}", .{region.offset});
        try std.fmt.format(writer, ",\n\t\t\tcontent.len: {}", .{region.content.getSlice().len});
        try std.fmt.format(writer, ",\n\t\t\tis_writable: {}", .{region.is_writable});
        try writer.writeAll("\n\t\t},\n");
    }
    try writer.writeAll("\t],");
    try std.fmt.format(writer, "\n\tframe_count: {}", .{ctx.frame_count});
    try std.fmt.format(writer, ",\n\tlog: {s}", .{ctx.log.getSlice()});
    try std.fmt.format(writer, ",\n\trodata.len: {}", .{ctx.rodata.getSlice().len});
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
