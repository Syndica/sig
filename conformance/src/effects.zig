const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const sig = @import("sig");
const std = @import("std");

const memory = sig.vm.memory;

const ManagedString = @import("protobuf").ManagedString;

const InstructionError = sig.core.instruction.InstructionError;
const TransactionContext = sig.runtime.transaction_context.TransactionContext;

const intFromInstructionError = sig.core.instruction.intFromInstructionError;

pub fn createInstrEffects(
    allocator: std.mem.Allocator,
    transaction_context: *const TransactionContext,
    maybe_instruction_error: ?InstructionError,
) !pb.InstrEffects {
    const result = if (maybe_instruction_error) |err|
        intFromInstructionError(err)
    else
        0;

    const modified_accounts = try getModifiedAccounts(
        allocator,
        transaction_context,
    );

    const return_data = try ManagedString.copy(
        transaction_context.return_data.data.constSlice(),
        allocator,
    );

    return pb.InstrEffects{
        .result = result,
        .custom_err = transaction_context.custom_error orelse 0,
        .modified_accounts = modified_accounts,
        .cu_avail = transaction_context.compute_meter,
        .return_data = return_data,
    };
}

fn getModifiedAccounts(
    allocator: std.mem.Allocator,
    transaction_context: *const TransactionContext,
) !std.ArrayList(pb.AcctState) {
    var accounts = std.ArrayList(pb.AcctState).init(allocator);
    errdefer accounts.deinit();

    for (transaction_context.accounts) |acc| {
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
            .rent_epoch = acc.account.rent_epoch,
            .owner = try ManagedString.copy(
                &acc.account.owner.data,
                allocator,
            ),
        });
    }

    return accounts;
}

pub fn createSyscallEffects(allocator: std.mem.Allocator, params: struct {
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
        for (log_collector.collect()) |msg| {
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
        pub fn lessThan(_: void, a: pb.InputDataRegion, b: pb.InputDataRegion) bool {
            return a.offset < b.offset;
        }
    }.lessThan);

    return regions;
}
