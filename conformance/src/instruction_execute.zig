const std = @import("std");
const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const sig = @import("sig");
const utils = @import("utils.zig");

const executor = sig.runtime.executor;
const sysvar = sig.runtime.sysvar;
const program_loader = sig.runtime.program_loader;

const AccountMap = sig.runtime.account_loader.BatchAccountCache.AccountMap;
const Pubkey = sig.core.Pubkey;
const AccountSharedData = sig.runtime.AccountSharedData;
const InstructionError = sig.core.instruction.InstructionError;
const TransactionContext = sig.runtime.transaction_context.TransactionContext;
const ProgramMap = sig.runtime.program_loader.ProgramMap;

const EMIT_LOGS = false;

/// [fd] https://github.com/firedancer-io/firedancer/blob/0ad2143a9960b7daa5eb594367835d0cbae25657/src/flamenco/runtime/tests/fd_exec_sol_compat.c#L591
/// [solfuzz-agave] https://github.com/firedancer-io/solfuzz-agave/blob/98f939ba8afcb1b7a5af4316c6085f92111b62a7/src/lib.rs#L1043
export fn sol_compat_instr_execute_v1(
    out_ptr: [*]u8,
    out_size: *u64,
    in_ptr: [*]const u8,
    in_size: u64,
) i32 {
    errdefer |err| std.debug.panic("err: {s}", .{@errorName(err)});
    const allocator = std.heap.c_allocator;

    var decode_arena = std.heap.ArenaAllocator.init(allocator);
    defer decode_arena.deinit();

    const in_slice = in_ptr[0..in_size];
    var pb_instr_ctx = pb.InstrContext.decode(
        in_slice,
        decode_arena.allocator(),
    ) catch |err| {
        std.debug.print("pb.InstrContext.decode: {s}\n", .{@errorName(err)});
        return 0;
    };
    defer pb_instr_ctx.deinit();

    // utils.printPbInstrContext(pb_instr_ctx) catch |err| {
    //     std.debug.print("printPbInstrContext: {s}\n", .{@errorName(err)});
    //     return 0;
    // };

    const result = executeInstruction(allocator, pb_instr_ctx, EMIT_LOGS) catch |err| {
        std.debug.print("executeInstruction: {s}\n", .{@errorName(err)});
        return 0;
    };

    // printPbInstrEffects(result) catch |err| {
    //     std.debug.print("printPbInstrEffects: {s}\n", .{@errorName(err)});
    //     return 0;
    // };

    const result_bytes = try result.encode(allocator);
    defer allocator.free(result_bytes);

    const out_slice = out_ptr[0..out_size.*];
    if (result_bytes.len > out_slice.len) {
        std.debug.print("out_slice.len: {d} < result_bytes.len: {d}\n", .{
            out_slice.len,
            result_bytes.len,
        });
        return 0;
    }
    @memcpy(out_slice[0..result_bytes.len], result_bytes);
    out_size.* = result_bytes.len;

    return 1;
}

fn executeInstruction(
    allocator: std.mem.Allocator,
    pb_instr_ctx: pb.InstrContext,
    emit_logs: bool,
) !pb.InstrEffects {
    const vm_environment: *sig.vm.Environment = try allocator.create(sig.vm.Environment);
    const program_map: *ProgramMap = try allocator.create(ProgramMap);

    var tc: TransactionContext = undefined;
    try utils.createTransactionContext(
        allocator,
        pb_instr_ctx,
        .{
            .program_map = program_map,
            .vm_environment = vm_environment,
        },
        &tc,
    );
    defer utils.deinitTransactionContext(allocator, tc);

    // Create an accounts map for loading programs, account data is owned by transaction context
    // so does not need to be freed
    var accounts_map = AccountMap{};
    errdefer accounts_map.deinit(allocator);
    for (tc.accounts) |tc_account| {
        try accounts_map.put(allocator, tc_account.pubkey, .{ .clean = tc_account.account.* });
    }

    // Override vm environment in the tc context
    vm_environment.* = try sig.vm.Environment.initV1(
        allocator,
        tc.feature_set,
        &tc.compute_budget,
        tc.slot,
        false,
        false,
    );

    // Load programs into the program map
    const clock = try tc.sysvar_cache.get(sysvar.Clock);
    program_map.* = try program_loader.loadPrograms(
        allocator,
        &accounts_map,
        vm_environment,
        clock.slot,
    );

    if (pb_instr_ctx.program_id.getSlice().len != Pubkey.SIZE) return error.OutOfBounds;
    const instr_info = try utils.createInstructionInfo(
        allocator,
        &tc,
        .{ .data = pb_instr_ctx.program_id.getSlice()[0..Pubkey.SIZE].* },
        pb_instr_ctx.data.getSlice(),
        pb_instr_ctx.instr_accounts.items,
    );
    defer instr_info.deinit(allocator);

    var result: ?InstructionError = null;
    executor.executeInstruction(allocator, &tc, instr_info) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => |e| result = e,
    };

    if (emit_logs) {
        std.debug.print("Execution Logs:\n", .{});
        for (tc.log_collector.?.collect(), 1..) |msg, index| {
            std.debug.print("    {}: {s}\n", .{ index, msg });
        }
    }

    // Special casing to return only the custom error for transactions which have
    // encountered the loader v4 program or bpf loader v3 migrate instruction.
    if (tc.custom_error == 0x30000000 or tc.custom_error == 0x40000000) {
        return .{
            .result = 0,
            .custom_err = tc.custom_error.?,
            .modified_accounts = .init(allocator),
            .cu_avail = 0,
            .return_data = .Empty,
        };
    }

    return utils.createInstrEffects(allocator, &tc, result);
}
