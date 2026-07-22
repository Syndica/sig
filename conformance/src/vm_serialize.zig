const std = @import("std");
const sig = @import("sig");
const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const utils = @import("utils.zig");

const serialize = sig.runtime.program.bpf.serialize;
const executor = sig.runtime.executor;

const Pubkey = sig.core.Pubkey;
const TransactionContext = sig.runtime.transaction_context.TransactionContext;

/// VM parameter serialization conformance harness.
///
/// Mirrors agave's `sol_compat_vm_serialize_execute_v1` (and the equivalent in
/// solfuzz-agave) by decoding an `InstrContext`, pushing a single top-level
/// instruction, and reporting the serialized program-input region.
///
/// [agave] https://github.com/anza-xyz/agave/blob/master/svm/src/conformance/serialization.rs
/// [solfuzz-agave]
/// https://github.com/firedancer-io/solfuzz-agave/blob/agave-v4.1.0-beta.3/src/vm_serialization.rs
pub export fn sol_compat_vm_serialize_execute_v1(
    out_ptr: [*]u8,
    out_size: *u64,
    in_ptr: [*]const u8,
    in_size: u64,
) i32 {
    var arena = std.heap.ArenaAllocator.init(std.heap.c_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const in_slice = in_ptr[0..in_size];
    var reader: std.Io.Reader = .fixed(in_slice);
    const pb_instr_ctx = pb.InstrContext.decode(&reader, allocator) catch |err| {
        std.debug.print("pb.InstrContext.decode: {s}\n", .{@errorName(err)});
        return 0;
    };

    const effects = serializeInstruction(allocator, pb_instr_ctx) catch |err| {
        std.debug.print("serializeInstruction: {s}\n", .{@errorName(err)});
        return 0;
    };

    var writer: std.Io.Writer.Allocating = .init(allocator);
    effects.encode(&writer.writer, allocator) catch |err| {
        std.debug.print("effects.encode: {s}\n", .{@errorName(err)});
        return 0;
    };
    const result_bytes = writer.written();

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

fn serializeInstruction(
    allocator: std.mem.Allocator,
    pb_instr_ctx: pb.InstrContext,
) !pb.VMSerializationEffects {
    var tc: TransactionContext = undefined;
    const compiled_message = try utils.createTransactionContext(allocator, pb_instr_ctx, .{}, &tc);
    defer compiled_message.deinit(allocator);
    defer utils.deinitTransactionContext(allocator, tc);

    if (pb_instr_ctx.program_id.len != Pubkey.SIZE) return error.OutOfBounds;
    const program_id: Pubkey = .{ .data = pb_instr_ctx.program_id[0..Pubkey.SIZE].* };

    const instr_info = try utils.createInstructionInfo(
        allocator,
        &tc,
        program_id,
        pb_instr_ctx.data,
        pb_instr_ctx.instr_accounts.items,
        compiled_message,
    );
    defer instr_info.deinit(allocator);

    // serializeParameters needs an active instruction frame so it can borrow
    // the program account to decide between the aligned/unaligned layouts.
    executor.pushInstruction(&tc, instr_info) catch @panic("pushInstruction failed");

    const ic = try tc.getCurrentInstructionContext();

    const slot = tc.slot;
    const direct_mapping = tc.feature_set.active(.account_data_direct_mapping, slot);
    const virtual_address_space_adjustments =
        tc.feature_set.active(.virtual_address_space_adjustments, slot);
    const direct_account_pointers_in_program_input =
        tc.feature_set.active(.direct_account_pointers_in_program_input, slot);

    var serialized = serialize.serializeParameters(
        allocator,
        ic,
        direct_mapping,
        virtual_address_space_adjustments,
        direct_account_pointers_in_program_input,
    ) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return errorEffects(),
    };
    defer serialized.deinit(allocator);

    var input_memory_regions: std.ArrayListUnmanaged(pb.VMInputMemoryRegion) = .empty;
    try input_memory_regions.ensureTotalCapacityPrecise(allocator, serialized.regions.items.len);
    for (serialized.regions.items) |region| {
        const slice = region.constSlice();
        input_memory_regions.appendAssumeCapacity(.{
            .vm_address = region.vm_addr_start,
            .region_size = slice.len,
            .is_writable = region.host_memory == .mutable,
        });
    }

    var account_metadata: std.ArrayListUnmanaged(pb.VMSerializedAccountMetadata) = .empty;
    try account_metadata.ensureTotalCapacityPrecise(allocator, serialized.account_metas.len);
    for (serialized.account_metas.constSlice()) |meta| {
        account_metadata.appendAssumeCapacity(.{
            .original_data_len = meta.original_data_len,
            .vm_data_addr = meta.vm_data_addr,
            .vm_key_addr = meta.vm_key_addr,
            .vm_lamports_addr = meta.vm_lamports_addr,
            .vm_owner_addr = meta.vm_owner_addr,
        });
    }

    return .{
        .has_error = false,
        .serialized_memory_hash = std.hash.XxHash64.hash(0, serialized.memory.items),
        .vm_input_memory_regions = input_memory_regions,
        .serialized_account_metadata = account_metadata,
    };
}

fn errorEffects() pb.VMSerializationEffects {
    return .{ .has_error = true };
}
