const std = @import("std");
const sig = @import("sig");
const pb = @import("proto/org/solana/sealevel/v1.pb.zig");

const ELFLoaderCtx = pb.ELFLoaderCtx;
const ElfLoaderEffects = pb.ELFLoaderEffects;

const svm = sig.vm;
const elf = svm.elf;

export fn sol_compat_elf_loader_v1(
    out_ptr: [*]u8,
    out_size: *u64,
    in_ptr: [*]const u8,
    in_size: u64,
) i32 {
    errdefer |err| std.debug.panic("err: {s}", .{@errorName(err)});
    const allocator = std.heap.c_allocator;

    _ = &allocator;

    // zig_protobuf leaks sometimes on invalid input, so we just work around with by using an arena
    var decode_arena = std.heap.ArenaAllocator.init(allocator);
    defer decode_arena.deinit();

    var reader = std.io.Reader.fixed(in_ptr[0..in_size]);
    var ctx = ELFLoaderCtx.decode(&reader, decode_arena.allocator()) catch return 0;
    defer ctx.deinit(decode_arena.allocator());

    var elf_effects = executeElfTest(ctx, allocator) catch return 0;
    defer elf_effects.deinit(allocator);

    var writer: std.io.Writer.Allocating = .init(allocator);
    defer writer.deinit();
    try elf_effects.encode(&writer.writer, allocator);
    const effect_bytes = writer.written();

    const out_slice = out_ptr[0..out_size.*];
    if (effect_bytes.len > out_slice.len) return 0;

    @memcpy(out_slice[0..effect_bytes.len], effect_bytes);
    out_size.* = effect_bytes.len;
    return 1;
}

fn executeElfTest(ctx: ELFLoaderCtx, allocator: std.mem.Allocator) !ElfLoaderEffects {
    const ctx_elf = ctx.elf orelse return error.Unknown;
    const elf_bytes = ctx_elf.data;

    var feature_set: sig.core.FeatureSet = .ALL_DISABLED;
    if (ctx.features) |features| for (features.features.items) |id| {
        feature_set.setSlotId(id, 0) catch std.debug.panic("unknown id: 0x{x}", .{id});
    };

    const env: svm.Environment = .initV1(
        &feature_set,
        &.DEFAULT,
        0,
        ctx.deploy_checks,
    );

    const duped_elf_bytes = try allocator.dupe(u8, elf_bytes);
    defer allocator.free(duped_elf_bytes);

    var executable = elf.load(
        allocator,
        duped_elf_bytes,
        &env.loader,
        env.config,
    ) catch |err| {
        return .{
            .@"error" = ebpfErrToCode(err),
            .calldests = .{},
        };
    };
    defer executable.deinit(allocator);

    const ro_data = switch (executable.ro_section) {
        .owned => |o| o.data,
        .borrowed => |a| executable.bytes[a.start..a.end],
    };

    var elf_effects: ElfLoaderEffects = .{
        .@"error" = 0,
        .rodata = try allocator.dupe(u8, ro_data),
        .rodata_sz = ro_data.len,
        .entry_pc = executable.entry_pc,
        .text_off = executable.text_vaddr -| svm.memory.RODATA_START,
        .text_cnt = executable.instructions.len,
        .calldests = .{},
    };

    var calldests: std.AutoHashMapUnmanaged(u64, void) = .{};
    defer calldests.deinit(allocator);
    var map_iter = executable.function_registry.map.iterator();
    while (map_iter.next()) |entry| {
        const fn_addr = entry.value_ptr.value;
        try calldests.put(allocator, fn_addr, {});
    }
    var iter = calldests.keyIterator();
    while (iter.next()) |key| {
        try elf_effects.calldests.append(allocator, key.*);
    }
    std.sort.heap(u64, elf_effects.calldests.items, {}, std.sort.asc(u64));

    return elf_effects;
}

fn ebpfErrToCode(err: elf.LoadError) i32 {
    return switch (err) {
        error.InvalidSectionHeader,
        error.Overlap,
        error.InvalidSize,
        error.InvalidFileHeader,
        error.SectionNotInOrder,
        error.InvalidAlignment,
        error.StringTooLong,
        error.InvalidDynamicSectionTable,
        => 1,
        error.EntrypointOutOfBounds => 2,
        error.InvalidEntrypoint => 3,
        // error.FailedToGetSection => 4,
        error.UnresolvedSymbol => 5,
        error.SectionNotFound => 6,
        error.RelativeJumpOutOfBounds => 7,
        error.SymbolHashCollision => 8,
        error.WrongEndianess => 9,
        error.WrongAbi => 10,
        error.WrongMachine => 11,
        error.WrongClass => 12,
        error.NotOneTextSection => 13,
        error.WritableSectionNotSupported => 14,
        // error.AddressOutsideLoadableSection => 15,
        error.InvalidVirtualAddress => 16,
        error.UnknownRelocation => 17,
        // error.FailedToReadRelocationInfo => 18,
        error.WrongType => 19,
        error.UnknownSymbol => 20,
        error.OutOfBounds => 21,
        error.UnsupportedSBPFVersion => 22,
        error.InvalidProgramHeader => 23,
        else => unreachable,
    };
}
