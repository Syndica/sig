const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const std = @import("std");
const sig = @import("sig");
const utils = @import("utils.zig");

const ELFLoaderCtx = pb.ELFLoaderCtx;
const ElfLoaderEffects = pb.ELFLoaderEffects;

const svm = sig.vm;
const elf = svm.elf;

const xxhash = std.hash.XxHash64.hash;

pub export fn sol_compat_elf_loader_v1(
    out_ptr: [*]u8,
    out_size: *u64,
    in_ptr: [*]const u8,
    in_size: u64,
) i32 {
    testAndHandleIO(out_ptr, out_size, in_ptr, in_size) catch |e| {
        std.debug.print("error: {s}\n", .{@errorName(e)});
        return 0;
    };
    return 1;
}

fn testAndHandleIO(
    out_ptr: [*]u8,
    out_size: *u64,
    in_ptr: [*]const u8,
    in_size: u64,
) !void {
    const allocator = std.heap.c_allocator;

    // zig_protobuf leaks sometimes on invalid input, so we just work around with by using an arena
    var decode_arena = std.heap.ArenaAllocator.init(allocator);
    defer decode_arena.deinit();

    const in_slice = in_ptr[0..in_size];
    var in_reader: std.Io.Reader = .fixed(in_slice);

    var ctx = try ELFLoaderCtx.decode(&in_reader, decode_arena.allocator());
    defer ctx.deinit(decode_arena.allocator());

    var effects = try executeElfTest(ctx, allocator);
    defer effects.deinit(allocator);

    var writer: std.Io.Writer.Allocating = .init(allocator);
    defer writer.deinit();
    try effects.encode(&writer.writer, allocator);
    const effects_bytes = writer.written();

    const out_slice = out_ptr[0..out_size.*];
    if (effects_bytes.len > out_slice.len) {
        std.debug.print("out_slice.len: {d} < effects_bytes.len: {d}\n", .{
            out_slice.len,
            effects_bytes.len,
        });
        return error.OutputTooSmall;
    }
    @memcpy(out_slice[0..effects_bytes.len], effects_bytes);
    out_size.* = effects_bytes.len;
}

fn executeElfTest(ctx: ELFLoaderCtx, allocator: std.mem.Allocator) !ElfLoaderEffects {
    const elf_bytes = ctx.elf_data;

    const feature_set = try utils.loadFeatureSet(ctx);

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
            .err_code = ebpfErrToCode(err),
            .calldests_hash = 0,
        };
    };
    defer executable.deinit(allocator);

    const ro_data = switch (executable.ro_section) {
        .owned => |o| o.data,
        .borrowed => |a| executable.bytes[a.start..a.end],
    };

    const calldests_hash: u64 = blk: {
        var calldests_map = std.AutoHashMapUnmanaged(u64, void).empty;
        defer calldests_map.deinit(allocator);
        var map_iter = executable.function_registry.map.iterator();
        while (map_iter.next()) |entry| {
            const fn_addr = entry.value_ptr.value;
            try calldests_map.put(allocator, fn_addr, {});
        }
        var calldests = std.ArrayList(u64).empty;
        defer calldests.deinit(allocator);
        var iter = calldests_map.keyIterator();
        while (iter.next()) |key| {
            try calldests.append(allocator, key.*);
        }
        std.sort.heap(u64, calldests.items, {}, std.sort.asc(u64));
        break :blk xxhash(0, std.mem.sliceAsBytes(calldests.items));
    };

    return .{
        .err_code = 0,
        .rodata_hash = xxhash(0, ro_data),
        .text_cnt = executable.instructions.len,
        .text_off = executable.text_vaddr -| svm.memory.RODATA_START,
        .entry_pc = executable.entry_pc,
        .calldests_hash = calldests_hash,
    };
}

fn ebpfErrToCode(err: elf.LoadError) u32 {
    return switch (err) {
        error.InvalidSectionHeader,
        error.Overlap,
        error.InvalidSize,
        error.InvalidFileHeader,
        error.SectionNotInOrder,
        error.InvalidAlignment,
        error.StringTooLong,
        error.InvalidDynamicSectionTable,
        error.NoSectionNameStringTable,
        error.InvalidRelocationTable,
        error.NoStringTable,
        error.InvalidString,
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
        error.OutOfMemory => 21, // internal failure, map to ValueOutOfBounds
        else => unreachable,
    };
}
