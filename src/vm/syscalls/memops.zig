const std = @import("std");
const sig = @import("../../sig.zig");

const memory = sig.vm.memory;
const syscalls = sig.vm.syscalls;

const SyscallError = sig.vm.SyscallError;
const RegisterMap = sig.vm.interpreter.RegisterMap;
const Error = syscalls.Error;
const MemoryMap = sig.vm.memory.MemoryMap;
const TransactionContext = sig.runtime.transaction_context.TransactionContext;
const features = sig.runtime.features;
const SerializedAccountMetadata = sig.runtime.program.bpf.serialize.SerializedAccountMeta;

const MemoryChunkIterator = struct {
    memory_map: *MemoryMap,
    accounts: []const SerializedAccountMetadata,
    initial_addr: u64,
    start: u64,
    end: u64,
    len: u64,
    account_index: ?u64,
    is_account: ?bool,
    resize_area: bool,
    reversed: bool,

    fn init(
        memory_map: *MemoryMap,
        accounts: []const SerializedAccountMetadata,
        vm_addr: u64,
        len: u64,
        resize_area: bool,
        reversed: bool,
    ) !MemoryChunkIterator {
        const vm_addr_end = std.math.add(u64, vm_addr, len) catch return error.AccessViolation;
        return .{
            .memory_map = memory_map,
            .accounts = accounts,
            .initial_addr = vm_addr,
            .len = len,
            .start = vm_addr,
            .end = vm_addr_end,
            .account_index = null,
            .is_account = null,
            .resize_area = resize_area,
            .reversed = reversed,
        };
    }

    fn next(self: *MemoryChunkIterator, comptime access: memory.MemoryState) !?Chunk {
        if (self.start == self.end) return null;

        const region = switch (self.reversed) {
            true => try self.memory_map.region(access, self.end -| 1),
            false => try self.memory_map.region(access, self.start),
        }.*;

        var region_is_account: bool = false;

        var account_index = self.account_index orelse switch (self.reversed) {
            true => self.accounts.len -| 1,
            false => 0,
        };
        self.account_index = account_index;

        while (true) {
            if (self.getAccount(account_index)) |account| {
                const account_addr = account.vm_data_addr;
                const resize_addr = account_addr +| account.original_data_len;

                if (self.reversed) {
                    if (account_index > 0 and account_addr > region.vm_addr_start) {
                        account_index -|= 1;
                        self.account_index = account_index;
                    } else {
                        region_is_account = (account.original_data_len != 0 and
                            region.vm_addr_start == account_addr)
                            // Unaligned programs don't have a resize area.
                            or (self.resize_area and region.vm_addr_start == resize_addr);
                        break;
                    }
                } else {
                    if (resize_addr < region.vm_addr_start) {
                        account_index +|= 1;
                        self.account_index = account_index;
                    } else {
                        region_is_account = (account.original_data_len != 0 and
                            region.vm_addr_start == account_addr)
                            // Unaligned programs don't have a resize area.
                            or (self.resize_area and region.vm_addr_start == resize_addr);
                        break;
                    }
                }
            } else {
                region_is_account = false;
                break;
            }
        }

        if (self.is_account) |is_account| {
            if (is_account != region_is_account) {
                return error.InvalidLength;
            }
        } else {
            self.is_account = region_is_account;
        }

        if (self.reversed) {
            if (region.vm_addr_start >= self.start) {
                const len = self.end -| region.vm_addr_start;
                self.end = region.vm_addr_start;
                return .{ region, self.end, len };
            } else {
                const len = self.end -| self.start;
                self.end = self.start;
                return .{ region, self.end, len };
            }
        } else {
            const vm_addr = self.start;
            if (region.vm_addr_end <= self.end) {
                const len = region.vm_addr_end -| self.start;
                self.start = region.vm_addr_end;
                return .{ region, vm_addr, len };
            } else {
                const len = self.end -| self.start;
                self.start = self.end;
                return .{ region, vm_addr, len };
            }
        }
    }

    fn getAccount(self: *MemoryChunkIterator, index: u64) ?SerializedAccountMetadata {
        if (index >= self.accounts.len) return null;
        return self.accounts[index];
    }
};

const Chunk = struct {
    memory.Region,
    /// addr
    u64,
    /// remaining
    u64,
};

fn iterateMemoryPairs(
    dst_addr: u64,
    comptime dst_state: memory.MemoryState,
    src_addr: u64,
    comptime src_state: memory.MemoryState,
    len: u64,
    memory_map: *MemoryMap,
    accounts: []const SerializedAccountMetadata,
    resize_area: bool,
    reverse: bool,
    Context: type,
    ctx: *Context,
) !void {
    var src_iter = try MemoryChunkIterator.init(
        memory_map,
        accounts,
        src_addr,
        len,
        resize_area,
        reverse,
    );
    var dst_iter = try MemoryChunkIterator.init(
        memory_map,
        accounts,
        dst_addr,
        len,
        resize_area,
        reverse,
    );

    var src_chunk: ?Chunk = null;
    var dst_chunk: ?Chunk = null;

    while (true) {
        // If we're still in a chunk, select that. Otherwise try to get the next chunk, and
        // if that fails, break out of the loop because we're done.
        src_chunk = src_chunk orelse (try src_iter.next(src_state)) orelse break;
        const src_region, const src_chunk_addr, const src_remaining = src_chunk.?;

        dst_chunk = dst_chunk orelse (try dst_iter.next(dst_state)) orelse break;
        const dst_region, const dst_chunk_addr, const dst_remaining = dst_chunk.?;

        const chunk_len = @min(src_remaining, dst_remaining);

        const src_vm_addr, const dst_vm_addr = if (reverse)
            .{
                src_chunk_addr +| src_remaining -| chunk_len,
                dst_chunk_addr +| dst_remaining -| chunk_len,
            }
        else
            .{ src_chunk_addr, dst_chunk_addr };

        const src_host = try memory_map.mapRegion(src_state, src_region, src_vm_addr, chunk_len);
        const dst_host = try memory_map.mapRegion(dst_state, dst_region, dst_vm_addr, chunk_len);

        try ctx.run(src_host, dst_host);

        src_chunk.?[2] -|= chunk_len;
        dst_chunk.?[2] -|= chunk_len;

        if (!reverse) {
            src_chunk.?[1] +|= chunk_len;
            dst_chunk.?[1] +|= chunk_len;
        }

        if (src_remaining == 0) src_chunk = null;
        if (dst_remaining == 0) dst_chunk = null;
    }
}

const MemmoveContext = struct {
    // memmove() is in Zig's compiler-rt, but not exposed via builtin or stdlib outside this symbol:
    // https://github.com/ziglang/zig/blob/79460d4a3eef8eb927b02a7eda8bc9999a766672/lib/compiler_rt/memmove.zig#L9-L22
    // TODO(0.15): Use `@memmove` builtin.
    extern fn memmove(dst: ?[*]u8, src: ?[*]const u8, len: usize) callconv(.c) ?[*]u8;

    fn run(_: *@This(), src: []const u8, dst: []u8) !void {
        std.debug.assert(dst.len == src.len);
        _ = @This().memmove(dst.ptr, src.ptr, src.len);
    }
};

fn memmoveNonContigious(
    dst_addr: u64,
    src_addr: u64,
    len: u64,
    accounts: []const SerializedAccountMetadata,
    memory_map: *MemoryMap,
    resize_area: bool,
) !void {
    const reverse = (dst_addr -% src_addr) < len;
    var ctx: MemmoveContext = .{};
    return iterateMemoryPairs(
        dst_addr,
        .mutable,
        src_addr,
        .constant,
        len,
        memory_map,
        accounts,
        resize_area,
        reverse,
        MemmoveContext,
        &ctx,
    );
}

fn memsetNonContigious(
    dst_addr: u64,
    c: u8,
    len: u64,
    accounts: []const SerializedAccountMetadata,
    memory_map: *MemoryMap,
    check_aligned: bool,
) !void {
    var dst_iter = try MemoryChunkIterator.init(
        memory_map,
        accounts,
        dst_addr,
        len,
        check_aligned,
        false,
    );

    while (try dst_iter.next(.mutable)) |chunk| {
        const dst_region, const dst_vm_addr, const dst_len = chunk;
        const dst_host = try memory_map.mapRegion(.mutable, dst_region, dst_vm_addr, dst_len);
        @memset(dst_host, c);
    }
}

const MemcmpContext = struct {
    result: i32,

    fn run(ctx: *MemcmpContext, s1: []const u8, s2: []const u8) !void {
        for (s1, s2) |a, b| {
            if (a != b) {
                ctx.result = @as(i32, a) -| @as(i32, b);
                return error.Diff;
            }
        }
        ctx.result = 0;
        return;
    }
};

fn memcmpNonContigious(
    src_addr: u64,
    dst_addr: u64,
    len: u64,
    accounts: []const SerializedAccountMetadata,
    memory_map: *MemoryMap,
    resize_area: bool,
) !i32 {
    var ctx: MemcmpContext = .{ .result = 0 };
    iterateMemoryPairs(
        dst_addr,
        .constant,
        src_addr,
        .constant,
        len,
        memory_map,
        accounts,
        resize_area,
        false,
        MemcmpContext,
        &ctx,
    ) catch |err| switch (err) {
        error.Diff => {},
        else => |e| return e,
    };
    return ctx.result;
}

/// [agave] https://github.com/anza-xyz/agave/blob/a11b42a73288ab5985009e21ffd48e79f8ad6c58/programs/bpf_loader/src/syscalls/mem_ops.rs#L8-L15
fn consumeMemoryCompute(tc: *TransactionContext, length: u64) !void {
    const budget = tc.compute_budget;
    const cost = @max(budget.mem_op_base_cost, length / budget.cpi_bytes_per_unit);
    try tc.consumeCompute(cost);
}

/// [agave] https://github.com/anza-xyz/agave/blob/a11b42a73288ab5985009e21ffd48e79f8ad6c58/programs/bpf_loader/src/syscalls/mem_ops.rs#L130-L162
pub fn memset(tc: *TransactionContext, memory_map: *MemoryMap, registers: *RegisterMap) Error!void {
    const dst_addr = registers.get(.r1);
    const scalar = registers.get(.r2);
    const len = registers.get(.r3);

    // [agave] https://github.com/anza-xyz/agave/blob/a11b42a73288ab5985009e21ffd48e79f8ad6c58/programs/bpf_loader/src/syscalls/mem_ops.rs#L142
    try consumeMemoryCompute(tc, len);

    const feature_set = tc.feature_set;
    const check_aligned = tc.getCheckAligned();
    if (feature_set.active.contains(features.BPF_ACCOUNT_DATA_DIRECT_MAPPING)) {
        try memsetNonContigious(
            dst_addr,
            @truncate(scalar),
            len,
            tc.serialized_accounts.constSlice(),
            memory_map,
            check_aligned,
        );
    } else {
        const host = try memory_map.translateSlice(u8, .mutable, dst_addr, len, check_aligned);
        @memset(host, @truncate(scalar));
    }
}

pub fn isOverlapping(src_addr: u64, src_len: u64, dst_addr: u64, dst_len: u64) bool {
    if (src_addr > dst_addr) {
        return (src_addr -| dst_addr) < dst_len;
    } else {
        return (dst_addr -| src_addr) < src_len;
    }
}

/// [agave] https://github.com/anza-xyz/agave/blob/a11b42a73288ab5985009e21ffd48e79f8ad6c58/programs/bpf_loader/src/syscalls/mem_ops.rs#L31-L52
pub fn memcpy(tc: *TransactionContext, memory_map: *MemoryMap, registers: *RegisterMap) Error!void {
    const dst_addr = registers.get(.r1);
    const src_addr = registers.get(.r2);
    const len = registers.get(.r3);

    try consumeMemoryCompute(tc, len);

    if (isOverlapping(src_addr, len, dst_addr, len)) {
        return SyscallError.CopyOverlapping;
    }

    const feature_set = tc.feature_set;
    const check_aligned = tc.getCheckAligned();
    if (feature_set.active.contains(features.BPF_ACCOUNT_DATA_DIRECT_MAPPING)) {
        try memmoveNonContigious(
            dst_addr,
            src_addr,
            len,
            tc.serialized_accounts.constSlice(),
            memory_map,
            check_aligned,
        );
    } else {
        const dst_host = try memory_map.translateSlice(u8, .mutable, dst_addr, len, check_aligned);
        const src_host = try memory_map.translateSlice(u8, .constant, src_addr, len, check_aligned);
        @memcpy(dst_host, src_host);
    }
}

/// [agave] https://github.com/anza-xyz/agave/blob/a11b42a73288ab5985009e21ffd48e79f8ad6c58/programs/bpf_loader/src/syscalls/mem_ops.rs#L54-L70
pub fn memmove(tc: *TransactionContext, memory_map: *MemoryMap, reg_map: *RegisterMap) Error!void {
    const dst_addr = reg_map.get(.r1);
    const src_addr = reg_map.get(.r2);
    const len = reg_map.get(.r3);

    try consumeMemoryCompute(tc, len);

    const feature_set = tc.feature_set;
    const check_aligned = tc.getCheckAligned();
    if (feature_set.active.contains(features.BPF_ACCOUNT_DATA_DIRECT_MAPPING)) {
        try memmoveNonContigious(
            dst_addr,
            src_addr,
            len,
            tc.serialized_accounts.constSlice(),
            memory_map,
            check_aligned,
        );
    } else {
        const dst_host = try memory_map.translateSlice(u8, .mutable, dst_addr, len, check_aligned);
        const src_host = try memory_map.translateSlice(u8, .constant, src_addr, len, check_aligned);
        _ = MemmoveContext.memmove(dst_host.ptr, src_host.ptr, len);
    }
}

/// [agave] https://github.com/anza-xyz/agave/blob/a11b42a73288ab5985009e21ffd48e79f8ad6c58/programs/bpf_loader/src/syscalls/mem_ops.rs#L72-L128
pub fn memcmp(tc: *TransactionContext, memory_map: *MemoryMap, registers: *RegisterMap) Error!void {
    const a_addr = registers.get(.r1);
    const b_addr = registers.get(.r2);
    const len = registers.get(.r3);
    const cmp_result_addr = registers.get(.r4);

    // [agave] https://github.com/anza-xyz/agave/blob/a11b42a73288ab5985009e21ffd48e79f8ad6c58/programs/bpf_loader/src/syscalls/mem_ops.rs#L84
    try consumeMemoryCompute(tc, len);

    const feature_set = tc.feature_set;
    const check_aligned = tc.getCheckAligned();
    if (feature_set.active.contains(features.BPF_ACCOUNT_DATA_DIRECT_MAPPING)) {
        const cmp_result = try memory_map.translateType(
            i32,
            .mutable,
            cmp_result_addr,
            check_aligned,
        );

        const ic = &tc.instruction_stack.buffer[tc.instruction_stack.len - 1];
        cmp_result.* = try memcmpNonContigious(
            a_addr,
            b_addr,
            len,
            tc.serialized_accounts.constSlice(),
            memory_map,
            ic.getCheckAligned(),
        );
    } else {
        const a = try memory_map.translateSlice(u8, .constant, a_addr, len, check_aligned);
        const b = try memory_map.translateSlice(u8, .constant, b_addr, len, check_aligned);
        const cmp_result = try memory_map.translateType(
            i32,
            .mutable,
            cmp_result_addr,
            check_aligned,
        );

        var memcmp_ctx: MemcmpContext = .{ .result = 0 };
        memcmp_ctx.run(a, b) catch {};
        cmp_result.* = memcmp_ctx.result;
    }
}

test "chunk iterator no regions" {
    const allocator = std.testing.allocator;
    var memory_map = try MemoryMap.init(
        allocator,
        &.{},
        .v3,
        .{ .aligned_memory_mapping = false },
    );
    defer memory_map.deinit(allocator);

    var src_chunk_iter = try MemoryChunkIterator.init(
        &memory_map,
        &.{},
        0,
        1,
        true,
        false,
    );
    try std.testing.expectError(error.AccessViolation, src_chunk_iter.next(.constant));
}

test "chunk iterator out of bounds upper" {
    const allocator = std.testing.allocator;
    var memory_map = try MemoryMap.init(
        allocator,
        &.{},
        .v3,
        .{ .aligned_memory_mapping = false },
    );
    defer memory_map.deinit(allocator);

    try std.testing.expectError(error.AccessViolation, MemoryChunkIterator.init(
        &memory_map,
        &.{},
        std.math.maxInt(u64),
        1,
        true,
        false,
    ));
}

test "chunk iterator out of bounds" {
    const allocator = std.testing.allocator;
    var memory_map = try MemoryMap.init(
        allocator,
        &.{memory.Region.init(.constant, &(.{0xFF} ** 42), memory.RODATA_START)},
        .v3,
        .{ .aligned_memory_mapping = false },
    );
    defer memory_map.deinit(allocator);

    {
        var src_chunk_iter = try MemoryChunkIterator.init(
            &memory_map,
            &.{},
            memory.RODATA_START - 1,
            42,
            true,
            false,
        );
        try std.testing.expectError(error.AccessViolation, src_chunk_iter.next(.constant));
    }

    {
        var src_chunk_iter = try MemoryChunkIterator.init(
            &memory_map,
            &.{},
            memory.RODATA_START,
            43,
            true,
            false,
        );
        _ = try src_chunk_iter.next(.constant);
        try std.testing.expectError(error.AccessViolation, src_chunk_iter.next(.constant));
    }

    {
        var src_chunk_iter = try MemoryChunkIterator.init(
            &memory_map,
            &.{},
            memory.RODATA_START,
            43,
            true,
            true,
        );
        try std.testing.expectError(error.AccessViolation, src_chunk_iter.next(.constant));
    }

    {
        var src_chunk_iter = try MemoryChunkIterator.init(
            &memory_map,
            &.{},
            memory.RODATA_START - 1,
            43,
            true,
            true,
        );
        _ = try src_chunk_iter.next(.constant);
        try std.testing.expectError(error.AccessViolation, src_chunk_iter.next(.constant));
    }
}

test "chunk iterator one" {
    const allocator = std.testing.allocator;
    var memory_map = try MemoryMap.init(
        allocator,
        &.{memory.Region.init(.constant, &(.{0xFF} ** 42), memory.RODATA_START)},
        .v3,
        .{ .aligned_memory_mapping = false },
    );
    defer memory_map.deinit(allocator);

    {
        var src_chunk_iter = try MemoryChunkIterator.init(
            &memory_map,
            &.{},
            memory.RODATA_START - 1,
            1,
            true,
            false,
        );
        try std.testing.expectError(error.AccessViolation, src_chunk_iter.next(.constant));
    }

    {
        var src_chunk_iter = try MemoryChunkIterator.init(
            &memory_map,
            &.{},
            memory.RODATA_START + 42,
            1,
            true,
            false,
        );
        try std.testing.expectError(error.AccessViolation, src_chunk_iter.next(.constant));
    }

    {
        inline for (.{
            .{ memory.RODATA_START, 0 },
            .{ memory.RODATA_START + 42, 0 },
            .{ memory.RODATA_START, 1 },
            .{ memory.RODATA_START, 42 },
            .{ memory.RODATA_START + 41, 1 },
        }) |entry| {
            const vm_addr, const len = entry;
            inline for (.{ true, false }) |reverse| {
                var iter = try MemoryChunkIterator.init(
                    &memory_map,
                    &.{},
                    vm_addr,
                    len,
                    true,
                    reverse,
                );

                if (len == 0) {
                    try std.testing.expectEqual(null, try iter.next(.constant));
                } else {
                    _, const chunk_addr, const chunk_len = (try iter.next(.constant)).?;
                    try std.testing.expectEqual(vm_addr, chunk_addr);
                    try std.testing.expectEqual(len, chunk_len);
                }
            }
        }
    }
}

test "chunk iterator two" {
    const allocator = std.testing.allocator;
    var memory_map = try MemoryMap.init(
        allocator,
        &.{
            memory.Region.init(.constant, &(.{0x11} ** 8), memory.RODATA_START),
            memory.Region.init(.constant, &(.{0x22} ** 4), memory.RODATA_START + 8),
        },
        .v3,
        .{ .aligned_memory_mapping = false },
    );
    defer memory_map.deinit(allocator);

    inline for (.{
        .{ memory.RODATA_START, 8, &.{.{ memory.RODATA_START, 8 }} },
        .{ memory.RODATA_START + 7, 2, &.{
            .{ memory.RODATA_START + 7, 1 },
            .{ memory.RODATA_START + 8, 1 },
        } },
        .{ memory.RODATA_START + 8, 4, &.{.{ memory.RODATA_START + 8, 4 }} },
    }) |entry| {
        const vm_addr, const len, const expected = entry;
        inline for (.{ true, false }) |reverse| {
            var iter = try MemoryChunkIterator.init(
                &memory_map,
                &.{},
                vm_addr,
                len,
                true,
                reverse,
            );

            const result = blk: {
                var list: std.ArrayListUnmanaged(Chunk) = .{};
                while (try iter.next(.constant)) |chunk| {
                    try list.append(allocator, chunk);
                }
                break :blk try list.toOwnedSlice(allocator);
            };
            defer allocator.free(result);

            if (reverse) std.mem.reverse(Chunk, result);

            inline for (expected, result) |e, r| {
                const expected_addr, const expected_len = e;
                _, const chunk_addr, const chunk_len = r;

                try std.testing.expectEqual(expected_addr, chunk_addr);
                try std.testing.expectEqual(expected_len, chunk_len);
            }
        }
    }
}

test "chunks short" {
    const allocator = std.testing.allocator;
    var memory_map = try MemoryMap.init(
        allocator,
        &.{
            memory.Region.init(.constant, &(.{0x11} ** 8), memory.RODATA_START),
            memory.Region.init(.constant, &(.{0x22} ** 4), memory.RODATA_START + 8),
        },
        .v3,
        .{ .aligned_memory_mapping = false },
    );
    defer memory_map.deinit(allocator);

    // dst shorter than src
    try std.testing.expectError(error.AccessViolation, memmoveNonContigious(
        memory.RODATA_START,
        memory.RODATA_START + 8,
        8,
        &.{},
        &memory_map,
        true,
    ));

    // src shorter than dst
    try std.testing.expectError(error.AccessViolation, memmoveNonContigious(
        memory.RODATA_START + 10,
        memory.RODATA_START + 2,
        3,
        &.{},
        &memory_map,
        true,
    ));
}

test "memmove non contiguous readonly" {
    const allocator = std.testing.allocator;
    var memory_map = try MemoryMap.init(
        allocator,
        &.{
            memory.Region.init(.constant, &(.{0x11} ** 8), memory.RODATA_START),
            memory.Region.init(.constant, &(.{0x22} ** 4), memory.RODATA_START + 8),
        },
        .v3,
        .{ .aligned_memory_mapping = false },
    );
    defer memory_map.deinit(allocator);

    try std.testing.expectError(error.AccessViolation, memmoveNonContigious(
        memory.RODATA_START,
        memory.RODATA_START + 8,
        4,
        &.{},
        &memory_map,
        true,
    ));
}

test "memset non contiguous readonly" {
    const allocator = std.testing.allocator;
    var memory_map = try MemoryMap.init(
        allocator,
        &.{
            memory.Region.init(.constant, &(.{0x11} ** 8), memory.RODATA_START),
            memory.Region.init(.constant, &(.{0x22} ** 4), memory.RODATA_START + 8),
        },
        .v3,
        .{ .aligned_memory_mapping = false },
    );
    defer memory_map.deinit(allocator);

    try std.testing.expectError(error.AccessViolation, memsetNonContigious(
        memory.RODATA_START,
        0x33,
        9,
        &.{},
        &memory_map,
        true,
    ));
}

test "memset non contigious" {
    const allocator = std.testing.allocator;

    const mem1: [1]u8 = .{0x11};
    var mem2: [2]u8 = .{ 0x22, 0x22 };
    var mem3: [3]u8 = .{ 0x33, 0x33, 0x33 };
    var mem4: [4]u8 = .{ 0x44, 0x44, 0x44, 0x44 };

    var memory_map = try MemoryMap.init(
        allocator,
        &.{
            memory.Region.init(.constant, &mem1, memory.RODATA_START),
            memory.Region.init(.mutable, &mem2, memory.RODATA_START + 1),
            memory.Region.init(.mutable, &mem3, memory.RODATA_START + 3),
            memory.Region.init(.mutable, &mem4, memory.RODATA_START + 6),
        },
        .v3,
        .{ .aligned_memory_mapping = false },
    );
    defer memory_map.deinit(allocator);

    try memsetNonContigious(memory.RODATA_START + 1, 0x55, 7, &.{}, &memory_map, true);

    try std.testing.expectEqualSlices(u8, &.{0x11}, &mem1);
    try std.testing.expectEqualSlices(u8, &.{ 0x55, 0x55 }, &mem2);
    try std.testing.expectEqualSlices(u8, &.{ 0x55, 0x55, 0x55 }, &mem3);
    try std.testing.expectEqualSlices(u8, &.{ 0x55, 0x55, 0x44, 0x44 }, &mem4);
}

test "memcmp non contigious" {
    const allocator = std.testing.allocator;
    var memory_map = try MemoryMap.init(
        allocator,
        &.{
            memory.Region.init(.constant, "foo", memory.RODATA_START),
            memory.Region.init(.constant, "barbad", memory.RODATA_START + 3),
            memory.Region.init(.constant, "foobarbad", memory.RODATA_START + 9),
        },
        .v3,
        .{ .aligned_memory_mapping = false },
    );
    defer memory_map.deinit(allocator);

    try std.testing.expectEqual(0, try memcmpNonContigious(
        memory.RODATA_START,
        memory.RODATA_START + 9,
        9,
        &.{},
        &memory_map,
        true,
    ));

    try std.testing.expectEqual(0, try memcmpNonContigious(
        memory.RODATA_START + 10,
        memory.RODATA_START + 1,
        8,
        &.{},
        &memory_map,
        true,
    ));

    var ctx: MemcmpContext = .{ .result = 0 };
    ctx.run("oobar", "obarb") catch {};
    try std.testing.expectEqual(ctx.result, try memcmpNonContigious(
        memory.RODATA_START + 1,
        memory.RODATA_START + 11,
        5,
        &.{},
        &memory_map,
        true,
    ));
}

test "isOverlapping" {
    for ([_]struct { usize, usize, usize, bool }{
        .{ 1, 2, 2, true }, // dst overlaps src
        .{ 2, 1, 2, true }, // src overlaps dst
        .{ 1, 1, 1, true }, // exact overlap
        .{ 1, 10, 1, false }, // neither overlaps
    }) |test_case| {
        const src, const dst, const len, const expect = test_case;
        errdefer std.log.err("isOverlapping failed src={x} dst={x} len={}\n", .{ src, dst, len });
        try std.testing.expectEqual(expect, isOverlapping(src, len, dst, len));
    }
}

test "memset syscall" {
    const vm_addr = memory.HEAP_START;
    var buf = "hello world".*;

    try sig.vm.tests.testSyscall(
        memset,
        &.{
            memory.Region.init(.mutable, &buf, vm_addr),
        },
        // zig fmt: off
        &.{
            .{ .{ vm_addr,     0,     2,       0, 0 }, 0 }, // part of buffer
            .{ .{ vm_addr + 2, 0,     2,       0, 0 }, 0 }, // other part of buffer (unaligned vm ptr)
            .{ .{ vm_addr,     1,     buf.len, 0, 0 }, 0 }, // full buffer, non-zero scalar
            .{ .{ vm_addr,     0,     0,       0, 0 }, 0 }, // empty slice
            .{ .{ vm_addr + 1, 0,     0,       0, 0 }, 0 }, // empty slice (unaligned)
            .{ .{ vm_addr,     0x999, buf.len, 0, 0 }, 0 }, // overflowing u8 scalar
            .{ .{ 0x1337,      42,    7,       0, 0 }, error.AccessViolation }, // invalid buffer
        },
        // zig fmt: on
        struct {
            fn verify(tc: *TransactionContext, memory_map: *MemoryMap, args: anytype) !void {
                const addr, const scalar, const len, _, _ = args;

                const aligned = tc.getCheckAligned();
                const slice = try memory_map.translateSlice(u8, .constant, addr, len, aligned);

                try std.testing.expect(std.mem.allEqual(u8, slice, @truncate(scalar)));
            }
        }.verify,
        .{},
    );
}

test "memcmp syscall" {
    const vm_addr = memory.HEAP_START;
    const result_addr = vm_addr + 0x1337;
    var result: [@sizeOf(i32)]u8 = undefined;

    try sig.vm.tests.testSyscall(
        memcmp,
        &.{
            memory.Region.init(.constant, "ababcz", vm_addr),
            memory.Region.init(.mutable, &result, result_addr),
        },
        // zig fmt: off
        &.{
            .{ .{ vm_addr,     vm_addr,     3, result_addr, 0 }, 0 }, // overlapping
            .{ .{ vm_addr,     vm_addr + 2, 2, result_addr, 0 }, 0 }, // non-overlapping: 0..2 vs 2..4
            .{ .{ vm_addr,     vm_addr + 1, 1, result_addr, 0 }, 0 }, // "a" cmp "b" (diff = -1)
            .{ .{ vm_addr,     vm_addr + 5, 1, result_addr, 0 }, 0 }, // "a" cmp "z" (diff > -1)
            .{ .{ vm_addr + 1, vm_addr,     1, result_addr, 0 }, 0 }, // "b" cmp "a" (diff = 1)
            .{ .{ vm_addr + 5, vm_addr,     1, result_addr, 0 }, 0 }, // "b" cmp "z" (diff > 1)
            .{ .{ 0x42,        vm_addr,     1, result_addr, 0 }, error.AccessViolation }, // invalid a addr
            .{ .{ vm_addr,     0x42,        1, result_addr, 0 }, error.AccessViolation }, // invalid b addr
            .{ .{ 0x1337,      0x42,        1, result_addr, 0 }, error.AccessViolation }, // invalid both addr
            .{ .{ vm_addr,     vm_addr,     1, 0x42,        0 }, error.AccessViolation }, // invalid result addr
        },
        // zig fmt: on
        struct {
            fn verify(tc: *TransactionContext, memory_map: *MemoryMap, args: anytype) !void {
                const a_ptr, const b_ptr, const len, const res_ptr, _ = args;

                const aligned = tc.getCheckAligned();
                const a = try memory_map.translateSlice(u8, .constant, a_ptr, len, aligned);
                const b = try memory_map.translateSlice(u8, .constant, b_ptr, len, aligned);
                const res = (try memory_map.translateType(i32, .constant, res_ptr, aligned)).*;

                switch (std.mem.order(u8, a, b)) {
                    .eq => try std.testing.expectEqual(res, 0),
                    .lt => try std.testing.expect(res < 0),
                    .gt => try std.testing.expect(res > 0),
                }
            }
        }.verify,
        .{},
    );
}

test "memcpy syscall" {
    const vm_addr = memory.HEAP_START;
    var buf = "hello world".*;

    try sig.vm.tests.testSyscall(
        memcpy,
        &.{
            memory.Region.init(.mutable, &buf, vm_addr),
        },
        // zig fmt: off
        &.{
            .{ .{ vm_addr, vm_addr + buf.len / 2, buf.len / 2, 0, 0 }, 0 }, // normal copy
            .{ .{ vm_addr, vm_addr + 1,           3,           0, 0 }, error.CopyOverlapping }, // overlapping copy
            .{ .{ 0x1337,  vm_addr,               5,           0, 0 }, error.AccessViolation }, // invalid dst ptr
            .{ .{ vm_addr, 0x1337,                5,           0, 0 }, error.AccessViolation }, // invalid src ptr
            .{ .{ 0x42,    0x1337,                5,           0, 0 }, error.AccessViolation }, // invalid both ptr
        },
        // zig fmt: on
        struct {
            fn verify(tc: *TransactionContext, memory_map: *MemoryMap, args: anytype) !void {
                const dst_addr, const src_addr, const len, _, _ = args;

                const aligned = tc.getCheckAligned();
                const dst = try memory_map.translateSlice(u8, .constant, dst_addr, len, aligned);
                const src = try memory_map.translateSlice(u8, .constant, src_addr, len, aligned);

                try std.testing.expect(std.mem.eql(u8, dst, src));
            }
        }.verify,
        .{},
    );
}

test "memmove syscall" {
    const vm_addr = memory.HEAP_START;
    var buf = "hello world".*;

    try sig.vm.tests.testSyscall(
        memmove,
        &.{
            memory.Region.init(.mutable, &buf, vm_addr),
        },
        // zig fmt: off
        &.{
            .{ .{ vm_addr,     vm_addr + buf.len / 2, buf.len / 2, 0, 0 }, 0 }, // normal copy
            .{ .{ vm_addr,     vm_addr + 1,           3,           0, 0 }, 0 }, // overlapping src copy
            .{ .{ vm_addr + 1, vm_addr,               3,           0, 0 }, 0 }, // overlapping dst copy
            .{ .{ 0x1337,      vm_addr,               5,           0, 0 }, error.AccessViolation }, // invalid dst ptr
            .{ .{ vm_addr,     0x1337,                5,           0, 0 }, error.AccessViolation }, // invalid src ptr
        },
        // zig fmt: on
        struct {
            fn verify(tc: *TransactionContext, memory_map: *MemoryMap, args: anytype) !void {
                const dst_addr, const src_addr, const len, _, _ = args;

                // skip checking overlapping data validity as its hard to tell using `testSyscall`
                if (isOverlapping(src_addr, len, dst_addr, len)) return;

                const aligned = tc.getCheckAligned();
                const dst = try memory_map.translateSlice(u8, .constant, dst_addr, len, aligned);
                const src = try memory_map.translateSlice(u8, .constant, src_addr, len, aligned);

                try std.testing.expect(std.mem.eql(u8, dst, src));
            }
        }.verify,
        .{},
    );
}
