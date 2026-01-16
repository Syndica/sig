const std = @import("std");
const sig = @import("../../sig.zig");

const memory = sig.vm.memory;
const syscalls = sig.vm.syscalls;

const SyscallError = sig.vm.SyscallError;
const RegisterMap = sig.vm.interpreter.RegisterMap;
const Error = syscalls.Error;
const MemoryMap = sig.vm.memory.MemoryMap;
const TransactionContext = sig.runtime.transaction_context.TransactionContext;

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.4/syscalls/src/mem_ops.rs#L3-L10
fn consumeMemoryCompute(tc: *TransactionContext, length: u64) !void {
    const budget = tc.compute_budget;
    const cost = @max(budget.mem_op_base_cost, length / budget.cpi_bytes_per_unit);
    try tc.consumeCompute(cost);
}

/// Returns whether `src_ptr[0..src_len]` overlaps with `dst_ptr[0..dst_len]`.
/// Lengths are in terms of bytes, unless the pointer is a slice, in which case
/// we multiply the length by the abi size of the element.
///
/// NOTE: We call `@intFromPtr` inside in order to ensure *Zig* pointers are passed in.
/// This is because we need to check whether the "physical" addresses are overlapping,
/// not the virtual ones.
///
/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.4/syscalls/src/mem_ops.rs#L13-L24
pub fn isOverlapping(src: anytype, dst: anytype) bool {
    const src_ptr, const src_len = unpack(src);
    const dst_ptr, const dst_len = unpack(dst);
    return overlaps(src_ptr, src_len, dst_ptr, dst_len);
}

inline fn unpack(input: anytype) struct { u64, u64 } {
    const is_slice = @typeInfo(@TypeOf(input)).pointer.size == .slice;
    const ptr = @intFromPtr(if (is_slice) input.ptr else input);
    const size = @sizeOf(std.meta.Child(@TypeOf(input)));
    const len = size *| if (is_slice) input.len else 1;
    return .{ ptr, len };
}

fn overlaps(src_ptr: u64, src_len: u64, dst_ptr: u64, dst_len: u64) bool {
    if (((src_ptr > dst_ptr) and (src_ptr -| dst_ptr < dst_len)) or
        ((dst_ptr >= src_ptr) and (dst_ptr -| src_ptr < src_len)))
    {
        @branchHint(.unlikely);
        return true;
    }
    return false;
}

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.4/syscalls/src/mem_ops.rs#L26-L47
pub fn memcpy(tc: *TransactionContext, memory_map: *MemoryMap, registers: *RegisterMap) Error!void {
    const dst_addr = registers.get(.r1);
    const src_addr = registers.get(.r2);
    const len = registers.get(.r3);

    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.4/syscalls/src/mem_ops.rs#L38
    try consumeMemoryCompute(tc, len);

    if (overlaps(src_addr, len, dst_addr, len)) {
        return SyscallError.CopyOverlapping;
    }

    const check_aligned = tc.getCheckAligned();
    const dst_host = try memory_map.translateSlice(u8, .mutable, dst_addr, len, check_aligned);
    const src_host = try memory_map.translateSlice(u8, .constant, src_addr, len, check_aligned);
    @memcpy(dst_host, src_host);
}

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.4/syscalls/src/mem_ops.rs#L49-L65
pub fn memmove(tc: *TransactionContext, memory_map: *MemoryMap, reg_map: *RegisterMap) Error!void {
    const dst_addr = reg_map.get(.r1);
    const src_addr = reg_map.get(.r2);
    const len = reg_map.get(.r3);

    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.4/syscalls/src/mem_ops.rs#L61
    try consumeMemoryCompute(tc, len);

    const check_aligned = tc.getCheckAligned();
    const dst_host = try memory_map.translateSlice(u8, .mutable, dst_addr, len, check_aligned);
    const src_host = try memory_map.translateSlice(u8, .constant, src_addr, len, check_aligned);

    const S = struct {
        // memmove() is in Zig's compiler-rt, but not exposed via builtin or stdlib outside this symbol:
        // https://github.com/ziglang/zig/blob/79460d4a3eef8eb927b02a7eda8bc9999a766672/lib/compiler_rt/memmove.zig#L9-L22
        // TODO(0.15): Use `@memmove` builtin.
        extern fn memmove(dst: ?[*]u8, src: ?[*]const u8, len: usize) callconv(.c) ?[*]u8;
    };
    _ = S.memmove(dst_host.ptr, src_host.ptr, len);
}

/// [agave] https://github.com/anza-xyz/agave/blob/6dcc39fcba90fbb5c924c71a1ef287c234f56c17/syscalls/src/mem_ops.rs#L67-L111
pub fn memcmp(tc: *TransactionContext, memory_map: *MemoryMap, registers: *RegisterMap) Error!void {
    const a_addr = registers.get(.r1);
    const b_addr = registers.get(.r2);
    const len = registers.get(.r3);
    const result_address = registers.get(.r4);

    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.4/syscalls/src/mem_ops.rs#L79
    try consumeMemoryCompute(tc, len);

    const check_aligned = tc.getCheckAligned();
    const s1 = try memory_map.translateSlice(u8, .constant, a_addr, len, check_aligned);
    const s2 = try memory_map.translateSlice(u8, .constant, b_addr, len, check_aligned);
    const cmp_result = try memory_map.translateType(
        i32,
        .mutable,
        result_address,
        check_aligned,
    );

    for (s1, s2) |a, b| {
        if (a != b) {
            cmp_result.* = @as(i32, a) -| @as(i32, b);
            break;
        }
    } else cmp_result.* = 0;
}

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.4/syscalls/src/mem_ops.rs#L113-L135
pub fn memset(tc: *TransactionContext, memory_map: *MemoryMap, registers: *RegisterMap) Error!void {
    const dst_addr = registers.get(.r1);
    const scalar = registers.get(.r2);
    const len = registers.get(.r3);

    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.4/syscalls/src/mem_ops.rs#L125
    try consumeMemoryCompute(tc, len);

    const check_aligned = tc.getCheckAligned();
    const host = try memory_map.translateSlice(u8, .mutable, dst_addr, len, check_aligned);
    @memset(host, @truncate(scalar));
}

test overlaps {
    for ([_]struct { usize, usize, usize, bool }{
        .{ 1, 2, 2, true }, // dst overlaps src
        .{ 2, 1, 2, true }, // src overlaps dst
        .{ 1, 1, 1, true }, // exact overlap
        .{ 1, 10, 1, false }, // neither overlaps
    }) |test_case| {
        const src, const dst, const len, const expect = test_case;
        try std.testing.expectEqual(expect, overlaps(src, len, dst, len));
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
                if (overlaps(src_addr, len, dst_addr, len)) return;

                const aligned = tc.getCheckAligned();
                const dst = try memory_map.translateSlice(u8, .constant, dst_addr, len, aligned);
                const src = try memory_map.translateSlice(u8, .constant, src_addr, len, aligned);

                try std.testing.expect(std.mem.eql(u8, dst, src));
            }
        }.verify,
        .{},
    );
}
