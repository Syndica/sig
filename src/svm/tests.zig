const std = @import("std");
const sig = @import("../sig.zig");
const Executable = @import("Executable.zig");
const memory = @import("memory.zig");
const Vm = @import("Vm.zig");
const syscalls = @import("syscalls.zig");
const ebpf = @import("ebpf.zig");
const Elf = @import("Elf.zig");

const Region = memory.Region;
const MemoryMap = memory.MemoryMap;
const expectEqual = std.testing.expectEqual;

fn testAsm(source: []const u8, expected: anytype) !void {
    return testAsmWithMemory(source, &.{}, expected);
}

fn testAsmWithMemory(source: []const u8, program_memory: []const u8, expected: anytype) !void {
    const allocator = std.testing.allocator;
    var executable = try Executable.fromAsm(allocator, source);
    defer executable.deinit(allocator);

    const mutable = try allocator.dupe(u8, program_memory);
    defer allocator.free(mutable);

    const stack_memory = try allocator.alloc(u8, 4096);
    defer allocator.free(stack_memory);

    const m = try MemoryMap.init(&.{
        Region.init(.constant, &.{}, memory.PROGRAM_START),
        Region.init(.mutable, stack_memory, memory.STACK_START),
        Region.init(.constant, &.{}, memory.HEAP_START),
        Region.init(.mutable, mutable, memory.INPUT_START),
    }, .v1);

    var loader: Executable.BuiltinProgram = .{};
    var vm = try Vm.init(allocator, &executable, m, &loader);
    defer vm.deinit();

    const result = vm.run();
    try expectEqual(expected, result);
}

test "basic mov" {
    try testAsm(
        \\entrypoint:
        \\  mov r1, 1
        \\  mov r0, r1
        \\  exit
    , 1);
}

test "mov32 imm large" {
    try testAsm(
        \\entrypoint:
        \\  mov32 r0, -1
        \\  exit
    , 0xFFFFFFFF);
}

test "mov large" {
    try testAsm(
        \\entrypoint:
        \\  mov32 r1, -1
        \\  mov32 r0, r1
        \\  exit
    , 0xFFFFFFFF);
}

test "bounce" {
    try testAsm(
        \\entrypoint:
        \\  mov r0, 1
        \\  mov r6, r0
        \\  mov r7, r6
        \\  mov r8, r7
        \\  mov r9, r8
        \\  mov r0, r9
        \\  exit
    , 1);
}

test "add32" {
    try testAsm(
        \\entrypoint:
        \\  mov32 r0, 0
        \\  mov32 r1, 2
        \\  add32 r0, 1
        \\  add32 r0, r1
        \\  exit
    , 3);
}

test "add64" {
    try testAsm(
        \\entrypoint:
        \\  lddw r0, 0x300000fff
        \\  add r0, -1
        \\  exit
    , 0x300000FFE);
}

test "alu32 logic" {
    try testAsm(
        \\entrypoint:
        \\  mov32 r0, 0
        \\  mov32 r1, 1
        \\  mov32 r2, 2
        \\  mov32 r3, 3
        \\  mov32 r4, 4
        \\  mov32 r5, 5
        \\  mov32 r6, 6
        \\  mov32 r7, 7
        \\  mov32 r8, 8
        \\  or32 r0, r5
        \\  or32 r0, 0xa0
        \\  and32 r0, 0xa3
        \\  mov32 r9, 0x91
        \\  and32 r0, r9
        \\  lsh32 r0, 22
        \\  lsh32 r0, r8
        \\  rsh32 r0, 19
        \\  rsh32 r0, r7
        \\  xor32 r0, 0x03
        \\  xor32 r0, r2
        \\  exit
    , 0x11);
}
test "alu64 logic" {
    try testAsm(
        \\entrypoint:
        \\  mov r0, 0
        \\  mov r1, 1
        \\  mov r2, 2
        \\  mov r3, 3
        \\  mov r4, 4
        \\  mov r5, 5
        \\  mov r6, 6
        \\  mov r7, 7
        \\  mov r8, 8
        \\  or r0, r5
        \\  or r0, 0xa0
        \\  and r0, 0xa3
        \\  mov r9, 0x91
        \\  and r0, r9
        \\  lsh r0, 32
        \\  lsh r0, 22
        \\  lsh r0, r8
        \\  rsh r0, 32
        \\  rsh r0, 19
        \\  rsh r0, r7
        \\  xor r0, 0x03
        \\  xor r0, r2
        \\  exit
    , 0x11);
}

test "mul32 imm" {
    try testAsm(
        \\entrypoint:
        \\  mov r0, 3
        \\  mul32 r0, 4
        \\  exit
    , 12);
}

test "mul32 reg" {
    try testAsm(
        \\entrypoint:
        \\  mov r0, 3
        \\  mov r1, 4
        \\  mul32 r0, r1
        \\  exit
    , 12);
}

test "mul32 overflow" {
    try testAsm(
        \\entrypoint:
        \\  mov r0, 0x40000001
        \\  mov r1, 4
        \\  mul32 r0, r1
        \\  exit
    , 4);
}

test "mul64 imm" {
    try testAsm(
        \\entrypoint:
        \\  mov r0, 0x40000001
        \\  mul r0, 4
        \\  exit
    , 0x100000004);
}

test "mul64 reg" {
    try testAsm(
        \\entrypoint:
        \\  mov r0, 0x40000001
        \\  mov r1, 4
        \\  mul r0, r1
        \\  exit
    , 0x100000004);
}

test "mul32 negative" {
    try testAsm(
        \\entrypoint:
        \\  mov r0, -1
        \\  mul32 r0, 4
        \\  exit
    , 0xFFFFFFFFFFFFFFFC);
}

test "div32 imm" {
    try testAsm(
        \\entrypoint:
        \\  lddw r0, 0x10000000c
        \\  div32 r0, 4
        \\  exit
    , 0x3);
}

test "div32 reg" {
    try testAsm(
        \\entrypoint:
        \\  mov r0, 12
        \\  lddw r1, 0x100000004
        \\  div32 r0, r1
        \\  exit
    , 0x3);
}

test "div32 small" {
    try testAsm(
        \\entrypoint:
        \\  lddw r0, 0x10000000c
        \\  mov r1, 4
        \\  div32 r0, r1
        \\  exit
    , 0x3);
}

test "div64 imm" {
    try testAsm(
        \\entrypoint:
        \\  mov r0, 0xc
        \\  lsh r0, 32
        \\  div r0, 4
        \\  exit
    , 0x300000000);
}

test "div64 reg" {
    try testAsm(
        \\entrypoint:
        \\  mov r0, 0xc
        \\  lsh r0, 32
        \\  mov r1, 4
        \\  div r0, r1
        \\  exit
    , 0x300000000);
}

test "div division by zero" {
    try testAsm(
        \\entrypoint:
        \\  mov32 r0, 1
        \\  mov32 r1, 0
        \\  div r0, r1
        \\  exit
    , error.DivisionByZero);
}

test "div32 division by zero" {
    try testAsm(
        \\entrypoint:
        \\  mov32 r0, 1
        \\  mov32 r1, 0
        \\  div32 r0, r1
        \\  exit
    , error.DivisionByZero);
}

test "neg32" {
    try testAsm(
        \\entrypoint:
        \\  mov32 r0, 2
        \\  neg32 r0
        \\  exit
    , 0xFFFFFFFE);
}

test "neg64" {
    try testAsm(
        \\entrypoint:
        \\  mov r0, 2
        \\  neg r0
        \\  exit
    , 0xFFFFFFFFFFFFFFFE);
}

test "sub32 imm" {
    try testAsm(
        \\entrypoint:
        \\  mov32 r0, 3
        \\  sub32 r0, 1
        \\  exit
    , 2);
}

test "sub32 reg" {
    try testAsm(
        \\entrypoint:
        \\  mov32 r0, 4
        \\  mov32 r1, 2
        \\  sub32 r0, r1
        \\  exit
    , 2);
}

test "sub64 imm" {
    try testAsm(
        \\entrypoint:
        \\  mov r0, 3
        \\  sub r0, 1
        \\  exit
    , 2);
}

test "sub64 imm negative" {
    try testAsm(
        \\entrypoint:
        \\  mov r0, 3
        \\  sub r0, -1
        \\  exit
    , 4);
}

test "sub64 reg" {
    try testAsm(
        \\entrypoint:
        \\  mov r0, 4
        \\  mov r1, 2
        \\  sub r0, r1
        \\  exit
    , 2);
}

test "mod32" {
    try testAsm(
        \\entrypoint:
        \\  mov32 r0, 5748
        \\  mod32 r0, 92
        \\  mov32 r1, 13
        \\  mod32 r0, r1
        \\  exit
    ,
        0x5,
    );
}

test "mod32 overflow" {
    try testAsm(
        \\entrypoint:
        \\  lddw r0, 0x100000003
        \\  mod32 r0, 3
        \\  exit
    ,
        0x0,
    );
}

test "mod32 all" {
    try testAsm(
        \\entrypoint:
        \\  mov32 r0, -1316649930
        \\  lsh r0, 32
        \\  or r0, 0x100dc5c8
        \\  mov32 r1, 0xdde263e
        \\  lsh r1, 32
        \\  or r1, 0x3cbef7f3
        \\  mod r0, r1
        \\  mod r0, 0x658f1778
        \\  exit
    ,
        0x30ba5a04,
    );
}

test "mod64 divide by zero" {
    try testAsm(
        \\entrypoint:
        \\  mov32 r0, 1
        \\  mov32 r1, 0
        \\  mod r0, r1
        \\  exit
    ,
        error.DivisionByZero,
    );
}

test "mod32 divide by zero" {
    try testAsm(
        \\entrypoint:
        \\  mov32 r0, 1
        \\  mov32 r1, 0
        \\  mod32 r0, r1
        \\  exit
    ,
        error.DivisionByZero,
    );
}

test "arsh32 imm" {
    try testAsm(
        \\entrypoint:
        \\  mov32 r0, 0xf8
        \\  lsh32 r0, 28
        \\  arsh32 r0, 16
        \\  exit
    ,
        0xffff8000,
    );
}

test "arsh32 reg" {
    try testAsm(
        \\entrypoint:
        \\  mov32 r0, 0xf8
        \\  mov32 r1, 16
        \\  lsh32 r0, 28
        \\  arsh32 r0, r1
        \\  exit
    ,
        0xffff8000,
    );
}

test "arsh64" {
    try testAsm(
        \\entrypoint:
        \\  mov32 r0, 1
        \\  lsh r0, 63
        \\  arsh r0, 55
        \\  mov32 r1, 5
        \\  arsh r0, r1
        \\  exit
    ,
        0xfffffffffffffff8,
    );
}

test "lddw" {
    try testAsm(
        \\entrypoint:
        \\  lddw r0, 0x1122334455667788
        \\  exit
    , 0x1122334455667788);

    try testAsm(
        \\entrypoint:
        \\  lddw r0, 0x0000000080000000
        \\  exit
    , 0x80000000);

    try testAsm(
        \\entrypoint:
        \\  mov r0, 0
        \\  mov r1, 0
        \\  mov r2, 0
        \\  lddw r0, 0x1
        \\  ja +2
        \\  lddw r1, 0x1
        \\  lddw r2, 0x1
        \\  add r1, r2
        \\  add r0, r1
        \\  exit
    , 0x2);
}

test "lsh64 reg" {
    try testAsm(
        \\entrypoint:
        \\  mov r0, 0x1
        \\  mov r7, 4
        \\  lsh r0, r7
        \\  exit
    , 0x10);
}

test "rhs32 imm" {
    try testAsm(
        \\entrypoint:
        \\  xor r0, r0
        \\  add r0, -1
        \\  rsh32 r0, 8
        \\  exit
    , 0x00ffffff);
}

test "rhs64 reg" {
    try testAsm(
        \\entrypoint:
        \\  mov r0, 0x10
        \\  mov r7, 4
        \\  rsh r0, r7
        \\  exit
    , 0x1);
}

test "be16" {
    try testAsmWithMemory(
        \\entrypoint:
        \\  ldxh r0, [r1]
        \\  be16 r0
        \\  exit
    ,
        &.{ 0x11, 0x22 },
        0x1122,
    );
}

test "be16 high" {
    try testAsmWithMemory(
        \\entrypoint:
        \\  ldxdw r0, [r1]
        \\  be16 r0
        \\  exit
    ,
        &.{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 },
        0x1122,
    );
}

test "be32" {
    try testAsmWithMemory(
        \\entrypoint:
        \\  ldxw r0, [r1]
        \\  be32 r0
        \\  exit
    ,
        &.{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 },
        0x11223344,
    );
}

test "be32 high" {
    try testAsmWithMemory(
        \\entrypoint:
        \\  ldxdw r0, [r1]
        \\  be32 r0
        \\  exit
    ,
        &.{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 },
        0x11223344,
    );
}

test "be64" {
    try testAsmWithMemory(
        \\entrypoint:
        \\  ldxdw r0, [r1]
        \\  be64 r0
        \\  exit
    ,
        &.{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 },
        0x1122334455667788,
    );
}

test "ldxb" {
    try testAsmWithMemory(
        \\entrypoint:
        \\  ldxb r0, [r1+2]
        \\  exit
    ,
        &.{ 0xaa, 0xbb, 0x11, 0xcc, 0xdd },
        0x11,
    );
}

test "ldxh" {
    try testAsmWithMemory(
        \\entrypoint:
        \\  ldxh r0, [r1+2]
        \\  exit
    ,
        &.{ 0xaa, 0xbb, 0x11, 0x22, 0xcc, 0xdd },
        0x2211,
    );
}

test "ldxw" {
    try testAsmWithMemory(
        \\entrypoint:
        \\  ldxw r0, [r1+2]
        \\  exit
    ,
        &.{ 0xaa, 0xbb, 0x11, 0x22, 0x33, 0x44, 0xcc, 0xdd },
        0x44332211,
    );
}

test "ldxw same reg" {
    try testAsmWithMemory(
        \\entrypoint:
        \\  mov r0, r1
        \\  sth [r0], 0x1234
        \\  ldxh r0, [r0]
        \\  exit
    ,
        &.{ 0xff, 0xff },
        0x1234,
    );
}

test "ldxdw" {
    try testAsmWithMemory(
        \\entrypoint:
        \\  ldxdw r0, [r1+2]
        \\  exit
    ,
        &.{
            0xaa, 0xbb, 0x11, 0x22, 0x33, 0x44,
            0x55, 0x66, 0x77, 0x88, 0xcc, 0xdd,
        },
        0x8877665544332211,
    );
}

test "ldxdw oob" {
    try testAsmWithMemory(
        \\entrypoint:
        \\  ldxdw r0, [r1+6]
        \\  exit
    ,
        &.{
            0xaa, 0xbb, 0x11, 0x22, 0x33, 0x44,
            0x55, 0x66, 0x77, 0x88, 0xcc, 0xdd,
        },
        error.VirtualAccessTooLong,
    );
}

test "ldxdw oom" {
    try testAsmWithMemory(
        \\entrypoint:
        \\  ldxdw r0, [r1+6]
        \\  exit
    ,
        &.{},
        error.AccessNotMapped,
    );
}

test "ldxb all" {
    try testAsmWithMemory(
        \\entrypoint:
        \\  mov r0, r1
        \\  ldxb r9, [r0+0]
        \\  lsh r9, 0
        \\  ldxb r8, [r0+1]
        \\  lsh r8, 4
        \\  ldxb r7, [r0+2]
        \\  lsh r7, 8
        \\  ldxb r6, [r0+3]
        \\  lsh r6, 12
        \\  ldxb r5, [r0+4]
        \\  lsh r5, 16
        \\  ldxb r4, [r0+5]
        \\  lsh r4, 20
        \\  ldxb r3, [r0+6]
        \\  lsh r3, 24
        \\  ldxb r2, [r0+7]
        \\  lsh r2, 28
        \\  ldxb r1, [r0+8]
        \\  lsh r1, 32
        \\  ldxb r0, [r0+9]
        \\  lsh r0, 36
        \\  or r0, r1
        \\  or r0, r2
        \\  or r0, r3
        \\  or r0, r4
        \\  or r0, r5
        \\  or r0, r6
        \\  or r0, r7
        \\  or r0, r8
        \\  or r0, r9
        \\  exit
    ,
        &.{
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08, 0x09,
        },
        0x9876543210,
    );
}

test "ldxh all" {
    try testAsmWithMemory(
        \\entrypoint:
        \\  mov r0, r1
        \\  ldxh r9, [r0+0]
        \\  be16 r9
        \\  lsh r9, 0
        \\  ldxh r8, [r0+2]
        \\  be16 r8
        \\  lsh r8, 4
        \\  ldxh r7, [r0+4]
        \\  be16 r7
        \\  lsh r7, 8
        \\  ldxh r6, [r0+6]
        \\  be16 r6
        \\  lsh r6, 12
        \\  ldxh r5, [r0+8]
        \\  be16 r5
        \\  lsh r5, 16
        \\  ldxh r4, [r0+10]
        \\  be16 r4
        \\  lsh r4, 20
        \\  ldxh r3, [r0+12]
        \\  be16 r3
        \\  lsh r3, 24
        \\  ldxh r2, [r0+14]
        \\  be16 r2
        \\  lsh r2, 28
        \\  ldxh r1, [r0+16]
        \\  be16 r1
        \\  lsh r1, 32
        \\  ldxh r0, [r0+18]
        \\  be16 r0
        \\  lsh r0, 36
        \\  or r0, r1
        \\  or r0, r2
        \\  or r0, r3
        \\  or r0, r4
        \\  or r0, r5
        \\  or r0, r6
        \\  or r0, r7
        \\  or r0, r8
        \\  or r0, r9
        \\  exit
    ,
        &.{
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x02, 0x00, 0x03,
            0x00, 0x04, 0x00, 0x05,
            0x00, 0x06, 0x00, 0x07,
            0x00, 0x08, 0x00, 0x09,
        },
        0x9876543210,
    );

    try testAsmWithMemory(
        \\entrypoint:
        \\  mov r0, r1
        \\  ldxh r9, [r0+0]
        \\  be16 r9
        \\  ldxh r8, [r0+2]
        \\  be16 r8
        \\  ldxh r7, [r0+4]
        \\  be16 r7
        \\  ldxh r6, [r0+6]
        \\  be16 r6
        \\  ldxh r5, [r0+8]
        \\  be16 r5
        \\  ldxh r4, [r0+10]
        \\  be16 r4
        \\  ldxh r3, [r0+12]
        \\  be16 r3
        \\  ldxh r2, [r0+14]
        \\  be16 r2
        \\  ldxh r1, [r0+16]
        \\  be16 r1
        \\  ldxh r0, [r0+18]
        \\  be16 r0
        \\  or r0, r1
        \\  or r0, r2
        \\  or r0, r3
        \\  or r0, r4
        \\  or r0, r5
        \\  or r0, r6
        \\  or r0, r7
        \\  or r0, r8
        \\  or r0, r9
        \\  exit
    ,
        &.{
            0x00, 0x01, 0x00, 0x02, 0x00, 0x04, 0x00, 0x08,
            0x00, 0x10, 0x00, 0x20, 0x00, 0x40, 0x00, 0x80,
            0x01, 0x00, 0x02, 0x00,
        },
        0x3FF,
    );
}

test "ldxw all" {
    try testAsmWithMemory(
        \\entrypoint:
        \\  mov r0, r1
        \\  ldxw r9, [r0+0]
        \\  be32 r9
        \\  ldxw r8, [r0+4]
        \\  be32 r8
        \\  ldxw r7, [r0+8]
        \\  be32 r7
        \\  ldxw r6, [r0+12]
        \\  be32 r6
        \\  ldxw r5, [r0+16]
        \\  be32 r5
        \\  ldxw r4, [r0+20]
        \\  be32 r4
        \\  ldxw r3, [r0+24]
        \\  be32 r3
        \\  ldxw r2, [r0+28]
        \\  be32 r2
        \\  ldxw r1, [r0+32]
        \\  be32 r1
        \\  ldxw r0, [r0+36]
        \\  be32 r0
        \\  or r0, r1
        \\  or r0, r2
        \\  or r0, r3
        \\  or r0, r4
        \\  or r0, r5
        \\  or r0, r6
        \\  or r0, r7
        \\  or r0, r8
        \\  or r0, r9
        \\  exit
    ,
        &.{
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x08,
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00,
            0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x08, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
        },
        0x030F0F,
    );
}

test "stb" {
    try testAsmWithMemory(
        \\entrypoint:
        \\  stb [r1+2], 0x11
        \\  ldxb r0, [r1+2]
        \\  exit
    ,
        &.{ 0xaa, 0xbb, 0xff, 0xcc, 0xdd },
        0x11,
    );
}

test "sth" {
    try testAsmWithMemory(
        \\entrypoint:
        \\ sth [r1+2], 0x2211
        \\ ldxh r0, [r1+2]
        \\ exit
    ,
        &.{
            0xaa, 0xbb, 0xff, 0xff,
            0xff, 0xff, 0xcc, 0xdd,
        },
        0x2211,
    );
}

test "stw" {
    try testAsmWithMemory(
        \\entrypoint:
        \\  stw [r1+2], 0x44332211
        \\  ldxw r0, [r1+2]
        \\  exit
    ,
        &.{
            0xaa, 0xbb, 0xff, 0xff,
            0xff, 0xff, 0xcc, 0xdd,
        },
        0x44332211,
    );
}

test "stdw" {
    try testAsmWithMemory(
        \\entrypoint:
        \\  stdw [r1+2], 0x44332211
        \\  ldxdw r0, [r1+2]
        \\  exit
    ,
        &.{
            0xaa, 0xbb, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xcc, 0xdd,
        },
        0x44332211,
    );
}

test "stxb" {
    try testAsmWithMemory(
        \\entrypoint:
        \\  mov32 r2, 0x11
        \\  stxb [r1+2], r2
        \\  ldxb r0, [r1+2]
        \\  exit
    ,
        &.{ 0xaa, 0xbb, 0xff, 0xcc, 0xdd },
        0x11,
    );
}

test "stxh" {
    try testAsmWithMemory(
        \\entrypoint:
        \\  mov32 r2, 0x2211
        \\  stxh [r1+2], r2
        \\  ldxh r0, [r1+2]
        \\  exit
    ,
        &.{ 0xaa, 0xbb, 0xff, 0xff, 0xcc, 0xdd },
        0x2211,
    );
}

test "stxw" {
    try testAsmWithMemory(
        \\entrypoint:
        \\  mov32 r2, 0x44332211
        \\  stxw [r1+2], r2
        \\  ldxw r0, [r1+2]
        \\  exit
    ,
        &.{ 0xaa, 0xbb, 0xff, 0xff, 0xff, 0xff, 0xcc, 0xdd },
        0x44332211,
    );
}

test "stxdw" {
    try testAsmWithMemory(
        \\entrypoint:
        \\  mov r2, -2005440939
        \\  lsh r2, 32
        \\  or r2, 0x44332211
        \\  stxdw [r1+2], r2
        \\  ldxdw r0, [r1+2]
        \\  exit
    ,
        &.{
            0xaa, 0xbb, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xcc, 0xdd,
        },
        0x8877665544332211,
    );
}

test "stxb all" {
    try testAsmWithMemory(
        \\entrypoint:
        \\  mov r0, 0xf0
        \\  mov r2, 0xf2
        \\  mov r3, 0xf3
        \\  mov r4, 0xf4
        \\  mov r5, 0xf5
        \\  mov r6, 0xf6
        \\  mov r7, 0xf7
        \\  mov r8, 0xf8
        \\  stxb [r1], r0
        \\  stxb [r1+1], r2
        \\  stxb [r1+2], r3
        \\  stxb [r1+3], r4
        \\  stxb [r1+4], r5
        \\  stxb [r1+5], r6
        \\  stxb [r1+6], r7
        \\  stxb [r1+7], r8
        \\  ldxdw r0, [r1]
        \\  be64 r0
        \\  exit
    ,
        &.{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
        0xf0f2f3f4f5f6f7f8,
    );

    try testAsmWithMemory(
        \\entrypoint:
        \\  mov r0, r1
        \\  mov r1, 0xf1
        \\  mov r9, 0xf9
        \\  stxb [r0], r1
        \\  stxb [r0+1], r9
        \\  ldxh r0, [r0]
        \\  be16 r0
        \\  exit
    ,
        &.{ 0xff, 0xff },
        0xf1f9,
    );
}

test "stxb chain" {
    try testAsmWithMemory(
        \\entrypoint:
        \\  mov r0, r1
        \\  ldxb r9, [r0+0]
        \\  stxb [r0+1], r9
        \\  ldxb r8, [r0+1]
        \\  stxb [r0+2], r8
        \\  ldxb r7, [r0+2]
        \\  stxb [r0+3], r7
        \\  ldxb r6, [r0+3]
        \\  stxb [r0+4], r6
        \\  ldxb r5, [r0+4]
        \\  stxb [r0+5], r5
        \\  ldxb r4, [r0+5]
        \\  stxb [r0+6], r4
        \\  ldxb r3, [r0+6]
        \\  stxb [r0+7], r3
        \\  ldxb r2, [r0+7]
        \\  stxb [r0+8], r2
        \\  ldxb r1, [r0+8]
        \\  stxb [r0+9], r1
        \\  ldxb r0, [r0+9]
        \\  exit
    ,
        &.{
            0x2a, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00,
        },
        0x2a,
    );
}

test "exit without value" {
    try testAsm(
        \\entrypoint:
        \\  exit
    ,
        0x0,
    );
}

test "exit" {
    try testAsm(
        \\entrypoint:
        \\  mov r0, 0
        \\  exit
    , 0x0);
}

test "early exit" {
    try testAsm(
        \\entrypoint:
        \\  mov r0, 3
        \\  exit
        \\  mov r0, 4
        \\  exit
    , 3);
}

test "ja" {
    try testAsm(
        \\entrypoint:
        \\  mov r0, 1
        \\  ja +1
        \\  mov r0, 2
        \\  exit
    ,
        0x1,
    );
}

test "jeq imm" {
    try testAsm(
        \\entrypoint:
        \\  mov32 r0, 0
        \\  mov32 r1, 0xa
        \\  jeq r1, 0xb, +4
        \\  mov32 r0, 1
        \\  mov32 r1, 0xb
        \\  jeq r1, 0xb, +1
        \\  mov32 r0, 2
        \\  exit
    ,
        0x1,
    );
}

test "jeq reg" {
    try testAsm(
        \\entrypoint:
        \\  mov32 r0, 0
        \\  mov32 r1, 0xa
        \\  mov32 r2, 0xb
        \\  jeq r1, r2, +4
        \\  mov32 r0, 1
        \\  mov32 r1, 0xb
        \\  jeq r1, r2, +1
        \\  mov32 r0, 2
        \\  exit
    ,
        0x1,
    );
}

test "jge imm" {
    try testAsm(
        \\entrypoint:
        \\  mov32 r0, 0
        \\  mov32 r1, 0xa
        \\  jge r1, 0xb, +4
        \\  mov32 r0, 1
        \\  mov32 r1, 0xc
        \\  jge r1, 0xb, +1
        \\  mov32 r0, 2
        \\  exit
    ,
        0x1,
    );
}

test "jge reg" {
    try testAsm(
        \\entrypoint:
        \\  mov32 r0, 0
        \\  mov32 r1, 0xa
        \\  mov32 r2, 0xb
        \\  jge r1, r2, +4
        \\  mov32 r0, 1
        \\  mov32 r1, 0xb
        \\  jge r1, r2, +1
        \\  mov32 r0, 2
        \\  exit
    ,
        0x1,
    );
}

test "jle imm" {
    try testAsm(
        \\entrypoint:
        \\  mov32 r0, 0
        \\  mov32 r1, 5
        \\  jle r1, 4, +1
        \\  jle r1, 6, +1
        \\  exit
        \\  jle r1, 5, +1
        \\  exit
        \\  mov32 r0, 1
        \\  exit
    ,
        0x1,
    );
}

test "jle reg" {
    try testAsm(
        \\entrypoint:
        \\  mov r0, 0
        \\  mov r1, 5
        \\  mov r2, 4
        \\  mov r3, 6
        \\  jle r1, r2, +2
        \\  jle r1, r1, +1
        \\  exit
        \\  jle r1, r3, +1
        \\  exit
        \\  mov r0, 1
        \\  exit
    ,
        0x1,
    );
}

test "jgt imm" {
    try testAsm(
        \\entrypoint:
        \\  mov32 r0, 0
        \\  mov32 r1, 5
        \\  jgt r1, 6, +2
        \\  jgt r1, 5, +1
        \\  jgt r1, 4, +1
        \\  exit
        \\  mov32 r0, 1
        \\  exit
    ,
        0x1,
    );
}

test "jgt reg" {
    try testAsm(
        \\entrypoint:
        \\  mov r0, 0
        \\  mov r1, 5
        \\  mov r2, 6
        \\  mov r3, 4
        \\  jgt r1, r2, +2
        \\  jgt r1, r1, +1
        \\  jgt r1, r3, +1
        \\  exit
        \\  mov r0, 1
        \\  exit
    ,
        0x1,
    );
}

test "jlt imm" {
    try testAsm(
        \\entrypoint:
        \\  mov32 r0, 0
        \\  mov32 r1, 5
        \\  jlt r1, 4, +2
        \\  jlt r1, 5, +1
        \\  jlt r1, 6, +1
        \\  exit
        \\  mov32 r0, 1
        \\  exit
    ,
        0x1,
    );
}

test "jlt reg" {
    try testAsm(
        \\entrypoint:
        \\  mov r0, 0
        \\  mov r1, 5
        \\  mov r2, 4
        \\  mov r3, 6
        \\  jlt r1, r2, +2
        \\  jlt r1, r1, +1
        \\  jlt r1, r3, +1
        \\  exit
        \\  mov r0, 1
        \\  exit
    ,
        0x1,
    );
}

test "jlt extend" {
    try testAsm(
        \\entrypoint:
        \\  mov r0, 0
        \\  add r0, -3  
        \\  jlt r0, -2, +2 
        \\  mov r0, 1             
        \\  exit                 
        \\  mov r0, 2           
        \\  exit    
    ,
        2,
    );
}

test "jne imm" {
    try testAsm(
        \\entrypoint:
        \\  mov32 r0, 0
        \\  mov32 r1, 0xb
        \\  jne r1, 0xb, +4
        \\  mov32 r0, 1
        \\  mov32 r1, 0xa
        \\  jne r1, 0xb, +1
        \\  mov32 r0, 2
        \\  exit
    ,
        0x1,
    );
}

test "jne reg" {
    try testAsm(
        \\entrypoint:
        \\  mov32 r0, 0
        \\  mov32 r1, 0xb
        \\  mov32 r2, 0xb
        \\  jne r1, r2, +4
        \\  mov32 r0, 1
        \\  mov32 r1, 0xa
        \\  jne r1, r2, +1
        \\  mov32 r0, 2
        \\  exit
    ,
        0x1,
    );
}

test "jset imm" {
    try testAsm(
        \\entrypoint:
        \\  mov32 r0, 0
        \\  mov32 r1, 0x7
        \\  jset r1, 0x8, +4
        \\  mov32 r0, 1
        \\  mov32 r1, 0x9
        \\  jset r1, 0x8, +1
        \\  mov32 r0, 2
        \\  exit
    ,
        0x1,
    );
}

test "jset reg" {
    try testAsm(
        \\entrypoint:
        \\  mov32 r0, 0
        \\  mov32 r1, 0x7
        \\  mov32 r2, 0x8
        \\  jset r1, r2, +4
        \\  mov32 r0, 1
        \\  mov32 r1, 0x9
        \\  jset r1, r2, +1
        \\  mov32 r0, 2
        \\  exit
    ,
        0x1,
    );
}

test "jsge imm" {
    try testAsm(
        \\entrypoint:
        \\  mov32 r0, 0
        \\  mov r1, -2
        \\  jsge r1, -1, +5
        \\  jsge r1, 0, +4
        \\  mov32 r0, 1
        \\  mov r1, -1
        \\  jsge r1, -1, +1
        \\  mov32 r0, 2
        \\  exit
    ,
        0x1,
    );
}

test "jsge reg" {
    try testAsm(
        \\entrypoint:
        \\  mov32 r0, 0
        \\  mov r1, -2
        \\  mov r2, -1
        \\  mov32 r3, 0
        \\  jsge r1, r2, +5
        \\  jsge r1, r3, +4
        \\  mov32 r0, 1
        \\  mov  r1, r2
        \\  jsge r1, r2, +1
        \\  mov32 r0, 2
        \\ exit
    ,
        0x1,
    );
}

test "jsle imm" {
    try testAsm(
        \\entrypoint:
        \\  mov32 r0, 0
        \\  mov r1, -2
        \\  jsle r1, -3, +1
        \\  jsle r1, -1, +1
        \\  exit
        \\  mov32 r0, 1
        \\  jsle r1, -2, +1
        \\  mov32 r0, 2
        \\  exit
    ,
        0x1,
    );
}

test "jsle reg" {
    try testAsm(
        \\entrypoint:
        \\  mov32 r0, 0
        \\  mov r1, -1
        \\  mov r2, -2
        \\  mov32 r3, 0
        \\  jsle r1, r2, +1
        \\  jsle r1, r3, +1
        \\  exit
        \\  mov32 r0, 1
        \\  mov r1, r2
        \\  jsle r1, r2, +1
        \\  mov32 r0, 2
        \\  exit
    ,
        0x1,
    );
}

test "jsgt imm" {
    try testAsm(
        \\entrypoint:
        \\  mov32 r0, 0
        \\  mov r1, -2
        \\  jsgt r1, -1, +4
        \\  mov32 r0, 1
        \\  mov32 r1, 0
        \\  jsgt r1, -1, +1
        \\  mov32 r0, 2
        \\  exit
    ,
        0x1,
    );
}

test "jsgt reg" {
    try testAsm(
        \\entrypoint:
        \\  mov32 r0, 0
        \\  mov r1, -2
        \\  mov r2, -1
        \\  jsgt r1, r2, +4
        \\  mov32 r0, 1
        \\  mov32 r1, 0
        \\  jsgt r1, r2, +1
        \\  mov32 r0, 2
        \\  exit
    ,
        0x1,
    );
}

test "jslt imm" {
    try testAsm(
        \\entrypoint:
        \\  mov32 r0, 0
        \\  mov r1, -2
        \\  jslt r1, -3, +2
        \\  jslt r1, -2, +1
        \\  jslt r1, -1, +1
        \\  exit
        \\  mov32 r0, 1
        \\  exit
    ,
        0x1,
    );
}

test "jslt reg" {
    try testAsm(
        \\entrypoint:
        \\  mov32 r0, 0
        \\  mov r1, -2
        \\  mov r2, -3
        \\  mov r3, -1
        \\  jslt r1, r1, +2
        \\  jslt r1, r2, +1
        \\  jslt r1, r3, +1
        \\  exit
        \\  mov32 r0, 1
        \\  exit
    ,
        0x1,
    );
}

test "stack1" {
    try testAsm(
        \\entrypoint:
        \\  mov r1, 51
        \\  stdw [r10-16], 0xab
        \\  stdw [r10-8], 0xcd
        \\  and r1, 1
        \\  lsh r1, 3
        \\  mov r2, r10
        \\  add r2, r1
        \\  ldxdw r0, [r2-16]
        \\  exit
    ,
        0xcd,
    );
}

test "entrypoint exit" {
    try testAsm(
        \\entrypoint:
        \\  call function_foo
        \\  mov r0, 42
        \\  exit
        \\function_foo:
        \\  mov r0, 12
        \\  exit
    , 42);
}

test "call depth in bounds" {
    try testAsm(
        \\entrypoint:
        \\  mov r1, 0
        \\  mov r2, 63
        \\  call function_foo
        \\  mov r0, r1
        \\  exit
        \\function_foo:
        \\  add r1, 1
        \\  jeq r1, r2, +1
        \\  call function_foo
        \\  exit
    , 63);
}

test "call depth out of bounds" {
    try testAsm(
        \\entrypoint:
        \\  mov r1, 0
        \\  mov r2, 64
        \\  call function_foo
        \\  mov r0, r1
        \\  exit
        \\function_foo:
        \\  add r1, 1
        \\  jeq r1, r2, +1
        \\  call function_foo
        \\  exit
    , error.CallDepthExceeded);
}

test "callx imm" {
    try testAsm(
        \\entrypoint:
        \\  mov64 r0, 0x0
        \\  mov64 r8, 0x1
        \\  lsh64 r8, 0x20
        \\  or64 r8, 0x30
        \\  callx r8
        \\  exit
        \\function_foo:
        \\  mov64 r0, 0x2A
        \\  exit
    , 42);
}

test "callx out of bounds" {
    try testAsm(
        \\entrypoint:
        \\  mov64 r0, 0x3
        \\  callx r0
        \\  exit
    , error.PcOutOfBounds);
}

test "call bpf 2 bpf" {
    try testAsm(
        \\entrypoint:
        \\  mov64 r6, 0x11
        \\  mov64 r7, 0x22
        \\  mov64 r8, 0x44
        \\  mov64 r9, 0x88
        \\  call function_foo
        \\  mov64 r0, r6
        \\  add64 r0, r7
        \\  add64 r0, r8
        \\  add64 r0, r9
        \\  exit
        \\function_foo:
        \\  mov64 r6, 0x00
        \\  mov64 r7, 0x00
        \\  mov64 r8, 0x00
        \\  mov64 r9, 0x00
        \\  exit
    , 255);
}

test "fixed stack out of bounds" {
    try testAsm(
        \\entrypoint:
        \\  stb [r10-0x4000], 0
        \\  exit
    , error.AccessNotMapped);
}

fn testElf(path: []const u8, expected: anytype) !void {
    return testElfWithSyscalls(path, &.{}, expected);
}

fn testElfWithSyscalls(
    path: []const u8,
    extra_syscalls: []const syscalls.Syscall,
    expected: anytype,
) !void {
    const allocator = std.testing.allocator;

    const input_file = try std.fs.cwd().openFile(path, .{});
    const bytes = try input_file.readToEndAlloc(allocator, ebpf.MAX_FILE_SIZE);
    defer allocator.free(bytes);

    var loader: Executable.BuiltinProgram = .{};
    defer loader.deinit(allocator);

    for (extra_syscalls) |syscall| {
        _ = try loader.functions.registerHashed(
            allocator,
            syscall.name,
            syscall.builtin_fn,
        );
    }

    const elf = try Elf.parse(allocator, bytes, &loader);

    var executable = try Executable.fromElf(allocator, &elf);
    defer executable.deinit(allocator);

    const stack_memory = try allocator.alloc(u8, 4096);
    defer allocator.free(stack_memory);

    const m = try MemoryMap.init(&.{
        executable.getProgramRegion(),
        Region.init(.mutable, stack_memory, memory.STACK_START),
        Region.init(.constant, &.{}, memory.HEAP_START),
        Region.init(.mutable, &.{}, memory.INPUT_START),
    }, .v1);

    var vm = try Vm.init(allocator, &executable, m, &loader);
    defer vm.deinit();

    const result = vm.run();
    try expectEqual(expected, result);
}

test "BPF_64_64 sbpfv1" {
    // [ 1] .text             PROGBITS        0000000000000120 000120 000018 00  AX  0   0  8
    // prints the address of the first byte in the .text section
    try testElf(
        sig.ELF_DATA_DIR ++ "reloc_64_64_sbpfv1.so",
        memory.PROGRAM_START + 0x120,
    );
}

test "BPF_64_RELATIVE data sbpv1" {
    // [ 1] .text             PROGBITS        00000000000000e8 0000e8 000020 00  AX  0   0  8
    // [ 2] .rodata           PROGBITS        0000000000000108 000108 000019 01 AMS  0   0  1
    // prints the address of the first byte in the .rodata sections
    try testElf(
        sig.ELF_DATA_DIR ++ "reloc_64_relative_data_sbpfv1.so",
        memory.PROGRAM_START + 0x108,
    );
}

test "BPF_64_RELATIVE sbpv1" {
    try testElf(
        sig.ELF_DATA_DIR ++ "reloc_64_relative_sbpfv1.so",
        memory.PROGRAM_START + 0x138,
    );
}

test "load elf rodata sbpfv1" {
    try testElf(
        sig.ELF_DATA_DIR ++ "rodata_section_sbpfv1.so",
        42,
    );
}

test "static internal call sbpv1" {
    try testElf(
        sig.ELF_DATA_DIR ++ "static_internal_call_sbpfv1.so",
        10,
    );
}

test "syscall reloc 64_32" {
    try testElfWithSyscalls(
        sig.ELF_DATA_DIR ++ "syscall_reloc_64_32.so",
        &.{.{ .name = "log", .builtin_fn = syscalls.printString }},
        0,
    );
}
