const std = @import("std");
const sig = @import("../sig.zig");

const sbpf = sig.vm.sbpf;
const memory = sig.vm.memory;
const syscalls = sig.vm.syscalls;
const executor = sig.runtime.executor;

const InstructionInfo = sig.runtime.InstructionInfo;
const Elf = sig.vm.elf.Elf;
const Executable = sig.vm.Executable;
const Config = sig.vm.Config;
const Region = sig.vm.memory.Region;
const MemoryMap = sig.vm.memory.MemoryMap;
const Vm = sig.vm.interpreter.Vm;
const VmResult = sig.vm.interpreter.Result;
const OpCode = sbpf.Instruction.OpCode;
const SyscallMap = sig.vm.SyscallMap;
const Syscall = sig.vm.syscalls.Syscall;

const expectEqual = std.testing.expectEqual;
const createTransactionContext = sig.runtime.testing.createTransactionContext;
const deinitTranactionContext = sig.runtime.testing.deinitTransactionContext;

// Execution tests

fn testAsm(
    config: Config,
    source: []const u8,
    expected: anytype,
) !void {
    return testAsmWithMemory(
        config,
        source,
        &.{},
        expected,
    );
}

fn testAsmWithMemory(
    config: Config,
    source: []const u8,
    program_memory: []const u8,
    expected: anytype,
) !void {
    const allocator = std.testing.allocator;

    var loader: SyscallMap = .ALL_DISABLED;
    var executable = try Executable.fromAsm(allocator, source, config);
    defer executable.deinit(allocator);

    try executable.verify(&loader);

    const mutable = try allocator.dupe(u8, program_memory);
    defer allocator.free(mutable);

    const stack_memory = try allocator.alloc(u8, config.stackSize());
    defer allocator.free(stack_memory);

    const m = try MemoryMap.init(
        allocator,
        &.{
            Region.init(.constant, &.{}, memory.RODATA_START),
            Region.init(.mutable, stack_memory, memory.STACK_START),
            Region.init(.constant, &.{}, memory.HEAP_START),
            Region.init(.mutable, mutable, memory.INPUT_START),
        },
        config.maximum_version,
        config,
    );

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var cache, var tc = try createTransactionContext(
        allocator,
        prng.random(),
        .{ .compute_meter = expected[1] },
    );
    defer {
        deinitTranactionContext(allocator, &tc);
        cache.deinit(allocator);
    }

    var vm = try Vm.init(
        allocator,
        &executable,
        m,
        &loader,
        stack_memory.len,
        &tc,
    );
    defer vm.deinit();

    const expected_result, const expected_instruction_count = expected;
    const result, const instruction_count = vm.run();
    try expectEqual(VmResult.fromValue(expected_result), result);
    try expectEqual(expected_instruction_count, instruction_count);
}

test "basic mov" {
    try testAsm(.{},
        \\entrypoint:
        \\  mov r1, 1
        \\  mov r0, r1
        \\  return
    , .{ 1, 3 });
}

test "mov32 imm large" {
    try testAsm(.{},
        \\entrypoint:
        \\  mov32 r0, -1
        \\  return
    , .{ 0xFFFFFFFF, 2 });
}

test "mov32 large" {
    try testAsm(.{},
        \\entrypoint:
        \\  mov32 r1, -1
        \\  mov32 r0, r1
        \\  return
    , .{ 0xFFFFFFFFFFFFFFFF, 3 });
}

test "mov large" {
    try testAsm(.{},
        \\entrypoint:
        \\  mov64 r1, -1
        \\  mov64 r0, r1
        \\  exit
    , .{ 0xFFFFFFFFFFFFFFFF, 3 });
}

test "bounce" {
    try testAsm(.{},
        \\entrypoint:
        \\  mov r0, 1
        \\  mov r6, r0
        \\  mov r7, r6
        \\  mov r8, r7
        \\  mov r9, r8
        \\  mov r0, r9
        \\  return
    , .{ 1, 7 });
}

test "add32" {
    try testAsm(.{},
        \\entrypoint:
        \\  mov32 r0, 0
        \\  mov32 r1, 2
        \\  add32 r0, 1
        \\  add32 r0, r1
        \\  return
    , .{ 3, 5 });
}

test "add64" {
    try testAsm(.{ .maximum_version = .v0 },
        \\entrypoint:
        \\  lddw r0, 0x300000fff
        \\  add r0, -1
        \\  exit
    , .{ 0x300000FFE, 3 });
}

test "add32 negative" {
    try testAsm(.{},
        \\entrypoint:
        \\  mov32 r0, 0
        \\  add32 r0, -1
        \\  exit
    , .{ 0xFFFFFFFF, 3 });
}

test "alu32 logic" {
    try testAsm(.{},
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
        \\  return
    , .{ 0x11, 21 });
}

test "alu32 arithmetic" {
    try testAsm(.{},
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
        \\  mov32 r9, 9
        \\  sub32 r0, 13
        \\  sub32 r0, r1
        \\  add32 r0, 23
        \\  add32 r0, r7
        \\  lmul32 r0, 7
        \\  lmul32 r0, r3
        \\  udiv32 r0, 2
        \\  udiv32 r0, r4
        \\  return
    , .{ 110, 19 });
}

test "alu64 logic" {
    try testAsm(.{},
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
        \\  return
    , .{ 0x11, 23 });
}

test "mul32 imm" {
    try testAsm(.{ .maximum_version = .v0 },
        \\entrypoint:
        \\  mov r0, 3
        \\  mul32 r0, 4
        \\  exit
    , .{ 12, 3 });
}

test "mul32 reg" {
    try testAsm(.{ .maximum_version = .v0 },
        \\entrypoint:
        \\  mov r0, 3
        \\  mov r1, 4
        \\  mul32 r0, r1
        \\  exit
    , .{ 12, 4 });
}

test "mul32 overflow" {
    try testAsm(.{ .maximum_version = .v0 },
        \\entrypoint:
        \\  mov r0, 0x40000001
        \\  mov r1, 4
        \\  mul32 r0, r1
        \\  exit
    , .{ 4, 4 });
}

test "mul64 imm" {
    try testAsm(.{ .maximum_version = .v0 },
        \\entrypoint:
        \\  mov r0, 0x40000001
        \\  mul r0, 4
        \\  exit
    , .{ 0x100000004, 3 });
}

test "mul64 reg" {
    try testAsm(.{ .maximum_version = .v0 },
        \\entrypoint:
        \\  mov r0, 0x40000001
        \\  mov r1, 4
        \\  mul r0, r1
        \\  exit
    , .{ 0x100000004, 4 });
}

test "mul32 negative" {
    try testAsm(.{ .maximum_version = .v0 },
        \\entrypoint:
        \\  mov r0, -1
        \\  mul32 r0, 4
        \\  exit
    , .{ 0xFFFFFFFFFFFFFFFC, 3 });
}

test "div32 imm" {
    try testAsm(.{ .maximum_version = .v0 },
        \\entrypoint:
        \\  lddw r0, 0x10000000c
        \\  div32 r0, 4
        \\  exit
    , .{ 0x3, 3 });
}

test "div32 reg" {
    try testAsm(.{ .maximum_version = .v0 },
        \\entrypoint:
        \\  mov r0, 12
        \\  lddw r1, 0x100000004
        \\  div32 r0, r1
        \\  exit
    , .{ 0x3, 4 });
}

test "div32 small" {
    try testAsm(.{ .maximum_version = .v0 },
        \\entrypoint:
        \\  lddw r0, 0x10000000c
        \\  mov r1, 4
        \\  div32 r0, r1
        \\  exit
    , .{ 0x3, 4 });
}

test "div64 imm" {
    try testAsm(.{ .maximum_version = .v0 },
        \\entrypoint:
        \\  mov r0, 0xc
        \\  lsh r0, 32
        \\  div r0, 4
        \\  exit
    , .{ 0x300000000, 4 });
}

test "div64 reg" {
    try testAsm(.{ .maximum_version = .v0 },
        \\entrypoint:
        \\  mov r0, 0xc
        \\  lsh r0, 32
        \\  mov r1, 4
        \\  div r0, r1
        \\  exit
    , .{ 0x300000000, 5 });
}

test "div division by zero" {
    try testAsm(.{ .maximum_version = .v0 },
        \\entrypoint:
        \\  mov32 r0, 1
        \\  mov32 r1, 0
        \\  div r0, r1
        \\  exit
    , .{ error.DivisionByZero, 3 });
}

test "div32 division by zero" {
    try testAsm(.{ .maximum_version = .v0 },
        \\entrypoint:
        \\  mov32 r0, 1
        \\  mov32 r1, 0
        \\  div32 r0, r1
        \\  exit
    , .{ error.DivisionByZero, 3 });
}

test "neg32" {
    try testAsm(.{ .maximum_version = .v0 },
        \\entrypoint:
        \\  mov32 r0, 2
        \\  neg32 r0
        \\  exit
    , .{ 0xFFFFFFFE, 3 });
}

test "neg64" {
    try testAsm(.{ .maximum_version = .v0 },
        \\entrypoint:
        \\  mov r0, 2
        \\  neg r0
        \\  exit
    , .{ 0xFFFFFFFFFFFFFFFE, 3 });
}

test "neg64 wrapping" {
    try testAsm(.{ .maximum_version = .v0 },
        \\entrypoint:
        \\  mov64 r0, 1
        \\  lsh64 r0, 63
        \\  neg64 r0
        \\  exit
    , .{ 0x8000000000000000, 4 });
}

test "sub32 imm" {
    try testAsm(.{},
        \\entrypoint:
        \\  mov32 r0, 3
        \\  sub32 r0, 1
        \\  return
    , .{ 0xFFFFFFFE, 3 });
}

test "sub32 reg" {
    try testAsm(.{},
        \\entrypoint:
        \\  mov32 r0, 4
        \\  mov32 r1, 2
        \\  sub32 r0, r1
        \\  return
    , .{ 2, 4 });
}

test "sub64 imm" {
    try testAsm(.{},
        \\entrypoint:
        \\  mov r0, 3
        \\  sub r0, 1
        \\  return
    , .{ 0xFFFFFFFFFFFFFFFE, 3 });
}

test "sub64 imm negative" {
    try testAsm(.{},
        \\entrypoint:
        \\  mov r0, 3
        \\  sub r0, -1
        \\  return
    , .{ 0xFFFFFFFFFFFFFFFC, 3 });
}

test "sub64 reg" {
    try testAsm(.{},
        \\entrypoint:
        \\  mov r0, 4
        \\  mov r1, 2
        \\  sub r0, r1
        \\  return
    , .{ 2, 4 });
}

test "mod32" {
    try testAsm(.{ .maximum_version = .v0 },
        \\entrypoint:
        \\  mov32 r0, 5748
        \\  mod32 r0, 92
        \\  mov32 r1, 13
        \\  mod32 r0, r1
        \\  exit
    , .{ 0x5, 5 });
}

test "mod32 overflow" {
    try testAsm(.{ .maximum_version = .v0 },
        \\entrypoint:
        \\  lddw r0, 0x100000003
        \\  mod32 r0, 3
        \\  exit
    , .{ 0x0, 3 });
}

test "mod32 all" {
    try testAsm(.{ .maximum_version = .v0 },
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
    , .{ 0x30ba5a04, 9 });
}

test "mod64 divide by zero" {
    try testAsm(.{ .maximum_version = .v0 },
        \\entrypoint:
        \\  mov32 r0, 1
        \\  mov32 r1, 0
        \\  mod r0, r1
        \\  exit
    , .{ error.DivisionByZero, 3 });
}

test "mod32 divide by zero" {
    try testAsm(.{ .maximum_version = .v0 },
        \\entrypoint:
        \\  mov32 r0, 1
        \\  mov32 r1, 0
        \\  mod32 r0, r1
        \\  exit
    , .{ error.DivisionByZero, 3 });
}

test "arsh32 high shift" {
    try testAsm(.{},
        \\entrypoint:
        \\  mov r0, 8
        \\  mov32 r1, 0x00000001
        \\  hor64 r1, 0x00000001
        \\  arsh32 r0, r1
        \\  return
    , .{ 0x4, 5 });
}

test "arsh32 imm" {
    try testAsm(.{},
        \\entrypoint:
        \\  mov32 r0, 0xf8
        \\  lsh32 r0, 28
        \\  arsh32 r0, 16
        \\  return
    , .{ 0xFFFF8000, 4 });
}

test "arsh32 reg" {
    try testAsm(.{},
        \\entrypoint:
        \\  mov32 r0, 0xf8
        \\  mov32 r1, 16
        \\  lsh32 r0, 28
        \\  arsh32 r0, r1
        \\  return
    , .{ 0xFFFF8000, 5 });
}

test "arsh64" {
    try testAsm(.{},
        \\entrypoint:
        \\  mov32 r0, 1
        \\  lsh r0, 63
        \\  arsh r0, 55
        \\  mov32 r1, 5
        \\  arsh r0, r1
        \\  return
    , .{ 0xFFFFFFFFFFFFFFF8, 6 });
}

test "hor64" {
    try testAsm(.{},
        \\entrypoint:
        \\  hor64 r0, 0x10203040
        \\  hor64 r0, 0x01020304
        \\  return
    , .{ 0x1122334400000000, 3 });
}

test "lddw" {
    try testAsm(.{ .maximum_version = .v0 },
        \\entrypoint:
        \\  lddw r0, 0x1122334455667788
        \\  exit
    , .{ 0x1122334455667788, 2 });
}

test "lddw bottom" {
    try testAsm(.{ .maximum_version = .v0 },
        \\entrypoint:
        \\  lddw r0, 0x0000000080000000
        \\  exit
    , .{ 0x80000000, 2 });
}

test "lddw logic" {
    try testAsm(.{ .maximum_version = .v0 },
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
    , .{ 0x2, 9 });
}

test "le16" {
    try testAsmWithMemory(
        .{ .maximum_version = .v0 },
        \\  ldxh r0, [r1]
        \\  le16 r0
        \\  exit
    ,
        &.{ 0x22, 0x11 },
        .{ 0x1122, 3 },
    );
}

test "le16 high" {
    try testAsmWithMemory(
        .{ .maximum_version = .v0 },
        \\  ldxdw r0, [r1]
        \\  le16 r0
        \\  exit
    ,
        &.{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 },
        .{ 0x2211, 3 },
    );
}

test "le32" {
    try testAsmWithMemory(
        .{ .maximum_version = .v0 },
        \\  ldxw r0, [r1]
        \\  le32 r0
        \\  exit
    ,
        &.{ 0x44, 0x33, 0x22, 0x11 },
        .{ 0x11223344, 3 },
    );
}

test "le32 high" {
    try testAsmWithMemory(
        .{ .maximum_version = .v0 },
        \\  ldxdw r0, [r1]
        \\  le32 r0
        \\  exit
    ,
        &.{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 },
        .{ 0x44332211, 3 },
    );
}

test "le64" {
    try testAsmWithMemory(
        .{ .maximum_version = .v0 },
        \\  ldxdw r0, [r1]
        \\  le64 r0
        \\  exit
    ,
        &.{ 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 },
        .{ 0x1122334455667788, 3 },
    );
}

test "be16" {
    try testAsmWithMemory(
        .{},
        \\entrypoint:
        \\  ldxh r0, [r1]
        \\  be16 r0
        \\  return
    ,
        &.{ 0x11, 0x22 },
        .{ 0x1122, 3 },
    );
}

test "be16 high" {
    try testAsmWithMemory(
        .{},
        \\entrypoint:
        \\  ldxdw r0, [r1]
        \\  be16 r0
        \\  return
    ,
        &.{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 },
        .{ 0x1122, 3 },
    );
}

test "be32" {
    try testAsmWithMemory(
        .{},
        \\entrypoint:
        \\  ldxw r0, [r1]
        \\  be32 r0
        \\  return
    ,
        &.{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 },
        .{ 0x11223344, 3 },
    );
}

test "be32 high" {
    try testAsmWithMemory(
        .{},
        \\entrypoint:
        \\  ldxdw r0, [r1]
        \\  be32 r0
        \\  return
    ,
        &.{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 },
        .{ 0x11223344, 3 },
    );
}

test "be64" {
    try testAsmWithMemory(
        .{},
        \\entrypoint:
        \\  ldxdw r0, [r1]
        \\  be64 r0
        \\  return
    ,
        &.{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 },
        .{ 0x1122334455667788, 3 },
    );
}

test "lsh64 reg" {
    try testAsm(
        .{},
        \\entrypoint:
        \\  mov r0, 0x1
        \\  mov r7, 4
        \\  lsh r0, r7
        \\  return
    ,
        .{ 0x10, 4 },
    );
}

test "lsh32 overflow" {
    try testAsm(
        .{},
        \\entrypoint:
        \\  mov32 r0, 5
        \\  lsh32 r0, 30
        \\  exit
    ,
        .{ 0x40000000, 3 },
    );
}

test "rhs32 imm" {
    try testAsm(.{},
        \\entrypoint:
        \\  xor r0, r0
        \\  add r0, -1
        \\  rsh32 r0, 8
        \\  return
    , .{ 0x00FFFFFF, 4 });
}

test "rhs64 reg" {
    try testAsm(.{},
        \\entrypoint:
        \\  mov r0, 0x10
        \\  mov r7, 4
        \\  rsh r0, r7
        \\  return
    , .{ 0x1, 4 });
}

test "ldxb" {
    try testAsmWithMemory(
        .{},
        \\entrypoint:
        \\  ldxb r0, [r1+2]
        \\  return
    ,
        &.{ 0xaa, 0xbb, 0x11, 0xcc, 0xdd },
        .{ 0x11, 2 },
    );
}

test "ldxh" {
    try testAsmWithMemory(
        .{},
        \\entrypoint:
        \\  ldxh r0, [r1+2]
        \\  return
    ,
        &.{ 0xaa, 0xbb, 0x11, 0x22, 0xcc, 0xdd },
        .{ 0x2211, 2 },
    );
}

test "ldxw" {
    try testAsmWithMemory(
        .{},
        \\entrypoint:
        \\  ldxw r0, [r1+2]
        \\  return
    ,
        &.{ 0xaa, 0xbb, 0x11, 0x22, 0x33, 0x44, 0xcc, 0xdd },
        .{ 0x44332211, 2 },
    );
}

test "ldxw same reg" {
    try testAsmWithMemory(
        .{},
        \\entrypoint:
        \\  mov r0, r1
        \\  sth [r0], 0x1234
        \\  ldxh r0, [r0]
        \\  return
    ,
        &.{ 0xff, 0xff },
        .{ 0x1234, 4 },
    );
}

test "ldxdw" {
    try testAsmWithMemory(
        .{},
        \\entrypoint:
        \\  ldxdw r0, [r1+2]
        \\  return
    ,
        &.{
            0xaa, 0xbb, 0x11, 0x22, 0x33, 0x44,
            0x55, 0x66, 0x77, 0x88, 0xcc, 0xdd,
        },
        .{ 0x8877665544332211, 2 },
    );
}

test "ldxdw oob" {
    try testAsmWithMemory(
        .{},
        \\entrypoint:
        \\  ldxdw r0, [r1+6]
        \\  return
    ,
        &.{
            0xaa, 0xbb, 0x11, 0x22, 0x33, 0x44,
            0x55, 0x66, 0x77, 0x88, 0xcc, 0xdd,
        },
        .{ error.AccessViolation, 1 },
    );
}

test "ldxdw oom" {
    try testAsmWithMemory(
        .{},
        \\entrypoint:
        \\  ldxdw r0, [r1+6]
        \\  return
    ,
        &.{},
        .{ error.AccessViolation, 1 },
    );
}

test "ldxb all" {
    try testAsmWithMemory(
        .{},
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
        \\  return
    ,
        &.{
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08, 0x09,
        },
        .{ 0x9876543210, 31 },
    );
}

test "ldxh all" {
    try testAsmWithMemory(
        .{},
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
        \\  return
    ,
        &.{
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x02, 0x00, 0x03,
            0x00, 0x04, 0x00, 0x05,
            0x00, 0x06, 0x00, 0x07,
            0x00, 0x08, 0x00, 0x09,
        },
        .{ 0x9876543210, 41 },
    );

    try testAsmWithMemory(
        .{},
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
        \\  return
    ,
        &.{
            0x00, 0x01, 0x00, 0x02, 0x00, 0x04, 0x00, 0x08,
            0x00, 0x10, 0x00, 0x20, 0x00, 0x40, 0x00, 0x80,
            0x01, 0x00, 0x02, 0x00,
        },
        .{ 0x3FF, 31 },
    );
}

test "ldxw all" {
    try testAsmWithMemory(
        .{},
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
        \\  return
    ,
        &.{
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x08,
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00,
            0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x08, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
        },
        .{ 0x030F0F, 31 },
    );
}

test "stb" {
    try testAsmWithMemory(
        .{},
        \\entrypoint:
        \\  stb [r1+2], 0x11
        \\  ldxb r0, [r1+2]
        \\  return
    ,
        &.{ 0xaa, 0xbb, 0xff, 0xcc, 0xdd },
        .{ 0x11, 3 },
    );
}

test "sth" {
    try testAsmWithMemory(
        .{},
        \\entrypoint:
        \\ sth [r1+2], 0x2211
        \\ ldxh r0, [r1+2]
        \\ return
    ,
        &.{
            0xaa, 0xbb, 0xff, 0xff,
            0xff, 0xff, 0xcc, 0xdd,
        },
        .{ 0x2211, 3 },
    );
}

test "stw" {
    try testAsmWithMemory(
        .{},
        \\entrypoint:
        \\  stw [r1+2], 0x44332211
        \\  ldxw r0, [r1+2]
        \\  return
    ,
        &.{
            0xaa, 0xbb, 0xff, 0xff,
            0xff, 0xff, 0xcc, 0xdd,
        },
        .{ 0x44332211, 3 },
    );
}

test "stdw" {
    try testAsmWithMemory(
        .{},
        \\entrypoint:
        \\  stdw [r1+2], 0x44332211
        \\  ldxdw r0, [r1+2]
        \\  return
    ,
        &.{
            0xaa, 0xbb, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xcc, 0xdd,
        },
        .{ 0x44332211, 3 },
    );
}

test "stxb" {
    try testAsmWithMemory(
        .{},
        \\entrypoint:
        \\  mov32 r2, 0x11
        \\  stxb [r1+2], r2
        \\  ldxb r0, [r1+2]
        \\  return
    ,
        &.{ 0xaa, 0xbb, 0xff, 0xcc, 0xdd },
        .{ 0x11, 4 },
    );
}

test "stxh" {
    try testAsmWithMemory(
        .{},
        \\entrypoint:
        \\  mov32 r2, 0x2211
        \\  stxh [r1+2], r2
        \\  ldxh r0, [r1+2]
        \\  return
    ,
        &.{ 0xaa, 0xbb, 0xff, 0xff, 0xcc, 0xdd },
        .{ 0x2211, 4 },
    );
}

test "stxw" {
    try testAsmWithMemory(
        .{},
        \\entrypoint:
        \\  mov32 r2, 0x44332211
        \\  stxw [r1+2], r2
        \\  ldxw r0, [r1+2]
        \\  return
    ,
        &.{ 0xaa, 0xbb, 0xff, 0xff, 0xff, 0xff, 0xcc, 0xdd },
        .{ 0x44332211, 4 },
    );
}

test "stxdw" {
    try testAsmWithMemory(
        .{},
        \\entrypoint:
        \\  mov r2, -2005440939
        \\  lsh r2, 32
        \\  or r2, 0x44332211
        \\  stxdw [r1+2], r2
        \\  ldxdw r0, [r1+2]
        \\  return
    ,
        &.{
            0xaa, 0xbb, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xcc, 0xdd,
        },
        .{ 0x8877665544332211, 6 },
    );
}

test "stxb all" {
    try testAsmWithMemory(
        .{},
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
        \\  return
    ,
        &.{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
        .{ 0xf0f2f3f4f5f6f7f8, 19 },
    );

    try testAsmWithMemory(
        .{},
        \\entrypoint:
        \\  mov r0, r1
        \\  mov r1, 0xf1
        \\  mov r9, 0xf9
        \\  stxb [r0], r1
        \\  stxb [r0+1], r9
        \\  ldxh r0, [r0]
        \\  be16 r0
        \\  return
    ,
        &.{ 0xff, 0xff },
        .{ 0xf1f9, 8 },
    );
}

test "stxb chain" {
    try testAsmWithMemory(
        .{},
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
        \\  return
    ,
        &.{
            0x2a, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00,
        },
        .{ 0x2a, 21 },
    );
}

test "return without value" {
    try testAsm(
        .{},
        \\entrypoint:
        \\  return
    ,
        .{ 0x0, 1 },
    );
}

test "return" {
    try testAsm(
        .{},
        \\entrypoint:
        \\  mov r0, 0
        \\  return
    ,
        .{ 0x0, 2 },
    );
}

test "early return" {
    try testAsm(
        .{},
        \\entrypoint:
        \\  mov r0, 3
        \\  return
        \\  mov r0, 4
        \\  return
    ,
        .{ 3, 2 },
    );
}

test "ja" {
    try testAsm(
        .{},
        \\entrypoint:
        \\  mov r0, 1
        \\  ja +1
        \\  mov r0, 2
        \\  return
    ,
        .{ 0x1, 3 },
    );
}

test "ja label" {
    try testAsm(.{},
        \\entrypoint:
        \\  ja foo
        \\  exit
        \\foo:
        \\  mov r0, 10
        \\ exit
    , .{ 10, 3 });
}

test "jeq imm" {
    try testAsm(
        .{},
        \\entrypoint:
        \\  mov32 r0, 0
        \\  mov32 r1, 0xa
        \\  jeq r1, 0xb, +4
        \\  mov32 r0, 1
        \\  mov32 r1, 0xb
        \\  jeq r1, 0xb, +1
        \\  mov32 r0, 2
        \\  return
    ,
        .{ 0x1, 7 },
    );
}

test "jeq reg" {
    try testAsm(
        .{},
        \\entrypoint:
        \\  mov32 r0, 0
        \\  mov32 r1, 0xa
        \\  mov32 r2, 0xb
        \\  jeq r1, r2, +4
        \\  mov32 r0, 1
        \\  mov32 r1, 0xb
        \\  jeq r1, r2, +1
        \\  mov32 r0, 2
        \\  return
    ,
        .{ 0x1, 8 },
    );
}

test "jge imm" {
    try testAsm(
        .{},
        \\entrypoint:
        \\  mov32 r0, 0
        \\  mov32 r1, 0xa
        \\  jge r1, 0xb, +4
        \\  mov32 r0, 1
        \\  mov32 r1, 0xc
        \\  jge r1, 0xb, +1
        \\  mov32 r0, 2
        \\  return
    ,
        .{ 0x1, 7 },
    );
}

test "jge reg" {
    try testAsm(
        .{},
        \\entrypoint:
        \\  mov32 r0, 0
        \\  mov32 r1, 0xa
        \\  mov32 r2, 0xb
        \\  jge r1, r2, +4
        \\  mov32 r0, 1
        \\  mov32 r1, 0xb
        \\  jge r1, r2, +1
        \\  mov32 r0, 2
        \\  return
    ,
        .{ 0x1, 8 },
    );
}

test "jle imm" {
    try testAsm(
        .{},
        \\entrypoint:
        \\  mov32 r0, 0
        \\  mov32 r1, 5
        \\  jle r1, 4, +1
        \\  jle r1, 6, +1
        \\  return
        \\  jle r1, 5, +1
        \\  return
        \\  mov32 r0, 1
        \\  return
    ,
        .{ 0x1, 7 },
    );
}

test "jle reg" {
    try testAsm(
        .{},
        \\entrypoint:
        \\  mov r0, 0
        \\  mov r1, 5
        \\  mov r2, 4
        \\  mov r3, 6
        \\  jle r1, r2, +2
        \\  jle r1, r1, +1
        \\  return
        \\  jle r1, r3, +1
        \\  return
        \\  mov r0, 1
        \\  return
    ,
        .{ 0x1, 9 },
    );
}

test "jle label reg" {
    try testAsm(
        .{},
        \\entrypoint:
        \\  mov r2, 4
        \\  mov r3, 3
        \\  jle r3, r2, foo
        \\  exit
        \\foo:
        \\  mov r0, 10
        \\  exit
    ,
        .{ 10, 5 },
    );
}

test "jgt imm" {
    try testAsm(
        .{},
        \\entrypoint:
        \\  mov32 r0, 0
        \\  mov32 r1, 5
        \\  jgt r1, 6, +2
        \\  jgt r1, 5, +1
        \\  jgt r1, 4, +1
        \\  return
        \\  mov32 r0, 1
        \\  return
    ,
        .{ 0x1, 7 },
    );
}

test "jgt reg" {
    try testAsm(
        .{},
        \\entrypoint:
        \\  mov r0, 0
        \\  mov r1, 5
        \\  mov r2, 6
        \\  mov r3, 4
        \\  jgt r1, r2, +2
        \\  jgt r1, r1, +1
        \\  jgt r1, r3, +1
        \\  return
        \\  mov r0, 1
        \\  return
    ,
        .{ 0x1, 9 },
    );
}

test "jlt imm" {
    try testAsm(
        .{},
        \\entrypoint:
        \\  mov32 r0, 0
        \\  mov32 r1, 5
        \\  jlt r1, 4, +2
        \\  jlt r1, 5, +1
        \\  jlt r1, 6, +1
        \\  return
        \\  mov32 r0, 1
        \\  return
    ,
        .{ 0x1, 7 },
    );
}

test "jlt reg" {
    try testAsm(
        .{},
        \\entrypoint:
        \\  mov r0, 0
        \\  mov r1, 5
        \\  mov r2, 4
        \\  mov r3, 6
        \\  jlt r1, r2, +2
        \\  jlt r1, r1, +1
        \\  jlt r1, r3, +1
        \\  return
        \\  mov r0, 1
        \\  return
    ,
        .{ 0x1, 9 },
    );
}

test "jlt extend" {
    try testAsm(
        .{},
        \\entrypoint:
        \\  mov r0, 0
        \\  add r0, -3
        \\  jlt r0, -2, +2
        \\  mov r0, 1
        \\  return
        \\  mov r0, 2
        \\  return
    ,
        .{ 2, 5 },
    );
}

test "jne imm" {
    try testAsm(
        .{},
        \\entrypoint:
        \\  mov32 r0, 0
        \\  mov32 r1, 0xb
        \\  jne r1, 0xb, +4
        \\  mov32 r0, 1
        \\  mov32 r1, 0xa
        \\  jne r1, 0xb, +1
        \\  mov32 r0, 2
        \\  return
    ,
        .{ 0x1, 7 },
    );
}

test "jne reg" {
    try testAsm(
        .{},
        \\entrypoint:
        \\  mov32 r0, 0
        \\  mov32 r1, 0xb
        \\  mov32 r2, 0xb
        \\  jne r1, r2, +4
        \\  mov32 r0, 1
        \\  mov32 r1, 0xa
        \\  jne r1, r2, +1
        \\  mov32 r0, 2
        \\  return
    ,
        .{ 0x1, 8 },
    );
}

test "jset imm" {
    try testAsm(
        .{},
        \\entrypoint:
        \\  mov32 r0, 0
        \\  mov32 r1, 0x7
        \\  jset r1, 0x8, +4
        \\  mov32 r0, 1
        \\  mov32 r1, 0x9
        \\  jset r1, 0x8, +1
        \\  mov32 r0, 2
        \\  return
    ,
        .{ 0x1, 7 },
    );
}

test "jset reg" {
    try testAsm(
        .{},
        \\entrypoint:
        \\  mov32 r0, 0
        \\  mov32 r1, 0x7
        \\  mov32 r2, 0x8
        \\  jset r1, r2, +4
        \\  mov32 r0, 1
        \\  mov32 r1, 0x9
        \\  jset r1, r2, +1
        \\  mov32 r0, 2
        \\  return
    ,
        .{ 0x1, 8 },
    );
}

test "jsge imm" {
    try testAsm(
        .{},
        \\entrypoint:
        \\  mov32 r0, 0
        \\  mov r1, -2
        \\  jsge r1, -1, +5
        \\  jsge r1, 0, +4
        \\  mov32 r0, 1
        \\  mov r1, -1
        \\  jsge r1, -1, +1
        \\  mov32 r0, 2
        \\  return
    ,
        .{ 0x1, 8 },
    );
}

test "jsge reg" {
    try testAsm(
        .{},
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
        \\ return
    ,
        .{ 0x1, 10 },
    );
}

test "jsle imm" {
    try testAsm(
        .{},
        \\entrypoint:
        \\  mov32 r0, 0
        \\  mov r1, -2
        \\  jsle r1, -3, +1
        \\  jsle r1, -1, +1
        \\  return
        \\  mov32 r0, 1
        \\  jsle r1, -2, +1
        \\  mov32 r0, 2
        \\  return
    ,
        .{ 0x1, 7 },
    );
}

test "jsle reg" {
    try testAsm(
        .{},
        \\entrypoint:
        \\  mov32 r0, 0
        \\  mov r1, -1
        \\  mov r2, -2
        \\  mov32 r3, 0
        \\  jsle r1, r2, +1
        \\  jsle r1, r3, +1
        \\  return
        \\  mov32 r0, 1
        \\  mov r1, r2
        \\  jsle r1, r2, +1
        \\  mov32 r0, 2
        \\  return
    ,
        .{ 0x1, 10 },
    );
}

test "jsgt imm" {
    try testAsm(
        .{},
        \\entrypoint:
        \\  mov32 r0, 0
        \\  mov r1, -2
        \\  jsgt r1, -1, +4
        \\  mov32 r0, 1
        \\  mov32 r1, 0
        \\  jsgt r1, -1, +1
        \\  mov32 r0, 2
        \\  return
    ,
        .{ 0x1, 7 },
    );
}

test "jsgt reg" {
    try testAsm(
        .{},
        \\entrypoint:
        \\  mov32 r0, 0
        \\  mov r1, -2
        \\  mov r2, -1
        \\  jsgt r1, r2, +4
        \\  mov32 r0, 1
        \\  mov32 r1, 0
        \\  jsgt r1, r2, +1
        \\  mov32 r0, 2
        \\  return
    ,
        .{ 0x1, 8 },
    );
}

test "jslt imm" {
    try testAsm(
        .{},
        \\entrypoint:
        \\  mov32 r0, 0
        \\  mov r1, -2
        \\  jslt r1, -3, +2
        \\  jslt r1, -2, +1
        \\  jslt r1, -1, +1
        \\  return
        \\  mov32 r0, 1
        \\  return
    ,
        .{ 0x1, 7 },
    );
}

test "jslt reg" {
    try testAsm(
        .{},
        \\entrypoint:
        \\  mov32 r0, 0
        \\  mov r1, -2
        \\  mov r2, -3
        \\  mov r3, -1
        \\  jslt r1, r1, +2
        \\  jslt r1, r2, +1
        \\  jslt r1, r3, +1
        \\  return
        \\  mov32 r0, 1
        \\  return
    ,
        .{ 0x1, 9 },
    );
}

test "lmul loop" {
    try testAsm(
        .{},
        \\entrypoint:
        \\  mov r0, 0x7
        \\  add r1, 0xa
        \\  lsh r1, 0x20
        \\  rsh r1, 0x20
        \\  jeq r1, 0x0, +4
        \\  mov r0, 0x7
        \\  lmul r0, 0x7
        \\  add r1, -1
        \\  jne r1, 0x0, -3
        \\  return
    ,
        .{ 0x75db9c97, 37 },
    );
}

test "lmul128" {
    try testAsmWithMemory(
        .{},
        \\entrypoint:
        \\  mov r0, r1
        \\  mov r2, 30
        \\  mov r3, 0
        \\  mov r4, 20
        \\  mov r5, 0
        \\  lmul64 r3, r4
        \\  lmul64 r5, r2
        \\  add64 r5, r3
        \\  mov64 r0, r2
        \\  rsh64 r0, 0x20
        \\  mov64 r3, r4
        \\  rsh64 r3, 0x20
        \\  mov64 r6, r3
        \\  lmul64 r6, r0
        \\  add64 r5, r6
        \\  lsh64 r4, 0x20
        \\  rsh64 r4, 0x20
        \\  mov64 r6, r4
        \\  lmul64 r6, r0
        \\  lsh64 r2, 0x20
        \\  rsh64 r2, 0x20
        \\  lmul64 r4, r2
        \\  mov64 r0, r4
        \\  rsh64 r0, 0x20
        \\  add64 r0, r6
        \\  mov64 r6, r0
        \\  rsh64 r6, 0x20
        \\  add64 r5, r6
        \\  lmul64 r3, r2
        \\  lsh64 r0, 0x20
        \\  rsh64 r0, 0x20
        \\  add64 r0, r3
        \\  mov64 r2, r0
        \\  rsh64 r2, 0x20
        \\  add64 r5, r2
        \\  stxdw [r1+0x8], r5
        \\  lsh64 r0, 0x20
        \\  lsh64 r4, 0x20
        \\  rsh64 r4, 0x20
        \\  or64 r0, r4
        \\  stxdw [r1+0x0], r0
        \\  return
    ,
        &(.{0} ** 16),
        .{ 600, 42 },
    );
}

test "prime" {
    try testAsm(
        .{},
        \\entrypoint:
        \\  mov r1, 67
        \\  mov r0, 0x1
        \\  mov r2, 0x2
        \\  jgt r1, 0x2, +4
        \\  ja +10
        \\  add r2, 0x1
        \\  mov r0, 0x1
        \\  jge r2, r1, +7
        \\  mov r3, r1
        \\  udiv r3, r2
        \\  lmul r3, r2
        \\  mov r4, r1
        \\  sub r4, r3
        \\  mov r0, 0x0
        \\  jne r4, 0x0, -10
        \\  return
    ,
        .{ 1, 655 },
    );
}

test "subnet" {
    try testAsmWithMemory(
        .{},
        \\entrypoint:
        \\  mov r2, 0xe
        \\  ldxh r3, [r1+12]
        \\  jne r3, 0x81, +2
        \\  mov r2, 0x12
        \\  ldxh r3, [r1+16]
        \\  and r3, 0xffff
        \\  jne r3, 0x8, +5
        \\  add r1, r2
        \\  mov r0, 0x1
        \\  ldxw r1, [r1+16]
        \\  and r1, 0xffffff
        \\  jeq r1, 0x1a8c0, +1
        \\  mov r0, 0x0
        \\  return
    ,
        &.{
            0x00, 0x00, 0xc0, 0x9f, 0xa0, 0x97, 0x00, 0xa0, 0xcc, 0x3b,
            0xbf, 0xfa, 0x08, 0x00, 0x45, 0x10, 0x00, 0x3c, 0x46, 0x3c,
            0x40, 0x00, 0x40, 0x06, 0x73, 0x1c, 0xc0, 0xa8, 0x01, 0x02,
            0xc0, 0xa8, 0x01, 0x01, 0x06, 0x0e, 0x00, 0x17, 0x99, 0xc5,
            0xa0, 0xec, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0x7d, 0x78,
            0xe0, 0xa3, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02,
            0x08, 0x0a, 0x00, 0x9c, 0x27, 0x24, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x03, 0x03, 0x00,
        },
        .{ 0x1, 11 },
    );
}

test "fib" {
    try testAsm(.{},
        \\entrypoint:
        \\  mov r0, 10
        \\  call function_fib ; Compute the 10th Fibonacci number
        \\  exit ; Returns the computed value
        \\
        \\; Passes N in r0
        \\; Returns the Nth Fibonacci number in r0
        \\function_fib:
        \\  mov r1, 0       ; Fib(0) = 0
        \\  mov r2, 1       ; Fib(1) = 1
        \\  jle r0, 1, done ; If N <= 1, return r0 (Fib(0) or Fib(1))
        \\loop:
        \\  add r1, r2      ; r1 = r1 + r2 (next Fib number)
        \\  mov r3, r2      ; Store the old r2 value
        \\  mov r2, r1      ; Update r2 to new Fib number
        \\  mov r1, r3      ; Move the previous r2 into r1
        \\  add r0, -1      ; Decrement N
        \\  jgt r0, 1, loop ; Continue the loop if N > 1
        \\done:
        \\  mov r0, r2      ; Return the last computed Fibonacci number
        \\  exit
    , .{ 55, 62 });
}

test "pqr" {
    const allocator = std.testing.allocator;
    var program: [48]u8 = .{0} ** 48;
    // mov64 r0, X
    program[0] = @intFromEnum(OpCode.mov64_imm);
    // hor64 r0, X
    program[8] = @intFromEnum(OpCode.hor64_imm);

    // mov64 r1, X
    program[16] = @intFromEnum(OpCode.mov64_imm);
    program[17] = 1; // dst = r1
    // hor64 r1, X
    program[24] = @intFromEnum(OpCode.hor64_imm);
    program[25] = 1; // dst = r1

    // set the instruction we're testing to use r1 as the src
    program[33] = 16; // src = r1
    program[40] = @intFromEnum(OpCode.exit_or_syscall);

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var cache, var tc = try createTransactionContext(
        allocator,
        prng.random(),
        .{ .compute_meter = 6 },
    );
    defer {
        deinitTranactionContext(allocator, &tc);
        cache.deinit(allocator);
    }

    const max_int = std.math.maxInt(u64);
    inline for (
        // zig fmt: off
        [_]struct { OpCode, u64, u64, u64 }{
            .{ OpCode.udiv32_reg,  13, 4, 3 },
            .{ OpCode.uhmul64_reg, 13, 4, 0 },
            .{ OpCode.udiv32_reg,  13, 4, 3 },
            .{ OpCode.udiv64_reg,  13, 4, 3 },
            .{ OpCode.urem32_reg,  13, 4, 1 },
            .{ OpCode.urem64_reg,  13, 4, 1 },

            .{ OpCode.uhmul64_reg, 13, max_int, 12 },
            .{ OpCode.udiv32_reg,  13, max_int, 0 },
            .{ OpCode.udiv64_reg,  13, max_int, 0 },
            .{ OpCode.urem32_reg,  13, max_int, 13 },
            .{ OpCode.urem64_reg,  13, max_int, 13 },

            .{ OpCode.uhmul64_reg, max_int, 4, 3 },
            .{ OpCode.udiv32_reg,  max_int, 4, std.math.maxInt(u32) / 4 },
            .{ OpCode.udiv64_reg,  max_int, 4, max_int / 4 },
            .{ OpCode.urem32_reg,  max_int, 4, 3 },
            .{ OpCode.urem64_reg,  max_int, 4, 3 },

            .{ OpCode.uhmul64_reg, max_int, max_int, max_int - 1 },
            .{ OpCode.udiv32_reg,  max_int, max_int, 1 },
            .{ OpCode.udiv64_reg,  max_int, max_int, 1 },
            .{ OpCode.urem32_reg,  max_int, max_int, 0 },
            .{ OpCode.urem64_reg,  max_int, max_int, 0 },

            .{ OpCode.lmul32_reg,  13, 4, 52 },
            .{ OpCode.lmul64_reg,  13, 4, 52 },
            .{ OpCode.shmul64_reg, 13, 4, 0 },
            .{ OpCode.sdiv32_reg,  13, 4, 3 },
            .{ OpCode.sdiv64_reg,  13, 4, 3 },
            .{ OpCode.srem32_reg,  13, 4, 1 },
            .{ OpCode.srem64_reg,  13, 4, 1 },

            .{ OpCode.lmul32_reg,  13, ~@as(u64, 3), ~@as(u32, 51) },
            .{ OpCode.lmul64_reg,  13, ~@as(u64, 3), ~@as(u64, 51) },
            .{ OpCode.shmul64_reg, 13, ~@as(u64, 3), ~@as(u64, 0) },
            .{ OpCode.sdiv32_reg,  13, ~@as(u32, 3), ~@as(u32, 2) },
            .{ OpCode.sdiv64_reg,  13, ~@as(u64, 3), ~@as(u64, 2) },
            .{ OpCode.srem32_reg,  13, ~@as(u32, 3), 1 },
            .{ OpCode.srem64_reg,  13, ~@as(u64, 3), 1 },

            .{ OpCode.lmul32_reg,  ~@as(u64, 12), 4, ~@as(u32, 51) },
            .{ OpCode.lmul64_reg,  ~@as(u64, 12), 4, ~@as(u64, 51) },
            .{ OpCode.shmul64_reg, ~@as(u64, 12), 4, ~@as(u64, 0) },
            .{ OpCode.sdiv32_reg,  ~@as(u64, 12), 4, ~@as(u32, 2) },
            .{ OpCode.sdiv64_reg,  ~@as(u64, 12), 4, ~@as(u64, 2) },
            .{ OpCode.srem32_reg,  ~@as(u64, 12), 4, ~@as(u32, 0) },
            .{ OpCode.srem64_reg,  ~@as(u64, 12), 4, ~@as(u64, 0) },

            .{ OpCode.lmul32_reg,  ~@as(u64, 12), ~@as(u32, 3), 52 },
            .{ OpCode.lmul64_reg,  ~@as(u64, 12), ~@as(u64, 3), 52 },
            .{ OpCode.shmul64_reg, ~@as(u64, 12), ~@as(u64, 3), 0 },
            .{ OpCode.sdiv32_reg,  ~@as(u64, 12), ~@as(u32, 3), 3 },
            .{ OpCode.sdiv64_reg,  ~@as(u64, 12), ~@as(u64, 3), 3 },
            .{ OpCode.srem32_reg,  ~@as(u64, 12), ~@as(u32, 3), ~@as(u32, 0) },
            .{ OpCode.srem64_reg,  ~@as(u64, 12), ~@as(u64, 3), ~@as(u64, 0) },
        },
        // zig fmt: on
    ) |entry| {
        const opc, const dst, const src, const expected = entry;
        std.mem.writeInt(u32, program[4..][0..4], @truncate(dst), .little);
        std.mem.writeInt(u32, program[12..][0..4], @truncate(dst >> 32), .little);
        std.mem.writeInt(u32, program[20..][0..4], @truncate(src), .little);
        std.mem.writeInt(u32, program[28..][0..4], @truncate(src >> 32), .little);
        std.mem.writeInt(u32, program[36..][0..4], @truncate(src), .little);
        program[32] = @intFromEnum(opc);

        const config: Config = .{ .maximum_version = .v2 };

        var registry: sig.vm.Registry = .{};
        var loader: SyscallMap = .ALL_DISABLED;
        var executable = try Executable.fromTextBytes(
            allocator,
            &program,
            &loader,
            &registry,
            false,
            config,
        );
        defer executable.deinit(allocator);

        const map = try MemoryMap.init(allocator, &.{}, .v2, .{});

        tc.compute_meter = 6;
        var vm = try Vm.init(
            allocator,
            &executable,
            map,
            &loader,
            0,
            &tc,
        );
        defer vm.deinit();

        try expectEqual(expected, vm.run()[0].ok);
    }
}

test "pqr divide by zero" {
    const allocator = std.testing.allocator;
    var program: [24]u8 = .{0} ** 24;
    program[0] = @intFromEnum(OpCode.mov32_imm);
    program[16] = @intFromEnum(OpCode.exit_or_syscall);

    // TODO: Why does this cause a transitive error when using inline?
    for ([_]OpCode{
        OpCode.udiv32_reg,
        OpCode.udiv64_reg,
        OpCode.urem32_reg,
        OpCode.urem64_reg,
        OpCode.sdiv32_reg,
        OpCode.sdiv64_reg,
        OpCode.srem32_reg,
        OpCode.srem64_reg,
    }) |opcode| {
        program[8] = @intFromEnum(opcode);

        const config: Config = .{ .maximum_version = .v2 };

        var registry: sig.vm.Registry = .{};
        var loader: SyscallMap = .ALL_DISABLED;
        var executable = try Executable.fromTextBytes(
            allocator,
            &program,
            &loader,
            &registry,
            false,
            config,
        );
        defer executable.deinit(allocator);

        const map = try MemoryMap.init(allocator, &.{}, .v3, .{});
        var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

        var cache, var tc = try createTransactionContext(
            allocator,
            prng.random(),
            .{ .compute_meter = 2 },
        );
        defer {
            deinitTranactionContext(allocator, &tc);
            cache.deinit(allocator);
        }

        var vm = try Vm.init(
            allocator,
            &executable,
            map,
            &loader,
            0,
            &tc,
        );
        defer vm.deinit();

        try expectEqual(error.DivisionByZero, vm.run()[0].err);
    }
}

test "stack1" {
    try testAsm(
        .{},
        \\entrypoint:
        \\  mov r1, 51
        \\  stdw [r10-16], 0xab
        \\  stdw [r10-8], 0xcd
        \\  and r1, 1
        \\  lsh r1, 3
        \\  mov r2, r10
        \\  add r2, r1
        \\  ldxdw r0, [r2-16]
        \\  return
    ,
        .{ 0xcd, 9 },
    );
}

test "entrypoint return" {
    try testAsm(
        .{},
        \\entrypoint:
        \\  call function_foo
        \\  mov r0, 42
        \\  return
        \\function_foo:
        \\  mov r0, 12
        \\  return
    ,
        .{ 42, 5 },
    );
}

test "call depth in bounds" {
    try testAsm(
        .{},
        \\entrypoint:
        \\  mov r1, 0
        \\  mov r2, 63
        \\  call function_foo
        \\  mov r0, r1
        \\  return
        \\function_foo:
        \\  add r1, 1
        \\  jeq r1, r2, +1
        \\  call function_foo
        \\  return
    ,
        .{ 63, 256 },
    );
}

test "call depth out of bounds" {
    try testAsm(.{},
        \\entrypoint:
        \\  mov r1, 0
        \\  mov r2, 64
        \\  call function_foo
        \\  mov r0, r1
        \\  return
        \\function_foo:
        \\  add r1, 1
        \\  jeq r1, r2, +1
        \\  call function_foo
        \\  return
    , .{ error.CallDepthExceeded, 192 });
}

test "callx imm" {
    try testAsm(
        .{ .maximum_version = .v0 },
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
    ,
        .{ 42, 8 },
    );
}

test "callx out of bounds low" {
    try testAsm(.{ .maximum_version = .v0 },
        \\entrypoint:
        \\  mov64 r0, 0x3
        \\  callx r0
        \\  exit
    , .{ error.CallOutsideTextSegment, 2 });
}

test "callx out of bounds high" {
    try testAsm(.{},
        \\entrypoint:
        \\  mov64 r0, -0x1
        \\  lsh64 r0, 0x20
        \\  or64 r0, 0x3
        \\  callx r0
        \\  return
    , .{ error.CallOutsideTextSegment, 4 });
}

test "callx out of bounds max" {
    try testAsm(.{},
        \\entrypoint:
        \\  mov64 r0, -0x8
        \\  hor64 r0, -0x1
        \\  callx r0
        \\  return
    , .{ error.CallOutsideTextSegment, 3 });
}

test "call bpf 2 bpf" {
    try testAsm(.{},
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
        \\  return
        \\function_foo:
        \\  mov64 r6, 0x00
        \\  mov64 r7, 0x00
        \\  mov64 r8, 0x00
        \\  mov64 r9, 0x00
        \\  return
    , .{ 0xFF, 15 });
}

test "fixed stack out of bounds" {
    try testAsm(.{ .maximum_version = .v0 },
        \\entrypoint:
        \\  stb [r10-0x4000], 0
        \\  exit
    , .{ error.AccessViolation, 1 });
}

test "decrease frame pointer on v0" {
    const config: Config = .{ .maximum_version = .v0 };
    try testAsm(config,
        \\entrypoint:
        \\  call function_foo
        \\  mov r0, r10
        \\  exit
        \\function_foo:
        \\  exit
    , .{ memory.STACK_START + config.stack_frame_size, 4 });
}

test "dynamic frame pointer" {
    const config: Config = .{};
    try testAsm(
        config,
        \\entrypoint:
        \\  add r10, -64
        \\  stxdw [r10+8], r10
        \\  call function_foo
        \\  ldxdw r0, [r10+8]
        \\  return
        \\function_foo:
        \\  return
    ,
        .{ memory.STACK_START + config.stackSize() - 64, 6 },
    );

    try testAsm(
        config,
        \\entrypoint:
        \\  add r10, -64
        \\  call function_foo
        \\  return
        \\function_foo:
        \\  mov r0, r10
        \\  return
    ,
        .{ memory.STACK_START + config.stackSize() - 64, 5 },
    );

    try testAsm(
        config,
        \\entrypoint:
        \\  call function_foo
        \\  mov r0, r10
        \\  return
        \\function_foo:
        \\  add r10, -64
        \\  return
    ,
        .{ memory.STACK_START + config.stackSize(), 5 },
    );
}

// ELF Tests

fn testElf(config: Config, path: []const u8, expected: anytype) !void {
    return testElfWithSyscalls(
        config,
        path,
        &.{},
        expected,
    );
}

pub fn testElfWithSyscalls(
    config: Config,
    path: []const u8,
    extra_syscalls: []const Syscall,
    expected: anytype,
) !void {
    const allocator = std.testing.allocator;

    const input_file = try std.fs.cwd().openFile(path, .{});
    const bytes = try input_file.readToEndAlloc(allocator, sbpf.MAX_FILE_SIZE);
    defer allocator.free(bytes);

    var loader: SyscallMap = .ALL_DISABLED;
    for (extra_syscalls) |syscall| loader.enable(syscall);

    const elf = try Elf.parse(allocator, bytes, &loader, config);
    var executable = Executable.fromElf(elf);
    defer executable.deinit(allocator);

    try executable.verify(&loader);

    const stack_memory = try allocator.alloc(u8, config.stackSize());
    defer allocator.free(stack_memory);

    const m = try MemoryMap.init(
        allocator,
        &.{
            executable.getProgramRegion(),
            Region.init(.mutable, stack_memory, memory.STACK_START),
            Region.init(.constant, &.{}, memory.HEAP_START),
            Region.init(.mutable, &.{}, memory.INPUT_START),
        },
        config.maximum_version,
        config,
    );

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var cache, var tc = try createTransactionContext(
        allocator,
        prng.random(),
        .{
            .accounts = &.{
                .{ .pubkey = sig.runtime.program.system.ID },
            },
            .compute_meter = expected[1],
        },
    );
    defer {
        sig.runtime.testing.deinitTransactionContext(allocator, &tc);
        cache.deinit(allocator);
    }

    const instr_info = InstructionInfo{
        .program_meta = .{
            .index_in_transaction = 0,
            .pubkey = sig.runtime.program.system.ID,
        },
        .account_metas = .{},
        .dedupe_map = @splat(0xff),
        .instruction_data = &.{},
        .owned_instruction_data = false,
        .initial_account_lamports = 0,
    };

    try executor.pushInstruction(&tc, instr_info);

    var vm = try Vm.init(
        allocator,
        &executable,
        m,
        &loader,
        stack_memory.len,
        &tc,
    );
    defer vm.deinit();

    const expected_result, const expected_instruction_count = expected;
    const result, const instruction_count = vm.run();
    try expectEqual(VmResult.fromValue(expected_result), result);
    try expectEqual(expected_instruction_count, instruction_count);
}

test "BPF_64_64 sbpfv0" {
    // [ 1] .text             PROGBITS        0000000000000120 000120 000018 00  AX  0   0  8
    // prints the address of the first byte in the .text section
    try testElf(
        .{ .maximum_version = .v0 },
        sig.ELF_DATA_DIR ++ "reloc_64_64_sbpfv0.so",
        .{ memory.RODATA_START + 0x120, 2 },
    );
}

test "BPF_64_64" {
    // 0000000100000000  0000000100000001 R_SBF_64_64            0000000100000000 entrypoint
    try testElf(
        .{},
        sig.ELF_DATA_DIR ++ "reloc_64_64.so",
        .{ memory.BYTECODE_START, 3 },
    );
}

test "BPF_64_RELATIVE data sbpv0" {
    // 4: 0000000000000140     8 OBJECT  LOCAL  DEFAULT     3 reloc_64_relative_data.DATA
    // 0000000000000140  0000000000000008 R_BPF_64_RELATIVE
    try testElf(
        .{ .maximum_version = .v0 },
        sig.ELF_DATA_DIR ++ "reloc_64_relative_data_sbpfv0.so",
        .{ memory.RODATA_START + 0x140, 2 },
    );
}

test "BPF_64_RELATIVE data" {
    // 2: 0000000100000008     8 OBJECT  LOCAL  DEFAULT     2 reloc_64_relative_data.DATA
    try testElf(
        .{},
        sig.ELF_DATA_DIR ++ "reloc_64_relative_data.so",
        .{ memory.RODATA_START + 0x8, 3 },
    );
}

test "BPF_64_RELATIVE sbpv0" {
    try testElf(
        .{ .maximum_version = .v0 },
        sig.ELF_DATA_DIR ++ "reloc_64_relative_sbpfv0.so",
        .{ memory.RODATA_START + 0x138, 2 },
    );
}

test "load elf rodata sbpfv0" {
    try testElf(
        .{ .maximum_version = .v0 },
        sig.ELF_DATA_DIR ++ "rodata_section_sbpfv0.so",
        .{ 42, 7 },
    );
}

test "load elf rodata" {
    try testElf(
        .{ .optimize_rodata = false },
        sig.ELF_DATA_DIR ++ "rodata_section.so",
        .{ 42, 10 },
    );
}

test "syscall reloc 64_32" {
    try testElfWithSyscalls(
        .{ .maximum_version = .v0 },
        sig.ELF_DATA_DIR ++ "syscall_reloc_64_32_sbpfv0.so",
        &.{.sol_log_},
        .{ 0, 105 },
    );
}

test "static syscall" {
    try testElfWithSyscalls(
        .{},
        sig.ELF_DATA_DIR ++ "syscall_static.so",
        &.{.sol_log_},
        .{ 0, 106 },
    );
}

test "struct func pointer" {
    try testElfWithSyscalls(
        .{},
        sig.ELF_DATA_DIR ++ "struct_func_pointer.so",
        &.{},
        .{ 0x0102030405060708, 3 },
    );
}

test "struct func pointer sbpfv0" {
    try testElfWithSyscalls(
        .{ .maximum_version = .v0 },
        sig.ELF_DATA_DIR ++ "struct_func_pointer_sbpfv0.so",
        &.{},
        .{ 0x0102030405060708, 2 },
    );
}

test "data section" {
    // [ 6] .data             PROGBITS        0000000000000250 000250 000004 00  WA  0   0  4
    try expectEqual(
        error.WritableSectionsNotSupported,
        testElfWithSyscalls(
            .{ .maximum_version = .v0 },
            sig.ELF_DATA_DIR ++ "data_section_sbpfv0.so",
            &.{},
            .{ 0, 0 },
        ),
    );
}

test "bss section" {
    // [ 6] .bss              NOBITS          0000000000000250 000250 000004 00  WA  0   0  4
    try expectEqual(
        error.WritableSectionsNotSupported,
        testElfWithSyscalls(
            .{ .maximum_version = .v0 },
            sig.ELF_DATA_DIR ++ "bss_section_sbpfv0.so",
            &.{},
            .{ 0, 0 },
        ),
    );
}

// Verification tests

fn testVerify(
    config: Config,
    source: []const u8,
    expected: anytype,
) !void {
    try testVerifyWithSyscalls(config, source, &.{}, expected);
}

fn testVerifyTextBytes(
    config: Config,
    program: []const u8,
    expected: anytype,
) !void {
    try testVerifyTextBytesWithSyscalls(config, program, &.{}, expected);
}

fn testVerifyTextBytesWithSyscalls(
    config: Config,
    program: []const u8,
    extra_syscalls: []const Syscall,
    expected: anytype,
) !void {
    const allocator = std.testing.allocator;

    var loader: SyscallMap = .ALL_DISABLED;
    for (extra_syscalls) |syscall| loader.enable(syscall);

    var function_registry: sig.vm.Registry = .{};
    var executable = try Executable.fromTextBytes(
        allocator,
        program,
        &loader,
        &function_registry,
        false,
        config,
    );
    defer executable.deinit(allocator);

    const result = executable.verify(&loader);
    try expectEqual(expected, result);
}

fn testVerifyWithSyscalls(
    config: Config,
    source: []const u8,
    extra_syscalls: []const Syscall,
    expected: anytype,
) !void {
    const allocator = std.testing.allocator;

    var loader: SyscallMap = .ALL_DISABLED;
    for (extra_syscalls) |entry| loader.enable(entry);

    var executable = try Executable.fromAsm(allocator, source, config);
    defer executable.deinit(allocator);

    const result = executable.verify(&loader);
    try expectEqual(expected, result);
}

test "verifier div by zero immediate" {
    try testVerify(.{},
        \\entrypoint:
        \\  mov32 r0, 1
        \\  udiv32 r0, 0
        \\  exit
    , error.DivisionByZero);
}

test "endian size" {
    try testVerifyTextBytes(
        .{},
        &.{
            0xdc, 0x01, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
            0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x9d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        },
        error.UnsupportedLEBEArgument,
    );
}

test "incomplete lddw" {
    try testVerifyTextBytes(
        .{},
        &.{
            0x18, 0x00, 0x00, 0x00, 0x88, 0x77, 0x66, 0x55,
            0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        },
        error.InvalidFunction,
    );
}

test "lddw cannot be last" {
    try testVerifyTextBytes(
        .{},
        &.{
            0x18, 0x00, 0x00, 0x00, 0x88, 0x77, 0x66, 0x55,
        },
        error.InvalidFunction,
    );
}

test "invalid dst reg" {
    inline for (.{ .v0, .v3 }) |sbpf_version| {
        try testVerify(.{ .maximum_version = sbpf_version },
            \\entrypoint:
            \\  mov pc, 1
            \\  exit
        , error.InvalidDestinationRegister);
    }
}

test "invalid src reg" {
    inline for (.{ .v0, .v3 }) |sbpf_version| {
        try testVerify(.{ .maximum_version = sbpf_version },
            \\entrypoint:
            \\  mov r0, pc
            \\  exit
        , error.InvalidSourceRegister);
    }
}

test "resize stack pointer success" {
    try testVerify(.{},
        \\entrypoint:
        \\  add r10, -64
        \\  add r10, 64
        \\  exit
    , {});
}

test "unaligned stack" {
    try testVerify(.{},
        \\entrypoint:
        \\  add r10, 63
        \\  exit
    , error.UnalignedImmediate);
}

test "negative unaligned stack" {
    try testVerify(.{},
        \\entrypoint:
        \\  add r10, -63
        \\  exit
    , error.UnalignedImmediate);
}

test "jump to middle of lddw" {
    try testVerify(.{},
        \\entrypoint:
        \\  ja +1
        \\  lddw r0, 0x1122334455667788
        \\  exit
    , error.JumpToMiddleOfLddw);
}

test "call lddw" {
    try testVerify(.{},
        \\entrypoint:
        \\  call 1
        \\  lddw r0, 0x1122334455667788
        \\  exit
    , error.InvalidFunction);
}

test "callx r10" {
    inline for (.{ .v0, .v3 }) |sbpf_version| {
        try testVerify(.{ .maximum_version = sbpf_version },
            \\entrypoint:
            \\  callx r10
            \\  exit
        , error.InvalidRegister);
    }
}

test "function fallthrough" {
    try testVerify(.{},
        \\entrypoint:
        \\  mov r0, r1
        \\function_foo:
        \\  exit
    , error.InvalidFunction);
}

test "jump out" {
    try testVerify(.{},
        \\entrypoint:
        \\  ja +2
        \\  exit
    , error.JumpOutOfCode);
}

test "jump out start" {
    try testVerify(.{},
        \\entrypoint:
        \\  ja -2
        \\  exit
    , error.JumpOutOfCode);
}

test "invalid return" {
    try testVerifyTextBytes(
        .{ .maximum_version = .v0 },
        &.{
            0x9d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        },
        error.UnsupportedInstruction,
    );
}

test "invalid exit" {
    try testVerifyTextBytes(
        .{},
        &.{
            0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        },
        error.InvalidFunction,
    );
}

test "unknown syscall" {
    try testVerifyTextBytes(
        .{},
        &.{
            0x95, 0x00, 0x00, 0x00, 0xBD, 0x59, 0x75, 0x20, // syscall sol_log_
            0x9d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // return
        },
        error.InvalidSyscall,
    );
}

test "known syscall" {
    try testVerifyTextBytesWithSyscalls(
        .{},
        &.{
            0x95, 0x00, 0x00, 0x00, 0xBD, 0x59, 0x75, 0x20, // syscall sol_log_
            0x9d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // return
        },
        &.{.sol_log_},
        {},
    );
}

test "write r10" {
    try testVerify(.{},
        \\entrypoint:
        \\  mov r10, 1
        \\  exit
    , error.CannotWriteR10);
}

test "neg invalid on v3" {
    try testVerify(.{},
        \\entrypoint:
        \\  neg32 r0
        \\  exit
    , error.UnsupportedInstruction);
}

test "lddw invalid on v3" {
    try testVerify(.{},
        \\entrypoint:
        \\  lddw r0, 0x1122334455667788
        \\  exit
    , error.UnsupportedInstruction);
}

test "le invalid on v3" {
    try testVerify(.{},
        \\entrypoint:
        \\  le16 r0
        \\  exit
    , error.UnsupportedInstruction);

    try testVerify(.{},
        \\entrypoint:
        \\  le32 r0
        \\  exit
    , error.UnsupportedInstruction);

    try testVerify(.{},
        \\entrypoint:
        \\  le64 r0
        \\  exit
    , error.UnsupportedInstruction);
}

test "shift overflows" {
    const allocator = std.testing.allocator;
    const testcases = &.{
        .{ "lsh32 r0, 16", {} },
        .{ "lsh32 r0, 32", error.ShiftWithOverflow },
        .{ "lsh32 r0, 64", error.ShiftWithOverflow },
        // rsh32_imm
        .{ "rsh32 r0, 16", {} },
        .{ "rsh32 r0, 32", error.ShiftWithOverflow },
        .{ "rsh32 r0, 64", error.ShiftWithOverflow },
        // arsh32_imm
        .{ "arsh32 r0, 16", {} },
        .{ "arsh32 r0, 32", error.ShiftWithOverflow },
        .{ "arsh32 r0, 64", error.ShiftWithOverflow },
        // lsh64_imm
        .{ "lsh64 r0, 32", {} },
        .{ "lsh64 r0, 64", error.ShiftWithOverflow },
        // rsh64_imm
        .{ "rsh64 r0, 32", {} },
        .{ "rsh64 r0, 64", error.ShiftWithOverflow },

        // arsh64_imm
        .{ "arsh64 r0, 32", {} },
        .{ "arsh64 r0, 64", error.ShiftWithOverflow },
    };

    inline for (testcases) |case| {
        const name, const expected = case;
        const assembly = try std.fmt.allocPrint(allocator,
            \\entrypoint:
            \\  {s}
            \\  exit
        , .{name});
        defer allocator.free(assembly);
        try testVerify(.{}, assembly, expected);
    }
}

test "sdiv disabled" {
    const allocator = std.testing.allocator;
    inline for (.{
        "sdiv32 r0, 2",
        "sdiv32 r0, r1",
        "sdiv64 r0, 4",
        "sdiv64 r0, r1",
    }) |inst| {
        inline for (.{ .v0, .v3 }) |sbpf_version| {
            const assembly = try std.fmt.allocPrint(allocator,
                \\entrypoint:
                \\  {s}
                \\  exit
            , .{inst});
            defer allocator.free(assembly);
            try testVerify(
                .{ .maximum_version = sbpf_version },
                assembly,
                switch (sbpf_version) {
                    .v0 => error.UnsupportedInstruction,
                    .v3 => {},
                    else => unreachable,
                },
            );
        }
    }
}

test "return instruction" {
    inline for (.{ .v0, .v3 }) |sbpf_version| {
        try testVerifyTextBytes(
            .{ .maximum_version = sbpf_version },
            &.{
                0xbf, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, // mov64 r0, 2
                0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit (v1), syscall (v2)
                0x9d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // return
            },
            switch (sbpf_version) {
                .v0 => error.UnsupportedInstruction,
                .v3 => error.InvalidSyscall,
                else => unreachable,
            },
        );
    }
}

test "return in v2" {
    try testVerify(.{},
        \\entrypoint:
        \\  mov r0, 2
        \\  return
    , {});
}

test "function without return" {
    try testVerify(.{},
        \\entrypoint:
        \\  mov r0, 2
        \\  add64 r0, 5
    , error.InvalidFunction);
}

pub fn testSyscall(
    comptime syscall_func: anytype,
    regions: []const memory.Region,
    comptime test_cases: []const struct { [5]u64, syscalls.Error!u64 },
    comptime verify_func: ?fn (
        *sig.runtime.TransactionContext,
        *MemoryMap,
        anytype,
    ) anyerror!void,
    config: struct {
        align_memory_map: bool = false,
        version: sbpf.Version = .v3,
        compute_meter: u64 = 10_000,
    },
) !void {
    const testing = sig.runtime.testing;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    var cache, var tc = try testing.createTransactionContext(allocator, prng.random(), .{
        .accounts = &.{.{
            .pubkey = sig.core.Pubkey.initRandom(prng.random()),
            .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        }},
        .compute_meter = config.compute_meter,
    });
    defer {
        sig.runtime.testing.deinitTransactionContext(allocator, &tc);
        cache.deinit(allocator);
    }

    var registers = sig.vm.interpreter.RegisterMap.initFill(0);
    var memory_map = try MemoryMap.init(
        allocator,
        regions,
        config.version,
        .{ .aligned_memory_mapping = config.align_memory_map },
    );
    defer memory_map.deinit(allocator);

    for (test_cases) |case| {
        const args, const expected = case;
        for (args, 0..) |a, i| {
            registers.set(@enumFromInt(i + 1), a);
        }

        const result = syscall_func(&tc, &memory_map, &registers);
        if (expected) |value| {
            try result;
            try std.testing.expectEqual(value, registers.get(.r0));
            if (verify_func) |func| try func(&tc, &memory_map, args);
        } else |expected_err| {
            try std.testing.expectError(expected_err, result);
        }
    }
}
