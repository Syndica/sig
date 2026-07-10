const std = @import("std");
const sig = @import("shared");
const runtime = @import("../lib.zig");
const tracy = @import("tracy");

const sbpf = runtime.vm.sbpf;
const memory = runtime.vm.memory;

const Instruction = sbpf.Instruction;
const Register = Instruction.Register;
const SyscallMap = runtime.vm.SyscallMap;

pub const Executable = struct {
    bytes: []const u8,
    instructions: []align(1) const Instruction,
    version: sbpf.Version,
    entry_pc: u64,
    from_asm: bool,
    ro_section: Section,
    text_vaddr: u64,
    function_registry: Registry,
    config: Config,
    text_section_len: u64,

    pub fn fromAsm(
        allocator: std.mem.Allocator,
        source: []const u8,
        config: Config,
    ) !Executable {
        var function_registry, const instructions = try Assembler.parse(
            allocator,
            source,
            config,
        );
        // loader isn't owned by the executable, so it's fine for it to
        // die on the stack after the function returns
        var loader: SyscallMap = .ALL_DISABLED;
        return fromTextBytes(
            allocator,
            std.mem.sliceAsBytes(instructions),
            &loader,
            &function_registry,
            true,
            config,
        );
    }

    pub fn fromTextBytes(
        allocator: std.mem.Allocator,
        source: []const u8,
        loader: *SyscallMap,
        registry: *Registry,
        from_asm: bool,
        config: Config,
    ) !Executable {
        const version = config.maximum_version;

        const entry_pc = if (registry.lookupName("entrypoint")) |entry_pc|
            entry_pc.value
        else pc: {
            _ = try registry.registerHashedLegacy(
                allocator,
                loader,
                !version.enableStaticSyscalls(),
                "entrypoint",
                0,
            );
            break :pc 0;
        };

        if (source.len % 8 != 0) return error.ProgramLengthNotMultiple;
        return .{
            .instructions = std.mem.bytesAsSlice(Instruction, source),
            .bytes = source,
            .text_section_len = source.len,
            .version = version,
            .config = config,
            .function_registry = registry.*,
            .entry_pc = entry_pc,
            .ro_section = .{ .borrowed = .{
                .offset = if (version.enableLowerRodataVaddr())
                    memory.RODATA_START
                else
                    memory.BYTECODE_START,
                .start = 0,
                .end = source.len,
            } },
            .from_asm = from_asm,
            .text_vaddr = memory.BYTECODE_START,
        };
    }

    const VerifierError = error{
        NoProgram,
        ProgramLengthNotMultiple,
        DivisionByZero,
        UnsupportedLEBEArgument,
        LddwCannotBeLast,
        IncompleteLddw,
        JumpOutOfCode,
        InvalidSourceRegister,
        CannotWriteR10,
        InvalidDestinationRegister,
        UnknownOpCode,
        InvalidRegister,
        InvalidSyscall,
        InvalidFunction,
        UnalignedImmediate,
        ShiftWithOverflow,
        JumpToMiddleOfLddw,
    };

    /// [agave] https://github.com/anza-xyz/sbpf/blob/v0.20.0/src/verifier.rs#L222
    pub fn verify(self: *const Executable) VerifierError!void {
        const zone = tracy.Zone.init(@src(), .{ .name = "Executable.Verify" });
        defer zone.deinit();

        const version = self.version;
        const instructions = self.instructions;

        if (self.text_section_len % 8 != 0) return error.ProgramLengthNotMultiple;
        if (instructions.len == 0) return error.NoProgram;

        var pc: u64 = 0;
        while (pc + 1 <= instructions.len) : (pc += 1) {
            const inst = instructions[pc];
            var store: bool = false;

            switch (inst.opcode) {
                .add64_reg,
                .add32_imm,
                .add32_reg,
                .sub64_imm,
                .sub64_reg,
                .sub32_imm,
                .sub32_reg,
                .mov64_imm,
                .mov64_reg,
                .mov32_imm,
                .mov32_reg,
                .or64_imm,
                .or64_reg,
                .or32_imm,
                .or32_reg,
                .and64_imm,
                .and64_reg,
                .and32_imm,
                .and32_reg,
                .lsh32_reg,
                .lsh64_reg,
                .rsh32_reg,
                .rsh64_reg,
                .xor64_imm,
                .xor64_reg,
                .xor32_imm,
                .xor32_reg,
                .arsh32_reg,
                .arsh64_reg,
                => {}, // nothing to verify

                .add64_imm => if (version.manualStackFrameBump() and inst.dst == .r10) {
                    if (!std.mem.isAligned(inst.imm, 64)) return error.UnalignedImmediate;
                },

                .lsh32_imm,
                .rsh32_imm,
                .arsh32_imm,
                => if (inst.imm >= 32) return error.ShiftWithOverflow,

                .lsh64_imm,
                .rsh64_imm,
                .arsh64_imm,
                => if (inst.imm >= 64) return error.ShiftWithOverflow,

                .neg32,
                => if (version.disableNegation()) return error.UnknownOpCode,

                .mul32_reg,
                .div32_reg,
                .mod32_reg,
                => {},

                .mul64_imm,
                .mul64_reg,
                .div64_reg,
                .mod64_reg,
                .neg64,
                => if (version.moveMemoryInstructionClasses()) {
                    // SIMD-0173 turns these into load and store instructions.
                    store = true;
                },

                .div64_imm,
                .mod64_imm,
                => if (version.enablePqr()) {
                    store = true;
                } else if (inst.imm == 0) {
                    return error.DivisionByZero;
                },

                .mul32_imm => if (version.enablePqr()) return error.UnknownOpCode,
                .mod32_imm,
                .div32_imm,
                => if (version.enablePqr()) {
                    return error.UnknownOpCode;
                } else {
                    if (inst.imm == 0) return error.DivisionByZero;
                },

                // SIMD-0377: in v3 these bytes are JMP32 register-form jumps
                // (e.g. .uhmul64_reg == .jge32_reg). For older versions they
                // are PQR arithmetic, available only when `enablePqr()`.
                .udiv32_reg, // jset32_reg in v3
                .udiv64_reg, // jne32_reg  in v3
                .sdiv32_reg, // jslt32_reg in v3
                .sdiv64_reg, // jsle32_reg in v3
                .uhmul64_imm, // jge32_imm  in v3
                .uhmul64_reg, // jge32_reg  in v3
                .shmul64_imm, // jle32_imm  in v3
                .shmul64_reg, // jle32_reg  in v3
                .urem32_reg, // jsgt32_reg in v3
                .urem64_reg, // jsge32_reg in v3
                => if (version.enableJmp32()) {
                    try validateJumpTarget(pc, inst.off, instructions);
                } else if (!version.enablePqr()) return error.UnknownOpCode,

                // PQR ops that have no JMP32 alias — always pure arithmetic.
                .lmul32_imm,
                .lmul32_reg,
                .lmul64_imm,
                .lmul64_reg,
                .srem32_reg,
                .srem64_reg,
                => if (!version.enablePqr()) return error.UnknownOpCode,

                // SIMD-0377: in v3 these bytes are JMP32 immediate-form jumps.
                .udiv32_imm, // jset32_imm in v3
                .udiv64_imm, // jne32_imm  in v3
                .sdiv32_imm, // jslt32_imm in v3
                .sdiv64_imm, // jsle32_imm in v3
                .urem32_imm, // jsgt32_imm in v3
                .urem64_imm, // jsge32_imm in v3
                => if (version.enableJmp32()) {
                    try validateJumpTarget(pc, inst.off, instructions);
                } else if (version.enablePqr()) {
                    if (inst.imm == 0) return error.DivisionByZero;
                } else return error.UnknownOpCode,

                // PQR _imm ops with no JMP32 alias.
                .srem32_imm,
                .srem64_imm,
                => if (version.enablePqr()) {
                    if (inst.imm == 0) return error.DivisionByZero;
                } else return error.UnknownOpCode,

                // SIMD-0377: the six JMP32 opcodes whose byte values do not
                // collide with any pre-existing instruction get their own enum
                // tags and are validated here.
                .jeq32_imm,
                .jeq32_reg,
                .jgt32_imm,
                .jgt32_reg,
                .jlt32_imm,
                .jlt32_reg,
                => if (version.enableJmp32()) {
                    try validateJumpTarget(pc, inst.off, instructions);
                } else return error.UnknownOpCode,

                .hor64_imm => if (!version.disableLddw()) return error.UnknownOpCode,

                .le, .be => {
                    if (inst.opcode == .le and version.disableLe()) {
                        return error.UnknownOpCode;
                    }
                    switch (inst.imm) {
                        16, 32, 64 => {},
                        else => return error.UnsupportedLEBEArgument,
                    }
                },

                .ja,
                .jeq_imm,
                .jeq_reg,
                .jne_imm,
                .jne_reg,
                .jge_imm,
                .jge_reg,
                .jgt_imm,
                .jgt_reg,
                .jle_imm,
                .jle_reg,
                .jlt_imm,
                .jlt_reg,
                .jset_imm,
                .jset_reg,
                .jsge_imm,
                .jsge_reg,
                .jsgt_imm,
                .jsgt_reg,
                .jsle_imm,
                .jsle_reg,
                .jslt_imm,
                .jslt_reg,
                => try validateJumpTarget(pc, inst.off, instructions),

                .ld_b_reg,
                .ld_h_reg,
                .ld_w_reg,
                .ld_dw_reg,
                => if (version.moveMemoryInstructionClasses()) return error.UnknownOpCode,

                .st_b_imm,
                .st_h_imm,
                .st_w_imm,
                .st_dw_imm,
                .st_b_reg,
                .st_h_reg,
                .st_w_reg,
                .st_dw_reg,
                => if (!version.moveMemoryInstructionClasses()) {
                    store = true;
                } else return error.UnknownOpCode,

                .ld_4b_reg,
                => if (!version.moveMemoryInstructionClasses()) return error.UnknownOpCode,
                .st_4b_reg,
                => if (version.moveMemoryInstructionClasses()) {
                    store = true;
                } else return error.UnknownOpCode,

                .ld_dw_imm => if (!version.disableLddw()) {
                    // If this is the last instructions, half of it is missing!
                    if (pc == instructions.len - 1) return error.LddwCannotBeLast;
                    pc += 1;
                    const next_instruction = instructions[pc];
                    if (@intFromEnum(next_instruction.opcode) != 0) return error.IncompleteLddw;
                } else return error.UnknownOpCode,

                // [agave] https://github.com/anza-xyz/sbpf/blob/v0.14.4/src/verifier.rs#L401
                // Agave's verifier accepts any CALL_IMM and defers all checks
                // (src in {0,1}, syscall existence, internal target validity)
                // to the interpreter, which raises `UnsupportedInstruction`
                // / `CallOutsideTextSegment` at runtime. We match that to keep
                // verifier rejection semantics consistent across clients.
                .call_imm => {},
                .call_reg => {
                    // SIMD-0377: in v3 the target register lives in `dst`; in v2
                    // it lives in `src`; older versions use `imm`.
                    const reg = if (version.callxUsesSrcReg())
                        inst.src
                    else if (version.callxUsesDstReg())
                        inst.dst
                    else
                        std.meta.intToEnum(Register, inst.imm) catch
                            return error.InvalidRegister;
                    if (@intFromEnum(reg) >= 10) return error.InvalidRegister;
                },

                // SIMD-0178: in v3 opcode 0x95 only means `exit`; syscalls are
                // dispatched through `call_imm` with src=0 (validated above).
                // The companion SIMD-0178 `RETURN` opcode (0x9d) is not
                // implemented by any released `anza-xyz/sbpf` version, so we
                // let the catch-all reject it as `UnknownOpCode` like Agave.
                // [agave] https://github.com/anza-xyz/sbpf/blob/v0.14.4/src/verifier.rs#L403
                .exit_or_syscall => {},

                else => return error.UnknownOpCode,
            }

            try inst.checkRegisters(store, version);
        }

        // The program counter should now be equal to the number of instructions.
        if (pc != instructions.len) return error.JumpOutOfCode;
    }

    pub fn deinit(self: *const Executable, allocator: std.mem.Allocator) void {
        // Only deinit if we own the bytes/instructions, which is only the case
        // for when we create the executable from assembly for testing.
        if (self.from_asm) allocator.free(@as([]const Instruction, @alignCast(self.instructions)));
        self.ro_section.deinit(allocator);
        self.function_registry.deinit(allocator);
    }

    pub fn getProgramRegion(self: *const Executable) memory.Region {
        const offset, const ro_data = switch (self.ro_section) {
            .owned => |o| .{ o.offset, o.data },
            .borrowed => |b| .{ b.offset, self.bytes[b.start..b.end] },
        };
        return memory.Region.init(.constant, ro_data, offset);
    }

    fn validateJumpTarget(
        cur_pc: u64,
        off: i16,
        insts: []align(1) const Instruction,
    ) VerifierError!void {
        const destination = @as(i64, @bitCast(cur_pc)) + 1 + off;
        if (destination < 0 or destination >= insts.len) return error.JumpOutOfCode;
        const dest_inst = insts[@bitCast(destination)];
        if (@intFromEnum(dest_inst.opcode) == 0) return error.JumpToMiddleOfLddw;
    }
};

pub const Section = union(enum) {
    owned: Owned,
    borrowed: Borrowed,

    const Owned = struct {
        offset: u64,
        data: []align(16) const u8,
    };

    const Borrowed = struct {
        offset: u64,
        start: u64,
        end: u64,
    };

    pub fn deinit(section: Section, allocator: std.mem.Allocator) void {
        switch (section) {
            .owned => |owned| allocator.free(owned.data),
            .borrowed => {},
        }
    }
};

pub const Assembler = struct {
    source: []const u8,

    const Statement = union(enum) {
        label: []const u8,
        instruction: Statement.Instruction,

        const Instruction = struct {
            name: []const u8,
            operands: []const Operand,
        };
    };

    const Operand = union(enum) {
        register: Register,
        integer: i64,
        memory: Memory,
        label: []const u8,

        const Memory = struct {
            base: Register,
            offset: i16,
        };
    };

    fn parse(
        allocator: std.mem.Allocator,
        source: []const u8,
        config: Config,
    ) !struct { Registry, []const Instruction } {
        const version = config.maximum_version;
        var assembler: Assembler = .{ .source = source };
        const statements = try assembler.tokenize(allocator);
        defer {
            for (statements) |statement| {
                switch (statement) {
                    .instruction => |inst| allocator.free(inst.operands),
                    else => {},
                }
            }
            allocator.free(statements);
        }

        var labels: std.StringHashMapUnmanaged(u32) = .{};
        defer labels.deinit(allocator);

        var function_registry: Registry = .{};
        errdefer function_registry.deinit(allocator);

        try labels.put(allocator, "entrypoint", 0);
        var inst_ptr: u32 = 0;
        for (statements) |statement| {
            switch (statement) {
                .label => |name| {
                    if (std.mem.startsWith(u8, name, "function_") or
                        std.mem.eql(u8, name, "entrypoint"))
                    {
                        try function_registry.register(
                            allocator,
                            inst_ptr,
                            name,
                            inst_ptr,
                        );
                    }
                    try labels.put(allocator, name, inst_ptr);
                },
                .instruction => |inst| {
                    inst_ptr += if (std.mem.eql(u8, inst.name, "lddw")) 2 else 1;
                },
            }
        }

        var instructions: std.ArrayListUnmanaged(Instruction) = .{};
        defer instructions.deinit(allocator);
        inst_ptr = 0;

        for (statements) |statement| {
            switch (statement) {
                .label => {},
                .instruction => |inst| {
                    const name = inst.name;
                    const operands = inst.operands;

                    const bind = Instruction.map.get(name) orelse
                        std.debug.panic("invalid instruction: {s}", .{name});

                    const instruction: Instruction = switch (bind.inst) {
                        .alu_binary => inst: {
                            if (operands[0] == .register and operands[1] == .register) break :inst .{
                                .opcode = @enumFromInt(bind.opc | Instruction.x),
                                .dst = operands[0].register,
                                .src = operands[1].register,
                                .off = 0,
                                .imm = 0,
                            };

                            if (operands[0].register == .r10 and
                                bind.opc == Instruction.alu64 | Instruction.add and
                                !version.manualStackFrameBump()) break :inst .{
                                .opcode = .or64_imm,
                                .dst = .r0,
                                .src = .r0,
                                .off = 0,
                                .imm = 0,
                            };

                            break :inst .{
                                .opcode = @enumFromInt(bind.opc | Instruction.k),
                                .dst = operands[0].register,
                                .src = .r0,
                                .off = 0,
                                .imm = @truncate(@as(u64, @bitCast(operands[1].integer))),
                            };
                        },
                        .alu_unary => .{
                            .opcode = @enumFromInt(bind.opc),
                            .dst = operands[0].register,
                            .src = .r0,
                            .off = 0,
                            .imm = 0,
                        },
                        .no_operand => .{
                            .opcode = @enumFromInt(bind.opc),
                            .dst = .r0,
                            .src = .r0,
                            .off = 0,
                            .imm = 0,
                        },
                        .jump_conditional => inst: {
                            const is_immediate = operands[1] == .integer;
                            const is_label = operands[2] == .label;

                            if (is_label) {
                                break :inst if (is_immediate) .{
                                    .opcode = @enumFromInt(bind.opc | Instruction.k),
                                    .dst = operands[0].register,
                                    .src = .r0,
                                    .off = @intCast(resolveLabel(
                                        inst_ptr,
                                        &labels,
                                        operands[2].label,
                                    )),
                                    .imm = @bitCast(@as(i32, @intCast(operands[1].integer))),
                                } else .{
                                    .opcode = @enumFromInt(bind.opc | Instruction.x),
                                    .dst = operands[0].register,
                                    .src = operands[1].register,
                                    .off = @intCast(resolveLabel(
                                        inst_ptr,
                                        &labels,
                                        operands[2].label,
                                    )),
                                    .imm = 0,
                                };
                            } else {
                                break :inst if (is_immediate) .{
                                    .opcode = @enumFromInt(bind.opc | Instruction.k),
                                    .dst = operands[0].register,
                                    .src = .r0,
                                    .off = @intCast(operands[2].integer),
                                    .imm = @bitCast(@as(i32, @intCast(operands[1].integer))),
                                } else .{
                                    .opcode = @enumFromInt(bind.opc | Instruction.x),
                                    .dst = operands[0].register,
                                    .src = operands[1].register,
                                    .off = @intCast(operands[2].integer),
                                    .imm = 0,
                                };
                            }
                        },
                        .jump_unconditional => .{
                            .opcode = @enumFromInt(bind.opc),
                            .dst = .r0,
                            .src = .r0,
                            .off = switch (operands[0]) {
                                .label => |label| @intCast(resolveLabel(inst_ptr, &labels, label)),
                                .integer => |int| @intCast(int),
                                else => unreachable,
                            },
                            .imm = 0,
                        },
                        .load_dw_imm => .{
                            .opcode = .ld_dw_imm,
                            .dst = operands[0].register,
                            .src = .r0,
                            .off = 0,
                            .imm = @truncate(@as(u64, @bitCast(operands[1].integer))),
                        },
                        .load_reg => .{
                            .opcode = if (version.moveMemoryInstructionClasses())
                                @enumFromInt(bind.alt)
                            else
                                @enumFromInt(bind.opc),
                            .dst = operands[0].register,
                            .src = operands[1].memory.base,
                            .off = operands[1].memory.offset,
                            .imm = 0,
                        },
                        .store_reg => .{
                            .opcode = if (version.moveMemoryInstructionClasses())
                                @enumFromInt(bind.alt)
                            else
                                @enumFromInt(bind.opc),
                            .dst = operands[0].memory.base,
                            .src = operands[1].register,
                            .off = operands[0].memory.offset,
                            .imm = 0,
                        },
                        .store_imm => .{
                            .opcode = if (version.moveMemoryInstructionClasses())
                                @enumFromInt(bind.alt)
                            else
                                @enumFromInt(bind.opc),
                            .dst = operands[0].memory.base,
                            .src = .r0,
                            .off = operands[0].memory.offset,
                            .imm = @bitCast(@as(i32, @intCast(operands[1].integer))),
                        },
                        .endian => |bits| .{
                            .opcode = @enumFromInt(bind.opc),
                            .dst = operands[0].register,
                            .src = .r0,
                            .off = 0,
                            .imm = bits,
                        },
                        .call_imm => inst: {
                            const is_label = operands[0] == .label;
                            if (is_label) {
                                var target_pc: i64 = labels.get(operands[0].label) orelse
                                    std.debug.panic("label not found: {s}", .{name});
                                if (version.enableStaticSyscalls()) {
                                    target_pc = target_pc - inst_ptr - 1;
                                }
                                break :inst .{
                                    .opcode = @enumFromInt(bind.opc),
                                    .dst = .r0,
                                    .src = .r1,
                                    .off = 0,
                                    .imm = @bitCast(@as(i32, @intCast(target_pc))),
                                };
                            } else {
                                const offset = operands[0].integer;
                                const instr_imm = if (version.enableStaticSyscalls())
                                    offset
                                else
                                    offset + inst_ptr + 1;
                                const target_pc: u32 = @intCast(offset + inst_ptr + 1);
                                const label = try std.fmt.allocPrint(
                                    allocator,
                                    "function_{}",
                                    .{target_pc},
                                );
                                defer allocator.free(label);
                                try function_registry.register(
                                    allocator,
                                    target_pc,
                                    label,
                                    target_pc,
                                );
                                break :inst .{
                                    .opcode = @enumFromInt(bind.opc),
                                    .dst = .r0,
                                    .src = .r1,
                                    .off = 0,
                                    .imm = @intCast(instr_imm),
                                };
                            }
                        },
                        // SIMD-0377: in v3 the target register lives in `dst`; in
                        // v2 it lives in `src`; older versions encode it in `imm`.
                        .call_reg => if (version.callxUsesDstReg()) .{
                            .opcode = @enumFromInt(bind.opc),
                            .dst = operands[0].register,
                            .src = .r0,
                            .off = 0,
                            .imm = 0,
                        } else if (version.callxUsesSrcReg()) .{
                            .opcode = @enumFromInt(bind.opc),
                            .dst = .r0,
                            .src = operands[0].register,
                            .off = 0,
                            .imm = 0,
                        } else .{
                            .opcode = @enumFromInt(bind.opc),
                            .dst = .r0,
                            .src = .r0,
                            .off = 0,
                            .imm = @intFromEnum(operands[0].register),
                        },
                        else => std.debug.panic("TODO: {s}", .{@tagName(bind.inst)}),
                    };

                    try instructions.append(allocator, instruction);
                    inst_ptr += 1;

                    if (bind.inst == .load_dw_imm) {
                        switch (operands[1]) {
                            .integer => |int| {
                                try instructions.append(allocator, .{
                                    .opcode = @enumFromInt(0),
                                    .dst = .r0,
                                    .src = .r0,
                                    .off = 0,
                                    .imm = @truncate(@as(u64, @bitCast(int)) >> 32),
                                });
                                inst_ptr += 1;
                            },
                            else => {},
                        }
                    }
                },
            }
        }

        return .{
            function_registry,
            try instructions.toOwnedSlice(allocator),
        };
    }

    fn resolveLabel(
        inst_ptr: u32,
        labels: *const std.StringHashMapUnmanaged(u32),
        name: []const u8,
    ) i32 {
        const target_pc: i64 = labels.get(name) orelse
            std.debug.panic("label not found: {s}", .{name});
        return @intCast(target_pc - inst_ptr - 1);
    }

    fn tokenize(self: *Assembler, allocator: std.mem.Allocator) ![]const Statement {
        var statements: std.ArrayListUnmanaged(Statement) = .{};
        defer statements.deinit(allocator);

        var lines = std.mem.splitScalar(u8, self.source, '\n');
        while (lines.next()) |line| {
            const comment = std.mem.indexOfScalar(u8, line, ';') orelse line.len;
            var trimmed_line = std.mem.trim(u8, line[0..comment], " ");
            if (trimmed_line.len == 0) continue; // empty line, skip

            // is it a label? "ident:"
            if (std.mem.indexOfScalar(u8, trimmed_line, ':')) |index| {
                const ident = trimmed_line[0..index];
                try statements.append(allocator, .{ .label = ident });
                continue;
            }

            var operands: std.ArrayListUnmanaged(Operand) = .{};
            defer operands.deinit(allocator);

            // what's the first mnemonic of the instruction?
            var iter = std.mem.tokenizeAny(u8, trimmed_line, &.{ ' ', ',' });
            const name = iter.next() orelse @panic("no mnem");

            while (iter.next()) |op| {
                if (std.meta.stringToEnum(Register, op)) |reg| {
                    try operands.append(allocator, .{ .register = reg });
                } else if (std.mem.startsWith(u8, op, "[")) {
                    const left_bracket = std.mem.indexOfScalar(u8, op, '[').?;
                    const right_bracket = std.mem.indexOfScalar(u8, op, ']') orelse
                        @panic("no right bracket");
                    if (left_bracket == op.len) @panic("no right bracket");

                    var base = op[left_bracket + 1 .. right_bracket];
                    var offset: i16 = 0;

                    // does it have a + or -
                    // this can appear in [r1+10] for example
                    if (std.mem.indexOfAny(u8, base, "+-")) |symbol_offset| {
                        const symbol = base[symbol_offset..];
                        base = base[0..symbol_offset];
                        offset = try std.fmt.parseInt(i16, symbol, 0);
                    }

                    // otherwise it's just an address register argument
                    const reg = std.meta.stringToEnum(Register, base) orelse
                        @panic("unknown register");

                    try operands.append(allocator, .{ .memory = .{
                        .base = reg,
                        .offset = offset,
                    } });
                } else if (std.fmt.parseInt(i64, op, 0) catch null) |int| {
                    try operands.append(allocator, .{ .integer = int });
                } else if (std.fmt.parseInt(u64, op, 0) catch null) |int| {
                    try operands.append(allocator, .{ .integer = @bitCast(int) });
                } else {
                    try operands.append(allocator, .{ .label = op });
                }
            }

            try statements.append(allocator, .{ .instruction = .{
                .name = name,
                .operands = try operands.toOwnedSlice(allocator),
            } });
        }

        return statements.toOwnedSlice(allocator);
    }
};

pub const Registry = struct {
    map: std.AutoArrayHashMapUnmanaged(u64, Entry) = .{},

    const Entry = struct {
        name: []const u8,
        value: u64,
    };

    /// Duplicates `name` to free later later.
    pub fn register(
        self: *Registry,
        allocator: std.mem.Allocator,
        key: u64,
        name: []const u8,
        value: u64,
    ) !void {
        const gop = try self.map.getOrPut(allocator, key);
        if (gop.found_existing) {
            if (gop.value_ptr.value != value) {
                return error.SymbolHashCollision;
            }
        } else {
            gop.value_ptr.* = .{
                .name = try allocator.dupe(u8, name),
                .value = value,
            };
        }
    }

    pub fn registerHashed(
        self: *Registry,
        allocator: std.mem.Allocator,
        name: []const u8,
        value: u64,
    ) !u64 {
        const key = sbpf.hashSymbolName(name);
        try self.register(allocator, key, name, value);
        return key;
    }

    pub fn registerHashedLegacy(
        self: *Registry,
        allocator: std.mem.Allocator,
        loader: *const SyscallMap,
        hash_symbol_name: bool,
        name: []const u8,
        value: u64,
    ) !u64 {
        const hash = if (std.mem.eql(u8, name, "entrypoint"))
            sbpf.hashSymbolName(name)
        else
            sbpf.hashSymbolName(&std.mem.toBytes(value));
        const key: u64 = if (hash_symbol_name) blk: {
            if (loader.get(hash) != null) return error.SymbolHashCollision;
            break :blk hash;
        } else value;

        try self.register(allocator, key, &.{}, value);
        return key;
    }

    pub fn lookupKey(self: *const Registry, key: u64) ?Entry {
        return self.map.get(key);
    }

    // TODO: this can be sped up by using a bidirectional map
    pub fn lookupName(self: *const Registry, name: []const u8) ?Entry {
        var iter = self.map.iterator();
        while (iter.next()) |entry| {
            const entry_name = entry.value_ptr.name;
            if (std.mem.eql(u8, entry_name, name)) return entry.value_ptr.*;
        }
        return null;
    }

    pub fn deinit(self: *const Registry, allocator: std.mem.Allocator) void {
        var iter = self.map.iterator();
        while (iter.next()) |entry| {
            allocator.free(entry.value_ptr.name);
        }
        var copy = self.map;
        copy.deinit(allocator);
    }

    test "symbol collision" {
        const allocator = std.testing.allocator;
        var registry: Registry = .{};
        defer registry.deinit(allocator);

        _ = try registry.registerHashed(
            allocator,
            "foo",
            0,
        );

        try std.testing.expectError(
            error.SymbolHashCollision,
            registry.registerHashed(
                allocator,
                "gmyionqhgxitzddvxfwubqhpomupciyvbeczintxxtfdsfhiyxcnzyowtgnrnvvd",
                4,
            ),
        );
    }
};

/// [agave] https://github.com/anza-xyz/sbpf/blob/bce8eed8df53595afb8770531cf4ca938e449cf7/src/vm.rs#L52
/// VM configuration settings
pub const Config = struct {
    /// Maximum call depth
    max_call_depth: usize = 64,
    /// Size of a stack frame in bytes, must match the size specified in the LLVM BPF backend
    stack_frame_size: usize = 4096,
    /// Enable instruction meter and limiting
    enable_instruction_meter: bool = true,
    /// Reject ELF files containing issues that the verifier did not catch before (up to v0.2.21)
    reject_broken_elfs: bool = false,
    /// Avoid copying read only sections when possible
    optimize_rodata: bool = true,
    /// Allow a memory region at slot zero in the aligned memory mapping.
    /// Gated by `enable_sbpf_v3_deployment_and_execution` (SIMD-0189) at
    /// runtime: when true, callers may supply a region whose `vm_addr_start`
    /// is in slot 0 (e.g. the v3 rodata region at vaddr 0), and slot-0
    /// accesses can resolve to that region. When false, slot 0 is
    /// unconditionally an access-violation and callers must not pass a
    /// slot-0 region.
    /// [agave] https://github.com/anza-xyz/sbpf/blob/bce8eed8df53595afb8770531cf4ca938e449cf7/src/vm.rs#L142
    allow_memory_region_zero: bool = true,
    /// Use aligned memory mapping
    aligned_memory_mapping: bool = true,
    /// Enables gaps in VM address space between the stack frames
    enable_stack_frame_gaps: bool = true,
    /// SIMD-0460: when set, multi-byte loads/stores must be wholly within a
    /// single memory region (no cross-region byte-split fallback), and the
    /// memory map invokes the access-violation handler on translation failure
    /// (see MemoryMap.setAccessViolationHandler) to support direct-mapping
    /// auto-extension of writable+owned account regions.
    virtual_address_space_adjustments: bool = false,

    // The range of allowed SBPF versions
    minimum_version: sbpf.Version = .v0,
    maximum_version: sbpf.Version = .v3,

    pub fn stackSize(config: Config) u64 {
        return config.stack_frame_size * config.max_call_depth;
    }
};
