const std = @import("std");
const sig = @import("../sig.zig");
const tracy = @import("tracy");

const sbpf = sig.vm.sbpf;
const memory = sig.vm.memory;

const Elf = sig.vm.elf.Elf;
const Instruction = sbpf.Instruction;
const Register = Instruction.Register;
const SyscallMap = sig.vm.SyscallMap;

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

    /// Takes ownership of the `Elf`.
    pub fn fromElf(elf: Elf) Executable {
        const text_section_addr = elf.getShdrByName(".text").?.sh_addr;
        const text_vaddr = if (elf.version.enableElfVaddr() and
            text_section_addr >= memory.RODATA_START)
            text_section_addr
        else
            text_section_addr +| memory.RODATA_START;

        return .{
            .bytes = elf.bytes,
            .ro_section = elf.ro_section,
            .instructions = elf.getInstructions(),
            .version = elf.version,
            .entry_pc = elf.entry_pc,
            .from_asm = false,
            .text_vaddr = text_vaddr,
            .function_registry = elf.function_registry,
            .config = elf.config,
        };
    }

    pub fn fromBytes(
        allocator: std.mem.Allocator,
        source: []u8,
        loader: *const SyscallMap,
        config: Config,
    ) !Executable {
        const zone = tracy.Zone.init(@src(), .{ .name = "Executable.fromBytes" });
        defer zone.deinit();

        const elf = try Elf.parse(allocator, source, loader, config);
        return fromElf(elf);
    }

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
            .version = version,
            .config = config,
            .function_registry = registry.*,
            .entry_pc = entry_pc,
            .ro_section = .{ .borrowed = .{
                .offset = memory.RODATA_START,
                .start = 0,
                .end = source.len,
            } },
            .from_asm = from_asm,
            .text_vaddr = if (version.enableLowerBytecodeVaddr())
                memory.BYTECODE_START
            else
                memory.RODATA_START,
        };
    }

    pub fn verify(
        self: *const Executable,
        loader: *const SyscallMap,
    ) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "Executable.Verify" });
        defer zone.deinit();

        const version = self.version;
        const instructions = self.instructions;
        if (instructions.len == 0) return error.NoProgram;

        const map = self.function_registry.map;
        var iter = map.iterator();
        var function_start: u64 = 0;
        var function_end: u64 = instructions.len;

        var pc: u64 = 0;
        while (pc + 1 <= instructions.len) : (pc += 1) {
            const inst = instructions[pc];
            var store: bool = false;

            if (version.enableStaticSyscalls() and map.contains(pc)) {
                function_start = if (iter.next()) |entry| entry.key_ptr.* else 0;
                const before_index = iter.index;
                function_end = if (iter.next()) |entry| entry.key_ptr.* else instructions.len;
                iter.index = before_index;
                switch (instructions[function_end -| 1].opcode) {
                    .ja, .@"return" => {},
                    else => return error.InvalidFunction,
                }
            }

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

                .add64_imm => if (version.enableDynamicStackFrames() and inst.dst == .r10) {
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
                => if (version.disableNegation()) return error.UnsupportedInstruction,

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
                } else {
                    if (inst.imm == 0) return error.DivisionByZero;
                },

                .mul32_imm => if (version.enablePqr()) return error.UnsupportedInstruction,
                .mod32_imm,
                .div32_imm,
                => if (version.enablePqr()) {
                    return error.UnsupportedInstruction;
                } else {
                    if (inst.imm == 0) return error.DivisionByZero;
                },

                .udiv32_reg,
                .udiv64_reg,
                .sdiv32_reg,
                .sdiv64_reg,
                .lmul32_imm,
                .lmul32_reg,
                .lmul64_imm,
                .lmul64_reg,
                .uhmul64_imm,
                .uhmul64_reg,
                .shmul64_imm,
                .shmul64_reg,
                .urem32_reg,
                .urem64_reg,
                .srem32_reg,
                .srem64_reg,
                => if (!version.enablePqr()) return error.UnsupportedInstruction,

                .udiv32_imm,
                .udiv64_imm,
                .sdiv32_imm,
                .sdiv64_imm,
                .urem32_imm,
                .urem64_imm,
                .srem32_imm,
                .srem64_imm,
                => if (version.enablePqr()) {
                    if (inst.imm == 0) return error.DivisionByZero;
                } else return error.UnsupportedInstruction,

                .hor64_imm => if (!version.disableLddw()) return error.UnsupportedInstruction,

                .le, .be => {
                    if (inst.opcode == .le and version.disableLe()) {
                        return error.UnsupportedInstruction;
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
                => {
                    const destination = @as(i64, @bitCast(pc)) + 1 + inst.off;
                    if (destination < 0 or
                        destination < function_start or
                        destination >= function_end)
                    {
                        return error.JumpOutOfCode;
                    }

                    const dest_inst = instructions[@bitCast(destination)];
                    if (@intFromEnum(dest_inst.opcode) == 0) {
                        return error.JumpToMiddleOfLddw;
                    }
                },

                .ld_b_reg,
                .ld_h_reg,
                .ld_w_reg,
                .ld_dw_reg,
                => if (version.moveMemoryInstructionClasses()) return error.UnsupportedInstruction,

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
                } else return error.UnsupportedInstruction,

                .ld_4b_reg,
                => if (!version.moveMemoryInstructionClasses()) return error.UnsupportedInstruction,
                .st_4b_reg,
                => if (version.moveMemoryInstructionClasses()) {
                    store = true;
                } else return error.UnsupportedInstruction,

                .ld_dw_imm => if (!version.disableLddw()) {
                    // If this is the last instructions, half of it is missing!
                    if (pc == instructions.len - 1) return error.LddwCannotBeLast;
                    pc += 1;
                    const next_instruction = instructions[pc];
                    if (@intFromEnum(next_instruction.opcode) != 0) return error.IncompleteLddw;
                } else return error.UnsupportedInstruction,

                .call_imm => if (version.enableStaticSyscalls()) {
                    const target_pc = version.computeTargetPc(pc, inst);
                    if (!self.function_registry.map.contains(target_pc)) {
                        return error.InvalidFunction;
                    }
                },
                .call_reg => {
                    const reg = if (version.callRegUsesSrcReg())
                        inst.src
                    else
                        std.meta.intToEnum(Register, inst.imm) catch
                            return error.InvalidRegister;
                    if (@intFromEnum(reg) >= 10) return error.InvalidRegister;
                },

                .@"return" => if (!version.enableStaticSyscalls())
                    return error.UnsupportedInstruction,
                .exit_or_syscall => if (version.enableStaticSyscalls() and
                    loader.get(inst.imm) == null)
                {
                    return error.InvalidSyscall;
                },

                else => return error.UnsupportedInstruction,
            }

            try inst.checkRegisters(store, version);
        }
    }

    /// When the executable comes from the assembler, we need to guarantee that the
    /// instructions are aligned to `sbpf.Instruction` rather than 1 like they would be
    /// if we created the executable from the Elf file. The GPA requires allocations and
    /// deallocations to be made with the same semantic alignment.
    pub fn deinit(self: *const Executable, allocator: std.mem.Allocator) void {
        if (self.from_asm) allocator.free(@as(
            []const Instruction,
            @alignCast(self.instructions),
        ));

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
};

pub const Section = union(enum) {
    owned: Owned,
    borrowed: Borrowed,

    const Owned = struct {
        offset: u64,
        data: []const u8,
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
                            const is_immediate = operands[1] == .integer;
                            break :inst if (is_immediate) .{
                                .opcode = @enumFromInt(bind.opc | Instruction.k),
                                .dst = operands[0].register,
                                .src = .r0,
                                .off = 0,
                                .imm = @truncate(@as(u64, @bitCast(operands[1].integer))),
                            } else .{
                                .opcode = @enumFromInt(bind.opc | Instruction.x),
                                .dst = operands[0].register,
                                .src = operands[1].register,
                                .off = 0,
                                .imm = 0,
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
                            // Harded to work for both `exit` and `return`, even though
                            // the `exit` instruction was technically deprecated.
                            .opcode = if (version == .v0)
                                .exit_or_syscall
                            else
                                .@"return",
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
                                        version,
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
                                        version,
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
                                .label => |label| @intCast(resolveLabel(
                                    inst_ptr,
                                    &labels,
                                    label,
                                    version,
                                )),
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
                                const label = operands[0].label;
                                break :inst .{
                                    .opcode = @enumFromInt(bind.opc),
                                    .dst = .r0,
                                    .src = .r1,
                                    .off = 0,
                                    .imm = @bitCast(resolveLabel(
                                        inst_ptr,
                                        &labels,
                                        label,
                                        version,
                                    )),
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
                        .call_reg => if (version.callRegUsesSrcReg()) .{
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
        version: sbpf.Version,
    ) i32 {
        var target_pc: i64 = labels.get(name) orelse
            std.debug.panic("label not found: {s}", .{name});
        if (version.enableStaticSyscalls()) {
            target_pc = target_pc - inst_ptr - 1;
        }
        return @intCast(target_pc);
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
    /// Enable dynamic string allocation for labels
    enable_symbol_and_section_labels: bool = false,
    /// Reject ELF files containing issues that the verifier did not catch before (up to v0.2.21)
    reject_broken_elfs: bool = false,
    /// Avoid copying read only sections when possible
    optimize_rodata: bool = true,
    /// Use aligned memory mapping
    aligned_memory_mapping: bool = true,
    /// Enables gaps in VM address space between the stack frames
    enable_stack_frame_gaps: bool = true,

    // The range of allowed SBPF versions
    minimum_version: sbpf.Version = .v0,
    maximum_version: sbpf.Version = .v3,

    pub fn stackSize(config: Config) u64 {
        return config.stack_frame_size * config.max_call_depth;
    }
};
