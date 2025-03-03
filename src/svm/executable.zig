const std = @import("std");
const sbpf = @import("sbpf.zig");
const Elf = @import("elf.zig").Elf;
const memory = @import("memory.zig");
const syscalls = @import("syscalls.zig");
const Vm = @import("vm.zig").Vm;

pub const Executable = struct {
    bytes: []const u8,
    instructions: []align(1) const sbpf.Instruction,
    version: sbpf.Version,
    entry_pc: u64,
    from_elf: bool,
    ro_section: Section,
    text_vaddr: u64,
    function_registry: Registry(u64),
    config: Config,

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
            .from_elf = true,
            .text_vaddr = text_vaddr,
            .function_registry = elf.function_registry,
            .config = elf.config,
        };
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
        var loader: BuiltinProgram = .{};
        return fromTextBytes(
            allocator,
            std.mem.sliceAsBytes(instructions),
            &loader,
            &function_registry,
            config,
        );
    }

    pub fn fromTextBytes(
        allocator: std.mem.Allocator,
        source: []const u8,
        loader: *BuiltinProgram,
        registry: *Registry(u64),
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

        return .{
            .instructions = std.mem.bytesAsSlice(sbpf.Instruction, source),
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
            .from_elf = false,
            .text_vaddr = if (version.enableLowerBytecodeVaddr())
                memory.BYTECODE_START
            else
                memory.RODATA_START,
        };
    }

    /// When the executable comes from the assembler, we need to guarantee that the
    /// instructions are aligned to `sbpf.Instruction` rather than 1 like they would be
    /// if we created the executable from the Elf file. The GPA requires allocations and
    /// deallocations to be made with the same semantic alignment.
    pub fn deinit(self: *Executable, allocator: std.mem.Allocator) void {
        if (!self.from_elf) allocator.free(@as(
            []const sbpf.Instruction,
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

pub const Assembler = struct {
    source: []const u8,

    const Statement = union(enum) {
        label: []const u8,
        instruction: Instruction,

        const Instruction = struct {
            name: []const u8,
            operands: []const Operand,
        };
    };

    const Operand = union(enum) {
        register: sbpf.Instruction.Register,
        integer: i64,
        memory: Memory,
        label: []const u8,

        const Memory = struct {
            base: sbpf.Instruction.Register,
            offset: i16,
        };
    };

    fn parse(
        allocator: std.mem.Allocator,
        source: []const u8,
        config: Config,
    ) !struct { Registry(u64), []const sbpf.Instruction } {
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

        var function_registry: Registry(u64) = .{};
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

        var instructions: std.ArrayListUnmanaged(sbpf.Instruction) = .{};
        defer instructions.deinit(allocator);
        inst_ptr = 0;

        for (statements) |statement| {
            switch (statement) {
                .label => {},
                .instruction => |inst| {
                    const name = inst.name;
                    const operands = inst.operands;

                    if (sbpf.Instruction.disallowed.get(name)) |since| {
                        if (version.gte(since)) return error.UnknownInstruction;
                    }

                    const bind = sbpf.Instruction.map.get(name) orelse
                        std.debug.panic("invalid instruction: {s}", .{name});

                    const instruction: sbpf.Instruction = switch (bind.inst) {
                        .alu_binary => inst: {
                            const is_immediate = operands[1] == .integer;
                            break :inst if (is_immediate) .{
                                .opcode = @enumFromInt(bind.opc | sbpf.Instruction.k),
                                .dst = operands[0].register,
                                .src = .r0,
                                .off = 0,
                                .imm = @truncate(@as(u64, @bitCast(operands[1].integer))),
                            } else .{
                                .opcode = @enumFromInt(bind.opc | sbpf.Instruction.x),
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
                                @panic("TODO: label jump");
                            } else {
                                break :inst if (is_immediate) .{
                                    .opcode = @enumFromInt(bind.opc | sbpf.Instruction.k),
                                    .dst = operands[0].register,
                                    .src = .r0,
                                    .off = @intCast(operands[2].integer),
                                    .imm = @bitCast(@as(i32, @intCast(operands[1].integer))),
                                } else .{
                                    .opcode = @enumFromInt(bind.opc | sbpf.Instruction.x),
                                    .dst = operands[0].register,
                                    .src = operands[1].register,
                                    .off = @intCast(operands[2].integer),
                                    .imm = 0,
                                };
                            }
                        },
                        .jump_unconditional => if (operands[0] == .label)
                            @panic("TODO: jump_unconditional label")
                        else
                            .{
                                .opcode = @enumFromInt(bind.opc),
                                .dst = .r0,
                                .src = .r0,
                                .off = @intCast(operands[0].integer),
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
                                @enumFromInt(bind.secondary)
                            else
                                @enumFromInt(bind.opc),
                            .dst = operands[0].register,
                            .src = operands[1].memory.base,
                            .off = operands[1].memory.offset,
                            .imm = 0,
                        },
                        .store_reg => .{
                            .opcode = if (version.moveMemoryInstructionClasses())
                                @enumFromInt(bind.secondary)
                            else
                                @enumFromInt(bind.opc),
                            .dst = operands[0].memory.base,
                            .src = operands[1].register,
                            .off = operands[0].memory.offset,
                            .imm = 0,
                        },
                        .store_imm => .{
                            .opcode = if (version.moveMemoryInstructionClasses())
                                @enumFromInt(bind.secondary)
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
                                var target_pc: i64 = labels.get(label) orelse
                                    std.debug.panic("label not found: {s}", .{label});
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
                                    .opcode = .ld_dw_imm,
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

    fn tokenize(self: *Assembler, allocator: std.mem.Allocator) ![]const Statement {
        var statements: std.ArrayListUnmanaged(Statement) = .{};
        defer statements.deinit(allocator);

        var lines = std.mem.splitScalar(u8, self.source, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue; // empty line, skip

            const trimmed_line = std.mem.trim(u8, line, " ");

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
                if (std.mem.startsWith(u8, op, "r")) {
                    const reg = std.meta.stringToEnum(sbpf.Instruction.Register, op) orelse
                        @panic("unknown register");
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
                    const reg = std.meta.stringToEnum(sbpf.Instruction.Register, base) orelse
                        @panic("unknown register");

                    try operands.append(allocator, .{ .memory = .{
                        .base = reg,
                        .offset = offset,
                    } });
                } else if (std.mem.startsWith(u8, op, "function_")) {
                    try operands.append(allocator, .{ .label = op });
                } else {
                    if (std.fmt.parseInt(i64, op, 0)) |int| {
                        try operands.append(allocator, .{ .integer = int });
                    } else |err| std.debug.panic("err: {s}", .{@errorName(err)});
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

pub fn Registry(T: type) type {
    return struct {
        map: std.AutoHashMapUnmanaged(u64, Entry) = .{},

        const Entry = struct {
            name: []const u8,
            value: T,
        };
        const Self = @This();

        /// Duplicates `name` to free later later.
        pub fn register(
            self: *Self,
            allocator: std.mem.Allocator,
            key: u64,
            name: []const u8,
            value: T,
        ) !void {
            const gop = try self.map.getOrPut(allocator, key);
            if (gop.found_existing) {
                if (gop.value_ptr.value != value) {
                    return error.SymbolHashCollision;
                }
            } else {
                gop.value_ptr.* = .{ .name = try allocator.dupe(u8, name), .value = value };
            }
        }

        pub fn registerHashed(
            self: *Self,
            allocator: std.mem.Allocator,
            name: []const u8,
            value: T,
        ) !u64 {
            const key = sbpf.hashSymbolName(name);
            try self.register(allocator, key, name, value);
            return key;
        }

        pub fn registerHashedLegacy(
            self: *Self,
            allocator: std.mem.Allocator,
            loader: *BuiltinProgram,
            hash_symbol_name: bool,
            name: []const u8,
            value: T,
        ) !u64 {
            const hash = if (std.mem.eql(u8, name, "entrypoint"))
                sbpf.hashSymbolName(name)
            else
                sbpf.hashSymbolName(&std.mem.toBytes(value));
            const key: u64 = if (hash_symbol_name) blk: {
                if (loader.functions.lookupKey(hash) != null) {
                    return error.SymbolHashCollision;
                }
                break :blk hash;
            } else value;

            try self.register(allocator, key, &.{}, value);
            return key;
        }

        pub fn lookupKey(self: *const Self, key: u64) ?Entry {
            return self.map.get(key);
        }

        // TODO: this can be sped up by using a bidirectional map
        pub fn lookupName(self: *const Self, name: []const u8) ?Entry {
            var iter = self.map.valueIterator();
            while (iter.next()) |entry| {
                if (std.mem.eql(u8, entry.name, name)) return entry.*;
            }
            return null;
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            var iter = self.map.valueIterator();
            while (iter.next()) |entry| {
                allocator.free(entry.name);
            }
            self.map.deinit(allocator);
        }

        test "symbol collision" {
            const allocator = std.testing.allocator;
            var registry: Registry(u64) = .{};
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
}

pub const BuiltinProgram = struct {
    functions: Registry(*const fn (*Vm) syscalls.Error!void) = .{},

    pub fn deinit(self: *BuiltinProgram, allocator: std.mem.Allocator) void {
        self.functions.deinit(allocator);
    }
};

pub const Config = struct {
    optimize_rodata: bool = true,
    reject_broken_elfs: bool = false,
    enable_symbol_and_section_labels: bool = false,
    minimum_version: sbpf.Version = .v0,
    maximum_version: sbpf.Version = .v3,
    stack_frame_size: u64 = 4096,
    max_call_depth: u64 = 64,

    pub fn stackSize(config: Config) u64 {
        return config.stack_frame_size * config.max_call_depth;
    }
};
