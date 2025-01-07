//! Represents the self ELF file

const std = @import("std");
const ebpf = @import("ebpf.zig");
const memory = @import("memory.zig");
const Executable = @import("Executable.zig");
const Elf = @This();

const elf = std.elf;
const assert = std.debug.assert;

bytes: []u8,
header: elf.Elf64_Ehdr,
shdrs: []align(1) const elf.Elf64_Shdr,
phdrs: []align(1) const elf.Elf64_Phdr,
strtab: []const u8,

dynamic_table: [elf.DT_NUM]elf.Elf64_Xword,
dynamic_relocations_table: []align(1) const elf.Elf64_Rel,
dynamic_symbol_table: []align(1) const elf.Elf64_Sym,

entry_pc: u64,
version: ebpf.SBPFVersion,
function_registry: Executable.Registry(u32),

pub fn parse(
    allocator: std.mem.Allocator,
    bytes: []u8,
    loader: *Executable.BuiltinProgram,
) !Elf {
    const header_buffer = bytes[0..@sizeOf(elf.Elf64_Ehdr)];

    var self: Elf = .{
        .bytes = bytes,
        .header = @as(*align(1) const elf.Elf64_Ehdr, @ptrCast(header_buffer)).*,
        .entry_pc = 0,
        .version = .v1,
        .shdrs = &.{},
        .strtab = &.{},
        .phdrs = &.{},
        .dynamic_table = .{0} ** elf.DT_NUM,
        .dynamic_relocations_table = &.{},
        .dynamic_symbol_table = &.{},
        .function_registry = .{},
    };
    errdefer self.function_registry.deinit(allocator);

    try self.parseHeader();
    try self.parseDynamic();

    try self.validate();
    try self.relocate(allocator, loader);

    return self;
}

fn parseHeader(self: *Elf) !void {
    {
        const shoff = self.header.e_shoff;
        const shnum = self.header.e_shnum;
        const shsize = shnum * @sizeOf(elf.Elf64_Shdr);
        self.shdrs = std.mem.bytesAsSlice(elf.Elf64_Shdr, self.bytes[shoff..][0..shsize]);
    }

    {
        const phoff = self.header.e_phoff;
        const phnum = self.header.e_phnum;
        const phsize = phnum * @sizeOf(elf.Elf64_Phdr);
        self.phdrs = std.mem.bytesAsSlice(elf.Elf64_Phdr, self.bytes[phoff..][0..phsize]);
    }

    self.strtab = self.shdrSlice(self.header.e_shstrndx);

    const text_section = self.getShdrByName(".text") orelse return error.NoTextSection;
    const offset = self.header.e_entry -| text_section.sh_addr;
    self.entry_pc = try std.math.divExact(u64, offset, 8);

    const sbpf_version: ebpf.SBPFVersion = if (self.header.e_flags == ebpf.EF_SBPF_V2)
        .v2
    else
        .v1;
    if (sbpf_version != .v1)
        std.debug.panic("found sbpf version: {s}, support it!", .{@tagName(sbpf_version)});
    self.version = sbpf_version;
}

fn parseDynamic(
    self: *Elf,
) !void {
    var dynamic_table: ?[]align(1) const elf.Elf64_Dyn = null;

    if (self.getPhdrIndexByType(elf.PT_DYNAMIC)) |index| {
        dynamic_table = std.mem.bytesAsSlice(elf.Elf64_Dyn, self.phdrSlice(index));
    }

    // if PT_DYNAMIC doesn't exist or is invalid, fallback to parsing
    // SHT_DYNAMIC
    if (dynamic_table == null) {
        @panic("TODO: parse SHT_DYNAMIC");
    }

    // if neither PT_DYNAMIC nor SHT_DYNAMIC exist, this is a state file.
    if (dynamic_table == null) return;

    for (dynamic_table.?) |dyn| {
        if (dyn.d_tag == elf.DT_NULL) break;
        if (dyn.d_tag >= elf.DT_NUM) continue; // we don't parse any reversed tags

        self.dynamic_table[@as(u64, @bitCast(dyn.d_tag))] = dyn.d_val;
    }

    try self.parseDynamicRelocations();
    try self.parseDynamicSymbolTable();
}

fn parseDynamicRelocations(self: *Elf) !void {
    const vaddr = self.dynamic_table[elf.DT_REL];
    if (vaddr == 0) return;

    if (self.dynamic_table[elf.DT_RELENT] != @sizeOf(elf.Elf64_Rel)) {
        return error.InvalidDynamicSectionTable;
    }

    const size = self.dynamic_table[elf.DT_RELSZ];
    if (size == 0) return error.InvalidDynamicSectionTable;

    var offset: u64 = 0;
    for (self.phdrs) |phdr| {
        const p_vaddr = phdr.p_vaddr;
        const p_memsz = phdr.p_memsz;

        if (vaddr >= p_vaddr and vaddr < p_vaddr + p_memsz) {
            offset = vaddr - p_vaddr + phdr.p_offset;
            break;
        }
    } else @panic("invalid dynamic section, investigate special case");

    self.dynamic_relocations_table = std.mem.bytesAsSlice(
        elf.Elf64_Rel,
        self.bytes[offset..][0..size],
    );
}

fn parseDynamicSymbolTable(self: *Elf) !void {
    const vaddr = self.dynamic_table[elf.DT_SYMTAB];
    if (vaddr == 0) return;

    for (self.shdrs, 0..) |shdr, i| {
        if (shdr.sh_addr != vaddr) continue;

        if (shdr.sh_type != elf.SHT_SYMTAB and shdr.sh_type != elf.SHT_DYNSYM) {
            return error.InvalidSectionHeader;
        }

        self.dynamic_symbol_table = std.mem.bytesAsSlice(
            elf.Elf64_Sym,
            self.shdrSlice(@intCast(i)),
        );
        return;
    } else return error.InvalidDynamicSectionTable;
}

pub fn parseRoSections(self: *const Elf, allocator: std.mem.Allocator) !Executable.Section {
    const ro_names: []const []const u8 = &.{
        ".text",
        ".rodata",
        ".data.rel.ro",
        // ".eh_frame",
    };

    var lowest_addr: usize = std.math.maxInt(usize);
    var highest_addr: usize = 0;

    var ro_fill_length: usize = 0;
    var invalid_offsets: bool = false;

    var first_ro_section: usize = 0;
    var last_ro_section: usize = 0;
    var n_ro_sections: usize = 0;

    var ro_slices = try std.ArrayListUnmanaged(struct {
        usize,
        []const u8,
    }).initCapacity(allocator, self.shdrs.len);
    defer ro_slices.deinit(allocator);

    for (self.shdrs, 0..) |shdr, i| {
        const name = self.getString(shdr.sh_name);
        for (ro_names) |ro_name| {
            if (std.mem.eql(u8, ro_name, name)) break;
        } else continue;

        if (n_ro_sections == 0) {
            first_ro_section = i;
        }
        last_ro_section = i;
        n_ro_sections = n_ro_sections +| 1;

        const section_addr = shdr.sh_addr;

        if (!invalid_offsets) {
            if (section_addr != shdr.sh_offset) invalid_offsets = true;
        }

        const vaddr_end = section_addr +| memory.PROGRAM_START;
        if (vaddr_end > memory.STACK_START) {
            return error.ValueOutOfBounds;
        }

        const section_data = self.shdrSlice(@intCast(i));
        lowest_addr = @min(lowest_addr, section_addr);
        highest_addr = @max(highest_addr, section_addr +| section_data.len);
        ro_fill_length +|= section_data.len;

        ro_slices.appendAssumeCapacity(.{ section_addr, section_data });
    }

    // NOTE: this check isn't valid for SBFv1, just here for sanity. will need to remove for testing.
    if (lowest_addr +| ro_fill_length > highest_addr) {
        return error.ValueOutOfBounds;
    }

    lowest_addr = 0;
    const buf_len = highest_addr;
    if (buf_len > self.bytes.len) {
        return error.ValueOutOfBounds;
    }

    const ro_section = try allocator.alloc(u8, buf_len);
    for (ro_slices.items) |ro_slice| {
        const section_addr, const slice = ro_slice;
        const buf_offset_start = section_addr -| lowest_addr;
        @memcpy(ro_section[buf_offset_start..][0..slice.len], slice);
    }

    return .{ .owned = .{ .offset = lowest_addr, .data = ro_section } };
}

/// Validates the Elf. Returns errors for issues encountered.
fn validate(self: *Elf) !void {
    const header = self.header;

    // ensure 64-bit class
    if (header.e_ident[elf.EI_CLASS] != elf.ELFCLASS64) {
        return error.WrongClass;
    }
    // ensure little endian
    if (header.e_ident[elf.EI_DATA] != elf.ELFDATA2LSB) {
        return error.WrongEndianess;
    }
    // ensure no OS_ABI was set
    if (header.e_ident[ebpf.EI_OSABI] != ebpf.ELFOSABI_NONE) {
        return error.WrongAbi;
    }
    // ensure the ELF was compiled for BPF or possibly the custom SBPF machine number
    if (header.e_machine != elf.EM.BPF and @intFromEnum(header.e_machine) != ebpf.EM_SBPF) {
        return error.WrongMachine;
    }
    // ensure that this is a `.so`, dynamic library file
    if (header.e_type != .DYN) {
        return error.NotDynElf;
    }

    // ensure there is only one ".text" section
    {
        var count: u32 = 0;
        for (self.shdrs) |shdr| {
            if (std.mem.eql(u8, self.getString(shdr.sh_name), ".text")) {
                count += 1;
            }
        }
        if (count != 1) {
            return error.WrongNumberOfTextSections;
        }
    }

    // writable sections are not supported in our usecase
    // that will include ".bss", and ".data" sections that are writable
    // ".data.rel" is allowed though.
    for (self.shdrs) |shdr| {
        const name = self.getString(shdr.sh_name);
        if (std.mem.startsWith(u8, name, ".bss")) {
            return error.WritableSectionsNotSupported;
        }
        if (std.mem.startsWith(u8, name, ".data") and !std.mem.startsWith(u8, name, ".data.rel")) {
            // TODO: use a packed struct here, this is ugly
            if (shdr.sh_flags & (elf.SHF_ALLOC | elf.SHF_WRITE) == elf.SHF_ALLOC | elf.SHF_WRITE) {
                return error.WritableSectionsNotSupported;
            }
        }
    }

    // ensure all of the section headers are within bounds
    for (self.shdrs) |shdr| {
        const start = shdr.sh_offset;
        const end = try std.math.add(u64, start, shdr.sh_size);

        const file_size = self.bytes.len;
        if (start > file_size or end > file_size) return error.SectionHeaderOutOfBounds;
    }

    // ensure that the entry point is inside of the ".text" section
    const entrypoint = header.e_entry;
    const text_section = self.getShdrByName(".text") orelse
        return error.ShdrNotFound;

    if (entrypoint < text_section.sh_addr or
        entrypoint > text_section.sh_addr +| text_section.sh_size)
    {
        return error.EntrypointOutsideTextSection;
    }
}

fn relocate(
    self: *Elf,
    allocator: std.mem.Allocator,
    loader: *Executable.BuiltinProgram,
) !void {
    const text_section_index = self.getShdrIndexByName(".text") orelse
        return error.ShdrNotFound;
    const text_section = self.shdrs[text_section_index];

    // fixup PC-relative call instructions
    const text_bytes: []u8 = self.bytes[text_section.sh_offset..][0..text_section.sh_size];
    const instructions = try self.getInstructions();
    for (instructions, 0..) |inst, i| {
        if (inst.opcode == .call_imm and inst.imm != ~@as(u32, 0)) {
            const target_pc = @as(i64, @intCast(i)) +| @as(i32, @bitCast(inst.imm)) +| 1;
            if (target_pc < 0 or target_pc >= instructions.len)
                return error.RelativeJumpOutOfBounds;
            const key = try self.function_registry.registerHashedLegacy(
                allocator,
                &.{},
                @intCast(target_pc),
            );
            // offset into the instruction where the immediate is stored
            const offset = (i *| 8) +| 4;
            const slice = text_bytes[offset..][0..4];
            std.mem.writeInt(u32, slice, key, .little);
        }
    }

    for (self.dynamic_relocations_table) |reloc| {
        if (self.version != .v1) @panic("TODO here");
        const r_offset = reloc.r_offset;

        switch (@as(elf.R_X86_64, @enumFromInt(reloc.r_type()))) {
            .@"64" => {
                // if the relocation is addressing an instruction inside of the
                // text section, we'll need to offset it by the offset of the immediate
                // field into the instruction.
                // TODO: in V1 this is by default, but in V2 we check if the offset is inside of the
                // section
                const imm_offset = r_offset + 4;

                const ref_addr = std.mem.readInt(u32, self.bytes[imm_offset..][0..4], .little);
                const symbol = self.dynamic_symbol_table[reloc.r_sym()];

                var addr = symbol.st_value +| ref_addr;
                if (addr < memory.PROGRAM_START) {
                    addr +|= memory.PROGRAM_START;
                }

                {
                    const imm_low_offset = imm_offset;
                    const imm_slice = self.bytes[imm_low_offset..][0..4];
                    std.mem.writeInt(u32, imm_slice, @truncate(addr), .little);
                }

                {
                    const imm_high_offset = imm_offset +| 8;
                    const imm_slice = self.bytes[imm_high_offset..][0..4];
                    std.mem.writeInt(u32, imm_slice, @intCast(addr >> 32), .little);
                }
            },
            .RELATIVE => {
                const imm_offset = r_offset +| 4;

                // is the relocation targetting inside of the text section
                if (imm_offset >= text_section.sh_offset and
                    imm_offset < text_section.sh_offset + text_section.sh_size)
                {
                    // the target is a lddw instruction which takes up two instruction
                    // slots

                    const va_low = val: {
                        const imm_slice = self.bytes[imm_offset..][0..4];
                        break :val std.mem.readInt(u32, imm_slice, .little);
                    };

                    const va_high = val: {
                        const imm_high_offset = r_offset +| 12;
                        const imm_slice = self.bytes[imm_high_offset..][0..4];
                        break :val std.mem.readInt(u32, imm_slice, .little);
                    };

                    var ref_addr = (@as(u64, va_high) << 32) | va_low;
                    if (ref_addr == 0) return error.InvalidVirtualAddress;

                    if (ref_addr < memory.PROGRAM_START) {
                        ref_addr +|= memory.PROGRAM_START;
                    }

                    {
                        const imm_slice = self.bytes[imm_offset..][0..4];
                        std.mem.writeInt(u32, imm_slice, @truncate(ref_addr), .little);
                    }

                    {
                        const imm_high_offset = r_offset +| 12;
                        const imm_slice = self.bytes[imm_high_offset..][0..4];
                        std.mem.writeInt(u32, imm_slice, @intCast(ref_addr >> 32), .little);
                    }
                } else {
                    switch (self.version) {
                        .v1 => {
                            const address = std.mem.readInt(
                                u32,
                                self.bytes[imm_offset..][0..4],
                                .little,
                            );
                            const ref_addr = memory.PROGRAM_START +| address;
                            std.mem.writeInt(u64, self.bytes[r_offset..][0..8], ref_addr, .little);
                        },
                        else => @panic("TODO"),
                    }
                }
            },
            .@"32" => {
                // This relocation handles resolving calls to symbols
                // Hash the symbol name with Murmur and relocate the instruction's imm field.
                const imm_offset = r_offset +| 4;
                if (reloc.r_sym() >= self.dynamic_symbol_table.len) return error.UnknownSymbol;
                const symbol = self.dynamic_symbol_table[reloc.r_sym()];

                const dynstr_index = self.getShdrIndexByName(".dynstr") orelse
                    return error.NoDynStrSection;
                const dynstr = self.shdrSlice(dynstr_index);
                const symbol_name = std.mem.sliceTo(dynstr[symbol.st_name..], 0);

                // If the symbol is defined, this is a bpf-to-bpf call.
                if (symbol.st_type() == elf.STT_FUNC and symbol.st_value != 0) {
                    const target_pc = (symbol.st_value -| text_section.sh_addr) / 8;
                    const key = try self.function_registry.registerHashedLegacy(
                        allocator,
                        symbol_name,
                        @intCast(target_pc),
                    );
                    const slice = self.bytes[imm_offset..][0..4];
                    std.mem.writeInt(u32, slice, key, .little);
                } else {
                    const hash = ebpf.hashSymbolName(symbol_name);
                    if (loader.functions.lookupKey(hash) == null) {
                        // return error.UnresolvedSymbol;
                        @panic(symbol_name);
                    }
                    const slice = self.bytes[imm_offset..][0..4];
                    std.mem.writeInt(u32, slice, hash, .little);
                }
            },
            else => return error.UnknownRelocation,
        }
    }
}

pub fn getInstructions(self: *const Elf) ![]align(1) const ebpf.Instruction {
    const text_section_index = self.getShdrIndexByName(".text") orelse
        return error.ShdrNotFound;
    const text_bytes: []const u8 = self.shdrSlice(text_section_index);
    return std.mem.bytesAsSlice(ebpf.Instruction, text_bytes);
}

fn shdrSlice(self: *const Elf, index: u32) []const u8 {
    assert(index < self.shdrs.len);
    const shdr = self.shdrs[index];
    const sh_offset = shdr.sh_offset;
    const sh_size = shdr.sh_size;
    return self.bytes[sh_offset..][0..sh_size];
}

fn phdrSlice(self: *const Elf, index: u32) []const u8 {
    assert(index < self.shdrs.len);
    const phdr = self.phdrs[index];
    const p_offset = phdr.p_offset;
    const p_filesz = phdr.p_filesz;
    return self.bytes[p_offset..][0..p_filesz];
}

/// Returns the string for a given index into the string table.
fn getString(self: *const Elf, off: u32) [:0]const u8 {
    assert(off < self.strtab.len);
    const ptr: [*:0]const u8 = @ptrCast(self.strtab.ptr + off);
    return std.mem.sliceTo(ptr, 0);
}

fn getShdrIndexByName(self: *const Elf, name: []const u8) ?u32 {
    for (self.shdrs, 0..) |shdr, i| {
        const shdr_name = self.getString(shdr.sh_name);
        if (std.mem.eql(u8, shdr_name, name)) {
            return @intCast(i);
        }
    }
    return null;
}

pub fn getShdrByName(self: *const Elf, name: []const u8) ?elf.Elf64_Shdr {
    const index = self.getShdrIndexByName(name) orelse return null;
    return self.shdrs[index];
}

fn getPhdrIndexByType(self: *const Elf, p_type: elf.Elf64_Word) ?u32 {
    for (self.phdrs, 0..) |phdr, i| {
        if (phdr.p_type == p_type) return @intCast(i);
    }
    return null;
}
