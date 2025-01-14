//! Represents a parsed ELF file.
//!
//! Elf Spec: http://refspecs.linux-foundation.org/LSB_4.1.0/LSB-Core-generic/LSB-Core-generic.html

const std = @import("std");
const ebpf = @import("ebpf.zig");
const memory = @import("memory.zig");
const Executable = @import("Executable.zig");
const Elf = @This();

const elf = std.elf;
const assert = std.debug.assert;

bytes: []u8,

headers: Headers,
data: Data,

entry_pc: u64,
version: ebpf.SBPFVersion,
function_registry: Executable.Registry(u32),

/// Contains immutable headers parsed from the ELF file.
const Headers = struct {
    bytes: []const u8,
    header: elf.Elf64_Ehdr,
    // The following fields are align(1) because there's no guarantee of alignment inside of the ELF sections.
    shdrs: []align(1) const elf.Elf64_Shdr,
    phdrs: []align(1) const elf.Elf64_Phdr,

    fn parse(bytes: []const u8) Headers {
        const header: elf.Elf64_Ehdr = @bitCast(bytes[0..@sizeOf(elf.Elf64_Ehdr)].*);

        const shoff = header.e_shoff;
        const shnum = header.e_shnum;
        const shsize = shnum * @sizeOf(elf.Elf64_Shdr);
        const shdrs = std.mem.bytesAsSlice(elf.Elf64_Shdr, bytes[shoff..][0..shsize]);

        const phoff = header.e_phoff;
        const phnum = header.e_phnum;
        const phsize = phnum * @sizeOf(elf.Elf64_Phdr);
        const phdrs = std.mem.bytesAsSlice(elf.Elf64_Phdr, bytes[phoff..][0..phsize]);

        return .{
            .bytes = bytes,
            .header = header,
            .shdrs = shdrs,
            .phdrs = phdrs,
        };
    }

    fn shdrSlice(self: Headers, index: u32) []const u8 {
        const shdr = self.shdrs[index];
        const sh_offset = shdr.sh_offset;
        const sh_size = shdr.sh_size;
        return self.bytes[sh_offset..][0..sh_size];
    }

    fn phdrSlice(self: Headers, index: u32) []const u8 {
        const phdr = self.phdrs[index];
        const p_offset = phdr.p_offset;
        const p_filesz = phdr.p_filesz;
        return self.bytes[p_offset..][0..p_filesz];
    }

    fn getPhdrIndexByType(self: Headers, p_type: elf.Elf64_Word) ?u32 {
        for (self.phdrs, 0..) |phdr, i| {
            if (phdr.p_type == p_type) return @intCast(i);
        }
        return null;
    }
};

/// Contains data which is parsed from the headers.
const Data = struct {
    strtab: []const u8,
    dynamic_table: DynamicTable,
    relocations_table: []align(1) const elf.Elf64_Rel,
    symbol_table: []align(1) const elf.Elf64_Sym,

    const DynamicTable = [elf.DT_NUM]elf.Elf64_Xword;

    fn parse(headers: Headers) !Data {
        const strtab = headers.shdrSlice(headers.header.e_shstrndx);

        const dynamic_table = try parseDynamic(headers);

        const relocations_table, const symbol_table = if (dynamic_table) |table| blk: {
            const relocations_table = try parseDynamicRelocations(headers, table);
            const symbol_table = try parseDynamicSymbolTable(headers, table);
            break :blk .{ relocations_table, symbol_table };
        } else .{ &.{}, &.{} };

        return .{
            .strtab = strtab,
            .dynamic_table = dynamic_table orelse .{0} ** elf.DT_NUM,
            .relocations_table = relocations_table,
            .symbol_table = symbol_table,
        };
    }

    fn parseDynamic(headers: Headers) !?DynamicTable {
        var output_table: DynamicTable = .{0} ** elf.DT_NUM;
        var dynamic_table: ?[]align(1) const elf.Elf64_Dyn = null;

        if (headers.getPhdrIndexByType(elf.PT_DYNAMIC)) |index| {
            dynamic_table = std.mem.bytesAsSlice(elf.Elf64_Dyn, headers.phdrSlice(index));
        }

        // if PT_DYNAMIC doesn't exist or is invalid, fallback to parsing
        // SHT_DYNAMIC
        if (dynamic_table == null) {
            @panic("TODO: parse SHT_DYNAMIC");
        }

        // if neither PT_DYNAMIC nor SHT_DYNAMIC exist, this is a state file.
        if (dynamic_table == null) return null;

        for (dynamic_table.?) |dyn| {
            if (dyn.d_tag == elf.DT_NULL) break;
            if (dyn.d_tag >= elf.DT_NUM) continue; // we don't parse any reversed tags
            if (dyn.d_tag < 0) return error.InvalidDynamicTable;

            output_table[@as(u64, @bitCast(dyn.d_tag))] = dyn.d_val;
        }

        return output_table;
    }

    fn parseDynamicRelocations(
        headers: Headers,
        dynamic_table: DynamicTable,
    ) ![]align(1) const elf.Elf64_Rel {
        const vaddr = dynamic_table[elf.DT_REL];
        if (vaddr == 0) return &.{};

        if (dynamic_table[elf.DT_RELENT] != @sizeOf(elf.Elf64_Rel)) {
            return error.InvalidDynamicSectionTable;
        }

        const size = dynamic_table[elf.DT_RELSZ];
        if (size == 0) return error.InvalidDynamicSectionTable;

        var offset: u64 = 0;
        for (headers.phdrs) |phdr| {
            const p_vaddr = phdr.p_vaddr;
            const p_memsz = phdr.p_memsz;

            if (vaddr >= p_vaddr and vaddr < p_vaddr + p_memsz) {
                offset = vaddr - p_vaddr + phdr.p_offset;
                break;
            }
        } else @panic("invalid dynamic section, investigate special case");

        return std.mem.bytesAsSlice(elf.Elf64_Rel, headers.bytes[offset..][0..size]);
    }

    fn parseDynamicSymbolTable(
        headers: Headers,
        dynamic_table: DynamicTable,
    ) ![]align(1) const elf.Elf64_Sym {
        const vaddr = dynamic_table[elf.DT_SYMTAB];
        if (vaddr == 0) return &.{};

        for (headers.shdrs, 0..) |shdr, i| {
            if (shdr.sh_addr != vaddr) continue;
            if (shdr.sh_type != elf.SHT_SYMTAB and shdr.sh_type != elf.SHT_DYNSYM) {
                return error.InvalidSectionHeader;
            }
            return std.mem.bytesAsSlice(elf.Elf64_Sym, headers.shdrSlice(@intCast(i)));
        } else return error.InvalidDynamicSectionTable;
    }

    /// Returns the string for a given index into the string table.
    fn getString(self: Data, off: u32) [:0]const u8 {
        assert(off < self.strtab.len);
        const ptr: [*:0]const u8 = @ptrCast(self.strtab.ptr + off);
        return std.mem.sliceTo(ptr, 0);
    }

    fn getShdrIndexByName(self: Data, headers: Headers, name: []const u8) ?u32 {
        for (headers.shdrs, 0..) |shdr, i| {
            const shdr_name = self.getString(shdr.sh_name);
            if (std.mem.eql(u8, shdr_name, name)) {
                return @intCast(i);
            }
        }
        return null;
    }

    pub fn getShdrByName(self: Data, headers: Headers, name: []const u8) ?elf.Elf64_Shdr {
        const index = self.getShdrIndexByName(headers, name) orelse return null;
        return headers.shdrs[index];
    }
};

pub fn parse(
    allocator: std.mem.Allocator,
    bytes: []u8,
    loader: *Executable.BuiltinProgram,
) !Elf {
    const headers = Headers.parse(bytes);
    const data = try Data.parse(headers);

    const text_section = data.getShdrByName(headers, ".text") orelse return error.NoTextSection;
    const offset = headers.header.e_entry -| text_section.sh_addr;
    const entry_pc = try std.math.divExact(u64, offset, 8);

    const sbpf_version: ebpf.SBPFVersion = if (headers.header.e_flags == ebpf.EF_SBPF_V2)
        .v2
    else
        .v1;

    if (sbpf_version != .v1)
        std.debug.panic("found sbpf version: {s}, support it!", .{@tagName(sbpf_version)});

    var self: Elf = .{
        .bytes = bytes,
        .headers = headers,
        .data = data,
        .entry_pc = entry_pc,
        .version = sbpf_version,
        .function_registry = .{},
    };
    errdefer self.function_registry.deinit(allocator);

    try self.validate();
    try self.relocate(allocator, loader);

    return self;
}

pub fn parseRoSections(self: *const Elf, allocator: std.mem.Allocator) !Executable.Section {
    const ro_names: []const []const u8 = &.{
        ".text",
        ".rodata",
        ".data.rel.ro",
        ".eh_frame",
    };

    var lowest_addr: usize = std.math.maxInt(usize);
    var highest_addr: usize = 0;

    var ro_fill_length: usize = 0;

    var ro_slices = try std.ArrayListUnmanaged(struct {
        usize,
        []const u8,
    }).initCapacity(allocator, self.headers.shdrs.len);
    defer ro_slices.deinit(allocator);

    for (self.headers.shdrs, 0..) |shdr, i| {
        const name = self.data.getString(shdr.sh_name);
        for (ro_names) |ro_name| {
            if (std.mem.eql(u8, ro_name, name)) break;
        } else continue;

        const section_addr = shdr.sh_addr;

        if (section_addr != shdr.sh_offset) {
            return error.InvalidOffset;
        }

        const vaddr_end = section_addr +| memory.PROGRAM_START;
        if (vaddr_end > memory.STACK_START) {
            return error.ValueOutOfBounds;
        }

        const section_data = self.headers.shdrSlice(@intCast(i));
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
    @memset(ro_section, 0);
    for (ro_slices.items) |ro_slice| {
        const section_addr, const slice = ro_slice;
        const buf_offset_start = section_addr -| lowest_addr;
        @memcpy(ro_section[buf_offset_start..][0..slice.len], slice);
    }

    return .{ .owned = .{ .offset = lowest_addr, .data = ro_section } };
}

/// Validates the Elf. Returns errors for issues encountered.
fn validate(self: *Elf) !void {
    const header = self.headers.header;

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
        for (self.headers.shdrs) |shdr| {
            if (std.mem.eql(u8, self.data.getString(shdr.sh_name), ".text")) {
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
    for (self.headers.shdrs) |shdr| {
        const name = self.data.getString(shdr.sh_name);
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
    for (self.headers.shdrs) |shdr| {
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
    const text_section = self.headers.shdrs[text_section_index];

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

    for (self.data.relocations_table) |reloc| {
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
                const symbol = self.data.symbol_table[reloc.r_sym()];

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
                if (reloc.r_sym() >= self.data.symbol_table.len) return error.UnknownSymbol;
                const symbol = self.data.symbol_table[reloc.r_sym()];

                const dynstr_index = self.getShdrIndexByName(".dynstr") orelse
                    return error.NoDynStrSection;
                const dynstr = self.headers.shdrSlice(dynstr_index);
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

pub fn getInstructions(self: Elf) ![]align(1) const ebpf.Instruction {
    const text_section_index = self.getShdrIndexByName(".text") orelse
        return error.ShdrNotFound;
    const text_bytes: []const u8 = self.headers.shdrSlice(text_section_index);
    return std.mem.bytesAsSlice(ebpf.Instruction, text_bytes);
}

fn getShdrIndexByName(self: Elf, name: []const u8) ?u32 {
    return self.data.getShdrIndexByName(self.headers, name);
}

pub fn getShdrByName(self: Elf, name: []const u8) ?elf.Elf64_Shdr {
    return self.data.getShdrByName(self.headers, name);
}
