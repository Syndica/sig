//! Elf Spec: http://refspecs.linux-foundation.org/LSB_4.1.0/LSB-Core-generic/LSB-Core-generic.html

const std = @import("std");
const sig = @import("../sig.zig");
const sbpf = @import("sbpf.zig");
const memory = @import("memory.zig");

const lib = @import("lib.zig");
const Config = lib.Config;
const Registry = lib.Registry;
const Section = lib.Section;
const SyscallMap = sig.vm.SyscallMap;
const Executable = lib.Executable;

const elf = std.elf;

const expect = std.testing.expect;

pub const LoadError = error{
    UnsupportedSBPFVersion,
    WrongClass,
    WrongMachine,
    WrongAbi,
    WrongEndianess,
    WrongType,
    NotOneTextSection,
    WritableSectionNotSupported,
    SectionNotFound,
    EntrypointOutOfBounds,
    OutOfBounds,
    SymbolHashCollision,
    UnresolvedSymbol,
    UnknownSymbol,
    UnknownRelocation,
    InvalidEntrypoint,
    RelativeJumpOutOfBounds,
    InvalidVirtualAddress,
    OutOfMemory,
} || ParserError;

const ParserError = error{
    /// ELF file header is inconsistent or unsupported
    InvalidFileHeader,
    /// Program header is inconsistent or unsupported
    InvalidProgramHeader,
    /// Section header is inconsistent or unsupported
    InvalidSectionHeader,
    /// Section or symbol name is not UTF8 or too long
    InvalidString,
    /// Section or symbol name is too long
    StringTooLong,
    /// An index or memory range does exceed its boundaries
    OutOfBounds,
    /// The size isn't valid
    InvalidSize,
    /// Headers, tables or sections do overlap in the file
    Overlap,
    /// Sections are not sorted in ascending order
    SectionNotInOrder,
    /// No section name string table present in the file
    NoSectionNameStringTable,
    /// Invalid .dynamic section table
    InvalidDynamicSectionTable,
    /// Invalid relocation table
    InvalidRelocationTable,
    /// Invalid alignment
    InvalidAlignment,
    /// No string table
    NoStringTable,
    /// No dynamic string table
    NoDynamicStringTable,
};

pub fn load(
    allocator: std.mem.Allocator,
    bytes: []u8,
    loader: *const SyscallMap,
    config: Config,
) LoadError!Executable {
    // It's important we read *only* the bytes, 48..52, since if the program
    // is exactly 52 bytes long, we could read and return UnsupportedSBPFVersion
    // before we return OutOfBounds.
    if (bytes.len < 48 + @sizeOf(u32)) return error.OutOfBounds;
    const version: sbpf.Version = switch (std.mem.readInt(u32, bytes[48..][0..4], .little)) {
        0 => .v0,
        1 => .v1,
        2 => .v2,
        3 => .v3,
        else => .reserved,
    };

    // Ensure that the sbpf version we find is within the range that's enabled.
    if (@intFromEnum(version) < @intFromEnum(config.minimum_version) or
        @intFromEnum(version) > @intFromEnum(config.maximum_version))
    {
        return error.UnsupportedSBPFVersion;
    }

    return if (version.enableStricterVerification())
        try parseStrict(allocator, bytes, version, config)
    else
        try parseLenient(allocator, bytes, config, loader, version);
}

fn parseStrict(
    allocator: std.mem.Allocator,
    bytes: []u8,
    sbpf_version: sbpf.Version,
    config: Config,
) LoadError!Executable {
    if (bytes.len < @sizeOf(elf.Elf64_Ehdr)) return error.OutOfBounds;
    const header: elf.Elf64_Ehdr = @bitCast(bytes[0..@sizeOf(elf.Elf64_Ehdr)].*);

    // A list of the first 4 expected program headers.
    // Since this is a stricter parsing scheme, we need them to match exactly.
    const expected_phdrs: [4]struct { u32, u64 } = .{
        .{ elf.PF_X, memory.BYTECODE_START }, // byte code
        .{ elf.PF_R, memory.RODATA_START }, // read only data
        .{ elf.PF_R | elf.PF_W, memory.STACK_START }, // stack
        .{ elf.PF_R | elf.PF_W, memory.HEAP_START }, // heap
    };

    const ident: ElfIdent = @bitCast(header.e_ident);
    const phdr_table_end = (@sizeOf(elf.Elf64_Phdr) *| header.e_phnum) +| @sizeOf(elf.Elf64_Ehdr);
    if (!std.mem.eql(u8, ident.magic[0..4], elf.MAGIC) or
        ident.class != elf.ELFCLASS64 or
        ident.data != elf.ELFDATA2LSB or
        ident.version != 1 or
        ident.osabi != elf.OSABI.NONE or
        ident.abiversion != 0x00 or
        !std.mem.allEqual(u8, &ident.padding, 0) or
        @intFromEnum(header.e_machine) != sbpf.EM_SBPF or
        header.e_type != .DYN or
        header.e_version != 1 or
        header.e_phoff != @sizeOf(elf.Elf64_Ehdr) or
        header.e_ehsize != @sizeOf(elf.Elf64_Ehdr) or
        header.e_phentsize != @sizeOf(elf.Elf64_Phdr) or
        header.e_phnum < expected_phdrs.len or
        phdr_table_end >= bytes.len or
        header.e_shentsize != @sizeOf(elf.Elf64_Shdr) or
        header.e_shstrndx >= header.e_shnum)
    {
        return error.InvalidFileHeader;
    }

    const phdrs = std.mem.bytesAsSlice(
        elf.Elf64_Phdr,
        bytes[@sizeOf(elf.Elf64_Ehdr)..phdr_table_end],
    );
    for (expected_phdrs, phdrs[0..expected_phdrs.len]) |entry, phdr| {
        const p_flags, const p_vaddr = entry;
        // For writable sections, (those with the PF_W bit set), we expect their
        // value for p_filesz to be zero.
        const p_filesz = if (p_flags & elf.PF_W != 0) 0 else phdr.p_memsz;

        if (phdr.p_type != elf.PT_LOAD or
            phdr.p_flags != p_flags or
            phdr.p_offset < phdr_table_end or
            phdr.p_offset >= bytes.len or
            phdr.p_offset % 8 != 0 or
            phdr.p_vaddr != p_vaddr or
            phdr.p_paddr != p_vaddr or
            phdr.p_filesz != p_filesz or
            phdr.p_filesz > bytes.len -| phdr.p_offset or
            phdr.p_memsz >= memory.RODATA_START // larger than one region
        ) {
            return error.InvalidProgramHeader;
        }
    }

    const bytecode_header = phdrs[0];
    const vm_range_start = bytecode_header.p_vaddr;
    const vm_range_end = bytecode_header.p_vaddr +% bytecode_header.p_memsz;
    const entry_chk = header.e_entry +% 7;
    if (!(vm_range_start <= entry_chk and entry_chk < vm_range_end) or
        header.e_entry % 8 != 0)
    {
        return error.InvalidFileHeader;
    }

    const entry_pc = (header.e_entry -| bytecode_header.p_vaddr) / 8;
    const entry_inst: sbpf.Instruction = @bitCast(bytes[bytecode_header.p_offset..][0..8].*);
    if (!entry_inst.isFunctionStartMarker()) {
        return error.InvalidFileHeader;
    }

    var function_registry: Registry = .{};
    errdefer function_registry.deinit(allocator);

    const rodata_header = phdrs[1];

    return .{
        .bytes = bytes,
        .version = sbpf_version,
        .entry_pc = entry_pc,
        .from_asm = false,
        .ro_section = .{ .borrowed = .{
            .offset = rodata_header.p_vaddr,
            .start = rodata_header.p_offset,
            .end = rodata_header.p_offset +| rodata_header.p_filesz,
        } },
        .text_vaddr = vm_range_start,
        .config = config,
        .function_registry = function_registry,
        .instructions = std.mem.bytesAsSlice(sbpf.Instruction, try safeSlice(
            bytes,
            bytecode_header.p_offset,
            bytecode_header.p_filesz,
        )),
    };
}

const ElfIdent = extern struct {
    magic: [4]u8,
    class: u8,
    data: u8,
    version: u8,
    osabi: elf.OSABI,
    abiversion: u8,
    padding: [7]u8,
};

fn parseLenient(
    allocator: std.mem.Allocator,
    bytes: []u8,
    config: Config,
    loader: *const SyscallMap,
    version: sbpf.Version,
) !Executable {
    // [agave] https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L607
    var parsed = try Elf64.parse(bytes);

    // [agave] https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L617
    const text_shdr = try parsed.validate();

    // [agave] https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L620-L638
    const text_section_vaddr = text_shdr.sh_addr +| memory.RODATA_START;
    const vaddr_end = text_section_vaddr;

    // [agave] https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L632-L638
    if ((config.reject_broken_elfs and text_shdr.sh_addr != text_shdr.sh_offset) or
        vaddr_end > memory.STACK_START)
    {
        return error.OutOfBounds;
    }

    var function_registry: Registry = .{};
    errdefer function_registry.deinit(allocator);

    // [agave] https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L642-L647
    try parsed.relocate(allocator, bytes, &function_registry, loader, config);

    // [agave] https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L649-L653
    const offset = parsed.header.e_entry -| text_shdr.sh_addr;
    if (!std.mem.isAligned(offset, 8)) return error.InvalidEntrypoint;
    const entry_pc = offset / 8;

    // Remove `entrypoint` if we already picked it up somewhere. Doesn't matter
    // if we already had an entry like that, just need to prevent a symbol collision.
    _ = function_registry.map.swapRemove(sbpf.hashSymbolName("entrypoint"));
    _ = try function_registry.registerHashedLegacy(
        allocator,
        loader,
        true,
        "entrypoint",
        entry_pc,
    );

    const ro_section = try parsed.parseRoSections(allocator, config);

    const text_range = Elf64.Range.get(text_shdr);
    const text_bytes = bytes[text_range.lo..text_range.hi];
    const instruction_count = (text_range.hi - text_range.lo) / 8;
    const instructions = std.mem.bytesAsSlice(
        sbpf.Instruction,
        text_bytes[0 .. instruction_count * @sizeOf(sbpf.Instruction)],
    );

    return .{
        .bytes = bytes,
        .config = config,
        .entry_pc = entry_pc,
        .from_asm = false,
        .function_registry = function_registry,
        .instructions = instructions,
        .ro_section = ro_section,
        .text_vaddr = text_section_vaddr,
        .version = version,
    };
}

const SectionAttributes = packed struct(u64) {
    write: bool = false,
    alloc: bool = false,
    execinstr: bool = false,
    _3: u1 = 0,
    merge: bool = false,
    strings: bool = false,
    info_link: bool = false,
    link_order: bool = false,
    os_nonconforming: bool = false,
    group: bool = false,
    tls: bool = false,
    _11: u19 = 0,
    ordered: bool = false,
    exclude: bool = false,
    _32: u32 = 0,
};

/// [agave] https://github.com/anza-xyz/sbpf/blob/v0.13.0/src/elf_parser/mod.rs#L132
const Elf64 = struct {
    bytes: []const u8,
    header: elf.Elf64_Ehdr,

    // The following fields are align(1) because there's no guarantee of alignment inside of the ELF sections.
    shdrs: []align(1) const elf.Elf64_Shdr,
    phdrs: []align(1) const elf.Elf64_Phdr,

    text_offset: u64,
    text_size: u64,

    // Known section headers.
    text_section: ?u64,
    symtab: ?u64,
    strtab: ?u64,
    dyn: ?u64,
    dynstr: ?u64,
    dynsymtab: ?u64,

    // Known program headers.
    phndx_dyn: ?u64,

    // Dynamic relocation table entries.
    dt_rel_off: u64,
    dt_rel_sz: u64,

    const SECTION_NAME_LENGTH_MAXIMUM = 16;
    const SYMBOL_NAME_LENGTH_MAXIMUM = 64;

    /// Same as Elf64Shdr::file_range().
    ///
    /// [agave] https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L87-L93
    const Range = struct {
        lo: u64,
        hi: u64,

        fn get(shdr: elf.Elf64_Shdr) Range {
            if (shdr.sh_type == elf.SHT_NOBITS) {
                return .{ .lo = 0, .hi = 0 };
            } else {
                return .{
                    .lo = shdr.sh_offset,
                    .hi = shdr.sh_offset +| shdr.sh_size,
                };
            }
        }

        fn contains(r: Range, addr: u64) bool {
            if (addr < r.lo) return false;
            if (addr >= r.hi) return false;
            return true;
        }
    };

    /// [agave] https://github.com/anza-xyz/sbpf/blob/v0.13.0/src/elf_parser/mod.rs#L120
    fn checkOverlap(a_start: usize, a_end: usize, b_start: usize, b_end: usize) !void {
        if (a_end <= b_start or b_end <= a_start) return;
        return error.Overlap;
    }

    /// [agave] https://github.com/anza-xyz/sbpf/blob/v0.13.0/src/elf_parser/mod.rs#L148
    fn parse(bytes: []const u8) !Elf64 {
        // Elf64::parse_file_header
        if (bytes.len < @sizeOf(elf.Elf64_Ehdr)) return error.OutOfBounds;
        const header: elf.Elf64_Ehdr = @bitCast(bytes[0..@sizeOf(elf.Elf64_Ehdr)].*);
        const ident: ElfIdent = @bitCast(header.e_ident);

        const ehdr_start = 0;
        const ehdr_end = @sizeOf(elf.Elf64_Ehdr);

        if (!std.mem.eql(u8, &ident.magic, elf.MAGIC) or
            ident.class != elf.ELFCLASS64 or
            ident.data != elf.ELFDATA2LSB or
            ident.version != 1 or
            header.e_ehsize != @sizeOf(elf.Elf64_Ehdr) or
            header.e_phentsize != @sizeOf(elf.Elf64_Phdr) or
            header.e_shentsize != @sizeOf(elf.Elf64_Shdr) or
            header.e_shstrndx >= header.e_shnum)
        {
            return error.InvalidFileHeader;
        }

        // Elf64::parse_program_header_table
        // [agave] https://github.com/anza-xyz/sbpf/blob/v0.13.0/src/elf_parser/mod.rs#L164
        const phdr_start = header.e_phoff;
        const phdr_size = try mul(u64, header.e_phnum, @sizeOf(elf.Elf64_Phdr));
        const phdr_end = try add(u64, header.e_phoff, phdr_size);

        // [agave] https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L301
        try checkOverlap(ehdr_start, ehdr_end, phdr_start, phdr_end);

        // https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L302-L303
        if (phdr_size % @sizeOf(elf.Elf64_Phdr) != 0) return error.InvalidSize;
        const phdrs = std.mem.bytesAsSlice(
            elf.Elf64_Phdr,
            try safeSlice(bytes, phdr_start, phdr_size),
        );
        if (!std.mem.isAligned(phdr_start, 8)) return error.InvalidAlignment;

        // Elf64::parse_section_header_table
        const shdr_start = header.e_shoff;
        const shdr_size = try mul(u64, header.e_shnum, @sizeOf(elf.Elf64_Shdr));
        const shdr_end = try add(u64, header.e_shoff, shdr_size);

        // [agave] https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L318
        try checkOverlap(ehdr_start, ehdr_end, shdr_start, shdr_end);
        // [agave] https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L319
        try checkOverlap(phdr_start, phdr_end, shdr_start, shdr_end);

        // https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L321
        // Guaranteed to not overflow, as shdr_end is at least as large as e_shoff.
        if ((shdr_end - header.e_shoff) % @sizeOf(elf.Elf64_Shdr) != 0) return error.InvalidSize;
        const shdrs = std.mem.bytesAsSlice(
            elf.Elf64_Shdr,
            try safeSlice(bytes, shdr_start, shdr_size),
        );
        if (!std.mem.isAligned(header.e_shoff, 8)) return error.InvalidAlignment;

        // [agave] https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L174-L177
        if (shdrs.len == 0 or shdrs[0].sh_type != elf.SHT_NULL) {
            return error.InvalidSectionHeader;
        }

        var self: Elf64 = .{
            .bytes = bytes,
            .header = header,
            .shdrs = shdrs,
            .phdrs = phdrs,

            .text_offset = 0,
            .text_size = 0,

            .text_section = null,
            .symtab = null,
            .strtab = null,
            .dyn = null,
            .dynstr = null,
            .dynsymtab = null,
            .phndx_dyn = null,

            .dt_rel_off = 0,
            .dt_rel_sz = 0,
        };

        {
            var vaddr: u64 = 0;
            for (0..header.e_phnum) |i| {
                const phdr = self.phdrs[i];
                if (phdr.p_type != elf.PT_LOAD) {
                    if (phdr.p_type == elf.PT_DYNAMIC and self.phndx_dyn == null) {
                        self.phndx_dyn = i;
                    }
                    continue;
                }
                if (phdr.p_vaddr < vaddr) return error.InvalidProgramHeader;
                _ = try add(u64, phdr.p_offset, phdr.p_filesz);
                if (phdr.p_offset + phdr.p_filesz > bytes.len) {
                    return error.OutOfBounds;
                }
                vaddr = phdr.p_vaddr;
            }
        }

        // [agave] https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L198-L216
        {
            var offset: u64 = 0;
            for (0..header.e_shnum) |i| {
                const shdr = self.shdrs[i];
                if (shdr.sh_type == elf.SHT_NOBITS) continue;
                if (shdr.sh_type == elf.SHT_DYNAMIC and self.dyn == null) {
                    self.dyn = i;
                }

                const sh_start = shdr.sh_offset;
                const sh_end = try add(u64, shdr.sh_offset, shdr.sh_size);

                // [agave] https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L206-L208
                try checkOverlap(sh_start, sh_end, ehdr_start, ehdr_end);
                try checkOverlap(sh_start, sh_end, phdr_start, phdr_end);
                try checkOverlap(sh_start, sh_end, shdr_start, shdr_end);

                // [agave] https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L209-L215
                if (sh_start < offset) return error.SectionNotInOrder;
                offset = sh_end;
                if (sh_end > bytes.len) return error.OutOfBounds;
            }
        }

        // Parse sections
        // [agave] https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L240
        {
            if (header.e_shstrndx == elf.SHT_NULL) {
                return error.NoSectionNameStringTable;
            }

            const section_names_shdr_idx = header.e_shstrndx;
            const section_names_shdr = self.shdrs[section_names_shdr_idx];
            if (section_names_shdr.sh_type != elf.SHT_STRTAB) {
                return error.InvalidSectionHeader;
            }

            for (0..header.e_shnum) |i| {
                const shdr = self.shdrs[i];
                const name = try getStringInSection(
                    bytes,
                    section_names_shdr,
                    shdr.sh_name,
                    SECTION_NAME_LENGTH_MAXIMUM,
                );

                if (std.mem.eql(u8, name, ".symtab")) {
                    if (self.symtab != null) return error.InvalidSectionHeader;
                    self.symtab = i;
                } else if (std.mem.eql(u8, name, ".strtab")) {
                    if (self.strtab != null) return error.InvalidSectionHeader;
                    self.strtab = i;
                } else if (std.mem.eql(u8, name, ".dynstr")) {
                    if (self.dynstr != null) return error.InvalidSectionHeader;
                    self.dynstr = i;
                }
            }
        }

        // Parse dynamic
        // [agave] https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L241
        {
            var dynamic_table_start: ?u64 = null;
            var dynamic_table_end: ?u64 = null;

            // https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L364-L372
            if (self.phndx_dyn) |dyn| {
                const dyn_ph = self.phdrs[dyn];
                dynamic_table_start = dyn_ph.p_offset;
                dynamic_table_end = dyn_ph.p_offset +% dyn_ph.p_filesz;

                if (dynamic_table_end.? < dynamic_table_start.? or
                    dynamic_table_end.? > bytes.len or
                    dyn_ph.p_filesz % @sizeOf(elf.Elf64_Dyn) != 0 or
                    !std.mem.isAligned(dynamic_table_start.?, 8))
                {
                    dynamic_table_start = null;
                    dynamic_table_end = null;
                }
            }

            if (dynamic_table_start == null) if (self.dyn) |dyn| {
                const dyn_sh = self.shdrs[dyn];
                dynamic_table_start = dyn_sh.sh_offset;
                dynamic_table_end = add(u64, dyn_sh.sh_offset, dyn_sh.sh_size) catch
                    return error.InvalidDynamicSectionTable;
                if (dyn_sh.sh_size % @sizeOf(elf.Elf64_Dyn) != 0 or
                    dynamic_table_end.? > bytes.len or
                    !std.mem.isAligned(dynamic_table_start.?, 8))
                {
                    return error.InvalidDynamicSectionTable;
                }
            };

            if (dynamic_table_start == null) {
                return self; // nothing left to do
            }

            var dynamic_table: [elf.DT_NUM]u64 = @splat(0);
            const dyns = std.mem.bytesAsSlice(
                elf.Elf64_Dyn,
                bytes[dynamic_table_start.?..dynamic_table_end.?],
            );
            for (dyns) |dyn| {
                const d_tag: u64 = @bitCast(dyn.d_tag);
                if (d_tag == elf.DT_NULL) break;
                if (d_tag >= elf.DT_NUM) continue;
                dynamic_table[d_tag] = dyn.d_val;
            }

            // solana_sbpf::elf_parser::Elf64::parse_dynamic_relocations
            // [agave] https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L409
            relocs: {
                const vaddr = dynamic_table[elf.DT_REL];
                if (vaddr == 0) break :relocs;

                if (dynamic_table[elf.DT_RELENT] != @sizeOf(elf.Elf64_Rel)) {
                    return error.InvalidDynamicSectionTable;
                }

                const size = dynamic_table[elf.DT_RELSZ];
                if (size == 0) return error.InvalidDynamicSectionTable;

                // [agave] https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L430-L444
                // program_header_for_vaddr
                const maybe_phdr: ?elf.Elf64_Phdr = for (0..header.e_phnum) |i| {
                    const phdr = self.phdrs[i];
                    const p_vaddr0 = phdr.p_vaddr;
                    const p_memsz = phdr.p_memsz;
                    const p_vaddr1 = try add(u64, p_vaddr0, p_memsz);
                    if (p_vaddr0 <= vaddr and vaddr < p_vaddr1) break phdr;
                } else null;

                var offset: u64 = undefined;
                if (maybe_phdr) |phdr| {
                    offset = try sub(u64, vaddr, phdr.p_vaddr);
                    offset = try add(u64, offset, phdr.p_offset);
                } else {
                    for (self.shdrs) |shdr| {
                        if (shdr.sh_addr == vaddr) {
                            offset = shdr.sh_offset;
                            break;
                        }
                    } else {
                        return error.InvalidDynamicSectionTable;
                    }
                }

                const offset_plus_size = try add(u64, offset, size);
                if (size % @sizeOf(elf.Elf64_Rel) != 0 or
                    offset_plus_size > bytes.len or
                    !std.mem.isAligned(offset, 8))
                {
                    return error.InvalidDynamicSectionTable;
                }

                self.dt_rel_off = offset;
                self.dt_rel_sz = size;
            }

            // [agave] https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L410
            dynsym: {
                // [agave] https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L452-L455
                const vaddr = dynamic_table[elf.DT_SYMTAB];
                if (vaddr == 0) break :dynsym;

                // [agave] https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L457-L461
                const shdr_sym: elf.Elf64_Shdr = for (self.shdrs, 0..) |shdr, i| {
                    if (shdr.sh_addr == vaddr) {
                        self.dynsymtab = i;
                        break shdr;
                    }
                } else return error.InvalidDynamicSectionTable;

                // [agave] https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L463-L464
                {
                    if (shdr_sym.sh_type != elf.SHT_SYMTAB and shdr_sym.sh_type != elf.SHT_DYNSYM) {
                        return error.InvalidSectionHeader;
                    }

                    // [agave] https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L574
                    // [agave] https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf_parser/mod.rs#L671
                    const shdr_sym_start = shdr_sym.sh_offset;
                    const shdr_sym_end = try add(u64, shdr_sym.sh_offset, shdr_sym.sh_size);

                    if (shdr_sym.sh_size % @sizeOf(elf.Elf64_Sym) != 0) return error.InvalidSize;
                    if (shdr_sym_end > bytes.len) return error.OutOfBounds;
                    if (!std.mem.isAligned(shdr_sym_start, 8)) return error.InvalidAlignment;
                }
            }
        }

        return self;
    }

    /// On success, returns the only text section found.
    fn validate(self: *Elf64) !elf.Elf64_Shdr {
        const header = self.header;
        if (header.e_ident[elf.EI_CLASS] != elf.ELFCLASS64) return error.WrongClass;
        if (header.e_ident[elf.EI_DATA] != elf.ELFDATA2LSB) return error.WrongEndianess;
        if (header.e_ident[elf.EI_OSABI] != 0) return error.WrongAbi;
        if (header.e_machine != elf.EM.BPF and @intFromEnum(header.e_machine) != sbpf.EM_SBPF) {
            return error.WrongMachine;
        }
        if (header.e_type != .DYN) return error.WrongType;

        const section_names_shdr_idx = header.e_shstrndx;
        const section_names_shdr = self.shdrs[section_names_shdr_idx];

        var text_section: elf.Elf64_Shdr = undefined;
        var shndx_text: ?u64 = null;
        var writable_err: bool = false;
        var oob_err: bool = false;
        for (self.shdrs, 0..) |shdr, i| {
            // This can't actually fail, as we've already iterated through the names of sections in `parse`.
            const name = try getStringInSection(
                self.bytes,
                section_names_shdr,
                shdr.sh_name,
                SECTION_NAME_LENGTH_MAXIMUM,
            );

            // [agave] https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L765-L775
            if (std.mem.eql(u8, name, ".text")) {
                if (shndx_text == null) {
                    text_section = shdr;
                    shndx_text = i;
                } else return error.NotOneTextSection;
            }

            // [agave] https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L780-L791
            if (std.mem.startsWith(u8, name, ".bss")) {
                writable_err = true;
            }
            if (std.mem.startsWith(u8, name, ".data") and
                !std.mem.startsWith(u8, name, ".data.rel"))
            {
                const flags: SectionAttributes = @bitCast(shdr.sh_flags);
                if (flags.alloc and flags.write) {
                    writable_err = true;
                }
            }

            // [agave] https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L793-L802
            const shdr_end = add(u64, shdr.sh_offset, shdr.sh_size);
            if (shdr_end) |end| {
                if (end > self.bytes.len) oob_err = true;
            } else |_| {
                oob_err = true;
            }
        }

        // [agave] https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L776-L778
        if (shndx_text == null) return error.NotOneTextSection;
        // [agave] https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L786-L788
        if (writable_err) return error.WritableSectionNotSupported;
        // [agave] https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L798
        if (oob_err) return error.OutOfBounds;

        if (!(text_section.sh_addr <= header.e_entry and
            header.e_entry < (text_section.sh_addr +| text_section.sh_size)))
        {
            return error.EntrypointOutOfBounds;
        }

        const range = Range.get(text_section);
        self.text_offset = text_section.sh_addr;
        self.text_size = range.hi - range.lo;
        self.text_section = shndx_text;

        return text_section;
    }

    /// [agave] https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L990
    fn relocate(
        self: *Elf64,
        allocator: std.mem.Allocator,
        bytes: []u8,
        function_registry: *Registry,
        loader: *const SyscallMap,
        config: Config,
    ) LoadError!void {
        const text_section = self.shdrs[self.text_section.?];
        const text_range = Range.get(text_section);
        const text_bytes = bytes[text_range.lo..text_range.hi];

        const instruction_count = (text_range.hi - text_range.lo) / 8;
        const instructions = std.mem.bytesAsSlice(
            sbpf.Instruction,
            text_bytes[0 .. instruction_count * @sizeOf(sbpf.Instruction)],
        );
        for (instructions, 0..) |inst, i| {
            const immediate: i64 = @as(i32, @bitCast(inst.imm));
            if (inst.opcode == .call_imm and immediate != -1) {
                const target_pc = @as(i64, @intCast(i)) +| immediate +| 1;
                if (target_pc < 0 or target_pc >= instructions.len)
                    return error.RelativeJumpOutOfBounds;

                const key = try function_registry.registerHashedLegacy(
                    allocator,
                    loader,
                    true,
                    &.{},
                    @intCast(target_pc),
                );
                const offset = (i *| 8) +| 4;
                const slice = try safeSlice(text_bytes, offset, 4);
                std.mem.writeInt(u32, slice[0..4], @intCast(key), .little);
            }
        }

        const relocations = std.mem.bytesAsSlice(
            elf.Elf64_Rel,
            bytes[self.dt_rel_off..][0..self.dt_rel_sz],
        );
        for (relocations) |reloc| {
            const r_offset = reloc.r_offset;

            switch (@as(elf.R_X86_64, @enumFromInt(reloc.r_type()))) {
                .@"64" => {
                    const imm_offset = r_offset +| 4;

                    const dynsymtab = self.dynsymtab orelse return error.UnknownSymbol;
                    const sh_dynsym = self.shdrs[dynsymtab];
                    const symbol_table = std.mem.bytesAsSlice(
                        elf.Elf64_Sym,
                        bytes[sh_dynsym.sh_offset..][0..sh_dynsym.sh_size],
                    );

                    const addr_slice = try safeSlice(bytes, imm_offset, 4);
                    const ref_addr = std.mem.readInt(u32, addr_slice[0..4], .little);
                    // Make sure the relocation is referring to a symbol that's in the symbol table.
                    if (reloc.r_sym() >= symbol_table.len) return error.UnknownSymbol;
                    const symbol = symbol_table[reloc.r_sym()];

                    var addr = symbol.st_value +| ref_addr;
                    if (addr < memory.RODATA_START) {
                        addr +|= memory.RODATA_START;
                    }

                    // This is a LDDW instruction, which takes up the space of two regular instructions.
                    // We need to split up the address into two 32-bit chunks, and write to each of the
                    // slot's immediate field.
                    {
                        const imm_low_offset = imm_offset;
                        const imm_slice = try safeSlice(bytes, imm_low_offset, 4);
                        std.mem.writeInt(u32, imm_slice[0..4], @truncate(addr), .little);
                    }
                    {
                        const imm_high_offset = imm_offset +| 8;
                        const imm_slice = try safeSlice(bytes, imm_high_offset, 4);
                        std.mem.writeInt(u32, imm_slice[0..4], @truncate(addr >> 32), .little);
                    }
                },
                .RELATIVE => {
                    const imm_offset = r_offset +| 4;

                    // If the relocation is targetting an address inside of the text section
                    // the target is a LDDW instruction which takes up two instruction slots.
                    if (text_range.contains(r_offset)) {
                        const va_low = val: {
                            const imm_slice = try safeSlice(bytes, imm_offset, 4);
                            break :val std.mem.readInt(u32, imm_slice[0..4], .little);
                        };
                        const va_high = val: {
                            // One instruction slot over.
                            const imm_high_offset = imm_offset +| 8;
                            const imm_slice = try safeSlice(bytes, imm_high_offset, 4);
                            break :val std.mem.readInt(u32, imm_slice[0..4], .little);
                        };

                        // Combine both halfs to get the full 64-bit address.
                        var addr = (@as(u64, va_high) << 32) | va_low;
                        if (addr == 0) return error.InvalidVirtualAddress;
                        if (addr < memory.RODATA_START) {
                            addr +|= memory.RODATA_START;
                        }

                        {
                            const imm_slice = try safeSlice(bytes, imm_offset, 4);
                            std.mem.writeInt(u32, imm_slice[0..4], @truncate(addr), .little);
                        }
                        {
                            const imm_slice = try safeSlice(bytes, r_offset +| 12, 4);
                            std.mem.writeInt(u32, imm_slice[0..4], @intCast(addr >> 32), .little);
                        }
                    } else {
                        const address = address: {
                            const slice = try safeSlice(bytes, imm_offset, 4);
                            break :address std.mem.readInt(u32, slice[0..4], .little);
                        };
                        const slice = try safeSlice(bytes, r_offset, @sizeOf(u64));
                        std.mem.writeInt(u64, slice[0..8], address +| memory.RODATA_START, .little);
                    }
                },
                .@"32" => {
                    // The "32" relocation handles resolving calls to symbols.
                    // Hash the symbol name with Murmur and ammend the instruction's imm field.
                    const imm_offset = r_offset +| 4;

                    const dynsymtab = self.dynsymtab orelse return error.UnknownSymbol;
                    const sh_dynsym = self.shdrs[dynsymtab];
                    const symbol_table = std.mem.bytesAsSlice(
                        elf.Elf64_Sym,
                        bytes[sh_dynsym.sh_offset..][0..sh_dynsym.sh_size],
                    );

                    if (reloc.r_sym() >= symbol_table.len) return error.UnknownSymbol;
                    const symbol = symbol_table[reloc.r_sym()];

                    const dynstrtab = self.dynstr orelse return error.UnknownSymbol;
                    const dynstr = self.shdrs[dynstrtab];
                    const name = getStringInSection(
                        bytes,
                        dynstr,
                        symbol.st_name,
                        SYMBOL_NAME_LENGTH_MAXIMUM,
                    ) catch return error.UnknownSymbol;

                    // If the symbol is defined and a function, this is a BPF-to-BPF call.
                    if (symbol.st_type() == elf.STT_FUNC and symbol.st_value != 0) {
                        if (!text_range.contains(symbol.st_value)) {
                            return error.OutOfBounds;
                        }
                        const target_pc = (symbol.st_value -| text_section.sh_addr) / 8;
                        const key = try function_registry.registerHashedLegacy(
                            allocator,
                            loader,
                            true,
                            name,
                            @intCast(target_pc),
                        );
                        const slice = try safeSlice(bytes, imm_offset, 4);
                        std.mem.writeInt(u32, slice[0..4], @intCast(key), .little);
                    } else {
                        const hash = sbpf.hashSymbolName(name);
                        if (config.reject_broken_elfs and loader.get(hash) == null) {
                            return error.UnresolvedSymbol;
                        }
                        const slice = try safeSlice(bytes, imm_offset, 4);
                        std.mem.writeInt(u32, slice[0..4], hash, .little);
                    }
                },
                else => return error.UnknownRelocation,
            }
        }
    }

    /// [agave] https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/elf.rs#L812
    fn parseRoSections(
        self: *Elf64,
        allocator: std.mem.Allocator,
        config: Config,
    ) !Section {
        // List of allowed section names for storing data.
        const valid_ro_names: []const []const u8 = &.{
            ".text",
            ".rodata",
            ".data.rel.ro",
            ".eh_frame",
        };

        // Lowest virtual address used by a "data section".
        var lowest_addr: usize = std.math.maxInt(usize);
        // Highest virtual address occupied by a "data section".
        // This includes the length of that top section.
        var highest_addr: usize = 0;
        // Total length of data we've found.
        var ro_fill_length: usize = 0;

        const Entry = struct { usize, []const u8 };
        var sfba = std.heap.stackFallback(@sizeOf(Entry) * valid_ro_names.len, allocator);
        const gpa = sfba.get();

        var ro_slices = try std.ArrayListUnmanaged(Entry).initCapacity(gpa, self.shdrs.len);
        defer ro_slices.deinit(gpa);

        var invalid_offsets: bool = false;

        // Index of the first read-only section in the section header list.
        var first_ro_section: usize = 0;
        // Index of the last read-only section in the section header list.
        var last_ro_section: usize = 0;
        // Number of read-only sections in the ELF.
        var ro_sections: usize = 0;

        const section_names_shdr_idx = self.header.e_shstrndx;
        const section_names_shdr = self.shdrs[section_names_shdr_idx];

        for (self.shdrs, 0..) |shdr, i| {
            const name = getStringInSection(
                self.bytes,
                section_names_shdr,
                shdr.sh_name,
                SECTION_NAME_LENGTH_MAXIMUM,
            ) catch continue;

            for (valid_ro_names) |ro_name| {
                if (std.mem.eql(u8, ro_name, name)) break;
            } else continue;

            if (ro_sections == 0) first_ro_section = i;
            last_ro_section = i;
            ro_sections +|= 1;

            // Determine whether the section header has invalid offset metadata.
            // [agave] https://github.com/anza-xyz/sbpf/blob/v0.13.0/src/elf.rs#L796
            if (!invalid_offsets and shdr.sh_addr != shdr.sh_offset) {
                invalid_offsets = true;
            }
            const vaddr_end = shdr.sh_addr +| memory.RODATA_START;
            // [agave] https://github.com/anza-xyz/sbpf/blob/v0.13.0/src/elf.rs#L801
            if ((config.reject_broken_elfs and invalid_offsets) or vaddr_end > memory.STACK_START) {
                return error.OutOfBounds;
            }

            const section_range = Range.get(shdr);
            const section_size = section_range.hi - section_range.lo;
            const section_data = try safeSlice(self.bytes, section_range.lo, section_size);

            lowest_addr = @min(lowest_addr, shdr.sh_addr);
            highest_addr = @max(highest_addr, shdr.sh_addr +| section_data.len);
            ro_fill_length +|= section_data.len;

            ro_slices.appendAssumeCapacity(.{ shdr.sh_addr, section_data });
        }

        if (config.reject_broken_elfs and lowest_addr +| ro_fill_length > highest_addr) {
            return error.OutOfBounds;
        }

        const can_borrow = !invalid_offsets and
            last_ro_section +| 1 -| first_ro_section == ro_sections;
        const ro_section: Section = if (config.optimize_rodata and can_borrow) ro: {
            const addr_offset = if (lowest_addr >= memory.RODATA_START)
                lowest_addr
            else
                lowest_addr +| memory.RODATA_START;

            break :ro .{ .borrowed = .{
                .offset = addr_offset,
                .start = lowest_addr,
                .end = highest_addr,
            } };
        } else ro: {
            if (config.optimize_rodata) {
                highest_addr -|= lowest_addr;
            } else {
                lowest_addr = 0;
            }

            if (highest_addr > self.bytes.len) {
                return error.OutOfBounds;
            }

            // Concat all of the gathered read-only sections into one contiguous slice.
            const ro_section = try allocator.alignedAlloc(u8, .fromByteUnits(16), highest_addr);
            @memset(ro_section, 0);
            for (ro_slices.items) |ro_slice| {
                const section_addr, const slice = ro_slice;
                const buf_offset_start = section_addr -| lowest_addr;
                @memcpy(ro_section[buf_offset_start..][0..slice.len], slice);
            }
            const addr_offset = if (lowest_addr >= memory.RODATA_START)
                lowest_addr
            else
                lowest_addr +| memory.RODATA_START;
            break :ro .{ .owned = .{ .offset = addr_offset, .data = ro_section } };
        };

        return ro_section;
    }

    /// [agave] https://github.com/anza-xyz/sbpf/blob/v0.13.0/src/elf_parser/mod.rs#L468
    fn getStringInSection(
        bytes: []const u8,
        section_header: elf.Elf64_Shdr,
        offset_in_section: elf.Word,
        maximum_length: u32,
    ) ![:0]const u8 {
        if (section_header.sh_type != elf.SHT_STRTAB) {
            return error.InvalidSectionHeader;
        }
        const offset_in_file = try add(u64, section_header.sh_offset, offset_in_section);
        const string_range_start = offset_in_file;
        const string_range_end = @min(
            section_header.sh_offset + section_header.sh_size,
            offset_in_file + maximum_length,
        );

        if (string_range_end > bytes.len) return error.OutOfBounds;
        if (string_range_end < string_range_start) return error.OutOfBounds;

        const index = std.mem.indexOfScalar(
            u8,
            bytes[string_range_start..string_range_end],
            0,
        ) orelse return error.StringTooLong;
        return @ptrCast(bytes[string_range_start..][0..index]);
    }
};

fn safeSlice(base: anytype, start: u64, len: u64) error{OutOfBounds}!@TypeOf(base) {
    if (start >= base.len) return error.OutOfBounds;
    const end = add(u64, start, len) catch return error.OutOfBounds;
    if (end > base.len) return error.OutOfBounds;
    return base[start..][0..len];
}

// checked math helpers, but with an error code that matches labs

/// Returns the product of a and b. Returns an error on overflow.
pub fn mul(comptime T: type, a: T, b: T) (error{OutOfBounds}!T) {
    if (T == comptime_int) return a * b;
    const ov = @mulWithOverflow(a, b);
    if (ov[1] != 0) return error.OutOfBounds;
    return ov[0];
}

/// Returns the sum of a and b. Returns an error on overflow.
pub fn add(comptime T: type, a: T, b: T) (error{OutOfBounds}!T) {
    if (T == comptime_int) return a + b;
    const ov = @addWithOverflow(a, b);
    if (ov[1] != 0) return error.OutOfBounds;
    return ov[0];
}

/// Returns a - b, or an error on overflow.
pub fn sub(comptime T: type, a: T, b: T) (error{OutOfBounds}!T) {
    if (T == comptime_int) return a - b;
    const ov = @subWithOverflow(a, b);
    if (ov[1] != 0) return error.OutOfBounds;
    return ov[0];
}

test "parsing failing allocation" {
    const S = struct {
        fn foo(allocator: std.mem.Allocator) !void {
            const input_file = try std.fs.cwd().openFile(sig.ELF_DATA_DIR ++ "reloc_64_64.so", .{});
            const bytes = try input_file.readToEndAlloc(allocator, sbpf.MAX_FILE_SIZE);
            defer allocator.free(bytes);

            var parsed = try load(allocator, bytes, &.ALL_DISABLED, .{});
            defer parsed.deinit(allocator);
        }
    };

    const allocator = std.testing.allocator;
    try std.testing.checkAllAllocationFailures(allocator, S.foo, .{});
}

test "elf load" {
    const allocator = std.testing.allocator;
    const input_file = try std.fs.cwd().openFile(
        sig.ELF_DATA_DIR ++ "relative_call_sbpfv0.so",
        .{},
    );
    const bytes = try input_file.readToEndAlloc(allocator, sbpf.MAX_FILE_SIZE);
    defer allocator.free(bytes);

    var loader: SyscallMap = .ALL_DISABLED;
    var parsed = try load(allocator, bytes, &loader, .{});
    defer parsed.deinit(allocator);
}

fn newSection(
    sh_addr: elf.Elf64_Addr,
    sh_size: elf.Elf64_Xword,
    sh_name: elf.Word,
) elf.Elf64_Shdr {
    return .{
        .sh_name = sh_name,
        .sh_addr = sh_addr,
        .sh_size = sh_size,
        .sh_offset = std.math.sub(
            u64,
            sh_addr,
            memory.RODATA_START,
        ) catch sh_addr,
        .sh_flags = 0,
        .sh_link = 0,
        .sh_info = 0,
        .sh_addralign = 0,
        .sh_entsize = 0,
        .sh_type = 0,
    };
}

test "SHT_DYNAMIC fallback" {
    const allocator = std.testing.allocator;
    const input_file = try std.fs.cwd().openFile(
        sig.ELF_DATA_DIR ++ "struct_func_pointer_sbpfv0.so",
        .{},
    );
    const bytes = try input_file.readToEndAlloc(allocator, sbpf.MAX_FILE_SIZE);
    defer allocator.free(bytes);

    // we set the p_type of the PT_DYNAMIC header to PT_NULL, in order for the
    // parsing to skip past it and fallback to the SHT_DYNAMIC section. For this
    // specific input, the p_type is 232 bytes from the start.
    @as(*align(1) u32, @ptrCast(bytes[232..][0..4])).* = elf.PT_NULL;

    var loader: SyscallMap = .ALL_DISABLED;
    var parsed = try load(
        allocator,
        bytes,
        &loader,
        .{ .maximum_version = .v0 },
    );
    defer parsed.deinit(allocator);
}

test "add all symbols during relocate" {
    const allocator = std.testing.allocator;
    const input_file = try std.fs.cwd().openFile(
        sig.ELF_DATA_DIR ++ "hello_world.so",
        .{},
    );
    const bytes = try input_file.readToEndAlloc(allocator, sbpf.MAX_FILE_SIZE);
    defer allocator.free(bytes);

    var loader: SyscallMap = .ALL_DISABLED;
    var parsed = try load(allocator, bytes, &loader, .{ .maximum_version = .v0 });
    defer parsed.deinit(allocator);
}
