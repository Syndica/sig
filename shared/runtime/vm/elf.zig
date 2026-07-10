//! Elf Spec: http://refspecs.linux-foundation.org/LSB_4.1.0/LSB-Core-generic/LSB-Core-generic.html

const std = @import("std");
const sig = @import("shared");
const runtime = @import("../lib.zig");
const sbpf = @import("sbpf.zig");
const memory = @import("memory.zig");

const lib = @import("lib.zig");
const Config = lib.Config;
const Registry = lib.Registry;
const Section = lib.Section;
const SyscallMap = runtime.vm.SyscallMap;
const Executable = lib.Executable;

const elf = std.elf;

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
    const sbpf_version: sbpf.Version = switch (std.mem.readInt(u32, bytes[48..][0..4], .little)) {
        0 => .v0,
        1 => .v1,
        2 => .v2,
        3 => .v3,
        else => .reserved,
    };

    // Ensure that the sbpf version we find is within the range that's enabled.
    if (@intFromEnum(sbpf_version) < @intFromEnum(config.minimum_version) or
        @intFromEnum(sbpf_version) > @intFromEnum(config.maximum_version))
        return error.UnsupportedSBPFVersion;

    return if (sbpf_version.enableStricterElfHeaders())
        try parseStrict(allocator, bytes, sbpf_version, config)
    else
        try parseLenient(allocator, bytes, config, loader, sbpf_version);
}

/// Load an ELF file for SBPF v3 and later.
///
/// [sbpf] https://github.com/anza-xyz/sbpf/blob/v0.20.0/src/elf.rs#L467
fn parseStrict(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    sbpf_version: sbpf.Version,
    config: Config,
) LoadError!Executable {
    // [sbpf] https://github.com/anza-xyz/sbpf/blob/v0.20.0/src/elf.rs#L479
    if (bytes.len < @sizeOf(elf.Elf64_Ehdr)) return error.OutOfBounds;
    const header: elf.Elf64_Ehdr = @bitCast(bytes[0..@sizeOf(elf.Elf64_Ehdr)].*);

    // [sbpf] https://github.com/anza-xyz/sbpf/blob/v0.20.0/src/elf.rs#L480-507
    const ident: ElfIdent = @bitCast(header.e_ident);
    const phdr_table_end = (@sizeOf(elf.Elf64_Phdr) *|
        @as(u64, header.e_phnum)) +|
        @sizeOf(elf.Elf64_Ehdr);
    if (!std.mem.eql(u8, ident.magic[0..4], elf.MAGIC) or
        ident.class != elf.ELFCLASS64 or
        ident.data != elf.ELFDATA2LSB or
        ident.version != 1 or
        ident.osabi != elf.OSABI.NONE or
        ident.abiversion != 0x00 or
        !std.mem.allEqual(u8, &ident.padding, 0) or
        @intFromEnum(header.e_machine) != @intFromEnum(elf.EM.BPF) or
        header.e_version != 1 or
        header.e_phoff != @sizeOf(elf.Elf64_Ehdr) or
        header.e_ehsize != @sizeOf(elf.Elf64_Ehdr) or
        header.e_phentsize != @sizeOf(elf.Elf64_Phdr) or
        header.e_phnum == 0 or
        phdr_table_end > bytes.len)
    {
        return error.InvalidFileHeader;
    }

    // [sbpf] https://github.com/anza-xyz/sbpf/blob/v0.20.0/src/elf.rs#L509-L524
    const phdrs = std.mem.bytesAsSlice(
        elf.Elf64_Phdr,
        bytes[@sizeOf(elf.Elf64_Ehdr)..phdr_table_end],
    );
    const skip_rodata = phdrs[0].p_flags != elf.PF_R;
    const expected: []const struct { u32, u64 } = if (skip_rodata)
        &.{.{ elf.PF_X, memory.BYTECODE_START }}
    else if (header.e_phnum >= 2)
        &.{ .{ elf.PF_R, memory.RODATA_START }, .{ elf.PF_X, memory.BYTECODE_START } }
    else
        return error.InvalidFileHeader;

    // [sbpf] https://github.com/anza-xyz/sbpf/blob/v0.20.0/src/elf.rs#L525-L545
    var expected_offset: u64 = phdr_table_end;
    for (expected, phdrs[0..expected.len]) |entry, phdr| {
        const p_flags, const p_vaddr = entry;
        if (phdr.p_type != elf.PT_LOAD or
            phdr.p_flags != p_flags or
            phdr.p_offset != expected_offset or
            phdr.p_offset >= bytes.len or
            phdr.p_offset % 8 != 0 or
            phdr.p_vaddr != p_vaddr or
            phdr.p_paddr != p_vaddr or
            phdr.p_filesz != phdr.p_memsz or
            phdr.p_filesz > bytes.len -| phdr.p_offset or
            phdr.p_filesz % 8 != 0 or
            phdr.p_memsz >= memory.BYTECODE_START // larger than one region
        ) {
            return error.InvalidProgramHeader;
        }
        expected_offset = expected_offset +| phdr.p_filesz;
    }

    // [sbpf] https://github.com/anza-xyz/sbpf/blob/v0.20.0/src/elf.rs#L547-L558
    const ro_section_start, const ro_section_end = if (skip_rodata)
        .{ phdr_table_end, phdr_table_end }
    else if (phdrs[0].p_type == elf.PT_LOAD)
        .{ phdrs[0].p_offset, phdrs[0].p_offset +| phdrs[0].p_filesz }
    else // Match unwrap_or_default on Elf64Phdr::file_range()
        .{ 0, 0 };
    const ro_section: Section = .{ .borrowed = .{
        .offset = memory.RODATA_START,
        .start = ro_section_start,
        .end = ro_section_end,
    } };

    // [sbpf] https://github.com/anza-xyz/sbpf/blob/v0.20.0/src/elf.rs#L562-L571
    const bytecode_header = phdrs[expected.len - 1];
    const vm_range_start = bytecode_header.p_vaddr;
    const vm_range_end = bytecode_header.p_vaddr +| bytecode_header.p_memsz;
    const entry_chk = header.e_entry +| 7;
    if (entry_chk < vm_range_start or
        entry_chk >= vm_range_end or
        header.e_entry % 8 != 0)
    {
        return error.InvalidFileHeader;
    }
    const entry_pc = (header.e_entry -| bytecode_header.p_vaddr) / 8;

    // [sbpf] https://github.com/anza-xyz/sbpf/blob/v0.20.0/src/elf.rs#L577
    var function_registry: Registry = .{};
    errdefer function_registry.deinit(allocator);

    // NOTE: Sig does not support `enable_symbol_and_section_labels` which
    // requires additional parsing and validation here.
    // [sbpf] https://github.com/anza-xyz/sbpf/blob/v0.20.0/src/elf.rs#L578-L637

    return .{
        .bytes = bytes,
        .version = sbpf_version,
        .entry_pc = entry_pc,
        .from_asm = false,
        .ro_section = ro_section,
        .text_vaddr = vm_range_start,
        .config = config,
        .function_registry = function_registry,
        .text_section_len = bytecode_header.p_filesz,
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

/// Load an ELF file for SBPF v0, v1, and v2.
///
/// [sbpf] https://github.com/anza-xyz/sbpf/blob/v0.20.0/src/elf.rs#L654
fn parseLenient(
    allocator: std.mem.Allocator,
    bytes: []u8,
    config: Config,
    loader: *const SyscallMap,
    version: sbpf.Version,
) !Executable {
    // `relocate` reads ELF metadata (reloc table, dynsym, dynstr) from
    // `Elf64.bytes` while writing relocated values back into `bytes`. The
    // parser must see the original, pre-relocation bytes; otherwise an
    // earlier write landing in `.rel.dyn`/`.dynsym`/`.dynstr` could corrupt
    // later reads.
    // [sbpf] https://github.com/anza-xyz/sbpf/blob/v0.20.0/src/elf.rs#L660
    const unrelocated_bytes = try allocator.dupe(u8, bytes);
    defer allocator.free(unrelocated_bytes);

    // [sbpf] https://github.com/anza-xyz/sbpf/blob/v0.20.0/src/elf.rs#L667
    var elf_parsed = try Elf64.parse(unrelocated_bytes);

    // [sbpf] https://github.com/anza-xyz/sbpf/blob/v0.20.0/src/elf.rs#L672-681
    const text_shdr = try elf_parsed.validate();
    const text_section_vaddr = text_shdr.sh_addr +| memory.REGION_SIZE;
    if ((config.reject_broken_elfs and text_shdr.sh_addr != text_shdr.sh_offset) or
        text_section_vaddr > memory.STACK_START)
    {
        return error.OutOfBounds;
    }

    // [sbpf] https://github.com/anza-xyz/sbpf/blob/v0.20.0/src/elf.rs#L684-L690
    var function_registry: Registry = .{};
    errdefer function_registry.deinit(allocator);
    try elf_parsed.relocate(allocator, bytes, &function_registry, loader, config);

    // [sbpf] https://github.com/anza-xyz/sbpf/blob/v0.20.0/src/elf.rs#L697-L708
    const offset = elf_parsed.header.e_entry -| text_shdr.sh_addr;
    if (offset % 8 != 0) {
        return error.InvalidEntrypoint;
    }
    const entry_pc = offset / 8;
    _ = function_registry.map.swapRemove(sbpf.hashSymbolName("entrypoint"));
    _ = try function_registry.registerHashedLegacy(
        allocator,
        loader,
        true,
        "entrypoint",
        entry_pc,
    );

    // [sbpf] https://github.com/anza-xyz/sbpf/blob/v0.20.0/src/elf.rs#L710-730
    const ro_section = try elf_parsed.parseRoSections(allocator, &config, bytes);
    errdefer ro_section.deinit(allocator);

    // Extract instructions from the text section.
    //
    // When `parseRoSections` returns `Section.owned`, the merged read-only
    // buffer may overlay other sections on top of `.text` (e.g. a fuzz-crafted
    // ELF can declare an `SHT_DYNAMIC` section named `.rodata` whose `sh_addr`
    // lands inside the `.text` range). To stay byte-identical with sbpf's
    // `Executable::get_text_bytes`, which reads the text section from the
    // owned buffer (not `elf_bytes`) so it stays consistent with the
    // ro_section when sections overlap, we must do the same here.
    //
    // The patched `get_text_bytes` lives on firedancer-io's
    // `sbpf-v0.20.0-patches` branch (used by the conformance harness via
    // solfuzz-agave's Cargo.lock) and has since been upstreamed to
    // anza-xyz/sbpf `main` (post v0.20.0).
    //
    // [sbpf] https://github.com/firedancer-io/sbpf/blob/6cd6372eb4ee631f792642f97fe825bc269aaf58/src/elf.rs#L307-L321
    const text_range = Elf64.Range.get(text_shdr);
    const text_len = text_range.hi - text_range.lo;
    const text_bytes = switch (ro_section) {
        .owned => |o| blk: {
            // `o.offset` is the vaddr where `o.data[0]` is mapped.
            // `text_section_vaddr` is `text_shdr.sh_addr + REGION_SIZE`.
            // So the index into `o.data` of the first text byte is
            // `text_section_vaddr - o.offset` (matches sbpf).
            const text_offset_in_owned = text_section_vaddr -| o.offset;
            if (text_offset_in_owned +| text_len > o.data.len) {
                return error.OutOfBounds;
            }
            break :blk o.data[text_offset_in_owned..][0..text_len];
        },
        .borrowed => bytes[text_range.lo..text_range.hi],
    };
    const instruction_count = text_len / 8;
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
        .text_section_len = text_range.hi - text_range.lo,
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

/// [sbpf] https://github.com/anza-xyz/sbpf/blob/58c47586d70b3d2f1da6c4ff25dd0a3f53a979b6/src/elf_parser/mod.rs#L132
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
    /// [sbpf] https://github.com/anza-xyz/sbpf/blob/58c47586d70b3d2f1da6c4ff25dd0a3f53a979b6/src/elf_parser/mod.rs#L87-L94
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

    /// [sbpf] https://github.com/anza-xyz/sbpf/blob/58c47586d70b3d2f1da6c4ff25dd0a3f53a979b6/src/elf_parser/mod.rs#L120-L130
    fn checkOverlap(a_start: usize, a_end: usize, b_start: usize, b_end: usize) !void {
        if (a_end <= b_start or b_end <= a_start) return;
        return error.Overlap;
    }

    /// [sbpf] https://github.com/anza-xyz/sbpf/blob/58c47586d70b3d2f1da6c4ff25dd0a3f53a979b6/src/elf_parser/mod.rs#L148-L149
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
            header.e_version != 1 or
            header.e_ehsize != @sizeOf(elf.Elf64_Ehdr) or
            header.e_phentsize != @sizeOf(elf.Elf64_Phdr) or
            header.e_shentsize != @sizeOf(elf.Elf64_Shdr) or
            header.e_shstrndx >= header.e_shnum)
        {
            return error.InvalidFileHeader;
        }

        // Elf64::parse_program_header_table
        // [sbpf] https://github.com/anza-xyz/sbpf/blob/58c47586d70b3d2f1da6c4ff25dd0a3f53a979b6/src/elf_parser/mod.rs#L164-L166
        const phdr_start = header.e_phoff;
        const phdr_size = try mul(u64, header.e_phnum, @sizeOf(elf.Elf64_Phdr));
        const phdr_end = try add(u64, header.e_phoff, phdr_size);
        try checkOverlap(ehdr_start, ehdr_end, phdr_start, phdr_end);
        if (phdr_size % @sizeOf(elf.Elf64_Phdr) != 0) return error.InvalidSize;
        const phdrs = std.mem.bytesAsSlice(
            elf.Elf64_Phdr,
            try safeSlice(bytes, phdr_start, phdr_size),
        );
        if (!std.mem.isAligned(phdr_start, 8)) return error.InvalidAlignment;

        // Elf64::parse_section_header_table
        // [sbpf] https://github.com/anza-xyz/sbpf/blob/58c47586d70b3d2f1da6c4ff25dd0a3f53a979b6/src/elf_parser/mod.rs#L167-L168
        const shdr_start = header.e_shoff;
        const shdr_size = try mul(u64, header.e_shnum, @sizeOf(elf.Elf64_Shdr));
        const shdr_end = try add(u64, header.e_shoff, shdr_size);
        try checkOverlap(ehdr_start, ehdr_end, shdr_start, shdr_end);
        try checkOverlap(phdr_start, phdr_end, shdr_start, shdr_end);
        // Guaranteed to not overflow, as shdr_end is at least as large as e_shoff.
        if ((shdr_end - header.e_shoff) % @sizeOf(elf.Elf64_Shdr) != 0) return error.InvalidSize;
        const shdrs = std.mem.bytesAsSlice(
            elf.Elf64_Shdr,
            try safeSlice(bytes, shdr_start, shdr_size),
        );
        if (!std.mem.isAligned(header.e_shoff, 8)) return error.InvalidAlignment;

        // [sbpf] https://github.com/anza-xyz/sbpf/blob/58c47586d70b3d2f1da6c4ff25dd0a3f53a979b6/src/elf_parser/mod.rs#L174-L175
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

        // [sbpf] https://github.com/anza-xyz/sbpf/blob/58c47586d70b3d2f1da6c4ff25dd0a3f53a979b6/src/elf_parser/mod.rs#L179-L197
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

        // [sbpf] https://github.com/anza-xyz/sbpf/blob/58c47586d70b3d2f1da6c4ff25dd0a3f53a979b6/src/elf_parser/mod.rs#L198-L217
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

                try checkOverlap(sh_start, sh_end, ehdr_start, ehdr_end);
                try checkOverlap(sh_start, sh_end, phdr_start, phdr_end);
                try checkOverlap(sh_start, sh_end, shdr_start, shdr_end);

                if (sh_start < offset) return error.SectionNotInOrder;
                offset = sh_end;
                if (sh_end > bytes.len) return error.OutOfBounds;
            }
        }

        // Parse sections
        // [sbpf] https://github.com/anza-xyz/sbpf/blob/58c47586d70b3d2f1da6c4ff25dd0a3f53a979b6/src/elf_parser/mod.rs#L240-L241
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
        // [sbpf] https://github.com/anza-xyz/sbpf/blob/58c47586d70b3d2f1da6c4ff25dd0a3f53a979b6/src/elf_parser/mod.rs#L241
        {
            var dynamic_table_start: ?u64 = null;
            var dynamic_table_end: ?u64 = null;

            // [sbpf] https://github.com/anza-xyz/sbpf/blob/58c47586d70b3d2f1da6c4ff25dd0a3f53a979b6/src/elf_parser/mod.rs#L365-L372
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
            // [sbpf] https://github.com/anza-xyz/sbpf/blob/58c47586d70b3d2f1da6c4ff25dd0a3f53a979b6/src/elf_parser/mod.rs#L409-L410
            relocs: {
                const vaddr = dynamic_table[elf.DT_REL];
                if (vaddr == 0) break :relocs;

                if (dynamic_table[elf.DT_RELENT] != @sizeOf(elf.Elf64_Rel)) {
                    return error.InvalidDynamicSectionTable;
                }

                const size = dynamic_table[elf.DT_RELSZ];
                if (size == 0) return error.InvalidDynamicSectionTable;

                // program_header_for_vaddr
                // [sbpf] https://github.com/anza-xyz/sbpf/blob/58c47586d70b3d2f1da6c4ff25dd0a3f53a979b6/src/elf_parser/mod.rs#L430-L445
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

            // [sbpf] https://github.com/anza-xyz/sbpf/blob/58c47586d70b3d2f1da6c4ff25dd0a3f53a979b6/src/elf_parser/mod.rs#L410
            dynsym: {
                // [sbpf] https://github.com/anza-xyz/sbpf/blob/58c47586d70b3d2f1da6c4ff25dd0a3f53a979b6/src/elf_parser/mod.rs#L452-L456
                const vaddr = dynamic_table[elf.DT_SYMTAB];
                if (vaddr == 0) break :dynsym;

                // [sbpf] https://github.com/anza-xyz/sbpf/blob/58c47586d70b3d2f1da6c4ff25dd0a3f53a979b6/src/elf_parser/mod.rs#L457-L462
                const shdr_sym: elf.Elf64_Shdr = for (self.shdrs, 0..) |shdr, i| {
                    if (shdr.sh_addr == vaddr) {
                        self.dynsymtab = i;
                        break shdr;
                    }
                } else return error.InvalidDynamicSectionTable;

                // [sbpf] https://github.com/anza-xyz/sbpf/blob/58c47586d70b3d2f1da6c4ff25dd0a3f53a979b6/src/elf_parser/mod.rs#L463-L465
                {
                    if (shdr_sym.sh_type != elf.SHT_SYMTAB and shdr_sym.sh_type != elf.SHT_DYNSYM) {
                        return error.InvalidSectionHeader;
                    }

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
        var writable_err = false;
        var oob_err = false;
        for (self.shdrs, 0..) |shdr, i| {
            // This can't actually fail, as we've already iterated through the names of sections in `parse`.
            const name = try getStringInSection(
                self.bytes,
                section_names_shdr,
                shdr.sh_name,
                SECTION_NAME_LENGTH_MAXIMUM,
            );

            // [sbpf] https://github.com/anza-xyz/sbpf/blob/58c47586d70b3d2f1da6c4ff25dd0a3f53a979b6/src/elf.rs#L793-L803
            if (std.mem.eql(u8, name, ".text")) {
                if (shndx_text == null) {
                    text_section = shdr;
                    shndx_text = i;
                } else return error.NotOneTextSection;
            }

            // [sbpf] https://github.com/anza-xyz/sbpf/blob/58c47586d70b3d2f1da6c4ff25dd0a3f53a979b6/src/elf.rs#L808-L820
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

            // [sbpf] https://github.com/anza-xyz/sbpf/blob/58c47586d70b3d2f1da6c4ff25dd0a3f53a979b6/src/elf.rs#L821-L831
            const shdr_end = add(u64, shdr.sh_offset, shdr.sh_size);
            if (shdr_end) |end| {
                if (end > self.bytes.len) oob_err = true;
            } else |_| {
                oob_err = true;
            }
        }
        // [sbpf] https://github.com/anza-xyz/sbpf/blob/58c47586d70b3d2f1da6c4ff25dd0a3f53a979b6/src/elf.rs#L803-L806
        if (shndx_text == null) return error.NotOneTextSection;
        if (writable_err) return error.WritableSectionNotSupported;
        if (oob_err) return error.OutOfBounds;

        // [sbpf] https://github.com/anza-xyz/sbpf/blob/58c47586d70b3d2f1da6c4ff25dd0a3f53a979b6/src/elf.rs#L831-L835
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

    /// Perform relocations on the ELF file provided in `bytes`.
    /// The provided `bytes` must match be a mutable copy of the original bytes used to construct `self`.
    /// [sbpf] https://github.com/anza-xyz/sbpf/blob/58c47586d70b3d2f1da6c4ff25dd0a3f53a979b6/src/elf.rs#L966-L967
    fn relocate(
        self: *const Elf64,
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
            self.bytes[self.dt_rel_off..][0..self.dt_rel_sz],
        );
        for (relocations) |reloc| {
            const r_offset = reloc.r_offset;

            switch (@as(elf.R_X86_64, @enumFromInt(reloc.r_type()))) {
                .@"64" => {
                    const imm_offset = r_offset +| 4;

                    const addr_slice = try safeSlice(bytes, imm_offset, 4);
                    const ref_addr = std.mem.readInt(u32, addr_slice[0..4], .little);

                    const dynsymtab = self.dynsymtab orelse return error.UnknownSymbol;
                    const sh_dynsym = self.shdrs[dynsymtab];
                    const symbol_table = std.mem.bytesAsSlice(
                        elf.Elf64_Sym,
                        try safeSlice(self.bytes, sh_dynsym.sh_offset, sh_dynsym.sh_size),
                    );
                    if (reloc.r_sym() >= symbol_table.len) return error.UnknownSymbol;
                    const symbol = symbol_table[reloc.r_sym()];

                    var addr = symbol.st_value +| ref_addr;
                    if (addr < memory.REGION_SIZE) {
                        addr +|= memory.REGION_SIZE;
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
                        if (addr < memory.REGION_SIZE) {
                            addr +|= memory.REGION_SIZE;
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
                        const addr_imm_slice = try safeSlice(bytes, imm_offset, 4);
                        const addr: u64 = std.mem.readInt(
                            u32,
                            addr_imm_slice[0..4],
                            .little,
                        ) +| memory.REGION_SIZE;
                        const add_r_slice = try safeSlice(bytes, r_offset, @sizeOf(u64));
                        std.mem.writeInt(
                            u64,
                            add_r_slice[0..8],
                            addr,
                            .little,
                        );
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
                        try safeSlice(self.bytes, sh_dynsym.sh_offset, sh_dynsym.sh_size),
                    );
                    if (reloc.r_sym() >= symbol_table.len) return error.UnknownSymbol;
                    const symbol = symbol_table[reloc.r_sym()];

                    const dynstrtab = self.dynstr orelse return error.UnknownSymbol;
                    const dynstr = self.shdrs[dynstrtab];
                    const name = getStringInSection(
                        self.bytes,
                        dynstr,
                        symbol.st_name,
                        SYMBOL_NAME_LENGTH_MAXIMUM,
                    ) catch return error.UnknownSymbol;

                    // If the symbol is defined and a function, this is a BPF-to-BPF call.
                    if (symbol.st_type() == elf.STT_FUNC and symbol.st_value != 0) {
                        const text_vm_lo = text_section.sh_addr;
                        const text_vm_hi = text_section.sh_addr +| text_section.sh_size;
                        if (symbol.st_value < text_vm_lo or symbol.st_value >= text_vm_hi) {
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

    /// [sbpf] https://github.com/anza-xyz/sbpf/blob/58c47586d70b3d2f1da6c4ff25dd0a3f53a979b6/src/elf.rs#L840
    fn parseRoSections(
        self: *Elf64,
        allocator: std.mem.Allocator,
        config: *const Config,
        elf_bytes: []const u8,
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
            // [sbpf] https://github.com/anza-xyz/sbpf/blob/58c47586d70b3d2f1da6c4ff25dd0a3f53a979b6/src/elf.rs#L880-L883
            if (!invalid_offsets and shdr.sh_addr != shdr.sh_offset) {
                invalid_offsets = true;
            }

            // [sbpf] https://github.com/anza-xyz/sbpf/blob/58c47586d70b3d2f1da6c4ff25dd0a3f53a979b6/src/elf.rs#L884-L888
            const vaddr_end = shdr.sh_addr +| memory.BYTECODE_START;
            if ((config.reject_broken_elfs and invalid_offsets) or vaddr_end > memory.STACK_START) {
                return error.OutOfBounds;
            }

            const section_range = Range.get(shdr);
            const section_size = section_range.hi - section_range.lo;
            const section_data = try safeSlice(elf_bytes, section_range.lo, section_size);

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
            const addr_offset = if (lowest_addr >= memory.BYTECODE_START)
                lowest_addr
            else
                lowest_addr +| memory.BYTECODE_START;

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

            if (highest_addr > elf_bytes.len) {
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
            const addr_offset = if (lowest_addr >= memory.BYTECODE_START)
                lowest_addr
            else
                lowest_addr +| memory.BYTECODE_START;
            break :ro .{ .owned = .{ .offset = addr_offset, .data = ro_section } };
        };

        return ro_section;
    }

    /// [sbpf] https://github.com/anza-xyz/sbpf/blob/58c47586d70b3d2f1da6c4ff25dd0a3f53a979b6/src/elf_parser/mod.rs#L468
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
    if (start > base.len) return error.OutOfBounds;
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

test "lenient parse rejects nonstandard e_version" {
    const allocator = std.testing.allocator;
    const input_file = try std.fs.cwd().openFile(
        sig.ELF_DATA_DIR ++ "relative_call_sbpfv0.so",
        .{},
    );
    defer input_file.close();
    const bytes = try input_file.readToEndAlloc(allocator, sbpf.MAX_FILE_SIZE);
    defer allocator.free(bytes);

    // e_version is a u32 at offset 20 in Elf64_Ehdr. Agave's lenient parser
    // rejects e_version != EV_CURRENT (1); previously sig's only checked
    // e_ident.ei_version and silently accepted malformed values here.
    @as(*align(1) u32, @ptrCast(bytes[20..][0..4])).* = 0x00010001;

    var loader: SyscallMap = .ALL_DISABLED;
    try std.testing.expectError(
        error.InvalidFileHeader,
        load(allocator, bytes, &loader, .{ .maximum_version = .v0 }),
    );
}
