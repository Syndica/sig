//! Represents a parsed ELF file.
//!
//! Elf Spec: http://refspecs.linux-foundation.org/LSB_4.1.0/LSB-Core-generic/LSB-Core-generic.html

const std = @import("std");
const sbpf = @import("sbpf.zig");
const memory = @import("memory.zig");

const lib = @import("lib.zig");
const BuiltinProgram = lib.BuiltinProgram;
const Config = lib.Config;
const Executable = lib.Executable;
const Registry = lib.Registry;

const elf = std.elf;
const assert = std.debug.assert;

pub const Elf = struct {
    bytes: []u8,
    headers: Headers,
    data: Data,
    entry_pc: u64,
    version: sbpf.Version,
    function_registry: Registry(u64),
    ro_section: Executable.Section,
    config: Config,

    /// Contains immutable headers parsed from the ELF file.
    const Headers = struct {
        bytes: []const u8,
        header: elf.Elf64_Ehdr,
        // The following fields are align(1) because there's no guarantee of alignment inside of the ELF sections.
        shdrs: []align(1) const elf.Elf64_Shdr,
        phdrs: []align(1) const elf.Elf64_Phdr,

        fn parse(bytes: []const u8) !Headers {
            const header: elf.Elf64_Ehdr = @bitCast(bytes[0..@sizeOf(elf.Elf64_Ehdr)].*);

            const shoff = header.e_shoff;
            const shnum = header.e_shnum;
            const shsize = shnum * @sizeOf(elf.Elf64_Shdr);
            const shdrs = std.mem.bytesAsSlice(
                elf.Elf64_Shdr,
                try safeSlice(bytes, shoff, shsize),
            );

            const phoff = header.e_phoff;
            const phnum = header.e_phnum;
            const phsize = phnum * @sizeOf(elf.Elf64_Phdr);
            const phdrs = std.mem.bytesAsSlice(
                elf.Elf64_Phdr,
                try safeSlice(bytes, phoff, phsize),
            );

            return .{
                .bytes = bytes,
                .header = header,
                .shdrs = shdrs,
                .phdrs = phdrs,
            };
        }

        fn shdrSlice(self: Headers, index: u32) ![]const u8 {
            const shdr = self.shdrs[index];
            const sh_offset = shdr.sh_offset;
            const sh_size = shdr.sh_size;
            return try safeSlice(self.bytes, sh_offset, sh_size);
        }

        fn phdrSlice(self: Headers, index: u32) ![]const u8 {
            const phdr = self.phdrs[index];
            const p_offset = phdr.p_offset;
            const p_filesz = phdr.p_filesz;
            return try safeSlice(self.bytes, p_offset, p_filesz);
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
            const strtab = try headers.shdrSlice(headers.header.e_shstrndx);

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

            const dynamic_table = if (headers.getPhdrIndexByType(elf.PT_DYNAMIC)) |index| dt: {
                const slice = try headers.phdrSlice(index);
                if (slice.len % @sizeOf(elf.Elf64_Dyn) != 0) return error.InvalidSize;
                break :dt std.mem.bytesAsSlice(elf.Elf64_Dyn, slice);
            } else for (headers.shdrs, 0..) |shdr, i| {
                // if PT_DYNAMIC doesn't exist or is invalid, fallback to parsing
                // SHT_DYNAMIC
                if (shdr.sh_type == elf.SHT_DYNAMIC) {
                    break std.mem.bytesAsSlice(
                        elf.Elf64_Dyn,
                        try headers.shdrSlice(@intCast(i)),
                    );
                }
            }
            // if neither PT_DYNAMIC nor SHT_DYNAMIC exist, this is a state file.
            else return null;

            for (dynamic_table) |dyn| {
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

            const offset = for (headers.phdrs) |phdr| {
                if (inRangeOfPhdrVm(phdr, vaddr)) {
                    break vaddr - phdr.p_vaddr + phdr.p_offset;
                }
            } else for (headers.shdrs) |shdr| {
                if (shdr.sh_addr == vaddr) break shdr.sh_offset;
            } else return error.InvalidDynamicSectionTable;

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
                return std.mem.bytesAsSlice(elf.Elf64_Sym, try headers.shdrSlice(@intCast(i)));
            } else return error.InvalidDynamicSectionTable;
        }

        fn parseRoSections(
            self: Data,
            headers: Headers,
            config: Config,
            allocator: std.mem.Allocator,
        ) !Executable.Section {
            const version = config.minimum_version;
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
            }).initCapacity(allocator, headers.shdrs.len);
            defer ro_slices.deinit(allocator);

            var addr_file_offset: ?u64 = null;
            var invalid_offsets: bool = false;

            var first_ro_section: usize = 0;
            var last_ro_section: usize = 0;
            var n_ro_sections: usize = 0;

            for (headers.shdrs, 0..) |shdr, i| {
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
                    if (version.enableElfVaddr()) {
                        assert(config.optimize_rodata);
                        if (section_addr < shdr.sh_offset) {
                            invalid_offsets = true;
                        } else {
                            const offset = try std.math.sub(u64, section_addr, shdr.sh_offset);
                            addr_file_offset = addr_file_offset orelse offset;
                            if (addr_file_offset.? != offset) {
                                invalid_offsets = true;
                            }
                        }
                    } else if (section_addr != shdr.sh_offset) {
                        invalid_offsets = true;
                    }
                }

                var vaddr_end = if (version.enableElfVaddr() and
                    section_addr >= memory.PROGRAM_START)
                    section_addr
                else
                    section_addr +| memory.PROGRAM_START;
                if (version.rejectRodataStackOverlap()) {
                    vaddr_end +|= shdr.sh_size;
                }
                if ((config.reject_broken_elfs and invalid_offsets) or
                    vaddr_end > memory.STACK_START)
                {
                    return error.ValueOutOfBounds;
                }

                const section_data = try headers.shdrSlice(@intCast(i));
                lowest_addr = @min(lowest_addr, section_addr);
                highest_addr = @max(highest_addr, section_addr +| section_data.len);
                ro_fill_length +|= section_data.len;

                ro_slices.appendAssumeCapacity(.{ section_addr, section_data });
            }

            if (config.reject_broken_elfs and lowest_addr +| ro_fill_length > highest_addr) {
                return error.ValueOutOfBounds;
            }

            const can_borrow = !invalid_offsets and
                last_ro_section +| 1 -| first_ro_section == n_ro_sections and
                config.optimize_rodata;
            const ro_section: Executable.Section = if (can_borrow) ro: {
                const file_offset = addr_file_offset orelse 0;
                const start = lowest_addr -| file_offset;
                const end = highest_addr -| file_offset;

                if (lowest_addr >= memory.PROGRAM_START) {
                    break :ro .{ .borrowed = .{
                        .offset = lowest_addr -| memory.PROGRAM_START,
                        .start = start,
                        .end = end,
                    } };
                } else {
                    if (version.enableElfVaddr()) {
                        return error.ValueOutOfBounds;
                    }
                    break :ro .{ .borrowed = .{
                        .offset = lowest_addr,
                        .start = start,
                        .end = end,
                    } };
                }
            } else ro: {
                if (config.optimize_rodata) {
                    highest_addr -|= lowest_addr;
                } else {
                    lowest_addr = 0;
                }

                const buf_len = highest_addr;
                if (buf_len > headers.bytes.len) {
                    return error.ValueOutOfBounds;
                }

                const ro_section = try allocator.alloc(u8, buf_len);
                @memset(ro_section, 0);
                for (ro_slices.items) |ro_slice| {
                    const section_addr, const slice = ro_slice;
                    const buf_offset_start = section_addr -| lowest_addr;
                    @memcpy(ro_section[buf_offset_start..][0..slice.len], slice);
                }
                break :ro .{ .owned = .{ .offset = lowest_addr, .data = ro_section } };
            };
            return ro_section;
        }

        /// Returns the string for a given index into the string table.
        fn getString(self: Data, off: u32) [:0]const u8 {
            assert(off < self.strtab.len);
            const ptr: [*:0]const u8 = @ptrCast(self.strtab.ptr + off);
            return std.mem.sliceTo(ptr, 0);
        }

        pub fn getShdrIndexByName(self: Data, headers: Headers, name: []const u8) ?u32 {
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
        loader: *BuiltinProgram,
        config: Config,
    ) !Elf {
        const headers = try Headers.parse(bytes);
        const data = try Data.parse(headers);

        const text_section = data.getShdrByName(headers, ".text") orelse
            return error.NoTextSection;
        const offset = headers.header.e_entry -| text_section.sh_addr;
        const entry_pc = try std.math.divExact(u64, offset, 8);

        const sbpf_version: sbpf.Version = if (config.minimum_version == .v0)
            if (headers.header.e_flags == sbpf.EF_SBPF_v1)
                .v1
            else
                .v0
        else switch (headers.header.e_flags) {
            0 => .v0,
            1 => .v1,
            2 => .v2,
            3 => .v3,
            else => @enumFromInt(headers.header.e_flags),
        };

        if (@intFromEnum(sbpf_version) < @intFromEnum(config.minimum_version))
            return error.VersionUnsupported;

        var self: Elf = .{
            .bytes = bytes,
            .headers = headers,
            .data = data,
            .entry_pc = entry_pc,
            .version = sbpf_version,
            .function_registry = .{},
            .config = config,
            .ro_section = try data.parseRoSections(headers, config, allocator),
        };
        errdefer self.deinit(allocator);

        _ = try self.function_registry.registerHashedLegacy(
            allocator,
            !sbpf_version.enableStaticSyscalls(),
            "entrypoint",
            entry_pc,
        );

        try self.validate();
        try self.relocate(allocator, loader);

        return self;
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
        if (header.e_ident[sbpf.EI_OSABI] != sbpf.ELFOSABI_NONE) {
            return error.WrongAbi;
        }
        // ensure the ELF was compiled for BPF or possibly the custom SBPF machine number
        if (header.e_machine != elf.EM.BPF and @intFromEnum(header.e_machine) != sbpf.EM_SBPF) {
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
            if (std.mem.startsWith(u8, name, ".data") and
                !std.mem.startsWith(u8, name, ".data.rel"))
            {
                // TODO: use a packed struct here, this is ugly
                if (shdr.sh_flags & (elf.SHF_ALLOC | elf.SHF_WRITE) ==
                    elf.SHF_ALLOC | elf.SHF_WRITE)
                {
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
        const text_section_index = self.getShdrIndexByName(".text") orelse
            return error.NoTextSection;
        if (!self.inRangeOfShdrVaddr(text_section_index, entrypoint)) {
            return error.EntrypointOutsideTextSection;
        }
        const text_section_slice = try self.headers.shdrSlice(text_section_index);
        if (text_section_slice.len % @sizeOf(sbpf.Instruction) != 0)
            return error.InvalidTextSectionLength;

        if (self.config.minimum_version.enableElfVaddr()) {
            if (self.config.optimize_rodata != true) return error.UnsupportedSBPFVersion;
        }
    }

    fn relocate(
        self: *Elf,
        allocator: std.mem.Allocator,
        loader: *BuiltinProgram,
    ) !void {
        const config = self.config;
        const version = self.version;
        const text_section_index = self.getShdrIndexByName(".text") orelse
            return error.ShdrNotFound;
        const text_section = self.headers.shdrs[text_section_index];

        // fixup PC-relative call instructions
        const text_bytes: []u8 = try safeSlice(
            self.bytes,
            text_section.sh_offset,
            text_section.sh_size,
        );
        const instructions = self.getInstructions();
        for (instructions, 0..) |inst, i| {
            if (inst.opcode == .call_imm and
                inst.imm != ~@as(u32, 0) and
                !(version.enableStaticSyscalls() and inst.src == .r0))
            {
                const target_pc = @as(i64, @intCast(i)) +| @as(i32, @bitCast(inst.imm)) +| 1;
                if (target_pc < 0 or target_pc >= instructions.len)
                    return error.RelativeJumpOutOfBounds;
                const key = try self.function_registry.registerHashedLegacy(
                    allocator,
                    !version.enableStaticSyscalls(),
                    &.{},
                    @intCast(target_pc),
                );
                // offset into the instruction where the immediate is stored
                const offset = (i *| 8) +| 4;
                const slice = text_bytes[offset..][0..4];
                std.mem.writeInt(u32, slice, @intCast(key), .little);
            }
        }

        var phdr: ?elf.Elf64_Phdr = null;

        for (self.data.relocations_table) |reloc| {
            var r_offset = reloc.r_offset;

            if (version.enableElfVaddr()) {
                const found = if (phdr) |header| found: {
                    break :found inRangeOfPhdrVm(header, r_offset);
                } else false;
                if (!found) {
                    phdr = for (self.headers.phdrs) |header| {
                        if (inRangeOfPhdrVm(header, r_offset)) {
                            break header;
                        }
                    } else null;
                }
                const header = phdr orelse return error.ValueOutOfBounds;
                r_offset = r_offset -| header.p_vaddr +| header.p_offset;
            }

            switch (@as(elf.R_X86_64, @enumFromInt(reloc.r_type()))) {
                .@"64" => {
                    // if the relocation is addressing an instruction inside of the
                    // text section, we'll need to offset it by the offset of the immediate
                    // field into the instruction.
                    const in_text_section = self.inRangeOfShdr(
                        text_section_index,
                        r_offset,
                    ) or version == .v0;
                    const imm_offset = if (in_text_section) r_offset +| 4 else r_offset;

                    const addr_slice = try safeSlice(self.bytes, imm_offset, 4);
                    const ref_addr = std.mem.readInt(u32, addr_slice[0..4], .little);
                    const symbol = self.data.symbol_table[reloc.r_sym()];
                    var addr = symbol.st_value +| ref_addr;

                    if (addr < memory.PROGRAM_START) {
                        addr +|= memory.PROGRAM_START;
                    }

                    if (in_text_section or version == .v0) {
                        {
                            const imm_low_offset = imm_offset;
                            const imm_slice = try safeSlice(self.bytes, imm_low_offset, 4);
                            std.mem.writeInt(u32, imm_slice[0..4], @truncate(addr), .little);
                        }

                        {
                            const imm_high_offset = imm_offset +| 8;
                            const imm_slice = try safeSlice(self.bytes, imm_high_offset, 4);
                            std.mem.writeInt(u32, imm_slice[0..4], @intCast(addr >> 32), .little);
                        }
                    } else {
                        const imm_slice = try safeSlice(self.bytes, imm_offset, 8);
                        std.mem.writeInt(u64, imm_slice[0..8], addr, .little);
                    }
                },
                .RELATIVE => {
                    const imm_offset = r_offset +| 4;

                    // is the relocation targetting inside of the text section
                    if (self.inRangeOfShdr(text_section_index, imm_offset)) {
                        // the target is a lddw instruction which takes up two instruction slots

                        const va_low = val: {
                            const imm_slice = try safeSlice(self.bytes, imm_offset, 4);
                            break :val std.mem.readInt(u32, imm_slice[0..4], .little);
                        };

                        const va_high = val: {
                            const imm_high_offset = r_offset +| 12;
                            const imm_slice = try safeSlice(self.bytes, imm_high_offset, 4);
                            break :val std.mem.readInt(u32, imm_slice[0..4], .little);
                        };

                        var ref_addr = (@as(u64, va_high) << 32) | va_low;
                        if (ref_addr == 0) return error.InvalidVirtualAddress;

                        if (ref_addr < memory.PROGRAM_START) {
                            ref_addr +|= memory.PROGRAM_START;
                        }

                        {
                            const imm_slice = try safeSlice(self.bytes, imm_offset, 4);
                            std.mem.writeInt(
                                u32,
                                imm_slice[0..4],
                                @truncate(ref_addr),
                                .little,
                            );
                        }

                        {
                            const imm_high_offset = r_offset +| 12;
                            const imm_slice = try safeSlice(self.bytes, imm_high_offset, 4);
                            std.mem.writeInt(
                                u32,
                                imm_slice[0..4],
                                @intCast(ref_addr >> 32),
                                .little,
                            );
                        }
                    } else {
                        const address: u64 = switch (version) {
                            .v0 => addr: {
                                const addr_slice = try safeSlice(self.bytes, imm_offset, 4);
                                const address = std.mem.readInt(u32, addr_slice[0..4], .little);
                                break :addr memory.PROGRAM_START +| address;
                            },
                            else => addr: {
                                const addr_slice = try safeSlice(
                                    self.bytes,
                                    r_offset,
                                    @sizeOf(u64),
                                );
                                var address = std.mem.readInt(u64, addr_slice[0..8], .little);
                                if (address < memory.PROGRAM_START) {
                                    address +|= memory.PROGRAM_START;
                                }
                                break :addr address;
                            },
                        };
                        const addr_slice = try safeSlice(self.bytes, r_offset, @sizeOf(u64));
                        std.mem.writeInt(u64, addr_slice[0..8], address, .little);
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
                    const dynstr = try self.headers.shdrSlice(dynstr_index);
                    const symbol_name = std.mem.sliceTo(dynstr[symbol.st_name..], 0);

                    // If the symbol is defined, this is a bpf-to-bpf call.
                    if (symbol.st_type() == elf.STT_FUNC and symbol.st_value != 0) {
                        const target_pc = (symbol.st_value -| text_section.sh_addr) / 8;
                        const key = try self.function_registry.registerHashedLegacy(
                            allocator,
                            !version.enableStaticSyscalls(),
                            symbol_name,
                            @intCast(target_pc),
                        );
                        const slice = try safeSlice(self.bytes, imm_offset, 4);
                        std.mem.writeInt(u32, slice[0..4], @intCast(key), .little);
                    } else {
                        const hash = sbpf.hashSymbolName(symbol_name);
                        if (config.reject_broken_elfs and
                            loader.functions.lookupKey(hash) == null)
                        {
                            return error.UnresolvedSymbol;
                        }
                        const slice = try safeSlice(self.bytes, imm_offset, 4);
                        std.mem.writeInt(u32, slice[0..4], hash, .little);
                    }
                },
                else => return error.UnknownRelocation,
            }
        }
    }

    pub fn deinit(self: *Elf, allocator: std.mem.Allocator) void {
        self.function_registry.deinit(allocator);
        self.ro_section.deinit(allocator);
    }

    /// The function is guarnteed to succeed, since `parse` already checks that
    /// the `.text` section exists and it's sized correctly.
    pub fn getInstructions(self: Elf) []align(1) const sbpf.Instruction {
        const text_section_index = self.getShdrIndexByName(".text").?;
        const text_bytes: []const u8 = self.headers.shdrSlice(text_section_index) catch unreachable;
        return std.mem.bytesAsSlice(sbpf.Instruction, text_bytes);
    }

    fn getShdrIndexByName(self: Elf, name: []const u8) ?u32 {
        return self.data.getShdrIndexByName(self.headers, name);
    }

    pub fn getShdrByName(self: Elf, name: []const u8) ?elf.Elf64_Shdr {
        return self.data.getShdrByName(self.headers, name);
    }

    fn inRangeOfShdr(self: *const Elf, index: usize, addr: usize) bool {
        const shdr = self.headers.shdrs[index];
        const sh_offset = shdr.sh_offset;
        const sh_size = shdr.sh_size;
        return addr >= sh_offset and addr < sh_offset + sh_size;
    }

    fn inRangeOfShdrVaddr(self: *const Elf, index: usize, addr: usize) bool {
        const shdr = self.headers.shdrs[index];
        const sh_addr = shdr.sh_addr;
        const sh_size = shdr.sh_size;
        return addr >= sh_addr and addr < sh_addr + sh_size;
    }

    fn inRangeOfPhdrVm(phdr: elf.Elf64_Phdr, addr: usize) bool {
        const p_vaddr = phdr.p_vaddr;
        const p_memsz = phdr.p_memsz;
        return addr >= p_vaddr and addr < p_vaddr + p_memsz;
    }

    fn safeSlice(base: anytype, start: usize, len: usize) error{OutOfBounds}!@TypeOf(base) {
        if (start >= base.len) return error.OutOfBounds;
        const end = std.math.add(usize, start, len) catch return error.OutOfBounds;
        if (end > base.len) return error.OutOfBounds;
        return base[start..][0..len];
    }
};
