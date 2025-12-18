//! Represents a parsed ELF file.
//!
//! Elf Spec: http://refspecs.linux-foundation.org/LSB_4.1.0/LSB-Core-generic/LSB-Core-generic.html

const std = @import("std");
const sig = @import("../sig.zig");
const tracy = @import("tracy");
const sbpf = @import("sbpf.zig");
const memory = @import("memory.zig");

const lib = @import("lib.zig");
const Config = lib.Config;
const Registry = lib.Registry;
const Section = lib.Section;
const SyscallMap = sig.vm.SyscallMap;

const elf = std.elf;
const assert = std.debug.assert;

const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;
const expectError = std.testing.expectError;

pub const Elf = struct {
    bytes: []u8,
    headers: Headers,
    data: Data,
    entry_pc: u64,
    version: sbpf.Version,
    function_registry: Registry,
    ro_section: Section,
    config: Config,

    /// Contains immutable headers parsed from the ELF file.
    const Headers = struct {
        bytes: []const u8,
        header: elf.Elf64_Ehdr,
        // The following fields are align(1) because there's no guarantee of alignment inside of the ELF sections.
        shdrs: []align(1) const elf.Elf64_Shdr,
        phdrs: []align(1) const elf.Elf64_Phdr,

        /// [agave] https://github.com/anza-xyz/sbpf/blob/56e14672804ae762030e2f620aae6b6e6fa50d34/src/elf_parser/mod.rs#L120-L129
        fn checkOverlap(a_start: usize, a_end: usize, b_start: usize, b_end: usize) !void {
            if (a_end <= b_start or b_end <= a_start) return;
            return error.Overlap;
        }

        fn parse(bytes: []const u8) !Headers {
            // There aren't enough bytes in the ELF file to contain a header.
            if (bytes.len < @sizeOf(elf.Elf64_Ehdr)) return error.OutOfBounds;
            const header: elf.Elf64_Ehdr = @bitCast(bytes[0..@sizeOf(elf.Elf64_Ehdr)].*);
            const ident: ElfIdent = @bitCast(header.e_ident);

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

            // Compute the size of the program headers in the ELF in bytes.
            const ph_size = try std.math.mul(u64, header.e_phnum, @sizeOf(elf.Elf64_Phdr));
            const ph_end = try std.math.add(u64, header.e_phoff, ph_size);
            try checkOverlap(0, @sizeOf(elf.Elf64_Ehdr), header.e_phoff, ph_end);

            // A slice representing the program headers, re-interpreted into `Elf64_Phdr`.
            const phdrs = std.mem.bytesAsSlice(
                elf.Elf64_Phdr,
                try safeSlice(bytes, header.e_phoff, ph_size),
            );

            // Compute the size of the section headers in the ELF in bytes.
            const sh_size = try std.math.mul(u64, header.e_shnum, @sizeOf(elf.Elf64_Shdr));
            const sh_end = try std.math.add(u64, header.e_shoff, sh_size);
            try checkOverlap(0, @sizeOf(elf.Elf64_Ehdr), header.e_shoff, sh_end);
            try checkOverlap(header.e_phoff, ph_end, header.e_shoff, sh_end);

            // A slice representing the section headers, re-interpreted into `Elf64_Shdr`.
            const shdrs = std.mem.bytesAsSlice(
                elf.Elf64_Shdr,
                try safeSlice(bytes, header.e_shoff, sh_size),
            );

            if (!(shdrs.len > 0 and shdrs[0].sh_type == elf.SHT_NULL)) {
                return error.InvalidSectionHeader;
            }

            // Validate program header address ranges.
            var vaddr: elf.Elf64_Addr = 0;
            for (phdrs) |phdr| {
                if (phdr.p_type != elf.PT_LOAD) continue;
                if (phdr.p_vaddr < vaddr) return error.InvalidProgramHeader;
                defer vaddr = phdr.p_vaddr;

                const file_offset = try std.math.add(usize, phdr.p_offset, phdr.p_filesz);
                if (file_offset > bytes.len) {
                    return error.OutOfBounds;
                }
            }

            var offset: usize = 0;
            for (shdrs) |shdr| {
                if (shdr.sh_type == elf.SHT_NOBITS) continue;
                const start = shdr.sh_offset;
                const end = try std.math.add(usize, start, shdr.sh_size);

                try checkOverlap(0, @sizeOf(elf.Elf64_Ehdr), start, end);
                try checkOverlap(header.e_phoff, ph_end, start, end);
                try checkOverlap(header.e_shoff, sh_end, start, end);

                if (start < offset) return error.SectionNotInOrder;
                offset = end;
                if (offset > bytes.len) return error.OutOfBounds;
            }

            // Section header for the string table
            const headers: Headers = .{
                .bytes = bytes,
                .header = header,
                .shdrs = shdrs,
                .phdrs = phdrs,
            };

            try headers.parseSections();
            return headers;
        }

        fn parseSections(self: Headers) !void {
            // Validate section headers appear only once.
            var section_checks: [3]struct { name: []const u8, seen: bool } = .{
                .{ .name = ".symtab", .seen = false },
                .{ .name = ".strtab", .seen = false },
                .{ .name = ".dynstr", .seen = false },
            };

            const names_shdr: elf.Elf64_Shdr = if (self.header.e_shstrndx == elf.SHN_UNDEF)
                return error.NoSectionNameStringTable
            else if (self.header.e_shstrndx >= self.shdrs.len)
                return error.OutOfBounds
            else
                self.shdrs[self.header.e_shstrndx];

            for (self.shdrs) |shdr| {
                const name = try self.shdrString(names_shdr, shdr.sh_name, 16);
                for (&section_checks) |*check| {
                    if (std.mem.eql(u8, check.name, name)) {
                        if (check.seen) return error.InvalidSectionHeader;
                        check.seen = true;
                    }
                }
            }
        }

        /// Returns the byte contents of the `index`nth section.
        pub fn shdrSlice(self: Headers, index: u64) ![]const u8 {
            if (index >= self.shdrs.len) return error.OutOfBounds;
            return self.shdrBytes(self.shdrs[index]);
        }

        fn shdrBytes(self: Headers, shdr: elf.Elf64_Shdr) ![]const u8 {
            if (shdr.sh_type == elf.SHT_NOBITS) return &.{};
            const sh_offset = shdr.sh_offset;
            const sh_size = shdr.sh_size;
            return try safeSlice(self.bytes, sh_offset, sh_size);
        }

        /// Returns the byte contents of the `index`nth program section.
        fn phdrSlice(self: Headers, index: u64) ![]const u8 {
            if (index >= self.phdrs.len) return error.OutOfBounds;
            const phdr = self.phdrs[index];
            const p_offset = phdr.p_offset;
            const p_filesz = phdr.p_filesz;
            return try safeSlice(self.bytes, p_offset, p_filesz);
        }

        /// Returns a string from an STRTAB section given an offset and max string length.
        fn shdrString(self: Headers, shdr: elf.Elf64_Shdr, offset: u32, limit: u8) ![:0]const u8 {
            if (shdr.sh_type != elf.SHT_STRTAB) return error.InvalidSectionHeader;
            const slice = try self.shdrBytes(shdr);
            return try safeString(slice, offset, limit);
        }

        /// Finds the first program header to match the `p_type` provided.
        /// This function is usually used in cases where we're searching for a
        /// unique `p_type`, such as `PT_DYNAMIC`.
        fn getPhdrIndexByType(self: Headers, p_type: elf.Word) ?u32 {
            for (self.phdrs, 0..) |phdr, i| {
                if (phdr.p_type == p_type) return @intCast(i);
            }
            return null;
        }

        /// Determines whether an address is within the virtual address space of
        /// a particular section in the file image.
        fn inRangeOfShdr(self: Headers, index: usize, addr: usize) bool {
            const shdr = self.shdrs[index];
            const sh_offset = shdr.sh_offset;
            const sh_size = shdr.sh_size;
            return addr >= sh_offset and addr < sh_offset + sh_size;
        }
    };

    /// Contains data which is parsed from the headers.
    const Data = struct {
        strtab: ?[]const u8,
        dynamic_table: DynamicTable,
        relocations_table: []align(1) const elf.Elf64_Rel,
        symbol_table: []align(1) const elf.Elf64_Sym,

        const DynamicTable = [elf.DT_NUM]elf.Elf64_Xword;

        fn parse(headers: Headers) !Data {
            const strtab: ?[]const u8 = if (headers.header.e_shstrndx != elf.SHN_UNDEF)
                try headers.shdrSlice(headers.header.e_shstrndx)
            else
                null;

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

        /// Parses and returns the dynamic entry table, if the ELF has one.
        ///
        /// [agave] https://github.com/anza-xyz/sbpf/blob/615f120f70d3ef387aab304c5cdf66ad32dae194/src/elf_parser/mod.rs#L358-L404
        fn parseDynamic(headers: Headers) !?DynamicTable {
            var output_table: DynamicTable = .{0} ** elf.DT_NUM;

            var dynamic_table: ?[]align(1) const elf.Elf64_Dyn = null;

            if (headers.getPhdrIndexByType(elf.PT_DYNAMIC)) |index| phdr: {
                // If anything errors, we need to skip this strategy and try parsing the SHT_DYNAMIC
                const slice = headers.phdrSlice(index) catch break :phdr;
                if (slice.len % @sizeOf(elf.Elf64_Dyn) != 0) break :phdr;
                dynamic_table = std.mem.bytesAsSlice(elf.Elf64_Dyn, slice);
            }

            if (dynamic_table == null) {
                for (headers.shdrs, 0..) |shdr, i| {
                    // If PT_DYNAMIC doesn't exist or is invalid, fallback to parsing SHT_DYNAMIC
                    if (shdr.sh_type == elf.SHT_DYNAMIC) {
                        const slice = try headers.shdrSlice(i);
                        if (slice.len % @sizeOf(elf.Elf64_Dyn) != 0) return error.InvalidSize;
                        dynamic_table = std.mem.bytesAsSlice(elf.Elf64_Dyn, slice);
                        break;
                    }
                }
            }

            // If neither PT_DYNAMIC nor SHT_DYNAMIC exist, this is a state file.
            if (dynamic_table == null) return null;
            for (dynamic_table.?) |dyn| {
                const d_tag: u64 = @bitCast(dyn.d_tag);
                // The dynamic table is terminated by a `DT_NULL` entry.
                if (d_tag == elf.DT_NULL) break;
                // Above `DT_NUM`, the tags are reserved, and we skip over it.
                if (d_tag >= elf.DT_NUM) continue;

                output_table[d_tag] = dyn.d_val;
            }

            return output_table;
        }

        /// [agave] https://github.com/anza-xyz/sbpf/blob/615f120f70d3ef387aab304c5cdf66ad32dae194/src/elf_parser/mod.rs#L412
        fn parseDynamicRelocations(
            headers: Headers,
            dynamic_table: DynamicTable,
        ) ![]align(1) const elf.Elf64_Rel {
            // Find the virtual address of the dynamic relocation table.
            const vaddr = dynamic_table[elf.DT_REL];
            if (vaddr == elf.DT_NULL) return &.{};

            if (dynamic_table[elf.DT_RELENT] != @sizeOf(elf.Elf64_Rel)) {
                return error.InvalidDynamicSectionTable;
            }

            const size = dynamic_table[elf.DT_RELSZ];
            if (size == elf.DT_NULL) return error.InvalidDynamicSectionTable;

            // Determine the offset of relocation table in the ELF.
            // It could appear both inside of a section and a program section.
            const offset = for (headers.phdrs) |phdr| {
                if (inRangeOfPhdrVm(phdr, vaddr)) {
                    const offset = try std.math.sub(u64, vaddr, phdr.p_vaddr);
                    break try std.math.add(u64, offset, phdr.p_offset);
                }
            } else for (headers.shdrs) |shdr| {
                if (shdr.sh_addr == vaddr) break shdr.sh_offset;
            } else return error.InvalidDynamicSectionTable;

            const bytes = try safeSlice(headers.bytes, offset, size);
            if (bytes.len % @sizeOf(elf.Elf64_Rel) != 0) return error.InvalidDynamicSectionTable;
            return std.mem.bytesAsSlice(elf.Elf64_Rel, bytes);
        }

        /// [agave] https://github.com/anza-xyz/sbpf/blob/615f120f70d3ef387aab304c5cdf66ad32dae194/src/elf_parser/mod.rs#L448-L462
        fn parseDynamicSymbolTable(
            headers: Headers,
            dynamic_table: DynamicTable,
        ) ![]align(1) const elf.Elf64_Sym {
            // Get the virtual address of the symbol table.
            const vaddr = dynamic_table[elf.DT_SYMTAB];
            if (vaddr == elf.DT_NULL) return &.{};

            for (headers.shdrs, 0..) |shdr, i| {
                // Filter out section headers that aren't pointing to the symbol table.
                if (shdr.sh_addr != vaddr) continue;
                // We need either a SYMTAB or a DYNSYM section.
                if (shdr.sh_type != elf.SHT_SYMTAB and shdr.sh_type != elf.SHT_DYNSYM) {
                    return error.InvalidSectionHeader;
                }
                const slice = try headers.shdrSlice(i);
                if (slice.len % @sizeOf(elf.Elf64_Sym) != 0) return error.InvalidSize;
                return std.mem.bytesAsSlice(elf.Elf64_Sym, slice);
            } else return error.InvalidDynamicSectionTable;
        }

        /// [agave] https://github.com/anza-xyz/sbpf/blob/615f120f70d3ef387aab304c5cdf66ad32dae194/src/elf.rs#L827-L1002
        fn parseRoSections(
            self: Data,
            allocator: std.mem.Allocator,
            headers: Headers,
            config: Config,
            version: sbpf.Version,
        ) !Section {
            // List of allowed section names for storing data.
            const ro_names: []const []const u8 = &.{
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
            var sfba = std.heap.stackFallback(@sizeOf(Entry) * ro_names.len, allocator);
            const gpa = sfba.get();

            var ro_slices = try std.ArrayListUnmanaged(Entry).initCapacity(gpa, headers.shdrs.len);
            defer ro_slices.deinit(gpa);

            var addr_file_offset: ?u64 = null;
            var invalid_offsets: bool = false;

            // Index of the first read-only section in the section header list.
            var first_ro_section: usize = 0;
            // Index of the last read-only section in the section header list.
            var last_ro_section: usize = 0;
            // Number of read-only sections in the ELF.
            var n_ro_sections: usize = 0;

            for (headers.shdrs, 0..) |shdr, i| {
                // If the name of the section isn't in the list of
                // valid read-only sections, just skip it.
                const name = self.getSectionName(shdr.sh_name) catch continue;
                for (ro_names) |ro_name| {
                    if (std.mem.eql(u8, ro_name, name)) break;
                } else continue;

                if (n_ro_sections == 0) {
                    first_ro_section = i;
                }
                last_ro_section = i;
                n_ro_sections = n_ro_sections +| 1;

                // Determine whether the section header has invalid offset metadata.
                // [agave] https://github.com/anza-xyz/sbpf/blob/615f120f70d3ef387aab304c5cdf66ad32dae194/src/elf.rs#L870-L899
                if (!invalid_offsets) {
                    if (version.enableElfVaddr()) {
                        assert(config.optimize_rodata);
                        if (shdr.sh_addr < shdr.sh_offset) {
                            invalid_offsets = true;
                        } else {
                            const offset = try std.math.sub(u64, shdr.sh_addr, shdr.sh_offset);
                            addr_file_offset = addr_file_offset orelse offset;
                            if (addr_file_offset.? != offset) {
                                invalid_offsets = true;
                            }
                        }
                    } else if (shdr.sh_addr != shdr.sh_offset) {
                        invalid_offsets = true;
                    }
                }

                var vaddr_end = if (version.enableElfVaddr() and
                    shdr.sh_addr >= memory.RODATA_START)
                    shdr.sh_addr
                else
                    shdr.sh_addr +| memory.RODATA_START;

                if (version.rejectRodataStackOverlap()) {
                    vaddr_end +|= shdr.sh_size;
                }
                if ((config.reject_broken_elfs and invalid_offsets) or
                    vaddr_end > memory.STACK_START)
                {
                    return error.ValueOutOfBounds;
                }

                const section_data = try headers.shdrSlice(i);
                lowest_addr = @min(lowest_addr, shdr.sh_addr);
                highest_addr = @max(highest_addr, shdr.sh_addr +| section_data.len);
                ro_fill_length +|= section_data.len;

                ro_slices.appendAssumeCapacity(.{ shdr.sh_addr, section_data });
            }

            if (config.reject_broken_elfs and lowest_addr +| ro_fill_length > highest_addr) {
                return error.ValueOutOfBounds;
            }

            const can_borrow = !invalid_offsets and
                last_ro_section +| 1 -| first_ro_section == n_ro_sections and
                config.optimize_rodata;
            const ro_section: Section = if (can_borrow) ro: {
                const file_offset = addr_file_offset orelse 0;
                const start = lowest_addr -| file_offset;
                const end = highest_addr -| file_offset;

                if (lowest_addr >= memory.RODATA_START) {
                    break :ro .{ .borrowed = .{
                        .offset = lowest_addr,
                        .start = start,
                        .end = end,
                    } };
                } else {
                    if (version.enableElfVaddr()) {
                        return error.ValueOutOfBounds;
                    }
                    break :ro .{ .borrowed = .{
                        .offset = lowest_addr +| memory.RODATA_START,
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

                if (highest_addr > headers.bytes.len) {
                    return error.ValueOutOfBounds;
                }

                // Concat all of the gathered read-only sections into one contiguous slice.
                const ro_section = try allocator.alloc(u8, highest_addr);
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

        /// [agave] https://github.com/anza-xyz/sbpf/blob/615f120f70d3ef387aab304c5cdf66ad32dae194/src/elf.rs#L1194-L1346
        fn relocate(
            self: Data,
            allocator: std.mem.Allocator,
            headers: Headers,
            bytes: []u8,
            loader: *const SyscallMap,
            function_registry: *Registry,
            version: sbpf.Version,
            config: Config,
        ) !void {
            const zone = tracy.Zone.init(@src(), .{ .name = "Elf.Data.relocate" });
            defer zone.deinit();

            const text_section_index = self.getShdrIndexByName(headers, ".text") orelse
                return error.ShdrNotFound;

            // We don't use headers.shdrSlice() since we need to slice the mutable `bytes`.
            const text_section = headers.shdrs[text_section_index];
            const text_bytes: []u8 = try safeSlice(
                bytes,
                text_section.sh_offset,
                text_section.sh_size,
            );

            const instructions = try self.getInstructions(headers);
            for (instructions, 0..) |inst, i| {
                const immediate: i64 = @as(i32, @bitCast(inst.imm));
                if (inst.opcode == .call_imm and immediate != -1) {
                    const target_pc = @as(i64, @intCast(i)) +| immediate +| 1;
                    if (target_pc < 0 or target_pc >= instructions.len)
                        return error.RelativeJumpOutOfBounds;

                    // Compute at compile-time how large of a buffer we need to store the name.
                    var buf: [
                        std.fmt.count(
                            "function_{d}",
                            .{std.math.minInt(i64)}, // min to account for the sign character
                        )
                    ]u8 = undefined;
                    const name = if (config.enable_symbol_and_section_labels)
                        try std.fmt.bufPrint(&buf, "function_{d}", .{target_pc})
                    else
                        &.{};

                    const key = try function_registry.registerHashedLegacy(
                        allocator,
                        loader,
                        !version.enableStaticSyscalls(),
                        name,
                        @intCast(target_pc),
                    );

                    if (!version.enableStaticSyscalls()) {
                        // offset into the instruction where the immediate is stored
                        const offset = (i *| 8) +| 4;
                        const slice = try safeSlice(text_bytes, offset, 4);
                        std.mem.writeInt(u32, slice[0..4], @intCast(key), .little);
                    }
                }
            }

            var phdr: ?elf.Elf64_Phdr = null;
            for (self.relocations_table) |reloc| {
                var r_offset = reloc.r_offset;

                if (version.enableElfVaddr()) {
                    // "Cache" the `phdr` in order to avoid doing a linear search for each relocation.
                    // 99% of relocations will be in the same program section.
                    const found = if (phdr) |header| found: {
                        break :found inRangeOfPhdrVm(header, r_offset);
                    } else false;
                    if (!found) {
                        phdr = for (headers.phdrs) |header| {
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
                        // If the relocation is addressing an instruction inside of the
                        // text section, we'll need to offset it by the offset of the immediate
                        // field into the instruction.
                        const in_text_section = headers.inRangeOfShdr(
                            text_section_index,
                            r_offset,
                        ) or version == .v0;
                        const imm_offset = if (in_text_section) r_offset +| 4 else r_offset;

                        const addr_slice = try safeSlice(bytes, imm_offset, 4);
                        const ref_addr = std.mem.readInt(u32, addr_slice[0..4], .little);
                        // Make sure the relocation is referring to a symbol that's in the symbol table.
                        if (reloc.r_sym() >= self.symbol_table.len) return error.UnknownSymbol;
                        const symbol = self.symbol_table[reloc.r_sym()];
                        var addr = symbol.st_value +| ref_addr;

                        if (addr < memory.RODATA_START) {
                            addr +|= memory.RODATA_START;
                        }

                        if (in_text_section or version == .v0) {
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
                                std.mem.writeInt(
                                    u32,
                                    imm_slice[0..4],
                                    @truncate(addr >> 32),
                                    .little,
                                );
                            }
                        } else {
                            // This is refering to some constant outside of the .TEXT section,
                            // so we don't need to worry about fitting the data into an immediate field.
                            const imm_slice = try safeSlice(bytes, imm_offset, 8);
                            std.mem.writeInt(u64, imm_slice[0..8], addr, .little);
                        }
                    },
                    .RELATIVE => {
                        const imm_offset = r_offset +| 4;

                        // If the relocation is targetting an address inside of the text section
                        // the target is a LDDW instruction which takes up two instruction slots.
                        if (headers.inRangeOfShdr(text_section_index, imm_offset)) {
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
                            var ref_addr = (@as(u64, va_high) << 32) | va_low;
                            if (ref_addr == 0) return error.InvalidVirtualAddress;

                            if (ref_addr < memory.RODATA_START) {
                                ref_addr +|= memory.RODATA_START;
                            }

                            {
                                const imm_slice = try safeSlice(bytes, imm_offset, 4);
                                std.mem.writeInt(
                                    u32,
                                    imm_slice[0..4],
                                    @truncate(ref_addr),
                                    .little,
                                );
                            }

                            {
                                const imm_high_offset = r_offset +| 12;
                                const imm_slice = try safeSlice(bytes, imm_high_offset, 4);
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
                                    const addr_slice = try safeSlice(bytes, imm_offset, 4);
                                    const address = std.mem.readInt(u32, addr_slice[0..4], .little);
                                    break :addr memory.RODATA_START +| address;
                                },
                                else => addr: {
                                    const addr_slice = try safeSlice(bytes, r_offset, @sizeOf(u64));
                                    var address = std.mem.readInt(u64, addr_slice[0..8], .little);
                                    if (address < memory.RODATA_START) {
                                        address +|= memory.RODATA_START;
                                    }
                                    break :addr address;
                                },
                            };
                            const addr_slice = try safeSlice(bytes, r_offset, @sizeOf(u64));
                            std.mem.writeInt(u64, addr_slice[0..8], address, .little);
                        }
                    },
                    .@"32" => {
                        // The "32" relocation handles resolving calls to symbols.
                        // Hash the symbol name with Murmur and ammend the instruction's imm field.
                        const imm_offset = r_offset +| 4;
                        if (reloc.r_sym() >= self.symbol_table.len) return error.UnknownSymbol;
                        const symbol = self.symbol_table[reloc.r_sym()];

                        const dynstr_index = self.getShdrIndexByName(headers, ".dynstr") orelse
                            return error.NoDynStrSection;
                        const dynstr = try headers.shdrSlice(dynstr_index);
                        if (symbol.st_name >= dynstr.len) return error.UnknownSymbol;
                        const symbol_name = std.mem.sliceTo(dynstr[symbol.st_name..], 0);

                        // If the symbol is defined and a function, this is a BPF-to-BPF call.
                        if (symbol.st_type() == elf.STT_FUNC and symbol.st_value != 0) {
                            const target_pc = (symbol.st_value -| text_section.sh_addr) / 8;
                            const key = try function_registry.registerHashedLegacy(
                                allocator,
                                loader,
                                !version.enableStaticSyscalls(),
                                symbol_name,
                                @intCast(target_pc),
                            );
                            const slice = try safeSlice(bytes, imm_offset, 4);
                            std.mem.writeInt(u32, slice[0..4], @intCast(key), .little);
                        } else {
                            const hash = sbpf.hashSymbolName(symbol_name);
                            if (config.reject_broken_elfs and
                                loader.get(hash) == null)
                            {
                                return error.UnresolvedSymbol;
                            }
                            const slice = try safeSlice(bytes, imm_offset, 4);
                            std.mem.writeInt(u32, slice[0..4], hash, .little);
                        }
                    },
                    else => return error.UnknownRelocation,
                }
            }

            if (config.enable_symbol_and_section_labels) {
                const symbol_names_shdr = self.getShdrByName(headers, ".strtab") orelse
                    return error.NoStringTable;

                // Register all known function names from the symbol table.
                for (self.symbol_table) |sym| {
                    if (sym.st_info & 0xef != 0x02) continue;
                    if (sym.st_value < text_section.sh_addr or
                        sym.st_value >= text_section.sh_addr + text_section.sh_size)
                    {
                        return error.ValueOutOfBounds;
                    }

                    const target_pc = (sym.st_value -| text_section.sh_addr) / 8;
                    const symbol_name = headers.shdrString(symbol_names_shdr, sym.st_name, 64) catch
                        return error.UnknownSymbol;

                    _ = try function_registry.registerHashedLegacy(
                        allocator,
                        loader,
                        !version.enableStaticSyscalls(),
                        symbol_name,
                        @intCast(target_pc),
                    );
                }
            }
        }

        /// Returns the string for a given shdr.sh_name offset into the string table.
        fn getSectionName(self: Data, offset: u32) ![:0]const u8 {
            const strtab = self.strtab orelse return error.NoSectionNameStringTable;
            return try safeString(strtab, offset, 16);
        }

        /// Returns the index of the section with the name provided.
        fn getShdrIndexByName(self: Data, headers: Headers, name: []const u8) ?u32 {
            for (headers.shdrs, 0..) |shdr, i| {
                const shdr_name = self.getSectionName(shdr.sh_name) catch continue;
                if (std.mem.eql(u8, shdr_name, name)) {
                    return @intCast(i);
                }
            }
            return null;
        }

        /// Returns a slice of the instructions by re-interpreting the bytes.
        /// Assumes that there is a `.text` section and that the length of it .
        fn getInstructions(self: Data, headers: Headers) ![]align(1) const sbpf.Instruction {
            const text_section_index = self.getShdrIndexByName(headers, ".text").?;
            const text_bytes: []const u8 = try headers.shdrSlice(text_section_index);
            const instruction_count = text_bytes.len / 8;
            return std.mem.bytesAsSlice(
                sbpf.Instruction,
                text_bytes[0 .. instruction_count * @sizeOf(sbpf.Instruction)],
            );
        }

        pub fn getShdrByName(self: Data, headers: Headers, name: []const u8) ?elf.Elf64_Shdr {
            const index = self.getShdrIndexByName(headers, name) orelse return null;
            return headers.shdrs[index];
        }
    };

    pub fn parse(
        allocator: std.mem.Allocator,
        bytes: []u8,
        loader: *const SyscallMap,
        config: Config,
    ) !Elf {
        const headers = try Headers.parse(bytes);
        const data = try Data.parse(headers);

        // The behaviour for parsing the version changed in v1. Before it was
        // either equal `EM_SBPF_V1` or it wasn't. This method didn't allow
        // for specifying more than 2 possible versions, so now we have
        // well-defined values for the versions. We will determine which method
        // to use based on the configuration of the VM.
        const sbpf_version: sbpf.Version = if (config.maximum_version == .v0)
            if (headers.header.e_flags == sbpf.EM_SBPF_V1)
                .v1
            else
                .v0
        else switch (headers.header.e_flags) {
            0 => .v0,
            1 => .v1,
            2 => .v2,
            3 => .v3,
            else => |v| @enumFromInt(v),
        };

        // Ensure that the sbpf version we find is within the range that's enabled.
        if (@intFromEnum(sbpf_version) < @intFromEnum(config.minimum_version) or
            @intFromEnum(sbpf_version) > @intFromEnum(config.maximum_version))
        {
            // TODO: Conformance issue vs. agave-v2.1.0
            return error.VersionUnsupported;
        }

        if (sbpf_version.enableStricterElfHeaders()) {
            return try parseStrict(
                allocator,
                bytes,
                headers,
                data,
                sbpf_version,
                config,
            );
        } else {
            return try parseLenient(
                allocator,
                bytes,
                headers,
                data,
                sbpf_version,
                config,
                loader,
            );
        }
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

    fn parseStrict(
        allocator: std.mem.Allocator,
        bytes: []u8,
        headers: Headers,
        data: Data,
        sbpf_version: sbpf.Version,
        config: Config,
    ) !Elf {
        const header = headers.header;

        // A list of the first 5 expected program headers.
        // Since this is a stricter parsing scheme, we need them to match exactly.
        const expected_phdrs = .{
            .{ elf.PT_LOAD, elf.PF_X, memory.BYTECODE_START },
            .{ elf.PT_LOAD, elf.PF_R, memory.RODATA_START },
            .{ elf.PT_GNU_STACK, elf.PF_R | elf.PF_W, memory.STACK_START },
            .{ elf.PT_LOAD, elf.PF_R | elf.PF_W, memory.HEAP_START },
            .{ elf.PT_NULL, 0, 0xFFFFFFFF00000000 },
        };

        const ident: ElfIdent = @bitCast(header.e_ident);
        const phdr_table_end = (@sizeOf(elf.Elf64_Phdr) * header.e_phnum) +
            @sizeOf(elf.Elf64_Ehdr);
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

        inline for (
            expected_phdrs,
            headers.phdrs[0..expected_phdrs.len],
        ) |entry, phdr| {
            const p_type, const p_flags, const p_vaddr = entry;
            // For writable sections, (those with the PF_W bit set), we expect their
            // value for p_filesz to be zero.
            const p_filesz = if (p_flags & elf.PF_W != 0) 0 else phdr.p_memsz;

            if (phdr.p_type != p_type or
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

        const maybe_symbols_shdr = if (config.enable_symbol_and_section_labels) blk: {
            const strtab = data.strtab orelse return error.NoSectionNamesStringTable;
            for (headers.shdrs) |shdr| {
                const name = try safeString(strtab, shdr.sh_name, 64);
                if (std.mem.eql(u8, name, ".dynstr")) {
                    break :blk shdr;
                }
            }
            break :blk null;
        } else null;

        const bytecode_hdr = headers.phdrs[0];
        const rodata_hdr = headers.phdrs[1];
        const ro_section: Section = .{ .borrowed = .{
            .offset = rodata_hdr.p_vaddr,
            .start = rodata_hdr.p_offset,
            .end = rodata_hdr.p_offset + rodata_hdr.p_filesz,
        } };

        const entry_pc = (header.e_entry -| bytecode_hdr.p_vaddr) / 8;
        var self: Elf = .{
            .bytes = bytes,
            .headers = headers,
            .data = data,
            .entry_pc = entry_pc,
            .version = sbpf_version,
            .function_registry = .{},
            .config = config,
            .ro_section = ro_section,
        };
        errdefer self.deinit(allocator);

        const dynsym_table = std.mem.bytesAsSlice(elf.Elf64_Sym, try headers.phdrSlice(4));
        var expected_symbol_address = bytecode_hdr.p_vaddr;
        for (dynsym_table) |symbol| {
            if (symbol.st_info & elf.STT_FUNC == 0) continue;
            if (symbol.st_value != expected_symbol_address) return error.OutOfBounds;
            if (symbol.st_size == 0 or symbol.st_size % 8 != 0) return error.InvalidSize;
            if (!inRangeOfPhdrVm(bytecode_hdr, symbol.st_value)) return error.OutOfBounds;

            const name = if (config.enable_symbol_and_section_labels)
                try headers.shdrString(
                    maybe_symbols_shdr orelse return error.NoStringTable,
                    symbol.st_name,
                    0xff,
                )
            else
                &.{};

            const target_pc = (symbol.st_value -| bytecode_hdr.p_vaddr) / 8;
            try self.function_registry.register(allocator, target_pc, name, target_pc);
            expected_symbol_address = symbol.st_value +| symbol.st_size;
        }
        if (expected_symbol_address != bytecode_hdr.p_vaddr +| bytecode_hdr.p_memsz) {
            return error.OutOfBounds;
        }
        if (!inRangeOfPhdrVm(bytecode_hdr, header.e_entry) or
            header.e_entry % 8 != 0)
        {
            return error.InvalidFileHeader;
        }
        if (self.function_registry.lookupKey(self.entry_pc) == null) {
            return error.InvalidFileHeader;
        }

        return self;
    }

    fn parseLenient(
        allocator: std.mem.Allocator,
        bytes: []u8,
        headers: Headers,
        data: Data,
        sbpf_version: sbpf.Version,
        config: Config,
        loader: *const SyscallMap,
    ) !Elf {
        // Lenient parsing uses the v0 sbpf.Version parsing which differs from v1+ version passed in
        // https://github.com/anza-xyz/sbpf/blob/v0.10.0/src/elf.rs#L626-L630
        const version: sbpf.Version = switch (headers.header.e_flags) {
            sbpf.EM_SBPF_V1 => .reserved,
            else => .v0,
        };

        try validate(bytes, headers, data, version, config);

        const text_section = data.getShdrByName(headers, ".text") orelse
            return error.NoTextSection;

        // Double check text_section bounds
        const text_section_vaddr =
            if (version.enableElfVaddr() and text_section.sh_addr >= memory.RODATA_START)
                text_section.sh_addr
            else
                text_section.sh_addr +| memory.RODATA_START;
        const text_section_vaddr_end =
            if (version.rejectRodataStackOverlap())
                text_section_vaddr +| text_section.sh_size
            else
                text_section_vaddr;
        if (config.reject_broken_elfs and
            !version.enableElfVaddr() and
            text_section.sh_addr != text_section.sh_offset or
            text_section_vaddr_end > memory.STACK_START) return error.ValueOutOfBounds;

        var function_registry: Registry = .{};
        errdefer function_registry.deinit(allocator);

        try data.relocate(
            allocator,
            headers,
            bytes,
            loader,
            &function_registry,
            version,
            config,
        );

        const offset = headers.header.e_entry -| text_section.sh_addr;
        const entry_pc = std.math.divExact(u64, offset, 8) catch return error.InvalidEntrypoint;

        if (!version.enableStaticSyscalls()) {
            const hash = sbpf.hashSymbolName("entrypoint");
            if (function_registry.map.fetchOrderedRemove(hash)) |entry| {
                allocator.free(entry.value.name);
            }
        }

        _ = try function_registry.registerHashedLegacy(
            allocator,
            loader,
            !version.enableStaticSyscalls(),
            "entrypoint",
            entry_pc,
        );

        const ro_section = try data.parseRoSections(
            allocator,
            headers,
            config,
            version,
        );
        errdefer ro_section.deinit(allocator);

        return .{
            .bytes = bytes,
            .headers = headers,
            .data = data,
            .entry_pc = entry_pc,
            .version = sbpf_version,
            .function_registry = function_registry,
            .config = config,
            .ro_section = ro_section,
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

    /// Validates the Elf. Returns errors for issues encountered.
    fn validate(
        bytes: []u8,
        headers: Headers,
        data: Data,
        sbpf_version: sbpf.Version,
        config: Config,
    ) !void {
        const header = headers.header;

        // Ensure 64-bit class
        if (header.e_ident[elf.EI_CLASS] != elf.ELFCLASS64) {
            return error.WrongClass;
        }
        // Ensure little endian
        if (header.e_ident[elf.EI_DATA] != elf.ELFDATA2LSB) {
            return error.WrongEndianess;
        }
        // Ensure no OS_ABI was set
        if (header.e_ident[elf.EI_OSABI] != 0) {
            return error.WrongAbi;
        }
        // Ensure the ELF was compiled for BPF or possibly the custom SBPF machine number
        if (header.e_machine != elf.EM.BPF and @intFromEnum(header.e_machine) != sbpf.EM_SBPF) {
            return error.WrongMachine;
        }
        // Ensure that this is a `.so`, dynamic library file
        if (header.e_type != .DYN) {
            return error.NotDynElf;
        }

        // Check that the sbpf_version matches the config
        if (@intFromEnum(sbpf_version) < @intFromEnum(config.minimum_version) or
            @intFromEnum(sbpf_version) > @intFromEnum(config.maximum_version))
        {
            return error.UnsupportedSBPFVersion;
        }
        if (sbpf_version.enableElfVaddr()) {
            if (!config.optimize_rodata) {
                return error.UnsupportedSBPFVersion;
            }

            if (headers.phdrs.len >= 10) {
                return error.InvalidProgramHeader;
            }
        }

        // Ensure there is only one `.text` section
        {
            var count: u32 = 0;
            for (headers.shdrs) |shdr| {
                if (data.getSectionName(shdr.sh_name) catch null) |name| {
                    if (std.mem.eql(u8, name, ".text")) {
                        count +|= 1;
                    }
                }
            }
            if (count != 1) {
                return error.NotOneTextSection;
            }
        }

        // Writable sections are not supported in our usecase that will include
        // ".bss", and ".data" sections that are writable ".data.rel" is
        // allowed though.
        for (headers.shdrs) |shdr| {
            const name = data.getSectionName(shdr.sh_name) catch continue;
            if (std.mem.startsWith(u8, name, ".bss")) {
                return error.WritableSectionsNotSupported;
            }
            if (std.mem.startsWith(u8, name, ".data") and
                !std.mem.startsWith(u8, name, ".data.rel"))
            {
                const flags: SectionAttributes = @bitCast(shdr.sh_flags);
                if (flags.alloc or flags.write) {
                    return error.WritableSectionsNotSupported;
                }
            }
        }

        // Ensure all of the section headers are within bounds
        for (headers.shdrs) |shdr| {
            const start = shdr.sh_offset;
            const end = try std.math.add(u64, start, shdr.sh_size);

            const file_size = bytes.len;
            if (start > file_size or end > file_size) return error.SectionHeaderOutOfBounds;
        }

        // Ensure that the entry point is inside of the ".text" section
        const entrypoint = header.e_entry;
        const text_section_index = data.getShdrIndexByName(headers, ".text") orelse
            return error.NoTextSection;
        if (!inRangeOfShdrVaddr(headers, text_section_index, entrypoint)) {
            return error.EntrypointOutsideTextSection;
        }
    }

    pub fn deinit(self: *Elf, allocator: std.mem.Allocator) void {
        self.function_registry.deinit(allocator);
        self.ro_section.deinit(allocator);
    }

    pub fn getShdrIndexByName(self: Elf, name: []const u8) ?u32 {
        return self.data.getShdrIndexByName(self.headers, name);
    }

    pub fn getShdrByName(self: Elf, name: []const u8) ?elf.Elf64_Shdr {
        return self.data.getShdrByName(self.headers, name);
    }

    fn inRangeOfShdrVaddr(headers: Headers, index: usize, addr: usize) bool {
        const shdr = headers.shdrs[index];
        const sh_addr = shdr.sh_addr;
        const sh_size = shdr.sh_size;
        const offset = std.math.add(u64, sh_addr, sh_size) catch return false;
        return addr >= sh_addr and addr < offset;
    }

    fn inRangeOfPhdrVm(phdr: elf.Elf64_Phdr, addr: usize) bool {
        const p_vaddr = phdr.p_vaddr;
        const p_memsz = phdr.p_memsz;
        const offset = std.math.add(u64, p_vaddr, p_memsz) catch return false;
        return addr >= p_vaddr and addr < offset;
    }

    fn safeSlice(base: anytype, start: usize, len: usize) error{OutOfBounds}!@TypeOf(base) {
        if (start >= base.len) return error.OutOfBounds;
        const end = std.math.add(usize, start, len) catch return error.OutOfBounds;
        if (end > base.len) return error.OutOfBounds;
        return base[start..][0..len];
    }

    fn safeString(bytes: []const u8, offset: usize, limit: usize) ![:0]const u8 {
        if (offset >= bytes.len) return error.OutOfBounds;
        const slice = bytes[offset..][0..@min(bytes.len - offset, limit)];
        const end = std.mem.indexOfScalar(u8, slice, 0) orelse return error.StringTooLong;
        return @ptrCast(slice[0..end]);
    }

    /// The function is guarnteed to succeed, since `parse` already checks that
    /// the `.text` section exists and it's sized correctly.
    pub fn getInstructions(self: *const Elf) []align(1) const sbpf.Instruction {
        return self.data.getInstructions(self.headers) catch unreachable;
    }
};

test "parsing failing allocation" {
    const S = struct {
        fn foo(allocator: std.mem.Allocator) !void {
            const input_file = try std.fs.cwd().openFile(
                sig.ELF_DATA_DIR ++ "reloc_64_64.so",
                .{},
            );
            const bytes = try input_file.readToEndAlloc(allocator, sbpf.MAX_FILE_SIZE);
            defer allocator.free(bytes);

            var parsed = try Elf.parse(allocator, bytes, &.ALL_DISABLED, .{});
            defer parsed.deinit(allocator);
        }
    };

    const allocator = std.testing.allocator;
    try std.testing.checkAllAllocationFailures(allocator, S.foo, .{});
}

test "strict header empty" {
    const allocator = std.testing.allocator;
    var loader: SyscallMap = .ALL_DISABLED;
    try expectEqual(
        error.OutOfBounds,
        Elf.parse(allocator, &.{}, &loader, .{}),
    );
}

test "strict header version" {
    const allocator = std.testing.allocator;
    const input_file = try std.fs.cwd().openFile(sig.ELF_DATA_DIR ++ "strict_header.so", .{});
    const bytes = try input_file.readToEndAlloc(allocator, sbpf.MAX_FILE_SIZE);
    defer allocator.free(bytes);

    // set the e_flags to an invalid SBPF version
    bytes[0x0030] = 0xFF;

    var loader: SyscallMap = .ALL_DISABLED;
    try expectEqual(
        error.VersionUnsupported,
        Elf.parse(allocator, bytes, &loader, .{}),
    );
}

test "strict header functions" {
    const allocator = std.testing.allocator;
    const input_file = try std.fs.cwd().openFile(sig.ELF_DATA_DIR ++ "strict_header.so", .{});
    const bytes = try input_file.readToEndAlloc(allocator, sbpf.MAX_FILE_SIZE);
    defer allocator.free(bytes);

    var loader: SyscallMap = .ALL_DISABLED;
    var parsed = try Elf.parse(
        allocator,
        bytes,
        &loader,
        .{ .enable_symbol_and_section_labels = true },
    );
    defer parsed.deinit(allocator);

    const entrypoint = parsed.function_registry.lookupKey(0).?;
    try expect(std.mem.eql(u8, entrypoint.name, "entrypoint"));

    const foo = parsed.function_registry.lookupKey(2).?;
    try expect(std.mem.eql(u8, foo.name, "strict_header.foo"));
}

test "strict header corrupt file header" {
    const allocator = std.testing.allocator;
    const input_file = try std.fs.cwd().openFile(sig.ELF_DATA_DIR ++ "strict_header.so", .{});
    const bytes = try input_file.readToEndAlloc(allocator, sbpf.MAX_FILE_SIZE);
    defer allocator.free(bytes);

    const expected_results: [@sizeOf(elf.Elf64_Ehdr)]?error{
        InvalidFileHeader,
        OutOfBounds,
        Overlap,
        VersionUnsupported,
    } =
        .{error.InvalidFileHeader} ** 32 ++
        .{error.Overlap} ** 1 ++
        .{error.OutOfBounds} ** 15 ++
        .{error.VersionUnsupported} ** 4 ++
        .{error.InvalidFileHeader} ** 4 ++
        .{error.OutOfBounds} ** 2 ++
        .{error.InvalidFileHeader} ** 2 ++
        .{error.OutOfBounds} ** 2 ++
        .{error.InvalidFileHeader} ** 2;

    for (
        0..@sizeOf(elf.Elf64_Ehdr),
        expected_results,
    ) |offset, expected| {
        const copy = try allocator.dupe(u8, bytes);
        defer allocator.free(copy);
        copy[offset] = 0xAF;

        var loader: SyscallMap = .ALL_DISABLED;
        var result = Elf.parse(allocator, copy, &loader, .{});
        defer if (result) |*parsed| parsed.deinit(allocator) else |_| {};

        if (expected) |err| {
            try expectError(err, result);
        } else {
            try std.testing.expect(!std.meta.isError(result));
        }
    }
}

test "strict header corrupt program header" {
    const allocator = std.testing.allocator;
    const input_file = try std.fs.cwd().openFile(sig.ELF_DATA_DIR ++ "strict_header.so", .{});
    const bytes = try input_file.readToEndAlloc(allocator, sbpf.MAX_FILE_SIZE);
    defer allocator.free(bytes);

    const expected_results_readonly =
        .{error.InvalidProgramHeader} ** 48 ++
        .{null} ** 8;
    const expected_results_writable =
        .{error.InvalidProgramHeader} ** 40 ++
        .{null} ** 4 ++
        .{error.InvalidProgramHeader} ** 4 ++
        .{null} ** 8;

    const expected_results: [5][@sizeOf(elf.Elf64_Phdr)]?error{InvalidProgramHeader} = .{
        expected_results_readonly,
        expected_results_readonly,
        expected_results_writable,
        expected_results_writable,
        expected_results_readonly,
    };

    for (expected_results, 0..) |expected_result, header_index| {
        for (
            0..@sizeOf(elf.Elf64_Phdr),
            expected_result,
        ) |offset, expected| {
            const true_offset = @sizeOf(elf.Elf64_Ehdr) +
                (@sizeOf(elf.Elf64_Phdr) * header_index) +
                offset;

            const copy = try allocator.dupe(u8, bytes);
            defer allocator.free(copy);
            copy[true_offset] = 0xAF;

            var loader: SyscallMap = .ALL_DISABLED;
            var result = Elf.parse(allocator, copy, &loader, .{}) catch |e| switch (e) {
                error.OutOfBounds => error.InvalidProgramHeader,
                else => e,
            };

            defer if (result) |*parsed| parsed.deinit(allocator) else |_| {};

            if (expected) |err| {
                try expectError(err, result);
            } else {
                try std.testing.expect(!std.meta.isError(result));
            }
        }
    }
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
    var parsed = try Elf.parse(allocator, bytes, &loader, .{});
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

test "owned ro sections with sh offset" {
    const allocator = std.testing.allocator;
    const config: Config = .{
        .reject_broken_elfs = false,
    };
    const bytes: [512]u8 = .{0} ** 512;

    var rodata = newSection(20, 10, 7);
    rodata.sh_offset = 30;
    const headers: Elf.Headers = .{
        .bytes = &bytes,
        .header = undefined, // unused in our test
        .phdrs = &.{},
        .shdrs = &.{
            newSection(10, 10, 1),
            rodata,
        },
    };

    const data: Elf.Data = .{
        // NOTE: string table bytes must start and end with null terminator.
        // https://refspecs.linuxbase.org/elf/gabi4+/ch4.strtab.html
        .strtab = "\x00.text\x00" ++ ".rodata\x00",
        .relocations_table = &.{},
        .dynamic_table = .{0} ** elf.DT_NUM,
        .symbol_table = &.{},
    };

    const result = try data.parseRoSections(
        allocator,
        headers,
        config,
        .v0,
    );
    defer result.deinit(allocator);

    const owned = result.owned;
    try expectEqual(memory.RODATA_START + 10, owned.offset);
    try expectEqual(20, owned.data.len);
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
    var parsed = try Elf.parse(
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
    var parsed = try Elf.parse(allocator, bytes, &loader, .{
        .maximum_version = .v0, // parseLenient
        .enable_symbol_and_section_labels = true, // all symbols in registry codepath.
    });
    defer parsed.deinit(allocator);
}
