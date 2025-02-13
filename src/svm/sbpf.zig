//! Constants to do with Solana's sbpf
const std = @import("std");
const memory = @import("memory.zig");
const assert = std.debug.assert;

pub const EF_SBPF_v1: u32 = 0x20;

/// Solana BPF Elf Machine
pub const EM_SBPF: std.elf.Elf64_Half = 263;

// TODO(upgrade) these are in 0.14, we just haven't upgraded
pub const ELFOSABI_NONE: u8 = 0;
pub const EI_OSABI: u8 = 7;

pub const MAX_FILE_SIZE = 10 * 1024 * 1024;

pub const Version = enum(u32) {
    /// The "legacy" format
    v0,
    /// SIMD-0166
    v1,
    /// SIMD-0174, SIMD-0173
    v2,
    /// SIMD-0178, SIMD-0179, SIMD-0189
    v3,
    /// support other versions as well!
    _,

    /// Enable SIMD-0166: SBPF dynamic stack frames
    pub fn enableDynamicStackFrames(version: Version) bool {
        return version.gte(.v1);
    }

    /// Enable SIMD-0174: SBPF arithmetics improvements
    pub fn enablePqr(version: Version) bool {
        return version.gte(.v2);
    }
    /// ... SIMD-0174
    pub fn swapSubRegImmOperands(version: Version) bool {
        return version.gte(.v2);
    }
    /// ... SIMD-0174
    pub fn disableNegation(version: Version) bool {
        return version.gte(.v2);
    }

    /// Enable SIMD-0173: SBPF instruction encoding improvements
    pub fn callRegUsesSrcReg(version: Version) bool {
        return version.gte(.v2);
    }
    /// ... SIMD-0173
    pub fn disableLDDW(version: Version) bool {
        return version.gte(.v2);
    }
    pub fn moveMemoryInstructionClasses(version: Version) bool {
        return version.gte(.v2);
    }
    /// ... SIMD-0173
    pub fn enableLe(version: Version) bool {
        return version == .v0;
    }

    /// Enable SIMD-0178: SBPF Static Syscalls
    /// Enable SIMD-0179: SBPF stricter verification constraints
    pub fn enableStaticSyscalls(version: Version) bool {
        return version.gte(.v3);
    }
    /// Enable SIMD-0189: SBPF stricter ELF headers
    pub fn enableStricterElfHeaders(version: Version) bool {
        return version.gte(.v3);
    }
    /// ... SIMD-0189
    pub fn enableLowerBytecodeVaddr(version: Version) bool {
        return version.gte(.v3);
    }

    /// Ensure that rodata sections don't exceed their maximum allowed size and
    /// overlap with the stack
    pub fn rejectRodataStackOverlap(version: Version) bool {
        return version != .v0;
    }

    /// Allow sh_addr != sh_offset in elf sections.
    pub fn enableElfVaddr(version: Version) bool {
        return version != .v0;
    }

    fn gte(version: Version, other: Version) bool {
        return @intFromEnum(version) >= @intFromEnum(other);
    }
};

pub const Instruction = packed struct(u64) {
    opcode: OpCode,
    dst: Register,
    src: Register,
    off: i16,
    imm: u32,

    pub const OpCode = enum(u8) {
        /// BPF opcode: `lddw dst, imm` /// `dst = imm`. [DEPRECATED]
        ld_dw_imm = ld | imm | dw,
        /// bpf opcode: `ldxb dst, [src + off]` /// `dst = (src + off) as u8`.
        ld_b_reg = ldx | mem | b,
        /// bpf opcode: `ldxh dst, [src + off]` /// `dst = (src + off) as u16`.
        ld_h_reg = ldx | mem | h,
        /// bpf opcode: `ldxw dst, [src + off]` /// `dst = (src + off) as u32`.
        ld_w_reg = ldx | mem | w,
        /// bpf opcode: `ldxdw dst, [src + off]` /// `dst = (src + off) as u64`.
        ld_dw_reg = ldx | mem | dw,
        /// bpf opcode: `stb [dst + off], imm` /// `(dst + offset) as u8 = imm`.
        st_b_imm = st | mem | b,
        /// bpf opcode: `sth [dst + off], imm` /// `(dst + offset) as u16 = imm`.
        st_h_imm = st | mem | h,
        /// bpf opcode: `stw [dst + off], imm` /// `(dst + offset) as u32 = imm`.
        st_w_imm = st | mem | w,
        /// bpf opcode: `stdw [dst + off], imm` /// `(dst + offset) as u64 = imm`.
        st_dw_imm = st | mem | dw,
        /// bpf opcode: `stxb [dst + off], src` /// `(dst + offset) as u8 = src`.
        st_b_reg = stx | mem | b,
        /// bpf opcode: `stxh [dst + off], src` /// `(dst + offset) as u16 = src`.
        st_h_reg = stx | mem | h,
        /// bpf opcode: `stxw [dst + off], src` /// `(dst + offset) as u32 = src`.
        st_w_reg = stx | mem | w,
        /// bpf opcode: `stxdw [dst + off], src` /// `(dst + offset) as u64 = src`.
        st_dw_reg = stx | mem | dw,

        /// bpf opcode: `add32 dst, imm` /// `dst += imm`.
        add32_imm = alu32 | k | add,
        /// bpf opcode: `add32 dst, src` /// `dst += src`.
        add32_reg = alu32 | x | add,
        /// bpf opcode: `sub32 dst, imm` /// `dst = imm - dst`.
        sub32_imm = alu32 | k | sub,
        /// bpf opcode: `sub32 dst, src` /// `dst -= src`.
        sub32_reg = alu32 | x | sub,

        /// bpf opcode: `mul32 dst, imm` /// `dst *= imm`.
        mul32_imm = alu32 | k | mul,

        /// bpf opcode: `mul32 dst, src` /// `dst *= src`.
        mul32_reg = alu32 | x | mul,
        /// bpf opcode: `div32 dst, imm` /// `dst /= imm`.
        div32_imm = alu32 | k | div,
        /// bpf opcode: `div32 dst, src` /// `dst /= src`.
        div32_reg = alu32 | x | div,

        /// bpf opcode: `or32 dst, imm` /// `dst |= imm`.
        or32_imm = alu32 | k | @"or",
        /// bpf opcode: `or32 dst, src` /// `dst |= src`.
        or32_reg = alu32 | x | @"or",
        /// bpf opcode: `and32 dst, imm` /// `dst &= imm`.
        and32_imm = alu32 | k | @"and",
        /// bpf opcode: `and32 dst, src` /// `dst &= src`.
        and32_reg = alu32 | x | @"and",
        /// bpf opcode: `lsh32 dst, imm` /// `dst <<= imm`.
        lsh32_imm = alu32 | k | lsh,
        /// bpf opcode: `lsh32 dst, src` /// `dst <<= src`.
        lsh32_reg = alu32 | x | lsh,
        /// bpf opcode: `rsh32 dst, imm` /// `dst >>= imm`.
        rsh32_imm = alu32 | k | rsh,
        /// bpf opcode: `rsh32 dst, src` /// `dst >>= src`.
        rsh32_reg = alu32 | x | rsh,

        /// bpf opcode: `neg32 dst` /// `dst = -dst`.
        neg32 = alu32 | neg,

        /// bpf opcode: `mod32 dst, imm` /// `dst %= imm`.
        mod32_imm = alu32 | k | mod,
        /// bpf opcode: `mod32 dst, src` /// `dst %= src`.
        mod32_reg = alu32 | x | mod,

        /// bpf opcode: `xor32 dst, imm` /// `dst ^= imm`.
        xor32_imm = alu32 | k | xor,
        /// bpf opcode: `xor32 dst, src` /// `dst ^= src`.
        xor32_reg = alu32 | x | xor,
        /// bpf opcode: `mov32 dst, imm` /// `dst = imm`.
        mov32_imm = alu32 | k | mov,
        /// bpf opcode: `mov32 dst, src` /// `dst = src`.
        mov32_reg = alu32 | x | mov,
        /// bpf opcode: `arsh32 dst, imm` /// `dst >>= imm (arithmetic)`.
        arsh32_imm = alu32 | k | arsh,
        /// bpf opcode: `arsh32 dst, src` /// `dst >>= src (arithmetic)`.
        arsh32_reg = alu32 | x | arsh,

        /// bpf opcode: `le dst` /// `dst = htole<imm>(dst), with imm in {16, 32, 64}`.
        le = alu32 | k | end,
        /// bpf opcode: `be dst` /// `dst = htobe<imm>(dst), with imm in {16, 32, 64}`.
        be = alu32 | x | end,

        /// bpf opcode: `add64 dst, imm` /// `dst += imm`.
        add64_imm = alu64 | k | add,
        /// bpf opcode: `add64 dst, src` /// `dst += src`.
        add64_reg = alu64 | x | add,
        /// bpf opcode: `sub64 dst, imm` /// `dst -= imm`.
        sub64_imm = alu64 | k | sub,
        /// bpf opcode: `sub64 dst, src` /// `dst -= src`.
        sub64_reg = alu64 | x | sub,

        /// bpf opcode: `mul64 dst, imm` /// `dst *= imm`.
        mul64_imm = alu64 | k | mul,
        /// bpf opcode: `mul64 dst, src` /// `dst *= src`.
        mul64_reg = alu64 | x | mul,
        /// bpf opcode: `div64 dst, imm` /// `dst /= imm`.
        div64_imm = alu64 | k | div,
        /// bpf opcode: `div64 dst, src` /// `dst /= src`.
        div64_reg = alu64 | x | div,

        /// bpf opcode: `or64 dst, imm` /// `dst |= imm`.
        or64_imm = alu64 | k | @"or",
        /// bpf opcode: `or64 dst, src` /// `dst |= src`.
        or64_reg = alu64 | x | @"or",
        /// bpf opcode: `and64 dst, imm` /// `dst &= imm`.
        and64_imm = alu64 | k | @"and",
        /// bpf opcode: `and64 dst, src` /// `dst &= src`.
        and64_reg = alu64 | x | @"and",
        /// bpf opcode: `lsh64 dst, imm` /// `dst <<= imm`.
        lsh64_imm = alu64 | k | lsh,
        /// bpf opcode: `lsh64 dst, src` /// `dst <<= src`.
        lsh64_reg = alu64 | x | lsh,
        /// bpf opcode: `rsh64 dst, imm` /// `dst >>= imm`.
        rsh64_imm = alu64 | k | rsh,
        /// bpf opcode: `rsh64 dst, src` /// `dst >>= src`.
        rsh64_reg = alu64 | x | rsh,

        /// bpf opcode: `neg64 dst` /// `dst = -dst`.
        neg64 = alu64 | neg,

        /// bpf opcode: `mod64 dst, imm` /// `dst %= imm`.
        mod64_imm = alu64 | k | mod,
        /// bpf opcode: `mod64 dst, src` /// `dst %= src`.
        mod64_reg = alu64 | x | mod,

        /// bpf opcode: `xor64 dst, imm` /// `dst ^= imm`.
        xor64_imm = alu64 | k | xor,
        /// bpf opcode: `xor64 dst, src` /// `dst ^= src`.
        xor64_reg = alu64 | x | xor,
        /// bpf opcode: `mov64 dst, imm` /// `dst = imm`.
        mov64_imm = alu64 | k | mov,
        /// bpf opcode: `mov64 dst, src` /// `dst = src`.
        mov64_reg = alu64 | x | mov,
        /// bpf opcode: `arsh64 dst, imm` /// `dst >>= imm (arithmetic)`.
        arsh64_imm = alu64 | k | arsh,
        /// bpf opcode: `arsh64 dst, src` /// `dst >>= src (arithmetic)`.
        arsh64_reg = alu64 | x | arsh,
        /// bpf opcode: `hor64 dst, imm` /// `dst |= imm << 32`.
        hor64_imm = alu64 | k | hor,

        /// bpf opcode: `lmul32 dst, imm` /// `dst *= (dst * imm) as u32`.
        lmul32_imm = pqr | k | lmul,
        /// bpf opcode: `lmul32 dst, src` /// `dst *= (dst * src) as u32`.
        lmul32_reg = pqr | x | lmul,
        /// bpf opcode: `udiv32 dst, imm` /// `dst /= imm`.
        udiv32_imm = pqr | k | udiv,
        /// bpf opcode: `udiv32 dst, src` /// `dst /= src`.
        udiv32_reg = pqr | x | udiv,
        /// bpf opcode: `urem32 dst, imm` /// `dst %= imm`.
        urem32_imm = pqr | k | urem,
        /// bpf opcode: `urem32 dst, src` /// `dst %= src`.
        urem32_reg = pqr | x | urem,
        /// bpf opcode: `sdiv32 dst, imm` /// `dst /= imm`.
        sdiv32_imm = pqr | k | sdiv,
        /// bpf opcode: `sdiv32 dst, src` /// `dst /= src`.
        sdiv32_reg = pqr | x | sdiv,
        /// bpf opcode: `srem32 dst, imm` /// `dst %= imm`.
        srem32_imm = pqr | k | srem,
        /// bpf opcode: `srem32 dst, src` /// `dst %= src`.
        srem32_reg = pqr | x | srem,

        /// bpf opcode: `lmul64 dst, imm` /// `dst = (dst * imm) as u64`.
        lmul64_imm = pqr | b | k | lmul,
        /// bpf opcode: `lmul64 dst, src` /// `dst = (dst * src) as u64`.
        lmul64_reg = pqr | b | x | lmul,
        /// bpf opcode: `uhmul64 dst, imm` /// `dst = (dst * imm) >> 64`.
        uhmul64_imm = pqr | b | k | uhmul,
        /// bpf opcode: `uhmul64 dst, src` /// `dst = (dst * src) >> 64`.
        uhmul64_reg = pqr | b | x | uhmul,
        /// bpf opcode: `udiv64 dst, imm` /// `dst /= imm`.
        udiv64_imm = pqr | b | k | udiv,
        /// bpf opcode: `udiv64 dst, src` /// `dst /= src`.
        udiv64_reg = pqr | b | x | udiv,
        /// bpf opcode: `urem64 dst, imm` /// `dst %= imm`.
        urem64_imm = pqr | b | k | urem,
        /// bpf opcode: `urem64 dst, src` /// `dst %= src`.
        urem64_reg = pqr | b | x | urem,
        /// bpf opcode: `shmul64 dst, imm` /// `dst = (dst * imm) >> 64`.
        shmul64_imm = pqr | b | k | shmul,
        /// bpf opcode: `shmul64 dst, src` /// `dst = (dst * src) >> 64`.
        shmul64_reg = pqr | b | x | shmul,
        /// bpf opcode: `sdiv64 dst, imm` /// `dst /= imm`.
        sdiv64_imm = pqr | b | k | sdiv,
        /// bpf opcode: `sdiv64 dst, src` /// `dst /= src`.
        sdiv64_reg = pqr | b | x | sdiv,
        /// bpf opcode: `srem64 dst, imm` /// `dst %= imm`.
        srem64_imm = pqr | b | k | srem,
        /// bpf opcode: `srem64 dst, src` /// `dst %= src`.
        srem64_reg = pqr | b | x | srem,

        /// bpf opcode: `ja +off` /// `pc += off`.
        ja = jmp | 0x0,
        /// bpf opcode: `jeq dst, imm, +off` /// `pc += off if dst == imm`.
        jeq_imm = jmp | k | jeq,
        /// bpf opcode: `jeq dst, src, +off` /// `pc += off if dst == src`.
        jeq_reg = jmp | x | jeq,
        /// bpf opcode: `jgt dst, imm, +off` /// `pc += off if dst > imm`.
        jgt_imm = jmp | k | jgt,
        /// bpf opcode: `jgt dst, src, +off` /// `pc += off if dst > src`.
        jgt_reg = jmp | x | jgt,
        /// bpf opcode: `jge dst, imm, +off` /// `pc += off if dst >= imm`.
        jge_imm = jmp | k | jge,
        /// bpf opcode: `jge dst, src, +off` /// `pc += off if dst >= src`.
        jge_reg = jmp | x | jge,
        /// bpf opcode: `jlt dst, imm, +off` /// `pc += off if dst < imm`.
        jlt_imm = jmp | k | jlt,
        /// bpf opcode: `jlt dst, src, +off` /// `pc += off if dst < src`.
        jlt_reg = jmp | x | jlt,
        /// bpf opcode: `jle dst, imm, +off` /// `pc += off if dst <= imm`.
        jle_imm = jmp | k | jle,
        /// bpf opcode: `jle dst, src, +off` /// `pc += off if dst <= src`.
        jle_reg = jmp | x | jle,
        /// bpf opcode: `jset dst, imm, +off` /// `pc += off if dst & imm`.
        jset_imm = jmp | k | jset,
        /// bpf opcode: `jset dst, src, +off` /// `pc += off if dst & src`.
        jset_reg = jmp | x | jset,
        /// bpf opcode: `jne dst, imm, +off` /// `pc += off if dst != imm`.
        jne_imm = jmp | k | jne,
        /// bpf opcode: `jne dst, src, +off` /// `pc += off if dst != src`.
        jne_reg = jmp | x | jne,
        /// bpf opcode: `jsgt dst, imm, +off` /// `pc += off if dst > imm (signed)`.
        jsgt_imm = jmp | k | jsgt,
        /// bpf opcode: `jsgt dst, src, +off` /// `pc += off if dst > src (signed)`.
        jsgt_reg = jmp | x | jsgt,
        /// bpf opcode: `jsge dst, imm, +off` /// `pc += off if dst >= imm (signed)`.
        jsge_imm = jmp | k | jsge,
        /// bpf opcode: `jsge dst, src, +off` /// `pc += off if dst >= src (signed)`.
        jsge_reg = jmp | x | jsge,
        /// bpf opcode: `jslt dst, imm, +off` /// `pc += off if dst < imm (signed)`.
        jslt_imm = jmp | k | jslt,
        /// bpf opcode: `jslt dst, src, +off` /// `pc += off if dst < src (signed)`.
        jslt_reg = jmp | x | jslt,
        /// bpf opcode: `jsle dst, imm, +off` /// `pc += off if dst <= imm (signed)`.
        jsle_imm = jmp | k | jsle,
        /// bpf opcode: `jsle dst, src, +off` /// `pc += off if dst <= src (signed)`.
        jsle_reg = jmp | x | jsle,

        /// bpf opcode: `call imm` /// syscall function call to syscall with key `imm`.
        call_imm = jmp | call,
        /// bpf opcode: tail call.
        call_reg = jmp | x | call,

        /// bpf opcode: `exit` /// `return r0`. /// valid only until sbpfv3
        exit = jmp | exit_code,
        @"return" = jmp | x | exit_code,
        _,

        pub fn isReg(opcode: OpCode) bool {
            const is_reg_bit: u1 = @truncate(@intFromEnum(opcode) >> 3);
            return @bitCast(is_reg_bit);
        }

        pub fn is64(opcode: OpCode) bool {
            const class: u3 = @truncate(@intFromEnum(opcode));
            return switch (class) {
                alu64 => true,
                alu32 => false,
                else => std.debug.panic("TODO: {s}", .{@tagName(opcode)}),
            };
        }

        pub fn accessType(opcode: OpCode) memory.MemoryState {
            const class: u3 = @truncate(@intFromEnum(opcode));
            return switch (class) {
                ld, ldx => .constant,
                st, stx => .mutable,
                else => std.debug.panic("TODO: {s}", .{@tagName(opcode)}),
            };
        }
    };

    const Entry = struct {
        inst: InstructionType,
        opc: u8,
    };

    const InstructionType = union(enum) {
        alu_binary,
        alu_unary,
        load_dw_imm,
        load_abs,
        load_ind,
        load_reg,
        store_imm,
        store_reg,
        jump_unconditional,
        jump_conditional,
        syscall,
        call_imm,
        call_reg,
        endian: u32,
        no_operand,
    };

    pub const map = std.StaticStringMap(Entry).initComptime(&.{
        // zig fmt: off
        .{ "mov"  , .{ .inst = .alu_binary, .opc = mov | alu64  } }, 
        .{ "mov64", .{ .inst = .alu_binary, .opc = mov | alu64  } },
        .{ "mov32", .{ .inst = .alu_binary, .opc = mov | alu32  } },
        
        .{ "add"  , .{ .inst = .alu_binary, .opc = add | alu64  } },
        .{ "add64", .{ .inst = .alu_binary, .opc = add | alu64  } },
        .{ "add32", .{ .inst = .alu_binary, .opc = add | alu32  } },

        .{ "mul"  , .{ .inst = .alu_binary, .opc = mul | alu64  } },
        .{ "mul64", .{ .inst = .alu_binary, .opc = mul | alu64  } },
        .{ "mul32", .{ .inst = .alu_binary, .opc = mul | alu32  } },

        .{ "sub"  , .{ .inst = .alu_binary, .opc = sub | alu64  } },
        .{ "sub64", .{ .inst = .alu_binary, .opc = sub | alu64  } },
        .{ "sub32", .{ .inst = .alu_binary, .opc = sub | alu32  } },

        .{ "div"  , .{ .inst = .alu_binary, .opc = div | alu64  } },
        .{ "div64", .{ .inst = .alu_binary, .opc = div | alu64  } },
        .{ "div32", .{ .inst = .alu_binary, .opc = div | alu32  } },
        
        .{ "xor"  , .{ .inst = .alu_binary, .opc = xor | alu64  } },
        .{ "xor64", .{ .inst = .alu_binary, .opc = xor | alu64  } },
        .{ "xor32", .{ .inst = .alu_binary, .opc = xor | alu32  } },

        .{ "or"  , .{ .inst = .alu_binary, .opc = @"or" | alu64  } },
        .{ "or64", .{ .inst = .alu_binary, .opc = @"or" | alu64  } },
        .{ "or32", .{ .inst = .alu_binary, .opc = @"or" | alu32  } },

        .{ "and"  , .{ .inst = .alu_binary, .opc = @"and" | alu64  } },
        .{ "and64", .{ .inst = .alu_binary, .opc = @"and" | alu64  } },
        .{ "and32", .{ .inst = .alu_binary, .opc = @"and" | alu32  } },

        .{ "mod"  , .{ .inst = .alu_binary, .opc = mod | alu64  } },
        .{ "mod64", .{ .inst = .alu_binary, .opc = mod | alu64  } },
        .{ "mod32", .{ .inst = .alu_binary, .opc = mod | alu32  } },

        .{ "arsh"  , .{ .inst = .alu_binary, .opc = arsh | alu64  } },
        .{ "arsh64", .{ .inst = .alu_binary, .opc = arsh | alu64  } },
        .{ "arsh32", .{ .inst = .alu_binary, .opc = arsh | alu32  } },

        .{ "lsh"  , .{ .inst = .alu_binary, .opc = lsh | alu64 } },
        .{ "lsh64", .{ .inst = .alu_binary, .opc = lsh | alu64 } },
        .{ "lsh32", .{ .inst = .alu_binary, .opc = lsh | alu32 } },

        .{ "rsh"  , .{ .inst = .alu_binary, .opc = rsh | alu64 } },
        .{ "rsh64", .{ .inst = .alu_binary, .opc = rsh | alu64 } },
        .{ "rsh32", .{ .inst = .alu_binary, .opc = rsh | alu32 } },

        .{ "hor64", .{ .inst = .alu_binary, .opc = hor | alu64 } },

        .{ "lmul"  , .{ .inst = .alu_binary, .opc = pqr | lmul | b } },
        .{ "lmul64", .{ .inst = .alu_binary, .opc = pqr | lmul | b } },
        .{ "lmul32", .{ .inst = .alu_binary, .opc = pqr | lmul     } },

        .{ "uhmul"  , .{ .inst = .alu_binary, .opc = pqr | uhmul | b } },
        .{ "uhmul64", .{ .inst = .alu_binary, .opc = pqr | uhmul | b } },
        .{ "uhmul32", .{ .inst = .alu_binary, .opc = pqr | uhmul     } },

        .{ "shmul"  , .{ .inst = .alu_binary, .opc = pqr | shmul | b } },
        .{ "shmul64", .{ .inst = .alu_binary, .opc = pqr | shmul | b } },
        .{ "shmul32", .{ .inst = .alu_binary, .opc = pqr | shmul     } },

        .{ "udiv"  , .{ .inst = .alu_binary, .opc = pqr | udiv | b } },
        .{ "udiv64", .{ .inst = .alu_binary, .opc = pqr | udiv | b } },
        .{ "udiv32", .{ .inst = .alu_binary, .opc = pqr | udiv     } },

        .{ "urem"  , .{ .inst = .alu_binary, .opc = pqr | urem | b } },
        .{ "urem64", .{ .inst = .alu_binary, .opc = pqr | urem | b } },
        .{ "urem32", .{ .inst = .alu_binary, .opc = pqr | urem     } },

        .{ "sdiv"  , .{ .inst = .alu_binary, .opc = pqr | sdiv | b } },
        .{ "sdiv64", .{ .inst = .alu_binary, .opc = pqr | sdiv | b } },
        .{ "sdiv32", .{ .inst = .alu_binary, .opc = pqr | sdiv     } },

        .{ "srem"  , .{ .inst = .alu_binary, .opc = pqr | srem | b } },
        .{ "srem64", .{ .inst = .alu_binary, .opc = pqr | srem | b } },
        .{ "srem32", .{ .inst = .alu_binary, .opc = pqr | srem     } },
        
        .{ "neg"  , .{ .inst = .alu_unary,  .opc = neg | alu64  } },
        .{ "neg64", .{ .inst = .alu_unary,  .opc = neg | alu64  } },
        .{ "neg32", .{ .inst = .alu_unary,  .opc = neg | alu32  } },

        .{ "ja"   , .{ .inst = .jump_unconditional, .opc = ja | jmp } },

        .{ "jeq"  , .{ .inst = .jump_conditional, .opc = jeq  |  jmp  } },
        .{ "jgt"  , .{ .inst = .jump_conditional, .opc = jgt  |  jmp  } },
        .{ "jge"  , .{ .inst = .jump_conditional, .opc = jge  |  jmp  } },
        .{ "jlt"  , .{ .inst = .jump_conditional, .opc = jlt  |  jmp  } },
        .{ "jle"  , .{ .inst = .jump_conditional, .opc = jle  |  jmp  } },
        .{ "jset" , .{ .inst = .jump_conditional, .opc = jset |  jmp  } },
        .{ "jne"  , .{ .inst = .jump_conditional, .opc = jne  |  jmp  } },
        .{ "jsgt" , .{ .inst = .jump_conditional, .opc = jsgt |  jmp  } },
        .{ "jsge" , .{ .inst = .jump_conditional, .opc = jsge |  jmp  } },
        .{ "jslt" , .{ .inst = .jump_conditional, .opc = jslt |  jmp  } },
        .{ "jsle" , .{ .inst = .jump_conditional, .opc = jsle |  jmp  } },

        .{ "ldxb"  , .{ .inst = .load_reg,         .opc = mem | ldx | b   } },
        .{ "ldxh"  , .{ .inst = .load_reg,         .opc = mem | ldx | h   } },
        .{ "ldxw"  , .{ .inst = .load_reg,         .opc = mem | ldx | w   } },
        .{ "ldxdw" , .{ .inst = .load_reg,         .opc = mem | ldx | dw  } },

        .{ "stb"  , .{ .inst = .store_imm,        .opc = mem | st | b   } },
        .{ "sth"  , .{ .inst = .store_imm,        .opc = mem | st | h   } },
        .{ "stw"  , .{ .inst = .store_imm,        .opc = mem | st | w   } },
        .{ "stdw" , .{ .inst = .store_imm,        .opc = mem | st | dw  } },

        .{ "stxb"  , .{ .inst = .store_reg,        .opc = mem | stx | b   } },
        .{ "stxh"  , .{ .inst = .store_reg,        .opc = mem | stx | h   } },
        .{ "stxw"  , .{ .inst = .store_reg,        .opc = mem | stx | w   } },
        .{ "stxdw" , .{ .inst = .store_reg,        .opc = mem | stx | dw  } },

        .{ "be16", .{ .inst = .{.endian = 16 }, .opc = alu32 | x | end } },
        .{ "be32", .{ .inst = .{.endian = 32 }, .opc = alu32 | x | end } },
        .{ "be64", .{ .inst = .{.endian = 64 }, .opc = alu32 | x | end } },

        .{ "le16", .{ .inst = .{.endian = 16 }, .opc = alu32 | k | end } },
        .{ "le32", .{ .inst = .{.endian = 32 }, .opc = alu32 | k | end } },
        .{ "le64", .{ .inst = .{.endian = 64 }, .opc = alu32 | k | end } },

        .{ "exit"  , .{ .inst = .no_operand,       .opc = jmp | exit_code } },
        .{ "return", .{ .inst = .no_operand,       .opc = jmp | x | exit_code } },
        .{ "lddw"  , .{ .inst = .load_dw_imm,      .opc = ld  | imm | dw  } },
        .{ "call"  , .{ .inst = .call_imm,         .opc = jmp | call      } },
        .{ "callx" , .{ .inst = .call_reg,         .opc = jmp | call | x  } },

        // zig fmt: on
    });

    /// load from immediate
    pub const ld = 0b0000;
    /// load from register
    pub const ldx = 0b0001;
    /// store immediate
    pub const st = 0b0010;
    /// store valu from register
    pub const stx = 0b0011;
    /// 32 bit arithmetic
    pub const alu32 = 0b0100;
    /// control flow
    pub const jmp = 0b0101;
    /// product / quotient / remainder
    pub const pqr = 0b0110;
    /// 64 bit arithmetic
    pub const alu64 = 0b0111;

    /// source operand modifier: `src` register
    pub const x = 0b1000;
    /// source operand modifier: 32-bit immediate value.
    pub const k = 0b0000;

    /// size modifier: word (4 bytes).
    pub const w: u8 = 0x00;
    /// size modifier: half-word (2 bytes).
    pub const h: u8 = 0x08;
    /// size modifier: byte (1 byte).
    pub const b: u8 = 0x10;
    /// size modifier: double word (8 bytes).
    pub const dw: u8 = 0x18;
    /// size modifier: 1 byte.
    pub const @"1b": u8 = 0x20;
    /// size modifier: 2 bytes.
    pub const @"2b": u8 = 0x30;
    /// size modifier: 4 bytes.
    pub const @"4b": u8 = 0x80;
    /// size modifier: 8 bytes.
    pub const @"8b": u8 = 0x90;

    /// jmp operation code: jump always
    pub const ja: u8 = 0x00;
    ///  jmp operation code: jump if equal.
    pub const jeq: u8 = 0x10;
    ///  jmp operation code: jump if greater than.
    pub const jgt: u8 = 0x20;
    ///  jmp operation code: jump if greater or equal.
    pub const jge: u8 = 0x30;
    ///  jmp operation code: jump if `src` & `reg`.
    pub const jset: u8 = 0x40;
    ///  jmp operation code: jump if not equal.
    pub const jne: u8 = 0x50;
    ///  jmp operation code: jump if greater than (signed).
    pub const jsgt: u8 = 0x60;
    ///  jmp operation code: jump if greater or equal (signed).
    pub const jsge: u8 = 0x70;
    ///  jmp operation code: syscall function call.
    pub const call: u8 = 0x80;
    ///  jmp operation code: return from program.
    pub const exit_code: u8 = 0x90;
    ///  jmp operation code: static syscall.
    pub const syscall: u8 = 0x90;
    ///  jmp operation code: jump if lower than.
    pub const jlt: u8 = 0xa0;
    ///  jmp operation code: jump if lower or equal.
    pub const jle: u8 = 0xb0;
    ///  jmp operation code: jump if lower than (signed).
    pub const jslt: u8 = 0xc0;
    ///  jmp operation code: jump if lower or equal (signed).
    pub const jsle: u8 = 0xd0;

    /// mode modifier:
    pub const imm = 0b0000000;
    pub const abs = 0b0100000;
    pub const mem = 0b1100000;

    /// alu/alu64 operation code: addition.
    pub const add: u8 = 0x00;
    /// alu/alu64 operation code: subtraction.
    pub const sub: u8 = 0x10;

    /// alu/alu64 operation code: multiplication.
    pub const mul: u8 = 0x20;
    /// alu/alu64 operation code: division.
    pub const div: u8 = 0x30;

    /// alu/alu64 operation code: or.
    pub const @"or": u8 = 0x40;
    /// alu/alu64 operation code: and.
    pub const @"and": u8 = 0x50;
    /// alu/alu64 operation code: left shift.
    pub const lsh: u8 = 0x60;
    /// alu/alu64 operation code: right shift.
    pub const rsh: u8 = 0x70;

    /// alu/alu64 operation code: negation.
    pub const neg: u8 = 0x80;
    /// alu/alu64 operation code: modulus.
    pub const mod: u8 = 0x90;

    /// alu/alu64 operation code: exclusive or.
    pub const xor: u8 = 0xa0;
    /// alu/alu64 operation code: move.
    pub const mov: u8 = 0xb0;
    /// alu/alu64 operation code: sign extending right shift.
    pub const arsh: u8 = 0xc0;
    /// alu/alu64 operation code: endianness conversion.
    pub const end: u8 = 0xd0;
    /// alu/alu64 operation code: high or
    pub const hor: u8 = 0xf0;

    /// pqr operation code: unsigned high multiplication.
    pub const uhmul: u8 = 0x20;
    /// pqr operation code: unsigned division quotient.
    pub const udiv: u8 = 0x40;
    /// pqr operation code: unsigned division remainder.
    pub const urem: u8 = 0x60;
    /// pqr operation code: low multiplication.
    pub const lmul: u8 = 0x80;
    /// pqr operation code: signed high multiplication.
    pub const shmul: u8 = 0xa0;
    /// pqr operation code: signed division quotient.
    pub const sdiv: u8 = 0xc0;
    /// pqr operation code: signed division remainder.
    pub const srem: u8 = 0xe0;

    pub const Register = enum(u4) {
        /// Return Value
        r0,
        /// Argument 0
        r1,
        /// Argument 1
        r2,
        /// Argument 2
        r3,
        /// Argument 3
        r4,
        /// Argument 4 or stack-spill ptr
        r5,
        /// Call-preserved
        r6,
        /// Call-preserved
        r7,
        /// Call-preserved
        r8,
        /// Call-preserved
        r9,
        /// Frame pointer, System register
        r10,
        /// Stack pointer, System register
        r11,
        /// Program counter, Hidden register
        pc,
    };

    pub fn format(
        inst: Instruction,
        comptime fmt: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        comptime assert(fmt.len == 0);
        try writer.print("{s}", .{@tagName(inst.opcode)});
    }
};

pub fn hashSymbolName(name: []const u8) u32 {
   return std.hash.Murmur3_32.hashWithSeed(name, 0);
}
