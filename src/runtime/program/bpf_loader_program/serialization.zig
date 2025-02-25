const std = @import("std");
const sig = @import("../../../sig.zig");

const program = sig.runtime.program;
const svm = sig.svm;

const Pubkey = sig.core.Pubkey;
const InstructionError = sig.core.instruction.InstructionError;

const InstructionContext = sig.runtime.InstructionContext;
const BorrowedAccount = sig.runtime.BorrowedAccount;

const Region = sig.svm.memory.Region;

/// Solana BPF version flag
pub const EF_SBPF_V2: u32 = 0x20;
/// Maximum number of instructions in an eBPF program.
pub const PROG_MAX_INSNS: usize = 65_536;
/// Size of an eBPF instructions, in bytes.
pub const INSN_SIZE: usize = 8;
/// Frame pointer register
pub const FRAME_PTR_REG: usize = 10;
/// First scratch register
pub const FIRST_SCRATCH_REG: usize = 6;
/// Number of scratch registers
pub const SCRATCH_REGS: usize = 4;
/// Alignment of the memory regions in host address space in bytes
pub const HOST_ALIGN: usize = 16;
/// Upper half of a pointer is the region index, lower half the virtual address inside that region.
pub const VIRTUAL_ADDRESS_BITS: usize = 32;

/// Size (and alignment) of a memory region
pub const MM_REGION_SIZE: u64 = 1 << VIRTUAL_ADDRESS_BITS;
/// Virtual address of the bytecode region (in SBPFv3)
pub const MM_BYTECODE_START: u64 = 0;
/// Virtual address of the readonly data region (also contains the bytecode until SBPFv3)
pub const MM_RODATA_START: u64 = MM_REGION_SIZE;
/// Virtual address of the stack region
pub const MM_STACK_START: u64 = MM_REGION_SIZE * 2;
/// Virtual address of the heap region
pub const MM_HEAP_START: u64 = MM_REGION_SIZE * 3;
/// Virtual address of the input region
pub const MM_INPUT_START: u64 = MM_REGION_SIZE * 4;

pub const SerializedAccount = union(enum) {
    account: struct { u16, BorrowedAccount },
    duplicate: u16,
};

pub const SerializedAccountMeta = struct {
    original_data_len: usize,
    vm_data_addr: u64,
    vm_key_addr: u64,
    vm_lamports_addr: u64,
    vm_owner_addr: u64,
};

pub const Serializer = struct {
    allocator: std.mem.Allocator,
    buffer: std.ArrayListUnmanaged(u8),
    regions: std.BoundedArray(Region, 4),
    vaddr: u64,
    region_start: usize,
    aligned: bool,
    copy_account_data: bool,

    pub fn init(
        allocator: std.mem.Allocator,
        size: usize,
        region_start: usize,
        aligned: bool,
        copy_account_data: bool,
    ) !Serializer {
        // TODO: Alignment approach here is almost certainly WRONG
        // Waiting for aligment lesson by @Rexicon226 to correct approach here
        return .{
            .allocator = allocator,
            .buffer = try std.ArrayListUnmanaged(u8).initCapacity(allocator, size),
            .regions = std.ArrayList(Region).init(allocator),
            .vaddr = 0,
            .region_start = region_start,
            .aligned = aligned,
            .copy_account_data = copy_account_data,
        };
    }

    pub fn deinit(self: *Serializer) void {
        self.buffer.deinit(self.allocator);
    }

    pub fn write(self: *Serializer, comptime T: type, value: T) !u64 {
        // TODO: debug assert alignment
        const vaddr = self.vaddr +| self.buffer.items.len -| self.region_start;
        self.buffer.appendSliceAssumeCapacity(std.mem.asBytes(&value));
        return vaddr;
    }

    pub fn writeAll(self: *Serializer, data: []const u8) !u64 {
        const vaddr = self.vaddr +| self.buffer.items.len -| self.region_start;
        self.buffer.appendSliceAssumeCapacity(data);
        return vaddr;
    }

    pub fn writeAccount(self: *Serializer, account: *BorrowedAccount) u64 {
        const vm_data_addr = if (self.copy_account_data) blk: {
            const addr = self.vaddr +| self.buffer.items.len;
            self.writeAll(account.account.data);
            break :blk addr;
        } else blk: {
            self.pushRegion(true);
            const addr = self.vaddr;
            try self.pushAccountDataRegion(account);
            break :blk addr;
        };

        if (self.aligned) {
            // TODO: Implement
            // [agave] https://github.com/anza-xyz/agave/blob/32ac530151de63329f9ceb97dd23abfcee28f1d4/programs/bpf_loader/src/serialization.rs#L107-L123
        }

        return vm_data_addr;
    }

    pub fn pushRegion(self: *Serializer, is_writable: bool) void {
        const range_size = self.buffer.items.len -| self.region_start;
        const region = switch (is_writable) {
            inline true, false => |b| Region.init(
                b,
                self.buffer.items[self.region_start..self.buffer.items.len],
                self.vaddr,
            ),
        };
        self.regions.append(region);
        self.region_start = self.buffer.items.len;
        self.vaddr += range_size;
    }

    pub fn pushAccountDataRegion(self: *Serializer, account: *BorrowedAccount) !void {
        const data = account.account.data;
        if (data.len > 0) {
            const state = getAccountDataRegionMemoryState(account);
            const region = switch (state) {
                inline .constant, .mutable => |s| Region.init(s, data, self.vaddr),
            };
            self.vaddr += data.len;
            try self.regions.append(region);
        }
    }

    pub fn getAccountDataRegionMemoryState(account: *BorrowedAccount) svm.memory.MemoryState {
        account.checkDataIsMutable() catch {
            return .constant;
        };

        // TODO: Implement shared semantics for accounts
        // if (account.account.isShared()) {
        //     return .cow;
        // }

        return .mutable;
    }
};

pub fn serializeParameters(
    allocator: *std.mem.Allocator,
    ic: *InstructionContext,
    copy_account_data: bool,
) InstructionError!void {
    if (ic.account_metas.len > std.math.maxInt(u8)) {
        return InstructionError.MaxAccountsExceeded;
    }

    const is_loader_v1 = blk: {
        const program_account = try ic.borrowProgramAccount(ic.program_meta.index_in_transaction);
        defer program_account.account_write_guard.release();
        break :blk program_account.account.owner.equals(&program.bpf_loader_program.v1.ID);
    };

    const accounts = try std.ArrayList(SerializedAccount).initCapacity(
        allocator,
        ic.account_metas.len,
    );

    for (ic.account_metas, 0..) |account_meta, index_in_instruction| {
        if (account_meta.is_duplicate) {
            accounts.appendAssumeCapacity(.{ .duplicate = index_in_instruction });
        } else {
            const account = try ic.borrowInstructionAccount(account_meta.index_in_transaction);
            accounts.appendAssumeCapacity(.{ .account = .{ index_in_instruction, account } });
        }
    }

    if (is_loader_v1) {
        serializeParametersUnaligned(
            allocator,
            accounts.toOwnedSlice(),
            ic.serialized_instruction,
            ic.program_meta.pubkey,
            copy_account_data,
        );
    } else {
        serializeParametersAligned(
            allocator,
            accounts.toOwnedSlice(),
            ic.serialized_instruction,
            ic.program_meta.pubkey,
            copy_account_data,
        );
    }
}

fn serializeParametersAligned(
    allocator: *std.mem.Allocator,
    accounts: []SerializedAccount,
    serialized_instruction: []const u8,
    program_id: Pubkey,
    copy_account_data: bool,
) InstructionError!void {
    var size = @sizeOf(u64);
    for (accounts) |account| {
        size += 1; // dup
        switch (account) {
            .account => |index_and_account| {
                size += @sizeOf(u8) // is_signer
                + @sizeOf(u8) // is_writable
                + @sizeOf(Pubkey) // key
                + @sizeOf(u64) // lamports
                + @sizeOf(u64) // data len
                + @sizeOf(Pubkey) // owner
                + @sizeOf(u8) // executable
                + @sizeOf(u64); // rent_epoch
                if (copy_account_data) {
                    size += index_and_account[1].account.data.len;
                }
            },
            .duplicate => |_| {},
        }
    }
    size += @sizeOf(u64) // instruction data len
    + serialized_instruction.len // instruction data
    + @sizeOf(Pubkey); // program id

    var serializer = Serializer.init(
        allocator,
        size,
        MM_INPUT_START,
        false,
        copy_account_data,
    );
    errdefer serializer.deinit();

    var account_metas = try std.ArrayListUnmanaged(SerializedAccountMeta).initCapacity(
        allocator,
        accounts.len,
    );
    defer account_metas.deinit(allocator);

    _ = serializer.write(u64, std.mem.nativeToLittle(u64, accounts.len));
    for (accounts) |account| {
        switch (account) {
            .account => |index_and_borrowed_account| {
                _, const borrowed_account = index_and_borrowed_account;
                _ = serializer.write(u8, std.math.maxInt(u8));
                _ = serializer.write(u8, borrowed_account.borrow_context.is_signer);
                _ = serializer.write(u8, borrowed_account.borrow_context.is_writable);
                const vm_key_addr = serializer.writeAll(borrowed_account.pubkey.data);
                const vm_lamports_addr = serializer.write(u64, std.mem.nativeToLittle(u64, borrowed_account.account.lamports));
                _ = serializer.write(u64, std.mem.nativeToLittle(u64, borrowed_account.account.data.len));
                const vm_data_addr = serializer.writeAccount(&borrowed_account);
                const vm_owner_addr = serializer.writeAll(borrowed_account.account.owner.data);
                _ = serializer.write(u8, borrowed_account.account.executable);
                _ = serializer.write(u64, std.mem.nativeToLittle(u64, borrowed_account.account.rent_epoch));
                account_metas.appendAssumeCapacity(.{
                    .original_data_len = borrowed_account.account.data.len,
                    .vm_data_addr = vm_data_addr,
                    .vm_key_addr = vm_key_addr,
                    .vm_lamports_addr = vm_lamports_addr,
                    .vm_owner_addr = vm_owner_addr,
                });
            },
            .duplicate => |index| {
                account_metas.appendAssumeCapacity(account_metas.items[index]);
                _ = serializer.write(u16, index);
            },
        }
    }

    _ = serializer.write(u64, std.mem.nativeToLittle(u64, serialized_instruction.len));
    _ = serializer.writeAll(serialized_instruction);
    _ = serializer.writeAll(program_id.data);
}

fn serializeParametersUnaligned(
    allocator: *std.mem.Allocator,
    accounts: []SerializedAccount,
    serialized_instruction: []const u8,
    program_id: Pubkey,
    copy_account_data: bool,
) InstructionError!void {
    // TODO
}
