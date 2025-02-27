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

/// `assert_eq(std::mem::align_of::<u128>(), 8)` is true for BPF but not for some host machines
pub const BPF_ALIGN_OF_U128: usize = 8;

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/e1554f4067329a0dcf5035120ec6a06275d3b9ec/account-info/src/lib.rs#L17-L18
pub const MAX_PERMITTED_DATA_INCREASE: usize = 1_024 * 10;

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
    regions: std.BoundedArray(Region, 20),
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
        std.debug.print("Initializing with region_start: {}, aligned: {}, copy_account_data: {}\n", .{ region_start, aligned, copy_account_data });
        return .{
            .allocator = allocator,
            .buffer = try std.ArrayListUnmanaged(u8).initCapacity(allocator, size),
            .regions = std.BoundedArray(Region, 20){},
            .vaddr = region_start,
            .region_start = 0,
            .aligned = aligned,
            .copy_account_data = copy_account_data,
        };
    }

    pub fn deinit(self: *Serializer) void {
        self.buffer.deinit(self.allocator);
    }

    pub fn write(self: *Serializer, comptime T: type, value: T) u64 {
        const vaddr = self.vaddr +| self.buffer.items.len -| self.region_start;
        self.buffer.appendSliceAssumeCapacity(std.mem.asBytes(&value));
        return vaddr;
    }

    pub fn writeAll(self: *Serializer, data: []const u8) u64 {
        const vaddr = self.vaddr +| self.buffer.items.len -| self.region_start;
        self.buffer.appendSliceAssumeCapacity(data);
        return vaddr;
    }

    pub fn writeAccount(self: *Serializer, account: *const BorrowedAccount) !u64 {
        const vm_data_addr = if (self.copy_account_data) blk: {
            const addr = self.vaddr +| self.buffer.items.len;
            _ = self.writeAll(account.account.data);
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
        std.debug.print("self.region_start={}\n", .{self.region_start});

        const region = switch (is_writable) {
            inline true, false => Region.init(
                .constant, //b, // TODO: Discuss with @Rexicon226
                self.buffer.items[self.region_start..self.buffer.items.len],
                self.vaddr,
            ),
        };

        self.regions.appendAssumeCapacity(region);
        std.debug.print("self.regions.len={}\n", .{self.regions.slice().len});
        self.region_start = self.buffer.items.len;
        self.vaddr += range_size;
    }

    pub fn pushAccountDataRegion(self: *Serializer, account: *const BorrowedAccount) !void {
        const data = account.account.data;
        if (data.len > 0) {
            const state = try getAccountDataRegionMemoryState(account);
            const region = switch (state) {
                inline .constant, .mutable => |s| Region.init(s, data, self.vaddr),
            };
            self.vaddr += data.len;
            self.regions.appendAssumeCapacity(region);
        }
    }

    pub fn finish(self: *Serializer) !struct { []u8, []Region } {
        self.pushRegion(true);
        std.debug.assert(self.region_start == self.buffer.items.len);
        return .{ try self.buffer.toOwnedSlice(self.allocator), self.regions.slice() };
    }

    pub fn getAccountDataRegionMemoryState(account: *const BorrowedAccount) !svm.memory.MemoryState {
        if (account.checkDataIsMutable() != null) return .constant;

        // TODO: Implement shared semantics for accounts
        // if (account.account.isShared()) return .cow;

        return .mutable;
    }
};

pub fn serializeParameters(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    copy_account_data: bool,
) InstructionError!struct {
    []u8,
    []Region,
    []SerializedAccountMeta,
} {
    if (ic.account_metas.len > std.math.maxInt(u8)) {
        return InstructionError.MaxAccountsExceeded;
    }

    const is_loader_v1 = blk: {
        const program_account = try ic.borrowProgramAccount(ic.program_meta.index_in_transaction);
        defer program_account.account_write_guard.release();
        break :blk program_account.account.owner.equals(&program.bpf_loader_program.v1.ID);
    };

    // var accounts = std.ArrayList(SerializedAccount).initCapacity(
    //     allocator,
    //     ic.account_metas.len,
    // ) catch {
    //     return InstructionError.ProgramEnvironmentSetupFailure;
    // };

    // for (ic.account_metas.constSlice(), 0..) |account_meta, index_in_instruction| {
    //     if (account_meta.is_duplicate) {
    //         accounts.appendAssumeCapacity(.{ .duplicate = @intCast(index_in_instruction) });
    //     } else {
    //         const account = try ic.borrowInstructionAccount(account_meta.index_in_transaction);
    //         defer account.release();
    //         accounts.appendAssumeCapacity(.{ .account = .{ @intCast(index_in_instruction), account } });
    //     }
    // }

    if (is_loader_v1) {
        // serializeParametersUnaligned(
        //     allocator,
        //     accounts.toOwnedSlice(),
        //     ic.serialized_instruction,
        //     ic.program_meta.pubkey,
        //     copy_account_data,
        // );
    }

    return try serializeParametersAligned(
        allocator,
        accounts.toOwnedSlice() catch return InstructionError.ProgramEnvironmentSetupFailure,
        ic.serialized_instruction,
        ic.program_meta.pubkey,
        copy_account_data,
    );
}

fn serializeParametersAligned(
    allocator: std.mem.Allocator,
    accounts: []SerializedAccount,
    serialized_instruction: []const u8,
    program_id: Pubkey,
    copy_account_data: bool,
) InstructionError!struct {
    []u8,
    []Region,
    []SerializedAccountMeta,
} {
    std.debug.print("{}\n", .{accounts.len});
    std.debug.print("{any}\n", .{serialized_instruction});
    std.debug.print("{}\n", .{program_id});
    std.debug.print("{}\n", .{copy_account_data});

    var size: u64 = @sizeOf(u64);
    for (accounts) |account| {
        size += 1; // dup
        switch (account) {
            .account => |index_and_account| {
                _, const borrowed_account = index_and_account;
                size += @sizeOf(u8) // is_signer
                + @sizeOf(u8) // is_writable
                + @sizeOf(u8) // executable
                + @sizeOf(u32) // original data len
                + @sizeOf(Pubkey) // key
                + @sizeOf(Pubkey) // owner
                + @sizeOf(u64) // lamports
                + @sizeOf(u64) // data len
                + MAX_PERMITTED_DATA_INCREASE //
                + @sizeOf(u64); // rent_epoch
                if (copy_account_data) {
                    // [agave] https://github.com/anza-xyz/agave/blob/8c4347014939f9f5697e2252f2653a83279eb1d4/programs/bpf_loader/src/serialization.rs#L448
                    size += borrowed_account.account.data.len;
                } else {
                    size += BPF_ALIGN_OF_U128;
                }
            },
            .duplicate => size += 7, // padding for 64 bit alignment
        }
    }
    size += @sizeOf(u64) // instruction data len
    + serialized_instruction.len // instruction data
    + @sizeOf(Pubkey); // program id

    std.debug.print("size: {}\n", .{size});

    var serializer = Serializer.init(
        allocator,
        size,
        MM_INPUT_START,
        true,
        copy_account_data,
    ) catch {
        return InstructionError.ProgramEnvironmentSetupFailure;
    };
    errdefer serializer.deinit();

    var account_metas = std.ArrayListUnmanaged(SerializedAccountMeta).initCapacity(
        allocator,
        accounts.len,
    ) catch {
        return InstructionError.ProgramEnvironmentSetupFailure;
    };
    defer account_metas.deinit(allocator);

    _ = serializer.write(u64, std.mem.nativeToLittle(u64, accounts.len));
    for (accounts) |account| {
        switch (account) {
            .account => |index_and_borrowed_account| {
                _, const borrowed_account = index_and_borrowed_account;
                _ = serializer.write(u8, std.math.maxInt(u8));
                _ = serializer.write(u8, @intFromBool(borrowed_account.borrow_context.is_signer));
                _ = serializer.write(u8, @intFromBool(borrowed_account.borrow_context.is_writable));
                _ = serializer.write(u8, @intFromBool(borrowed_account.account.executable));
                _ = serializer.writeAll(&.{ 0, 0, 0, 0 });

                const vm_key_addr = serializer.writeAll(&borrowed_account.pubkey.data);
                const vm_owner_addr = serializer.writeAll(&borrowed_account.account.owner.data);
                const vm_lamports_addr = serializer.write(u64, std.mem.nativeToLittle(u64, borrowed_account.account.lamports));

                _ = serializer.write(u64, std.mem.nativeToLittle(u64, borrowed_account.account.data.len));
                const vm_data_addr = try serializer.writeAccount(&borrowed_account);

                _ = serializer.write(u64, std.mem.nativeToLittle(u64, borrowed_account.account.rent_epoch));

                account_metas.appendAssumeCapacity(.{
                    .original_data_len = borrowed_account.account.data.len,
                    .vm_key_addr = vm_key_addr,
                    .vm_owner_addr = vm_owner_addr,
                    .vm_lamports_addr = vm_lamports_addr,
                    .vm_data_addr = vm_data_addr,
                });
            },
            .duplicate => |index| {
                account_metas.appendAssumeCapacity(account_metas.items[index]);
                _ = serializer.write(u16, index);
                _ = serializer.writeAll(&.{ 0, 0, 0, 0, 0, 0, 0 });
            },
        }
    }

    _ = serializer.write(u64, std.mem.nativeToLittle(u64, serialized_instruction.len));
    _ = serializer.writeAll(serialized_instruction);
    _ = serializer.writeAll(&program_id.data);

    const memory, const regions = serializer.finish() catch {
        return InstructionError.ProgramEnvironmentSetupFailure;
    };
    errdefer allocator.free(memory);

    return .{
        memory,
        regions,
        account_metas.toOwnedSlice(allocator) catch {
            return InstructionError.ProgramEnvironmentSetupFailure;
        },
    };
}

test "serializeParameters" {
    const createTransactionContext = sig.runtime.program.test_program_execute.createTransactionContext;
    const createInstructionContext = sig.runtime.program.test_program_execute.createInstructionContext;

    // const allocator = std.testing.allocator;
    const allocator = std.heap.page_allocator;
    var prng = std.rand.DefaultPrng.init(0);

    const copy_account_data = false;
    const program_id = Pubkey.initRandom(prng.random());

    var tc = try createTransactionContext(allocator, .{
        .accounts = &.{
            .{
                .pubkey = program_id,
                .lamports = 0,
                .owner = program.bpf_loader_program.v2.ID,
                .executable = true,
                .rent_epoch = 0,
            },
            .{
                .pubkey = Pubkey.initRandom(prng.random()),
                .lamports = 1,
                .data = try allocator.dupe(u8, &.{ 1, 2, 3, 4, 5 }),
                .owner = program.bpf_loader_program.v2.ID,
                .executable = false,
                .rent_epoch = 100,
            },
            .{
                .pubkey = Pubkey.initRandom(prng.random()),
                .lamports = 2,
                .data = try allocator.dupe(u8, &.{ 11, 12, 13, 14, 15, 16, 17, 18, 19 }),
                .owner = program.bpf_loader_program.v2.ID,
                .executable = true,
                .rent_epoch = 200,
            },
            .{
                .pubkey = Pubkey.initRandom(prng.random()),
                .lamports = 3,
                .data = try allocator.dupe(u8, &.{}),
                .owner = program.bpf_loader_program.v2.ID,
                .executable = false,
                .rent_epoch = 3100,
            },
            .{
                .pubkey = Pubkey.initRandom(prng.random()),
                .lamports = 4,
                .data = try allocator.dupe(u8, &.{ 1, 2, 3, 4, 5 }),
                .owner = program.bpf_loader_program.v2.ID,
                .executable = false,
                .rent_epoch = 100,
            },
            .{
                .pubkey = Pubkey.initRandom(prng.random()),
                .lamports = 5,
                .data = try allocator.dupe(u8, &.{ 11, 12, 13, 14, 15, 16, 17, 18, 19 }),
                .owner = program.bpf_loader_program.v2.ID,
                .executable = true,
                .rent_epoch = 200,
            },
            .{
                .pubkey = Pubkey.initRandom(prng.random()),
                .lamports = 6,
                .data = try allocator.dupe(u8, &.{}),
                .owner = program.bpf_loader_program.v2.ID,
                .executable = false,
                .rent_epoch = 3100,
            },
        },
    });
    defer tc.deinit(allocator);

    const serialized_instruction = try allocator.dupe(u8, &.{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 });
    defer allocator.free(serialized_instruction);

    std.debug.print("serialized_instruction: {any}\n", .{serialized_instruction});

    var ic = try createInstructionContext(
        &tc,
        program_id,
        serialized_instruction,
        &.{
            .{ .index_in_transaction = 1, .is_signer = false, .is_writable = false },
            .{ .index_in_transaction = 1, .is_signer = false, .is_writable = false, .is_duplicate = true },
            .{ .index_in_transaction = 2, .is_signer = false, .is_writable = false, .is_duplicate = true },
            .{ .index_in_transaction = 3, .is_signer = false, .is_writable = false, .is_duplicate = true },
            .{ .index_in_transaction = 4, .is_signer = false, .is_writable = true, .is_duplicate = true },
            .{ .index_in_transaction = 4, .is_signer = false, .is_writable = true, .is_duplicate = true },
            .{ .index_in_transaction = 5, .is_signer = false, .is_writable = true, .is_duplicate = true },
            .{ .index_in_transaction = 6, .is_signer = false, .is_writable = true, .is_duplicate = true },
        },
    );

    const memory, const regions, const account_metas = try serializeParameters(
        allocator,
        &ic,
        copy_account_data,
    );

    _ = memory;
    _ = regions;
    _ = account_metas;
}
