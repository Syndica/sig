const builtin = @import("builtin");
const std = @import("std");
const std14 = @import("std14");
const sig = @import("../../../sig.zig");

const program = sig.runtime.program;
const vm = sig.vm;

const Pubkey = sig.core.Pubkey;
const InstructionError = sig.core.instruction.InstructionError;

const InstructionContext = sig.runtime.InstructionContext;
const BorrowedAccount = sig.runtime.BorrowedAccount;
const InstructionInfo = sig.runtime.InstructionInfo;

const Region = vm.memory.Region;

const MAX_PERMITTED_DATA_LENGTH = sig.runtime.program.system.MAX_PERMITTED_DATA_LENGTH;

const INPUT_START = sig.vm.memory.INPUT_START;

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/e1554f4067329a0dcf5035120ec6a06275d3b9ec/program-entrypoint/src/lib.rs#L316
/// `assert_eq(std::mem::align_of::<u128>(), 8)` is true for BPF but not for some host machines
pub const BPF_ALIGN_OF_U128: usize = 8;

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/e1554f4067329a0dcf5035120ec6a06275d3b9ec/account-info/src/lib.rs#L17-L18
pub const MAX_PERMITTED_DATA_INCREASE: usize = 1_024 * 10;

/// [agave] https://github.com/anza-xyz/agave/blob/108fcb4ff0f3cb2e7739ca163e6ead04e377e567/program-runtime/src/serialization.rs#L26
pub const SerializedAccount = union(enum) {
    account: struct { u16, BorrowedAccount },
    duplicate: u8,
};

/// [agave] https://github.com/anza-xyz/agave/blob/108fcb4ff0f3cb2e7739ca163e6ead04e377e567/program-runtime/src/invoke_context.rs#L182
pub const SerializedAccountMeta = struct {
    original_data_len: u64,
    vm_data_addr: u64,
    vm_key_addr: u64,
    vm_lamports_addr: u64,
    vm_owner_addr: u64,
};

/// [agave] https://github.com/anza-xyz/agave/blob/108fcb4ff0f3cb2e7739ca163e6ead04e377e567/program-runtime/src/serialization.rs#L31
pub const Serializer = struct {
    allocator: std.mem.Allocator,
    buffer: std.ArrayListUnmanaged(u8),
    regions: std.ArrayListUnmanaged(Region),
    vaddr: u64,
    region_start: usize,
    aligned: bool,
    account_data_direct_mapping: bool,
    stricter_abi_and_runtime_constraints: bool,

    pub fn init(
        allocator: std.mem.Allocator,
        size: usize,
        region_start: usize,
        aligned: bool,
        stricter_abi_and_runtime_constraints: bool,
        account_data_direct_mapping: bool,
    ) error{OutOfMemory}!Serializer {
        return .{
            .allocator = allocator,
            .buffer = try std.ArrayListUnmanaged(u8).initCapacity(allocator, size),
            .regions = std.ArrayListUnmanaged(Region){},
            .vaddr = region_start,
            .region_start = 0,
            .aligned = aligned,
            .account_data_direct_mapping = account_data_direct_mapping,
            .stricter_abi_and_runtime_constraints = stricter_abi_and_runtime_constraints,
        };
    }

    pub fn deinit(self: *Serializer) void {
        self.buffer.deinit(self.allocator);
        self.regions.deinit(self.allocator);
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/01e50dc39bde9a37a9f15d64069459fe7502ec3e/program-runtime/src/serialization.rs#L56-L57
    pub fn write(self: *Serializer, comptime T: type, value: T) u64 {
        return self.writeBytes(std.mem.asBytes(&value));
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/01e50dc39bde9a37a9f15d64069459fe7502ec3e/program-runtime/src/serialization.rs#L77-L78
    pub fn writeBytes(self: *Serializer, data: []const u8) u64 {
        const vaddr = (self.vaddr +| self.buffer.items.len) -| self.region_start;
        self.buffer.appendSliceAssumeCapacity(data);
        return vaddr;
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/01e50dc39bde9a37a9f15d64069459fe7502ec3e/program-runtime/src/serialization.rs#L91-L92
    pub fn writeAccount(
        self: *Serializer,
        account: *const BorrowedAccount,
    ) (error{OutOfMemory} || InstructionError)!u64 {
        if (!self.stricter_abi_and_runtime_constraints) {
            const addr = self.vaddr +| self.buffer.items.len;
            _ = self.writeBytes(account.constAccountData()); // intentionally ignored
            if (self.aligned) {
                const align_offset = std.mem.alignForward(
                    usize,
                    account.constAccountData().len,
                    BPF_ALIGN_OF_U128,
                ) - account.constAccountData().len;

                try self.buffer.appendNTimes(
                    self.allocator,
                    0,
                    MAX_PERMITTED_DATA_INCREASE + align_offset,
                );
            }
            return addr;
        }

        try self.pushRegion(true);
        const addr = self.vaddr;
        if (!self.account_data_direct_mapping) {
            _ = self.writeBytes(account.constAccountData()); // intentionally ignored

            if (self.aligned) try self.buffer.appendNTimes(
                self.allocator,
                0,
                MAX_PERMITTED_DATA_INCREASE,
            );
        }

        // TODO: Cow https://github.com/anza-xyz/agave/blob/01e50dc39bde9a37a9f15d64069459fe7502ec3e/program-runtime/src/serialization.rs#L134
        const address_space = if (self.aligned)
            account.constAccountData().len +| MAX_PERMITTED_DATA_INCREASE
        else
            account.constAccountData().len;

        if (address_space > 0) {
            const state = getAccountDataRegionMemoryState(account);
            if (!self.account_data_direct_mapping) {
                try self.pushRegion(state == .mutable);
                const region = &self.regions.items[self.regions.items.len - 1];
                const new_len = account.constAccountData().len;
                region.vm_addr_end = region.vm_addr_start + new_len;
                switch (state) {
                    .mutable => region.host_memory.mutable.len = new_len,
                    .constant => region.host_memory.constant.len = new_len,
                }
            } else {
                try self.regions.append(self.allocator, switch (state) {
                    .mutable => Region.init(.mutable, try account.mutableAccountData(), self.vaddr),
                    .constant => Region.init(.constant, account.constAccountData(), self.vaddr),
                });
                self.vaddr += address_space;
            }
        }

        if (self.aligned) {
            const align_offset = std.mem.alignForward(
                usize,
                account.constAccountData().len,
                BPF_ALIGN_OF_U128,
            ) - account.constAccountData().len;

            if (!self.account_data_direct_mapping) {
                try self.buffer.appendNTimes(self.allocator, 0, align_offset);
            } else {
                try self.buffer.appendNTimes(self.allocator, 0, BPF_ALIGN_OF_U128);
                self.region_start += BPF_ALIGN_OF_U128 -| align_offset;
            }
        }
        return addr;
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/01e50dc39bde9a37a9f15d64069459fe7502ec3e/program-runtime/src/serialization.rs#L154-L155
    pub fn pushRegion(self: *Serializer, is_writable: bool) error{OutOfMemory}!void {
        const range_size = self.buffer.items.len -| self.region_start;

        const region = switch (is_writable) {
            inline true, false => |mutable| Region.init(
                if (mutable) .mutable else .constant,
                self.buffer.items[self.region_start..self.buffer.items.len],
                self.vaddr,
            ),
        };

        try self.regions.append(self.allocator, region);
        self.region_start = self.buffer.items.len;
        self.vaddr += range_size;
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/01e50dc39bde9a37a9f15d64069459fe7502ec3e/program-runtime/src/serialization.rs#L172
    pub fn finish(self: *Serializer) error{OutOfMemory}!struct {
        std.ArrayListUnmanaged(u8),
        std.ArrayListUnmanaged(Region),
    } {
        try self.pushRegion(true);
        std.debug.assert(self.region_start == self.buffer.items.len);
        return .{
            self.buffer,
            self.regions,
        };
    }

    pub fn getAccountDataRegionMemoryState(account: *const BorrowedAccount) vm.memory.MemoryState {
        // TODO: Cow https://github.com/anza-xyz/agave/blob/01e50dc39bde9a37a9f15d64069459fe7502ec3e/program-runtime/src/serialization.rs#L608
        if (account.checkDataIsMutable() != null) return .constant;
        return .mutable;
    }
};

const SerializeReturn = struct {
    memory: std.ArrayListUnmanaged(u8),
    regions: std.ArrayListUnmanaged(Region),
    account_metas: std14.BoundedArray(SerializedAccountMeta, InstructionInfo.MAX_ACCOUNT_METAS),
    instruction_data_offset: u64,

    pub fn deinit(self: *SerializeReturn, allocator: std.mem.Allocator) void {
        self.memory.deinit(allocator);
        self.regions.deinit(allocator);
    }
};

/// [agave] https://github.com/anza-xyz/agave/blob/108fcb4ff0f3cb2e7739ca163e6ead04e377e567/program-runtime/src/serialization.rs#L188
pub fn serializeParameters(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    direct_mapping: bool,
    stricter_abi_and_runtime_constraints: bool,
    mask_out_rent_epoch_in_vm_serialization: bool,
) (error{OutOfMemory} || InstructionError)!SerializeReturn {
    if (ic.ixn_info.account_metas.items.len > InstructionInfo.MAX_ACCOUNT_METAS - 1) {
        return error.MaxAccountsExceeded;
    }

    const is_loader_v1 = blk: {
        const program_account = try ic.borrowProgramAccount();
        defer program_account.release();
        break :blk program_account.account.owner.equals(&program.bpf_loader.v1.ID);
    };

    var accounts = std.array_list.Managed(SerializedAccount).initCapacity(
        allocator,
        ic.ixn_info.account_metas.items.len,
    ) catch return InstructionError.ProgramEnvironmentSetupFailure;
    defer accounts.deinit();

    for (ic.ixn_info.account_metas.items, 0..) |account_meta, index_in_instruction| {
        const index_in_callee =
            try ic.ixn_info.getAccountInstructionIndex(account_meta.index_in_transaction);
        const is_duplicate = index_in_callee != index_in_instruction;

        if (is_duplicate) {
            accounts.appendAssumeCapacity(.{ .duplicate = @intCast(index_in_callee) });
        } else {
            const account = try ic.borrowInstructionAccount(@intCast(index_in_instruction));
            defer account.release();
            accounts.appendAssumeCapacity(.{ .account = .{
                @intCast(index_in_instruction),
                account,
            } });
        }
    }

    return if (is_loader_v1)
        serializeParametersUnaligned(
            allocator,
            accounts.items,
            ic.ixn_info.instruction_data,
            ic.ixn_info.program_meta.pubkey,
            direct_mapping,
            stricter_abi_and_runtime_constraints,
            mask_out_rent_epoch_in_vm_serialization,
        )
    else
        serializeParametersAligned(
            allocator,
            accounts.items,
            ic.ixn_info.instruction_data,
            ic.ixn_info.program_meta.pubkey,
            direct_mapping,
            stricter_abi_and_runtime_constraints,
            mask_out_rent_epoch_in_vm_serialization,
        );
}

/// [agave] https://github.com/anza-xyz/agave/blob/108fcb4ff0f3cb2e7739ca163e6ead04e377e567/program-runtime/src/serialization.rs#L282
fn serializeParametersUnaligned(
    allocator: std.mem.Allocator,
    accounts: []const SerializedAccount,
    instruction_data: []const u8,
    program_id: Pubkey,
    account_data_direct_mapping: bool,
    stricter_abi_and_runtime_constraints: bool,
    mask_out_rent_epoch_in_vm_serialization: bool,
) (error{OutOfMemory} || InstructionError)!SerializeReturn {
    var size: usize = @sizeOf(u64);
    for (accounts) |account| {
        size += 1; // dup
        switch (account) {
            .account => |index_and_account| {
                _, const borrowed_account = index_and_account;
                size += @sizeOf(u8) // is_signer
                    + @sizeOf(u8) // is_writable
                    + @sizeOf(Pubkey) // key
                    + @sizeOf(u64) // lamports
                    + @sizeOf(u64) // data len
                    + @sizeOf(Pubkey) // owner
                    + @sizeOf(u8) // executable
                    + @sizeOf(u64); // rent_epoch
                if (!(stricter_abi_and_runtime_constraints and account_data_direct_mapping)) {
                    size += borrowed_account.constAccountData().len;
                }
            },
            .duplicate => {},
        }
    }
    size += @sizeOf(u64) // instruction data len
        + instruction_data.len // instruction data
        + @sizeOf(Pubkey); // program id

    var serializer = try Serializer.init(
        allocator,
        size,
        INPUT_START,
        false,
        stricter_abi_and_runtime_constraints,
        account_data_direct_mapping,
    );

    var account_metas: std14.BoundedArray(
        SerializedAccountMeta,
        InstructionInfo.MAX_ACCOUNT_METAS,
    ) = .{};

    _ = serializer.write(u64, std.mem.nativeToLittle(u64, accounts.len));
    for (accounts) |account| {
        switch (account) {
            .account => |index_and_account| {
                _, const borrowed_account = index_and_account;

                _ = serializer.write(u8, std.math.maxInt(u8));
                _ = serializer.write(u8, @intFromBool(borrowed_account.context.is_signer));
                _ = serializer.write(u8, @intFromBool(borrowed_account.context.is_writable));

                const vm_key_addr = serializer.writeBytes(&borrowed_account.pubkey.data);
                const vm_lamports_addr = serializer.write(
                    u64,
                    std.mem.nativeToLittle(u64, borrowed_account.account.lamports),
                );

                _ = serializer.write(
                    u64,
                    std.mem.nativeToLittle(u64, borrowed_account.constAccountData().len),
                );
                const vm_data_addr = try serializer.writeAccount(&borrowed_account);
                const vm_owner_addr = serializer.writeBytes(&borrowed_account.account.owner.data);

                _ = serializer.write(u8, @intFromBool(borrowed_account.account.executable));

                const rent_epoch: u64 = if (mask_out_rent_epoch_in_vm_serialization)
                    std.math.maxInt(u64)
                else
                    borrowed_account.account.rent_epoch;
                _ = serializer.write(
                    u64,
                    std.mem.nativeToLittle(u64, rent_epoch),
                );

                account_metas.appendAssumeCapacity(.{
                    .original_data_len = borrowed_account.constAccountData().len,
                    .vm_key_addr = vm_key_addr,
                    .vm_owner_addr = vm_owner_addr,
                    .vm_lamports_addr = vm_lamports_addr,
                    .vm_data_addr = vm_data_addr,
                });
            },
            .duplicate => |index| {
                account_metas.appendAssumeCapacity(account_metas.get(index));
                _ = serializer.write(u8, @intCast(index));
            },
        }
    }
    _ = serializer.write(u64, std.mem.nativeToLittle(u64, instruction_data.len));
    const instruction_data_offset = serializer.writeBytes(instruction_data);
    _ = serializer.writeBytes(&program_id.data);

    var memory, var regions = try serializer.finish();
    errdefer {
        memory.deinit(allocator);
        regions.deinit(allocator);
    }

    return .{
        .memory = memory,
        .regions = regions,
        .account_metas = account_metas,
        .instruction_data_offset = instruction_data_offset,
    };
}

/// [agave] https://github.com/anza-xyz/agave/blob/108fcb4ff0f3cb2e7739ca163e6ead04e377e567/program-runtime/src/serialization.rs#L415
fn serializeParametersAligned(
    allocator: std.mem.Allocator,
    accounts: []const SerializedAccount,
    instruction_data: []const u8,
    program_id: Pubkey,
    account_data_direct_mapping: bool,
    stricter_abi_and_runtime_constraints: bool,
    mask_out_rent_epoch_in_vm_serialization: bool,
) (error{OutOfMemory} || InstructionError)!SerializeReturn {
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
                    + @sizeOf(u64); // rent_epoch

                if (!(stricter_abi_and_runtime_constraints and account_data_direct_mapping)) {
                    const data_len = borrowed_account.constAccountData().len;
                    const align_offset = std.mem.alignForward(
                        usize,
                        data_len,
                        BPF_ALIGN_OF_U128,
                    ) - data_len;
                    size += data_len +
                        MAX_PERMITTED_DATA_INCREASE +
                        align_offset;
                } else {
                    size += BPF_ALIGN_OF_U128;
                }
            },
            .duplicate => size += 7, // padding for 64 bit alignment
        }
    }
    size += @sizeOf(u64) // instruction data len
        + instruction_data.len // instruction data
        + @sizeOf(Pubkey); // program id

    var serializer = try Serializer.init(
        allocator,
        size,
        INPUT_START,
        true,
        stricter_abi_and_runtime_constraints,
        account_data_direct_mapping,
    );
    errdefer serializer.deinit();

    var account_metas: std14.BoundedArray(
        SerializedAccountMeta,
        InstructionInfo.MAX_ACCOUNT_METAS,
    ) = .{};

    _ = serializer.write(u64, std.mem.nativeToLittle(u64, accounts.len));
    for (accounts) |account| {
        switch (account) {
            .account => |index_and_borrowed_account| {
                _, const borrowed_account = index_and_borrowed_account;
                _ = serializer.write(u8, std.math.maxInt(u8)); // NON_DUP_MARKER
                _ = serializer.write(u8, @intFromBool(borrowed_account.context.is_signer));
                _ = serializer.write(u8, @intFromBool(borrowed_account.context.is_writable));
                _ = serializer.write(u8, @intFromBool(borrowed_account.account.executable));
                _ = serializer.writeBytes(&.{ 0, 0, 0, 0 });

                const vm_key_addr = serializer.writeBytes(&borrowed_account.pubkey.data);
                const vm_owner_addr = serializer.writeBytes(&borrowed_account.account.owner.data);
                const vm_lamports_addr = serializer.write(
                    u64,
                    std.mem.nativeToLittle(u64, borrowed_account.account.lamports),
                );

                _ = serializer.write(
                    u64,
                    std.mem.nativeToLittle(u64, borrowed_account.constAccountData().len),
                );
                const vm_data_addr = try serializer.writeAccount(&borrowed_account);

                const rent_epoch: u64 = if (mask_out_rent_epoch_in_vm_serialization)
                    std.math.maxInt(u64)
                else
                    borrowed_account.account.rent_epoch;
                _ = serializer.write(
                    u64,
                    std.mem.nativeToLittle(u64, rent_epoch),
                );

                account_metas.appendAssumeCapacity(.{
                    .original_data_len = borrowed_account.constAccountData().len,
                    .vm_key_addr = vm_key_addr,
                    .vm_owner_addr = vm_owner_addr,
                    .vm_lamports_addr = vm_lamports_addr,
                    .vm_data_addr = vm_data_addr,
                });
            },
            .duplicate => |index| {
                account_metas.appendAssumeCapacity(account_metas.get(index));
                _ = serializer.write(u8, index);
                _ = serializer.writeBytes(&.{ 0, 0, 0, 0, 0, 0, 0 });
            },
        }
    }

    _ = serializer.write(u64, std.mem.nativeToLittle(u64, instruction_data.len));
    const instruction_data_offset = serializer.writeBytes(instruction_data);
    _ = serializer.writeBytes(&program_id.data);

    var memory, var regions = try serializer.finish();
    errdefer {
        memory.deinit(allocator);
        regions.deinit(allocator);
    }

    return .{
        .memory = memory,
        .regions = regions,
        .account_metas = account_metas,
        .instruction_data_offset = instruction_data_offset,
    };
}

/// [agave] https://github.com/anza-xyz/agave/blob/108fcb4ff0f3cb2e7739ca163e6ead04e377e567/program-runtime/src/serialization.rs#L251
pub fn deserializeParameters(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    stricter_abi_and_runtime_constraints: bool,
    direct_mapping: bool,
    memory: []u8,
    account_metas: []const SerializedAccountMeta,
) (error{OutOfMemory} || InstructionError)!void {
    const is_loader_v1 = blk: {
        const program_account = try ic.borrowProgramAccount();
        defer program_account.release();
        break :blk program_account.account.owner.equals(&program.bpf_loader.v1.ID);
    };

    var account_lengths =
        try std.ArrayListUnmanaged(usize).initCapacity(allocator, account_metas.len);
    defer account_lengths.deinit(allocator);

    for (account_metas) |account_meta| {
        account_lengths.appendAssumeCapacity(account_meta.original_data_len);
    }

    if (is_loader_v1)
        try deserializeParametersUnaligned(
            allocator,
            ic,
            stricter_abi_and_runtime_constraints,
            direct_mapping,
            memory,
            account_lengths.items,
        )
    else
        try deserializeParametersAligned(
            allocator,
            ic,
            stricter_abi_and_runtime_constraints,
            direct_mapping,
            memory,
            account_lengths.items,
        );
}

/// [agave] https://github.com/anza-xyz/agave/blob/108fcb4ff0f3cb2e7739ca163e6ead04e377e567/program-runtime/src/serialization.rs#L360
fn deserializeParametersUnaligned(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    stricter_abi_and_runtime_constraints: bool,
    direct_mapping: bool,
    memory: []u8,
    account_lengths: []const usize,
) (error{OutOfMemory} || InstructionError)!void {
    var start: usize = @sizeOf(u64);
    for (0..ic.ixn_info.account_metas.items.len) |index_in_instruction_| {
        const index_in_instruction: u16 = @intCast(index_in_instruction_);
        const account_meta = ic.ixn_info.account_metas.items[index_in_instruction];
        const pre_len = account_lengths[index_in_instruction];

        const index_in_callee =
            try ic.ixn_info.getAccountInstructionIndex(account_meta.index_in_transaction);
        const is_duplicate = index_in_callee != index_in_instruction;

        start += 1; // is_dup
        if (!is_duplicate) {
            var borrowed_account = try ic.borrowInstructionAccount(index_in_instruction);
            defer borrowed_account.release();

            start += @sizeOf(u8) // is_signer
                + @sizeOf(u8) // is_writable
                + @sizeOf(Pubkey); // key

            // read and update Lamports
            if (start + @sizeOf(u64) > memory.len) return InstructionError.InvalidArgument;
            const lamports = std.mem.readInt(
                u64,
                memory[start .. start + @sizeOf(u64)][0..@sizeOf(u64)],
                .little,
            );
            start += @sizeOf(u64);
            if (borrowed_account.account.lamports != lamports) {
                try borrowed_account.setLamports(lamports);
            }

            // add lamports & data length
            start += @sizeOf(u64);
            if (!stricter_abi_and_runtime_constraints) {
                if (start + pre_len > memory.len) return InstructionError.InvalidArgument;
                const data = memory[start .. start + pre_len];
                const can_data_be_resized =
                    borrowed_account.checkCanSetDataLength(
                        ic.tc.accounts_resize_delta,
                        pre_len,
                    );
                if (can_data_be_resized) |err| {
                    if (!std.mem.eql(u8, data, borrowed_account.account.data)) return err;
                } else {
                    try borrowed_account.setDataFromSlice(
                        allocator,
                        &ic.tc.accounts_resize_delta,
                        data,
                    );
                }
            } else if (!direct_mapping and borrowed_account.checkDataIsMutable() == null) {
                if (start + pre_len > memory.len) return InstructionError.InvalidArgument;
                const data = memory[start .. start + pre_len];
                try borrowed_account.setDataFromSlice(
                    allocator,
                    &ic.tc.accounts_resize_delta,
                    data,
                );
            } else if (borrowed_account.constAccountData().len != pre_len) {
                try borrowed_account.setDataLength(
                    allocator,
                    &ic.tc.accounts_resize_delta,
                    pre_len,
                );
            }
            if (!(stricter_abi_and_runtime_constraints and direct_mapping))
                start += pre_len; // data
            start += @sizeOf(Pubkey) // owner
                + @sizeOf(u8) // executable
                + @sizeOf(u64); // rent_epoch
        }
    }
}

/// [agave] https://github.com/anza-xyz/agave/blob/108fcb4ff0f3cb2e7739ca163e6ead04e377e567/program-runtime/src/serialization.rs#L501
fn deserializeParametersAligned(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    stricter_abi_and_runtime_constraints: bool,
    direct_mapping: bool,
    memory: []u8,
    account_lengths: []const usize,
) (error{OutOfMemory} || InstructionError)!void {
    var start: usize = @sizeOf(u64);

    for (0..ic.ixn_info.account_metas.items.len) |index_in_instruction_| {
        const index_in_instruction: u16 = @intCast(index_in_instruction_);
        const account_meta = ic.ixn_info.account_metas.items[index_in_instruction];
        const pre_len = account_lengths[index_in_instruction];

        const index_in_callee =
            try ic.ixn_info.getAccountInstructionIndex(account_meta.index_in_transaction);
        const is_duplicate = index_in_callee != index_in_instruction;

        start += @sizeOf(u8); // position
        if (is_duplicate) {
            start += 7;
        } else {
            var borrowed_account = try ic.borrowInstructionAccount(index_in_instruction);
            defer borrowed_account.release();

            start += @sizeOf(u8) // is_signer
                + @sizeOf(u8) // is_writable
                + @sizeOf(u8) // executable
                + @sizeOf(u32) // original data len
                + @sizeOf(Pubkey); // key

            // read owner
            if (start + @sizeOf(Pubkey) > memory.len) return InstructionError.InvalidArgument;
            const owner = memory[start..][0..@sizeOf(Pubkey)];
            start += @sizeOf(Pubkey);

            // read and update Lamports
            if (start + @sizeOf(u64) > memory.len) return InstructionError.InvalidArgument;
            const lamports = std.mem.readInt(
                u64,
                memory[start..][0..@sizeOf(u64)],
                .little,
            );
            start += @sizeOf(u64);
            if (borrowed_account.account.lamports != lamports) {
                try borrowed_account.setLamports(lamports);
            }

            // read and check data length
            if (start + @sizeOf(u64) > memory.len) return InstructionError.InvalidArgument;
            const post_len = std.mem.readInt(
                u64,
                memory[start..][0..@sizeOf(u64)],
                .little,
            );
            start += @sizeOf(u64);
            if (post_len -| pre_len > MAX_PERMITTED_DATA_INCREASE or
                post_len > MAX_PERMITTED_DATA_LENGTH)
            {
                return InstructionError.InvalidRealloc;
            }

            if (!stricter_abi_and_runtime_constraints) {
                if (start + post_len > memory.len) return InstructionError.InvalidArgument;
                const data = memory[start .. start + post_len];
                const can_data_be_resized =
                    borrowed_account.checkCanSetDataLength(
                        ic.tc.accounts_resize_delta,
                        post_len,
                    );
                if (can_data_be_resized) |err| {
                    if (!std.mem.eql(u8, data, borrowed_account.account.data)) return err;
                } else {
                    try borrowed_account.setDataFromSlice(
                        allocator,
                        &ic.tc.accounts_resize_delta,
                        data,
                    );
                }
            } else if (!direct_mapping and borrowed_account.checkDataIsMutable() == null) {
                if (start + post_len > memory.len) return InstructionError.InvalidArgument;
                const data = memory[start .. start + post_len];
                try borrowed_account.setDataFromSlice(
                    allocator,
                    &ic.tc.accounts_resize_delta,
                    data,
                );
            } else if (borrowed_account.constAccountData().len != post_len) {
                try borrowed_account.setDataLength(
                    allocator,
                    &ic.tc.accounts_resize_delta,
                    post_len,
                );
            }

            const alignment_offset = std.mem.alignForward(
                usize,
                pre_len,
                BPF_ALIGN_OF_U128,
            ) - pre_len;
            start += if (!(stricter_abi_and_runtime_constraints and direct_mapping))
                pre_len +| MAX_PERMITTED_DATA_INCREASE +| alignment_offset // data + realloc pad
            else
                BPF_ALIGN_OF_U128;

            start += @sizeOf(u64); // rent_epoch
            // update owner at the end so that we are allowed to change the lamports and data
            if (!std.mem.eql(u8, &borrowed_account.account.owner.data, owner)) {
                try borrowed_account.setOwner(.{ .data = owner.* });
            }
        }
    }
}

// [agave] https://github.com/anza-xyz/agave/blob/108fcb4ff0f3cb2e7739ca163e6ead04e377e567/program-runtime/src/serialization.rs#L778
test serializeParameters {
    const AccountSharedData = sig.runtime.AccountSharedData;
    const createTransactionContext = sig.runtime.testing.createTransactionContext;
    const deinitTransactionContext = sig.runtime.testing.deinitTransactionContext;
    const createInstructionInfo = sig.runtime.testing.createInstructionInfo;

    // const allocator = std.testing.allocator;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const cases = [_]struct { Pubkey, bool }{
        .{ program.bpf_loader.v1.ID, false },
        .{ program.bpf_loader.v2.ID, false },
        .{ program.bpf_loader.v3.ID, false },
        .{ program.bpf_loader.v1.ID, true },
        .{ program.bpf_loader.v2.ID, true },
        .{ program.bpf_loader.v3.ID, true },
    };

    for (cases) |case| {
        const loader_id, const stricter_abi_and_runtime_constraints = case;
        const program_id = Pubkey.initRandom(prng.random());

        const cache, var tc = try createTransactionContext(
            allocator,
            prng.random(),
            .{
                .accounts = &.{
                    .{
                        .pubkey = program_id,
                        .lamports = 0,
                        .owner = loader_id,
                        .executable = true,
                        .rent_epoch = 0,
                    },
                    .{
                        .pubkey = Pubkey.initRandom(prng.random()),
                        .lamports = 1,
                        .data = &.{ 1, 2, 3, 4, 5 },
                        .owner = loader_id,
                        .executable = false,
                        .rent_epoch = 100,
                    },
                    .{
                        .pubkey = Pubkey.initRandom(prng.random()),
                        .lamports = 2,
                        .data = &.{ 11, 12, 13, 14, 15, 16, 17, 18, 19 },
                        .owner = loader_id,
                        .executable = true,
                        .rent_epoch = 200,
                    },
                    .{
                        .pubkey = Pubkey.initRandom(prng.random()),
                        .lamports = 3,
                        .data = &.{},
                        .owner = loader_id,
                        .executable = false,
                        .rent_epoch = 3100,
                    },
                    .{
                        .pubkey = Pubkey.initRandom(prng.random()),
                        .lamports = 4,
                        .data = &.{ 1, 2, 3, 4, 5 },
                        .owner = loader_id,
                        .executable = false,
                        .rent_epoch = 100,
                    },
                    .{
                        .pubkey = Pubkey.initRandom(prng.random()),
                        .lamports = 5,
                        .data = &.{ 11, 12, 13, 14, 15, 16, 17, 18, 19 },
                        .owner = loader_id,
                        .executable = true,
                        .rent_epoch = 200,
                    },
                    .{
                        .pubkey = Pubkey.initRandom(prng.random()),
                        .lamports = 6,
                        .data = &.{},
                        .owner = loader_id,
                        .executable = false,
                        .rent_epoch = 3100,
                    },
                    .{
                        .pubkey = program_id,
                        .lamports = 0,
                        .data = &.{},
                        .owner = program.bpf_loader.v1.ID,
                        .executable = true,
                        .rent_epoch = 0,
                    },
                },
            },
        );
        defer {
            deinitTransactionContext(allocator, &tc);
            sig.runtime.testing.deinitAccountMap(cache, allocator);
        }

        var instruction_info = try createInstructionInfo(
            &tc,
            program_id,
            [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 },
            &.{
                .{
                    .index_in_transaction = 1,
                    .is_signer = false,
                    .is_writable = false,
                },
                .{
                    .index_in_transaction = 1,
                    .is_signer = false,
                    .is_writable = false,
                },
                .{
                    .index_in_transaction = 2,
                    .is_signer = false,
                    .is_writable = false,
                },
                .{
                    .index_in_transaction = 3,
                    .is_signer = false,
                    .is_writable = false,
                },
                .{
                    .index_in_transaction = 4,
                    .is_signer = false,
                    .is_writable = true,
                },
                .{
                    .index_in_transaction = 4,
                    .is_signer = false,
                    .is_writable = true,
                },
                .{
                    .index_in_transaction = 5,
                    .is_signer = false,
                    .is_writable = true,
                },
                .{
                    .index_in_transaction = 6,
                    .is_signer = false,
                    .is_writable = true,
                },
            },
        );
        try instruction_info.account_metas.ensureTotalCapacity(
            allocator,
            InstructionInfo.MAX_ACCOUNT_METAS + 1,
        );
        defer instruction_info.deinit(allocator);

        try sig.runtime.executor.pushInstruction(&tc, instruction_info);
        const ic = try tc.getCurrentInstructionContext();

        { // MaxAccountsExceeded
            const original_len = ic.ixn_info.account_metas.items.len;
            defer ic.ixn_info.account_metas.items.len = original_len;

            while (ic.ixn_info.account_metas.items.len < InstructionInfo.MAX_ACCOUNT_METAS + 1) {
                ic.ixn_info.account_metas.appendAssumeCapacity(.{
                    .pubkey = Pubkey.ZEROES,
                    .index_in_transaction = 0,
                    .is_signer = false,
                    .is_writable = false,
                });
            }

            var serialized = serializeParameters(allocator, ic, false, false, false);
            defer if (serialized) |*ret| ret.deinit(allocator) else |_| {};
            try std.testing.expect(serialized == error.MaxAccountsExceeded);
        }

        const pre_accounts = blk: {
            var accounts = try std.ArrayListUnmanaged(struct {
                pubkey: Pubkey,
                account: AccountSharedData,
            }).initCapacity(allocator, tc.accounts.len);
            errdefer {
                for (accounts.items) |account| allocator.free(account.account.data);
                accounts.deinit(allocator);
            }
            for (tc.accounts) |account| {
                accounts.appendAssumeCapacity(.{
                    .pubkey = account.pubkey,
                    .account = .{
                        .lamports = account.account.lamports,
                        .owner = account.account.owner,
                        .data = try allocator.dupe(u8, account.account.data),
                        .executable = account.account.executable,
                        .rent_epoch = account.account.rent_epoch,
                    },
                });
            }
            break :blk try accounts.toOwnedSlice(allocator);
        };
        defer {
            for (pre_accounts) |account| allocator.free(account.account.data);
            allocator.free(pre_accounts);
        }

        var serialized = try serializeParameters(
            allocator,
            ic,
            false, // account_data_direct_mapping,
            stricter_abi_and_runtime_constraints,
            false,
        );
        defer serialized.deinit(allocator);

        const serialized_regions = try concatRegions(allocator, serialized.regions.items);
        defer allocator.free(serialized_regions);
        if (!stricter_abi_and_runtime_constraints) {
            try std.testing.expectEqualSlices(u8, serialized.memory.items, serialized_regions);
        }

        // TODO: compare against entrypoint deserialize method once implemented
        // [agave] https://github.com/anza-xyz/agave/blob/01e50dc39bde9a37a9f15d64069459fe7502ec3e/program-runtime/src/serialization.rs#L981
        // [agave] https://github.com/anza-xyz/agave/blob/01e50dc39bde9a37a9f15d64069459fe7502ec3e/program-runtime/src/serialization.rs#L893-L894

        try deserializeParameters(
            allocator,
            ic,
            stricter_abi_and_runtime_constraints,
            false, // account_data_direct_mapping,
            serialized.memory.items,
            serialized.account_metas.constSlice(),
        );
        for (pre_accounts, 0..) |pre_account, index_in_transaction| {
            const post_account = tc.accounts[index_in_transaction];
            try std.testing.expectEqual(
                0,
                post_account.read_refs,
            );
            try std.testing.expectEqual(
                false,
                post_account.write_ref,
            );
            try std.testing.expect(
                pre_account.pubkey.equals(&post_account.pubkey),
            );
            try std.testing.expectEqual(
                pre_account.account.lamports,
                post_account.account.lamports,
            );
            try std.testing.expect(
                pre_account.account.owner.equals(&post_account.account.owner),
            );
            try std.testing.expectEqualSlices(
                u8,
                pre_account.account.data,
                post_account.account.data,
            );
            try std.testing.expectEqual(
                pre_account.account.executable,
                post_account.account.executable,
            );
            try std.testing.expectEqual(
                pre_account.account.rent_epoch,
                post_account.account.rent_epoch,
            );
        }
    }
}

fn concatRegions(allocator: std.mem.Allocator, regions: []Region) ![]u8 {
    if (!builtin.is_test) {
        @compileError("concatRegions should only be called in test mode");
    }
    var size: u64 = 0;
    for (regions) |region| size += region.constSlice().len;
    var memory = try allocator.alloc(u8, size);
    for (regions) |region| {
        @memcpy(
            memory[region.vm_addr_start - INPUT_START ..][0..region.constSlice().len],
            region.constSlice(),
        );
    }
    return memory;
}
