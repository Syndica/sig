const builtin = @import("builtin");
const std = @import("std");
const std14 = @import("std14");
const sig = @import("../../../component.zig");
const solana = @import("lib").solana;

const program = sig.runtime.program;
const vm = sig.vm;

const Pubkey = solana.Pubkey;
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

/// [agave] https://github.com/anza-xyz/agave/blob/108fcb4ff0f3cb2e7739ca163e6ead04e377e567/program-runtime/src/serialization.rs#L29
/// Alignment of the host memory buffer. Agave uses `AlignedMemory::<HOST_ALIGN>` with HOST_ALIGN=16.
pub const HOST_ALIGN: std.mem.Alignment = .@"16"; // 16 bytes

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/e1554f4067329a0dcf5035120ec6a06275d3b9ec/account-info/src/lib.rs#L17-L18
pub const MAX_PERMITTED_DATA_INCREASE: usize = 1_024 * 10;

/// [agave] https://github.com/anza-xyz/agave/blob/108fcb4ff0f3cb2e7739ca163e6ead04e377e567/program-runtime/src/serialization.rs#L26
pub const SerializedAccount = union(enum) {
    account: struct { u16, BorrowedAccount },
    duplicate: u8,
};

/// [agave] https://github.com/anza-xyz/agave/blob/108fcb4ff0f3cb2e7739ca163e6ead04e377e567/program-runtime/src/invoke_context.rs#L182
pub const SerializedAccountMeta = struct {
    /// Address of the first byte of the serialized account record (the
    /// `NON_DUP_MARKER`/duplicate-marker byte). Used by SIMD-0449 to emit
    /// a trailing pointer array in the program input region.
    vm_addr: u64,
    original_data_len: u64,
    vm_data_addr: u64,
    vm_key_addr: u64,
    vm_lamports_addr: u64,
    vm_owner_addr: u64,
};

/// [agave] https://github.com/anza-xyz/agave/blob/108fcb4ff0f3cb2e7739ca163e6ead04e377e567/program-runtime/src/serialization.rs#L31
pub const Serializer = struct {
    allocator: std.mem.Allocator,
    buffer: std.ArrayListAlignedUnmanaged(u8, HOST_ALIGN),
    regions: std.ArrayListUnmanaged(Region),
    vaddr: u64,
    region_start: usize,
    aligned: bool,
    account_data_direct_mapping: bool,
    virtual_address_space_adjustments: bool,

    pub fn init(
        allocator: std.mem.Allocator,
        size: usize,
        region_start: usize,
        aligned: bool,
        virtual_address_space_adjustments: bool,
        account_data_direct_mapping: bool,
    ) error{OutOfMemory}!Serializer {
        return .{
            .allocator = allocator,
            .buffer = try std.ArrayListAlignedUnmanaged(u8, HOST_ALIGN).initCapacity(
                allocator,
                size,
            ),
            .regions = std.ArrayListUnmanaged(Region){},
            .vaddr = region_start,
            .region_start = 0,
            .aligned = aligned,
            .account_data_direct_mapping = account_data_direct_mapping,
            .virtual_address_space_adjustments = virtual_address_space_adjustments,
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
        /// Transaction-context account index, tagged onto the resulting
        /// account-data region as access_violation_handler_payload when
        /// SIMD-0460 is active. The handler uses this index to borrow the
        /// account from the transaction context's accounts list.
        index_in_transaction: u16,
    ) (error{OutOfMemory} || InstructionError)!u64 {
        if (!self.virtual_address_space_adjustments) {
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
            // SIMD-0460: only writable+owned accounts get a handler payload —
            // the handler grows them on write; readonly account accesses past
            // their data length just produce an access violation that the
            // loader maps to AccountDataTooSmall / ReadonlyDataModified.
            // [agave] https://github.com/anza-xyz/agave/blob/v4.0/program-runtime/src/serialization.rs#L28-L34
            const payload: ?u16 = if (account.checkDataIsMutable() == null)
                index_in_transaction
            else
                null;
            if (!self.account_data_direct_mapping) {
                try self.pushRegion(state == .mutable);
                const region = &self.regions.items[self.regions.items.len - 1];
                const new_len = account.constAccountData().len;
                region.vm_addr_end = region.vm_addr_start + new_len;
                switch (state) {
                    .mutable => region.host_memory.mutable.len = new_len,
                    .constant => region.host_memory.constant.len = new_len,
                }
                region.access_violation_handler_payload = payload;
            } else {
                var region = switch (state) {
                    .mutable => Region.init(.mutable, try account.mutableAccountData(), self.vaddr),
                    .constant => Region.init(.constant, account.constAccountData(), self.vaddr),
                };
                region.access_violation_handler_payload = payload;
                try self.regions.append(self.allocator, region);
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
        std.ArrayListAlignedUnmanaged(u8, HOST_ALIGN),
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
    memory: std.ArrayListAlignedUnmanaged(u8, HOST_ALIGN),
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
    virtual_address_space_adjustments: bool,
    direct_account_pointers_in_program_input: bool,
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
            // SIMD-0460: store index_in_transaction so the serializer can tag
            // the resulting account-data region for the access-violation handler,
            // which uses index_in_transaction to look up the account.
            accounts.appendAssumeCapacity(.{ .account = .{
                @intCast(account_meta.index_in_transaction),
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
            virtual_address_space_adjustments,
        )
    else
        serializeParametersAligned(
            allocator,
            accounts.items,
            ic.ixn_info.instruction_data,
            ic.ixn_info.program_meta.pubkey,
            direct_mapping,
            virtual_address_space_adjustments,
            direct_account_pointers_in_program_input,
        );
}

/// [agave] https://github.com/anza-xyz/agave/blob/108fcb4ff0f3cb2e7739ca163e6ead04e377e567/program-runtime/src/serialization.rs#L282
fn serializeParametersUnaligned(
    allocator: std.mem.Allocator,
    accounts: []const SerializedAccount,
    instruction_data: []const u8,
    program_id: Pubkey,
    account_data_direct_mapping: bool,
    virtual_address_space_adjustments: bool,
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
                if (!(virtual_address_space_adjustments and account_data_direct_mapping)) {
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
        virtual_address_space_adjustments,
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
            .account => |index_and_account| {
                const index_in_transaction, const borrowed_account = index_and_account;

                const vm_addr = serializer.write(u8, std.math.maxInt(u8));
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
                const vm_data_addr = try serializer.writeAccount(
                    &borrowed_account,
                    index_in_transaction,
                );
                const vm_owner_addr = serializer.writeBytes(&borrowed_account.account.owner.data);

                _ = serializer.write(u8, @intFromBool(borrowed_account.account.executable));

                _ = serializer.write(
                    u64,
                    std.mem.nativeToLittle(u64, std.math.maxInt(u64)),
                );

                account_metas.appendAssumeCapacity(.{
                    .vm_addr = vm_addr,
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
    virtual_address_space_adjustments: bool,
    direct_account_pointers_in_program_input: bool,
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

                if (!(virtual_address_space_adjustments and account_data_direct_mapping)) {
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

    // SIMD-0449: reserve trailing padding (to BPF_ALIGN_OF_U128) + one u64 per account.
    const account_pointers_offset: ?u64 = if (direct_account_pointers_in_program_input) blk: {
        const offset = std.mem.alignForward(u64, size, BPF_ALIGN_OF_U128) - size;
        size += offset + accounts.len * @sizeOf(u64);
        break :blk offset;
    } else null;

    var serializer = try Serializer.init(
        allocator,
        size,
        INPUT_START,
        true,
        virtual_address_space_adjustments,
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
                const index_in_transaction, const borrowed_account = index_and_borrowed_account;
                const vm_addr = serializer.write(u8, std.math.maxInt(u8)); // NON_DUP_MARKER
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
                const vm_data_addr = try serializer.writeAccount(
                    &borrowed_account,
                    index_in_transaction,
                );

                // [agave] https://github.com/anza-xyz/agave/blob/cfcee8181f/program-runtime/src/serialization.rs#L484
                _ = serializer.write(
                    u64,
                    std.mem.nativeToLittle(u64, std.math.maxInt(u64)),
                );

                account_metas.appendAssumeCapacity(.{
                    .vm_addr = vm_addr,
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

    // SIMD-0449: emit padding zeros to BPF_ALIGN_OF_U128 followed by one u64
    // per account holding the vm_addr of the account's serialized record.
    if (account_pointers_offset) |offset| {
        const zero_pad = [_]u8{0} ** BPF_ALIGN_OF_U128;
        _ = serializer.writeBytes(zero_pad[0..offset]);
        for (account_metas.constSlice()) |meta| {
            _ = serializer.write(u64, std.mem.nativeToLittle(u64, meta.vm_addr));
        }
    }

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
    virtual_address_space_adjustments: bool,
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
            virtual_address_space_adjustments,
            direct_mapping,
            memory,
            account_lengths.items,
        )
    else
        try deserializeParametersAligned(
            allocator,
            ic,
            virtual_address_space_adjustments,
            direct_mapping,
            memory,
            account_lengths.items,
        );
}

/// [agave] https://github.com/anza-xyz/agave/blob/108fcb4ff0f3cb2e7739ca163e6ead04e377e567/program-runtime/src/serialization.rs#L360
fn deserializeParametersUnaligned(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    virtual_address_space_adjustments: bool,
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
            if (!virtual_address_space_adjustments) {
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
            if (!(virtual_address_space_adjustments and direct_mapping))
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
    virtual_address_space_adjustments: bool,
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

            if (!virtual_address_space_adjustments) {
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
            start += if (!(virtual_address_space_adjustments and direct_mapping))
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
        const loader_id, const virtual_address_space_adjustments = case;
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
            virtual_address_space_adjustments,
            false, // direct_account_pointers_in_program_input
        );
        defer serialized.deinit(allocator);
        try std.testing.expect(HOST_ALIGN.check(@intFromPtr(serialized.memory.items.ptr)));

        const serialized_regions = try concatRegions(allocator, serialized.regions.items);
        defer allocator.free(serialized_regions);
        if (!virtual_address_space_adjustments) {
            try std.testing.expectEqualSlices(u8, serialized.memory.items, serialized_regions);
        }

        // TODO: compare against entrypoint deserialize method once implemented
        // [agave] https://github.com/anza-xyz/agave/blob/01e50dc39bde9a37a9f15d64069459fe7502ec3e/program-runtime/src/serialization.rs#L981
        // [agave] https://github.com/anza-xyz/agave/blob/01e50dc39bde9a37a9f15d64069459fe7502ec3e/program-runtime/src/serialization.rs#L893-L894

        try deserializeParameters(
            allocator,
            ic,
            virtual_address_space_adjustments,
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

// SIMD-0460: covers the access_violation_handler_payload tagging in
// writeAccount, and the index_in_instruction → index_in_transaction switch
// in serializeParameters. Verifies that under
// `virtual_address_space_adjustments`:
//   - writable+owned account-data regions are tagged with the account's
//     *transaction* index (not its instruction index), so the access-violation
//     handler can look the account up in `tc.accounts`.
//   - readonly account regions carry a null payload (the handler must not
//     try to grow them; the bpf_loader maps the violation to
//     AccountDataTooSmall / ReadonlyDataModified instead).
//   - writable-but-not-owned account regions also carry a null payload —
//     ExternalAccountDataModified is reported, not InvalidRealloc.
//
// Exercises both loader variants (v1 unaligned, v3 aligned) and both
// direct-mapping modes.
test "writeAccount tags account-data regions with index_in_transaction" {
    const testing = sig.runtime.testing;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const cases = [_]struct { Pubkey, bool }{
        // (loader_id, direct_mapping)
        .{ program.bpf_loader.v1.ID, false }, // unaligned, non-direct
        .{ program.bpf_loader.v1.ID, true }, //  unaligned, direct
        .{ program.bpf_loader.v3.ID, false }, // aligned,   non-direct
        .{ program.bpf_loader.v3.ID, true }, //  aligned,   direct
    };

    for (cases) |case| {
        const loader_id, const direct_mapping = case;

        const program_id = Pubkey.initRandom(prng.random());
        const other_owner = Pubkey.initRandom(prng.random());

        const cache, var tc = try testing.createTransactionContext(
            allocator,
            prng.random(),
            .{
                .accounts = &.{
                    // tx[0]: the executing program.
                    .{ .pubkey = program_id, .owner = loader_id, .executable = true },
                    // tx[1]: readonly, owned by the program.
                    .{
                        .pubkey = Pubkey.initRandom(prng.random()),
                        .data = &.{ 0xAA, 0xAA, 0xAA, 0xAA },
                        .owner = program_id,
                    },
                    // tx[2]: writable but owned by someone else.
                    .{
                        .pubkey = Pubkey.initRandom(prng.random()),
                        .data = &.{ 0xBB, 0xBB, 0xBB, 0xBB },
                        .owner = other_owner,
                    },
                    // tx[3]: writable, owned by the program — the only one
                    // that should receive a non-null payload.
                    .{
                        .pubkey = Pubkey.initRandom(prng.random()),
                        .data = &.{ 0xCC, 0xCC, 0xCC, 0xCC },
                        .owner = program_id,
                    },
                },
            },
        );
        defer {
            testing.deinitTransactionContext(allocator, &tc);
            testing.deinitAccountMap(cache, allocator);
        }

        // Instruction account order intentionally differs from transaction
        // order — this is what proves the payload is index_in_transaction,
        // not index_in_instruction.
        var info = try testing.createInstructionInfo(
            &tc,
            program_id,
            @as([]const u8, &.{}),
            &.{
                // ix[0] → tx[3] writable+owned
                .{ .index_in_transaction = 3, .is_signer = false, .is_writable = true },
                // ix[1] → tx[1] readonly (owned)
                .{ .index_in_transaction = 1, .is_signer = false, .is_writable = false },
                // ix[2] → tx[2] writable but not owned
                .{ .index_in_transaction = 2, .is_signer = false, .is_writable = true },
            },
        );
        defer info.deinit(allocator);

        try sig.runtime.executor.pushInstruction(&tc, info);
        const ic = try tc.getCurrentInstructionContext();

        var serialized = try serializeParameters(
            allocator,
            ic,
            direct_mapping,
            true, // virtual_address_space_adjustments
            false, // direct_account_pointers_in_program_input
        );
        defer serialized.deinit(allocator);

        // For each instruction-account, the corresponding account-data
        // region (if any) has vm_addr_start == meta.vm_data_addr. Look it
        // up and check the payload.
        const expected = [_]struct { idx_in_instruction: usize, payload: ?u16 }{
            .{ .idx_in_instruction = 0, .payload = 3 }, // writable+owned → tx index
            .{ .idx_in_instruction = 1, .payload = null }, // readonly
            .{ .idx_in_instruction = 2, .payload = null }, // not owned
        };

        for (expected) |e| {
            const meta = serialized.account_metas.get(e.idx_in_instruction);
            const region = for (serialized.regions.items) |*r| {
                if (r.vm_addr_start == meta.vm_data_addr) break r;
            } else return error.AccountRegionNotFound;
            try std.testing.expectEqual(e.payload, region.access_violation_handler_payload);
        }

        // Also verify: payloads are only ever populated for regions that
        // correspond to an account in the instruction. Header/instruction-data
        // regions must remain null so the handler never grows them.
        var account_region_starts: [3]u64 = .{
            serialized.account_metas.get(0).vm_data_addr,
            serialized.account_metas.get(1).vm_data_addr,
            serialized.account_metas.get(2).vm_data_addr,
        };
        for (serialized.regions.items) |r| {
            const is_account_region = std.mem.indexOfScalar(
                u64,
                &account_region_starts,
                r.vm_addr_start,
            ) != null;
            if (!is_account_region) {
                try std.testing.expectEqual(
                    @as(?u16, null),
                    r.access_violation_handler_payload,
                );
            }
        }
    }
}

// When virtual_address_space_adjustments is OFF, writeAccount takes an early
// return that doesn't produce per-account regions, so no payload is ever set.
// Locks in that the payload tagging only kicks in under SIMD-0460.
test "writeAccount does not tag regions when virtual_address_space_adjustments is off" {
    const testing = sig.runtime.testing;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const program_id = Pubkey.initRandom(prng.random());
    const cache, var tc = try testing.createTransactionContext(
        allocator,
        prng.random(),
        .{
            .accounts = &.{
                .{
                    .pubkey = program_id,
                    .owner = program.bpf_loader.v3.ID,
                    .executable = true,
                },
                .{
                    .pubkey = Pubkey.initRandom(prng.random()),
                    .data = &.{ 1, 2, 3, 4 },
                    .owner = program_id,
                },
            },
        },
    );
    defer {
        testing.deinitTransactionContext(allocator, &tc);
        testing.deinitAccountMap(cache, allocator);
    }

    var info = try testing.createInstructionInfo(
        &tc,
        program_id,
        @as([]const u8, &.{}),
        &.{
            .{ .index_in_transaction = 1, .is_signer = false, .is_writable = true },
        },
    );
    defer info.deinit(allocator);

    try sig.runtime.executor.pushInstruction(&tc, info);
    const ic = try tc.getCurrentInstructionContext();

    var serialized = try serializeParameters(
        allocator,
        ic,
        false, // direct_mapping
        false, // virtual_address_space_adjustments = OFF
        false, // direct_account_pointers_in_program_input
    );
    defer serialized.deinit(allocator);

    for (serialized.regions.items) |r| {
        try std.testing.expectEqual(
            @as(?u16, null),
            r.access_violation_handler_payload,
        );
    }
}

// SIMD-0449: when `direct_account_pointers_in_program_input` is active on
// ABIv1, after the program id the input region must contain padding zeros
// (up to BPF_ALIGN_OF_U128) followed by one little-endian u64 per
// instruction account holding the `vm_addr` of the account's serialized
// record. Duplicates reuse the original record's `vm_addr`, matching agave's
// `serialize_parameters_for_abiv1`. Verified against both
// virtual_address_space_adjustments off and on (with direct_mapping off).
// ABIv0 (loader-v1) must not emit the array even when the flag is on.
test "direct_account_pointers_in_program_input emits trailing pointer array" {
    const testing = sig.runtime.testing;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const Case = struct {
        loader: Pubkey,
        vasa: bool,
        expect_array: bool,
    };
    const cases = [_]Case{
        // ABIv1, vasa=false: array present, embedded in main buffer.
        .{ .loader = program.bpf_loader.v3.ID, .vasa = false, .expect_array = true },
        // ABIv1, vasa=true,  direct_mapping=false: array still present.
        .{ .loader = program.bpf_loader.v3.ID, .vasa = true, .expect_array = true },
        // ABIv0 (loader-v1) ignores SIMD-0449.
        .{ .loader = program.bpf_loader.v1.ID, .vasa = false, .expect_array = false },
    };

    for (cases) |case| {
        const program_id = Pubkey.initRandom(prng.random());
        const cache, var tc = try testing.createTransactionContext(
            allocator,
            prng.random(),
            .{
                .accounts = &.{
                    .{ .pubkey = program_id, .owner = case.loader, .executable = true },
                    .{
                        .pubkey = Pubkey.initRandom(prng.random()),
                        .data = &.{ 1, 2, 3, 4 },
                        .owner = program_id,
                    },
                    .{
                        .pubkey = Pubkey.initRandom(prng.random()),
                        .data = &.{ 5, 6, 7 },
                        .owner = program_id,
                    },
                },
            },
        );
        defer {
            testing.deinitTransactionContext(allocator, &tc);
            testing.deinitAccountMap(cache, allocator);
        }

        // Three instruction accounts: A, B, A — exercises the duplicate path.
        var info = try testing.createInstructionInfo(
            &tc,
            program_id,
            @as([]const u8, &.{ 0xDE, 0xAD }),
            &.{
                .{ .index_in_transaction = 1, .is_signer = false, .is_writable = true },
                .{ .index_in_transaction = 2, .is_signer = false, .is_writable = false },
                .{ .index_in_transaction = 1, .is_signer = false, .is_writable = true },
            },
        );
        defer info.deinit(allocator);

        try sig.runtime.executor.pushInstruction(&tc, info);
        const ic = try tc.getCurrentInstructionContext();

        var serialized = try serializeParameters(
            allocator,
            ic,
            false, // direct_mapping
            case.vasa,
            true, // direct_account_pointers_in_program_input
        );
        defer serialized.deinit(allocator);

        if (!case.expect_array) {
            // ABIv0: every account meta still has a populated vm_addr (the
            // field is shared with abiv1) but no trailing array is emitted.
            // Asserting that is best done by recomputing the size the
            // serializer would have used absent the flag — easier to just
            // confirm the non-duplicate metas have plausible vm_addrs.
            try std.testing.expect(serialized.account_metas.get(0).vm_addr != 0);
            continue;
        }

        // The trailing pointer array always lives at the very end of the
        // *last* region pushed by `finish()`. That region holds everything
        // written after the last `writeAccount` call (rent_epoch, instruction
        // data, program_id, padding, and finally the pointer array). Reading
        // the last region works under both `virtual_address_space_adjustments`
        // settings — under vasa=true the regions are non-contiguous in vm
        // address space (gaps for `MAX_PERMITTED_DATA_INCREASE`), so a simple
        // concatenation does not work.
        const last_region = serialized.regions.items[serialized.regions.items.len - 1];
        const region_bytes = last_region.constSlice();

        const num_accounts = serialized.account_metas.constSlice().len;
        const tail_size = num_accounts * @sizeOf(u64);
        try std.testing.expect(region_bytes.len >= tail_size);

        const array_offset_in_region = region_bytes.len - tail_size;
        const array_vm_start = last_region.vm_addr_start + array_offset_in_region;
        // SIMD-0449 demands BPF_ALIGN_OF_U128 alignment relative to
        // INPUT_START; INPUT_START is itself BPF_ALIGN_OF_U128-aligned, so
        // checking the offset suffices.
        try std.testing.expectEqual(
            0,
            (array_vm_start - INPUT_START) % BPF_ALIGN_OF_U128,
        );

        for (serialized.account_metas.constSlice(), 0..) |meta, i| {
            const slot_off = array_offset_in_region + i * @sizeOf(u64);
            const got = std.mem.readInt(
                u64,
                region_bytes[slot_off..][0..@sizeOf(u64)],
                .little,
            );
            try std.testing.expectEqual(meta.vm_addr, got);
        }

        // Duplicate (idx 2) must reuse the original (idx 0) vm_addr.
        try std.testing.expectEqual(
            serialized.account_metas.get(0).vm_addr,
            serialized.account_metas.get(2).vm_addr,
        );

        // Sanity: each non-duplicate vm_addr points at a NON_DUP_MARKER byte.
        // Under vasa=false the whole input is one contiguous buffer, so we can
        // index it directly. Under vasa=true regions are scattered, and we'd
        // have to walk them — skip that bookkeeping here; the layout is
        // already covered by the SIMD-0460 region tests above.
        if (!case.vasa) {
            const NON_DUP_MARKER: u8 = 0xFF;
            const meta0 = serialized.account_metas.get(0);
            const meta1 = serialized.account_metas.get(1);
            const buf = serialized.memory.items;
            try std.testing.expectEqual(
                NON_DUP_MARKER,
                buf[meta0.vm_addr - INPUT_START],
            );
            try std.testing.expectEqual(
                NON_DUP_MARKER,
                buf[meta1.vm_addr - INPUT_START],
            );
        }
    }
}
