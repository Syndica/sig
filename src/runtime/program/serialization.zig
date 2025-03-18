const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../../sig.zig");

const ids = sig.runtime.ids;
const program = sig.runtime.program;
const vm = sig.vm;

const Pubkey = sig.core.Pubkey;
const InstructionError = sig.core.instruction.InstructionError;

const InstructionContext = sig.runtime.InstructionContext;
const BorrowedAccount = sig.runtime.BorrowedAccount;

const Region = vm.memory.Region;

const MAX_PERMITTED_DATA_LENGTH = sig.runtime.program.system_program.MAX_PERMITTED_DATA_LENGTH;

const INPUT_START = sig.vm.memory.INPUT_START;

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/e1554f4067329a0dcf5035120ec6a06275d3b9ec/program-entrypoint/src/lib.rs#L316
/// `assert_eq(std::mem::align_of::<u128>(), 8)` is true for BPF but not for some host machines
pub const BPF_ALIGN_OF_U128: usize = 8;

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/e1554f4067329a0dcf5035120ec6a06275d3b9ec/account-info/src/lib.rs#L17-L18
pub const MAX_PERMITTED_DATA_INCREASE: usize = 1_024 * 10;

pub const SerializedAccount = union(enum) {
    account: struct { u16, BorrowedAccount },
    duplicate: u8,
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
    ) error{OutOfMemory}!Serializer {
        return .{
            .allocator = allocator,
            .buffer = try std.ArrayListUnmanaged(u8).initCapacity(allocator, size),
            .regions = std.BoundedArray(Region, 4){},
            .vaddr = region_start,
            .region_start = 0,
            .aligned = aligned,
            .copy_account_data = copy_account_data,
        };
    }

    pub fn deinit(self: *Serializer) void {
        self.buffer.deinit(self.allocator);
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/01e50dc39bde9a37a9f15d64069459fe7502ec3e/program-runtime/src/serialization.rs#L56-L57
    pub fn write(self: *Serializer, comptime T: type, value: T) u64 {
        const vaddr = self.vaddr +| self.buffer.items.len -| self.region_start;
        self.buffer.appendSliceAssumeCapacity(std.mem.asBytes(&value));
        return vaddr;
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/01e50dc39bde9a37a9f15d64069459fe7502ec3e/program-runtime/src/serialization.rs#L77-L78
    pub fn writeAll(self: *Serializer, data: []const u8) u64 {
        const vaddr = self.vaddr +| self.buffer.items.len -| self.region_start;
        self.buffer.appendSliceAssumeCapacity(data);
        return vaddr;
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/01e50dc39bde9a37a9f15d64069459fe7502ec3e/program-runtime/src/serialization.rs#L91-L92
    pub fn writeAccount(self: *Serializer, account: *const BorrowedAccount) InstructionError!u64 {
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
            const align_offset = std.mem.alignForward(
                usize,
                account.constAccountData().len,
                BPF_ALIGN_OF_U128,
            ) - account.constAccountData().len;

            if (self.copy_account_data) {
                self.buffer.appendNTimes(
                    self.allocator,
                    0,
                    MAX_PERMITTED_DATA_INCREASE + align_offset,
                ) catch {
                    return InstructionError.InvalidArgument;
                };
            } else {
                self.buffer.appendNTimes(
                    self.allocator,
                    0,
                    MAX_PERMITTED_DATA_INCREASE + BPF_ALIGN_OF_U128,
                ) catch {
                    return InstructionError.InvalidArgument;
                };
                self.region_start += BPF_ALIGN_OF_U128 -| align_offset;
                self.pushRegion(account.checkDataIsMutable() == null);
            }
        }

        return vm_data_addr;
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/01e50dc39bde9a37a9f15d64069459fe7502ec3e/program-runtime/src/serialization.rs#L154-L155
    pub fn pushRegion(self: *Serializer, is_writable: bool) void {
        const range_size = self.buffer.items.len -| self.region_start;

        const region = switch (is_writable) {
            inline true, false => |mutable| Region.init(
                if (mutable) .mutable else .constant,
                self.buffer.items[self.region_start..self.buffer.items.len],
                self.vaddr,
            ),
        };

        self.regions.appendAssumeCapacity(region);
        self.region_start = self.buffer.items.len;
        self.vaddr += range_size;
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/01e50dc39bde9a37a9f15d64069459fe7502ec3e/program-runtime/src/serialization.rs#L133-L134
    pub fn pushAccountDataRegion(
        self: *Serializer,
        account: *const BorrowedAccount,
    ) InstructionError!void {
        // TODO: Cow https://github.com/anza-xyz/agave/blob/01e50dc39bde9a37a9f15d64069459fe7502ec3e/program-runtime/src/serialization.rs#L134
        if (account.constAccountData().len > 0) {
            const state = getAccountDataRegionMemoryState(account);
            const region = switch (state) {
                inline .constant, .mutable => |s| Region.init(
                    s,
                    if (s == .constant)
                        account.constAccountData()
                    else
                        try account.mutableAccountData(),
                    self.vaddr,
                ),
            };
            self.vaddr += account.constAccountData().len;
            self.regions.appendAssumeCapacity(region);
        }
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/01e50dc39bde9a37a9f15d64069459fe7502ec3e/program-runtime/src/serialization.rs#L172
    pub fn finish(self: *Serializer) error{OutOfMemory}!struct { []u8, []Region } {
        self.pushRegion(true);
        std.debug.assert(self.region_start == self.buffer.items.len);
        return .{ try self.buffer.toOwnedSlice(self.allocator), self.regions.slice() };
    }

    pub fn getAccountDataRegionMemoryState(account: *const BorrowedAccount) vm.memory.MemoryState {
        // TODO: Cow https://github.com/anza-xyz/agave/blob/01e50dc39bde9a37a9f15d64069459fe7502ec3e/program-runtime/src/serialization.rs#L608
        if (account.checkDataIsMutable() != null) return .constant;
        return .mutable;
    }
};

pub fn serializeParameters(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    copy_account_data: bool,
) (error{OutOfMemory} || InstructionError)!struct {
    []u8,
    []Region,
    []SerializedAccountMeta,
} {
    if (ic.info.account_metas.len > std.math.maxInt(u8))
        return InstructionError.MaxAccountsExceeded;

    const is_loader_v1 = blk: {
        const program_account = try ic.borrowProgramAccount();
        defer program_account.release();
        break :blk program_account.account.owner.equals(&ids.BPF_LOADER_V1_PROGRAM_ID);
    };

    var accounts = std.ArrayList(SerializedAccount).initCapacity(
        allocator,
        ic.info.account_metas.len,
    ) catch return InstructionError.ProgramEnvironmentSetupFailure;

    for (ic.info.account_metas.constSlice(), 0..) |account_meta, index_in_instruction| {
        if (account_meta.index_in_callee != index_in_instruction) {
            accounts.appendAssumeCapacity(.{ .duplicate = @intCast(account_meta.index_in_callee) });
        } else {
            const account = try ic.borrowInstructionAccount(account_meta.index_in_transaction);
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
            try accounts.toOwnedSlice(),
            ic.info.instruction_data,
            ic.info.program_meta.pubkey,
            copy_account_data,
        )
    else
        serializeParametersAligned(
            allocator,
            try accounts.toOwnedSlice(),
            ic.info.instruction_data,
            ic.info.program_meta.pubkey,
            copy_account_data,
        );
}

fn serializeParametersUnaligned(
    allocator: std.mem.Allocator,
    accounts: []SerializedAccount,
    instruction_data: []const u8,
    program_id: Pubkey,
    copy_account_data: bool,
) (error{OutOfMemory} || InstructionError)!struct {
    []u8,
    []Region,
    []SerializedAccountMeta,
} {
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
                if (copy_account_data) {
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
        copy_account_data,
    );

    var account_metas = try std.ArrayListUnmanaged(SerializedAccountMeta).initCapacity(
        allocator,
        accounts.len,
    );
    defer account_metas.deinit(allocator);

    _ = serializer.write(u64, std.mem.nativeToLittle(u64, accounts.len));
    for (accounts) |account| {
        switch (account) {
            .account => |index_and_account| {
                _, const borrowed_account = index_and_account;

                _ = serializer.write(u8, std.math.maxInt(u8));
                _ = serializer.write(u8, @intFromBool(borrowed_account.context.is_signer));
                _ = serializer.write(u8, @intFromBool(borrowed_account.context.is_writable));

                const vm_key_addr = serializer.writeAll(&borrowed_account.pubkey.data);
                const vm_lamports_addr = serializer.write(
                    u64,
                    std.mem.nativeToLittle(u64, borrowed_account.account.lamports),
                );

                _ = serializer.write(
                    u64,
                    std.mem.nativeToLittle(u64, borrowed_account.constAccountData().len),
                );
                const vm_data_addr = try serializer.writeAccount(&borrowed_account);
                const vm_owner_addr = serializer.writeAll(&borrowed_account.account.owner.data);

                _ = serializer.write(u8, @intFromBool(borrowed_account.account.executable));
                _ = serializer.write(
                    u64,
                    std.mem.nativeToLittle(u64, borrowed_account.account.rent_epoch),
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
                account_metas.appendAssumeCapacity(account_metas.items[index]);
                _ = serializer.write(u8, @intCast(index));
            },
        }
    }
    _ = serializer.write(u64, std.mem.nativeToLittle(u64, instruction_data.len));
    _ = serializer.writeAll(instruction_data);
    _ = serializer.writeAll(&program_id.data);

    const memory, const regions = try serializer.finish();

    return .{
        memory,
        regions,
        try account_metas.toOwnedSlice(allocator),
    };
}

fn serializeParametersAligned(
    allocator: std.mem.Allocator,
    accounts: []SerializedAccount,
    instruction_data: []const u8,
    program_id: Pubkey,
    copy_account_data: bool,
) (error{OutOfMemory} || InstructionError)!struct {
    []u8,
    []Region,
    []SerializedAccountMeta,
} {
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
                    const data_len = borrowed_account.constAccountData().len;
                    const align_offset = std.mem.alignForward(
                        usize,
                        data_len,
                        BPF_ALIGN_OF_U128,
                    ) - data_len;
                    size += borrowed_account.constAccountData().len + align_offset;
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
                _ = serializer.write(u8, @intFromBool(borrowed_account.context.is_signer));
                _ = serializer.write(u8, @intFromBool(borrowed_account.context.is_writable));
                _ = serializer.write(u8, @intFromBool(borrowed_account.account.executable));
                _ = serializer.writeAll(&.{ 0, 0, 0, 0 });

                const vm_key_addr = serializer.writeAll(&borrowed_account.pubkey.data);
                const vm_owner_addr = serializer.writeAll(&borrowed_account.account.owner.data);
                const vm_lamports_addr = serializer.write(
                    u64,
                    std.mem.nativeToLittle(u64, borrowed_account.account.lamports),
                );

                _ = serializer.write(
                    u64,
                    std.mem.nativeToLittle(u64, borrowed_account.constAccountData().len),
                );
                const vm_data_addr = try serializer.writeAccount(&borrowed_account);

                _ = serializer.write(
                    u64,
                    std.mem.nativeToLittle(u64, borrowed_account.account.rent_epoch),
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
                account_metas.appendAssumeCapacity(account_metas.items[index]);
                _ = serializer.write(u8, index);
                _ = serializer.writeAll(&.{ 0, 0, 0, 0, 0, 0, 0 });
            },
        }
    }

    _ = serializer.write(u64, std.mem.nativeToLittle(u64, instruction_data.len));
    _ = serializer.writeAll(instruction_data);
    _ = serializer.writeAll(&program_id.data);

    const memory, const regions = try serializer.finish();
    errdefer allocator.free(memory);

    return .{
        memory,
        regions,
        try account_metas.toOwnedSlice(allocator),
    };
}

pub fn deserializeParameters(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    copy_account_data: bool,
    memory: []u8,
    account_metas: []SerializedAccountMeta,
) (error{OutOfMemory} || InstructionError)!void {
    const is_loader_v1 = blk: {
        const program_account = try ic.borrowProgramAccount();
        defer program_account.release();
        break :blk program_account.account.owner.equals(&ids.BPF_LOADER_V1_PROGRAM_ID);
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
            copy_account_data,
            memory,
            try account_lengths.toOwnedSlice(allocator),
        )
    else
        try deserializeParametersAligned(
            allocator,
            ic,
            copy_account_data,
            memory,
            try account_lengths.toOwnedSlice(allocator),
        );
}

fn deserializeParametersUnaligned(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    copy_account_data: bool,
    memory: []u8,
    account_lengths: []const usize,
) (error{OutOfMemory} || InstructionError)!void {
    var start: usize = @sizeOf(u64);
    for (0..ic.info.account_metas.len) |index_in_instruction_| {
        const index_in_instruction: u16 = @intCast(index_in_instruction_);
        const account_meta = ic.info.account_metas.buffer[index_in_instruction];
        const pre_len = account_lengths[index_in_instruction];

        start += 1; // is_dup
        if (account_meta.index_in_callee == index_in_instruction) {
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

            // add data length
            start += @sizeOf(u64);
            if (copy_account_data) {
                if (start + pre_len > memory.len) return InstructionError.InvalidArgument;
                const data = memory[start .. start + pre_len];
                const can_data_be_resized =
                    borrowed_account.checkCanSetDataLength(ic.tc.accounts_resize_delta, pre_len);
                const can_data_be_mutated = borrowed_account.checkDataIsMutable();
                if (can_data_be_resized == null and can_data_be_mutated == null) {
                    try borrowed_account.setDataFromSlice(
                        allocator,
                        &ic.tc.accounts_resize_delta,
                        data,
                    );
                } else {
                    if (!std.mem.eql(u8, borrowed_account.account.data, data)) {
                        if (can_data_be_resized) |err| return err;
                        if (can_data_be_mutated) |err| return err;
                    }
                }
            }
        }

        start += @sizeOf(Pubkey) // owner
        + @sizeOf(u8) // executable
        + @sizeOf(u64); // rent_epoch
    }
}

fn deserializeParametersAligned(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    copy_account_data: bool,
    memory: []u8,
    account_lengths: []const usize,
) (error{OutOfMemory} || InstructionError)!void {
    var start: usize = @sizeOf(u64);

    for (0..ic.info.account_metas.len) |index_in_instruction_| {
        const index_in_instruction: u16 = @intCast(index_in_instruction_);
        const account_meta = ic.info.account_metas.buffer[index_in_instruction];
        const pre_len = account_lengths[index_in_instruction];

        start += @sizeOf(u8);
        if (account_meta.index_in_callee != index_in_instruction) {
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
            const owner = memory[start .. start + @sizeOf(Pubkey)];
            start += @sizeOf(Pubkey);

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

            // read and check data length
            if (start + @sizeOf(u64) > memory.len) return InstructionError.InvalidArgument;
            const post_len = std.mem.readInt(
                u64,
                memory[start .. start + @sizeOf(u64)][0..@sizeOf(u64)],
                .little,
            );
            start += @sizeOf(u64);
            if (post_len -| pre_len > MAX_PERMITTED_DATA_INCREASE or
                post_len > MAX_PERMITTED_DATA_LENGTH)
            {
                return InstructionError.InvalidRealloc;
            }

            const alignment_offset = std.mem.alignForward(
                usize,
                pre_len,
                BPF_ALIGN_OF_U128,
            ) - pre_len;
            if (copy_account_data) {
                if (start + post_len > memory.len) return InstructionError.InvalidArgument;
                const data = memory[start .. start + post_len];
                const can_data_be_resized =
                    borrowed_account.checkCanSetDataLength(ic.tc.accounts_resize_delta, post_len);
                const can_data_be_mutated = borrowed_account.checkDataIsMutable();
                if (can_data_be_resized == null and can_data_be_mutated == null) {
                    try borrowed_account.setDataFromSlice(
                        allocator,
                        &ic.tc.accounts_resize_delta,
                        data,
                    );
                } else {
                    if (!std.mem.eql(u8, borrowed_account.account.data, data)) {
                        if (can_data_be_resized) |err| return err;
                        if (can_data_be_mutated) |err| return err;
                    }
                }
            } else {
                start += BPF_ALIGN_OF_U128 -| alignment_offset;
                if (start + post_len > memory.len) return InstructionError.InvalidArgument;
                const data = memory[start .. start + post_len];
                const can_data_be_resized =
                    borrowed_account.checkCanSetDataLength(ic.tc.accounts_resize_delta, post_len);
                const can_data_be_mutated = borrowed_account.checkDataIsMutable();
                if (can_data_be_resized == null and can_data_be_mutated == null) {
                    try borrowed_account.setDataLength(
                        allocator,
                        &ic.tc.accounts_resize_delta,
                        post_len,
                    );
                    const allocated_bytes = post_len -| pre_len;
                    if (allocated_bytes > 0) {
                        const account_data = try borrowed_account.mutableAccountData();
                        if (pre_len +| allocated_bytes > account_data.len) {
                            return InstructionError.InvalidArgument;
                        }
                        if (allocated_bytes > data.len) {
                            return InstructionError.InvalidArgument;
                        }
                        @memcpy(
                            account_data[pre_len..pre_len +| allocated_bytes],
                            data[0..allocated_bytes],
                        );
                    }
                } else {
                    if (borrowed_account.constAccountData().len != post_len) {
                        if (can_data_be_resized) |err| return err;
                        if (can_data_be_mutated) |err| return err;
                    }
                }
            }

            start += MAX_PERMITTED_DATA_INCREASE;
            start += alignment_offset;
            start += @sizeOf(u64); // rent_epoch

            // update owner at the end so that we are allowed to change the lamports and data
            if (!std.mem.eql(u8, &borrowed_account.account.owner.data, owner)) {
                try borrowed_account.setOwner(.{ .data = owner[0..@sizeOf(Pubkey)].* });
            }
        }
    }
}

test "serializeParameters" {
    const TransactionContextAccount = sig.runtime.TransactionContextAccount;
    const createTransactionContext = sig.runtime.testing.createTransactionContext;
    const createInstructionInfo = sig.runtime.testing.createInstructionInfo;

    // const allocator = std.testing.allocator;
    const allocator = std.heap.page_allocator;
    var prng = std.rand.DefaultPrng.init(0);

    for ([_]Pubkey{
        ids.BPF_LOADER_V1_PROGRAM_ID,
        ids.BPF_LOADER_V2_PROGRAM_ID,
        ids.BPF_LOADER_V3_PROGRAM_ID,
    }) |loader_id| {
        for ([_]bool{
            false,
            true,
        }) |copy_account_data| {
            const program_id = Pubkey.initRandom(prng.random());

            var tc = try createTransactionContext(
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
                            .data = try allocator.dupe(u8, &.{ 1, 2, 3, 4, 5 }),
                            .owner = loader_id,
                            .executable = false,
                            .rent_epoch = 100,
                        },
                        .{
                            .pubkey = Pubkey.initRandom(prng.random()),
                            .lamports = 2,
                            .data = try allocator.dupe(
                                u8,
                                &.{ 11, 12, 13, 14, 15, 16, 17, 18, 19 },
                            ),
                            .owner = loader_id,
                            .executable = true,
                            .rent_epoch = 200,
                        },
                        .{
                            .pubkey = Pubkey.initRandom(prng.random()),
                            .lamports = 3,
                            .data = try allocator.dupe(u8, &.{}),
                            .owner = loader_id,
                            .executable = false,
                            .rent_epoch = 3100,
                        },
                        .{
                            .pubkey = Pubkey.initRandom(prng.random()),
                            .lamports = 4,
                            .data = try allocator.dupe(u8, &.{ 1, 2, 3, 4, 5 }),
                            .owner = loader_id,
                            .executable = false,
                            .rent_epoch = 100,
                        },
                        .{
                            .pubkey = Pubkey.initRandom(prng.random()),
                            .lamports = 5,
                            .data = try allocator.dupe(
                                u8,
                                &.{ 11, 12, 13, 14, 15, 16, 17, 18, 19 },
                            ),
                            .owner = loader_id,
                            .executable = true,
                            .rent_epoch = 200,
                        },
                        .{
                            .pubkey = Pubkey.initRandom(prng.random()),
                            .lamports = 6,
                            .data = try allocator.dupe(u8, &.{}),
                            .owner = loader_id,
                            .executable = false,
                            .rent_epoch = 3100,
                        },
                    },
                },
            );
            defer tc.deinit(allocator);

            const instruction_info = try createInstructionInfo(
                allocator,
                &tc,
                program_id,
                [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 },
                &.{
                    .{
                        .index_in_transaction = 1,
                        .index_in_caller = 1,
                        .index_in_callee = 0,
                        .is_signer = false,
                        .is_writable = false,
                    },
                    .{
                        .index_in_transaction = 1,
                        .index_in_caller = 1,
                        .index_in_callee = 0,
                        .is_signer = false,
                        .is_writable = false,
                    },
                    .{
                        .index_in_transaction = 2,
                        .index_in_caller = 2,
                        .index_in_callee = 1,
                        .is_signer = false,
                        .is_writable = false,
                    },
                    .{
                        .index_in_transaction = 3,
                        .index_in_caller = 3,
                        .index_in_callee = 2,
                        .is_signer = false,
                        .is_writable = false,
                    },
                    .{
                        .index_in_transaction = 4,
                        .index_in_caller = 4,
                        .index_in_callee = 3,
                        .is_signer = false,
                        .is_writable = true,
                    },
                    .{
                        .index_in_transaction = 4,
                        .index_in_caller = 4,
                        .index_in_callee = 3,
                        .is_signer = false,
                        .is_writable = true,
                    },
                    .{
                        .index_in_transaction = 5,
                        .index_in_caller = 5,
                        .index_in_callee = 4,
                        .is_signer = false,
                        .is_writable = true,
                    },
                    .{
                        .index_in_transaction = 6,
                        .index_in_caller = 6,
                        .index_in_callee = 5,
                        .is_signer = false,
                        .is_writable = true,
                    },
                },
            );

            var ic = InstructionContext{
                .tc = &tc,
                .info = instruction_info,
                .depth = 0,
            };

            const pre_accounts = blk: {
                var accounts = std.ArrayList(TransactionContextAccount).init(allocator);
                errdefer {
                    for (accounts.items) |account| account.deinit(allocator);
                    accounts.deinit();
                }
                for (tc.accounts) |account| {
                    try accounts.append(TransactionContextAccount.init(account.pubkey, .{
                        .lamports = account.account.lamports,
                        .owner = account.account.owner,
                        .data = try allocator.dupe(u8, account.account.data),
                        .executable = account.account.executable,
                        .rent_epoch = account.account.rent_epoch,
                    }));
                }
                break :blk try accounts.toOwnedSlice();
            };
            defer {
                for (pre_accounts) |account| account.deinit(allocator);
                allocator.free(pre_accounts);
            }

            const memory, const regions, const account_metas = try serializeParameters(
                allocator,
                &ic,
                copy_account_data,
            );

            const serialized_regions = try concatRegions(allocator, regions);
            if (copy_account_data) {
                try std.testing.expectEqualSlices(u8, memory, serialized_regions);
            }

            // TODO: deserialize and compare
            // [agave] https://github.com/anza-xyz/agave/blob/01e50dc39bde9a37a9f15d64069459fe7502ec3e/program-runtime/src/serialization.rs#L981
            // [agave] https://github.com/anza-xyz/agave/blob/01e50dc39bde9a37a9f15d64069459fe7502ec3e/program-runtime/src/serialization.rs#L893-L894

            try deserializeParameters(
                allocator,
                &ic,
                copy_account_data,
                memory,
                account_metas,
            );
            for (pre_accounts, 0..) |pre_account, index_in_transaction| {
                const post_account = tc.accounts[index_in_transaction];
                try std.testing.expectEqual(
                    pre_account.read_refs,
                    post_account.read_refs,
                );
                try std.testing.expectEqual(
                    pre_account.write_ref,
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
}

fn concatRegions(allocator: std.mem.Allocator, regions: []Region) ![]u8 {
    if (!builtin.is_test) {
        @panic("concatRegions should only be called in test mode");
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
