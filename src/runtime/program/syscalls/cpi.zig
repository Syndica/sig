const std = @import("std");
const sig = @import("../../sig.zig");

const memory = @import("../../vm/memory.zig");
const MemoryMap = memory.MemoryMap;

const ids = sig.runtime.ids;
const bincode = sig.bincode;
const program = sig.runtime.program;
const pubkey_utils = sig.runtime.pubkey_utils;
const sysvar = sig.runtime.sysvar;
const system_program = sig.runtime.program.system_program;
const feature_set = sig.runtime.feature_set;

const Pubkey = sig.core.Pubkey;
const Hash = sig.core.Hash;
const ComputeBudget = sig.runtime.ComputeBudget;
const InstructionError = sig.core.instruction.InstructionError;

const FeatureSet = sig.runtime.FeatureSet;
const InstructionContext = sig.runtime.InstructionContext;
const TransactionContext = sig.runtime.TransactionContext;
const TransactionContextAccount = sig.runtime.TransactionContextAccount;
const AccountSharedData = sig.runtime.AccountSharedData;
const LogCollector = sig.runtime.LogCollector;

const Epoch = sig.core.Epoch;
const InstructionAccount = sig.core.instruction.InstructionAccount;
const InstructionError = sig.core.instruction.InstructionError;

/// [agave] https://github.com/anza-xyz/agave/blob/359d7eb2b68639443d750ffcec0c7e358f138975/programs/bpf_loader/src/syscalls/mod.rs#L86
const SyscallError = error {
    InvalidPointer,
    InvalidLength,
    UnalignedPointer,
    MaxInstructionAccountInfosExceeded,
};

fn StableVec(comptime T: type) type {
    return extern struct {
        const Self = @This();

        addr: u64,
        cap: u64,
        len: u64,

        fn slice(self: Self, comptime state: memory.MemoryState) switch (state) {
            .constant => []const T,
            .mutable => []T,
        } {
            return switch (state) {
                .constant => @as([*]const T, @ptrFromInt(self.addr))[0..self.len],
                .mtuable => @as([*]T, @ptrFromInt(self.addr))[0..self.len],
            };
        }
    };
}

const StableInstruction = extern struct {
    accounts: StableVec(AccountMeta),
    data: StableVec(u8),
    program_id: Pubkey,
};

/// This struct will be backed by mmaped and snapshotted data files.
/// So the data layout must be stable and consistent across the entire cluster!
const AccountMeta = extern struct {
    /// lamports in the account
    lamports: u64,
    /// the epoch at which this account will next owe rent
    rent_epoch: Epoch,
    /// the program that owns this account. If executable, the program that loads this account.
    owner: Pubkey,
    /// this account's data contains a loaded program (and is now read-only)
    executable: bool,
};

const SerializedAccountMetadata = struct {
    original_data_len: usize,
    vm_data_addr: u64,
    vm_key_addr: u64,
    vm_lamports_addr: u64,
    vm_owner_addr: u64,
};

/// [agave] https://github.com/anza-xyz/agave/blob/master/359d7eb2b68639443d750ffcec0c7e358f138975/bpf_loader/src/syscalls/cpi.rs#L597
const SolAccountInfo = extern struct {
    key_addr: u64,
    lamports_addr: u64,
    data_len: u64,
    data_addr: u64,
    owner_addr: u64,
    rent_epoch: u64,
    is_signer: bool,
    is_writable: bool,
    executable: bool,
};

const AccountInfo = struct {
    key: *const Pubkey,
    is_signer: bool,
    is_writable: bool,
    lamports: *const u64,
    data: []const u8,
    owner: *const Pubkey,
    executable: bool,
    rent_epoch: Epoch,
};

fn VmValue(comptime T: type) type {
    return union(enum) {
        vm_address: struct {
            vm_addr: u64,
            memory_map: *const MemoryMap,
            check_aligned: bool,
        },
        translated: *T,
    };
}

const MM_INPUT_START = memory.INPUT_START;

/// [agave] https://github.com/anza-xyz/agave/blob/359d7eb2b68639443d750ffcec0c7e358f138975/programs/bpf_loader/src/syscalls/mod.rs#L604
fn translate(
    memory_map: *const MemoryMap,
    comptime state: memory.MemoryState,
    vm_addr: u64,
    len: u64,
) !u64 {
    const slice = try memory_map.vmap(state, vm_addr, len);
    return @intFromPtr(slice.ptr);
}

/// [agave] https://github.com/anza-xyz/agave/blob/359d7eb2b68639443d750ffcec0c7e358f138975/programs/bpf_loader/src/syscalls/mod.rs#L616
fn translateType(
    comptime T: type,
    comptime state: memory.MemoryState,
    memory_map: *const MemoryMap,
    vm_addr: u64,
    check_aligned: bool,
) !switch (state) {
    .mutable => *T,
    .constant => *const T,
} {
    const host_addr = try translate(memory_map, state, vm_addr, @sizeOf(u64));
    if (!check_aligned) {
        return @ptrFromInt(host_addr);
    } else if (host_addr % @alignOf(T) != 0) {
        return SyscallError.UnalignedPointer;
    } else {
        return @ptrFromInt(host_addr);
    }
}

/// [agave] https://github.com/anza-xyz/agave/blob/359d7eb2b68639443d750ffcec0c7e358f138975/programs/bpf_loader/src/syscalls/mod.rs#L647
fn translateSlice(
    comptime T: type,
    comptime state: memory.MemoryState,
    memory_map: *const MemoryMap,
    vm_addr: u64,
    len: u64,
    check_aligned: bool,
) !switch (state) {
    .mutable => []T,
    .constant => []const T,
} {
    if (len == 0) {
        const Static = struct { var _: [0]T = undefined; };
        return &Static._;
    }

    const total_size = std.math.mul(u64, len, @sizeOf(u64)) catch std.math.maxInt(u64);
    _ = std.math.cast(isize, total_size) catch {
        return SyscallError.InvalidLength;
    };

    const host_addr = try translate(memory_map, state, vm_addr, total_size);
    if (check_aligned and host_addr % @alignOf(T) != 0) {
        return SyscallError.UnalignedPointer;
    }
    
    return switch (state) {
        .mutable => @as([*]T, @ptrFromInt(host_addr))[0..len],
        .constant => @as([*]const T, @ptrFromInt(host_addr))[0..len],
    };
}

/// [agave] https://github.com/anza-xyz/agave/blob/359d7eb2b68639443d750ffcec0c7e358f138975/programs/bpf_loader/src/syscalls/cpi.rs#L38
fn checkAccountInfoPtr(
    ic: *InstructionContext,
    vm_addr: u64,
    expected_vm_addr: u64,
    field: []const u8,
) !void {
    if (vm_addr != expected_vm_addr) {
        try ic.tc.log("Invalid account info pointer `{}`: {x} != {x}", .{
            field,
            vm_addr,
            expected_vm_addr,
        });
        return SyscallError.InvalidPointer;
    }
}

/// Host side representation of AccountInfo or SolAccountInfo passed to the CPI syscall.
///
/// At the start of a CPI, this can be different from the data stored in the
/// corresponding BorrowedAccount, and needs to be synched.
/// 
/// [agave] https://github.com/anza-xyz/agave/blob/359d7eb2b68639443d750ffcec0c7e358f138975/programs/bpf_loader/src/syscalls/cpi.rs#L96
const CallerAccount = struct {
    lamports: *u64,
    owner: *Pubkey,
    // The original data length of the account at the start of the current
    // instruction. We use this to determine wether an account was shrunk or
    // grown before or after CPI, and to derive the vm address of the realloc
    // region.
    original_data_len: usize,
    // This points to the data section for this account, as serialized and
    // mapped inside the vm (see serialize_parameters() in
    // BpfExecutor::execute).
    //
    // This is only set when direct mapping is off (see the relevant comment in
    // CallerAccount::from_account_info).
    serialized_data: []u8,
    // Given the corresponding input AccountInfo::data, vm_data_addr points to
    // the pointer field and ref_to_len_in_vm points to the length field.
    vm_data_addr: u64,
    ref_to_len_in_vm: VmValue(u64),

    /// [agave] https://github.com/anza-xyz/agave/blob/359d7eb2b68639443d750ffcec0c7e358f138975/programs/bpf_loader/src/syscalls/cpi.rs#L119
    fn fromAccountInfo(
        ic: *InstructionContext,
        memory_map: *const MemoryMap,
        account_info: *const AccountInfo,
        account_metadata: *const SerializedAccountMetadata,
    ) !CallerAccount {
        _ = _vm_addr;

        const direct_mapping = ic.tc.feature_set.active.contains(
            feature_set.BPF_ACCOUNT_DATA_DIRECT_MAPPING,
        );

        if (direct_mapping) {
            try checkAccountInfoPtr(
                ic,
                @intFromPtr(account_info.key),
                account_metadata.vm_key_addr,
                "key",
            );
            try checkAccountInfoPtr(
                ic,
                @intFromPtr(account_info.owner),
                account_metadata.vm_owner_addr,
                "owner",
            );
        }

        // account_info points to host memory. The addresses used internally are
        // in vm space so they need to be translated.
        const lamports = blk: {
            // Double translate lamports out of RefCell
            const ptr = try translateType(
                u64,
                .constant,
                memory_map,
                @intFromPtr(account_info.lamports),
                ic.getCheckAligned(),
            );
            if (direct_mapping) {
                if (@intFromPtr(account_info.lamports) >= MM_INPUT_START) {
                    return SyscallError.InvalidPointer;
                }
                try checkAccountInfoPtr(
                    ic,
                    ptr,
                    account_metadata.vm_lamports_addr,
                    "lamports",
                );
            }
            break :blk try translateType(
                u64,
                .mutable,
                memory_map,
                ptr,
                ic.getCheckAligned(),
            );
        };

        const owner = try translateType(
            Pubkey,
            .mutable,
            memory_map,
            @intFromPtr(account_info.owner),
            ic.getCheckAligned(),
        );

        const serialized, const vm_data_addr, const ref_to_len = blk: {
            if (direct_mapping and @intFromPtr(account_info.data.ptr) >= MM_INPUT_START) {
                return SyscallError.InvalidPointer;
            }

            const data: []const u8 = (try translateType(
                []const u8,
                .constant,
                memory_map,
                @intFromPtr(account_info.data.ptr),
                ic.getCheckAligned(),
            )).*;

            if (direct_mapping) {
                try checkAccountInfoPtr(
                    ic,
                    @intFromPtr(data.ptr),
                    account_metadata.vm_data_addr,
                    "data",
                );
            }

            // [agave] https://github.com/anza-xyz/agave/blob/01e50dc39bde9a37a9f15d64069459fe7502ec3e/programs/bpf_loader/src/syscalls/cpi.rs#L195-L200
            try ic.tc.consumeCompute(std.math.divFloor(
                u64,
                data.len,
                ic.tc.compute_budget.cpi_bytes_per_unit,
            ) catch std.math.maxInt(u64));

            const ref_to_len = if (direct_mapping) r2l: {
                const vm_addr = @as(u64, @intFromPtr(account_info.data.ptr)) +| @sizeOf(u64);
                if (vm_addr >= MM_INPUT_START) {
                    return SyscallError.InvalidPointer;
                }
                // In the same vein as the other check_account_info_pointer() checks, we don't lock
                // this pointer to a specific address but we don't want it to be inside accounts, or
                // callees might be able to write to the pointed memory.
                break :r2l VmValue(u64){ .vm_address = .{
                    .vm_addr = vm_addr,
                    .memory_map = memory_map,
                    .check_aligned = ic.getCheckAligned(),
                } };
            } else r2l: { 
                const translated: *u64 = @ptrFromInt(try translate(
                    memory_map,
                    .constant,
                    @as(u64, @intFromPtr(account_info.data.ptr)) +| @sizeOf(u64),
                    8,
                ));
                break :r2l VmValue(u64){ .translated = translated };
            };

            const vm_data_addr = @intFromPtr(data.ptr);
            const serialized = if (direct_mapping) ser: {
                // when direct mapping is enabled, the permissions on the
                // realloc region can change during CPI so we must delay
                // translating until when we know whether we're going to mutate
                // the realloc region or not. Consider this case:
                //
                // [caller can't write to an account] <- we are here
                // [callee grows and assigns account to the caller]
                // [caller can now write to the account]
                //
                // If we always translated the realloc area here, we'd get a
                // memory access violation since we can't write to the account
                // _yet_, but we will be able to once the caller returns.
                const Static = struct { var _: [0]u8 = undefined; };
                break :ser &Static._;
            } else try translateSlice(
                u8,
                .mutable,
                memory_map,
                vm_data_addr,
                data.len(),
                ic.getCheckAligned(),
            );

            break :blk .{ serialized, vm_data_addr, ref_to_len };
        };

        return .{
            .lamports = lamports,
            .owner = owner,
            .original_data_len = account_metadata.original_data_len,
            .serialized_data = serialized,
            .vm_data_addr = vm_data_addr,
            .ref_to_len_in_vm = ref_to_len,
        };
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/359d7eb2b68639443d750ffcec0c7e358f138975/programs/bpf_loader/src/syscalls/cpi.rs#L264
    fn fromSolAccountInfo(
        ic: *InstructionContext,
        memory_map: *const MemoryMap,
        vm_addr: u64,
        account_info: *const SolAccountInfo,
        account_metadata: *const SerializedAccountMetadata,
    ) !CallerAccount {
        const direct_mapping = ic.tc.feature_set.active.contains(
            feature_set.BPF_ACCOUNT_DATA_DIRECT_MAPPING,
        );

        if (direct_mapping) {
            try checkAccountInfoPtr(
                ic,
                account_info.key_addr,
                account_metadata.vm_key_addr,
                "key",
            );
            try checkAccountInfoPtr(
                ic,
                account_info.owner_addr,
                account_metadata.vm_owner_addr,
                "owner",
            );
            try checkAccountInfoPtr(
                ic,
                account_info.lamports_addr,
                account_metadata.vm_lamports_addr,
                "lamports",
            );
            try checkAccountInfoPtr(
                ic,
                account_info.data_addr,
                account_metadata.vm_data_addr,
                "data",
            );
        }

        // account_info points to host memory. The addresses used internally are
        // in vm space so they need to be translated.
        const lamports = try translateType(
            u64,
            .mutable,
            memory_map,
            account_info.lamports_addr,
            ic.getCheckAligned(),
        );
        const owner = try translateType(
            Pubkey,
            .mutable,
            memory_map,
            account_info.owner_addr,
            ic.getCheckAligned(),
        );

        try ic.tc.consumeCompute(std.math.divFloor(
            u64,
            account_info.data_len,
            ic.tc.compute_budget.cpi_bytes_per_unit,
        ) catch std.math.maxInt(u64));
        
        const serialized_data = if (direct_mapping) ser: {
            // See comment in CallerAccount::from_account_info()
            const Static = struct { var _: [0]u8 = undefined; };
            break :ser &Static._;
        } else try translateSlice(
            u8,
            .mutable,
            memory_map,
            account_info.data_addr,
            account_info.data_len,
            ic.getCheckAligned(),
        );

        // we already have the host addr we want: &mut account_info.data_len.
        // The account info might be read only in the vm though, so we translate
        // to ensure we can write. This is tested by programs/sbf/rust/ro_modify
        // which puts SolAccountInfo in rodata.
        const data_len_vm_addr = vm_addr +|
            @intFromPtr(&account_info.data_len) -|
            @intFromPtr(account_info);

        const ref_to_len = if (direct_mapping)
            VmValue(u64){ .vm_address = .{ 
                .vm_addr = data_len_vm_addr,
                .memory_map = memory_map,
                .check_aligned = ic.getCheckAligned(),
            } }
        else
            VmValue(u64){ .translated = translate(
                memory_map,
                .mutable,
                data_len_vm_addr,
                @sizeOf(u64),
            ) };

        return .{
            .lamports = lamports,
            .owner = owner,
            .original_data_len = account_metadata.original_data_len,
            .serialized_data = serialized_data,
            .vm_data_addr = account_info.data_addr, 
            .ref_to_len_in_vm = ref_to_len,
        };
    }

    // [agave] https://github.com/anza-xyz/agave/blob/master/programs/bpf_loader/src/syscalls/cpi.rs#L372C8-L372C22
    // fn reallocRegion(
    //     self: *const CallerAccount,
    //     allocator: std.mem.Allocator,
    //     memory_map: *const MemoryMap,
    //     is_loader_deprecated: bool,
    // ) !?*const memory.Region {
    //     return accountReallocRegion(
    //         memory_map,
    //         self.vm_data_addr,
    //         self.original_data_len,
    //         is_loader_deprecated,
    //     );
    // }
};

/// [agave] https://github.com/anza-xyz/agave/blob/master/programs/bpf_loader/src/syscalls/cpi.rs#L2770
const MockInst = struct {
    program_id: Pubkey,
    accounts: []const AccountMeta,
    data: []const u8,

    /// [agave] https://github.com/anza-xyz/agave/blob/master/programs/bpf_loader/src/syscalls/cpi.rs#L2777
    fn intoRegion(self: MockInst, allocator: std.mem.Allocator, vm_addr: u64) !memory.Region {
        const accounts_len = @sizeOf(AccountMeta) * self.accounts.len;
        const size = @sizeOf(StableInstruction) + accounts_len + self.data.len;

        const data = try allocator.alloc(u8, size);
        errdefer allocator.free(data);

        const ins = StableInstruction{
            .program_id = self.program_id,
            .accounts = StableVec(AccountMeta){
                .addr = vm_addr + @sizeOf(StableInstruction),
                .cap = self.accounts.len,
                .len = self.accounts.len,
            },
            .data = StableVec(u8){
                .addr = vm_addr + @sizeOf(StableInstruction) + accounts_len,
                .cap = self.data.len,
                .len = self.data.len,
            },
        };

        var buf = std.io.fixedBufferStream(data);
        try buf.writer().writeAll(std.mem.asBytes(&ins));
        try buf.writer().writeAll(std.mem.sliceAsBytes(self.accounts));
        try buf.writer().writeAll(self.data);
        return memory.Region.init(.mutable, data, vm_addr);
    }
};

test "CallerAccount" {
    const testing = sig.runtime.program.testing;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    const account_key = Pubkey.initRandom(prng.random());

    var tc = try testing.createTransactionContext(allocator, prng.random(), .{
        .accounts = &.{
            .{
                .pubkey = system_program.ID,
                .owner = ids.NATIVE_LOADER_ID,
            },
        },
    });
    defer tc.deinit(allocator);

    var ic = InstructionContext{
        .depth = 0,
        .tc = &tc,
        .info = try testing.createInstructionInfo(
            allocator,
            &tc,
            system_program.ID,
            system_program.Instruction{ .assign = .{ .owner = account_key } }, // can be whatever.
            &.{},
        ),
    };
    defer ic.deinit(allocator);

    const mock = MockInst{
        .accounts = &.{
            .{

            },
        },
        .data = "hello world",
        .program_id = system_program.ID,
    };

    const region = try mock.intoRegion(allocator, MM_INPUT_START);
    const region_mem = region.getSlice(.mutable) catch unreachable;
    defer allocator.free(region_mem);

    const memory_map = MemoryMap.init(&.{region}, .v3);

    const rg_inst_offset = 0;
    const rg_inst: StableInstruction = @bitCast(region_mem[0..@sizeOf(StableInstruction)].*);

    const rg_acc_offset = @sizeOf(StableInstruction);
    const rg_acc = std.mem.sliceAsBytes(
        region_mem[rg_acc_offset..][0..rg_inst.accounts.len * @sizeOf(AccountMeta)],
    );

    const rg_data_offset = rg_acc_offset + rg_acc.len * @sizeOf(AccountMeta);
    const rg_data = region_mem[rg_data_offset..][0..rg_inst.data.len];

    const account_metadata = SerializedAccountMetadata{
        .original_data_len = region_mem.len,
        .vm_data_addr = region.vm_addr_start + rg_data_offset,
        .vm_key_addr = rg_inst_offset + @offsetOf(StableInstruction, "program_id"),
        .vm_lamports_addr = rg_acc_offset + @offsetOf(AccountMeta, "lamports"),
        .vm_owner_addr = rg_acc_offset + @offsetOf(AccountMeta, "owner"),
    };

    const account_info = AccountInfo{
        .key = account_key, 
        .is_signer = false,
        .is_writable = true,
        .lamports = &lamports,
        .data = data,
        .owner = &owner,
        .executable = true,
        .rent_epoch = 0,
    };

    const caller_account = try CallerAccount.fromAccountInfo(
        &ic,
        &memory_map,
        &account_info,
        &account_metadata,
    );
}