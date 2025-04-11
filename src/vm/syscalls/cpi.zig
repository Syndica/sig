const std = @import("std");
const builtin = @import("builtin");
const sig = @import("../../sig.zig");
const memory = @import("../memory.zig");

const ids = sig.runtime.ids;
const bpf_loader_program = sig.runtime.program.bpf_loader_program;
const system_program = sig.runtime.program.system_program;
const features = sig.runtime.features;
const pubkey_utils = sig.runtime.pubkey_utils;

const Pubkey = sig.core.Pubkey;
const Epoch = sig.core.Epoch;
const Instruction = sig.core.Instruction;
const InstructionAccount = sig.core.instruction.InstructionAccount;
const InstructionError = sig.core.instruction.InstructionError;

const BorrowedAccount = sig.runtime.BorrowedAccount;
const InstructionInfo = sig.runtime.InstructionInfo;
const InstructionContext = sig.runtime.InstructionContext;
const EpochContext = sig.runtime.EpochContext;
const SlotContext = sig.runtime.SlotContext;
const TransactionContext = sig.runtime.TransactionContext;
const SerializedAccountMetadata = sig.runtime.program.bpf.serialize.SerializedAccountMeta;

const MemoryMap = memory.MemoryMap;
const MM_INPUT_START = memory.INPUT_START;

pub const SyscallError = error{
    BadSeeds,
    TooManySigners,
    UnalignedPointer,
    InvalidPointer,
    TooManyAccounts,
    InstructionTooLarge,
    MaxInstructionDataLenExceeded,
    MaxInstructionAccountsExceeded,
    MaxInstructionAccountInfosExceeded,
} || sig.vm.syscalls.Error;

/// [agave] StableVec: https://github.com/anza-xyz/solana-sdk/blob/master/stable-layout/src/stable_vec.rs#L30
/// [agave] https://github.com/anza-xyz/solana-sdk/blob/0666fa5999750153070e5c43d64813467bfdc38e/stable-layout/src/stable_instruction.rs#L33
const StableInstructionRust = extern struct {
    // StableVec(AccountMetaRust)
    accounts_addr: u64,
    accounts_cap: u64,
    accounts_len: u64,
    // StableVec(u8)
    data_addr: u64,
    data_cap: u64,
    data_len: u64,
    // Stores Pubkey directly instead of vm address
    program_id: Pubkey,
};

/// [agave] https://github.com/anza-xyz/agave/blob/04fd7a006d8b400096e14a69ac16e10dc3f6018a/programs/bpf_loader/src/syscalls/cpi.rs#L577
const StableInstructionC = extern struct {
    program_id_addr: u64,
    accounts_addr: u64,
    accounts_len: u64,
    data_addr: u64,
    data_len: u64,
};

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/f7a6475ae883e0216eaeab42f525833f667965a0/instruction/src/account_meta.rs#L25
const AccountMetaRust = extern struct {
    /// An account's public key.
    pubkey: Pubkey,
    /// True if an `Instruction` requires a `Transaction` signature matching `pubkey`.
    is_signer: bool,
    /// True if the account data or metadata may be mutated during program execution.
    is_writable: bool,
};

/// [agave] https://github.com/anza-xyz/agave/blob/04fd7a006d8b400096e14a69ac16e10dc3f6018a/programs/bpf_loader/src/syscalls/cpi.rs#L588
const AccountMetaC = extern struct {
    pubkey_addr: u64,
    is_writable: bool,
    is_signer: bool,
};

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/ddf107050306fa07c714f7c37abcfab1d1edae26/account-info/src/lib.rs#L22
const AccountInfoRust = extern struct {
    key_addr: u64,
    lamports_addr: Rc(RefCell(u64)),
    data: Rc(RefCell([]u8)),
    owner_addr: u64,
    rent_epoch: Epoch,
    is_signer: bool,
    is_writable: bool,
    executable: bool,
};

/// [agave] https://github.com/anza-xyz/agave/blob/04fd7a006d8b400096e14a69ac16e10dc3f6018a/359d7eb2b68639443d750ffcec0c7e358f138975/bpf_loader/src/syscalls/cpi.rs#L597
const AccountInfoC = extern struct {
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

/// [rust] https://doc.rust-lang.org/src/alloc/rc.rs.html#281-289
/// [agave] https://github.com/anza-xyz/agave/blob/04fd7a006d8b400096e14a69ac16e10dc3f6018a/programs/bpf_loader/src/syscalls/cpi.rs#L2971
fn RcBox(comptime T: type) type {
    return extern struct {
        strong: usize = 0,
        weak: usize = 0,
        value: T,

        const VALUE_OFFSET = @sizeOf(usize) * 2;
    };
}

/// [rust] https://doc.rust-lang.org/src/alloc/rc.rs.html#314-317
fn Rc(comptime T: type) type {
    return extern struct {
        ptr: *RcBox(T),

        fn fromRaw(value_ptr: *T) @This() {
            return .{ .ptr = @fieldParentPtr("value", value_ptr) };
        }

        fn deref(self: @This()) *T {
            return &self.ptr.value;
        }
    };
}

/// [rust] https://doc.rust-lang.org/src/core/cell.rs.html#730
fn RefCell(comptime T: type) type {
    return extern struct {
        borrow: isize = 0,
        value: [@sizeOf(T)]u8 align(@alignOf(T)), // support defined-layout when T isnt.

        pub fn init(value: T) @This() {
            return .{ .value = std.mem.asBytes(&value)[0..@sizeOf(T)].* };
        }

        pub fn asPtr(self: *@This()) *T {
            return @ptrCast(&self.value);
        }
    };
}

/// [agave] https://github.com/anza-xyz/agave/blob/359d7eb2b68639443d750ffcec0c7e358f138975/programs/bpf_loader/src/syscalls/cpi.rs#L57
fn VmValue(comptime T: type) type {
    return union(enum) {
        const Self = @This();

        vm_address: struct {
            vm_addr: u64,
            memory_map: *const MemoryMap,
            check_aligned: bool,
        },
        translated: *T,

        pub fn get(self: Self, comptime state: memory.MemoryState) !(switch (state) {
            .constant => *const T,
            .mutable => *T,
        }) {
            switch (self) {
                .translated => |ptr| return ptr,
                .vm_address => |vma| {
                    return translateType(T, state, vma.memory_map, vma.vm_addr, vma.check_aligned);
                },
            }
        }
    };
}

/// [agave] https://github.com/anza-xyz/agave/blob/04fd7a006d8b400096e14a69ac16e10dc3f6018a/programs/bpf_loader/src/syscalls/mod.rs#L235-L247
/// [agave] https://github.com/anza-xyz/agave/blob/04fd7a006d8b400096e14a69ac16e10dc3f6018a/programs/bpf_loader/src/syscalls/cpi.rs#L609-L623
const VmSlice = extern struct {
    ptr: u64,
    len: u64,
};

/// [agave] https://github.com/anza-xyz/agave/blob/359d7eb2b68639443d750ffcec0c7e358f138975/programs/bpf_loader/src/syscalls/mod.rs#L604
fn translate(
    comptime state: memory.MemoryState,
    memory_map: *const MemoryMap,
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
) !(switch (state) {
    .mutable => *T,
    .constant => *const T,
}) {
    const host_addr = try translate(state, memory_map, vm_addr, @sizeOf(T));
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
) !(switch (state) {
    .mutable => []T,
    .constant => []const T,
}) {
    if (len == 0) {
        return &.{}; // &mut []
    }

    const total_size = len *| @sizeOf(T);
    _ = std.math.cast(isize, total_size) orelse return SyscallError.InvalidLength;

    const host_addr = try translate(state, memory_map, vm_addr, total_size);
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
    ic: *const InstructionContext,
    vm_addr: u64,
    expected_vm_addr: u64,
    field: []const u8,
) !void {
    if (vm_addr != expected_vm_addr) {
        try ic.tc.log("Invalid account info pointer `{s}`: {x} != {x}", .{
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
    fn fromAccountInfoRust(
        ic: *const InstructionContext,
        memory_map: *const MemoryMap,
        _vm_addr: u64,
        account_info: *const AccountInfoRust,
        account_metadata: *const SerializedAccountMetadata,
    ) !CallerAccount {
        _ = _vm_addr; // unused

        const direct_mapping = ic.ec.feature_set.active.contains(
            features.BPF_ACCOUNT_DATA_DIRECT_MAPPING,
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
        }

        // account_info points to host memory. The addresses used internally are
        // in vm space so they need to be translated.
        const lamports: *u64 = blk: {
            // NOTE: Models the RefCell as_ptr() access here
            // [agave] https://github.com/anza-xyz/agave/blob/359d7eb2b68639443d750ffcec0c7e358f138975/programs/bpf_loader/src/syscalls/cpi.rs#L151
            const lamports_addr: u64 = @intFromPtr(account_info.lamports_addr.deref().asPtr());

            // Double translate lamports out of RefCell
            const ptr: *const u64 = try translateType(
                u64,
                .constant,
                memory_map,
                lamports_addr,
                ic.getCheckAligned(),
            );
            if (direct_mapping) {
                if (lamports_addr >= MM_INPUT_START) {
                    return SyscallError.InvalidPointer;
                }
                try checkAccountInfoPtr(
                    ic,
                    ptr.*,
                    account_metadata.vm_lamports_addr,
                    "lamports",
                );
            }
            break :blk try translateType(
                u64,
                .mutable,
                memory_map,
                ptr.*,
                ic.getCheckAligned(),
            );
        };

        const owner: *Pubkey = try translateType(
            Pubkey,
            .mutable,
            memory_map,
            account_info.owner_addr,
            ic.getCheckAligned(),
        );

        const serialized, const vm_data_addr, const ref_to_len = blk: {
            // NOTE: trying to model the ptr stuff going on here:
            // [agave] https://github.com/anza-xyz/agave/blob/359d7eb2b68639443d750ffcec0c7e358f138975/programs/bpf_loader/src/syscalls/cpi.rs#L183
            const data_ptr: u64 = @intFromPtr(account_info.data.deref().asPtr());

            if (direct_mapping and data_ptr >= MM_INPUT_START) {
                return SyscallError.InvalidPointer;
            }

            // Double translate data out of RefCell
            const data: []const u8 = (try translateType(
                []const u8,
                .constant,
                memory_map,
                data_ptr,
                ic.getCheckAligned(),
            )).*;

            if (direct_mapping) {
                try checkAccountInfoPtr(
                    ic,
                    data_ptr,
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
                const vm_addr = data_ptr +| @sizeOf(u64);
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
                    .constant,
                    memory_map,
                    data_ptr +| @sizeOf(u64),
                    8,
                ));
                break :r2l VmValue(u64){ .translated = translated };
            };

            const vm_data_addr = @intFromPtr(data.ptr);
            const serialized: []u8 = if (direct_mapping) ser: {
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
                break :ser &.{}; // &mut []
            } else try translateSlice(
                u8,
                .mutable,
                memory_map,
                vm_data_addr,
                data.len,
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
    fn fromAccountInfoC(
        ic: *const InstructionContext,
        memory_map: *const MemoryMap,
        vm_addr: u64,
        account_info: *const AccountInfoC,
        account_metadata: *const SerializedAccountMetadata,
    ) !CallerAccount {
        const direct_mapping = ic.ec.feature_set.active.contains(
            features.BPF_ACCOUNT_DATA_DIRECT_MAPPING,
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

        const serialized_data: []u8 = if (direct_mapping) ser: {
            // See comment in CallerAccount.fromAccountInfo()
            break :ser &.{}; // &mut []
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
            VmValue(u64){ .translated = @ptrFromInt(try translate(
                .mutable,
                memory_map,
                data_len_vm_addr,
                @sizeOf(u64),
            )) };

        return .{
            .lamports = lamports,
            .owner = owner,
            .original_data_len = account_metadata.original_data_len,
            .serialized_data = serialized_data,
            .vm_data_addr = account_info.data_addr,
            .ref_to_len_in_vm = ref_to_len,
        };
    }

    // TODO: used in `cpi_common`
    // [agave] https://github.com/anza-xyz/agave/blob/04fd7a006d8b400096e14a69ac16e10dc3f6018a/programs/bpf_loader/src/syscalls/cpi.rs#L372C8-L372C22
    // fn reallocRegion(
    //     self: *const CallerAccount,
    //     allocator: std.mem.Allocator,
    //     memory_map: *const MemoryMap,
    //     is_loader_deprecated: bool,
    // ) !?*const memory.Region {
    //     return accountReallocRegion(
    //         allocator,
    //         memory_map,
    //         self.vm_data_addr,
    //         self.original_data_len,
    //         is_loader_deprecated,
    //     );
    // }
};

/// Update the given account before executing CPI.
///
/// caller_account and callee_account describe the same account. At CPI entry
/// caller_account might include changes the caller has made to the account
/// before executing CPI.
///
/// This method updates callee_account so the CPI callee can see the caller's
/// changes.
///
/// When true is returned, the caller account must be updated after CPI. This
/// is only set for direct mapping when the pointer may have changed.
///
/// [agave] https://github.com/anza-xyz/agave/blob/04fd7a006d8b400096e14a69ac16e10dc3f6018a/programs/bpf_loader/src/syscalls/cpi.rs#L1201
fn updateCalleeAccount(
    allocator: std.mem.Allocator,
    ic: *const InstructionContext,
    memory_map: *const MemoryMap,
    is_loader_deprecated: bool,
    direct_mapping: bool,
    callee_account: *BorrowedAccount,
    caller_account: *const CallerAccount,
) !bool {
    var must_update_caller = false;

    if (callee_account.account.lamports != caller_account.lamports.*) {
        try callee_account.setLamports(caller_account.lamports.*);
    }

    if (direct_mapping) {
        const prev_len = callee_account.constAccountData().len;
        const post_len = (try caller_account.ref_to_len_in_vm.get(.constant)).*;

        const maybe_err: ?InstructionError = callee_account.checkCanSetDataLength(
            ic.tc.accounts_resize_delta,
            post_len,
        ) orelse callee_account.checkDataIsMutable();

        if (maybe_err) |err| {
            if (prev_len != post_len) return err;
        }

        // bpf_loader_deprecated programs don't have a realloc region
        const realloc_bytes_used = post_len -| caller_account.original_data_len;
        if (is_loader_deprecated and realloc_bytes_used > 0) {
            return InstructionError.InvalidRealloc;
        }

        if (prev_len != post_len) {
            try callee_account.setDataLength(allocator, &ic.tc.accounts_resize_delta, post_len);
            must_update_caller = true;
        }

        if (realloc_bytes_used > 0) {
            const serialized_data = try translateSlice(
                u8,
                .constant,
                memory_map,
                caller_account.vm_data_addr +| caller_account.original_data_len,
                realloc_bytes_used,
                ic.getCheckAligned(),
            );
            @memcpy(
                try callee_account.mutableAccountData(),
                serialized_data,
            );
        }
    } else {
        // The redundant check helps to avoid the expensive data comparison if we can
        const serialized_data: []const u8 = caller_account.serialized_data;
        const maybe_err: ?InstructionError = callee_account.checkCanSetDataLength(
            ic.tc.accounts_resize_delta,
            serialized_data.len,
        ) orelse callee_account.checkDataIsMutable();

        if (maybe_err) |err| {
            if (!std.mem.eql(u8, callee_account.constAccountData(), serialized_data)) return err;
        } else {
            try callee_account.setDataFromSlice(
                allocator,
                &ic.tc.accounts_resize_delta,
                serialized_data,
            );
        }
    }

    // Change the owner at the end so that we are allowed to change the lamports and data before
    if (!callee_account.account.owner.equals(caller_account.owner)) {
        try callee_account.setOwner(caller_account.owner.*);
    }

    return must_update_caller;
}

const TranslatedAccount = struct { index_in_caller: u64, caller_account: ?CallerAccount };
const TranslatedAccounts = std.BoundedArray(TranslatedAccount, InstructionInfo.MAX_ACCOUNT_METAS);

/// Implements SyscallInvokeSigned::translate_accounts for both AccountInfo & SolAccountInfo.
/// [agave] https://github.com/anza-xyz/agave/blob/359d7eb2b68639443d750ffcec0c7e358f138975/programs/bpf_loader/src/syscalls/cpi.rs#L498
/// [agave] https://github.com/anza-xyz/agave/blob/359d7eb2b68639443d750ffcec0c7e358f138975/programs/bpf_loader/src/syscalls/cpi.rs#L725
fn translateAccounts(
    allocator: std.mem.Allocator,
    ic: *const InstructionContext,
    memory_map: *const MemoryMap,
    is_loader_deprecated: bool,
    comptime AccountInfoType: type,
    account_infos_addr: u64,
    account_infos_len: u64,
    account_metas: []const InstructionInfo.AccountMeta,
) !TranslatedAccounts {
    // translate_account_infos():
    // [agave] https://github.com/anza-xyz/agave/blob/359d7eb2b68639443d750ffcec0c7e358f138975/programs/bpf_loader/src/syscalls/cpi.rs#L805

    const direct_mapping = ic.ec.feature_set.active.contains(
        features.BPF_ACCOUNT_DATA_DIRECT_MAPPING,
    );

    // In the same vein as the other checkAccountInfoPtr() checks, we don't lock
    // this pointer to a specific address but we don't want it to be inside accounts, or
    // callees might be able to write to the pointed memory.
    if (direct_mapping and
        (account_infos_addr +| (account_infos_len *| @sizeOf(u64))) >= MM_INPUT_START)
    {
        return SyscallError.InvalidPointer;
    }

    const account_infos = try translateSlice(
        AccountInfoType,
        .constant,
        memory_map,
        account_infos_addr,
        account_infos_len,
        ic.getCheckAligned(),
    );

    // check_account_infos():
    // [agave] https://github.com/anza-xyz/agave/blob/master/https://github.com/anza-xyz/agave/blob/04fd7a006d8b400096e14a69ac16e10dc3f6018a/programs/bpf_loader/src/syscalls/cpi.rs#L1018/bpf_loader/src/syscalls/cpi.rs#L1018
    if (ic.ec.feature_set.active.contains(features.LOOSEN_CPI_SIZE_RESTRICTION)) {
        const max_cpi_account_infos: u64 = if (ic.ec.feature_set.active.contains(
            features.INCREASE_TX_ACCOUNT_LOCK_LIMIT,
        )) 128 else 64;

        if (account_infos.len > max_cpi_account_infos) {
            // TODO: add {account_infos.len} and {max_cpi_account_infos} as context to error.
            // [agave] https://github.com/anza-xyz/agave/blob/161fc1965bdb4190aa2d7e36c7c745b4661b10ed/programs/bpf_loader/src/syscalls/mod.rs#L124-L128
            return SyscallError.MaxInstructionAccountInfosExceeded;
        }
    } else {
        const adjusted_len = @as(u64, account_infos.len) *| @sizeOf(Pubkey);
        if (adjusted_len > ic.tc.compute_budget.max_cpi_instruction_size) {
            // Cap the number of account_infos a caller can pass to approximate
            // maximum that accounts that could be passed in an instruction
            return SyscallError.TooManyAccounts;
        }
    }

    // translate_and_update_accounts():
    // [agave] https://github.com/anza-xyz/agave/blob/04fd7a006d8b400096e14a69ac16e10dc3f6018a/programs/bpf_loader/src/syscalls/cpi.rs#L853

    var accounts: TranslatedAccounts = .{};
    try accounts.append(.{
        .index_in_caller = ic.ixn_info.program_meta.index_in_transaction,
        .caller_account = null,
    });

    for (account_metas, 0..) |meta, i| {
        if (meta.index_in_callee != i) continue; // Skip duplicate account

        var callee_account = try ic.borrowInstructionAccount(meta.index_in_caller);
        defer callee_account.release();

        if (callee_account.account.executable) {
            // Use the known account
            try ic.tc.consumeCompute(std.math.divFloor(
                u64,
                callee_account.constAccountData().len,
                ic.tc.compute_budget.cpi_bytes_per_unit,
            ) catch std.math.maxInt(u64));

            try accounts.append(.{
                .index_in_caller = meta.index_in_caller,
                .caller_account = null,
            });
            continue;
        }

        const account_key = ic.getAccountKeyByIndexUnchecked(meta.index_in_caller);
        const caller_account_index = for (account_infos, 0..) |info, idx| {
            const info_key = try translateType(
                Pubkey,
                .constant,
                memory_map,
                info.key_addr,
                ic.getCheckAligned(),
            );
            if (info_key.equals(&account_key)) break idx;
        } else {
            try ic.tc.log("Instruction references an unknown account {}", .{account_key});
            return InstructionError.MissingAccount;
        };

        const serialized_metadata = if (meta.index_in_caller < ic.ixn_info.account_metas.len) blk: {
            break :blk &ic.vm_accounts.slice()[meta.index_in_caller];
        } else {
            try ic.tc.log("Internal error: index mismatch for account {}", .{account_key});
            return InstructionError.MissingAccount;
        };

        // build the CallerAccount corresponding to this account.
        if (caller_account_index >= account_infos.len) {
            return SyscallError.InvalidLength;
        }

        const caller_account = try @call(
            .auto,
            switch (AccountInfoType) {
                AccountInfoC => CallerAccount.fromAccountInfoC,
                AccountInfoRust => CallerAccount.fromAccountInfoRust,
                else => @compileError("invalid AccountInfo type"),
            },
            .{
                ic,
                memory_map,
                account_infos_addr +| (caller_account_index *| @sizeOf(AccountInfoType)),
                &account_infos[caller_account_index],
                serialized_metadata,
            },
        );

        // before initiating CPI, the caller may have modified the
        // account (caller_account). We need to update the corresponding
        // BorrowedAccount (callee_account) so the callee can see the
        // changes.
        const update_caller = try updateCalleeAccount(
            allocator,
            ic,
            memory_map,
            is_loader_deprecated,
            direct_mapping,
            &callee_account,
            &caller_account,
        );

        try accounts.append(.{
            .index_in_caller = meta.index_in_caller,
            .caller_account = if (meta.is_writable or update_caller) caller_account else null,
        });
    }

    return accounts;
}

/// [agave] https://github.com/anza-xyz/agave/blob/04fd7a006d8b400096e14a69ac16e10dc3f6018a/programs/bpf_loader/src/syscalls/cpi.rs#L438
/// [agave] https://github.com/anza-xyz/agave/blob/04fd7a006d8b400096e14a69ac16e10dc3f6018a/programs/bpf_loader/src/syscalls/cpi.rs#L650
fn translateInstruction(
    allocator: std.mem.Allocator,
    ic: *const InstructionContext,
    memory_map: *const MemoryMap,
    comptime AccountInfoType: type,
    vm_addr: u64,
) !Instruction {
    const InstructionType, const AccountMetaType = switch (AccountInfoType) {
        AccountInfoRust => .{ StableInstructionRust, AccountMetaRust },
        AccountInfoC => .{ StableInstructionC, AccountMetaC },
        else => @compileError("invalid AccountInfo type"),
    };

    const ix = try translateType(
        InstructionType,
        .constant,
        memory_map,
        vm_addr,
        ic.getCheckAligned(),
    );
    const account_metas = try translateSlice(
        AccountMetaType,
        .constant,
        memory_map,
        ix.accounts_addr,
        ix.accounts_len,
        ic.getCheckAligned(),
    );
    const data = try translateSlice(
        u8,
        .constant,
        memory_map,
        ix.data_addr,
        ix.data_len,
        ic.getCheckAligned(),
    );
    const program_id = switch (AccountInfoType) {
        AccountInfoRust => ix.program_id,
        AccountInfoC => (try translateType(
            Pubkey,
            .constant,
            memory_map,
            ix.program_id_addr,
            ic.getCheckAligned(),
        )).*,
        else => unreachable,
    };

    const loosen_cpi_size_restriction = ic.tc.feature_set.active.contains(
        features.LOOSEN_CPI_SIZE_RESTRICTION,
    );

    // check_instruction_size():
    // [agave] https://github.com/anza-xyz/agave/blob/04fd7a006d8b400096e14a69ac16e10dc3f6018a/programs/bpf_loader/src/syscalls/cpi.rs#L980
    if (loosen_cpi_size_restriction) {
        // [agave] https://github.com/anza-xyz/agave/blob/04fd7a006d8b400096e14a69ac16e10dc3f6018a/programs/bpf_loader/src/syscalls/cpi.rs#L19
        const MAX_CPI_INSTRUCTION_DATA_LEN = 10 * 1024;
        if (data.len > MAX_CPI_INSTRUCTION_DATA_LEN) {
            // TODO: add error context { data_len, max_data_len }
            return SyscallError.MaxInstructionDataLenExceeded;
        }

        // [agave] https://github.com/anza-xyz/agave/blob/04fd7a006d8b400096e14a69ac16e10dc3f6018a/programs/bpf_loader/src/syscalls/cpi.rs#L25
        const MAX_CPI_INSTRUCTION_ACCOUNTS = std.math.maxInt(u8);
        if (account_metas.len > MAX_CPI_INSTRUCTION_ACCOUNTS) {
            // TODO: add error context { num_accounts, max_accounts }
            return SyscallError.MaxInstructionAccountsExceeded;
        }
    } else {
        const max_size = ic.tc.compute_budget.max_cpi_instruction_size;
        const size = (@as(u64, account_metas.len) *| @sizeOf(AccountMetaType)) +| data.len;
        if (size > max_size) {
            // TODO: add error context { size, max_size }
            return SyscallError.InstructionTooLarge;
        }
    }

    if (loosen_cpi_size_restriction) {
        try ic.tc.consumeCompute(std.math.divFloor(
            u64,
            data.len,
            ic.tc.compute_budget.cpi_bytes_per_unit,
        ) catch std.math.maxInt(u64));
    }

    var accounts = try allocator.alloc(InstructionAccount, account_metas.len);
    errdefer allocator.free(accounts);

    for (account_metas, 0..) |account_meta, i| {
        // NOTE: checks for bools to be 0 or 1, but why is this volatile?
        // [agave] https://github.com/anza-xyz/agave/blob/04fd7a006d8b400096e14a69ac16e10dc3f6018a/programs/bpf_loader/src/syscalls/cpi.rs#L482
        if (@as(*const volatile u8, @ptrCast(&account_meta.is_signer)).* > 1 or
            @as(*const volatile u8, @ptrCast(&account_meta.is_writable)).* > 1)
        {
            return InstructionError.InvalidArgument;
        }

        accounts[i] = InstructionAccount{
            .is_signer = account_meta.is_signer,
            .is_writable = account_meta.is_writable,
            .pubkey = switch (AccountInfoType) {
                AccountInfoRust => account_meta.pubkey,
                AccountInfoC => (try translateType(
                    Pubkey,
                    .constant,
                    memory_map,
                    account_meta.pubkey_addr,
                    ic.getCheckAligned(),
                )).*,
                else => unreachable,
            },
        };
    }

    return Instruction{
        .accounts = accounts,
        .data = data,
        .program_id = program_id,
    };
}

// [agave] https://github.com/anza-xyz/agave/blob/04fd7a006d8b400096e14a69ac16e10dc3f6018a/programs/bpf_loader/src/syscalls/mod.rs#L81
const MAX_SIGNERS = 16;

fn translateSigners(
    ic: *const InstructionContext,
    memory_map: *const MemoryMap,
    signers_seeds_addr: u64,
    signers_seeds_len: u64,
    program_id: Pubkey,
) !std.BoundedArray(Pubkey, MAX_SIGNERS) {
    if (signers_seeds_len == 0) return .{};

    const signers_seeds: []const VmSlice = try translateSlice(
        VmSlice,
        .constant,
        memory_map,
        signers_seeds_addr,
        signers_seeds_len,
        ic.getCheckAligned(),
    );

    if (signers_seeds.len > MAX_SIGNERS) {
        return SyscallError.TooManySigners;
    }

    var signers: std.BoundedArray(Pubkey, MAX_SIGNERS) = .{};
    for (signers_seeds) |signer_vm_slice| {
        const untranslated_seeds = try translateSlice(
            VmSlice,
            .constant,
            memory_map,
            signer_vm_slice.ptr,
            signer_vm_slice.len,
            ic.getCheckAligned(),
        );

        if (untranslated_seeds.len > MAX_SIGNERS) {
            return SyscallError.TooManySigners;
        }

        var seeds: std.BoundedArray([]const u8, MAX_SIGNERS) = .{};
        for (untranslated_seeds) |seeds_vm_slice| {
            seeds.appendAssumeCapacity(try translateSlice(
                u8,
                .constant,
                memory_map,
                seeds_vm_slice.ptr,
                seeds_vm_slice.len,
                ic.getCheckAligned(),
            ));
        }

        signers.appendAssumeCapacity(pubkey_utils.createProgramAddress(
            seeds.slice(),
            &.{}, // NOTE: no bump seeds AFAIK
            program_id,
        ) catch return SyscallError.BadSeeds);
    }

    return signers;
}

const TestContext = struct {
    ec: *EpochContext,
    sc: *SlotContext,
    tc: *TransactionContext,
    ic: InstructionContext,

    fn init(allocator: std.mem.Allocator, prng: std.Random, account_data: []const u8) !TestContext {
        comptime std.debug.assert(builtin.is_test);

        const tc = try allocator.create(TransactionContext);
        errdefer allocator.destroy(tc);

        const account_key = Pubkey.initRandom(prng);
        const testing = sig.runtime.testing;

        const ec, const sc, tc.* = try testing.createExecutionContexts(allocator, prng, .{
            .accounts = &.{
                .{
                    .pubkey = account_key,
                    .data = account_data,
                    .owner = bpf_loader_program.v3.ID,
                    .lamports = prng.uintAtMost(u64, 1000),
                },
                .{
                    .pubkey = system_program.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                },
            },
        });
        errdefer {
            ec.deinit();
            allocator.destroy(ec);
            allocator.destroy(sc);
            tc.deinit();
        }

        const ic = InstructionContext{
            .depth = 0,
            .ec = ec,
            .sc = sc,
            .tc = tc,
            .ixn_info = try testing.createInstructionInfo(
                tc,
                system_program.ID,
                system_program.Instruction{ .assign = .{ .owner = account_key } }, // whatever.
                &.{
                    .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
                    .{ .is_signer = false, .is_writable = false, .index_in_transaction = 1 },
                },
            ),
        };
        errdefer ic.deinit(allocator);

        return .{
            .ec = ec,
            .sc = sc,
            .tc = tc,
            .ic = ic,
        };
    }

    fn deinit(self: *TestContext, allocator: std.mem.Allocator) void {
        self.ec.deinit();
        allocator.destroy(self.ec);
        allocator.destroy(self.sc);
        self.tc.deinit();
        allocator.destroy(self.tc);
        self.ic.deinit(allocator);
    }

    fn getAccount(self: *const TestContext) TestAccount {
        const index = 0;
        const account_meta = self.ic.ixn_info.account_metas.get(index);
        const account_shared = self.ic.tc.accounts[index].account;

        return .{
            .index = index,
            .key = account_meta.pubkey,
            .owner = account_shared.owner,
            .lamports = account_shared.lamports,
            .data = account_shared.data,
            .rent_epoch = account_shared.rent_epoch,
            .is_signer = account_meta.is_signer,
            .is_writable = account_meta.is_writable,
            .executable = account_shared.executable,
        };
    }
};

const TestAccount = struct {
    index: u16,
    key: Pubkey,
    owner: Pubkey,
    lamports: u64,
    data: []u8,
    rent_epoch: Epoch,
    is_signer: bool,
    is_writable: bool,
    executable: bool,

    // [agave] https://github.com/anza-xyz/agave/blob/359d7eb2b68639443d750ffcec0c7e358f138975/programs/bpf_loader/src/syscalls/cpi.rs#L2895
    fn intoAccountInfoRust(
        self: *const TestAccount,
        allocator: std.mem.Allocator,
        vm_addr: u64,
    ) !struct { []u8, SerializedAccountMetadata } {
        const size = @sizeOf(AccountInfoRust) +
            @sizeOf(Pubkey) * 2 +
            @sizeOf(RcBox(RefCell(*u64))) +
            @sizeOf(u64) +
            @sizeOf(RcBox(RefCell([]u8))) +
            self.data.len;

        const buffer = try allocator.alloc(u8, size);
        errdefer allocator.free(buffer);

        const key_addr = vm_addr + @sizeOf(AccountInfoRust);
        const lamports_cell_addr = key_addr + @sizeOf(Pubkey);
        const lamports_addr = lamports_cell_addr + @sizeOf(RcBox(RefCell(*u64)));
        const owner_addr = lamports_addr + @sizeOf(u64);
        const data_cell_addr = owner_addr + @sizeOf(Pubkey);
        const data_addr = data_cell_addr + @sizeOf(RcBox(RefCell([]u8)));
        const data_len = self.data.len;

        buffer[0..@sizeOf(AccountInfoRust)].* = @bitCast(AccountInfoRust{
            .key_addr = key_addr,
            .is_signer = self.is_signer,
            .is_writable = self.is_writable,
            .lamports_addr = Rc(RefCell(u64)).fromRaw(
                @ptrFromInt(lamports_cell_addr + RcBox(*u64).VALUE_OFFSET),
            ),
            .data = Rc(RefCell([]u8)).fromRaw(
                @ptrFromInt(data_cell_addr + RcBox([]u8).VALUE_OFFSET),
            ),
            .owner_addr = owner_addr,
            .executable = self.executable,
            .rent_epoch = self.rent_epoch,
        });

        buffer[key_addr - vm_addr ..][0..@sizeOf(Pubkey)].* = @bitCast(self.key);
        buffer[lamports_cell_addr - vm_addr ..][0..@sizeOf(RcBox(RefCell(*u64)))].* = @bitCast(
            RcBox(RefCell(u64)){ .value = RefCell(u64).init(lamports_addr) },
        );
        buffer[lamports_addr - vm_addr ..][0..@sizeOf(u64)].* = @bitCast(self.lamports);
        buffer[owner_addr - vm_addr ..][0..@sizeOf(Pubkey)].* = @bitCast(self.owner);
        buffer[data_cell_addr - vm_addr ..][0..@sizeOf(RcBox(RefCell([]u8)))].* = @bitCast(
            RcBox(RefCell([]u8)){
                .value = RefCell([]u8).init(@as([*]u8, @ptrFromInt(data_addr))[0..data_len]),
            },
        );
        @memcpy(buffer[data_addr - vm_addr ..][0..data_len], self.data);

        return .{ buffer, SerializedAccountMetadata{
            .original_data_len = data_len,
            .vm_data_addr = data_addr,
            .vm_key_addr = key_addr,
            .vm_lamports_addr = lamports_addr,
            .vm_owner_addr = owner_addr,
        } };
    }
};

test "vm.syscalls.cpi: CallerAccount.fromAccountInfoRust" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    var ctx = try TestContext.init(allocator, prng.random(), "foobar");
    defer ctx.deinit(allocator);

    const account = ctx.getAccount();
    const vm_addr = MM_INPUT_START;

    const buffer, const serialized_metadata = try account.intoAccountInfoRust(allocator, vm_addr);
    defer allocator.free(buffer);

    const memory_map = try MemoryMap.init(
        allocator,
        &.{
            memory.Region.init(.constant, &.{}, memory.RODATA_START), // nothing in .rodata,
            memory.Region.init(.mutable, &.{}, memory.STACK_START), // nothing in the stack,
            memory.Region.init(.mutable, &.{}, memory.HEAP_START), // nothing in the heap,
            memory.Region.init(.mutable, buffer, vm_addr), // INPUT_START
        },
        .v3,
        .{ .aligned_memory_mapping = false },
    );
    defer memory_map.deinit(allocator);

    const account_info = try translateType(
        AccountInfoRust,
        .constant,
        &memory_map,
        vm_addr,
        false,
    );

    const caller_account = try CallerAccount.fromAccountInfoRust(
        &ctx.ic,
        &memory_map,
        vm_addr,
        account_info,
        &serialized_metadata,
    );

    try std.testing.expectEqual(caller_account.lamports.*, account.lamports);
    try std.testing.expect(caller_account.owner.*.equals(&account.owner));
    try std.testing.expectEqual(caller_account.original_data_len, account.data.len);
    try std.testing.expectEqual(
        (try caller_account.ref_to_len_in_vm.get(.constant)).*,
        account.data.len,
    );
    try std.testing.expect(
        std.mem.eql(u8, caller_account.serialized_data, account.data),
    );
}

test "vm.syscalls.cpi: CallerAccount.fromAccountInfoC" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    var ctx = try TestContext.init(allocator, prng.random(), "foobar");
    defer ctx.deinit(allocator);

    const account = ctx.getAccount();
    const size = @sizeOf(AccountInfoC) +
        @sizeOf(Pubkey) * 2 +
        @sizeOf(u64) +
        account.data.len;

    const buffer = try allocator.alignedAlloc(u8, @alignOf(AccountInfoC), size);
    defer allocator.free(buffer);

    const memory_map = try MemoryMap.init(
        allocator,
        &.{
            memory.Region.init(.constant, &.{}, memory.RODATA_START),
            memory.Region.init(.mutable, &.{}, memory.STACK_START),
            memory.Region.init(.mutable, buffer, memory.HEAP_START),
            // no INPUT_START
        },
        .v3,
        .{},
    );
    defer memory_map.deinit(allocator);

    const vm_addr = memory.HEAP_START;
    const key_addr = vm_addr + @sizeOf(AccountInfoC);
    const owner_addr = key_addr + @sizeOf(Pubkey);
    const lamports_addr = owner_addr + @sizeOf(Pubkey);
    const data_addr = lamports_addr + @sizeOf(u64);

    var buf = std.io.fixedBufferStream(buffer);
    try buf.writer().writeAll(std.mem.asBytes(&AccountInfoC{
        .key_addr = key_addr,
        .lamports_addr = lamports_addr,
        .data_len = account.data.len,
        .data_addr = data_addr,
        .owner_addr = owner_addr,
        .rent_epoch = account.rent_epoch,
        .is_signer = account.is_signer,
        .is_writable = account.is_writable,
        .executable = account.executable,
    }));

    try buf.writer().writeAll(std.mem.asBytes(&account.key));
    try buf.writer().writeAll(std.mem.asBytes(&account.owner));
    try buf.writer().writeAll(std.mem.asBytes(&account.lamports));
    try buf.writer().writeAll(account.data);

    const account_info = try translateType(
        AccountInfoC,
        .constant,
        &memory_map,
        vm_addr,
        false,
    );

    const caller_account = try CallerAccount.fromAccountInfoC(
        &ctx.ic,
        &memory_map,
        vm_addr,
        account_info,
        &SerializedAccountMetadata{
            .original_data_len = account.data.len,
            .vm_data_addr = data_addr,
            .vm_key_addr = key_addr,
            .vm_lamports_addr = lamports_addr,
            .vm_owner_addr = owner_addr,
        },
    );

    try std.testing.expectEqual(caller_account.lamports.*, account.lamports);
    try std.testing.expect(caller_account.owner.*.equals(&account.owner));
    try std.testing.expectEqual(caller_account.original_data_len, account.data.len);
    try std.testing.expectEqual(
        (try caller_account.ref_to_len_in_vm.get(.constant)).*,
        account.data.len,
    );
    try std.testing.expect(
        std.mem.eql(u8, caller_account.serialized_data, account.data),
    );
}

test "vm.syscalls.cpi: translateAccounts" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    var ctx = try TestContext.init(allocator, prng.random(), "foobar");
    defer ctx.deinit(allocator);

    const account = ctx.getAccount();
    const vm_addr = MM_INPUT_START;

    const buffer, const serialized_metadata = try account.intoAccountInfoRust(allocator, vm_addr);
    defer allocator.free(buffer);

    const memory_map = try MemoryMap.init(
        allocator,
        &.{
            memory.Region.init(.constant, &.{}, memory.RODATA_START), // nothing in .rodata,
            memory.Region.init(.mutable, &.{}, memory.STACK_START), // nothing in the stack,
            memory.Region.init(.mutable, &.{}, memory.HEAP_START), // nothing in the heap,
            memory.Region.init(.mutable, buffer, vm_addr), // INPUT_START
        },
        .v3,
        .{ .aligned_memory_mapping = false },
    );
    defer memory_map.deinit(allocator);

    ctx.ic.vm_accounts.appendAssumeCapacity(serialized_metadata);

    // [agave] https://github.com/anza-xyz/agave/blob/04fd7a006d8b400096e14a69ac16e10dc3f6018a/programs/bpf_loader/src/syscalls/cpi.rs#L2554
    const accounts = try translateAccounts(
        allocator,
        &ctx.ic,
        &memory_map,
        false, // is_loader_deprecated
        AccountInfoRust,
        vm_addr, // account_infos_addr
        1, // account_infos_len
        &.{
            .{
                .pubkey = account.key,
                .index_in_transaction = account.index,
                .index_in_caller = 0,
                .index_in_callee = 0,
                .is_signer = account.is_signer,
                .is_writable = account.is_writable,
            },
            .{ // intentional duplicate to test skipping it
                .pubkey = account.key,
                .index_in_transaction = account.index,
                .index_in_caller = 0,
                .index_in_callee = 0,
                .is_signer = account.is_signer,
                .is_writable = account.is_writable,
            },
        },
    );

    try std.testing.expectEqual(accounts.len, 2);
    try std.testing.expect(accounts.get(0).caller_account == null);

    const caller_account = accounts.get(1).caller_account.?;
    try std.testing.expect(std.mem.eql(u8, caller_account.serialized_data, account.data));
    try std.testing.expectEqual(caller_account.original_data_len, account.data.len);
}

fn testTranslateInstruction(comptime AccountInfoType: type) !void {
    const InstructionType, const AccountMetaType = switch (AccountInfoType) {
        AccountInfoRust => .{ StableInstructionRust, AccountMetaRust },
        AccountInfoC => .{ StableInstructionC, AccountMetaC },
        else => @compileError("invalid AccountInfo type"),
    };

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    var ctx = try TestContext.init(allocator, prng.random(), "foo");
    defer ctx.deinit(allocator);

    const data = "ins data";
    const program_id = Pubkey.initRandom(prng.random());
    const accounts = [_]InstructionAccount{.{
        .pubkey = Pubkey.initRandom(prng.random()),
        .is_signer = true,
        .is_writable = false,
    }};

    const accounts_len = @sizeOf(AccountMetaType) * accounts.len;
    var total_size = @sizeOf(InstructionType) + accounts_len + data.len;
    
    const keys_offset = total_size;
    if (AccountInfoType == AccountInfoC) {
        total_size += @sizeOf(Pubkey) + (accounts.len * @sizeOf(Pubkey));
    }

    const buffer = try allocator.alloc(u8, total_size);
    defer allocator.free(buffer);

    const vm_addr = MM_INPUT_START;
    const memory_map = try MemoryMap.init(
        allocator,
        &.{
            memory.Region.init(.constant, &.{}, memory.RODATA_START),
            memory.Region.init(.mutable, &.{}, memory.STACK_START),
            memory.Region.init(.mutable, &.{}, memory.HEAP_START),
            memory.Region.init(.mutable, buffer, memory.INPUT_START),
        },
        .v3,
        .{ .aligned_memory_mapping = false },
    );
    defer memory_map.deinit(allocator);

    const ins: InstructionType = switch (InstructionType) {
        StableInstructionRust => .{
            .accounts_addr = vm_addr + @sizeOf(InstructionType),
            .accounts_cap = accounts.len,
            .accounts_len = accounts.len,
            .data_addr = vm_addr + @sizeOf(InstructionType) + accounts_len,
            .data_cap = data.len,
            .data_len = data.len,
            .program_id = program_id,
        },
        StableInstructionC => .{
            .program_id_addr = vm_addr + keys_offset,
            .accounts_addr = vm_addr + @sizeOf(InstructionType),
            .accounts_len = accounts.len,
            .data_addr = vm_addr + @sizeOf(InstructionType) + accounts_len,
            .data_len = data.len,
        },
        else => unreachable,
    };

    var buf = std.io.fixedBufferStream(buffer);
    try buf.writer().writeAll(std.mem.asBytes(&ins));

    for (accounts, 0..) |ins_account, i| {
        const account_meta: AccountMetaType = switch (AccountMetaType) {
            AccountMetaC => .{
                .pubkey_addr = keys_offset + ((i + 1) * @sizeOf(Pubkey)),
                .is_writable = ins_account.is_writable,
                .is_signer = ins_account.is_signer,
            },
            AccountMetaRust => .{
                .pubkey = ins_account.pubkey,
                .is_writable = ins_account.is_writable,
                .is_signer = ins_account.is_signer,
            },
            else => unreachable,
        };
        try buf.writer().writeAll(std.mem.asBytes(&account_meta));
    }

    try buf.writer().writeAll(data);
    if (AccountInfoType == AccountInfoC) {
        try buf.writer().writeAll(std.mem.asBytes(&program_id));
        for (accounts) |a| try buf.writer().writeAll(std.mem.asBytes(&a.pubkey));
    }

    const translated_instruction = try translateInstruction(
        allocator,
        &ctx.ic,
        &memory_map,
        AccountInfoType,
        vm_addr,
    );
    defer allocator.free(translated_instruction.accounts);

    try std.testing.expect(translated_instruction.program_id.equals(&program_id));
    try std.testing.expect(std.mem.eql(u8, translated_instruction.data, data));

    try std.testing.expectEqual(translated_instruction.accounts.len, accounts.len);
    for (accounts, translated_instruction.accounts) |a, b| {
        try std.testing.expect(a.pubkey.equals(&b.pubkey));
        try std.testing.expectEqual(a.is_signer, b.is_signer);
        try std.testing.expectEqual(a.is_writable, b.is_writable);
    }
}

test "vm.syscalls.cpi: translateInstructionRust" {
    try testTranslateInstruction(AccountInfoRust);
}

test "vm.syscalls.cpi: translateInstructionC" {
    try testTranslateInstruction(AccountInfoC);
}

test "vm.syscalls.cpi: translateSigners" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    var ctx = try TestContext.init(allocator, prng.random(), "foo");
    defer ctx.deinit(allocator);

    const program_id = Pubkey.initRandom(prng.random());
    const derive_key, const bump_seed = pubkey_utils.findProgramAddress(&.{"foo"}, program_id).?;

    // mock_signers(&.{"foo", &.{bump_seed}}, vm_addr)
    // [agave] https://github.com/anza-xyz/agave/blob/04fd7a006d8b400096e14a69ac16e10dc3f6018a/programs/bpf_loader/src/syscalls/cpi.rs#L2815
    const signers: []const []const u8 = &.{ "foo", &.{bump_seed} };
    const total_size = @sizeOf(VmSlice) +
        (signers.len * @sizeOf(VmSlice)) +
        signers[0].len + signers[1].len;

    const buffer = try allocator.alloc(u8, total_size);
    defer allocator.free(buffer);

    const vm_addr = MM_INPUT_START;
    const memory_map = try MemoryMap.init(
        allocator,
        &.{
            memory.Region.init(.constant, &.{}, memory.RODATA_START),
            memory.Region.init(.mutable, &.{}, memory.STACK_START),
            memory.Region.init(.mutable, &.{}, memory.HEAP_START),
            memory.Region.init(.mutable, buffer, memory.INPUT_START),
        },
        .v3,
        .{ .aligned_memory_mapping = false },
    );
    defer memory_map.deinit(allocator);

    var buf = std.io.fixedBufferStream(buffer);
    try buf.writer().writeAll(std.mem.asBytes(&VmSlice{
        .ptr = vm_addr + @sizeOf(VmSlice), // start of signers below
        .len = signers.len,
    }));

    var bytes_offset = @sizeOf(VmSlice) + (signers.len * @sizeOf(VmSlice));
    for (signers) |bytes| {
        try buf.writer().writeAll(std.mem.asBytes(&VmSlice{
            .ptr = vm_addr + bytes_offset,
            .len = bytes.len,
        }));
        bytes_offset += bytes.len;
    }
    for (signers) |bytes| {
        try buf.writer().writeAll(bytes);
    }

    const translated_signers = try translateSigners(
        &ctx.ic,
        &memory_map,
        vm_addr,
        1,
        program_id,
    );
    try std.testing.expectEqual(translated_signers.len, 1);
    try std.testing.expect(translated_signers.get(0).equals(&derive_key));
}