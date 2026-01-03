const std = @import("std");
const builtin = @import("builtin");
const sig = @import("../../sig.zig");

const ids = sig.runtime.ids;
const bpf_loader_program = sig.runtime.program.bpf_loader;
const system_program = sig.runtime.program.system;
const pubkey_utils = sig.runtime.pubkey_utils;
const serialize = sig.runtime.program.bpf.serialize;
const memory = sig.vm.memory;

const Pubkey = sig.core.Pubkey;
const Epoch = sig.core.Epoch;
const Instruction = sig.core.Instruction;
const InstructionAccount = sig.core.instruction.InstructionAccount;
const InstructionError = sig.core.instruction.InstructionError;

const BorrowedAccount = sig.runtime.BorrowedAccount;
const InstructionInfo = sig.runtime.InstructionInfo;
const InstructionContext = sig.runtime.InstructionContext;
const TransactionContext = sig.runtime.TransactionContext;
const SerializedAccountMetadata = sig.runtime.program.bpf.serialize.SerializedAccountMeta;
const PRECOMPILES = sig.runtime.program.precompiles.PRECOMPILES;

const SyscallError = sig.vm.syscalls.Error;
const RegisterMap = sig.vm.interpreter.RegisterMap;
const Error = sig.vm.ExecutionError;

const VmSlice = memory.VmSlice;
const MemoryMap = memory.MemoryMap;
const MM_INPUT_START = memory.INPUT_START;

const MAX_PERMITTED_DATA_INCREASE = serialize.MAX_PERMITTED_DATA_INCREASE;
const BPF_ALIGN_OF_U128 = serialize.BPF_ALIGN_OF_U128;

/// SIMD-0339 based calculation of AccountInfo translation byte size. Fixed size of **80 bytes** for each AccountInfo broken down as:
/// - 32 bytes for account address
/// - 32 bytes for owner address
/// - 8 bytes for lamport balance
/// - 8 bytes for data length
///
/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.4/program-runtime/src/cpi.rs#L68
const ACCOUNT_INFO_BYTE_SIZE = 80;

/// [agave] StableVec: https://github.com/anza-xyz/solana-sdk/blob/c54daf5355ad43448786cafdb66ff07d3add8be5/stable-layout/src/stable_vec.rs#L30
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
pub const AccountMetaRust = extern struct {
    /// An account's public key.
    pubkey: Pubkey,
    /// True if an `Instruction` requires a `Transaction` signature matching `pubkey`.
    is_signer: u8,
    /// True if the account data or metadata may be mutated during program execution.
    is_writable: u8,
};

/// [agave] https://github.com/anza-xyz/agave/blob/04fd7a006d8b400096e14a69ac16e10dc3f6018a/programs/bpf_loader/src/syscalls/cpi.rs#L588
const AccountMetaC = extern struct {
    pubkey_addr: u64,
    is_writable: u8,
    is_signer: u8,
};

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/ddf107050306fa07c714f7c37abcfab1d1edae26/account-info/src/lib.rs#L22
pub const AccountInfoRust = extern struct {
    key_addr: u64,
    lamports_addr: Rc(RefCell(u64)),
    data: Rc(RefCell([]u8)),
    owner_addr: u64,
    rent_epoch: Epoch,
    is_signer: u8,
    is_writable: u8,
    executable: u8,
};

/// [agave] https://github.com/anza-xyz/agave/blob/04fd7a006d8b400096e14a69ac16e10dc3f6018a/359d7eb2b68639443d750ffcec0c7e358f138975/bpf_loader/src/syscalls/cpi.rs#L597
pub const AccountInfoC = extern struct {
    key_addr: u64,
    lamports_addr: u64,
    data_len: u64,
    data_addr: u64,
    owner_addr: u64,
    rent_epoch: u64,
    is_signer: u8,
    is_writable: u8,
    executable: u8,
};

const RC_VALUE_OFFSET = @sizeOf(usize) * 2;

/// [rust] https://doc.rust-lang.org/src/alloc/rc.rs.html#281-289
/// [agave] https://github.com/anza-xyz/agave/blob/04fd7a006d8b400096e14a69ac16e10dc3f6018a/programs/bpf_loader/src/syscalls/cpi.rs#L2971
fn RcBox(comptime T: type) type {
    return extern struct {
        strong: usize = 0,
        weak: usize = 0,
        value: T,
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
        vm_address: struct {
            vm_addr: u64,
            memory_map: *const MemoryMap,
            check_aligned: bool,
        },
        translated_addr: usize,

        pub fn get(self: @This(), comptime state: memory.MemoryState) !(switch (state) {
            .constant => *align(1) const T,
            .mutable => *align(1) T,
        }) {
            return switch (self) {
                .translated_addr => |ptr| @ptrFromInt(ptr),
                .vm_address => |vma| vma.memory_map.translateType(
                    T,
                    state,
                    vma.vm_addr,
                    vma.check_aligned,
                ),
            };
        }
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
        // Intentional ' instead of ` to match logs.
        try ic.tc.log("Invalid account info pointer `{s}': 0x{x} != 0x{x}", .{
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
    lamports: *align(1) u64,
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

    fn getSerializedData(
        memory_map: *const MemoryMap,
        vm_addr: u64,
        len: u64,
        stricter_abi_and_runtime_constraints: bool,
        direct_mapping: bool,
    ) ![]u8 {
        if (stricter_abi_and_runtime_constraints and direct_mapping) {
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
            return &.{};
        } else if (stricter_abi_and_runtime_constraints) {
            // Workaround the memory permissions (as these are from the PoV of being inside the VM)
            const slice = try memory_map.translateSlice(u8, .mutable, MM_INPUT_START, 1, false);
            return (slice.ptr + (vm_addr -| MM_INPUT_START))[0..len];
        } else {
            return try memory_map.translateSlice(u8, .mutable, vm_addr, len, false);
        }
    }

    /// Parses out a CallerAccount from an AccountInfoRust that lives in VM host memory.
    fn fromAccountInfoRust(
        ic: *const InstructionContext,
        memory_map: *const MemoryMap,
        _: u64, // vm_addr. Unused, but we need the same function prototype as `fromAccountInfoC()`.
        account_info: *align(1) const AccountInfoRust,
        account_metadata: *const SerializedAccountMetadata,
    ) !CallerAccount {
        const account_data_direct_mapping = ic.tc.feature_set.active(
            .account_data_direct_mapping,
            ic.tc.slot,
        );
        const stricter_abi_and_runtime_constraints = ic.tc.feature_set.active(
            .stricter_abi_and_runtime_constraints,
            ic.tc.slot,
        );

        if (stricter_abi_and_runtime_constraints) {
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
        const lamports: *align(1) u64 = blk: {
            // Models the RefCell as_ptr() access here
            // [agave] https://github.com/anza-xyz/agave/blob/359d7eb2b68639443d750ffcec0c7e358f138975/programs/bpf_loader/src/syscalls/cpi.rs#L151
            const lamports_addr: u64 = @intFromPtr(account_info.lamports_addr.deref().asPtr());

            // Double translate lamports out of RefCell
            const ptr = try memory_map.translateType(
                u64,
                .constant,
                lamports_addr,
                ic.getCheckAligned(),
            );
            if (stricter_abi_and_runtime_constraints) {
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
            break :blk try memory_map.translateType(
                u64,
                .mutable,
                ptr.*,
                ic.getCheckAligned(),
            );
        };

        const owner: *Pubkey = try memory_map.translateType(
            Pubkey,
            .mutable,
            account_info.owner_addr,
            ic.getCheckAligned(),
        );

        const serialized, const vm_data_addr, const ref_to_len_addr = blk: {
            // See above on lamports regarding Rc(RefCell) pointer accessing.
            const data_ptr: u64 = @intFromPtr(account_info.data.deref().asPtr());
            if (stricter_abi_and_runtime_constraints and data_ptr >= MM_INPUT_START) {
                return SyscallError.InvalidPointer;
            }

            // Double translate data out of RefCell
            const data: VmSlice = (try memory_map.translateType(
                VmSlice,
                .constant,
                data_ptr,
                ic.getCheckAligned(),
            )).*;
            if (stricter_abi_and_runtime_constraints) {
                try checkAccountInfoPtr(
                    ic,
                    data.ptr,
                    account_metadata.vm_data_addr,
                    "data",
                );
            }

            try ic.tc.consumeCompute(data.len / ic.tc.compute_budget.cpi_bytes_per_unit);

            const vm_len_addr = data_ptr +| @sizeOf(u64);
            if (stricter_abi_and_runtime_constraints) {
                // In the same vein as the other check_account_info_pointer() checks, we don't lock
                // this pointer to a specific address but we don't want it to be inside accounts, or
                // callees might be able to write to the pointed memory.
                if (vm_len_addr >= MM_INPUT_START) {
                    return SyscallError.InvalidPointer;
                }
            }

            const ref_to_len_addr = try memory_map.translate(.mutable, vm_len_addr, @sizeOf(u64));
            const vm_data_addr = data.ptr;
            const serialized: []u8 = try getSerializedData(
                memory_map,
                vm_data_addr,
                data.len,
                stricter_abi_and_runtime_constraints,
                account_data_direct_mapping,
            );

            break :blk .{ serialized, vm_data_addr, ref_to_len_addr };
        };

        return .{
            .lamports = lamports,
            .owner = owner,
            .original_data_len = account_metadata.original_data_len,
            .serialized_data = serialized,
            .vm_data_addr = vm_data_addr,
            .ref_to_len_in_vm = .{ .translated_addr = ref_to_len_addr },
        };
    }

    /// Parses out a CallerAccount from an AccountInfoC that lives in VM host memory.
    fn fromAccountInfoC(
        ic: *const InstructionContext,
        memory_map: *const MemoryMap,
        vm_addr: u64,
        account_info: *align(1) const AccountInfoC,
        account_metadata: *const SerializedAccountMetadata,
    ) !CallerAccount {
        const account_data_direct_mapping = ic.tc.feature_set.active(
            .account_data_direct_mapping,
            ic.tc.slot,
        );
        const stricter_abi_and_runtime_constraints = ic.tc.feature_set.active(
            .stricter_abi_and_runtime_constraints,
            ic.tc.slot,
        );

        if (stricter_abi_and_runtime_constraints) {
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
        const lamports = try memory_map.translateType(
            u64,
            .mutable,
            account_info.lamports_addr,
            ic.getCheckAligned(),
        );
        const owner = try memory_map.translateType(
            Pubkey,
            .mutable,
            account_info.owner_addr,
            ic.getCheckAligned(),
        );

        try ic.tc.consumeCompute(account_info.data_len / ic.tc.compute_budget.cpi_bytes_per_unit);

        const serialized_data: []u8 = try getSerializedData(
            memory_map,
            account_info.data_addr,
            account_info.data_len,
            stricter_abi_and_runtime_constraints,
            account_data_direct_mapping,
        );

        // we already have the host addr we want: &mut account_info.data_len.
        // The account info might be read only in the vm though, so we translate
        // to ensure we can write. This is tested by programs/sbf/rust/ro_modify
        // which puts SolAccountInfo in rodata.
        const vm_len_addr = vm_addr +|
            @intFromPtr(&account_info.data_len) -|
            @intFromPtr(account_info);

        const ref_to_len_addr = try memory_map.translate(.mutable, vm_len_addr, @sizeOf(u64));
        return .{
            .lamports = lamports,
            .owner = owner,
            .original_data_len = account_metadata.original_data_len,
            .serialized_data = serialized_data,
            .vm_data_addr = account_info.data_addr,
            .ref_to_len_in_vm = .{ .translated_addr = ref_to_len_addr },
        };
    }
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
    callee_account: *BorrowedAccount,
    caller_account: *const CallerAccount,
    stricter_abi_and_runtime_constraints: bool,
    account_data_direct_mapping: bool,
) !bool {
    var must_update_caller = false;

    if (callee_account.account.lamports != caller_account.lamports.*) {
        try callee_account.setLamports(caller_account.lamports.*);
    }

    if (stricter_abi_and_runtime_constraints) {
        const prev_len = callee_account.constAccountData().len;
        const post_len = (try caller_account.ref_to_len_in_vm.get(.constant)).*;
        if (prev_len != post_len) {
            const is_caller_loader_deprecated = !ic.getCheckAligned();
            const address_space = caller_account.original_data_len +|
                (MAX_PERMITTED_DATA_INCREASE * @intFromBool(!is_caller_loader_deprecated));
            if (post_len > address_space) {
                return InstructionError.InvalidRealloc;
            }
            try callee_account.setDataLength(allocator, &ic.tc.accounts_resize_delta, post_len);
            // pointer to data may have changed, so caller must be updated
            must_update_caller = true;
        }
        if (!account_data_direct_mapping and callee_account.checkDataIsMutable() == null) {
            try callee_account.setDataFromSlice(
                allocator,
                &ic.tc.accounts_resize_delta,
                caller_account.serialized_data,
            );
        }
    } else {
        // The redundant check helps to avoid the expensive data comparison if we can
        const can_data_be_resized = callee_account.checkCanSetDataLength(
            ic.tc.accounts_resize_delta,
            caller_account.serialized_data.len,
        );
        if (can_data_be_resized) |err| {
            if (!std.mem.eql(u8, callee_account.account.data, caller_account.serialized_data))
                return err;
        } else {
            try callee_account.setDataFromSlice(
                allocator,
                &ic.tc.accounts_resize_delta,
                caller_account.serialized_data,
            );
        }
    }

    // Change the owner at the end so that we are allowed to change the lamports and data before
    if (!callee_account.account.owner.equals(caller_account.owner)) {
        try callee_account.setOwner(caller_account.owner.*);
        // caller gave ownership and thus write access away, so caller must be updated
        must_update_caller = true;
    }

    return must_update_caller;
}

const TranslatedAccounts = std.BoundedArray(TranslatedAccount, InstructionInfo.MAX_ACCOUNT_METAS);
const TranslatedAccount = struct {
    index_in_caller: u16,
    caller_account: CallerAccount,
    update_caller_account_region: bool,
    update_caller_account_info: bool,
};

/// Implements SyscallInvokeSigned::translate_accounts for both AccountInfoRust & AccountInfoC.
/// Reads the AccountInfos from VM and converting them into CallerAccounts + metadata index.
///
/// [agave] https://github.com/anza-xyz/agave/blob/359d7eb2b68639443d750ffcec0c7e358f138975/programs/bpf_loader/src/syscalls/cpi.rs#L498
/// [agave] https://github.com/anza-xyz/agave/blob/359d7eb2b68639443d750ffcec0c7e358f138975/programs/bpf_loader/src/syscalls/cpi.rs#L725
fn translateAccounts(
    comptime AccountType: type,
    allocator: std.mem.Allocator,
    ic: *const InstructionContext,
    memory_map: *const MemoryMap,
    account_infos_addr: u64,
    account_infos_len: u64,
    cpi_info: *const InstructionInfo,
) !TranslatedAccounts {
    const account_metas = cpi_info.account_metas.items;

    // translate_account_infos():
    const tc = ic.tc;
    const account_data_direct_mapping = tc.feature_set.active(
        .account_data_direct_mapping,
        tc.slot,
    );
    const stricter_abi_and_runtime_constraints = tc.feature_set.active(
        .stricter_abi_and_runtime_constraints,
        tc.slot,
    );
    const increase_info_limit = tc.feature_set.active(.increase_cpi_account_info_limit, tc.slot);

    // In the same vein as the other checkAccountInfoPtr() checks, we don't lock
    // this pointer to a specific address but we don't want it to be inside accounts, or
    // callees might be able to write to the pointed memory.
    if (stricter_abi_and_runtime_constraints and
        (account_infos_addr +| (account_infos_len *| @sizeOf(AccountType))) >= MM_INPUT_START)
    {
        return SyscallError.InvalidPointer;
    }

    const account_infos = try memory_map.translateSlice(
        AccountType,
        .constant,
        account_infos_addr,
        account_infos_len,
        ic.getCheckAligned(),
    );

    // check_account_infos():
    const max_cpi_account_infos: u32 = if (increase_info_limit)
        255
    else if (tc.feature_set.active(.increase_tx_account_lock_limit, tc.slot))
        128
    else
        64;
    if (account_infos.len > max_cpi_account_infos) {
        return SyscallError.MaxInstructionAccountInfosExceeded;
    }

    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.4/program-runtime/src/cpi.rs#L969-L981
    if (increase_info_limit) {
        const account_info_bytes = account_infos.len *| ACCOUNT_INFO_BYTE_SIZE;
        try tc.consumeCompute(account_info_bytes / tc.compute_budget.cpi_bytes_per_unit);
    }

    // translate keys upfront before inner loop below.
    var account_info_keys: std.BoundedArray(
        *align(1) const Pubkey,
        InstructionInfo.MAX_ACCOUNT_METAS,
    ) = .{};
    for (account_infos) |account_info| {
        account_info_keys.appendAssumeCapacity(try memory_map.translateType(
            Pubkey,
            .constant,
            account_info.key_addr,
            ic.getCheckAligned(),
        ));
    }

    // translate_and_update_accounts():

    var accounts: TranslatedAccounts = .{};
    for (account_metas, 0..) |meta, index_in_instruction| {
        const cpi_index_in_caller =
            try cpi_info.getAccountInstructionIndex(meta.index_in_transaction);

        if (cpi_index_in_caller != index_in_instruction) {
            continue; // Skip duplicate account.
        }

        const index_in_caller =
            try ic.ixn_info.getAccountInstructionIndex(meta.index_in_transaction);

        var callee_account = try ic.borrowInstructionAccount(index_in_caller);
        defer callee_account.release();

        const account_key = blk: {
            const account_meta = tc.getAccountAtIndex(meta.index_in_transaction) orelse
                return InstructionError.MissingAccount;
            break :blk account_meta.pubkey;
        };

        if (callee_account.account.executable) {
            // Use the known account
            try tc.consumeCompute(
                callee_account.constAccountData().len / tc.compute_budget.cpi_bytes_per_unit,
            );
            continue;
        }

        const caller_account_index = for (account_info_keys.constSlice(), 0..) |key, idx| {
            if (key.equals(&account_key)) break idx;
        } else {
            try tc.log("Instruction references an unknown account {}", .{account_key});
            return InstructionError.MissingAccount;
        };

        const serialized_account_metas = tc.serialized_accounts.constSlice();
        const serialized_metadata = if (index_in_caller < serialized_account_metas.len) blk: {
            break :blk &serialized_account_metas[index_in_caller];
        } else {
            try tc.log("Internal error: index mismatch for account {}", .{account_key});
            return InstructionError.MissingAccount;
        };

        // build the CallerAccount corresponding to this account.
        if (caller_account_index >= account_infos.len) {
            return SyscallError.InvalidLength;
        }

        const caller_account = try @call(
            .auto,
            switch (AccountType) {
                AccountInfoC => CallerAccount.fromAccountInfoC,
                AccountInfoRust => CallerAccount.fromAccountInfoRust,
                else => @compileError("invalid AccountInfo type"),
            },
            .{
                ic,
                memory_map,
                account_infos_addr +| (caller_account_index *| @sizeOf(AccountType)),
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
            &callee_account,
            &caller_account,
            stricter_abi_and_runtime_constraints,
            account_data_direct_mapping,
        );

        try accounts.append(.{
            .index_in_caller = index_in_caller,
            .caller_account = caller_account,
            .update_caller_account_region = meta.is_writable or update_caller,
            .update_caller_account_info = meta.is_writable,
        });
    }

    return accounts;
}

/// Converts a StableInstruction type in VM memory (depending on AccountInfoType) into Instruction.
///
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

    const stable_instruction = try memory_map.translateType(
        InstructionType,
        .constant,
        vm_addr,
        ic.getCheckAligned(),
    );

    const program_id = switch (AccountInfoType) {
        AccountInfoRust => stable_instruction.program_id,
        AccountInfoC => (try memory_map.translateType(
            Pubkey,
            .constant,
            stable_instruction.program_id_addr,
            ic.getCheckAligned(),
        )).*,
        else => unreachable,
    };
    const account_metas = try memory_map.translateSlice(
        AccountMetaType,
        .constant,
        stable_instruction.accounts_addr,
        stable_instruction.accounts_len,
        ic.getCheckAligned(),
    );
    const data = try memory_map.translateSlice(
        u8,
        .constant,
        stable_instruction.data_addr,
        stable_instruction.data_len,
        ic.getCheckAligned(),
    );

    const tc = ic.tc;
    const loosen_cpi_size = tc.feature_set.active(.loosen_cpi_size_restriction, tc.slot);
    const increase_info_limit = tc.feature_set.active(.increase_cpi_account_info_limit, tc.slot);

    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.4/program-runtime/src/cpi.rs#L146-L161
    if (loosen_cpi_size) {
        if (account_metas.len >= InstructionInfo.MAX_ACCOUNT_METAS) {
            return SyscallError.MaxInstructionAccountsExceeded;
        }
        if (data.len > 10 * 1024) {
            return SyscallError.MaxInstructionDataLenExceeded;
        }

        var total_cu_cost = data.len / tc.compute_budget.cpi_bytes_per_unit;
        // [agave] https://github.com/anza-xyz/agave/blob/v3.1.4/program-runtime/src/cpi.rs#L555-L567
        if (increase_info_limit) {
            // NOTE: Agave uses the same size here (34 bytes) no matter which type it is.
            total_cu_cost +|= account_metas.len *| @sizeOf(AccountMetaRust) /
                tc.compute_budget.cpi_bytes_per_unit;
        }
        try tc.consumeCompute(total_cu_cost);
    } else {
        // [agave] https://github.com/solana-labs/solana/blob/dbf06e258ae418097049e845035d7d5502fe1327/programs/bpf_loader/src/syscalls/cpi.rs#L1114-L1120
        const total_size = account_metas.len *| @sizeOf(AccountInfoRust) +| data.len;
        if (total_size > tc.compute_budget.max_cpi_instruction_size) {
            return SyscallError.InstructionTooLarge;
        }
    }

    var accounts = try allocator.alloc(InstructionAccount, account_metas.len);
    errdefer allocator.free(accounts);

    for (account_metas, 0..) |account_meta, i| {
        // Check if the u8 which holds the bools is valid (contains 0 or 1).
        if (account_meta.is_signer > 1 or account_meta.is_writable > 1) {
            return InstructionError.InvalidArgument;
        }

        accounts[i] = InstructionAccount{
            .is_signer = account_meta.is_signer > 0,
            .is_writable = account_meta.is_writable > 0,
            .pubkey = switch (AccountInfoType) {
                AccountInfoRust => account_meta.pubkey,
                AccountInfoC => (try memory_map.translateType(
                    Pubkey,
                    .constant,
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
        .owned_data = false,
        .program_id = program_id,
    };
}

// [agave] https://github.com/anza-xyz/agave/blob/04fd7a006d8b400096e14a69ac16e10dc3f6018a/programs/bpf_loader/src/syscalls/mod.rs#L81
const MAX_SIGNERS = 16;

/// Reads a slice of seed slices from the VM and converts them into program address Pubkeys.
///
/// [agave] https://github.com/anza-xyz/agave/blob/bb5a6e773d5f41388a962c5c4f96f5f2ef2209d0/programs/bpf_loader/src/syscalls/cpi.rs#L511
/// [agave] https://github.com/anza-xyz/agave/blob/bb5a6e773d5f41388a962c5c4f96f5f2ef2209d0/programs/bpf_loader/src/syscalls/cpi.rs#L735
fn translateSigners(
    ic: *const InstructionContext,
    memory_map: *const MemoryMap,
    signers_seeds_addr: u64,
    signers_seeds_len: u64,
    program_id: Pubkey,
) !std.BoundedArray(Pubkey, MAX_SIGNERS) {
    if (signers_seeds_len == 0) return .{};

    const signers_seeds = try memory_map.translateSlice(
        VmSlice,
        .constant,
        signers_seeds_addr,
        signers_seeds_len,
        ic.getCheckAligned(),
    );

    if (signers_seeds.len > MAX_SIGNERS) {
        return SyscallError.TooManySigners;
    }

    var signers: std.BoundedArray(Pubkey, MAX_SIGNERS) = .{};
    for (signers_seeds) |signer_vm_slice| {
        const untranslated_seeds = try memory_map.translateSlice(
            VmSlice,
            .constant,
            signer_vm_slice.ptr,
            signer_vm_slice.len,
            ic.getCheckAligned(),
        );

        if (untranslated_seeds.len > MAX_SIGNERS) {
            return SyscallError.MaxSeedLengthExceeded;
        }

        var seeds: std.BoundedArray([]const u8, MAX_SIGNERS) = .{};
        for (untranslated_seeds) |seeds_vm_slice| {
            seeds.appendAssumeCapacity(try memory_map.translateSlice(
                u8,
                .constant,
                seeds_vm_slice.ptr,
                seeds_vm_slice.len,
                ic.getCheckAligned(),
            ));
        }

        const key = pubkey_utils.createProgramAddress(
            seeds.slice(),
            &.{}, // no bump seeds AFAIK
            program_id,
        ) catch return SyscallError.BadSeeds;
        signers.appendAssumeCapacity(key);
    }

    return signers;
}

fn accountDataRegion(
    memory_map: *const MemoryMap,
    vm_data_addr: u64,
    original_data_len: usize,
) !(?*memory.Region) {
    if (original_data_len == 0) {
        return null;
    }

    const region = try memory_map.region(.constant, vm_data_addr);
    std.debug.assert(region.vm_addr_start == vm_data_addr);
    return region;
}

fn accountReallocRegion(
    memory_map: *const MemoryMap,
    vm_data_addr: u64,
    original_data_len: usize,
    is_loader_deprecated: bool,
) !(?*memory.Region) {
    if (is_loader_deprecated) {
        return null;
    }

    const addr = vm_data_addr +| original_data_len;
    const region = try memory_map.region(.constant, addr);
    std.debug.assert(region.vm_addr_start == addr);
    std.debug.assert(
        region.constSlice().len >= MAX_PERMITTED_DATA_INCREASE and
            region.constSlice().len < MAX_PERMITTED_DATA_INCREASE +| BPF_ALIGN_OF_U128,
    );
    return region;
}

/// Update the given account after executing CPI.
///
/// caller_account and callee_account describe to the same account. At CPI exit
/// callee_account might include changes the callee has made to the account
/// after executing.
///
/// This method updates caller_account so the CPI caller can see the callee's
/// changes.
///
/// [agave] https://github.com/anza-xyz/agave/blob/bb5a6e773d5f41388a962c5c4f96f5f2ef2209d0/programs/bpf_loader/src/syscalls/cpi.rs#L1335
fn updateCallerAccount(
    ic: *const InstructionContext,
    memory_map: *const MemoryMap,
    caller_account: *CallerAccount,
    callee_account: *BorrowedAccount,
    stricter_abi_and_runtime_constraints: bool,
    account_data_direct_mapping: bool,
) !void {
    caller_account.lamports.* = callee_account.account.lamports;
    caller_account.owner.* = callee_account.account.owner;

    const prev_len: usize = (try caller_account.ref_to_len_in_vm.get(.constant)).*;
    const post_len = callee_account.constAccountData().len;
    const is_caller_loader_deprecated = !ic.getCheckAligned();

    const reserve = stricter_abi_and_runtime_constraints and is_caller_loader_deprecated;
    const address_space = caller_account.original_data_len +|
        (MAX_PERMITTED_DATA_INCREASE * @intFromBool(!reserve));

    if (post_len > address_space and
        (stricter_abi_and_runtime_constraints or prev_len != post_len))
    {
        try ic.tc.log(
            "Account data size realloc limited to {} in inner instructions",
            .{address_space -| caller_account.original_data_len},
        );
        return InstructionError.InvalidRealloc;
    }

    if (prev_len != post_len) {
        // when stricter_abi_and_runtime_constraints is enabled we don't cache the serialized data
        // in caller_account.serialized_data. See CallerAccount.fromAccountInfoRust.
        if (!(stricter_abi_and_runtime_constraints and account_data_direct_mapping)) {
            // If the account has been shrunk, we're going to zero the unused memory
            // *that was previously used*.
            if (post_len < prev_len) {
                if (post_len > caller_account.serialized_data.len)
                    return InstructionError.AccountDataTooSmall;
                @memset(caller_account.serialized_data[post_len..], 0);
            }
            // Set the length of caller_account.serialized_data to post_len.
            caller_account.serialized_data = try CallerAccount.getSerializedData(
                memory_map,
                caller_account.vm_data_addr,
                post_len,
                stricter_abi_and_runtime_constraints,
                account_data_direct_mapping,
            );
        }
        // this is the len field in the AccountInfo.data slice
        (try caller_account.ref_to_len_in_vm.get(.mutable)).* = post_len;

        // this is the len field in the serialized parameters
        const serialized_len = try memory_map.translateType(
            u64,
            .mutable,
            caller_account.vm_data_addr -| @sizeOf(u64),
            ic.tc.getCheckAligned(),
        );
        serialized_len.* = post_len;
    }

    if (!(stricter_abi_and_runtime_constraints and account_data_direct_mapping)) {
        // Propagate changes in the callee up to the caller.
        const to = caller_account.serialized_data;
        const from = callee_account.constAccountData();
        if (from.len < post_len) return SyscallError.InvalidLength;
        if (to.len != from.len) return InstructionError.AccountDataTooSmall;
        @memcpy(to, from);
    }
}

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.4/program-runtime/src/cpi.rs#L802
pub fn invokeSigned(AccountInfo: type) sig.vm.SyscallFn {
    return struct {
        fn common(
            tc: *TransactionContext,
            memory_map: *MemoryMap,
            registers: *RegisterMap,
        ) !void {
            const instruction_addr = registers.get(.r1);
            const account_infos_addr = registers.get(.r2);
            const account_infos_len = registers.get(.r3);
            const signers_seeds_addr = registers.get(.r4);
            const signers_seeds_len = registers.get(.r5);

            const allocator = tc.allocator;
            const ic = try tc.getCurrentInstructionContext();

            const stricter_abi_and_runtime_constraints = ic.tc.feature_set.active(
                .stricter_abi_and_runtime_constraints,
                ic.tc.slot,
            );
            const account_data_direct_mapping = ic.tc.feature_set.active(
                .account_data_direct_mapping,
                ic.tc.slot,
            );

            try tc.consumeCompute(tc.compute_budget.invoke_units);

            // TODO: timings

            const instruction = try translateInstruction(
                allocator,
                ic,
                memory_map,
                AccountInfo,
                instruction_addr,
            );
            defer instruction.deinit(allocator);

            const signers = try translateSigners(
                ic,
                memory_map,
                signers_seeds_addr,
                signers_seeds_len,
                ic.ixn_info.program_meta.pubkey,
            );

            // [agave] https://github.com/anza-xyz/agave/blob/v3.1.4/program-runtime/src/cpi.rs#L193-L222
            if (ids.NATIVE_LOADER_ID.equals(&instruction.program_id) or
                bpf_loader_program.v1.ID.equals(&instruction.program_id) or
                bpf_loader_program.v2.ID.equals(&instruction.program_id) or
                (bpf_loader_program.v3.ID.equals(&instruction.program_id) and
                    isBpfLoaderV3InstructionBlacklisted(instruction.data, tc.feature_set, tc.slot)) or
                (blk: {
                    for (PRECOMPILES) |p| if (p.program_id.equals(&instruction.program_id)) break :blk true;
                    break :blk false;
                }))
            {
                // [agave] https://github.com/anza-xyz/agave/blob/v3.1.4/program-runtime/src/cpi.rs#L219
                return SyscallError.ProgramNotSupported;
            }

            const info = try sig.runtime.executor.prepareCpiInstructionInfo(
                tc,
                instruction,
                signers.slice(),
            );
            defer info.deinit(ic.tc.allocator);

            var accounts = try translateAccounts(
                AccountInfo,
                allocator,
                ic,
                memory_map,
                account_infos_addr,
                account_infos_len,
                &info,
            );

            // Process the callee instruction.
            // Doesn't call `executeNativeCpiInstruction` as info already setup.
            try sig.runtime.executor.executeInstruction(allocator, ic.tc, info);

            // CPI Exit.
            // Synchronize the callee's account changes so the caller can see them.
            for (accounts.slice()) |*translated| {
                var callee_account = try ic.borrowInstructionAccount(translated.index_in_caller);
                defer callee_account.release();

                if (translated.update_caller_account_info) {
                    try updateCallerAccount(
                        ic,
                        memory_map,
                        &translated.caller_account,
                        &callee_account,
                        stricter_abi_and_runtime_constraints,
                        account_data_direct_mapping,
                    );
                }
            }

            if (!stricter_abi_and_runtime_constraints) {
                // nothing left for us to do
                return;
            }

            for (accounts.constSlice()) |translated| {
                var callee_account = try ic.borrowInstructionAccount(translated.index_in_caller);
                defer callee_account.release();

                if (translated.update_caller_account_region) {
                    // update_caller_account_region()
                    const caller_account = &translated.caller_account;
                    const is_caller_loader_deprecated = !ic.getCheckAligned();

                    const address_space = if (is_caller_loader_deprecated)
                        caller_account.original_data_len
                    else
                        caller_account.original_data_len +| MAX_PERMITTED_DATA_INCREASE;

                    if (address_space > 0) {
                        const region = memory_map.findRegion(caller_account.vm_data_addr) catch
                            return InstructionError.MissingAccount;
                        std.debug.assert(region.vm_addr_start == caller_account.vm_data_addr);

                        switch (callee_account.checkDataIsMutable() == null) {
                            inline true, false => |mutable| {
                                const state: memory.MemoryState = if (mutable)
                                    .mutable
                                else
                                    .constant;

                                const data = if (account_data_direct_mapping)
                                    callee_account.account.data
                                else
                                    region.hostSlice(state).?[0..callee_account.account.data.len];

                                region.* = .init(state, data, region.vm_addr_start);
                            },
                        }
                    }
                }
            }
        }
    }.common;
}

/// Some Loader-V3 instructions are not allowed to be invoked via CPI. This helper
/// determines if an instruction is authorized to be invoked through CPI.
///
/// Returns whether the provided instruction is *not* allowed to be called.
///
/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.4/program-runtime/src/cpi.rs#L202-L216
fn isBpfLoaderV3InstructionBlacklisted(
    instruction_data: []const u8,
    feature_set: *const sig.core.FeatureSet,
    slot: sig.core.Slot,
) bool {
    if (instruction_data.len == 0) return true;
    const Inst = @typeInfo(bpf_loader_program.v3.Instruction).@"union".tag_type.?;
    const inst = std.meta.intToEnum(Inst, instruction_data[0]) catch return true;
    return switch (inst) {
        .upgrade => false,
        .set_authority => false,
        .set_authority_checked => !feature_set.active(
            .enable_bpf_loader_set_authority_checked_ix,
            slot,
        ),
        .extend_program_checked => !feature_set.active(
            .enable_extend_program_checked,
            slot,
        ),
        .close => false,
        else => true,
    };
}

// CPI Tests

const testing = sig.runtime.testing;

const TestContext = struct {
    cache: sig.utils.collections.PubkeyMap(sig.runtime.AccountSharedData),
    tc: *TransactionContext,
    ic: InstructionContext,

    fn init(allocator: std.mem.Allocator, prng: std.Random, account_data: []const u8) !TestContext {
        comptime std.debug.assert(builtin.is_test);

        const tc = try allocator.create(TransactionContext);
        errdefer allocator.destroy(tc);

        const account_key = Pubkey.initRandom(prng);

        const cache, tc.* = try testing.createTransactionContext(allocator, prng, .{
            .accounts = &.{
                .{
                    .pubkey = account_key,
                    .data = account_data,
                    .owner = system_program.ID,
                    .lamports = prng.uintAtMost(u64, 1000),
                },
                .{
                    .pubkey = system_program.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                    .executable = true,
                },
            },
            .compute_meter = std.math.maxInt(u64),
        });
        errdefer {
            testing.deinitTransactionContext(allocator, tc);
            sig.runtime.testing.deinitAccountMap(cache, allocator);
        }

        try sig.runtime.executor.pushInstruction(tc, try testing.createInstructionInfo(
            tc,
            system_program.ID,
            "", // empty instruction data.
            &.{
                .{ .is_signer = true, .is_writable = true, .index_in_transaction = 0 },
                .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
            },
        ));

        return .{
            .cache = cache,
            .tc = tc,
            .ic = (try tc.getCurrentInstructionContext()).*,
        };
    }

    fn deinit(self: *TestContext, allocator: std.mem.Allocator) void {
        testing.deinitTransactionContext(allocator, self.tc);
        allocator.destroy(self.tc);
        self.ic.deinit(allocator);
        sig.runtime.testing.deinitAccountMap(self.cache, allocator);
    }

    fn getAccount(self: *const TestContext) TestAccount {
        const index = 0;
        const account_meta = self.ic.ixn_info.account_metas.items[index];
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
    fn intoAccountInfo(
        self: *const TestAccount,
        allocator: std.mem.Allocator,
        comptime AccountInfoType: type,
        vm_addr: u64,
        custom_vm_data_addr: ?u64,
    ) !struct { []u8, SerializedAccountMetadata } {
        const size = @sizeOf(AccountInfoType) +
            @sizeOf(Pubkey) * 2 +
            @sizeOf(RcBox(RefCell(*u64))) +
            @sizeOf(u64) +
            @sizeOf(RcBox(RefCell([]u8))) +
            self.data.len;

        const buffer = try allocator.alloc(u8, size);
        errdefer allocator.free(buffer);

        const key_addr = vm_addr + @sizeOf(AccountInfoType);
        const lamports_cell_addr = key_addr + @sizeOf(Pubkey);
        const lamports_addr = lamports_cell_addr + @sizeOf(RcBox(RefCell(*u64)));
        const owner_addr = lamports_addr + @sizeOf(u64);
        const data_cell_addr = owner_addr + @sizeOf(Pubkey);
        const data_addr = data_cell_addr + @sizeOf(RcBox(RefCell([]u8)));
        const data_len = self.data.len;

        const actual_data_addr = custom_vm_data_addr orelse data_addr;

        switch (AccountInfoType) {
            AccountInfoRust => buffer[0..@sizeOf(AccountInfoRust)].* = @bitCast(AccountInfoRust{
                .key_addr = key_addr,
                .is_signer = @intFromBool(self.is_signer),
                .is_writable = @intFromBool(self.is_writable),
                .lamports_addr = Rc(RefCell(u64)).fromRaw(
                    @ptrFromInt(lamports_cell_addr + RC_VALUE_OFFSET),
                ),
                .data = Rc(RefCell([]u8)).fromRaw(
                    @ptrFromInt(data_cell_addr + RC_VALUE_OFFSET),
                ),
                .owner_addr = owner_addr,
                .executable = @intFromBool(self.executable),
                .rent_epoch = self.rent_epoch,
            }),
            AccountInfoC => buffer[0..@sizeOf(AccountInfoC)].* = @bitCast(AccountInfoC{
                .key_addr = key_addr,
                .is_signer = @intFromBool(self.is_signer),
                .is_writable = @intFromBool(self.is_writable),
                .lamports_addr = lamports_addr,
                .data_addr = actual_data_addr,
                .data_len = data_len,
                .owner_addr = owner_addr,
                .executable = @intFromBool(self.executable),
                .rent_epoch = self.rent_epoch,
            }),
            else => @compileError("invalid AccountInfo type"),
        }

        buffer[key_addr - vm_addr ..][0..@sizeOf(Pubkey)].* = @bitCast(self.key);
        buffer[lamports_cell_addr - vm_addr ..][0..@sizeOf(RcBox(RefCell(*u64)))].* = @bitCast(
            RcBox(RefCell(u64)){ .value = RefCell(u64).init(lamports_addr) },
        );
        buffer[lamports_addr - vm_addr ..][0..@sizeOf(u64)].* = @bitCast(self.lamports);
        buffer[owner_addr - vm_addr ..][0..@sizeOf(Pubkey)].* = @bitCast(self.owner);
        buffer[data_cell_addr - vm_addr ..][0..@sizeOf(RcBox(RefCell([]u8)))].* = @bitCast(
            RcBox(RefCell([]u8)){
                .value = RefCell([]u8).init(@as([*]u8, @ptrFromInt(actual_data_addr))[0..data_len]),
            },
        );
        @memcpy(buffer[data_addr - vm_addr ..][0..data_len], self.data);

        return .{ buffer, SerializedAccountMetadata{
            .original_data_len = data_len,
            .vm_data_addr = actual_data_addr,
            .vm_key_addr = key_addr,
            .vm_lamports_addr = lamports_addr,
            .vm_owner_addr = owner_addr,
        } };
    }
};

test "CallerAccount.fromAccountInfoRust" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    var ctx = try TestContext.init(allocator, prng.random(), "foobar");
    defer ctx.deinit(allocator);

    const account = ctx.getAccount();
    const vm_addr = MM_INPUT_START;

    const buffer, const serialized_metadata =
        try account.intoAccountInfo(allocator, AccountInfoRust, vm_addr, null);
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

    const account_info = try memory_map.translateType(
        AccountInfoRust,
        .constant,
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

test "CallerAccount.fromAccountInfoC" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

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
        .is_signer = @intFromBool(account.is_signer),
        .is_writable = @intFromBool(account.is_writable),
        .executable = @intFromBool(account.executable),
    }));

    try buf.writer().writeAll(std.mem.asBytes(&account.key));
    try buf.writer().writeAll(std.mem.asBytes(&account.owner));
    try buf.writer().writeAll(std.mem.asBytes(&account.lamports));
    try buf.writer().writeAll(account.data);

    const account_info = try memory_map.translateType(
        AccountInfoC,
        .constant,
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

test "translateAccounts" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    var ctx = try TestContext.init(allocator, prng.random(), "foobar");
    defer ctx.deinit(allocator);

    const account = ctx.getAccount();
    const vm_addr = MM_INPUT_START;

    const buffer, const serialized_metadata =
        try account.intoAccountInfo(allocator, AccountInfoRust, vm_addr, null);
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

    ctx.tc.serialized_accounts.appendAssumeCapacity(serialized_metadata);

    var metas: InstructionInfo.AccountMetas = .empty;
    defer metas.deinit(allocator);
    try metas.appendSlice(allocator, &.{
        .{
            .pubkey = account.key,
            .index_in_transaction = account.index,
            .is_signer = account.is_signer,
            .is_writable = account.is_writable,
        },
        .{ // intentional duplicate to test skipping it
            .pubkey = account.key,
            .index_in_transaction = account.index,
            .is_signer = account.is_signer,
            .is_writable = account.is_writable,
        },
    });

    var dedupe_map: [InstructionInfo.MAX_ACCOUNT_METAS]u8 = @splat(0xff);
    dedupe_map[account.index] = 0;
    const cpi_info: InstructionInfo = .{
        .program_meta = ctx.ic.ixn_info.program_meta,
        .account_metas = metas,
        .dedupe_map = dedupe_map,
        .instruction_data = "",
        .owned_instruction_data = false,
    };

    const accounts = try translateAccounts(
        AccountInfoRust,
        allocator,
        &ctx.ic,
        &memory_map,
        vm_addr, // account_infos_addr
        1, // account_infos_len
        &cpi_info, // cpi_info
    );

    try std.testing.expectEqual(accounts.len, 1);
    try std.testing.expect(accounts.get(0).update_caller_account_region);

    const caller_account = accounts.get(0).caller_account;
    try std.testing.expect(std.mem.eql(u8, caller_account.serialized_data, account.data));
    try std.testing.expectEqual(caller_account.original_data_len, account.data.len);
}

fn intoStableInstruction(
    allocator: std.mem.Allocator,
    comptime AccountInfoType: type,
    vm_addr: u64,
    data: []const u8,
    program_id: Pubkey,
    accounts: []const InstructionAccount,
) ![]u8 {
    const InstructionType, const AccountMetaType = switch (AccountInfoType) {
        AccountInfoRust => .{ StableInstructionRust, AccountMetaRust },
        AccountInfoC => .{ StableInstructionC, AccountMetaC },
        else => @compileError("invalid AccountInfo type"),
    };

    const accounts_len = @sizeOf(AccountMetaType) * accounts.len;
    var total_size = @sizeOf(InstructionType) + accounts_len + data.len;

    const keys_offset = total_size;
    if (AccountInfoType == AccountInfoC) {
        total_size += @sizeOf(Pubkey) + (accounts.len * @sizeOf(Pubkey));
    }

    const buffer = try allocator.alloc(u8, total_size);
    errdefer allocator.free(buffer);

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
                .pubkey_addr = vm_addr + keys_offset + ((i + 1) * @sizeOf(Pubkey)),
                .is_writable = @intFromBool(ins_account.is_writable),
                .is_signer = @intFromBool(ins_account.is_signer),
            },
            AccountMetaRust => .{
                .pubkey = ins_account.pubkey,
                .is_writable = @intFromBool(ins_account.is_writable),
                .is_signer = @intFromBool(ins_account.is_signer),
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

    return buffer;
}

fn testTranslateInstruction(comptime AccountInfoType: type) !void {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    var ctx = try TestContext.init(allocator, prng.random(), "foo");
    defer ctx.deinit(allocator);

    const data = "ins data";
    const program_id = Pubkey.initRandom(prng.random());
    const accounts = [_]InstructionAccount{.{
        .pubkey = Pubkey.initRandom(prng.random()),
        .is_signer = true,
        .is_writable = false,
    }};

    const vm_addr = MM_INPUT_START;
    const buffer = try intoStableInstruction(
        allocator,
        AccountInfoType,
        vm_addr,
        data,
        program_id,
        &accounts,
    );
    defer allocator.free(buffer);

    const memory_map = try MemoryMap.init(
        allocator,
        &.{
            memory.Region.init(.constant, &.{}, memory.RODATA_START),
            memory.Region.init(.mutable, &.{}, memory.STACK_START),
            memory.Region.init(.mutable, &.{}, memory.HEAP_START),
            memory.Region.init(.mutable, buffer, vm_addr),
        },
        .v3,
        .{ .aligned_memory_mapping = false },
    );
    defer memory_map.deinit(allocator);

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

test "translateInstructionRust" {
    try testTranslateInstruction(AccountInfoRust);
}

test "translateInstructionC" {
    try testTranslateInstruction(AccountInfoC);
}

test "translateSigners" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

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

const TestCallerAccount = struct {
    lamports: u64,
    owner: Pubkey,
    vm_addr: u64,
    account_len: u64,
    len: u64,
    regions: []memory.Region,
    buffer: []u8,
    direct_mapping: bool,
    memory_map: MemoryMap,

    fn init(
        allocator: std.mem.Allocator,
        lamports: u64,
        owner: Pubkey,
        data: []const u8,
        direct_mapping: bool,
    ) !TestCallerAccount {
        const size = @sizeOf(u64) +
            (data.len * @intFromBool(!direct_mapping)) +
            MAX_PERMITTED_DATA_INCREASE;

        const buffer = try allocator.alloc(u8, size);
        errdefer allocator.free(buffer);
        @memset(buffer, 0);

        // write [len][data if not direct mapping]
        buffer[0..8].* = @bitCast(@as(u64, data.len));
        if (!direct_mapping) {
            @memcpy(buffer[8..][0..data.len], data);
        }

        // Setup regions
        var regions: std.BoundedArray(memory.Region, 6) = .{};
        try regions.append(memory.Region.init(.constant, &.{}, memory.RODATA_START));
        try regions.append(memory.Region.init(.constant, &.{}, memory.STACK_START));
        const vm_addr = memory.HEAP_START;

        var region_addr = vm_addr;
        const region_size = @sizeOf(u64) +
            (data.len + MAX_PERMITTED_DATA_INCREASE) * @intFromBool(!direct_mapping);

        // region for [len][data if not direct mapping]
        try regions.append(memory.Region.init(.mutable, buffer[0..region_size], region_addr));
        region_addr += region_size;

        var account_len: usize = buffer.len;
        if (direct_mapping) {
            // region for directly mapped data
            try regions.append(memory.Region.init(.constant, data, region_addr));
            region_addr += data.len;
            // region for realloc padding
            try regions.append(memory.Region.init(.mutable, buffer[@sizeOf(u64)..], region_addr));
        } else {
            account_len = @sizeOf(u64) + data.len;
        }

        const pinned_regions = try allocator.dupe(memory.Region, regions.slice());
        errdefer allocator.free(pinned_regions);

        return .{
            .lamports = lamports,
            .owner = owner,
            .vm_addr = vm_addr,
            .account_len = account_len,
            .len = data.len,
            .regions = pinned_regions,
            .buffer = buffer,
            .direct_mapping = direct_mapping,
            .memory_map = try MemoryMap.init(
                allocator,
                pinned_regions,
                .v3,
                .{ .aligned_memory_mapping = false },
            ),
        };
    }

    fn deinit(self: *TestCallerAccount, allocator: std.mem.Allocator) void {
        self.memory_map.deinit(allocator);
        allocator.free(self.regions);
        allocator.free(self.buffer);
    }

    fn slice(self: *const TestCallerAccount) []const u8 {
        return self.buffer[@sizeOf(u64)..];
    }

    fn getCallerAccount(self: *TestCallerAccount) CallerAccount {
        const data = self.buffer[@sizeOf(u64)..self.account_len];
        return .{
            .lamports = &self.lamports,
            .owner = &self.owner,
            .original_data_len = self.len,
            .serialized_data = if (self.direct_mapping) &.{} else data,
            .vm_data_addr = self.vm_addr + @sizeOf(u64),
            .ref_to_len_in_vm = .{ .translated_addr = @intFromPtr(&self.len) },
        };
    }
};

// test CalleeAccount (BorrowedAccount) updates.

test "updateCalleeAccount: lamports owner" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    for ([_]bool{ false, true }) |stricter_abi_and_runtime_constraints| {
        var ctx = try TestContext.init(allocator, prng.random(), &.{});
        defer ctx.deinit(allocator);
        const account = ctx.getAccount();

        var ca = try TestCallerAccount.init(
            allocator,
            1234,
            account.owner,
            account.data,
            false, // direct mapping
        );
        defer ca.deinit(allocator);
        var caller_account = ca.getCallerAccount();

        var callee_account = try ctx.ic.borrowInstructionAccount(account.index);
        defer callee_account.release();

        caller_account.lamports.* = 42;
        caller_account.owner.* = Pubkey.initRandom(prng.random());

        _ = try updateCalleeAccount(
            allocator,
            &ctx.ic,
            &callee_account,
            &caller_account,
            stricter_abi_and_runtime_constraints,
            false, // account_data_direct_mapping
        );

        try std.testing.expectEqual(callee_account.account.lamports, 42);
        try std.testing.expect(callee_account.account.owner.equals(caller_account.owner));
    }
}

test "updateCalleeAccount: data writable" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    for ([_]bool{ false, true }) |stricter_abi_and_runtime_constraints| {
        var ctx = try TestContext.init(allocator, prng.random(), "foobar");
        defer ctx.deinit(allocator);
        const account = ctx.getAccount();

        var ca = try TestCallerAccount.init(
            allocator,
            1234,
            account.owner,
            account.data,
            false, // direct mapping
        );
        defer ca.deinit(allocator);
        var caller_account = ca.getCallerAccount();

        var callee_account = try ctx.ic.borrowInstructionAccount(account.index);
        defer callee_account.release();

        // stricter_abi_and_runtime_constraints does not copy data in updateCalleeAccount()
        caller_account.serialized_data[0] = 'b';
        _ = try updateCalleeAccount(
            allocator,
            &ctx.ic,
            &callee_account,
            &caller_account,
            stricter_abi_and_runtime_constraints,
            false, // account_data_direct_mapping
        );
        try std.testing.expectEqualSlices(u8, callee_account.constAccountData(), "boobar");

        // growing resize
        var resize_data = "foobarbaz".*;
        (try caller_account.ref_to_len_in_vm.get(.mutable)).* = resize_data.len;
        caller_account.serialized_data = &resize_data;
        try std.testing.expectEqual(
            stricter_abi_and_runtime_constraints,
            try updateCalleeAccount(
                allocator,
                &ctx.ic,
                &callee_account,
                &caller_account,
                stricter_abi_and_runtime_constraints,
                true, // account_data_direct_mapping
            ),
        );

        // truncating resize
        var truncate_data = "baz".*;
        (try caller_account.ref_to_len_in_vm.get(.mutable)).* = truncate_data.len;
        caller_account.serialized_data = &truncate_data;
        try std.testing.expectEqual(
            stricter_abi_and_runtime_constraints,
            try updateCalleeAccount(
                allocator,
                &ctx.ic,
                &callee_account,
                &caller_account,
                stricter_abi_and_runtime_constraints,
                true, // account_data_direct_mapping
            ),
        );

        // close account
        (try caller_account.ref_to_len_in_vm.get(.mutable)).* = 0;
        caller_account.serialized_data = &.{};
        var owner = system_program.ID;
        caller_account.owner = &owner;
        _ = try updateCalleeAccount(
            allocator,
            &ctx.ic,
            &callee_account,
            &caller_account,
            stricter_abi_and_runtime_constraints,
            true, // account_data_direct_mapping
        );
        try std.testing.expectEqualSlices(u8, callee_account.constAccountData(), "");

        // growing beyond `address_space`
        (try caller_account.ref_to_len_in_vm.get(.mutable)).* = MAX_PERMITTED_DATA_INCREASE + 7;
        const result = updateCalleeAccount(
            allocator,
            &ctx.ic,
            &callee_account,
            &caller_account,
            stricter_abi_and_runtime_constraints,
            true, // account_data_direct_mapping
        );
        if (stricter_abi_and_runtime_constraints) {
            try std.testing.expectError(InstructionError.InvalidRealloc, result);
        } else {
            _ = try result;
        }
    }
}

test "updateCalleeAccount: data readonly" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    for ([_]bool{ false, true }) |stricter_abi_and_runtime_constraints| {
        // Custom TestContext to set readonly account.
        var ctx = try TestContext.init(allocator, prng.random(), "foobar");
        defer ctx.deinit(allocator);

        // Set random owner to mark readonly.
        const random_owner = Pubkey.initRandom(prng.random());
        ctx.tc.accounts[0].account.owner = random_owner;

        const account = ctx.getAccount();

        var ca = try TestCallerAccount.init(
            allocator,
            1234,
            account.owner,
            account.data,
            false, // direct mapping
        );
        defer ca.deinit(allocator);
        var caller_account = ca.getCallerAccount();

        var callee_account = try ctx.ic.borrowInstructionAccount(account.index);
        defer callee_account.release();

        // stricter_abi_and_runtime_constraints does not copy data in updateCalleeAccount()
        caller_account.serialized_data[0] = 'b';
        try std.testing.expectError(
            InstructionError.ExternalAccountDataModified,
            updateCalleeAccount(
                allocator,
                &ctx.ic,
                &callee_account,
                &caller_account,
                false, // stricter_abi_and_runtime_constraints
                false, // account_data_direct_mapping
            ),
        );

        // growing resize
        var resize_data = "foobarbaz".*;
        (try caller_account.ref_to_len_in_vm.get(.mutable)).* = resize_data.len;
        caller_account.serialized_data = &resize_data;
        try std.testing.expectError(
            InstructionError.AccountDataSizeChanged,
            updateCalleeAccount(
                allocator,
                &ctx.ic,
                &callee_account,
                &caller_account,
                stricter_abi_and_runtime_constraints,
                true, // account_data_direct_mapping
            ),
        );

        // truncating resize
        var truncate_data = "baz".*;
        (try caller_account.ref_to_len_in_vm.get(.mutable)).* = truncate_data.len;
        caller_account.serialized_data = &truncate_data;
        try std.testing.expectError(
            InstructionError.AccountDataSizeChanged,
            updateCalleeAccount(
                allocator,
                &ctx.ic,
                &callee_account,
                &caller_account,
                stricter_abi_and_runtime_constraints,
                true, // account_data_direct_mapping
            ),
        );
    }
}

// test CallerAccount updates

test "updateCallerAccount: lamports owner" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    for ([_]bool{ false, true }) |stricter_abi_and_runtime_constraints| {
        var ctx = try TestContext.init(allocator, prng.random(), &.{});
        defer ctx.deinit(allocator);
        const account = ctx.getAccount();

        var ca = try TestCallerAccount.init(
            allocator,
            1234, // lamports
            account.owner,
            account.data,
            false, // direct mapping
        );
        defer ca.deinit(allocator);
        var caller_account = ca.getCallerAccount();

        var callee_account = try ctx.ic.borrowInstructionAccount(account.index);
        defer callee_account.release();

        try callee_account.setLamports(42);
        try callee_account.setOwner(Pubkey.initRandom(prng.random()));

        try updateCallerAccount(
            &ctx.ic,
            &ca.memory_map,
            &caller_account,
            &callee_account,
            stricter_abi_and_runtime_constraints,
            stricter_abi_and_runtime_constraints,
        );

        try std.testing.expectEqual(caller_account.lamports.*, 42);
        try std.testing.expect(caller_account.owner.equals(&callee_account.account.owner));
    }
}

test "updateCallerAccount: data" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    var ctx = try TestContext.init(allocator, prng.random(), "foobar");
    defer ctx.deinit(allocator);
    const account = ctx.getAccount();

    var ca = try TestCallerAccount.init(
        allocator,
        account.lamports,
        account.owner,
        account.data,
        false, // direct mapping
    );
    defer ca.deinit(allocator);
    var caller_account = ca.getCallerAccount();

    var callee_account = try ctx.ic.borrowInstructionAccount(account.index);
    defer callee_account.release();

    const len_ptr: *align(1) u64 = @ptrCast(ca.buffer[0..8]);
    const original_data_len = account.data.len;

    for ([_]struct { []const u8, usize }{
        .{ "foo", MAX_PERMITTED_DATA_INCREASE + 3 },
        .{ "foobaz", MAX_PERMITTED_DATA_INCREASE },
        .{ "foobazbad", MAX_PERMITTED_DATA_INCREASE - 3 },
    }) |entry| {
        const new_value, const realloc_size = entry;

        try std.testing.expect(std.mem.eql(
            u8,
            caller_account.serialized_data,
            callee_account.account.data,
        ));

        // Set to new slice.
        try callee_account.setDataFromSlice(allocator, &ctx.tc.accounts_resize_delta, new_value);
        try updateCallerAccount(
            &ctx.ic,
            &ca.memory_map,
            &caller_account,
            &callee_account,
            false, // stricter_abi_and_runtime_constraints
            false, // account_data_direct_mapping
        );

        const size = callee_account.account.data.len;
        try std.testing.expectEqual(size, (try caller_account.ref_to_len_in_vm.get(.constant)).*);
        try std.testing.expectEqual(size, len_ptr.*);
        try std.testing.expectEqual(size, caller_account.serialized_data.len);
        try std.testing.expect(std.mem.eql(
            u8,
            callee_account.account.data,
            caller_account.serialized_data[0..size],
        ));

        const realloced = ca.slice()[size..];
        try std.testing.expectEqual(realloced.len, realloc_size);
        try std.testing.expect(std.mem.allEqual(u8, realloced, 0));
    }

    // Extend to maximum.
    try callee_account.setDataLength(
        allocator,
        &ctx.tc.accounts_resize_delta,
        original_data_len + MAX_PERMITTED_DATA_INCREASE,
    );
    try updateCallerAccount(
        &ctx.ic,
        &ca.memory_map,
        &caller_account,
        &callee_account,
        false, // stricter_abi_and_runtime_constraints
        false, // account_data_direct_mapping
    );

    const realloced = ca.slice()[callee_account.account.data.len..];
    try std.testing.expectEqual(realloced.len, 0);
    try std.testing.expect(std.mem.allEqual(u8, realloced, 0));

    // Extend past maximum.
    try callee_account.setDataLength(
        allocator,
        &ctx.tc.accounts_resize_delta,
        original_data_len + MAX_PERMITTED_DATA_INCREASE + 1,
    );
    try std.testing.expectError(InstructionError.InvalidRealloc, updateCallerAccount(
        &ctx.ic,
        &ca.memory_map,
        &caller_account,
        &callee_account,
        false, // stricter_abi_and_runtime_constraints
        false, // account_data_direct_mapping
    ));

    // close the account
    try callee_account.setDataLength(allocator, &ctx.tc.accounts_resize_delta, 0);
    try updateCallerAccount(
        &ctx.ic,
        &ca.memory_map,
        &caller_account,
        &callee_account,
        false, // stricter_abi_and_runtime_constraints
        false, // account_data_direct_mapping
    );
    try std.testing.expectEqual(callee_account.account.data.len, 0);
}

test "inokeSignedRust" {
    try testCpiCommon(AccountInfoRust);
}

test "invokeSignedC" {
    try testCpiCommon(AccountInfoC);
}

fn testCpiCommon(comptime AccountType: type) !void {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    for ([_]bool{ false, true }) |stricter_abi_and_runtime_constraints| {
        var ctx = try TestContext.init(allocator, prng.random(), "hello world");
        defer ctx.deinit(allocator);
        const account = ctx.getAccount();

        if (stricter_abi_and_runtime_constraints) {
            const feature_set: *sig.core.FeatureSet = @constCast(ctx.tc.feature_set);
            feature_set.setSlot(.stricter_abi_and_runtime_constraints, ctx.tc.slot);
            feature_set.setSlot(.account_data_direct_mapping, ctx.tc.slot);
        }

        // the CPI program to execute.
        const program_id = system_program.ID;
        const data = try sig.bincode.writeAlloc(
            allocator,
            system_program.Instruction{ .assign = .{ .owner = program_id } },
            .{},
        );
        defer allocator.free(data);
        const accounts = [_]InstructionAccount{.{
            .pubkey = account.key,
            .is_signer = true,
            .is_writable = true,
        }};

        // setting up CPI structs in memory
        const instruction_addr = memory.HEAP_START;
        const instruction_buffer = try intoStableInstruction(
            allocator,
            AccountType,
            instruction_addr,
            data,
            program_id,
            &accounts,
        );
        defer allocator.free(instruction_buffer);

        // Update the account data to be:
        // - its own region for stricter_abi_and_runtime_constraints.
        // - start at INPUT_START for getSerializedData().
        const account_data_addr = memory.INPUT_START;
        const account_data_buffer = try allocator.dupe(u8, account.data);
        defer allocator.free(account_data_buffer);

        const account_info_addr =
            std.mem.alignForward(u64, instruction_addr + instruction_buffer.len, BPF_ALIGN_OF_U128);
        const account_info_buffer, const serialized_metadata = try account.intoAccountInfo(
            allocator,
            AccountType,
            account_info_addr,
            account_data_addr,
        );
        defer allocator.free(account_info_buffer);

        ctx.tc.serialized_accounts.appendAssumeCapacity(serialized_metadata);

        var memory_map = try MemoryMap.init(
            allocator,
            &.{
                memory.Region.init(.constant, &.{}, memory.RODATA_START),
                memory.Region.init(.mutable, &.{}, memory.STACK_START),
                memory.Region.init(.constant, instruction_buffer, instruction_addr),
                memory.Region.init(.mutable, account_info_buffer, account_info_addr),
                memory.Region.init(.mutable, account_data_buffer, account_data_addr),
            },
            .v3,
            .{ .aligned_memory_mapping = false },
        );
        defer memory_map.deinit(allocator);

        // invoke CPI

        var registers = RegisterMap.initFill(0);
        registers.set(.r1, instruction_addr);
        registers.set(.r2, account_info_addr);
        registers.set(.r3, 1); // account_infos_len
        registers.set(.r4, 0); // null signers_addr
        registers.set(.r5, 0); // zero signers_len

        try invokeSigned(AccountType)(ctx.tc, &memory_map, &registers);
    }
}

test isBpfLoaderV3InstructionBlacklisted {
    const all_enabled = sig.core.features.Set.ALL_ENABLED_AT_GENESIS;
    const all_disabled = sig.core.features.Set.ALL_DISABLED;
    try std.testing.expect(isBpfLoaderV3InstructionBlacklisted(&.{}, &all_disabled, 0));
    try std.testing.expect(!isBpfLoaderV3InstructionBlacklisted(&.{3}, &all_disabled, 0));
    try std.testing.expect(!isBpfLoaderV3InstructionBlacklisted(&.{4}, &all_disabled, 0));
    try std.testing.expect(!isBpfLoaderV3InstructionBlacklisted(&.{5}, &all_disabled, 0));
    try std.testing.expect(isBpfLoaderV3InstructionBlacklisted(&.{7}, &all_disabled, 0));
    try std.testing.expect(!isBpfLoaderV3InstructionBlacklisted(&.{7}, &all_enabled, 0));
    try std.testing.expect(!isBpfLoaderV3InstructionBlacklisted(&.{3}, &all_disabled, 0));
    try std.testing.expect(isBpfLoaderV3InstructionBlacklisted(&.{8}, &all_disabled, 0));
    try std.testing.expect(isBpfLoaderV3InstructionBlacklisted(&.{9}, &all_disabled, 0));
    try std.testing.expect(!isBpfLoaderV3InstructionBlacklisted(&.{9}, &all_enabled, 0));
}
