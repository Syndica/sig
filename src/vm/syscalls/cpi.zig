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

const BatchAccountCache = sig.runtime.account_loader.BatchAccountCache;
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
        const Self = @This();

        vm_address: struct {
            vm_addr: u64,
            memory_map: *const MemoryMap,
            check_aligned: bool,
        },
        translated_addr: usize,

        pub fn get(self: Self, comptime state: memory.MemoryState) !(switch (state) {
            .constant => *align(1) const T,
            .mutable => *align(1) T,
        }) {
            switch (self) {
                .translated_addr => |ptr| return @ptrFromInt(ptr),
                .vm_address => |vma| {
                    return vma.memory_map.translateType(T, state, vma.vm_addr, vma.check_aligned);
                },
            }
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
        _vm_addr: u64,
        account_info: *align(1) const AccountInfoRust,
        account_metadata: *const SerializedAccountMetadata,
    ) !CallerAccount {
        _ = _vm_addr; // unused, but have same signature as fromAccountInfoC().

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
                    data_ptr,
                    account_metadata.vm_data_addr,
                    "data",
                );
            }

            try ic.tc.consumeCompute(std.math.divFloor(
                u64,
                data.len,
                ic.tc.compute_budget.cpi_bytes_per_unit,
            ) catch std.math.maxInt(u64));

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
                ic.tc.account_data_direct_mapping,
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

        try ic.tc.consumeCompute(std.math.divFloor(
            u64,
            account_info.data_len,
            ic.tc.compute_budget.cpi_bytes_per_unit,
        ) catch std.math.maxInt(u64));

        const serialized_data: []u8 = try getSerializedData(
            memory_map,
            account_info.data_addr,
            account_info.data_len,
            stricter_abi_and_runtime_constraints,
            ic.tc.account_data_direct_mapping,
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
    direct_mapping: bool,
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
        if (!direct_mapping and callee_account.checkDataIsMutable() == null) {
            try callee_account.setDataFromSlice(
                allocator,
                &ic.tc.accounts_resize_delta,
                caller_account.serialized_data,
            );
        }
    } else {
        // The redundant check helps to avoid the expensive data comparison if we can
        const can_data_be_resized =
            callee_account.checkCanSetDataLength(
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
    allocator: std.mem.Allocator,
    ic: *const InstructionContext,
    memory_map: *const MemoryMap,
    comptime AccountInfoType: type,
    account_infos_addr: u64,
    account_infos_len: u64,
    account_metas: []const InstructionInfo.AccountMeta,
) !TranslatedAccounts {
    // translate_account_infos():

    const stricter_abi_and_runtime_constraints = ic.tc.feature_set.active(
        .stricter_abi_and_runtime_constraints,
        ic.tc.slot,
    );

    // In the same vein as the other checkAccountInfoPtr() checks, we don't lock
    // this pointer to a specific address but we don't want it to be inside accounts, or
    // callees might be able to write to the pointed memory.
    if (stricter_abi_and_runtime_constraints and
        (account_infos_addr +| (account_infos_len *| @sizeOf(AccountInfoType))) >= MM_INPUT_START)
    {
        return SyscallError.InvalidPointer;
    }

    const account_infos = try memory_map.translateSlice(
        AccountInfoType,
        .constant,
        account_infos_addr,
        account_infos_len,
        ic.getCheckAligned(),
    );

    // check_account_infos():
    const max_cpi_account_infos: u64 = if (ic.tc.feature_set.active(
        .increase_tx_account_lock_limit,
        ic.tc.slot,
    )) 128 else 64;

    if (account_infos.len > max_cpi_account_infos) {
        return SyscallError.MaxInstructionAccountInfosExceeded;
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
        const index_in_caller =
            try ic.ixn_info.getAccountInstructionIndex(meta.index_in_transaction);
        if (index_in_caller != index_in_instruction) {
            continue; // Skip duplicate account.
        }

        var callee_account = try ic.borrowInstructionAccount(index_in_caller);
        defer callee_account.release();

        const account_key = blk: {
            const account_meta = ic.tc.getAccountAtIndex(meta.index_in_transaction) orelse
                return InstructionError.NotEnoughAccountKeys;
            break :blk account_meta.pubkey;
        };

        if (callee_account.account.executable) {
            // Use the known account
            try ic.tc.consumeCompute(std.math.divFloor(
                u64,
                callee_account.constAccountData().len,
                ic.tc.compute_budget.cpi_bytes_per_unit,
            ) catch std.math.maxInt(u64));
            continue;
        }

        const caller_account_index = for (account_info_keys.constSlice(), 0..) |key, idx| {
            if (key.equals(&account_key)) break idx;
        } else {
            try ic.tc.log("Instruction references an unknown account {}", .{account_key});
            return InstructionError.MissingAccount;
        };

        const serialized_account_metas = ic.tc.serialized_accounts.constSlice();
        const serialized_metadata = if (index_in_caller < serialized_account_metas.len) blk: {
            break :blk &serialized_account_metas[index_in_caller];
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
            &callee_account,
            &caller_account,
            stricter_abi_and_runtime_constraints,
            ic.tc.account_data_direct_mapping,
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

    // check_instruction_size():
    const MAX_ACCOUNTS_PER_INSTRUCTION = InstructionInfo.MAX_ACCOUNT_METAS - 1;
    if (account_metas.len > MAX_ACCOUNTS_PER_INSTRUCTION) {
        return SyscallError.MaxInstructionAccountsExceeded;
    }

    const MAX_INSTRUCTION_DATA_LEN = 10 * 1024;
    if (data.len > MAX_INSTRUCTION_DATA_LEN) {
        return SyscallError.MaxInstructionDataLenExceeded;
    }

    try ic.tc.consumeCompute(std.math.divFloor(
        u64,
        data.len,
        ic.tc.compute_budget.cpi_bytes_per_unit,
    ) catch std.math.maxInt(u64));

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
        if (!(stricter_abi_and_runtime_constraints and ic.tc.account_data_direct_mapping)) {
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
                ic.tc.account_data_direct_mapping,
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

    if (!(stricter_abi_and_runtime_constraints and ic.tc.account_data_direct_mapping)) {
        // Propagate changes in the callee up to the caller.
        const to = caller_account.serialized_data;
        const from = callee_account.constAccountData();
        if (from.len < post_len) return SyscallError.InvalidLength;
        if (to.len != from.len) return InstructionError.AccountDataTooSmall;
        @memcpy(to, from);
    }
}

/// [agave] https://github.com/anza-xyz/agave/blob/bb5a6e773d5f41388a962c5c4f96f5f2ef2209d0/programs/bpf_loader/src/syscalls/cpi.rs#L1054
fn cpiCommon(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    memory_map: *MemoryMap,
    comptime AccountInfoType: type,
    instruction_addr: u64,
    account_infos_addr: u64,
    account_infos_len: u64,
    signers_seeds_addr: u64,
    signers_seeds_len: u64,
) Error!void {
    try ic.tc.consumeCompute(ic.tc.compute_budget.invoke_units);

    // TODO: timings

    const instruction = try translateInstruction(
        allocator,
        ic,
        memory_map,
        AccountInfoType,
        instruction_addr,
    );
    defer allocator.free(instruction.accounts);

    const signers = try translateSigners(
        ic,
        memory_map,
        signers_seeds_addr,
        signers_seeds_len,
        ic.ixn_info.program_meta.pubkey,
    );

    // check_authorized_program(ic, instruction):
    // [agave] https://github.com/anza-xyz/agave/blob/bb5a6e773d5f41388a962c5c4f96f5f2ef2209d0/programs/bpf_loader/src/syscalls/cpi.rs#L1028C4-L1028C28
    if (ids.NATIVE_LOADER_ID.equals(&instruction.program_id) or
        bpf_loader_program.v1.ID.equals(&instruction.program_id) or
        bpf_loader_program.v2.ID.equals(&instruction.program_id) or
        (bpf_loader_program.v3.ID.equals(&instruction.program_id) and
            isBpfLoaderV3InstructionAuthorized(instruction.data, ic.tc.feature_set, ic.tc.slot)) or
        (blk: {
            for (PRECOMPILES) |p| if (p.program_id.equals(&instruction.program_id)) break :blk true;
            break :blk false;
        }))
    {
        // TODO add {instruction.program_id} as context to error.
        // https://github.com/anza-xyz/agave/blob/bb5a6e773d5f41388a962c5c4f96f5f2ef2209d0/programs/bpf_loader/src/syscalls/cpi.rs#L1048
        return SyscallError.ProgramNotSupported;
    }

    const info = try sig.runtime.executor.prepareCpiInstructionInfo(
        ic.tc,
        instruction,
        signers.slice(),
    );

    var accounts = try translateAccounts(
        allocator,
        ic,
        memory_map,
        AccountInfoType,
        account_infos_addr,
        account_infos_len,
        info.account_metas.constSlice(),
    );

    // Process the callee instruction.
    // Doesn't call `executeNativeCpiInstruction` as info already setup.
    try sig.runtime.executor.executeInstruction(allocator, ic.tc, info);

    // CPI Exit.
    // Synchronize the callee's account changes so the caller can see them.
    const stricter_abi_and_runtime_constraints = ic.tc.feature_set.active(
        .stricter_abi_and_runtime_constraints,
        ic.tc.slot,
    );

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
            );
        }
    }

    if (stricter_abi_and_runtime_constraints) {
        for (accounts.constSlice()) |translated| {
            var callee_account = try ic.borrowInstructionAccount(translated.index_in_caller);
            defer callee_account.release();
            if (translated.update_caller_account_region) {
                // update_caller_account_region()

                const caller_account = &translated.caller_account;
                const is_caller_loader_deprecated = !ic.getCheckAligned();
                const address_space = caller_account.original_data_len +|
                    (MAX_PERMITTED_DATA_INCREASE * @intFromBool(!is_caller_loader_deprecated));

                if (address_space > 0) {
                    const region = memory_map.region(.constant, caller_account.vm_data_addr) catch
                        return InstructionError.MissingAccount;
                    std.debug.assert(region.vm_addr_start == caller_account.vm_data_addr);

                    const shared = false; // TODO: callee_account.account.data is not ref-counted
                    const writable = callee_account.checkDataIsMutable() == null;
                    const data = if (ic.tc.account_data_direct_mapping)
                        callee_account.constAccountData()
                    else
                        region.constSlice();

                    // Modify memory_map's region AccessType & Memory
                    region.host_memory = if (writable and !shared)
                        .{ .mutable = @constCast(data) }
                    else
                        .{ .constant = data };
                }
            }
        }
    }
}

/// Some bpf loader v3 instructions are not allowed to be invoked via cpi. This method
/// determines if a bpf loader v3 instruction is part of the cpi restriced set of instructions.
fn isBpfLoaderV3InstructionAuthorized(
    instruction_data: []const u8,
    feature_set: *const sig.core.FeatureSet,
    slot: sig.core.Slot,
) bool {
    if (instruction_data.len == 0) return true;
    const V3Tag = @typeInfo(bpf_loader_program.v3.Instruction).@"union".tag_type.?;
    const v3_tag = std.meta.intToEnum(V3Tag, instruction_data[0]) catch return true;
    return switch (v3_tag) {
        // upgrade instruction
        .upgrade => false,
        // set authority instruction
        .set_authority => false,
        // close instrucion
        .close => false,
        // set authority checked instruction
        .set_authority_checked => !feature_set.active(
            .enable_bpf_loader_set_authority_checked_ix,
            slot,
        ),
        // migrate instruction
        .migrate => false,
        // extend program checked instruction
        .extend_program_checked => !feature_set.active(
            .enable_extend_program_checked,
            slot,
        ),
        else => true,
    };
}

fn invokeSigned(
    comptime AccountInfoType: type,
    tc: *TransactionContext,
    memory_map: *MemoryMap,
    registers: *RegisterMap,
) Error!void {
    const instruction_addr = registers.get(.r1);
    const account_infos_addr = registers.get(.r2);
    const account_infos_len = registers.get(.r3);
    const signers_seeds_addr = registers.get(.r4);
    const signers_seeds_len = registers.get(.r5);

    const caller_ic = try tc.getCurrentInstructionContext();

    return cpiCommon(
        tc.allocator,
        caller_ic,
        memory_map,
        AccountInfoType,
        instruction_addr,
        account_infos_addr,
        account_infos_len,
        signers_seeds_addr,
        signers_seeds_len,
    ) catch |e| {
        if (@errorReturnTrace()) |t| std.debug.dumpStackTrace(t.*);
        return e;
    };
}

/// [agave] https://github.com/anza-xyz/agave/blob/master/programs/bpf_loader/src/syscalls/cpi.rs#L608-L630
pub fn invokeSignedC(
    tc: *TransactionContext,
    memory_map: *MemoryMap,
    registers: *RegisterMap,
) Error!void {
    return invokeSigned(AccountInfoC, tc, memory_map, registers);
}

/// [agave] https://github.com/anza-xyz/agave/blob/master/programs/bpf_loader/src/syscalls/cpi.rs#L399-L421
pub fn invokeSignedRust(
    tc: *TransactionContext,
    memory_map: *MemoryMap,
    registers: *RegisterMap,
) Error!void {
    return invokeSigned(AccountInfoRust, tc, memory_map, registers);
}

// CPI Tests

const testing = sig.runtime.testing;

const TestContext = struct {
    cache: BatchAccountCache,
    tc: *TransactionContext,
    ic: InstructionContext,

    fn init(allocator: std.mem.Allocator, prng: std.Random, account_data: []const u8) !TestContext {
        comptime std.debug.assert(builtin.is_test);

        const tc = try allocator.create(TransactionContext);
        errdefer allocator.destroy(tc);

        const account_key = Pubkey.initRandom(prng);

        var cache, tc.* = try testing.createTransactionContext(allocator, prng, .{
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
            testing.deinitTransactionContext(allocator, tc.*);
            cache.deinit(allocator);
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
        testing.deinitTransactionContext(allocator, self.tc.*);
        allocator.destroy(self.tc);
        self.ic.deinit(allocator);
        self.cache.deinit(allocator);
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
    fn intoAccountInfo(
        self: *const TestAccount,
        allocator: std.mem.Allocator,
        comptime AccountInfoType: type,
        vm_addr: u64,
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
                .data_addr = data_addr,
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

test "CallerAccount.fromAccountInfoRust" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    var ctx = try TestContext.init(allocator, prng.random(), "foobar");
    defer ctx.deinit(allocator);

    const account = ctx.getAccount();
    const vm_addr = MM_INPUT_START;

    const buffer, const serialized_metadata =
        try account.intoAccountInfo(allocator, AccountInfoRust, vm_addr);
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
    var prng = std.Random.DefaultPrng.init(5083);

    var ctx = try TestContext.init(allocator, prng.random(), "foobar");
    defer ctx.deinit(allocator);

    const account = ctx.getAccount();
    const vm_addr = MM_INPUT_START;

    const buffer, const serialized_metadata =
        try account.intoAccountInfo(allocator, AccountInfoRust, vm_addr);
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

    // [agave] https://github.com/anza-xyz/agave/blob/04fd7a006d8b400096e14a69ac16e10dc3f6018a/programs/bpf_loader/src/syscalls/cpi.rs#L2554
    const accounts = try translateAccounts(
        allocator,
        &ctx.ic,
        &memory_map,
        false, // is_loader_deprecated
        AccountInfoRust,
        vm_addr, // account_infos_addr
        1, // account_infos_len
        ctx.ic.ixn_info.program_meta.index_in_transaction, // program_meta_index
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
    var prng = std.Random.DefaultPrng.init(5083);

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
        &ca.memory_map,
        &callee_account,
        &caller_account,
        false, // is_loader_deprecated
        false, // direct_mapping
    );

    try std.testing.expectEqual(callee_account.account.lamports, 42);
    try std.testing.expect(callee_account.account.owner.equals(caller_account.owner));
}

test "updateCalleeAccount: data" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

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

    // Update the serialized data into account data
    {
        var data = "foo".*;
        caller_account.serialized_data = &data;

        _ = try updateCalleeAccount(
            allocator,
            &ctx.ic,
            &ca.memory_map,
            &callee_account,
            &caller_account,
            false, // is_loader_deprecated
            false, // direct_mapping
        );
        try std.testing.expect(std.mem.eql(
            u8,
            callee_account.account.data,
            caller_account.serialized_data,
        ));
    }

    // Close the account.
    {
        caller_account.serialized_data = &.{};
        (try caller_account.ref_to_len_in_vm.get(.mutable)).* = 0;

        var owner = system_program.ID;
        caller_account.owner = &owner;

        _ = try updateCalleeAccount(
            allocator,
            &ctx.ic,
            &ca.memory_map,
            &callee_account,
            &caller_account,
            false, // is_loader_deprecated
            false, // direct_mapping
        );
        try std.testing.expect(std.mem.eql(u8, callee_account.account.data, &.{}));
    }
}

test "updateCalleeAccount: data readonly" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

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

    // Make account readonly (going through setOwner would hit error.ModifiedProgramId).
    callee_account.account.owner = Pubkey.initRandom(prng.random());

    // Check data must be the same when readonly
    caller_account.serialized_data[0] = 'b';
    try std.testing.expectError(
        InstructionError.ExternalAccountDataModified,
        updateCalleeAccount(
            allocator,
            &ctx.ic,
            &ca.memory_map,
            &callee_account,
            &caller_account,
            false, // is_loader_deprecated
            false, // direct_mapping
        ),
    );

    // Check without direct mapping + different size.
    var data = "foobarbaz".*;
    caller_account.serialized_data = &data;
    (try caller_account.ref_to_len_in_vm.get(.mutable)).* = data.len;
    try std.testing.expectError(
        InstructionError.AccountDataSizeChanged,
        updateCalleeAccount(
            allocator,
            &ctx.ic,
            &ca.memory_map,
            &callee_account,
            &caller_account,
            false, // is_loader_deprecated
            false, // direct_mapping
        ),
    );
}

test "updateCalleeAccount: data direct mapping" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    var ctx = try TestContext.init(allocator, prng.random(), "foobar");
    defer ctx.deinit(allocator);
    const account = ctx.getAccount();

    var ca = try TestCallerAccount.init(
        allocator,
        1234,
        account.owner,
        account.data,
        true, // direct mapping
    );
    defer ca.deinit(allocator);
    var caller_account = ca.getCallerAccount();

    var callee_account = try ctx.ic.borrowInstructionAccount(account.index);
    defer callee_account.release();

    const serialized_data = try ca.memory_map.translateSlice(
        u8,
        .mutable,
        caller_account.vm_data_addr +| caller_account.original_data_len,
        3,
        ctx.ic.getCheckAligned(),
    );
    @memcpy(serialized_data, "baz");

    for ([_]struct { usize, []const u8 }{
        .{ 9, "foobarbaz" }, // > original_data_len, copies from realloc region
        .{ 6, "foobar" }, // == original_data_len, truncates
        .{ 3, "foo" }, // < original_data_len, truncates
    }) |entry| {
        const len, const expected = entry;

        (try caller_account.ref_to_len_in_vm.get(.mutable)).* = len;
        _ = try updateCalleeAccount(
            allocator,
            &ctx.ic,
            &ca.memory_map,
            &callee_account,
            &caller_account,
            false, // is_loader_deprecated
            true, // direct_mapping
        );
        try std.testing.expect(std.mem.eql(u8, expected, callee_account.account.data));
    }

    // Close the account
    caller_account.serialized_data = &.{};
    (try caller_account.ref_to_len_in_vm.get(.mutable)).* = 0;
    var owner = system_program.ID;
    caller_account.owner = &owner;
    _ = try updateCalleeAccount(
        allocator,
        &ctx.ic,
        &ca.memory_map,
        &callee_account,
        &caller_account,
        false, // is_loader_deprecated
        true, // direct_mapping
    );
    try std.testing.expect(std.mem.eql(u8, callee_account.account.data, ""));
}

// test CallerAccount updates

test "updateCallerAccount: lamports owner" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

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
        allocator,
        &ctx.ic,
        &ca.memory_map,
        &caller_account,
        &callee_account,
        false, // is loader account
        false, // direct mapping
    );

    try std.testing.expectEqual(caller_account.lamports.*, 42);
    try std.testing.expect(caller_account.owner.equals(&callee_account.account.owner));
}

test "updateCallerAccount: data" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

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
            allocator,
            &ctx.ic,
            &ca.memory_map,
            &caller_account,
            &callee_account,
            false, // is_loader_deprecated
            false, // direct_mapping
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
        allocator,
        &ctx.ic,
        &ca.memory_map,
        &caller_account,
        &callee_account,
        false, // is_loader_deprecated
        false, // direct_mapping
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
        allocator,
        &ctx.ic,
        &ca.memory_map,
        &caller_account,
        &callee_account,
        false, // is_loader_deprecated
        false, // direct_mapping
    ));

    // close the account
    try callee_account.setDataLength(allocator, &ctx.tc.accounts_resize_delta, 0);
    try updateCallerAccount(
        allocator,
        &ctx.ic,
        &ca.memory_map,
        &caller_account,
        &callee_account,
        false, // is_loader_deprecated
        false, // direct_mapping
    );
    try std.testing.expectEqual(callee_account.account.data.len, 0);
}

test "updateCallerAccount: data direct mapping" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    var ctx = try TestContext.init(allocator, prng.random(), "foobar");
    defer ctx.deinit(allocator);
    const account = ctx.getAccount();

    var ca = try TestCallerAccount.init(
        allocator,
        account.lamports,
        account.owner,
        account.data,
        true, // direct mapping
    );
    defer ca.deinit(allocator);
    var caller_account = ca.getCallerAccount();

    var callee_account = try ctx.ic.borrowInstructionAccount(account.index);
    defer callee_account.release();

    const len_ptr: *align(1) u64 = @ptrCast(ca.buffer[0..8]);
    const original_data_len = account.data.len;

    for ([_]bool{ false, true }) |change_ptr| {
        for ([_]struct { []const u8, usize }{
            .{ "foobazbad", 3 }, // > original_data_len, writes into realloc
            .{ "foo", 0 }, // < original_data_len, zeroes account capacity + realloc capacity
            .{ "foobaz", 0 }, // = original_data_len
            .{ "", 0 }, // check lower bound
        }) |entry| {
            const new, const realloc_used = entry;
            if (change_ptr) {
                const copy = try allocator.dupe(u8, callee_account.account.data);
                allocator.free(callee_account.account.data);
                callee_account.account.data = copy;
            }

            try callee_account.setDataFromSlice(allocator, &ctx.tc.accounts_resize_delta, new);
            try updateCallerAccount(
                allocator,
                &ctx.ic,
                &ca.memory_map,
                &caller_account,
                &callee_account,
                false, // is_loader_deprecated
                true, // direct_mapping
            );

            // Check the caller & callee account data pointers match
            try std.testing.expectEqual(
                callee_account.account.data.ptr,
                (try ca.memory_map.translateSlice(
                    u8,
                    .constant,
                    caller_account.vm_data_addr,
                    1,
                    true,
                )).ptr,
            );

            // Check account info lengths were updated
            const size = callee_account.account.data.len;
            try std.testing.expectEqual(size, len_ptr.*);
            try std.testing.expectEqual(
                size,
                (try caller_account.ref_to_len_in_vm.get(.constant)).*,
            );

            const realloc_area = try ca.memory_map.translateSlice(
                u8,
                .constant,
                caller_account.vm_data_addr +| caller_account.original_data_len,
                MAX_PERMITTED_DATA_INCREASE,
                ctx.ic.getCheckAligned(),
            );

            // TODO: Make sure spare capacity account data is zeroed (no data capacity atm).
            // if (size < original_data_len) {
            //     const original_slice = callee_account.constAccountData().ptr[0..original_data_len];
            //     try std.testing.expect(std.mem.allEqual(
            //         u8,
            //         original_slice[original_data_len - size..],
            //         0,
            //     ));
            // }

            try std.testing.expect(std.mem.allEqual(u8, realloc_area[realloc_used..], 0));
            try std.testing.expect(std.mem.eql(
                u8,
                realloc_area[0..realloc_used],
                callee_account.constAccountData()[size - realloc_used ..],
            ));
        }
    }

    // Bump size to max & check zero padding.
    {
        try callee_account.setDataLength(
            allocator,
            &ctx.tc.accounts_resize_delta,
            original_data_len + MAX_PERMITTED_DATA_INCREASE,
        );
        try updateCallerAccount(
            allocator,
            &ctx.ic,
            &ca.memory_map,
            &caller_account,
            &callee_account,
            false, // is_loader_deprecated
            true, // direct_mapping
        );
        try std.testing.expect(std.mem.allEqual(u8, caller_account.serialized_data, 0));
    }

    // Bump size and over & check still zero padded.
    {
        try callee_account.setDataLength(
            allocator,
            &ctx.tc.accounts_resize_delta,
            original_data_len + MAX_PERMITTED_DATA_INCREASE + 1,
        );
        try std.testing.expectError(InstructionError.InvalidRealloc, updateCallerAccount(
            allocator,
            &ctx.ic,
            &ca.memory_map,
            &caller_account,
            &callee_account,
            false, // is_loader_deprecated
            false, // direct_mapping (false on overgrow?)
        ));
        try std.testing.expect(std.mem.allEqual(u8, caller_account.serialized_data, 0));
    }

    // Close account
    {
        try callee_account.setDataLength(allocator, &ctx.tc.accounts_resize_delta, 0);
        try callee_account.setOwner(system_program.ID);
        try updateCallerAccount(
            allocator,
            &ctx.ic,
            &ca.memory_map,
            &caller_account,
            &callee_account,
            false, // is_loader_deprecated
            true, // direct_mapping
        );
        try std.testing.expectEqual(callee_account.constAccountData().len, 0);
    }
}

test "updateCallerAccount: data capacity direct mapping" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    var ctx = try TestContext.init(allocator, prng.random(), "foobar");
    defer ctx.deinit(allocator);
    const account = ctx.getAccount();

    var ca = try TestCallerAccount.init(
        allocator,
        account.lamports,
        account.owner,
        account.data,
        true, // direct mapping
    );
    defer ca.deinit(allocator);
    var caller_account = ca.getCallerAccount();

    var callee_account = try ctx.ic.borrowInstructionAccount(account.index);
    defer callee_account.release();

    // Update the buffer.
    try callee_account.setDataFromSlice(allocator, &ctx.tc.accounts_resize_delta, "baz");

    {
        // TODO: ensure enough account data capacity (no data capacity atm).
        // try std.testing.expect(callee_account.capacity >= 3);
        try std.testing.expectEqual(callee_account.constAccountData().len, 3);

        try updateCallerAccount(
            allocator,
            &ctx.ic,
            &ca.memory_map,
            &caller_account,
            &callee_account,
            false, // is_loader_deprecated
            true, // direct_mapping
        );

        // TODO: ensure enough account data capacity (no data capacity atm).
        // try std.testing.expect(callee_account.capacity >= caller_account.original_data_len);
        try std.testing.expectEqual(callee_account.constAccountData().len, 3);
    }

    try std.testing.expect(std.mem.eql(
        u8,
        callee_account.constAccountData(),
        try ca.memory_map.translateSlice(
            u8,
            .constant,
            caller_account.vm_data_addr,
            callee_account.constAccountData().len,
            true,
        ),
    ));
}

test "cpiCommon (invokeSignedRust)" {
    try testCpiCommon(AccountInfoRust);
}

test "cpiCommon (invokeSignedC)" {
    try testCpiCommon(AccountInfoC);
}

fn testCpiCommon(comptime AccountInfoType: type) !void {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    var ctx = try TestContext.init(allocator, prng.random(), "");
    defer ctx.deinit(allocator);
    const account = ctx.getAccount();

    // the CPI program to execute.
    const program_id = system_program.ID;
    const data = try sig.bincode.writeAlloc(
        allocator,
        system_program.Instruction{ .assign = .{ .owner = Pubkey.initRandom(prng.random()) } },
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
    const heap_buffer = try intoStableInstruction(
        allocator,
        AccountInfoType,
        instruction_addr,
        data,
        program_id,
        &accounts,
    );
    defer allocator.free(heap_buffer);

    const account_info_addr = memory.INPUT_START;
    const input_buffer, const serialized_metadata =
        try account.intoAccountInfo(allocator, AccountInfoType, account_info_addr);
    defer allocator.free(input_buffer);

    ctx.tc.serialized_accounts.appendAssumeCapacity(serialized_metadata);

    var memory_map = try MemoryMap.init(
        allocator,
        &.{
            memory.Region.init(.constant, &.{}, memory.RODATA_START),
            memory.Region.init(.mutable, &.{}, memory.STACK_START),
            memory.Region.init(.constant, heap_buffer, instruction_addr),
            memory.Region.init(.mutable, input_buffer, account_info_addr),
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

    switch (AccountInfoType) {
        AccountInfoRust => try invokeSignedRust(ctx.tc, &memory_map, &registers),
        AccountInfoC => try invokeSignedC(ctx.tc, &memory_map, &registers),
        else => @compileError("invalid AccountInfo type"),
    }
}

test isBpfLoaderV3InstructionAuthorized {
    const all_enabled = sig.core.features.Set.ALL_ENABLED_AT_GENESIS;
    const all_disabled = sig.core.features.Set.ALL_DISABLED;
    try std.testing.expect(isBpfLoaderV3InstructionAuthorized(&.{}, &all_disabled, 0));
    try std.testing.expect(!isBpfLoaderV3InstructionAuthorized(&.{3}, &all_disabled, 0));
    try std.testing.expect(!isBpfLoaderV3InstructionAuthorized(&.{4}, &all_disabled, 0));
    try std.testing.expect(!isBpfLoaderV3InstructionAuthorized(&.{5}, &all_disabled, 0));
    try std.testing.expect(isBpfLoaderV3InstructionAuthorized(&.{7}, &all_disabled, 0));
    try std.testing.expect(!isBpfLoaderV3InstructionAuthorized(&.{7}, &all_enabled, 0));
    try std.testing.expect(!isBpfLoaderV3InstructionAuthorized(&.{3}, &all_disabled, 0));
    try std.testing.expect(!isBpfLoaderV3InstructionAuthorized(&.{8}, &all_disabled, 0));
    try std.testing.expect(isBpfLoaderV3InstructionAuthorized(&.{9}, &all_disabled, 0));
    try std.testing.expect(!isBpfLoaderV3InstructionAuthorized(&.{9}, &all_enabled, 0));
}
